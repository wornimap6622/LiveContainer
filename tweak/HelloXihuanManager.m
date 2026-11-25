//
//  HelloXihuanManager.m
//  自动点赞核心 (点喜欢.deb 完整复刻)
//
//  完整链路:
//   1. getDataWithVc: 从划卡VC拿 userCards/unswipedUsers 列表
//   2. filterUser: 按 objectID 去重(排除已处理)
//   3. timerTick 定时取出用户, 按 type 分派
//   4. praiseUser: 调 PUGMomentLikeUseCase likeMoment:attitudeId:source:completion:
//
#import "HelloXihuanManager.h"
#import "HelloHelper.h"
#import "HelloCountdownLabel.h"
#import <objc/runtime.h>
#import <objc/message.h>
#import <stdlib.h>

// 空转计数: 连续拿不到卡片时累加, 超过阈值自动停任务 (防止 taskNumber=0 时无限空转)
static NSInteger g_xh_empty_tick_total = 0;

@implementation HelloXihuanManager

+ (instancetype)shared {
    static HelloXihuanManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[HelloXihuanManager alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        self.isStart = NO;
        self.taskNumber = 0;
        self.taskSpeed = 3.0;
        self.taskSpeedMax = 0.0;   // 0 = 固定速度，无区间
        self.taskSpeedText = @"3";
        self.activeTime = 30;
        self.alreadyTask = 0;
        self.type = 0;
        self.userArray = [NSMutableArray array];
        self.parisedUserArray = [NSMutableArray array];
        self.followUserArray = [NSMutableArray array];
        self.commentUserArray = [NSMutableArray array];
        [self initData];
    }
    return self;
}

// 从 UserDefaults 恢复参数
- (void)initData {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    NSDictionary *param = [ud objectForKey:@"hello_param"];
    if (param) {
        self.taskNumber = [param[@"taskNumber"] integerValue];
        self.taskSpeed = [param[@"taskSpeed"] doubleValue];
        self.taskSpeedMax = [param[@"taskSpeedMax"] doubleValue];
        self.taskSpeedText = param[@"taskSpeedText"];
        if (!self.taskSpeedText || self.taskSpeedText.length == 0) {
            self.taskSpeedText = [NSString stringWithFormat:@"%g", self.taskSpeed];
        }
        self.activeTime = [param[@"activeTime"] integerValue];
        self.msgText = param[@"msgText"];
        self.type = [param[@"type"] integerValue];
    }
}

- (void)saveData {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    NSDictionary *param = @{
        @"taskNumber": @(self.taskNumber),
        @"taskSpeed": @(self.taskSpeed),
        @"taskSpeedMax": @(self.taskSpeedMax),
        @"taskSpeedText": self.taskSpeedText ?: @"",
        @"activeTime": @(self.activeTime),
        @"msgText": self.msgText ?: @"",
        @"type": @(self.type),
    };
    [ud setObject:param forKey:@"hello_param"];
    [ud synchronize];
}

#pragma mark - 速度区间随机（对齐安卓 matchSpeed 1-3 / 2-5 区间）

// 解析速度输入串：支持 "1-3"(区间随机) / "1.5"(固定) / "1.5-3"(区间)。
// 成功返回 YES 并设置 taskSpeed/taskSpeedMax，失败返回 NO 保持原值。
- (BOOL)parseSpeed:(NSString *)s {
    if (!s || s.length == 0) return NO;
    NSString *t = [s stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    t = [t stringByReplacingOccurrencesOfString:@"－" withString:@"-"];
    t = [t stringByReplacingOccurrencesOfString:@"—" withString:@"-"];
    t = [t stringByReplacingOccurrencesOfString:@"～" withString:@"-"];
    t = [t stringByReplacingOccurrencesOfString:@"~" withString:@"-"];
    if (t.length == 0) return NO;
    double lo = 0, hi = 0;
    NSRange dash = [t rangeOfString:@"-"];
    @try {
        if (dash.location != NSNotFound && dash.location > 0) {
            lo = [[t substringToIndex:dash.location] doubleValue];
            hi = [[t substringFromIndex:dash.location + 1] doubleValue];
            if (lo <= 0 || hi <= 0) return NO;
            if (lo > hi) { double tmp = lo; lo = hi; hi = tmp; }
        } else {
            lo = [t doubleValue];
            if (lo <= 0) return NO;
            hi = 0.0;   // 0 = 固定
        }
    } @catch (NSException *e) {
        return NO;
    }
    self.taskSpeed = lo;
    self.taskSpeedMax = hi;
    self.taskSpeedText = t;
    return YES;
}

// 取下一次匹配的随机间隔（秒）：区间则 [lo, hi] 随机，固定则返回 lo
- (NSTimeInterval)nextTickInterval {
    double lo = self.taskSpeed > 0 ? self.taskSpeed : 3.0;
    double hi = self.taskSpeedMax;
    if (hi > lo) {
        double r = (double)arc4random() / (double)UINT32_MAX; // 0~1
        return lo + r * (hi - lo);
    }
    return lo;
}

- (void)startWithVc:(UIViewController *)vc type:(NSInteger)type {
    [HelloHelper log:@"startWithVc 调用: vc=%@ vcClass=%@ type=%ld", vc, NSStringFromClass([vc class]), (long)type];
    // 传入 VC 可能已失效(页面重建/授权拦截导致 viewWillAppear 提前返回): 回退到当前活跃划卡页
    if (!vc || !vc.view || !vc.view.window) {
        UIViewController *live = [HelloHelper getSwipeVC];
        [HelloHelper log:@"startWithVc: 传入VC失效(%@), 回退到当前划卡VC=%@",
         vc ? @"不在窗口" : @"nil", live ? NSStringFromClass([live class]) : @"(nil)"];
        if (live) vc = live;
    }
    self.vc = vc;
    self.type = type;
    self.isStart = YES;
    self.alreadyTask = 0;
    g_xh_empty_tick_total = 0;
    // 初始显示倒计时: "划卡 N 次" (taskNumber>0 时显示剩余, =0 显示已处理数)
    [self updateCountdownLabel];
    [self startTask];
}

- (void)startTask {
    // (本地版: 无远程授权, 直接放行)
    if (!self.isStart) return;
    if (self.taskSpeedMax > self.taskSpeed) {
        [HelloHelper log:@"startTask 开始: speed=%g~%g(随机) taskNumber=%ld", self.taskSpeed, self.taskSpeedMax, (long)self.taskNumber];
    } else {
        [HelloHelper log:@"startTask 开始: speed=%.1f(固定) taskNumber=%ld", self.taskSpeed, (long)self.taskNumber];
    }

    [self.timer invalidate];
    // 区间随机：不 repeats，每次 tick 后按随机间隔重新调度
    NSTimeInterval interval = [self nextTickInterval];
    self.timer = [NSTimer timerWithTimeInterval:interval
                                         target:self
                                       selector:@selector(timerTick)
                                       userInfo:nil
                                        repeats:NO];
    [[NSRunLoop mainRunLoop] addTimer:self.timer forMode:NSRunLoopCommonModes];
    [self.timer fire];
}

- (void)stopTask {
    self.isStart = NO;
    [self.timer invalidate];
    self.timer = nil;
    [HelloCountdownLabel hide]; // 停止时隐藏倒计时
    [self saveData];
}

// 任务运行中则重新显示倒计时 (页面切回时调用)
- (void)refreshCountdownIfRunning {
    if (self.isStart) {
        [self updateCountdownLabel];
    } else {
        [HelloCountdownLabel hide];
    }
}

// 更新悬浮倒计时标签 (屏幕中间上方, 白底黑字)
- (void)updateCountdownLabel {
    NSInteger remain;
    if (self.taskNumber > 0) {
        remain = self.taskNumber - self.alreadyTask;
        if (remain < 0) remain = 0;
    } else {
        // taskNumber=0 (不限), 显示已处理数
        remain = self.alreadyTask;
    }
    // 前缀 "划卡" (e58892e58da1), 单位 "次" (e6aca1)
    [HelloCountdownLabel showWithPrefix:[HelloHelper strWithUTF8Hex:@"e58892e58da1"]
                                 remain:remain
                                   unit:[HelloHelper strWithUTF8Hex:@"e6aca1"]];
}

- (void)timerTick {
    // (本地版: 无远程授权, 直接放行)
    if (!self.isStart) {
        [self.timer invalidate];
        return;
    }

    [HelloHelper log:@"timerTick: vc=%@ vcClass=%@ vc.view=%@ vc.view.window=%@",
     self.vc, self.vc ? NSStringFromClass([self.vc class]) : @"(nil)",
     self.vc && self.vc.view ? @"有" : @"(nil)",
     (self.vc && self.vc.view && self.vc.view.window) ? @"在窗口上" : @"(不在窗口)"];

    // VC 失效时重新定位当前划卡页: 页面重建/授权拦截会让旧VC脱离窗口, 拿不到卡片就会无限空转
    if (!self.vc || !self.vc.view || !self.vc.view.window) {
        UIViewController *live = [HelloHelper getSwipeVC];
        if (live) {
            self.vc = live;
            g_xh_empty_tick_total = 0;
            [HelloHelper log:@"timerTick: 原VC失效, 已切换到当前划卡VC=%@", NSStringFromClass([live class])];
        }
    }

    // 达到任务数量则停止
    if (self.taskNumber > 0 && self.alreadyTask >= self.taskNumber) {
        [HelloHelper log:@"达到匹配人数 %ld, 停止", (long)self.taskNumber];
        [self stopTask];
        return;
    }

    // 直接从划卡VC拿当前顶部卡片, 对齐 auto_swipe.js 已验证方案
    id card = [self topUserCardWithVc:self.vc];
    if (!card) {
        self.noCardCount++;
        [HelloHelper log:@"timerTick: 无卡片可操作 (连续 %ld 次), 等待下一张...", (long)self.noCardCount];
        // 防卡死: 连续 5 次无卡强制跳过一次 (对齐 TantanHelper)
        if (self.noCardCount >= 5) {
            [HelloHelper log:@"timerTick: 连续 %ld 次无卡, 强制跳过一次防卡死", (long)self.noCardCount];
            self.noCardCount = 0;
            [self forceSkipCard];
        }
        // 安全阀: 长时间拿不到卡片自动停任务, 避免 taskNumber=0 时永远空转 (表现为"一直划")
        g_xh_empty_tick_total++;
        if (g_xh_empty_tick_total >= 40) {
            g_xh_empty_tick_total = 0;
            [HelloHelper log:@"timerTick: 连续 40 次空转无卡片, 自动停止任务"];
            [self stopTask];
        }
        [self scheduleNextTick];
        return;
    }
    self.noCardCount = 0; // 有卡则清零
    g_xh_empty_tick_total = 0; // 有卡则空转计数清零

    self.alreadyTask++;

    // 更新倒计时标签 (每次处理一张卡片后刷新剩余次数)
    [self updateCountdownLabel];

    switch (self.type) {
        case 0: // 喜欢
            [self praiseUser:card];
            break;
        case 1: // 关注
            [self attentionUser:card];
            break;
        case 2: // 评论
        case 3: // 消息
            [self sendMsgToUser:card];
            break;
    }
    [self scheduleNextTick];
}

// 按随机间隔重新调度下一次 tick（区间随机速度用，替代固定 repeats:YES）
- (void)scheduleNextTick {
    if (!self.isStart) return;
    NSTimeInterval interval = [self nextTickInterval];
    self.timer = [NSTimer timerWithTimeInterval:interval
                                         target:self
                                       selector:@selector(timerTick)
                                       userInfo:nil
                                        repeats:NO];
    [[NSRunLoop mainRunLoop] addTimer:self.timer forMode:NSRunLoopCommonModes];
}

// 获取当前顶部卡片 (对齐 auto_swipe.js: [vc topUserCard] / [vc pluginTopCard])
- (id)topUserCardWithVc:(UIViewController *)vc {
    if (!vc) {
        [HelloHelper log:@"topUserCardWithVc: vc 为 nil"];
        return nil;
    }
    [HelloHelper log:@"topUserCardWithVc: class=%@ 是否响应 topUserCard=%d 是否响应 pluginTopCard=%d",
     NSStringFromClass([vc class]),
     [vc respondsToSelector:NSSelectorFromString(@"topUserCard")],
     [vc respondsToSelector:NSSelectorFromString(@"pluginTopCard")]];
    id card = nil;
    SEL topSel = NSSelectorFromString(@"topUserCard");
    if ([vc respondsToSelector:topSel]) {
        card = ((id(*)(id, SEL))objc_msgSend)(vc, topSel);
        [HelloHelper log:@"topUserCardWithVc: topUserCard 返回 %@ (class=%@)", card, card ? NSStringFromClass([card class]) : @"(nil)"];
    }
    if (!card) {
        SEL pluginSel = NSSelectorFromString(@"pluginTopCard");
        if ([vc respondsToSelector:pluginSel]) {
            card = ((id(*)(id, SEL))objc_msgSend)(vc, pluginSel);
            [HelloHelper log:@"topUserCardWithVc: pluginTopCard 返回 %@ (class=%@)", card, card ? NSStringFromClass([card class]) : @"(nil)"];
        }
    }
    [HelloHelper log:@"topUserCardWithVc: 最终 card=%@", card ? NSStringFromClass([card class]) : @"(nil)"];
    return card;
}

#pragma mark - 数据获取

// 从划卡VC拿用户列表: userCards 或 unswipedUsers
- (void)getDataWithVc:(UIViewController *)vc {
    if (!vc) {
        [HelloHelper log:@"getDataWithVc: vc 为 nil"];
        return;
    }
    [HelloHelper log:@"getDataWithVc: vc=%@ class=%@", vc, NSStringFromClass([vc class])];

    id list = nil;
    if ([vc respondsToSelector:NSSelectorFromString(@"userCards")]) {
        list = [vc valueForKey:@"userCards"];
        [HelloHelper log:@"getDataWithVc: userCards = %@ (count=%ld)", list, (long)[list count]];
    } else if ([vc respondsToSelector:NSSelectorFromString(@"unswipedUsers")]) {
        list = [vc valueForKey:@"unswipedUsers"];
        [HelloHelper log:@"getDataWithVc: unswipedUsers = %@ (count=%ld)", list, (long)[list count]];
    } else {
        [HelloHelper log:@"getDataWithVc: vc 既无 userCards 也无 unswipedUsers 属性!"];
    }
    if (list) {
        self.userArray = [list mutableCopy];
    }
}

- (void)loadMoreUserWithVc:(UIViewController *)vc {
    [self getDataWithVc:vc];
    // 过滤已处理的
    self.userArray = [[self filterUser:self.userArray] mutableCopy];
}

#pragma mark - 筛选

// 按 objectID 去重, 排除已点赞/关注/评论的
- (NSArray *)filterUser:(NSArray *)users {
    NSMutableArray *result = [NSMutableArray array];
    for (id user in users) {
        NSString *objectID = nil;
        if ([user respondsToSelector:NSSelectorFromString(@"objectID")]) {
            objectID = [user valueForKey:@"objectID"];
            objectID = [NSString stringWithFormat:@"%@", objectID];
        }
        if (objectID &&
            ![self.parisedUserArray containsObject:objectID] &&
            ![self.followUserArray containsObject:objectID] &&
            ![self.commentUserArray containsObject:objectID]) {
            [result addObject:user];
        }
    }
    return result;
}

#pragma mark - 点赞 (含活跃时间过滤)

// 6.0.0 活跃时间: PUGSuggestedUser.user.activityDate (由 Tweak.m 缓存/直取)
extern NSString *XHActivityStringForUser(id o);

// 读取卡片用户的最近活跃时间
// 6.0.0 正确链路: PUGSuggestedUser.user.activityDate
// 兼容老链路:     card -> cardViewModel -> rawData -> user -> activityDate
- (NSString *)readActivityDateFromCard:(id)card {
    if (!card) return nil;
    NSString *dateStr = nil;

    // ① 6.0.0 真正主路径 (card 是 PUGChinaUserCardView 视图, 本身没有模型)
    //    vc.pluginUserWithCard:card  -> PUGUser -> activityDate
    @try {
        id vc = self.vc;
        SEL uSel = NSSelectorFromString(@"pluginUserWithCard:");
        if (vc && [vc respondsToSelector:uSel]) {
            id u = ((id(*)(id, SEL, id))objc_msgSend)(vc, uSel, card);
            NSString *s = XHActivityStringForUser(u);
            [HelloHelper log:@"[V6] readActivity: pluginUserWithCard -> %@(%@) 时间=%@",
             u, u ? NSStringFromClass([u class]) : @"(nil)", s ?: @"(nil)"];
            if (s.length > 0) return s;
        }
    } @catch (NSException *e) {
        [HelloHelper log:@"[V6] readActivity: pluginUserWithCard 异常 %@", e];
    }

    // ② 6.0.0 备用: vc.pluginUsecase -> unswipedUsers[0] -> PUGSuggestedUser.user.activityDate
    @try {
        id vc = self.vc;
        SEL ucSel = NSSelectorFromString(@"pluginUsecase");
        if (vc && [vc respondsToSelector:ucSel]) {
            id uc = ((id(*)(id, SEL))objc_msgSend)(vc, ucSel);
            SEL unSel = NSSelectorFromString(@"unswipedUsers");
            if (uc && [uc respondsToSelector:unSel]) {
                id arr = ((id(*)(id, SEL))objc_msgSend)(uc, unSel);
                if ([arr isKindOfClass:[NSArray class]] && [arr count] > 0) {
                    id su = [arr objectAtIndex:0];
                    NSString *s = XHActivityStringForUser(su);
                    [HelloHelper log:@"[V6] readActivity: usecase.unswipedUsers[0]=%@ 时间=%@",
                     su ? NSStringFromClass([su class]) : @"(nil)", s ?: @"(nil)"];
                    if (s.length > 0) return s;
                }
            }
        }
    } @catch (NSException *e) {
        [HelloHelper log:@"[V6] readActivity: pluginUsecase 异常 %@", e];
    }

    // ③ card 本身可能是模型对象 (老链路 / 直接传模型进来时)
    @try {
        NSString *s = XHActivityStringForUser(card);
        if (s.length > 0) {
            dateStr = s;
        }
    } @catch (NSException *e) {
        [HelloHelper log:@"readActivityDateFromCard: 6.0.0路径异常 %@", e];
    }
    if (dateStr.length > 0) return dateStr;
    @try {
        id vm = nil;
        SEL vmSel = NSSelectorFromString(@"cardViewModel");
        if ([card respondsToSelector:vmSel]) {
            vm = ((id(*)(id, SEL))objc_msgSend)(card, vmSel);
        }
        id rd = nil;
        if (vm) {
            SEL rdSel = NSSelectorFromString(@"rawData");
            if ([vm respondsToSelector:rdSel]) {
                rd = ((id(*)(id, SEL))objc_msgSend)(vm, rdSel);
            }
        }
        id user = nil;
        if (rd) {
            SEL userSel = NSSelectorFromString(@"user");
            if ([rd respondsToSelector:userSel]) {
                user = ((id(*)(id, SEL))objc_msgSend)(rd, userSel);
            }
        }
        if (user) {
            SEL adSel = NSSelectorFromString(@"activityDate");
            if ([user respondsToSelector:adSel]) {
                id d = ((id(*)(id, SEL))objc_msgSend)(user, adSel);
                if ([d isKindOfClass:[NSDate class]]) {
                    dateStr = [NSString stringWithFormat:@"%@", d];
                } else if ([d isKindOfClass:[NSString class]]) {
                    dateStr = (NSString *)d;
                }
            }
        }
    } @catch (NSException *e) {
        [HelloHelper log:@"readActivityDateFromCard: 异常 %@", e];
    }
    return dateStr;
}

// 判断活跃: activeMinutes<=0 恒真; 读不到时间时按"不活跃"处理(避免恒右滑)
- (BOOL)isRecentlyActive:(NSString *)dateStr minutes:(NSInteger)minutes {
    if (minutes <= 0) return YES;
    if (!dateStr || dateStr.length == 0) return NO;
    @try {
        NSDate *d = nil;
        // 多种格式尝试解析 (activityDate 通常是 ISO8601 或带毫秒)
        NSDateFormatter *df = [[NSDateFormatter alloc] init];
        df.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
        NSArray *formats = @[
            @"yyyy-MM-dd'T'HH:mm:ss.SSSZ",
            @"yyyy-MM-dd'T'HH:mm:ssZ",
            @"yyyy-MM-dd HH:mm:ss Z",
            @"yyyy-MM-dd'T'HH:mm:ss",
        ];
        for (NSString *fmt in formats) {
            df.dateFormat = fmt;
            d = [df dateFromString:dateStr];
            if (d) break;
        }
        if (!d) {
            // 兜底: NSISO8601DateFormatter (iOS 10+, 运行时可用)
            if ([NSISO8601DateFormatter class]) {
                NSISO8601DateFormatter *iso = [[NSISO8601DateFormatter alloc] init];
                iso.formatOptions = NSISO8601DateFormatWithInternetDateTime;
                d = [iso dateFromString:dateStr];
            }
        }
        if (!d) return YES;
        NSTimeInterval diff = [[NSDate date] timeIntervalSinceDate:d];
        double diffMin = diff / 60.0;
        return diffMin <= (double)minutes;
    } @catch (NSException *e) {
        return YES;
    }
}

#pragma mark - 在线/活跃/离线三维判断 (吸收 TantanHelper findOnlineInView)

// 扫描卡片视图上的 UI 文本, 判断在线/活跃状态
// 返回: 0=未知(回退用活跃时间判断) 1=在线 2=活跃(分钟前) 3=离线/闲置
- (NSInteger)detectUserStateFromCard:(id)card {
    NSInteger state = 0; // 0=未知
    @try {
        // 递归扫描 card 视图的所有 UILabel/UIButton 文本
        NSMutableArray *texts = [NSMutableArray array];
        [self collectTextsFromView:card intoArray:texts];
        for (NSString *t in texts) {
            NSString *lower = [t lowercaseString];
            if ([lower containsString:@"在线"] || [lower containsString:@"online"] || [lower containsString:@"刚刚活跃"] || [lower containsString:@"刚刚在线"]) {
                return 1; // 在线
            }
            if ([lower containsString:@"分钟前活跃"] || [lower containsString:@"小时前活跃"] ||
                [lower containsString:@"分钟前在线"] || [lower containsString:@"active"] || [lower containsString:@"mins ago"]) {
                return 2; // 活跃(有具体时间)
            }
            if ([lower containsString:@"离线"] || [lower containsString:@"offline"] || [lower containsString:@"很久没上线"] || [lower containsString:@"长期不在线"]) {
                state = 3; // 离线(继续扫, 可能后面有更明确的"在线")
            }
        }
    } @catch (NSException *e) {
        [HelloHelper log:@"detectUserStateFromCard: 异常 %@", e];
    }
    return state;
}

// 递归收集视图树上的文本
- (void)collectTextsFromView:(UIView *)view intoArray:(NSMutableArray *)texts {
    if (!view || texts.count > 500) return;
    if ([view isKindOfClass:[UILabel class]]) {
        NSString *t = ((UILabel *)view).text;
        if (t && t.length > 0) [texts addObject:t];
    } else if ([view isKindOfClass:[UIButton class]]) {
        NSString *t = [((UIButton *)view) titleForState:UIControlStateNormal];
        if (t && t.length > 0) [texts addObject:t];
    }
    for (UIView *sub in view.subviews) {
        [self collectTextsFromView:sub intoArray:texts];
    }
}

#pragma mark - 多级降级执行 (吸收 TantanHelper performLike)

// 喜欢候选选择器列表
- (NSArray *)likeSelectors {
    return @[
        @"userCardDidTapLike:", @"didTapLikeButton:", @"likeButtonTapped:",
        @"didTapLike:", @"likeAction:", @"didSwipeRight:", @"cardDidSwipeRight:",
        @"handleSwipeRight", @"swipeRightAction:", @"swipeRight", @"didSwipeRight",
        @"likeAction", @"userLike"
    ];
}

// 跳过候选选择器列表
- (NSArray *)passSelectors {
    return @[
        @"userCardDidTapDislike:", @"didTapPassButton:", @"passButtonTapped:",
        @"didTapPass:", @"passAction:", @"didSwipeLeft:", @"cardDidSwipeLeft:",
        @"handleSwipeLeft", @"swipeLeftAction:", @"swipeLeft", @"didSwipeLeft", @"passAction"
    ];
}

// 反射调用: 依次尝试候选选择器, 成功返回 YES
- (BOOL)callSelectorIfExists:(NSArray *)selectors onTarget:(id)target withArg:(id)arg {
    if (!target) return NO;
    for (NSString *selName in selectors) {
        SEL sel = NSSelectorFromString(selName);
        if (![target respondsToSelector:sel]) continue;
        @try {
            // 判断选择器是否有参数 (带冒号结尾 = 有1个参数)
            BOOL hasArg = [selName hasSuffix:@":"];
            if (hasArg) {
                ((void(*)(id, SEL, id))objc_msgSend)(target, sel, arg);
            } else {
                ((void(*)(id, SEL))objc_msgSend)(target, sel);
            }
            [HelloHelper log:@"callSelectorIfExists: 成功调用 %@", selName];
            return YES;
        } @catch (NSException *e) {
            [HelloHelper log:@"callSelectorIfExists: %@ 异常 %@", selName, e];
        }
    }
    return NO;
}

// 模拟划卡手势 (左/右)
- (void)simulateSwipeOnVc:(UIViewController *)vc direction:(BOOL)isLike {
    if (!vc || !vc.view) return;
    @try {
        // iOS 无公开 API 直接伪造触摸, 这里尝试通过 vc 的 pan 手势识别器
        for (UIGestureRecognizer *g in vc.view.gestureRecognizers) {
            if ([g isKindOfClass:[UIPanGestureRecognizer class]]) {
                [HelloHelper log:@"simulateSwipeOnVc: 发现 pan 手势, 但无法直接伪造(降级)"];
            }
        }
        // 兜底: 反射调用探探的划卡方法
        [HelloHelper log:@"simulateSwipeOnVc: 尝试反射调用划卡方法 direction=%d", isLike];
        NSArray *swipeSels = isLike ? @[@"handleSwipeRight", @"didSwipeRight", @"swipeRight"] : @[@"handleSwipeLeft", @"didSwipeLeft", @"swipeLeft"];
        [self callSelectorIfExists:swipeSels onTarget:vc withArg:nil];
    } @catch (NSException *e) {
        [HelloHelper log:@"simulateSwipeOnVc: 异常 %@", e];
    }
}

// 强制跳过一次 (防卡死用)
- (void)forceSkipCard {
    id vc = self.vc;
    if (!vc) return;
    [HelloHelper log:@"forceSkipCard: 强制跳过"];
    // 优先反射调跳过方法
    if ([self callSelectorIfExists:[self passSelectors] onTarget:vc withArg:nil]) {
        return;
    }
    // 兜底: 真实按钮点击跳过 (742 无 performAction:userCard:...)
    [HelloHelper tapRealButtonWithKeywords:@"dislike,pass,nope,skip" isLike:NO];
}

- (void)praiseUser:(id)card {
    if (!card) return;

    id vc = self.vc;
    if (!vc) {
        [HelloHelper log:@"praiseUser: vc 为 nil!"];
        return;
    }

    // 诊断: self.vc 与 getSwipeVC 是否一致 (两者不一致说明划卡VC定位有问题)
    UIViewController *swipeVc = [HelloHelper getSwipeVC];
    [HelloHelper log:@"praiseUser: self.vc=%@ (class=%@) getSwipeVC=%@ (class=%@) 是否同一对象=%d",
     self.vc, NSStringFromClass([self.vc class]),
     swipeVc, swipeVc ? NSStringFromClass([swipeVc class]) : @"(nil)",
     (swipeVc == self.vc)];

    // ===== 第一步: 三维状态判断 (在线/活跃/离线) =====
    NSInteger state = [self detectUserStateFromCard:card];
    NSString *actDate = [self readActivityDateFromCard:card];
    BOOL active = NO;
    [HelloHelper log:@"praiseUser: cardClass=%@ 活跃时间=%@ UI状态=%ld activeTime=%ld",
     NSStringFromClass([card class]), actDate ?: @"(nil)", (long)state, (long)self.activeTime];

    if (state == 1) {
        // 在线 -> 喜欢 (最高优先级)
        active = YES;
        [HelloHelper log:@"praiseUser: 在线 -> 喜欢"];
    } else if (state == 2) {
        // 活跃(X分钟前) -> 按 activeTime 阈值判断
        active = [self isRecentlyActive:actDate minutes:self.activeTime];
        [HelloHelper log:@"praiseUser: 活跃(有具体时间) -> %@", active ? @"喜欢" : @"跳过"];
    } else if (state == 3) {
        // 离线 -> 跳过
        active = NO;
        [HelloHelper log:@"praiseUser: 离线 -> 跳过"];
    } else {
        // 未知 -> 回退用活跃时间判断
        active = [self isRecentlyActive:actDate minutes:self.activeTime];
        [HelloHelper log:@"[V6] praiseUser: 状态未知, 回退活跃时间判断 (活跃=%@ activeTime=%ld) -> %@",
         actDate ?: @"(nil)", (long)self.activeTime, active ? @"喜欢" : @"跳过"];
    }

    NSInteger actionType = active ? 2 : 1; // 2=喜欢 1=跳过
    [HelloHelper log:@"[V6] praiseUser: 执行 card=%@ active=%d actionType=%ld 时间=%@",
     NSStringFromClass([card class]), active, (long)actionType, actDate ?: @"(nil)"];

    // ===== 第二步: 多级降级执行 =====
    // 级别0: 真实按钮点击 (对齐最初版 TantanHelper, 742 上最可靠, 不干扰原生划卡)
    NSString *keywords = active ? @"like,heart,love" : @"dislike,pass,nope,skip";
    if ([HelloHelper tapRealButtonWithKeywords:keywords isLike:active]) {
        [HelloHelper log:@"praiseUser: 级别0 真实按钮点击成功 -> %@", active ? @"喜欢" : @"跳过"];
        return;
    }
    [HelloHelper log:@"praiseUser: 级别0 真实按钮点击失败, 降级到级别1 反射调用"];
    // 级别1: 反射调用候选方法 (喜欢/跳过)
    NSArray *sels = active ? [self likeSelectors] : [self passSelectors];
    if ([self callSelectorIfExists:sels onTarget:vc withArg:card]) {
        [HelloHelper log:@"praiseUser: 级别1 反射降级成功 -> actionType=%ld (%@)", (long)actionType, active ? @"喜欢" : @"跳过"];
        return;
    }
    [HelloHelper log:@"praiseUser: 级别1 反射调用失败, 降级到级别2 卡片方法"];
    // 级别2: 对卡片对象调用方法
    if ([self callSelectorIfExists:sels onTarget:card withArg:nil]) {
        [HelloHelper log:@"praiseUser: 级别2 卡片方法降级成功 -> %@", active ? @"喜欢" : @"跳过"];
        return;
    }
    [HelloHelper log:@"praiseUser: 级别2 卡片方法失败, 降级到级别3 模拟手势"];
    // 级别3: 模拟手势 (对齐最初版 simulateCardSwipe, 742 无 performAction:userCard:...)
    [HelloHelper simulateCardSwipe:active];
    [HelloHelper log:@"praiseUser: 级别3 模拟手势已尝试 %@ (是否成功看 simulateCardSwipe 日志)", active ? @"右划(喜欢)" : @"左划(跳过)"];
}

#pragma mark - 关注

- (void)attentionUser:(id)user {
    if (!user) return;
    NSString *objectID = [user valueForKey:@"objectID"];
    if (!objectID) return;

    Class updater = NSClassFromString(@"PUGFollowshipRelationUpdater");
    if (!updater) return;

    id instance = nil;
    if ([updater respondsToSelector:@selector(shared)]) {
        instance = [updater performSelector:@selector(shared)];
    } else {
        instance = [[updater alloc] init];
    }
    if (!instance) return;

    SEL sel = NSSelectorFromString(@"changeFollowship:completion:");
    if (![instance respondsToSelector:sel]) return;

    [self.followUserArray addObject:objectID];

    ((void(*)(id, SEL, id, id))objc_msgSend)(instance, sel, objectID, nil);
}

#pragma mark - 评论/消息

- (void)sendMsgToUser:(id)user {
    if (!user) return;
    NSString *objectID = [user valueForKey:@"objectID"];
    if (!objectID) return;

    Class commentUseCase = NSClassFromString(@"PUGMomentCommentUseCase");
    if (!commentUseCase) return;

    id instance = nil;
    if ([commentUseCase respondsToSelector:@selector(shared)]) {
        instance = [commentUseCase performSelector:@selector(shared)];
    } else {
        instance = [[commentUseCase alloc] init];
    }
    if (!instance) return;

    SEL sel = NSSelectorFromString(@"sendCommentToUser:comment:content:creation:completion:");
    if (![instance respondsToSelector:sel]) return;

    [self.commentUserArray addObject:objectID];

    NSString *msg = self.msgText ?: @"";
    ((void(*)(id, SEL, id, id, id, id, id))objc_msgSend)(instance, sel, objectID, msg, msg, nil, nil);
}

@end
