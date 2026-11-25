//
//  HelloSendMgr.m
//  顺发消息/顺发图片管理器 (借鉴视屏.deb)
//
//  完整链路:
//   1. 从会话列表 VC 拿会话数组 (conversationArray / displayedConversations / 数据源)
//   2. 遍历会话, 逐个 initWithConversation:shouldLoadMessages: 创建 PUGMessagesViewController
//   3. 发送文本: 通过 chatMessenger 的 sendText:
//   4. 发送图片: 从本地路径读图 -> 上传 -> 发送
//
#import "HelloSendMgr.h"
#import "HelloHelper.h"
#import "HelloAuth.h"
#import "HelloCountdownLabel.h"
#import <objc/runtime.h>
#import <objc/message.h>

@implementation HelloSendMgr

+ (instancetype)shared {
    static HelloSendMgr *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[HelloSendMgr alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        self.isRunning = NO;
        self.activeTime = 0;
        self.sendDelay = 0.9;   // 默认发送速度 0.9 秒
        self.alreadySent = 0;
        self.sendType = 0;
        self.imageSendMode = 0;   // 默认旧版发图
        self.prioritizeIncoming = YES; // 默认先发对方先开口的聊天框
        self.conversationArray = [NSMutableArray array];
        self.sentArray = [NSMutableArray array];
        self.audioFileURLs = [NSMutableArray array];
        self.videoFilePaths = [NSMutableArray array];
        [self initData];
    }
    return self;
}

- (void)initData {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    NSDictionary *param = [ud objectForKey:@"hello_send_param"];
    if (param) {
        self.activeTime = [param[@"activeTime"] integerValue];
        self.sendDelay = [param[@"sendDelay"] doubleValue];
        // 旧版本默认值 5.0 迁移到新的 0.9 (5.0 正好是旧默认, 用户多半没主动改)
        if (self.sendDelay <= 0 || self.sendDelay == 5.0) self.sendDelay = 0.9;
        self.msgText = param[@"msgText"];
        self.imageSendMode = [param[@"imageSendMode"] integerValue];
        if (self.imageSendMode != 0 && self.imageSendMode != 1) self.imageSendMode = 0;
        if (param[@"prioritizeIncoming"] != nil) {
            self.prioritizeIncoming = [param[@"prioritizeIncoming"] boolValue];
        }
    }
}

- (void)saveData {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    NSDictionary *param = @{
        @"activeTime": @(self.activeTime),
        @"sendDelay": @(self.sendDelay),
        @"msgText": self.msgText ?: @"",
        @"imageSendMode": @(self.imageSendMode),
        @"prioritizeIncoming": @(self.prioritizeIncoming),
    };
    [ud setObject:param forKey:@"hello_send_param"];
    [ud synchronize];
}

- (void)startSendWithVc:(UIViewController *)listVC type:(NSInteger)type {
    [HelloHelper log:@"startSendWithVc: listVC=%@ class=%@ type=%ld", listVC, NSStringFromClass([listVC class]), (long)type];
    self.listVC = listVC;
    self.sendType = type;

    // 先统计会话数量, 弹窗确认后再真正开始
    [self loadConversations];
    NSInteger total = self.conversationArray.count;
    if (total == 0) {
        // 列表为空, 尝试延迟再取一次
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [self loadConversations];
            [self showConfirmAlert];
        });
        return;
    }
    [self showConfirmAlert];
}

// 弹窗确认: 告诉用户有多少个会话, 确认后才开始发送
- (void)showConfirmAlert {
    NSInteger total = self.conversationArray.count;
    NSString *title = [HelloHelper strWithUTF8Hex:@"e9a1bae58f91e7a1aee8aea4"]; // 顺发确认
    NSString *msg = [NSString stringWithFormat:@"%@ %ld %@\n%@", [HelloHelper strWithUTF8Hex:@"e6a380e6b58be588b0"], (long)total, [HelloHelper strWithUTF8Hex:@"e4b8aae4bc9ae8af9d"], [HelloHelper strWithUTF8Hex:@"e698afe590a6e5bc80e5a78be9a1bae58f91"]]; // 检测到 N 个会话\n是否开始顺发

    [HelloHelper log:@"showConfirmAlert: total=%ld type=%ld msg=%@", (long)total, (long)self.sendType, msg];

    // 用当前最顶层 VC present, 确保弹窗可见
    UIViewController *hostVC = [self topViewController];
    if (!hostVC) {
        hostVC = self.listVC;
    }

    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                   message:msg
                                                            preferredStyle:UIAlertControllerStyleAlert];
    // 取消
    [alert addAction:[UIAlertAction actionWithTitle:[HelloHelper strWithUTF8Hex:@"e58f96e6b688"] style:UIAlertActionStyleCancel handler:^(UIAlertAction *action) {
        [HelloHelper log:@"用户取消顺发"];
    }]];
    // 确认
    [alert addAction:[UIAlertAction actionWithTitle:[HelloHelper strWithUTF8Hex:@"e5bc80e5a78b"] style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        [HelloHelper log:@"用户确认顺发, 开始发送"];
        self.isRunning = YES;
        self.alreadySent = 0;
        [self.sentArray removeAllObjects];  // 每次任务重置去重记录
        self.totalConversations = self.conversationArray.count; // 快照总数, 用于倒计时
        [self updateCountdownLabel];        // 初始显示倒计时
        [self startTask];
    }]];

    dispatch_async(dispatch_get_main_queue(), ^{
        [hostVC presentViewController:alert animated:YES completion:nil];
    });
}

- (UIViewController *)topViewController {
    UIViewController *root = [UIApplication sharedApplication].keyWindow.rootViewController;
    while (root.presentedViewController) {
        root = root.presentedViewController;
    }
    return root;
}

- (void)startTask {
    if (!self.isRunning) return;
    [HelloHelper log:@"startTask: delay=%.1f activeTime=%ld", self.sendDelay, (long)self.activeTime];

    // 会话列表已在 startSendWithVc 里加载好

    [self.timer invalidate];
    NSTimeInterval interval = (self.sendDelay > 0 ? self.sendDelay : 0.9);
    self.timer = [NSTimer timerWithTimeInterval:interval
                                         target:self
                                       selector:@selector(sendNext)
                                       userInfo:nil
                                        repeats:YES];
    [[NSRunLoop mainRunLoop] addTimer:self.timer forMode:NSRunLoopCommonModes];
    [self.timer fire];
}

- (void)stopTask {
    self.isRunning = NO;
    [self.timer invalidate];
    self.timer = nil;
    [HelloCountdownLabel hide]; // 停止时隐藏倒计时
    [self saveData];
}

// 任务运行中则重新显示倒计时 (页面切回时调用)
- (void)refreshCountdownIfRunning {
    if (self.isRunning) {
        [self updateCountdownLabel];
    } else {
        [HelloCountdownLabel hide];
    }
}

// 更新悬浮倒计时标签 (屏幕中间上方, 白底黑字)
// 总数固定 = 检测到的会话总数 (174人 -> 174 173 172 ...)
- (void)updateCountdownLabel {
    NSInteger total = self.totalConversations;
    if (total <= 0) {
        total = self.conversationArray.count; // 兜底
    }
    NSInteger remain = total - self.alreadySent;
    if (remain < 0) remain = 0;
    // 前缀 "顺发" (e9a1bae58f91), 单位 "人" (e4baba)
    [HelloCountdownLabel showWithPrefix:[HelloHelper strWithUTF8Hex:@"e9a1bae58f91"]
                                 remain:remain
                                   unit:[HelloHelper strWithUTF8Hex:@"e4baba"]];
}

#pragma mark - 会话列表获取

- (void)loadConversations {
    [self.conversationArray removeAllObjects];
    UIViewController *listVC = self.listVC;
    if (!listVC) {
        [HelloHelper log:@"loadConversations: listVC 为 nil"];
        return;
    }

    // 1. 优先从 _useCase 的 allConversationsInMemory 拿 (真实数据源)
    @try {
        id useCase = [listVC valueForKey:@"useCase"];
        if (useCase) {
            SEL allSel = NSSelectorFromString(@"allConversationsInMemory");
            if ([useCase respondsToSelector:allSel]) {
                id arr = ((id(*)(id, SEL))objc_msgSend)(useCase, allSel);
                if ([arr isKindOfClass:[NSArray class]] && [arr count] > 0) {
                    [self filterRealConversations:arr];
                    [HelloHelper log:@"loadConversations: allConversationsInMemory 拿到 %ld 个会话(过滤后 %ld)", (long)[arr count], (long)self.conversationArray.count];
                    return;
                }
            }
            // 2. 备选: allListUsecase 逐个取
            SEL listSel = NSSelectorFromString(@"allListUsecase");
            if ([useCase respondsToSelector:listSel]) {
                id lists = ((id(*)(id, SEL))objc_msgSend)(useCase, listSel);
                if ([lists isKindOfClass:[NSArray class]] && [lists count] > 0) {
                    NSMutableArray *all = [NSMutableArray array];
                    for (id lu in lists) {
                        SEL cmSel = NSSelectorFromString(@"allConversationsInMemory");
                        if ([lu respondsToSelector:cmSel]) {
                            id sub = ((id(*)(id, SEL))objc_msgSend)(lu, cmSel);
                            if ([sub isKindOfClass:[NSArray class]]) [all addObjectsFromArray:sub];
                        }
                    }
                    if (all.count > 0) {
                        [self filterRealConversations:all];
                        [HelloHelper log:@"loadConversations: allListUsecase 汇总 %ld 个(过滤后 %ld)", (long)all.count, (long)self.conversationArray.count];
                        return;
                    }
                }
            }
        }
    } @catch (NSException *e) {
        [HelloHelper log:@"loadConversations: useCase 取值异常 %@", e];
    }

    // 3. 兜底: 尝试属性名
    NSArray *candidates = @[@"conversationArray", @"conversations", @"conversationList",
                            @"displayedConversations", @"dataArray", @"conversationModels"];
    for (NSString *key in candidates) {
        @try {
            if ([listVC respondsToSelector:NSSelectorFromString(key)]) {
                id v = [listVC valueForKey:key];
                if ([v isKindOfClass:[NSArray class]] && [v count] > 0) {
                    [self filterRealConversations:v];
                    [HelloHelper log:@"loadConversations: 通过属性 %@ 拿到 %ld 个会话(过滤后 %ld)", key, (long)[v count], (long)self.conversationArray.count];
                    return;
                }
            }
        } @catch (NSException *e) {}
    }

    [HelloHelper log:@"loadConversations: 无法获取会话列表!"];
}

// 判断是否“对方先开口”: 你没发过消息, 但对方发过
- (BOOL)isIncomingFirstConversation:(id)conv {
    BOOL hasMineCount = NO;
    NSInteger mine = 0;
    NSInteger total = 0;
    @try {
        id v = [conv valueForKey:@"mineMessagesCount"];
        if (v) { mine = [v integerValue]; hasMineCount = YES; }
    } @catch (NSException *e) {}
    @try {
        id v = [conv valueForKey:@"messageCount"];
        if (v) total = [v integerValue];
    } @catch (NSException *e) {}

    if (hasMineCount) {
        return (mine == 0 && total > 0);
    }

    // 兜底: mineMessagesCount 不存在时, 用"最后一条是否我发的"判断
    if (total <= 0) return NO;
    @try {
        id v = [conv valueForKey:@"latestMessageSentByCurrentUser"];
        if (v) return ![v boolValue];
    } @catch (NSException *e) {}
    return NO;
}

// 两段队列: 对方先开口的排前面, 其余排后面
- (void)prioritizeIncomingFirst {
    if (!self.prioritizeIncoming) {
        [HelloHelper log:@"[顺发排序] 已关闭(发送聊天框再发配对人), 保持原会话顺序"];
        return;
    }
    NSMutableArray *incoming = [NSMutableArray array];
    NSMutableArray *rest = [NSMutableArray array];
    for (id conv in self.conversationArray) {
        if ([self isIncomingFirstConversation:conv]) {
            [incoming addObject:conv];
        } else {
            [rest addObject:conv];
        }
    }
    [self.conversationArray removeAllObjects];
    [self.conversationArray addObjectsFromArray:incoming];
    [self.conversationArray addObjectsFromArray:rest];
    [HelloHelper log:@"[顺发排序] 对方先开口 %ld 个, 其余 %ld 个", (long)incoming.count, (long)rest.count];
}

// 过滤系统会话 (订阅账号/官方打招呼/折叠锚点等), 只保留真实用户会话
- (void)filterRealConversations:(NSArray *)arr {
    [self.conversationArray removeAllObjects];
    for (id conv in arr) {
        NSString *convID = [self conversationIDOf:conv];
        if (!convID) continue;
        // 真实用户会话 ID 是纯数字; 系统会话带字母前缀
        BOOL isNumeric = convID.length > 0;
        for (NSUInteger i = 0; i < convID.length; i++) {
            unichar c = [convID characterAtIndex:i];
            if (c < '0' || c > '9') { isNumeric = NO; break; }
        }
        if (isNumeric) {
            [self.conversationArray addObject:conv];
        } else {
            [HelloHelper log:@"过滤系统会话: %@", convID];
        }
    }
    [self prioritizeIncomingFirst];
}

- (void)grabConversations {
    UIViewController *listVC = self.listVC;
    if (!listVC) return;
    for (NSString *key in @[@"conversationArray", @"conversations", @"conversationList", @"displayedConversations"]) {
        @try {
            id v = [listVC valueForKey:key];
            if ([v isKindOfClass:[NSArray class]] && [v count] > 0) {
                self.conversationArray = [v mutableCopy];
                [HelloHelper log:@"grabConversations: 通过 %@ 拿到 %ld 个会话", key, (long)[v count]];
                return;
            }
        } @catch (NSException *e) {}
    }
}

#pragma mark - 顺发核心

- (void)sendNext {
    if (!self.isRunning) {
        [self.timer invalidate];
        return;
    }

    // 活跃时间控制: activeTime > 0 时, 达到数量则停止; =0 发送所有
    if (self.activeTime > 0 && self.alreadySent >= self.activeTime) {
        [HelloHelper log:@"顺发完成: 已发 %ld 条", (long)self.alreadySent];
        [self stopTask];
        return;
    }

    if (self.conversationArray.count == 0) {
        [HelloHelper log:@"sendNext: 会话列表为空, 重新加载..."];
        [self loadConversations];
        if (self.conversationArray.count == 0) {
            [HelloHelper log:@"sendNext: 无更多会话, 顺发结束"];
            [self stopTask];
            return;
        }
    }

    // 用循环代替递归, 避免栈溢出
    while (self.conversationArray.count > 0) {
        id conversation = [self.conversationArray popFirstObject];
        if (!conversation) break;

        // 去重
        NSString *convID = [self conversationIDOf:conversation];
        if (convID && [self.sentArray containsObject:convID]) {
            [HelloHelper log:@"sendNext: 会话 %@ 已发过, 跳过", convID];
            continue;  // 继续下一个, 不递归
        }
        if (convID) {
            [self.sentArray addObject:convID];
        }

        self.alreadySent++;

        // 更新倒计时标签 (每发一条刷新剩余条数)
        [self updateCountdownLabel];

        // 按 sendType 分发: 0=文本 1=图片 2=语音 3=视频
        switch (self.sendType) {
            case 1:
                [self sendImageToConversation:conversation];
                break;
            case 2:
                [self sendAudioToConversation:conversation];
                break;
            case 3:
                [self sendVideoToConversation:conversation];
                break;
            case 0:
            default:
                [self sendTextToConversation:conversation];
                break;
        }

        // 发送后延迟刷新会话列表, 让消息立即显示 (解决"假发")
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [self refreshConversationList];
        });

        return;  // 本次只发一个, 等定时器触发下一个
    }

    // 所有会话都已发过
    [HelloHelper log:@"sendNext: 所有会话均已处理"];
    [self stopTask];
}

- (NSString *)conversationIDOf:(id)conv {
    // 调试: 打印 otherID / objectID / primaryKeyID 对比, 确认探探 conversationID 到底是哪个
    id dbgOther = nil, dbgObject = nil, dbgPK = nil;
    @try { dbgOther = [conv valueForKey:@"otherID"]; } @catch (NSException *e) {}
    if (!dbgOther) @try { dbgOther = [conv valueForKey:@"_otherID"]; } @catch (NSException *e) {}
    @try { dbgObject = [conv valueForKey:@"objectID"]; } @catch (NSException *e) {}
    if (!dbgObject) @try { dbgObject = [conv valueForKey:@"_objectID"]; } @catch (NSException *e) {}
    @try { dbgPK = [conv valueForKey:@"primaryKeyID"]; } @catch (NSException *e) {}
    [HelloHelper log:@"conversationIDOf: otherID=%@ objectID=%@ primaryKeyID=%@", dbgOther, dbgObject, dbgPK];

    // 探探单聊 conversation 的唯一标识是 objectID (PUGBaseModel._objectID)
    if (dbgObject) return [NSString stringWithFormat:@"%@", dbgObject];
    if (dbgPK) return [NSString stringWithFormat:@"%@", dbgPK];
    // 兜底: otherID (对方 userID)
    if (dbgOther) return [NSString stringWithFormat:@"%@", dbgOther];
    // 最后兜底
    for (NSString *k in @[@"conversationID", @"userID"]) {
        @try {
            id v = [conv valueForKey:k];
            if (v) return [NSString stringWithFormat:@"%@", v];
        } @catch (NSException *e) {}
    }
    [HelloHelper log:@"conversationIDOf: 全部失败, 返回 nil"];
    return nil;
}

// 从 conversation 拿对方 userID (PUGConversation._otherID 是 NSString; 或 otherUser.objectID)
- (NSString *)userIDOf:(id)conv {
    // 1. 直接 _otherID (PUGConversation 的对方 userID, NSString 类型, 最可靠)
    @try {
        id otherID = [conv valueForKey:@"otherID"];
        if (otherID) return [NSString stringWithFormat:@"%@", otherID];
    } @catch (NSException *e) {}
    @try {
        id otherID = [conv valueForKey:@"_otherID"];
        if (otherID) return [NSString stringWithFormat:@"%@", otherID];
    } @catch (NSException *e) {}
    // 2. otherUser.objectID (PUGUser -> PUGBaseModel._objectID)
    @try {
        id otherUser = [conv valueForKey:@"otherUser"];
        if (otherUser) {
            id objID = [otherUser valueForKey:@"objectID"];
            if (objID) return [NSString stringWithFormat:@"%@", objID];
            id pid = [otherUser valueForKey:@"primaryKeyID"];
            if (pid) return [NSString stringWithFormat:@"%@", pid];
        }
    } @catch (NSException *e) {}
    // 3. 兜底
    for (NSString *k in @[@"userID", @"otherUserID", @"otherUserId"]) {
        @try {
            id v = [conv valueForKey:k];
            if (v) return [NSString stringWithFormat:@"%@", v];
        } @catch (NSException *e) {}
    }
    [HelloHelper log:@"userIDOf: 无法获取 userID"];
    return nil;
}

#pragma mark - 发送文本

- (void)sendTextToConversation:(id)conversation {
    [HelloHelper log:@"sendTextToConversation: conv=%@", conversation];

    // 解析要发送的文本 (#连续 @随机)
    NSString *raw = self.msgText ?: @"";
    if (!raw || raw.length == 0) {
        [HelloHelper log:@"sendTextToConversation: 文字为空, 不发送"];
        return;
    }
    NSArray *texts = [self textsToSend:raw];
    [HelloHelper log:@"sendTextToConversation: 本次发送 %ld 条文本", (long)texts.count];

    // 拿对方 userID
    NSString *userID = [self userIDOf:conversation];
    if (!userID) {
        [HelloHelper log:@"sendTextToConversation: 无法获取 userID, 尝试 conversationID"];
        userID = [self conversationIDOf:conversation];
    }
    if (!userID) {
        [HelloHelper log:@"sendTextToConversation: 无法获取 userID, 放弃发送"];
        return;
    }

    for (NSString *t in texts) {
        [self sendTextToUserID:userID text:t];
    }
}

// 直接用 PUGChatService 类方法发送文本 (走探探正常消息通道, 即时显示)
- (void)sendTextToUserID:(NSString *)userID text:(NSString *)text {
    [HelloHelper log:@"sendTextToUserID: userID=%@ text=%@", userID, text];
    Class chatService = NSClassFromString(@"PUGChatService");
    if (!chatService) {
        [HelloHelper log:@"sendTextToUserID: PUGChatService 类不存在!"];
        return;
    }
    SEL sendSel = NSSelectorFromString(@"sendMessage:userID:completion:");
    if (![chatService respondsToSelector:sendSel]) {
        [HelloHelper log:@"sendTextToUserID: PUGChatService 无 sendMessage:userID:completion:"];
        return;
    }
    // 签名 v40@0:8@16@24@?32  (self, _cmd, message, userID, completion)
    ((void(*)(id, SEL, id, id, id))objc_msgSend)(chatService, sendSel, text, userID, nil);
    [HelloHelper log:@"sendTextToUserID: 已调用 PUGChatService sendMessage:userID:completion:"];
}

// 兼容旧签名 (保留, 供可能的调用)
- (void)sendText:(id)msgVC text:(NSString *)text {
    [HelloHelper log:@"sendText(旧): 已废弃, 改用 PUGChatService 类方法"];
}// 解析文本: # 分割 -> 连续发送多条; @ 分割 -> 随机发送一条
- (NSArray *)textsToSend:(NSString *)raw {
    if (!raw || raw.length == 0) return @[];
    // 先判断 @ 随机
    if ([raw rangeOfString:@"@"].location != NSNotFound) {
        NSArray *parts = [raw componentsSeparatedByString:@"@"];
        NSMutableArray *valid = [NSMutableArray array];
        for (NSString *p in parts) {
            NSString *t = [p stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            if (t.length > 0) [valid addObject:t];
        }
        if (valid.count == 0) return @[];
        if (valid.count == 1) return @[valid[0]];
        // 随机选一条
        NSUInteger idx = arc4random_uniform((uint32_t)valid.count);
        return @[valid[idx]];
    }
    // # 连续
    if ([raw rangeOfString:@"#"].location != NSNotFound) {
        NSArray *parts = [raw componentsSeparatedByString:@"#"];
        NSMutableArray *valid = [NSMutableArray array];
        for (NSString *p in parts) {
            NSString *t = [p stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            if (t.length > 0) [valid addObject:t];
        }
        return valid;
    }
    // 单条
    return @[raw];
}

#pragma mark - 发送图片

- (void)sendImageToConversation:(id)conversation {
    UIImage *image = self.selectedImage;
    if (!image) {
        [HelloHelper log:@"sendImageToConversation: 未选择图片, 不发送"];
        return;
    }
    [HelloHelper log:@"sendImageToConversation: conv=%@ image=%@ mode=%ld", conversation, image, (long)self.imageSendMode];

    // 0 = 旧版 builder 链路; 失败/类不存在时自动回退现在链路
    if (self.imageSendMode == 0) {
        if ([self sendImageOldWay:conversation image:image]) return;
        [HelloHelper log:@"sendImageToConversation: 旧版发图不可用, 回退现在链路"];
    }

    // 现在链路: 离屏 msgVC + viewDidLoad + PUGEXIFImage + imagePickerHandler.sendImageConfirmed:
    id msgVC = [self createMessagesVCWithConversation:conversation];
    if (!msgVC) {
        [HelloHelper log:@"sendImageToConversation: 创建聊天页失败"];
        return;
    }
    SEL viewDidLoadSel = NSSelectorFromString(@"viewDidLoad");
    if ([msgVC respondsToSelector:viewDidLoadSel]) {
        ((void(*)(id, SEL))objc_msgSend)(msgVC, viewDidLoadSel);
        [HelloHelper log:@"sendImageToConversation: 已触发 viewDidLoad"];
    }
    [self sendImage:msgVC image:image];
}

// 旧版图片发送: 6.0.0 实际签名 v32@0:8@?16@?24 (builder block + completion block)
// 注意: 不是 messenger 对象，也不是 builder 对象；selector 在 PUGChatMessengerUseCase / PUGChatContext 上。
- (BOOL)sendImageOldWay:(id)conversation image:(UIImage *)image {
    id useCase = [self useCaseForConversation:conversation];
    if (!useCase) {
        [HelloHelper log:@"sendImageOldWay: 拿不到 useCase"];
        return NO;
    }
    SEL sendSel = NSSelectorFromString(@"sendImageMessageWithParameterBuilder:completion:");
    if (![useCase respondsToSelector:sendSel]) {
        [HelloHelper log:@"sendImageOldWay: %@ 无 sendImageMessageWithParameterBuilder:completion:", NSStringFromClass([useCase class])];
        return NO;
    }

    void (^builderBlock)(id) = ^(id builder) {
        if (!builder) {
            [HelloHelper log:@"sendImageOldWay: builder 为 nil"];
            return;
        }
        SEL setImageSel = NSSelectorFromString(@"setImage:");
        if ([builder respondsToSelector:setImageSel]) {
            @try {
                ((void(*)(id, SEL, id))objc_msgSend)(builder, setImageSel, image);
                [HelloHelper log:@"sendImageOldWay: builder setImage 成功"];
            } @catch (NSException *e) {
                [HelloHelper log:@"sendImageOldWay: builder setImage 异常 %@", e];
            }
        } else {
            [HelloHelper log:@"sendImageOldWay: builder 无 setImage:"];
        }
    };

    void (^completionBlock)(id, id, id) = ^(id msg, id response, id error) {
        [HelloHelper log:@"sendImageOldWay: completion msg=%@ error=%@", msg, error];
    };

    [HelloHelper log:@"sendImageOldWay: 调用 %@ 的 block 版发图", NSStringFromClass([useCase class])];
    ((void(*)(id, SEL, id, id))objc_msgSend)(useCase, sendSel, builderBlock, completionBlock);
    return YES;
}

// 拿会话对应的 useCase (6.0.0 的 sendImageMessage... 在 useCase 上)
- (id)useCaseForConversation:(id)conversation {
    Class chatService = NSClassFromString(@"PUGChatService");
    NSString *convID = [self conversationIDOf:conversation];
    if (chatService && convID) {
        SEL ucSel = NSSelectorFromString(@"messageUseCaseWithConversationID:shouldLoadMessages:");
        if ([chatService respondsToSelector:ucSel]) {
            id uc = ((id(*)(id, SEL, id, BOOL))objc_msgSend)(chatService, ucSel, convID, YES);
            if (uc) {
                [HelloHelper log:@"useCaseForConversation: 拿到 %@", NSStringFromClass([uc class])];
                return uc;
            }
        }
    }
    id msgVC = [self createMessagesVCWithConversation:conversation];
    if (msgVC) {
        @try {
            id uc = [msgVC valueForKey:@"useCase"];
            if (uc) return uc;
        } @catch (NSException *e) {}
    }
    return nil;
}

// v6 图片发送: PUGEXIFImage + imagePickerHandler.sendImageConfirmed:
- (void)sendImage:(id)msgVC image:(UIImage *)image {
    [HelloHelper log:@"sendImage: 进入, msgVC=%@ image=%@", NSStringFromClass([msgVC class]), image];

    Class exifCls = NSClassFromString(@"PUGEXIFImage");
    if (!exifCls) {
        [HelloHelper log:@"sendImage: PUGEXIFImage 类不存在!"];
        return;
    }
    id exifImage = [[exifCls alloc] init];
    if (!exifImage) {
        [HelloHelper log:@"sendImage: PUGEXIFImage alloc init 失败"];
        return;
    }
    @try {
        [exifImage setValue:image forKey:@"image"];
        [HelloHelper log:@"sendImage: setValue:image 成功"];
    } @catch (NSException *e) {
        [HelloHelper log:@"sendImage: setValue:image 失败 %@", e];
        @try { [exifImage setValue:image forKey:@"_image"]; [HelloHelper log:@"sendImage: setValue:_image 成功"]; }
        @catch (NSException *e2) { [HelloHelper log:@"sendImage: setValue:_image 也失败 %@", e2]; }
    }

    // 定位 imagePickerHandler
    id iph = nil;
    NSArray *candKeys = @[@"imagePickerHandler", @"_imagePickerHandler", @"mediaHandler", @"_mediaHandler",
                          @"imageHandler", @"_imageHandler", @"mediaPickerHandler", @"_mediaPickerHandler"];
    for (NSString *k in candKeys) {
        @try {
            id v = [msgVC valueForKey:k];
            if (v && [v respondsToSelector:NSSelectorFromString(@"sendImageConfirmed:")]) {
                [HelloHelper log:@"sendImage: 找到 %@ -> %@", k, NSStringFromClass([v class])];
                iph = v;
                break;
            }
        } @catch (NSException *e) {}
    }

    if (iph) {
        [HelloHelper log:@"sendImage: 调用 imagePickerHandler.sendImageConfirmed: PUGEXIFImage"];
        ((void(*)(id, SEL, id))objc_msgSend)(iph, NSSelectorFromString(@"sendImageConfirmed:"), exifImage);
        return;
    }

    SEL confirmedSel = NSSelectorFromString(@"sendImageConfirmed:");
    if ([msgVC respondsToSelector:confirmedSel]) {
        [HelloHelper log:@"sendImage: msgVC 直接调 sendImageConfirmed: PUGEXIFImage"];
        ((void(*)(id, SEL, id))objc_msgSend)(msgVC, confirmedSel, exifImage);
        return;
    }

    [HelloHelper log:@"sendImage: 未找到 imagePickerHandler"];
}

// 从 msgVC 定位 imagePickerHandler (供图片/视频发送复用)
- (id)imagePickerHandlerOfMsgVC:(id)msgVC {
    NSArray *candKeys = @[@"imagePickerHandler", @"_imagePickerHandler", @"mediaHandler", @"_mediaHandler",
                          @"imageHandler", @"_imageHandler", @"mediaPickerHandler", @"_mediaPickerHandler"];
    for (NSString *k in candKeys) {
        @try {
            id v = [msgVC valueForKey:k];
            if (v) {
                [HelloHelper log:@"imagePickerHandlerOfMsgVC: 找到 %@ -> %@", k, NSStringFromClass([v class])];
                return v;
            }
        } @catch (NSException *e) {}
    }
    return nil;
}

#pragma mark - 发送语音

- (void)sendAudioToConversation:(id)conversation {
    [HelloHelper log:@"sendAudioToConversation: conv=%@", conversation];

    // 若语音列表为空, 先扫描 Documents/audio/
    if (self.audioFileURLs.count == 0) {
        [self scanAudioFiles];
    }
    if (self.audioFileURLs.count == 0) {
        [HelloHelper log:@"sendAudioToConversation: 未找到语音文件, 不发送"];
        return;
    }
    NSURL *audioURL = [self.audioFileURLs firstObject];
    if (!audioURL) {
        [HelloHelper log:@"sendAudioToConversation: audioURL 为空"];
        return;
    }

    // 拿正确初始化的 messenger (PUGChatMessenger)
    id messenger = [self messengerForConversation:conversation];
    if (!messenger) {
        [HelloHelper log:@"sendAudioToConversation: 无法获取 messenger"];
        return;
    }

    // 正确路径: sendAudioMessageWithParameterBuilder:completion:
    // 逆向确认: builder 参数是 block void(^)(id<PUGChatSendAudioParameter>)
    // PUGChatSendAudioParameter 协议只有两个方法: audioFileURL / setAudioFileURL:
    // messenger 内部会自动填充 conversationID/otherID/msgType 等字段
    SEL sendAudioSel = NSSelectorFromString(@"sendAudioMessageWithParameterBuilder:completion:");
    if (![messenger respondsToSelector:sendAudioSel]) {
        [HelloHelper log:@"sendAudioToConversation: messenger 无 sendAudioMessageWithParameterBuilder:completion:"];
        return;
    }

    __block NSURL *url = audioURL;
    id builderBlock = ^(id param) {
        // param 是 id<PUGChatSendAudioParameter>, 只需 setAudioFileURL:
        SEL setSel = NSSelectorFromString(@"setAudioFileURL:");
        if (param && [param respondsToSelector:setSel]) {
            ((void(*)(id, SEL, id))objc_msgSend)(param, setSel, url);
            [HelloHelper log:@"sendAudioToConversation: block 设置 audioFileURL=%@ 成功", url];
        } else {
            [HelloHelper log:@"sendAudioToConversation: block param 无 setAudioFileURL: (class=%@)", param ? NSStringFromClass([param class]) : @"nil"];
        }
    };
    // completion 回调: void(^)(PUGMessage *, TXTResponse *, PUGError *)
    id completionBlock = ^(id msg, id response, id error) {
        if (error) {
            [HelloHelper log:@"sendAudioToConversation: 发送失败 error=%@", error];
        } else {
            [HelloHelper log:@"sendAudioToConversation: 发送成功 msg=%@", msg];
        }
    };
    [HelloHelper log:@"sendAudioToConversation: 调用 sendAudioMessageWithParameterBuilder:completion: (block)"];
    ((void(*)(id, SEL, id, id))objc_msgSend)(messenger, sendAudioSel, builderBlock, completionBlock);
    [HelloHelper log:@"sendAudioToConversation: 已调用发送"];
}



#pragma mark - 发送视频

- (void)sendVideoToConversation:(id)conversation {
    [HelloHelper log:@"sendVideoToConversation: conv=%@", conversation];

    if (self.videoFilePaths.count == 0) {
        [self scanVideoFiles];
    }
    if (self.videoFilePaths.count == 0) {
        [HelloHelper log:@"sendVideoToConversation: 未找到视频文件, 不发送"];
        return;
    }
    NSString *videoPath = [self.videoFilePaths firstObject];
    if (!videoPath) {
        [HelloHelper log:@"sendVideoToConversation: videoPath 为空"];
        return;
    }

    // 改用 v6 图片同款链路: 离屏 msgVC + viewDidLoad + imagePickerHandler.sendVideoWithFileUrl:
    // (builder+messenger 模式会导致闪退, 与图片历史问题同根源)
    id msgVC = [self createMessagesVCWithConversation:conversation];
    if (!msgVC) {
        [HelloHelper log:@"sendVideoToConversation: 创建聊天页失败"];
        return;
    }
    SEL viewDidLoadSel = NSSelectorFromString(@"viewDidLoad");
    if ([msgVC respondsToSelector:viewDidLoadSel]) {
        ((void(*)(id, SEL))objc_msgSend)(msgVC, viewDidLoadSel);
        [HelloHelper log:@"sendVideoToConversation: 已触发 viewDidLoad"];
    }

    id iph = [self imagePickerHandlerOfMsgVC:msgVC];
    if (!iph) {
        [HelloHelper log:@"sendVideoToConversation: 未找到 imagePickerHandler, 发送失败"];
        return;
    }

    SEL sendVideoSel = NSSelectorFromString(@"sendVideoWithFileUrl:");
    if (![iph respondsToSelector:sendVideoSel]) {
        [HelloHelper log:@"sendVideoToConversation: imagePickerHandler 无 sendVideoWithFileUrl:"];
        return;
    }

    NSURL *videoURL = [NSURL fileURLWithPath:videoPath];
    [HelloHelper log:@"sendVideoToConversation: 调用 sendVideoWithFileUrl: %@", videoURL];
    ((void(*)(id, SEL, id))objc_msgSend)(iph, sendVideoSel, videoURL);
    [HelloHelper log:@"sendVideoToConversation: 已调用 sendVideoWithFileUrl:"];
}

// 通用: 拿 messenger 并发送 builder 消息
- (void)sendViaMessenger:(id)conversation selectorName:(NSString *)selName builder:(id)builder {
    id messenger = [self messengerForConversation:conversation];
    if (!messenger) {
        [HelloHelper log:@"sendViaMessenger: 无法获取 messenger (%@)", selName];
        return;
    }
    SEL sendSel = NSSelectorFromString(selName);
    if (![messenger respondsToSelector:sendSel]) {
        [HelloHelper log:@"sendViaMessenger: messenger 无 %@", selName];
        return;
    }
    // 签名 v32@0:8@16@?24 (self, _cmd, builder, completion) —— builder 是对象
    ((void(*)(id, SEL, id, id))objc_msgSend)(messenger, sendSel, builder, nil);
    [HelloHelper log:@"sendViaMessenger: 已调用 %@", selName];
}

// 获取 messenger: 优先 [PUGChatService chatMessengerWithConversationID:isGroupChat:]
- (id)messengerForConversation:(id)conversation {
    Class chatService = NSClassFromString(@"PUGChatService");
    NSString *convID = [self conversationIDOf:conversation];

    // 1. chatMessengerWithConversationID:isGroupChat: (类方法)
    if (chatService) {
        SEL sel = NSSelectorFromString(@"chatMessengerWithConversationID:isGroupChat:");
        if ([chatService respondsToSelector:sel] && convID) {
            // 签名 @28@0:8@16B24
            id m = ((id(*)(id, SEL, id, BOOL))objc_msgSend)(chatService, sel, convID, NO);
            if (m) {
                [HelloHelper log:@"messengerForConversation: 通过 chatMessengerWithConversationID 拿到 %@", NSStringFromClass([m class])];
                return m;
            }
        }
    }

    // 2. messageUseCaseWithConversationID:shouldLoadMessages: -> messenger
    if (chatService && convID) {
        SEL ucSel = NSSelectorFromString(@"messageUseCaseWithConversationID:shouldLoadMessages:");
        if ([chatService respondsToSelector:ucSel]) {
            id useCase = ((id(*)(id, SEL, id, BOOL))objc_msgSend)(chatService, ucSel, convID, YES);
            if (useCase) {
                id m = [self messengerFromUseCase:useCase];
                if (m) return m;
            }
        }
    }

    // 3. 兜底: 从离屏 msgVC 拿 messenger (旧方案)
    id msgVC = [self createMessagesVCWithConversation:conversation];
    if (msgVC) {
        id m = [self messengerFromUseCase:[msgVC valueForKey:@"useCase"]];
        if (m) return m;
        m = [msgVC valueForKey:@"messenger"];
        if (m) return m;
    }

    [HelloHelper log:@"messengerForConversation: 全部失败"];
    return nil;
}

// 从 useCase 拿 messenger (messenger 属性 / _messenger / messageSender)
- (id)messengerFromUseCase:(id)useCase {
    if (!useCase) return nil;
    @try {
        id m = [useCase valueForKey:@"messenger"];
        if (m) { [HelloHelper log:@"messengerFromUseCase: useCase.messenger -> %@", NSStringFromClass([m class])]; return m; }
    } @catch (NSException *e) {}
    @try {
        id m = [useCase valueForKey:@"_messenger"];
        if (m) { [HelloHelper log:@"messengerFromUseCase: useCase._messenger -> %@", NSStringFromClass([m class])]; return m; }
    } @catch (NSException *e) {}
    @try {
        id m = [useCase valueForKey:@"messageSender"];
        if (m) { [HelloHelper log:@"messengerFromUseCase: useCase.messageSender -> %@", NSStringFromClass([m class])]; return m; }
    } @catch (NSException *e) {}
    return nil;
}

#pragma mark - 扫描语音/视频文件

- (void)scanAudioFiles {
    [self.audioFileURLs removeAllObjects];
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *docDir = paths.count > 0 ? paths[0] : NSTemporaryDirectory();
    NSString *audioDir = [docDir stringByAppendingPathComponent:@"audio"];
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:audioDir]) {
        [HelloHelper log:@"scanAudioFiles: 目录不存在 %@", audioDir];
        return;
    }
    NSArray *files = [fm contentsOfDirectoryAtPath:audioDir error:nil];
    files = [files sortedArrayUsingSelector:@selector(compare:)];
    for (NSString *name in files) {
        NSString *low = [name lowercaseString];
        if ([low hasSuffix:@".m4a"] || [low hasSuffix:@".mp3"] || [low hasSuffix:@".wav"] || [low hasSuffix:@".caf"]) {
            NSString *full = [audioDir stringByAppendingPathComponent:name];
            [self.audioFileURLs addObject:[NSURL fileURLWithPath:full]];
            [HelloHelper log:@"scanAudioFiles: 找到语音 %@", name];
        }
    }
    [HelloHelper log:@"scanAudioFiles: 共 %ld 个语音文件", (long)self.audioFileURLs.count];
}

- (void)scanVideoFiles {
    [self.videoFilePaths removeAllObjects];
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *docDir = paths.count > 0 ? paths[0] : NSTemporaryDirectory();
    NSString *videoDir = [docDir stringByAppendingPathComponent:@"video"];
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:videoDir]) {
        [HelloHelper log:@"scanVideoFiles: 目录不存在 %@", videoDir];
        return;
    }
    NSArray *files = [fm contentsOfDirectoryAtPath:videoDir error:nil];
    files = [files sortedArrayUsingSelector:@selector(compare:)];
    for (NSString *name in files) {
        NSString *low = [name lowercaseString];
        if ([low hasSuffix:@".mp4"] || [low hasSuffix:@".mov"] || [low hasSuffix:@".m4v"]) {
            NSString *full = [videoDir stringByAppendingPathComponent:name];
            [self.videoFilePaths addObject:full];
            [HelloHelper log:@"scanVideoFiles: 找到视频 %@", name];
        }
    }
    [HelloHelper log:@"scanVideoFiles: 共 %ld 个视频文件", (long)self.videoFilePaths.count];
}

#pragma mark - 刷新会话列表 (解决"假发": 发送后立即刷新)

// 发送成功后刷新会话列表, 让新消息立即显示, 不必手动点界面
- (void)refreshConversationList {
    UIViewController *listVC = self.listVC;
    Class chatService = NSClassFromString(@"PUGChatService");

    // 1. 拉最新会话列表 (服务层, 异步)
    if (chatService) {
        SEL loadSel = NSSelectorFromString(@"loadNewerConversationsWithCompletionBlock:");
        if ([chatService respondsToSelector:loadSel]) {
            [HelloHelper log:@"refreshConversationList: 调用 loadNewerConversationsWithCompletionBlock:"];
            ((void(*)(id, SEL, id))objc_msgSend)(chatService, loadSel, nil);
        }
    }

    if (listVC) {
        // 2. processConversationChanges: 无参数, 探探处理会话变化并刷新UI的正确入口
        SEL pcSel = NSSelectorFromString(@"processConversationChanges");
        if ([listVC respondsToSelector:pcSel]) {
            @try {
                [HelloHelper log:@"refreshConversationList: 调用 listVC processConversationChanges"];
                ((void(*)(id, SEL))objc_msgSend)(listVC, pcSel);
            } @catch (NSException *e) {}
        }

        // 3. 直接拿 conversationListTableView 调 reloadData (最可靠的UI重绘)
        @try {
            SEL tvSel = NSSelectorFromString(@"conversationListTableView");
            if ([listVC respondsToSelector:tvSel]) {
                id tv = ((id(*)(id, SEL))objc_msgSend)(listVC, tvSel);
                if (tv && [tv respondsToSelector:@selector(reloadData)]) {
                    [HelloHelper log:@"refreshConversationList: 直接调 tableView reloadData"];
                    [tv reloadData];
                }
            }
        } @catch (NSException *e) {}

        // 4. reloadTableView: 需要参数, 传 nil 可能无效, 保留但放到最后
        SEL reloadSel = NSSelectorFromString(@"reloadTableView:");
        if ([listVC respondsToSelector:reloadSel]) {
            @try {
                [HelloHelper log:@"refreshConversationList: 调用 listVC reloadTableView:"];
                ((void(*)(id, SEL, id))objc_msgSend)(listVC, reloadSel, nil);
            } @catch (NSException *e) {}
        }
        SEL loadAllSel = NSSelectorFromString(@"loadAllConversations");
        if ([listVC respondsToSelector:loadAllSel]) {
            @try {
                [HelloHelper log:@"refreshConversationList: 调用 listVC loadAllConversations"];
                ((void(*)(id, SEL))objc_msgSend)(listVC, loadAllSel);
            } @catch (NSException *e) {}
        }
    }
}

#pragma mark - 创建聊天页

- (id)createMessagesVCWithConversation:(id)conversation {
    Class msgVCClass = NSClassFromString(@"PUGMessagesViewController");
    if (!msgVCClass) {
        [HelloHelper log:@"createMessagesVC: PUGMessagesViewController 类不存在!"];
        return nil;
    }

    id msgVC = nil;

    // 1. initWithConversation:shouldLoadMessages:
    SEL initSel = NSSelectorFromString(@"initWithConversation:shouldLoadMessages:");
    if ([msgVCClass instancesRespondToSelector:initSel]) {
        msgVC = ((id(*)(id, SEL, id, BOOL))objc_msgSend)([msgVCClass alloc], initSel, conversation, YES);
        if (msgVC) {
            [HelloHelper log:@"createMessagesVC: 用 initWithConversation:shouldLoadMessages: 成功"];
            return msgVC;
        }
    }

    // 2. initWithConversation:
    SEL initSel2 = NSSelectorFromString(@"initWithConversation:");
    if ([msgVCClass instancesRespondToSelector:initSel2]) {
        msgVC = ((id(*)(id, SEL, id))objc_msgSend)([msgVCClass alloc], initSel2, conversation);
        if (msgVC) {
            [HelloHelper log:@"createMessagesVC: 用 initWithConversation: 成功"];
            return msgVC;
        }
    }

    // 3. initWithConversationID:shouldLoadMessages:
    SEL initSel3 = NSSelectorFromString(@"initWithConversationID:shouldLoadMessages:");
    if ([msgVCClass instancesRespondToSelector:initSel3]) {
        id convID = [self conversationIDOf:conversation];
        if (convID) {
            msgVC = ((id(*)(id, SEL, id, BOOL))objc_msgSend)([msgVCClass alloc], initSel3, convID, YES);
            if (msgVC) {
                [HelloHelper log:@"createMessagesVC: 用 initWithConversationID:shouldLoadMessages: 成功"];
                return msgVC;
            }
        }
    }

    [HelloHelper log:@"createMessagesVC: 未找到可用的初始化方法!"];
    return nil;
}

@end
