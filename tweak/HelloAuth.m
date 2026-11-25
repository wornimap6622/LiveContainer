//
//  HelloAuth.m
//  远程授权校验实现
//
//  直链: https://gitee.com/wornimap/ggtrtt/raw/master/保密协议.txt
//  内容: 1=正常, 2=停止
//
#import "HelloAuth.h"
#import "HelloHelper.h"
#import "HelloXihuanManager.h"
#import "HelloSendMgr.h"
#import "HelloGlobalBall.h"
#import <UIKit/UIKit.h>

// 授权直链 (UTF-8 hex 编码存储, 避免明文)
// https://gitee.com/wornimap/ggtrtt/raw/master/%E4%BF%9D%E5%AF%86%E5%8D%8F%E8%AE%AE.txt
static NSString *kEncodedURL = @"68747470733a2f2f67697465652e636f6d2f776f726e696d61702f6767747274742f7261772f6d61737465722f2545342542462539442545352541462538362545352538442538462545382541452541452e747874";

@interface HelloAuth ()
@property (nonatomic, assign) BOOL passed;
@property (nonatomic, assign) BOOL checked;
- (void)doCheck;
- (void)notifyPassed;
@end

@implementation HelloAuth

+ (instancetype)shared {
    static HelloAuth *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[HelloAuth alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _passed = NO;    // 默认拦截 (成功一次后才放行)
        _checked = NO;
    }
    return self;
}

// 从 hex 解码出 URL 字符串
- (NSString *)authURL {
    NSString *hex = kEncodedURL;
    NSMutableData *data = [NSMutableData dataWithCapacity:hex.length / 2];
    for (NSUInteger i = 0; i + 1 < hex.length; i += 2) {
        NSString *byteStr = [hex substringWithRange:NSMakeRange(i, 2)];
        unsigned int byte = 0;
        [[NSScanner scannerWithString:byteStr] scanHexInt:&byte];
        uint8_t b = (uint8_t)byte;
        [data appendBytes:&b length:1];
    }
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

// 提取授权数字: 优先精确匹配【1】/【2】, 兜底取首个数字字符, 无数字返回 -1
// 修复: 之前"写【1】也拦截"是 extractNumber 被内容里其他数字(时间戳/BOM)干扰, 现在优先识别【N】标记
- (NSInteger)extractNumberFromString:(NSString *)s {
    if (!s || s.length == 0) return -1;
    // 1. 精确匹配【1】或【2】
    if ([s containsString:@"【1】"]) return 1;
    if ([s containsString:@"【2】"]) return 2;
    // 2. 兜底: 首个数字字符
    for (NSUInteger i = 0; i < s.length; i++) {
        unichar ch = [s characterAtIndex:i];
        if (ch >= '0' && ch <= '9') {
            return ch - '0';
        }
    }
    return -1;
}

// 心跳计数 (放行后每次成功重校验 +1)
static NSInteger g_heartbeatCount = 0;

// 联系作者弹窗只触发一次 (进程内标记, 重启探探后重置)
static BOOL g_contactAlertShown = NO;

// 全局拦截标志: 一旦被【2】拦截, 置为 YES, 红球/蓝球/悬浮球挂载时检查此标志不再挂载
// 默认拦截(YES): 启动先隐藏, 首次校验返回【1】才放行
static BOOL g_authBlocked = YES;

// 云端拦截标志: 记录当前拦截是否由云端停用导致 (与 Gitee 直链拦截区分)
static BOOL g_cloudBlocked = NO;

// 持久化: 授权状态 + 心跳间隔 (复用 NSUserDefaults 标准套件, 跨重启保留)
static NSString *kAuthOKKey = @"xh_auth_ok";           // 是否曾成功校验过(【1】)
static NSString *kIntervalKey = @"xh_heartbeat_interval"; // 心跳间隔(秒), 默认 90

BOOL XHAuthBlocked(void) {
    return g_authBlocked;
}

// 读取心跳间隔(秒): 优先持久化值, 否则默认 90
static double _heartbeatInterval(void) {
    NSInteger sec = [[NSUserDefaults standardUserDefaults] integerForKey:kIntervalKey];
    if (sec <= 0) sec = 90;
    // 限定在合理范围 5~3600 秒
    if (sec < 5) sec = 5;
    if (sec > 3600) sec = 3600;
    return (double)sec;
}

// 外部设置心跳间隔(秒): 供设置面板/输入框调用, 持久化
void XHSetHeartbeatInterval(double seconds) {
    NSInteger sec = (NSInteger)seconds;
    if (sec < 5) sec = 5;
    if (sec > 3600) sec = 3600;
    [[NSUserDefaults standardUserDefaults] setInteger:sec forKey:kIntervalKey];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [HelloHelper log:@"[授权] 心跳间隔已设为 %ld 秒", (long)sec];
}

- (void)startCheck {
    if (self.checked) {
        [HelloHelper log:@"[授权] 已启动过校验, 跳过"];
        return;
    }
    self.checked = YES;

    // 成功一次即显示: 启动时读持久化授权状态, 若之前成功过(【1】)则直接放行, 不拦截
    BOOL cachedOK = [[NSUserDefaults standardUserDefaults] boolForKey:kAuthOKKey];
    if (cachedOK) {
        self.passed = YES;
        g_authBlocked = NO;
        [HelloHelper log:@"[授权] 检测到历史授权成功, 直接放行 (飞行模式/离线也显示)"];
    } else {
        self.passed = NO;
        g_authBlocked = YES;
        [HelloHelper log:@"[授权] 无历史授权记录, 先拦截, 等待首次校验"];
    }

    double interval = _heartbeatInterval();
    [HelloHelper log:@"[授权] 校验启动: 首检 5s 后, 之后每 %.0fs 心跳一次", interval];

    // 首次校验: 5 秒后
    __weak typeof(self) weakSelf = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        typeof(self) self = weakSelf;
        if (!self) return;
        [HelloHelper log:@"[授权] 首次校验触发"];
        [self doCheck];
    });
}

// 安排下一次心跳 (放行后按可配置间隔循环)
- (void)scheduleHeartbeat {
    double interval = _heartbeatInterval();
    __weak typeof(self) weakSelf = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(interval * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        typeof(self) self = weakSelf;
        if (!self) return;
        // 已被【2】拦截则停止心跳
        if (g_authBlocked && !self.passed) return;
        [HelloHelper log:@"[授权] 心跳触发, 重新校验"];
        [self doCheck];
    });
}

// 实际执行授权校验请求
- (void)doCheck {
    NSString *urlStr = [self authURL];
    // 加时间戳参数绕过 CDN 缓存 (Gitee raw 有 60 秒缓存)
    NSString *sep = [urlStr rangeOfString:@"?"].location == NSNotFound ? @"?" : @"&";
    urlStr = [NSString stringWithFormat:@"%@%@t=%.0f", urlStr, sep, [[NSDate date] timeIntervalSince1970]];
    NSURL *url = [NSURL URLWithString:urlStr];
    if (!url) {
        [HelloHelper log:@"[授权] URL 解析失败, 拦截"];
        self.passed = NO;
        return;
    }

    [HelloHelper log:@"[授权] 开始请求直链 %@", urlStr];

    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url
                                                       cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                                                   timeoutInterval:10.0];
    [req setValue:@"no-cache" forHTTPHeaderField:@"Cache-Control"];
    [req setValue:@"no-cache" forHTTPHeaderField:@"Pragma"];
    NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    cfg.timeoutIntervalForRequest = 10.0;
    NSURLSession *session = [NSURLSession sessionWithConfiguration:cfg];

    __weak typeof(self) weakSelf = self;
    NSURLSessionDataTask *task = [session dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
        dispatch_async(dispatch_get_main_queue(), ^{
            typeof(self) self = weakSelf;
            if (!self) return;

            if (err || !data) {
                // 网络失败/断网: 保持当前状态不拦截(成功过一次就继续显示), 只重试
                [HelloHelper log:@"[授权] 网络失败(保持当前状态, 稍后重试): %@", err ?: @"无数据"];
                [self scheduleHeartbeat];
                return;
            }

            NSString *content = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (!content) content = [[NSString alloc] initWithData:data encoding:NSASCIIStringEncoding];
            content = [content stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];

            [HelloHelper log:@"[授权] 响应内容=%@", content];

            NSInteger num = [self extractNumberFromString:content];
            if (num == 1) {
                [HelloHelper log:@"[授权] 校验通过(内容=1), 放行"];
                self.passed = YES;
                g_authBlocked = NO;
                // 成功一次即持久化: 之后飞行模式/重启也能显示
                [[NSUserDefaults standardUserDefaults] setBool:YES forKey:kAuthOKKey];
                [[NSUserDefaults standardUserDefaults] synchronize];
                g_heartbeatCount++;
                [HelloHelper log:@"[授权] 心跳重校验 #%ld", (long)g_heartbeatCount];
                [self notifyPassed];
                // 放行后按可配置间隔持续心跳
                [self scheduleHeartbeat];
            } else if (num == 2) {
                [HelloHelper log:@"[授权] 识别为 2, 拦截"];
                self.passed = NO;
                g_authBlocked = YES;
                // 收到【2】才清除持久化授权, 下次启动重新拦截
                [[NSUserDefaults standardUserDefaults] setBool:NO forKey:kAuthOKKey];
                [[NSUserDefaults standardUserDefaults] synchronize];
                [self removeButtons];
                // 联系作者弹窗: 首次识别到【2】后延迟 60 秒弹一次, 之后不再弹
                [self scheduleContactAlertOnce];
            } else {
                // 未识别到有效数字: 保持当前状态, 不轻易拦截(避免误判), 重试
                [HelloHelper log:@"[授权] 未识别到有效数字(%@), 保持状态重试", content];
                [self scheduleHeartbeat];
            }
        });
    }];
    [task resume];
}

// 云端停用控制入口 (HelloCloud 心跳回调调用)
// blocked=YES -> 拦截(隐藏所有功能); NO -> 仅当拦截是云端造成的才恢复
- (void)setCloudBlocked:(BOOL)blocked {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (blocked) {
            if (!g_cloudBlocked) {
                [HelloHelper log:@"[授权] 云端停用: 触发拦截"];
            }
            g_cloudBlocked = YES;
            g_authBlocked = YES;
            self.passed = NO;
            [self removeButtons];
            [self scheduleContactAlertOnce];
        } else {
            // 只有当前拦截是云端造成时才解除; Gitee 直链的拦截不受影响
            if (g_cloudBlocked) {
                [HelloHelper log:@"[授权] 云端恢复: 解除拦截"];
                g_cloudBlocked = NO;
                g_authBlocked = NO;
                self.passed = YES;
                [self notifyPassed];
            } else {
                // 云端未拦截过, 无需处理 (避免误解除 Gitee 拦截)
            }
        }
    });
}

// 放行通知: 校验通过后刷新插件按钮 (通知各模块恢复挂载)
- (void)notifyPassed {
    [[NSNotificationCenter defaultCenter] postNotificationName:@"xh_auth_passed" object:nil];
    [HelloHelper log:@"[授权] 收到放行通知, 刷新插件按钮"];
}

// 移除所有功能入口 (拦截时调用): 悬浮球 + 红球 + 蓝球 + 停止任务
- (void)removeButtons {
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            // 隐藏全局悬浮球 (所有开关面板 + 一键新机入口)
            XHHideGlobalBall();
            [HelloHelper log:@"[授权] 已隐藏全局悬浮球"];
            UIButton *redBtn = [HelloXihuanManager shared].outActionBtn;
            if (redBtn) {
                [redBtn removeFromSuperview];
                [HelloXihuanManager shared].outActionBtn = nil;
                [HelloHelper log:@"[授权] 已移除划卡红球按钮"];
            }
            UIButton *blueBtn = [HelloSendMgr shared].sendEntryBtn;
            if (blueBtn) {
                [blueBtn removeFromSuperview];
                [HelloSendMgr shared].sendEntryBtn = nil;
                [HelloHelper log:@"[授权] 已移除顺发蓝球按钮"];
            }
            // 停止可能正在运行的任务
            if ([HelloXihuanManager shared].isStart) {
                [[HelloXihuanManager shared] stopTask];
            }
            if ([HelloSendMgr shared].isRunning) {
                [[HelloSendMgr shared] stopTask];
            }
        } @catch (NSException *e) {
            [HelloHelper log:@"[授权] 移除按钮失败: %@", e];
        }
    });
}

// 联系作者弹窗: 首次识别到【2】后延迟 60 秒弹一次, 整个运行期间只弹一次
- (void)scheduleContactAlertOnce {
    if (g_contactAlertShown) {
        [HelloHelper log:@"[授权] 联系作者弹窗已弹过, 跳过"];
        return;
    }
    __weak typeof(self) weakSelf = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(60.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        typeof(self) self = weakSelf;
        if (!self) return;
        if (g_contactAlertShown) return;
        g_contactAlertShown = YES;
        [HelloHelper log:@"[授权] 延迟 60 秒后弹出联系作者提示"];
        [self showContactAlert];
    });
}

- (void)showContactAlert {
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            UIWindow *win = nil;
            if (@available(iOS 13.0, *)) {
                for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
                    if (scene.activationState == UISceneActivationStateForegroundActive) {
                        for (UIWindow *w in scene.windows) {
                            if (w.isKeyWindow) { win = w; break; }
                        }
                    }
                }
            }
            if (!win) {
                win = [UIApplication sharedApplication].keyWindow;
            }

            UIViewController *root = win.rootViewController;
            while (root.presentedViewController) root = root.presentedViewController;

            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"提示"
                                                                           message:@"请联系作者"
                                                                    preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
            [root presentViewController:alert animated:YES completion:nil];
        } @catch (NSException *e) {
            [HelloHelper log:@"[授权] 弹窗失败: %@", e];
        }
    });
}

@end
