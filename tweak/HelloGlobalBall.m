//
//  HelloGlobalBall.m
//  全局悬浮球: 一键新机 + 版本填写
//  挂载方式: 直接加到探探自己的 keyWindow 上(非独立window), 绝不干扰探探触摸
//
#import "HelloGlobalBall.h"
#import "HelloHelper.h"
#import "HelloAuth.h"
#import <objc/runtime.h>
#import <objc/message.h>

void XHNewDevice(void);
void XHSetSpoofVersion(NSString *version);
NSString *XHGetSpoofVersion(void);

// 统一开关接口 (实现在 Tweak.m, 跨文件可见)
BOOL XHGetSwitch(NSString *key, BOOL defaultVal);
void XHSetSwitch(NSString *key, BOOL on);

// 开关 key (与 Tweak.m 中一致)
static NSString *const kSwVip      = @"xh_switch.vip";       // 会员
static NSString *const kSwMatchLimit = @"xh_switch.match_limit"; // 解除匹配限制
static NSString *const kSwPopup    = @"xh_switch.popup";     // 弹窗
static NSString *const kSwPick     = @"xh_switch.pick";      // 四选一(合并: 次数限制 + 接口对接)
static NSString *const kSwSpoofVer = @"xh_switch.spoofver";  // 版本伪装
static NSString *const kSwDevice   = @"xh_switch.device";    // 设备改机
static NSString *const kSwVerifyPic = @"xh_switch.verify_picture"; // 人脸(头像)认证
static NSString *const kSwVerifyId  = @"xh_switch.verify_id";      // 实名(身份证)认证
static NSString *const kSwBlockClear = @"xh_switch.block_clear"; // 拦截清空登录态(默认关)
static NSString *const kSwSSL = @"xh_switch.ssl"; // 强制开启低版本网络(绕过SSL Pinning)
static NSString *const kSwLocation = @"xh_switch.location"; // 地图定位(坐标伪造, 默认关)

static NSString *const kGlobalBallPosKey = @"xh_ball_pos_global";
static const CGFloat kBallSize = 56.0;

static UIButton *g_ballBtn = nil;
static UIView *g_panelView = nil;
static UIView *g_maskView = nil;
static UITextField *g_verField = nil;
static NSMutableArray *g_switches = nil;   // 所有开关 (刷新状态用)

// ============ 拖动 ============
@interface XHGlobalBallDragHandler : NSObject
+ (instancetype)shared;
- (void)handlePan:(UIPanGestureRecognizer *)pan;
@end

static const void *kGBStartFrameAssoc = &kGBStartFrameAssoc;
static const void *kGBStartPointAssoc = &kGBStartPointAssoc;

// ============ 触摸穿透 window: 空白区域 hitTest 返回 nil, 只有球体/面板/遮罩响应 ============
@interface XHPassthroughWindow : UIWindow
@end
@implementation XHPassthroughWindow
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *hit = [super hitTest:point withEvent:event];
    // 只有命中球体按钮 / 面板 / 遮罩 才返回, 否则穿透到探探
    if (hit == self) return nil;
    return hit;
}
@end

@implementation XHGlobalBallDragHandler
+ (instancetype)shared {
    static XHGlobalBallDragHandler *inst = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ inst = [[XHGlobalBallDragHandler alloc] init]; });
    return inst;
}
- (void)handlePan:(UIPanGestureRecognizer *)pan {
    UIView *v = pan.view;
    if (pan.state == UIGestureRecognizerStateBegan) {
        objc_setAssociatedObject(v, kGBStartFrameAssoc, [NSValue valueWithCGRect:v.frame], OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        objc_setAssociatedObject(v, kGBStartPointAssoc, [NSValue valueWithCGPoint:[pan translationInView:v.superview]], OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    } else if (pan.state == UIGestureRecognizerStateChanged) {
        NSValue *sfv = objc_getAssociatedObject(v, kGBStartFrameAssoc);
        NSValue *spv = objc_getAssociatedObject(v, kGBStartPointAssoc);
        if (!sfv || !spv) return;
        CGRect sf = [sfv CGRectValue];
        CGPoint sp = [spv CGPointValue];
        CGPoint tr = [pan translationInView:v.superview];
        CGRect nf = sf;
        nf.origin.x = sf.origin.x + (tr.x - sp.x);
        nf.origin.y = sf.origin.y + (tr.y - sp.y);
        CGFloat sw = [UIScreen mainScreen].bounds.size.width;
        CGFloat sh = [UIScreen mainScreen].bounds.size.height;
        if (nf.origin.x < 0) nf.origin.x = 0;
        if (nf.origin.y < 0) nf.origin.y = 0;
        if (nf.origin.x + nf.size.width > sw) nf.origin.x = sw - nf.size.width;
        if (nf.origin.y + nf.size.height > sh) nf.origin.y = sh - nf.size.height;
        v.frame = nf;
    } else if (pan.state == UIGestureRecognizerStateEnded || pan.state == UIGestureRecognizerStateCancelled) {
        CGPoint p = v.frame.origin;
        [[NSUserDefaults standardUserDefaults] setObject:[NSString stringWithFormat:@"%.0f,%.0f", p.x, p.y] forKey:kGlobalBallPosKey];
        [[NSUserDefaults standardUserDefaults] synchronize];
    }
}
@end

// ============ 工具 ============
static void gb_hidePanel(void) {
    if (g_panelView) g_panelView.hidden = YES;
    if (g_maskView) g_maskView.hidden = YES;
    if (g_verField) [g_verField resignFirstResponder];
}

static void gb_showPanel(void) {
    if (!g_panelView) return;
    if (g_verField) g_verField.text = XHGetSpoofVersion();
    // 刷新所有开关状态 (从 NSUserDefaults 读取最新值)
    for (UISwitch *sw in g_switches) {
        NSString *key = objc_getAssociatedObject(sw, "xh_sw_key");
        if (key) sw.on = XHGetSwitch(key, NO);
    }
    CGFloat sw = [UIScreen mainScreen].bounds.size.width;
    CGFloat sh = [UIScreen mainScreen].bounds.size.height;
    CGFloat pw = sw - 32;
    CGFloat ph = g_panelView.frame.size.height;
    CGFloat px = (sw - pw) / 2;
    CGFloat ballY = g_ballBtn ? g_ballBtn.frame.origin.y : sh * 0.3;
    // 优先显示在球下方; 放不下则显示在球上方; 再放不下则居中
    CGFloat py = ballY + kBallSize + 16;
    if (py + ph > sh - 20) py = ballY - ph - 16;
    if (py < 20) py = (sh - ph) / 2;
    // 最终硬约束: 面板必须完整落在屏幕内 (上下各留 20pt 边距)
    if (py < 20) py = 20;
    if (py + ph > sh - 20) py = sh - ph - 20;
    if (py < 20) py = 20;
    g_panelView.frame = CGRectMake(px, py, pw, ph);
    g_maskView.frame = [UIScreen mainScreen].bounds;
    g_maskView.hidden = NO;
    g_panelView.hidden = NO;
    UIView *superV = g_ballBtn.superview;
    [superV bringSubviewToFront:g_maskView];
    [superV bringSubviewToFront:g_panelView];
    [superV bringSubviewToFront:g_ballBtn];
}

// ============ 面板构建 ============
// 创建一行开关 (标题 + UISwitch), defaultVal 指定未设置时的默认值
static void gb_addSwitch(UIView *panel, CGFloat *y, CGFloat pw, NSString *titleHex, NSString *key, BOOL defaultVal) {
    CGFloat rowY = *y;
    UILabel *label = [[UILabel alloc] initWithFrame:CGRectMake(18, rowY, pw - 90, 30)];
    label.text = [HelloHelper strWithUTF8Hex:titleHex];
    label.font = [UIFont systemFontOfSize:15];
    label.textColor = [UIColor whiteColor];
    [panel addSubview:label];

    UISwitch *sw = [[UISwitch alloc] initWithFrame:CGRectMake(pw - 18 - 51, rowY, 51, 31)];
    sw.on = XHGetSwitch(key, defaultVal);
    // 用关联对象把 key 绑到 switch 上, 切换时读取
    objc_setAssociatedObject(sw, "xh_sw_key", key, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    [sw addTarget:[XHGlobalBallDragHandler shared] action:@selector(didToggleSwitch:) forControlEvents:UIControlEventValueChanged];
    [panel addSubview:sw];
    if (!g_switches) g_switches = [NSMutableArray array];
    [g_switches addObject:sw];
    *y = rowY + 40;
}

static UIView *gb_buildPanel(void) {
    CGFloat sw = [UIScreen mainScreen].bounds.size.width;
    CGFloat sh = [UIScreen mainScreen].bounds.size.height;
    CGFloat pw = sw - 32;
    // 面板高度动态适配: 不超过屏幕高度的 75%, 且留出安全边距, 避免超屏
    CGFloat ph = 684;  // 内容总高度(11开关+版本+新机按钮)
    CGFloat maxPh = sh - 80;  // 上下各留 40pt 边距
    if (ph > maxPh) ph = maxPh;
    if (ph < 300) ph = 300;  // 最小高度保护(极小屏/横屏)
    UIView *panel = [[UIView alloc] initWithFrame:CGRectMake(0, 0, pw, ph)];
    panel.backgroundColor = [UIColor colorWithWhite:0.12 alpha:0.97];
    panel.layer.cornerRadius = 14;
    panel.layer.masksToBounds = YES;
    panel.hidden = YES;

    UIScrollView *scroll = [[UIScrollView alloc] initWithFrame:CGRectMake(0, 0, pw, ph)];
    scroll.showsVerticalScrollIndicator = YES;
    [panel addSubview:scroll];

    CGFloat y = 18;
    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(18, y, pw - 36, 24)];
    title.text = [HelloHelper strWithUTF8Hex:@"e585a8e5b180e8aebee7bdae"];
    title.font = [UIFont boldSystemFontOfSize:17];
    title.textColor = [UIColor whiteColor];
    [scroll addSubview:title];
    y += 34;

    // ---- 版本号放在最上面, 键盘弹出也不挡保存 ----
    UILabel *verLabel = [[UILabel alloc] initWithFrame:CGRectMake(18, y, 120, 20)];
    verLabel.text = [HelloHelper strWithUTF8Hex:@"e78988e69cace58fb7"];
    verLabel.font = [UIFont systemFontOfSize:13];
    verLabel.textColor = [UIColor lightGrayColor];
    [scroll addSubview:verLabel];
    y += 22;

    UITextField *tf = [[UITextField alloc] initWithFrame:CGRectMake(18, y, pw - 36 - 76, 38)];
    tf.borderStyle = UITextBorderStyleRoundedRect;
    tf.keyboardType = UIKeyboardTypeNumbersAndPunctuation;
    tf.textColor = [UIColor blackColor];
    tf.text = XHGetSpoofVersion();
    tf.placeholder = @"6.9.9";
    tf.backgroundColor = [UIColor whiteColor];
    [scroll addSubview:tf];
    g_verField = tf;

    UIButton *saveBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    [saveBtn setTitle:[HelloHelper strWithUTF8Hex:@"e4bf9de5ad98"] forState:UIControlStateNormal];
    [saveBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    saveBtn.backgroundColor = [UIColor colorWithRed:0.2 green:0.6 blue:1.0 alpha:1.0];
    saveBtn.layer.cornerRadius = 6;
    saveBtn.frame = CGRectMake(pw - 18 - 76, y, 76, 38);
    [saveBtn addTarget:[XHGlobalBallDragHandler shared] action:@selector(didClickSave) forControlEvents:UIControlEventTouchUpInside];
    [scroll addSubview:saveBtn];
    y += 54;

    // 功能开关区
    UILabel *swTitle = [[UILabel alloc] initWithFrame:CGRectMake(18, y, pw - 36, 20)];
    swTitle.text = [HelloHelper strWithUTF8Hex:@"e58a9fe883bde5bc80e585b3"];
    swTitle.font = [UIFont systemFontOfSize:13];
    swTitle.textColor = [UIColor lightGrayColor];
    [scroll addSubview:swTitle];
    y += 24;

    // 功能开关 (标题用 UTF8 hex 绕过编译期中文丢失)
    gb_addSwitch(scroll, &y, pw, @"e4bc9ae59198", kSwVip, NO);                 // 会员
    gb_addSwitch(scroll, &y, pw, @"e8a7a3e999a4e58cb9e9858de99990e588b6", kSwMatchLimit, NO); // 解除匹配限制(默认关)
    gb_addSwitch(scroll, &y, pw, @"e5b18fe894bde68980e69c89e5bcb9e7aa97", kSwPopup, NO); // 屏蔽所有弹窗
    gb_addSwitch(scroll, &y, pw, @"e6b4bbe4bd93e5bcbae588b6e58cb9e9858d", kSwPick, NO); // 活体强制匹配
    gb_addSwitch(scroll, &y, pw, @"e78988e69cace4bcaae8a385", kSwSpoofVer, NO); // 版本伪装
    gb_addSwitch(scroll, &y, pw, @"e8aebee5a487e694b9e69cba", kSwDevice, NO);  // 设备改机(默认关)
    gb_addSwitch(scroll, &y, pw, @"e59cb0e59bbee5ae9ae4bd8d", kSwLocation, NO); // 地图定位(默认关, 开=坐标伪造生效)
    gb_addSwitch(scroll, &y, pw, @"e4babae884b8e8aea4e8af81", kSwVerifyPic, NO); // 人脸认证
    gb_addSwitch(scroll, &y, pw, @"e5ae9ee5908de8aea4e8af81", kSwVerifyId, NO);  // 实名认证
    gb_addSwitch(scroll, &y, pw, @"e68ba6e688aae799bbe5bd95e98080e587ba", kSwBlockClear, NO); // 拦截登录退出(默认关)
    gb_addSwitch(scroll, &y, pw, @"e5bcbae588b6e5bc80e590afe4bd8ee78988e69cace7bd91e7bb9c", kSwSSL, NO); // 强制开启低版本网络(绕过SSL Pinning)
    y += 6;

    // 分隔线
    UIView *sep = [[UIView alloc] initWithFrame:CGRectMake(18, y, pw - 36, 1)];
    sep.backgroundColor = [UIColor colorWithWhite:0.3 alpha:1.0];
    [scroll addSubview:sep];
    y += 14;

    UIButton *mapBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    [mapBtn setTitle:[HelloHelper strWithUTF8Hex:@"e59cb0e59bbee5ae9ae4bd8d"] forState:UIControlStateNormal]; // 地图定位
    [mapBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    mapBtn.backgroundColor = [UIColor colorWithRed:0.1 green:0.6 blue:0.4 alpha:1.0];
    mapBtn.layer.cornerRadius = 8;
    mapBtn.frame = CGRectMake(18, y, pw - 36, 46);
    mapBtn.titleLabel.font = [UIFont boldSystemFontOfSize:15];
    [mapBtn addTarget:[XHGlobalBallDragHandler shared] action:@selector(didClickMap) forControlEvents:UIControlEventTouchUpInside];
    [scroll addSubview:mapBtn];
    y += 56;

    UIButton *resetBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    [resetBtn setTitle:[HelloHelper strWithUTF8Hex:@"e4b880e994aee696b0e69cba"] forState:UIControlStateNormal];
    [resetBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    resetBtn.backgroundColor = [UIColor colorWithRed:0.9 green:0.2 blue:0.2 alpha:1.0];
    resetBtn.layer.cornerRadius = 8;
    resetBtn.frame = CGRectMake(18, y, pw - 36, 50);
    resetBtn.titleLabel.font = [UIFont boldSystemFontOfSize:16];
    [resetBtn addTarget:[XHGlobalBallDragHandler shared] action:@selector(didClickReset) forControlEvents:UIControlEventTouchUpInside];
    [scroll addSubview:resetBtn];
    y += 66;

    scroll.contentSize = CGSizeMake(pw, y + 20);

    return panel;
}

@implementation XHGlobalBallDragHandler (Actions)

- (void)ballTapped {
    if (g_panelView.hidden) gb_showPanel(); else gb_hidePanel();
}

- (void)maskTapped {
    gb_hidePanel();
}

- (void)didToggleSwitch:(UISwitch *)sw {
    NSString *key = objc_getAssociatedObject(sw, "xh_sw_key");
    if (!key) return;
    BOOL on = sw.isOn;
    XHSetSwitch(key, on);
    // 提示 (用 UTF8 hex 规避中文)
    [HelloHelper toast:[HelloHelper strWithUTF8Hex:@"e5b7b2e4bf9de5ad98efbc8ce9878de590afe68ea2e68ea2e7949fe69588"]];
    [HelloHelper log:@"[开关] %@ -> %d", key, on];
}

- (void)didClickSave {
    NSString *v = [g_verField.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    XHSetSpoofVersion(v);
    [HelloHelper toast:[HelloHelper strWithUTF8Hex:@"e5b7b2e4bf9de5ad98e78988e69cace58fb7"]];
    gb_hidePanel();
}

- (void)didClickMap {
    Class m = NSClassFromString(@"LHMapVC");
    if (m && [m respondsToSelector:@selector(showFromTool)]) {
        ((void(*)(id, SEL))objc_msgSend)(m, @selector(showFromTool));
    }
}

- (void)didClickReset {
    // 直接执行一键新机(不弹系统确认框, 避免独立 window 下 presentViewController 失效导致无响应)
    gb_hidePanel();
    XHNewDevice();
    [HelloHelper toast:[HelloHelper strWithUTF8Hex:@"e696b0e69cbae5ae8ce68890"]];
}

@end

// ============ 挂载: 独立 UIWindow (windowLevel 最高, 不受探探 keyWindow 切换影响) ============
static UIWindow *g_ballWindow = nil;

static void gb_tryInstall(void) {
    // 授权拦截后不挂载悬浮球 (成功一次即显示, 拦截即隐藏)
    if (XHAuthBlocked()) {
        if (g_ballWindow) g_ballWindow.hidden = YES;
        return;
    }
    if (!g_ballBtn) {
        CGFloat w = kBallSize;
        g_ballBtn = [UIButton buttonWithType:UIButtonTypeCustom];
        g_ballBtn.frame = CGRectMake(0, 0, w, w);
        g_ballBtn.layer.cornerRadius = w / 2;
        g_ballBtn.backgroundColor = [UIColor colorWithRed:0.15 green:0.75 blue:0.35 alpha:0.9];
        [g_ballBtn setTitle:[HelloHelper strWithUTF8Hex:@"e5b7a5e585b7"] forState:UIControlStateNormal];
        g_ballBtn.titleLabel.font = [UIFont systemFontOfSize:13];
        [g_ballBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        [g_ballBtn addTarget:[XHGlobalBallDragHandler shared] action:@selector(ballTapped) forControlEvents:UIControlEventTouchUpInside];

        CGFloat sw = [UIScreen mainScreen].bounds.size.width;
        CGFloat sh = [UIScreen mainScreen].bounds.size.height;
        CGPoint defaultPos = CGPointMake(sw - w - 16, sh * 0.68);
        NSString *saved = [[NSUserDefaults standardUserDefaults] stringForKey:kGlobalBallPosKey];
        if (saved && saved.length > 0) {
            NSArray *parts = [saved componentsSeparatedByString:@","];
            if (parts.count == 2) {
                CGPoint p = CGPointMake([parts[0] floatValue], [parts[1] floatValue]);
                if (p.x >= 0 && p.y >= 0 && p.x + w <= sw && p.y + w <= sh) defaultPos = p;
            }
        }
        g_ballBtn.frame = CGRectMake(defaultPos.x, defaultPos.y, w, w);

        UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:[XHGlobalBallDragHandler shared] action:@selector(handlePan:)];
        pan.cancelsTouchesInView = NO;
        [g_ballBtn addGestureRecognizer:pan];

        // 遮罩
        g_maskView = [[UIView alloc] initWithFrame:[UIScreen mainScreen].bounds];
        g_maskView.backgroundColor = [UIColor colorWithWhite:0 alpha:0.25];
        g_maskView.hidden = YES;
        UITapGestureRecognizer *mt = [[UITapGestureRecognizer alloc] initWithTarget:[XHGlobalBallDragHandler shared] action:@selector(maskTapped)];
        [g_maskView addGestureRecognizer:mt];

        // 面板
        g_panelView = gb_buildPanel();
    }

    // 独立 window: 挂载一次即可, 永远在最上层 (不受探探广告页/主界面 window 切换影响)
    // 用 XHPassthroughWindow 实现触摸穿透(空白区域不拦截探探)
    if (!g_ballWindow) {
        g_ballWindow = [[XHPassthroughWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
        g_ballWindow.windowLevel = UIWindowLevelAlert + 1;
        g_ballWindow.backgroundColor = [UIColor clearColor];
        g_ballWindow.userInteractionEnabled = YES;
        g_ballWindow.hidden = NO;
    }
    if (g_maskView.superview != g_ballWindow) {
        [g_ballWindow addSubview:g_maskView];
        [g_ballWindow addSubview:g_panelView];
        [g_ballWindow addSubview:g_ballBtn];
    }
    [g_ballWindow bringSubviewToFront:g_ballBtn];
}

void XHInstallGlobalBall(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        // 轮询直到挂载成功 (独立 window, 启动早期就能挂)
        for (int i = 0; i < 60; i++) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * i * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                gb_tryInstall();
            });
        }
    });
}

// 隐藏全局悬浮球 (授权拦截时调用: 关闭所有功能入口)
void XHHideGlobalBall(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (g_ballWindow) {
            g_ballWindow.hidden = YES;
            g_ballWindow.userInteractionEnabled = NO;
        }
        if (g_ballBtn) [g_ballBtn removeFromSuperview];
        if (g_panelView) [g_panelView removeFromSuperview];
        if (g_maskView) [g_maskView removeFromSuperview];
        g_ballBtn = nil;
    });
}
