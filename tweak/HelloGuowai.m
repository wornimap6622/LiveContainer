//
//  HelloGuowai.m
//  切全局国内外: hook PUGDeviceInfo isChineseMobileNumber
//  原理(来自 showmoment.dylib 城山王版): isChineseMobileNumber 返回 YES=国内 NO=国外,
//  在"我的"界面(PUGMeOptExpViewController 国内 / PUGIntlNewUiSettingsMeViewController 国外)加切换按钮。
//
#import "HelloGuowai.h"
#import "HelloHelper.h"
#import <objc/runtime.h>
#import <UIKit/UIKit.h>

// 开关接口 (Tweak.m 提供)
BOOL XHGetSwitch(NSString *key, BOOL defaultVal);
void XHSetSwitch(NSString *key, BOOL on);


// 切国内外开关 key
static NSString *const kSwGuowai = @"xh_switch.guowai";  // 是否切国外

// 持久化 key
static NSString *const kMineIsChineseKey = @"mineIsChinese";

// ============ 原 IMP ============
static BOOL (*orig_isChineseMobileNumber)(id self, SEL _cmd) = NULL;

// hook: PUGDeviceInfo isChineseMobileNumber -> 返回国内外状态
static BOOL spoof_isChineseMobileNumber(id self, SEL _cmd) {
    // 读开关: 开=切国外(返回NO), 关=国内(返回YES)
    BOOL foreign = XHGetSwitch(kSwGuowai, NO);
    // 也兼容持久化的 mineIsChinese (和原 deb 一致, 用户手动点按钮时改)
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    NSString *saved = [ud stringForKey:kMineIsChineseKey];
    if (saved && [saved isEqualToString:@"0"]) {
        foreign = YES;  // "0" 表示切国外
    }
    if (foreign) {
        return NO;  // 国外
    }
    if (orig_isChineseMobileNumber) {
        return orig_isChineseMobileNumber(self, _cmd);
    }
    return YES;  // 默认国内
}

// 在当前 VC 加一个切换按钮
static void addSwitchButton(UIViewController *vc, NSString *title, BOOL toForeign) {
    if (!vc || !vc.view) return;
    // 移除旧的
    UIButton *old = objc_getAssociatedObject(vc, "xh_guowai_btn");
    [old removeFromSuperview];
    CGFloat sw = [UIScreen mainScreen].bounds.size.width;
    UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
    btn.frame = CGRectMake(sw - 100, 120, 88, 36);
    [btn setTitle:title forState:UIControlStateNormal];
    btn.backgroundColor = [UIColor colorWithRed:0.2 green:0.6 blue:1.0 alpha:0.9];
    [btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    btn.layer.cornerRadius = 8;
    btn.titleLabel.font = [UIFont boldSystemFontOfSize:14];
    btn.tag = toForeign ? 1 : 0;
    [btn addTarget:vc action:NSSelectorFromString(@"xh_toggleGuowai:") forControlEvents:UIControlEventTouchUpInside];
    [vc.view addSubview:btn];
    [vc.view bringSubviewToFront:btn];
    objc_setAssociatedObject(vc, "xh_guowai_btn", btn, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}

// 给 VC 动态加 toggle 方法
static void xh_toggleGuowai(id self, SEL _cmd, UIButton *btn) {
    BOOL toForeign = (btn.tag == 1);
    XHSetSwitch(kSwGuowai, toForeign);
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    [ud setObject:(toForeign ? @"0" : @"1") forKey:kMineIsChineseKey];
    [ud synchronize];
    [HelloHelper log:@"[切国外] 切换 -> %@", toForeign ? @"国外" : @"国内"];
    // 提示
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:nil
        message:toForeign ? @"已切换国外，重启探探生效" : @"已切换国内，重启探探生效"
        preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
    UIViewController *top = [UIApplication sharedApplication].keyWindow.rootViewController;
    while (top.presentedViewController) top = top.presentedViewController;
    if (top) [top presentViewController:alert animated:YES completion:nil];
}

// hook 国内版"我的" viewDidLoad, 加切国外按钮
static void (*orig_meOpt_viewDidLoad)(id self, SEL _cmd) = NULL;
static void spoof_meOpt_viewDidLoad(id self, SEL _cmd) {
    if (orig_meOpt_viewDidLoad) orig_meOpt_viewDidLoad(self, _cmd);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        addSwitchButton((UIViewController *)self, @"切国外", YES);
    });
}

// hook 国外版"我的" viewDidLoad, 加切国内按钮
static void (*orig_intl_viewDidLoad)(id self, SEL _cmd) = NULL;
static void spoof_intl_viewDidLoad(id self, SEL _cmd) {
    if (orig_intl_viewDidLoad) orig_intl_viewDidLoad(self, _cmd);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        addSwitchButton((UIViewController *)self, @"切国内", NO);
    });
}

// ============ 安装 ============
void HelloGuowaiInstall(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        @try {
            // 给 UIViewController 加 toggle 方法(动态)
            Class vcCls = [UIViewController class];
            if (!class_getInstanceMethod(vcCls, NSSelectorFromString(@"xh_toggleGuowai:"))) {
                class_addMethod(vcCls, NSSelectorFromString(@"xh_toggleGuowai:"), (IMP)xh_toggleGuowai, "v@:@");
            }

            // hook PUGDeviceInfo isChineseMobileNumber
            Class deviceInfo = objc_getClass("PUGDeviceInfo");
            if (deviceInfo) {
                Method m = class_getClassMethod(deviceInfo, @selector(isChineseMobileNumber));
                if (m) {
                    orig_isChineseMobileNumber = (BOOL(*)(id,SEL))method_getImplementation(m);
                    method_setImplementation(m, (IMP)spoof_isChineseMobileNumber);
                    [HelloHelper log:@"[切国外] hook PUGDeviceInfo isChineseMobileNumber 成功"];
                } else {
                    // 尝试实例方法
                    Method mi = class_getInstanceMethod(deviceInfo, @selector(isChineseMobileNumber));
                    if (mi) {
                        orig_isChineseMobileNumber = (BOOL(*)(id,SEL))method_getImplementation(mi);
                        method_setImplementation(mi, (IMP)spoof_isChineseMobileNumber);
                        [HelloHelper log:@"[切国外] hook PUGDeviceInfo isChineseMobileNumber(实例) 成功"];
                    } else {
                        [HelloHelper log:@"[切国外] PUGDeviceInfo isChineseMobileNumber 方法不存在!"];
                    }
                }
            } else {
                [HelloHelper log:@"[切国外] PUGDeviceInfo 类不存在!"];
            }

            // hook 国内版"我的"
            Class meOpt = objc_getClass("PUGMeOptExpViewController");
            if (meOpt) {
                Method m = class_getInstanceMethod(meOpt, @selector(viewDidLoad));
                if (m) {
                    orig_meOpt_viewDidLoad = (void(*)(id,SEL))method_getImplementation(m);
                    method_setImplementation(m, (IMP)spoof_meOpt_viewDidLoad);
                    [HelloHelper log:@"[切国外] hook PUGMeOptExpViewController viewDidLoad 成功"];
                }
            }
            // hook 国外版"我的"
            Class intl = objc_getClass("PUGIntlNewUiSettingsMeViewController");
            if (intl) {
                Method m = class_getInstanceMethod(intl, @selector(viewDidLoad));
                if (m) {
                    orig_intl_viewDidLoad = (void(*)(id,SEL))method_getImplementation(m);
                    method_setImplementation(m, (IMP)spoof_intl_viewDidLoad);
                    [HelloHelper log:@"[切国外] hook PUGIntlNewUiSettingsMeViewController viewDidLoad 成功"];
                }
            }
        } @catch (NSException *e) {
            [HelloHelper log:@"[切国外] 安装异常: %@", e];
        }
    });
}
