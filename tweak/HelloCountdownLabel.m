//
//  HelloCountdownLabel.m
//  悬浮倒计时标签 (独立 UIWindow, 屏幕中间上方, 白底黑字)
//
//  实现:
//    用一个独立 UIWindow (windowLevel = UIWindowLevelAlert) 承载一个
//    UILabel, 放在屏幕中间上方。白底黑字, 圆角, 带阴影。
//    独立窗口确保它始终置顶, 不被任何 VC 视图遮挡。
//
#import "HelloCountdownLabel.h"
#import "HelloHelper.h"

// 全局持有的窗口 (单例, 常驻)
static UIWindow *_cdWindow = nil;
static UILabel  *_cdLabel  = nil;

@implementation HelloCountdownLabel

// 保证窗口已创建并返回 label
+ (UILabel *)ensureLabel {
    if (!_cdWindow) {
        CGRect screen = [UIScreen mainScreen].bounds;
        _cdWindow = [[UIWindow alloc] initWithFrame:screen];
        _cdWindow.windowLevel = UIWindowLevelAlert + 1; // 高于弹窗, 始终置顶
        _cdWindow.backgroundColor = [UIColor clearColor];
        _cdWindow.userInteractionEnabled = NO; // 不拦截任何触摸
        _cdWindow.hidden = NO; // 先显示窗口, label 稍后设置

        CGFloat labelW = screen.size.width - 80;   // 宽度收缩
        CGFloat labelH = 40;                        // 高度缩小
        CGFloat labelX = 40;
        CGFloat labelY = 88; // 屏幕中间上方 (避开状态栏/导航)
        _cdLabel = [[UILabel alloc] initWithFrame:CGRectMake(labelX, labelY, labelW, labelH)];
        _cdLabel.textAlignment = NSTextAlignmentCenter;
        _cdLabel.font = [UIFont boldSystemFontOfSize:18]; // 字号缩小
        _cdLabel.textColor = [UIColor blackColor];        // 黑字
        _cdLabel.backgroundColor = [UIColor clearColor];  // 去掉白底 -> 透明
        _cdLabel.layer.cornerRadius = 0;
        _cdLabel.layer.masksToBounds = NO;
        _cdLabel.layer.borderWidth = 0;
        _cdLabel.numberOfLines = 1;
        _cdLabel.adjustsFontSizeToFitWidth = YES;
        _cdLabel.minimumScaleFactor = 0.6;

        // 白色描边 (保证去掉白底后, 在照片/彩色背景上清晰可读)
        _cdLabel.layer.shadowColor = [UIColor whiteColor].CGColor;
        _cdLabel.layer.shadowOpacity = 1.0;
        _cdLabel.layer.shadowRadius = 3;
        _cdLabel.layer.shadowOffset = CGSizeMake(0, 0);
        _cdWindow.rootViewController = [[UIViewController alloc] init];
        [_cdWindow.rootViewController.view addSubview:_cdLabel];
    }
    return _cdLabel;
}

// 拼显示文本: "划卡 999 次"
+ (NSString *)textWithPrefix:(NSString *)prefix remain:(NSInteger)remain unit:(NSString *)unit {
    NSString *p = prefix ?: @"";
    NSString *u = unit ?: @"";
    if (remain < 0) remain = 0;
    return [NSString stringWithFormat:@"%@ %ld %@", p, (long)remain, u];
}

+ (void)showWithPrefix:(NSString *)prefix remain:(NSInteger)remain unit:(NSString *)unit {
    dispatch_async(dispatch_get_main_queue(), ^{
        UILabel *label = [self ensureLabel];
        label.text = [self textWithPrefix:prefix remain:remain unit:unit];
        _cdWindow.hidden = NO;
        [HelloHelper log:@"[倒计时] 显示: %@", label.text];
    });
}

+ (void)updateWithPrefix:(NSString *)prefix remain:(NSInteger)remain unit:(NSString *)unit {
    [self showWithPrefix:prefix remain:remain unit:unit];
}

+ (void)hide {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (_cdWindow) {
            _cdWindow.hidden = YES;
        }
        [HelloHelper log:@"[倒计时] 已隐藏"];
    });
}

@end
