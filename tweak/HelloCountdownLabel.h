//
//  HelloCountdownLabel.h
//  悬浮倒计时标签 (独立 UIWindow, 屏幕中间上方, 白底黑字)
//
//  用途:
//    划卡/顺发任务进行时, 在屏幕中间上方显示剩余次数倒计时
//    例如 "划卡 999 次" / "顺发 88 条"
//
#import <UIKit/UIKit.h>

@interface HelloCountdownLabel : NSObject

// 显示倒计时
//   prefix:  前缀文字, 如 "划卡" / "顺发" (用 strWithUTF8Hex 构造)
//   remain:  剩余次数
//   unit:    单位, 如 "次" / "条" (用 strWithUTF8Hex 构造)
+ (void)showWithPrefix:(NSString *)prefix remain:(NSInteger)remain unit:(NSString *)unit;

// 更新倒计时 (窗口不存在时自动创建)
+ (void)updateWithPrefix:(NSString *)prefix remain:(NSInteger)remain unit:(NSString *)unit;

// 隐藏并移除倒计时标签
+ (void)hide;

@end
