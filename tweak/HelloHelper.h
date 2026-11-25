//
//  HelloHelper.h
//
#import <UIKit/UIKit.h>

@interface NSMutableArray (helloAdd)
- (id)popFirstObject;
- (void)removeFirstObject;
@end

@interface UIColor (helloAdd)
+ (UIColor *)hello_colorWithHexString:(NSString *)hexString;
@end

// 中文辅助: 用 UTF-8 字节构造字符串, 绕过 clang 编译期中文丢失
@interface HelloHelper : NSObject
+ (NSString *)strWithUTF8Hex:(NSString *)hex;
// 日志写到文件 (NSLog 在越狱 mobile 进程下可能丢失)
+ (void)log:(NSString *)fmt, ... NS_FORMAT_FUNCTION(1,2);
// 简短提示
+ (void)toast:(NSString *)msg;
// 运行时反射 dump: 遍历对象的 ivar / property, 打印名称+类型+值类型
+ (void)dumpObject:(id)obj;
// dump 对象自身类 (不含父类) 的 ivar + 相关方法名
+ (void)dumpSelfIvarsAndMethods:(id)obj;
// dump 对象类 (含父类) 的所有方法名, 用于定位发送方法
+ (void)dumpAllMethods:(id)obj;

// ===== 免越狱划卡辅助 (对齐最初版 TantanHelper, 不 hook 划卡VC) =====
+ (UIWindow *)getKeyWindow;
+ (UIViewController *)getCurrentLeafVC;
+ (UIViewController *)getSwipeVC;
+ (void)collectButtonsFromView:(UIView *)view screenW:(CGFloat)screenW intoArray:(NSMutableArray *)arr;
+ (BOOL)tapRealButtonWithKeywords:(NSString *)keywords isLike:(BOOL)isLike;
+ (void)simulateCardSwipe:(BOOL)isLike;
@end
