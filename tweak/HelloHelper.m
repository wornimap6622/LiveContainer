//
//  HelloHelper.m
//
#import "HelloHelper.h"
#import <objc/runtime.h>
#import <objc/message.h>

@implementation NSMutableArray (helloAdd)

- (id)popFirstObject {
    if (self.count == 0) {
        return nil;
    }
    id obj = self[0];
    [self removeObjectAtIndex:0];
    return obj;
}

- (void)removeFirstObject {
    if (self.count > 0) {
        [self removeObjectAtIndex:0];
    }
}

@end

@implementation UIColor (helloAdd)

+ (UIColor *)hello_colorWithHexString:(NSString *)hexString {
    NSString *cString = [[hexString stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] uppercaseString];
    if ([cString hasPrefix:@"#"]) {
        cString = [cString substringFromIndex:1];
    }
    if (cString.length != 6) {
        return [UIColor clearColor];
    }
    NSRange range = NSMakeRange(0, 2);
    NSString *rString = [cString substringWithRange:range];
    range.location = 2;
    NSString *gString = [cString substringWithRange:range];
    range.location = 4;
    NSString *bString = [cString substringWithRange:range];
    unsigned int r, g, b;
    [[NSScanner scannerWithString:rString] scanHexInt:&r];
    [[NSScanner scannerWithString:gString] scanHexInt:&g];
    [[NSScanner scannerWithString:bString] scanHexInt:&b];
    return [UIColor colorWithRed:r/255.0 green:g/255.0 blue:b/255.0 alpha:1.0];
}

@end

@implementation HelloHelper

// 日志: 干净版完全静音 (不 NSLog 不写文件)
+ (void)log:(NSString *)fmt, ... {
    (void)fmt;
}

// 用 UTF-8 十六进制字节串构造 NSString (绕过 clang 编译期中文丢失)
+ (NSString *)strWithUTF8Hex:(NSString *)hex {
    hex = [hex stringByReplacingOccurrencesOfString:@" " withString:@""];
    NSUInteger len = hex.length / 2;
    NSMutableData *data = [NSMutableData dataWithLength:len];
    unsigned char *bytes = (unsigned char *)data.mutableBytes;
    for (NSUInteger i = 0; i < len; i++) {
        NSString *byteStr = [hex substringWithRange:NSMakeRange(i * 2, 2)];
        unsigned int byteVal;
        [[NSScanner scannerWithString:byteStr] scanHexInt:&byteVal];
        bytes[i] = (unsigned char)byteVal;
    }
    NSString *result = [[NSString alloc] initWithBytes:bytes length:len encoding:NSUTF8StringEncoding];
    return result ?: @"";
}

// 运行时反射 dump: 遍历对象类层级的所有 ivar, 打印名字 + 类型编码 + 当前值的类
// 只对对象类型 (@ 开头) 的 ivar 取值, 避免结构体/基础类型导致卡死
+ (void)dumpObject:(id)obj {
    if (!obj) {
        [self log:@"dumpObject: obj 为 nil"];
        return;
    }
    Class cls = [obj class];
    [self log:@"===== dumpObject: %@ (%p) =====", NSStringFromClass(cls), obj];

    // 遍历类层级 (含父类) 收集 ivar
    Class cur = cls;
    int depth = 0;
    while (cur && depth < 8) {
        unsigned int ivarCount = 0;
        Ivar *ivars = class_copyIvarList(cur, &ivarCount);
        for (unsigned int i = 0; i < ivarCount; i++) {
            Ivar iv = ivars[i];
            const char *name = ivar_getName(iv);
            const char *type = ivar_getTypeEncoding(iv);
            // 只对对象类型取值
            if (type && type[0] == '@') {
                NSString *valDesc = @"?";
                @try {
                    id val = object_getIvar(obj, iv);
                    if (val == nil) {
                        valDesc = @"nil";
                    } else if ([val isKindOfClass:[NSArray class]]) {
                        valDesc = [NSString stringWithFormat:@"NSArray(%lu)", (unsigned long)[(NSArray*)val count]];
                    } else if ([val isKindOfClass:[NSDictionary class]]) {
                        valDesc = [NSString stringWithFormat:@"NSDictionary(%lu)", (unsigned long)[(NSDictionary*)val count]];
                    } else if ([val isKindOfClass:[NSString class]]) {
                        valDesc = [NSString stringWithFormat:@"NSString:%@", val];
                    } else if ([val isKindOfClass:[NSNumber class]]) {
                        valDesc = [NSString stringWithFormat:@"NSNumber:%@", val];
                    } else {
                        valDesc = [NSString stringWithFormat:@"%@", NSStringFromClass([val class])];
                    }
                } @catch (NSException *e) {
                    valDesc = @"<异常>";
                }
                [self log:@"  [ivar %@] %s : %s = %@", NSStringFromClass(cur), name, type, valDesc];
            } else {
                [self log:@"  [ivar %@] %s : %s", NSStringFromClass(cur), name, type];
            }
        }
        if (ivars) free(ivars);
        cur = class_getSuperclass(cur);
        depth++;
    }

    [self log:@"===== dump 结束 ====="];
}

// 只 dump 对象自身类 (不含父类) 的 ivar 和 method 名, 用于精确定位数据源
+ (void)dumpSelfIvarsAndMethods:(id)obj {
    if (!obj) return;
    Class cls = [obj class];
    [self log:@"===== dumpSelf: %@ (%p) =====", NSStringFromClass(cls), obj];

    unsigned int ivarCount = 0;
    Ivar *ivars = class_copyIvarList(cls, &ivarCount);
    for (unsigned int i = 0; i < ivarCount; i++) {
        Ivar iv = ivars[i];
        const char *name = ivar_getName(iv);
        const char *type = ivar_getTypeEncoding(iv);
        if (type && type[0] == '@') {
            NSString *valDesc = @"?";
            @try {
                id val = object_getIvar(obj, iv);
                if (val == nil) valDesc = @"nil";
                else if ([val isKindOfClass:[NSArray class]]) valDesc = [NSString stringWithFormat:@"NSArray(%lu)", (unsigned long)[(NSArray*)val count]];
                else if ([val isKindOfClass:[NSDictionary class]]) valDesc = [NSString stringWithFormat:@"NSDictionary(%lu)", (unsigned long)[(NSDictionary*)val count]];
                else if ([val isKindOfClass:[NSString class]]) valDesc = [NSString stringWithFormat:@"NSString:%@", val];
                else valDesc = NSStringFromClass([val class]);
            } @catch (NSException *e) { valDesc = @"<异常>"; }
            [self log:@"  [ivar] %s : %s = %@", name, type, valDesc];
        } else {
            [self log:@"  [ivar] %s : %s", name, type];
        }
    }
    if (ivars) free(ivars);

    // 列出所有方法名 (前 120 个), 帮助找数据源方法
    unsigned int mCount = 0;
    Method *methods = class_copyMethodList(cls, &mCount);
    [self log:@"  --- 方法列表 (共 %u 个) ---", mCount];
    int shown = 0;
    for (unsigned int i = 0; i < mCount && shown < 120; i++) {
        SEL sel = method_getName(methods[i]);
        const char *mname = sel_getName(sel);
        // 只看可能和会话/数据相关的方法
        if (strstr(mname, "onversation") || strstr(mname, "onversation") ||
            strstr(mname, "Conversation") || strstr(mname, "load") ||
            strstr(mname, "Load") || strstr(mname, "refresh") ||
            strstr(mname, "Refresh") || strstr(mname, "data") ||
            strstr(mname, "Data") || strstr(mname, "list") ||
            strstr(mname, "List") || strstr(mname, "cell") ||
            strstr(mname, "Cell") || strstr(mname, "Model") ||
            strstr(mname, "model")) {
            [self log:@"    %s", mname];
            shown++;
        }
    }
    if (methods) free(methods);
    [self log:@"===== dumpSelf 结束 ====="];
}

// dump 对象类 (含父类, 最多 6 层) 的所有方法名, 用于定位发送方法
+ (void)dumpAllMethods:(id)obj {
    if (!obj) return;
    Class cls = [obj class];
    [self log:@"===== dumpAllMethods: %@ (%p) =====", NSStringFromClass(cls), obj];

    Class cur = cls;
    int depth = 0;
    int total = 0;
    while (cur && depth < 6) {
        unsigned int mCount = 0;
        Method *methods = class_copyMethodList(cur, &mCount);
        [self log:@"  --- 类 %@ (共 %u 个方法) ---", NSStringFromClass(cur), mCount];
        for (unsigned int i = 0; i < mCount; i++) {
            SEL sel = method_getName(methods[i]);
            const char *mname = sel_getName(sel);
            if (!mname) continue;
            // 只打印和发送/消息/文本/输入/媒体/图片/上传相关的方法
            if (strstr(mname, "send") || strstr(mname, "Send") ||
                strstr(mname, "essage") || strstr(mname, "Message") ||
                strstr(mname, "Text") || strstr(mname, "text") ||
                strstr(mname, "Input") || strstr(mname, "input") ||
                strstr(mname, "ompose") || strstr(mname, "Compose") ||
                strstr(mname, "onversation") || strstr(mname, "Conversation") ||
                strstr(mname, "mage") || strstr(mname, "Image") ||
                strstr(mname, "hoto") || strstr(mname, "Photo") ||
                strstr(mname, "edia") || strstr(mname, "Media") ||
                strstr(mname, "pload") || strstr(mname, "Upload") ||
                strstr(mname, "sset") || strstr(mname, "Asset") ||
                strstr(mname, "seCase") || strstr(mname, "UseCase") ||
                strstr(mname, "messenger") || strstr(mname, "Messenger")) {
                [self log:@"    %s", mname];
                total++;
            }
        }
        if (methods) free(methods);
        cur = class_getSuperclass(cur);
        depth++;
    }
    [self log:@"===== dumpAllMethods 结束 (匹配 %d 个) =====", total];
}

// 简短提示 (自动消失的弹窗)
+ (void)toast:(NSString *)msg {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *win = [UIApplication sharedApplication].keyWindow;
        UIViewController *root = win.rootViewController;
        while (root.presentedViewController) root = root.presentedViewController;
        UIAlertController *a = [UIAlertController alertControllerWithTitle:nil message:msg preferredStyle:UIAlertControllerStyleAlert];
        [root presentViewController:a animated:YES completion:nil];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [a dismissViewControllerAnimated:YES completion:nil];
        });
    });
}

#pragma mark - 免越狱划卡辅助 (对齐最初版 TantanHelper, 不 hook 划卡VC)

// 取 keyWindow (兼容 iOS 13+ 多场景)
+ (UIWindow *)getKeyWindow {
    if (@available(iOS 13.0, *)) {
        for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
            if (scene.activationState == UISceneActivationStateForegroundActive) {
                for (UIWindow *w in scene.windows) {
                    if (w.isKeyWindow) return w;
                }
            }
        }
    }
    UIWindow *kw = [UIApplication sharedApplication].keyWindow;
    if (kw) return kw;
    for (UIWindow *w in [UIApplication sharedApplication].windows) {
        if (w.isKeyWindow) return w;
    }
    return [UIApplication sharedApplication].windows.firstObject;
}

// 取当前叶子 VC (穿透 nav/tab/present)
+ (UIViewController *)getCurrentLeafVC {
    UIWindow *win = [self getKeyWindow];
    UIViewController *vc = win.rootViewController;
    while (vc) {
        if (vc.presentedViewController) { vc = vc.presentedViewController; continue; }
        if ([vc isKindOfClass:[UINavigationController class]]) {
            vc = [(UINavigationController *)vc topViewController]; continue;
        }
        if ([vc isKindOfClass:[UITabBarController class]]) {
            vc = [(UITabBarController *)vc selectedViewController]; continue;
        }
        break;
    }
    return vc;
}

// 取划卡 VC: swipeViewController / swipeSubViewController 属性 (不 hook, 纯读取)
+ (UIViewController *)getSwipeVC {
    UIViewController *leaf = [self getCurrentLeafVC];
    [HelloHelper log:@"[getSwipeVC] leaf=%@ class=%@", leaf, leaf ? NSStringFromClass([leaf class]) : @"(nil)"];
    if (!leaf) {
        [HelloHelper log:@"[getSwipeVC] leaf 为 nil, 返回 nil"];
        return nil;
    }
    for (NSString *selName in @[@"swipeViewController", @"swipeSubViewController"]) {
        SEL sel = NSSelectorFromString(selName);
        BOOL has = [leaf respondsToSelector:sel];
        [HelloHelper log:@"[getSwipeVC] leaf 是否响应 %@ = %d", selName, has];
        if (has) {
            id vc = ((id(*)(id, SEL))objc_msgSend)(leaf, sel);
            [HelloHelper log:@"[getSwipeVC] %@ 返回值 = %@ (class=%@)", selName, vc, vc ? NSStringFromClass([vc class]) : @"(nil)"];
            if (vc) return vc;
        }
    }
    if ([NSStringFromClass([leaf class]) containsString:@"Swipe"]) {
        [HelloHelper log:@"[getSwipeVC] leaf 类名含 Swipe, 直接用 leaf"];
        return leaf;
    }
    [HelloHelper log:@"[getSwipeVC] 未找到划卡 VC, 返回 nil"];
    return nil;
}

// 扫描 view 及其子视图, 收集所有 UIButton (按标题/accessibilityLabel/identifier 匹配关键词)
+ (void)collectButtonsFromView:(UIView *)view screenW:(CGFloat)screenW intoArray:(NSMutableArray *)arr {
    if (!view) return;
    if ([view isKindOfClass:[UIButton class]]) {
        UIButton *b = (UIButton *)view;
        NSString *title = [[b titleForState:UIControlStateNormal] lowercaseString];
        NSString *acc = [b.accessibilityLabel lowercaseString];
        NSString *ident = [b.accessibilityIdentifier lowercaseString];
        if (title.length || acc.length || ident.length) {
            NSDictionary *d = @{@"view": b, @"title": title ?: @"", @"acc": acc ?: @"", @"ident": ident ?: @""};
            [arr addObject:d];
        }
    }
    for (UIView *sub in view.subviews) {
        [self collectButtonsFromView:sub screenW:screenW intoArray:arr];
    }
}

// 关键词匹配真实按钮并模拟点击 (对齐最初版 tapRealButtonWithKeywords:isLike:)
+ (BOOL)tapRealButtonWithKeywords:(NSString *)keywords isLike:(BOOL)isLike {
    UIViewController *swipeVC = [self getSwipeVC];
    NSMutableArray *buttons = [NSMutableArray array];
    CGFloat screenW = [UIScreen mainScreen].bounds.size.width;
    if (swipeVC && swipeVC.view) {
        [self collectButtonsFromView:swipeVC.view screenW:screenW intoArray:buttons];
    }
    UIWindow *win = [self getKeyWindow];
    if (win) {
        [self collectButtonsFromView:win screenW:screenW intoArray:buttons];
    }
    [HelloHelper log:@"[匹配] tapRealButton isLike=%d keywords=%@ swipeVC=%@ 扫描到按钮 %lu 个",
     isLike, keywords, swipeVC ? NSStringFromClass([swipeVC class]) : @"(nil)", (unsigned long)buttons.count];
    // 打印所有按钮详情 (最多 40 个, 便于定位真实按钮标题)
    NSInteger maxShow = 40;
    for (NSInteger i = 0; i < (NSInteger)buttons.count && i < maxShow; i++) {
        NSDictionary *d = buttons[i];
        UIButton *bb = d[@"view"];
        [HelloHelper log:@"[匹配] 按钮[%ld] title=%@ acc=%@ ident=%@ frame=(%.0f,%.0f,%.0f,%.0f) enabled=%d",
         (long)i, d[@"title"], d[@"acc"], d[@"ident"],
         bb.frame.origin.x, bb.frame.origin.y, bb.frame.size.width, bb.frame.size.height,
         bb.enabled];
    }
    if (buttons.count > maxShow) {
        [HelloHelper log:@"[匹配] ...还有 %lu 个按钮未列出", (unsigned long)(buttons.count - maxShow)];
    }
    NSArray *kws = [keywords componentsSeparatedByString:@","];
    for (NSDictionary *d in buttons) {
        NSString *title = d[@"title"];
        NSString *acc = d[@"acc"];
        NSString *ident = d[@"ident"];
        for (NSString *kw in kws) {
            NSString *k = [kw stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            if (!k.length) continue;
            if ([title containsString:k] || [acc containsString:k] || [ident containsString:k]) {
                UIButton *b = d[@"view"];
                [HelloHelper log:@"[匹配] 命中真实按钮 keyword=%@ title=%@ acc=%@ ident=%@ 即将 sendActions",
                 k, title, acc, ident];
                [b sendActionsForControlEvents:UIControlEventTouchUpInside];
                [HelloHelper log:@"[匹配] sendActionsForControlEvents 已调用 (点击完成)"];
                return YES;
            }
        }
    }
    [HelloHelper log:@"[匹配] 未命中任何关键词按钮, 返回 NO"];
    return NO;
}

// 模拟手势划卡 (兜底): 反射划卡方法
+ (void)simulateCardSwipe:(BOOL)isLike {
    UIViewController *vc = [self getSwipeVC];
    if (!vc || !vc.view) {
        [HelloHelper log:@"[匹配] simulateCardSwipe: vc 为 nil 或无 view, 无法划卡"];
        return;
    }
    NSArray *swipeSels = isLike ? @[@"handleSwipeRight", @"didSwipeRight", @"swipeRight"] : @[@"handleSwipeLeft", @"didSwipeLeft", @"swipeLeft"];
    BOOL anyFound = NO;
    for (NSString *selName in swipeSels) {
        SEL sel = NSSelectorFromString(selName);
        BOOL has = [vc respondsToSelector:sel];
        [HelloHelper log:@"[匹配] simulateCardSwipe 检查 %@ = %d", selName, has];
        if (has) {
            anyFound = YES;
            @try {
                ((void(*)(id, SEL))objc_msgSend)(vc, sel);
                [HelloHelper log:@"[匹配] simulateCardSwipe 成功调用 %@", selName];
                return;
            } @catch (NSException *e) {
                [HelloHelper log:@"[匹配] simulateCardSwipe %@ 异常 %@", selName, e];
            }
        }
    }
    if (!anyFound) {
        [HelloHelper log:@"[匹配] simulateCardSwipe: 划卡 VC (%@) 不响应任何划卡方法, 划卡失败", NSStringFromClass([vc class])];
    }
}

@end
