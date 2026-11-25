//
//  HelloLocation.m — 地图悬浮窗定位
//

#import <UIKit/UIKit.h>
#import <MapKit/MapKit.h>
#import <CoreLocation/CoreLocation.h>
#import <objc/runtime.h>
#import <objc/message.h>

// 全局可写坐标(默认深圳)
static double g_lat = 22.543099;
static double g_lon = 114.057868;

static void LH_log(NSString *m);  // 前向声明

// 坐标持久化 key
static NSString *const kLocLatKey = @"xh_loc_lat";
static NSString *const kLocLonKey = @"xh_loc_lon";

// 从 NSUserDefaults 读取最后选择的坐标; 没有则用默认深圳
static void LH_loadSavedLoc(void) {
    NSUserDefaults *sud = [NSUserDefaults standardUserDefaults];
    id lat = [sud objectForKey:kLocLatKey];
    id lon = [sud objectForKey:kLocLonKey];
    if (lat && lon) {
        g_lat = [lat doubleValue];
        g_lon = [lon doubleValue];
    }
}

// 把当前坐标写回 NSUserDefaults(长按定位后调用)
static void LH_saveLoc(void) {
    NSUserDefaults *sud = [NSUserDefaults standardUserDefaults];
    [sud setDouble:g_lat forKey:kLocLatKey];
    [sud setDouble:g_lon forKey:kLocLonKey];
    [sud synchronize];
}

// 一键新机调用: 清除保存的坐标, 重置回默认深圳
void XHResetLocation(void) {
    NSUserDefaults *sud = [NSUserDefaults standardUserDefaults];
    [sud removeObjectForKey:kLocLatKey];
    [sud removeObjectForKey:kLocLonKey];
    [sud synchronize];
    g_lat = 22.543099;
    g_lon = 114.057868;
    LH_log(@"一键新机: 定位已重置回默认(深圳)");
}

static void LH_log(NSString *m) {
    NSLog(@"[定位] %@", m);
    @try {
        NSArray *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        NSString *p = [docs[0] stringByAppendingPathComponent:@"xh_debug.log"];
        NSString *line = [NSString stringWithFormat:@"%@ [定位] %@\n", [NSDate date], m];
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:p];
        if (!fh) { [[NSFileManager defaultManager] createFileAtPath:p contents:nil attributes:nil]; fh = [NSFileHandle fileHandleForWritingAtPath:p]; }
        [fh seekToEndOfFile]; [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]]; [fh closeFile];
    } @catch (NSException *e) {}
}

static CLLocation *LH_fake(void) {
    return [[CLLocation alloc] initWithCoordinate:CLLocationCoordinate2DMake(g_lat, g_lon)
                                         altitude:20 horizontalAccuracy:10 verticalAccuracy:10
                                        timestamp:[NSDate date]];
}

// ============ 定位开关: 只有 xh_switch.location 打开时才伪造坐标 ============
// 默认关闭。hook 常驻, 但每次调用都读开关; 关闭时原样回落真实定位,
// 因此面板里打开/关闭立即生效, 不需要重启探探。
static NSString *const kLocSwitchKey = @"xh_switch.location";

static BOOL LH_switchOn(void) {
    id v = [[NSUserDefaults standardUserDefaults] objectForKey:kLocSwitchKey];
    if (v == nil) return NO;            // 默认关
    return [v boolValue];
}

BOOL XHLocationHookEnabled(void) { return LH_switchOn(); }

void XHSetLocationHookEnabled(BOOL on) {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    [ud setBool:on forKey:kLocSwitchKey];
    [ud synchronize];
    LH_log(on ? @"定位 hook 已开启(坐标伪造生效)" : @"定位 hook 已关闭(回落真实定位)");
}

// 原始实现(替换前保存), 开关关闭时原样回落
static IMP g_orig_CLMgrLocation = NULL;
static IMP g_orig_PUGCur = NULL, g_orig_PUGLast = NULL;
static IMP g_orig_PUGBGCur = NULL, g_orig_PUGBGLast = NULL;

static id LH_fallback(IMP imp, id self, SEL _cmd) {
    if (!imp) return nil;
    return ((id (*)(id, SEL))imp)(self, _cmd);
}

static id hook_sysLocation(id self, SEL _cmd) {
    if (!LH_switchOn()) return LH_fallback(g_orig_CLMgrLocation, self, _cmd);
    return LH_fake();
}
static id hook_PUGCur(id self, SEL _cmd) {
    if (!LH_switchOn()) return LH_fallback(g_orig_PUGCur, self, _cmd);
    return LH_fake();
}
static id hook_PUGLast(id self, SEL _cmd) {
    if (!LH_switchOn()) return LH_fallback(g_orig_PUGLast, self, _cmd);
    return LH_fake();
}
static id hook_PUGBGCur(id self, SEL _cmd) {
    if (!LH_switchOn()) return LH_fallback(g_orig_PUGBGCur, self, _cmd);
    return LH_fake();
}
static id hook_PUGBGLast(id self, SEL _cmd) {
    if (!LH_switchOn()) return LH_fallback(g_orig_PUGBGLast, self, _cmd);
    return LH_fake();
}

static void LH_showMap(void);
static UIWindow *g_mapWindow = nil;  // 地图独立 window (前向声明, 供 close 引用)
static UIWindow *g_prevKeyWindow = nil;  // 打开地图前的 keyWindow, 关闭时归还

// 找探探自己的主窗口 (windowLevel 为 Normal 且有 rootViewController)
static UIWindow *LH_findAppMainWindow(void) {
    UIWindow *fallback = nil;
    for (UIWindow *w in [UIApplication sharedApplication].windows) {
        if (w.hidden) continue;
        if (w == g_mapWindow) continue;
        if (!w.rootViewController) continue;
        if (w.windowLevel == UIWindowLevelNormal) return w;
        if (!fallback) fallback = w;
    }
    return fallback;
}

// 把 keyWindow 还给探探主窗口 (关地图后必须调用, 否则转场/返回键失效)
static void LH_restoreAppKeyWindow(void) {
    UIWindow *back = g_prevKeyWindow;
    if (!back || back.hidden || !back.rootViewController) {
        back = LH_findAppMainWindow();
    }
    g_prevKeyWindow = nil;
    if (back && back != g_mapWindow) {
        [back makeKeyWindow];
        LH_log(@"已归还 keyWindow");
    }
}

// ============ 地图 ============
@interface LHMapVC : UIViewController <MKMapViewDelegate, UISearchBarDelegate>
@property (nonatomic, strong) MKMapView *map;
@property (nonatomic, strong) UISearchBar *searchBar;
+ (void)showFromTool;
@end
@implementation LHMapVC
+ (void)showFromTool { LH_showMap(); }
- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor whiteColor];
    self.title = @"长按地图定位";
    UIBarButtonItem *close = [[UIBarButtonItem alloc] initWithTitle:@"关闭" style:UIBarButtonItemStyleDone target:self action:@selector(close)];
    self.navigationItem.leftBarButtonItem = close;

    // 导航栏搜索框: 输入城市/地点(如"郑州") -> 地图直接跳过去, 再长按选精确位置
    UISearchBar *sb = [[UISearchBar alloc] initWithFrame:CGRectMake(0, 0, 220, 36)];
    sb.placeholder = @"搜索城市/地点";
    sb.searchBarStyle = UISearchBarStyleMinimal;
    sb.delegate = self;
    self.searchBar = sb;
    self.navigationItem.titleView = sb;

    self.map = [[MKMapView alloc] initWithFrame:self.view.bounds];
    self.map.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.map.delegate = self;
    [self.view addSubview:self.map];

    CLLocationCoordinate2D c = CLLocationCoordinate2DMake(g_lat, g_lon);
    MKCoordinateRegion region = MKCoordinateRegionMakeWithDistance(c, 50000, 50000);
    [self.map setRegion:region animated:NO];

    // 长按手势
    UILongPressGestureRecognizer *lp = [[UILongPressGestureRecognizer alloc] initWithTarget:self action:@selector(handleLongPress:)];
    [self.map addGestureRecognizer:lp];
}

#pragma mark - 搜索地点

- (void)searchBarSearchButtonClicked:(UISearchBar *)searchBar {
    NSString *kw = [searchBar.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    [searchBar resignFirstResponder];
    if (kw.length == 0) return;
    LH_log([NSString stringWithFormat:@"搜索地点: %@", kw]);

    // 地理编码: 地名 -> 坐标
    CLGeocoder *geocoder = [[CLGeocoder alloc] init];
    __weak typeof(self) weakSelf = self;
    [geocoder geocodeAddressString:kw completionHandler:^(NSArray<CLPlacemark *> *placemarks, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            typeof(self) self = weakSelf;
            if (!self) return;
            if (error || placemarks.count == 0 || !placemarks.firstObject.location) {
                LH_log([NSString stringWithFormat:@"搜索失败: %@", error ?: @"无结果"]);
                UIAlertController *a = [UIAlertController alertControllerWithTitle:@"没找到这个地点"
                                                                           message:@"换个关键词试试，比如只输入城市名"
                                                                    preferredStyle:UIAlertControllerStyleAlert];
                [a addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
                [self presentViewController:a animated:YES completion:nil];
                return;
            }
            CLPlacemark *pm = placemarks.firstObject;
            CLLocationCoordinate2D c = pm.location.coordinate;
            // 跳到该地点, 范围 30km, 方便长按微调
            MKCoordinateRegion region = MKCoordinateRegionMakeWithDistance(c, 30000, 30000);
            [self.map setRegion:region animated:YES];

            [self.map removeAnnotations:self.map.annotations];
            MKPointAnnotation *ann = [[MKPointAnnotation alloc] init];
            ann.coordinate = c;
            ann.title = kw;
            [self.map addAnnotation:ann];
            LH_log([NSString stringWithFormat:@"搜索定位到 %@ (%.6f, %.6f) — 可长按微调", kw, c.latitude, c.longitude]);
        });
    }];
}

- (void)close {
    // 独立 window 模式: 关闭时隐藏 window, 并把 keyWindow 还给探探主窗口。
    // 关键(2026-11-23): 如果不归还, 关掉地图后 keyWindow 为空,
    // 会表现为"消息列表点不进会话、左上角返回键没反应"(转场依赖 keyWindow)。
    UIWindow *w = g_mapWindow;
    g_mapWindow = nil;
    if (w) {
        w.hidden = YES;
        w.rootViewController = nil;
    }
    LH_restoreAppKeyWindow();
}

- (void)handleLongPress:(UILongPressGestureRecognizer *)g {
    if (g.state != UIGestureRecognizerStateBegan) return;
    CGPoint p = [g locationInView:self.map];
    CLLocationCoordinate2D coord = [self.map convertPoint:p toCoordinateFromView:self.map];
    g_lat = coord.latitude;
    g_lon = coord.longitude;
    LH_saveLoc();  // 持久化, 下次启动仍是这个位置
    LH_log([NSString stringWithFormat:@"长按定位到 %.6f, %.6f", g_lat, g_lon]);

    // 加标注
    [self.map removeAnnotations:self.map.annotations];
    MKPointAnnotation *ann = [[MKPointAnnotation alloc] init];
    ann.coordinate = coord;
    ann.title = [NSString stringWithFormat:@"%.4f, %.4f", g_lat, g_lon];
    [self.map addAnnotation:ann];

    // 提示
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"已定位" message:[NSString stringWithFormat:@"%.6f, %.6f", g_lat, g_lon] preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:a animated:YES completion:nil];
}
@end

static void LH_showMap(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        // 复用已存在的窗口, 否则新建独立 UIWindow (最高层级, 注册/登录/主界面都能弹出)
        if (g_mapWindow && !g_mapWindow.hidden) {
            g_mapWindow.hidden = NO;
            return;
        }
        LHMapVC *vc = [[LHMapVC alloc] init];
        UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:vc];

        UIWindow *win = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
        win.windowLevel = UIWindowLevelAlert + 2;  // 高于悬浮球(alert+1), 确保在地图能点到
        win.rootViewController = nav;
        win.backgroundColor = [UIColor whiteColor];
        // 关键(2026-11-23): 用 hidden=NO 显示, 不用 makeKeyAndVisible。
        // makeKeyAndVisible 会把 keyWindow 抢到地图窗口, 关闭后 keyWindow 为空,
        // 导致"消息列表点不进会话 / 左上角返回键无反应"。地图只有长按+按钮, 不需要 key。
        win.hidden = NO;
        g_mapWindow = win;
        LH_log(@"地图窗口已弹出 (独立 window 模式)");
    });
}

__attribute__((constructor)) static void LHInit(void) {
    // 先恢复上次保存的坐标(没有则默认深圳)
    LH_loadSavedLoc();
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        // 坐标 hook(常驻)。是否真正伪造由 xh_switch.location 决定, 关闭时回落原实现。
        Method sm = class_getInstanceMethod([CLLocationManager class], @selector(location));
        if (sm) {
            g_orig_CLMgrLocation = method_getImplementation(sm);
            method_setImplementation(sm, (IMP)hook_sysLocation);
        }
        Class c1 = objc_getClass("PUGLocationManager");
        if (c1) {
            Method m = class_getInstanceMethod(c1, NSSelectorFromString(@"currentLocation"));
            if (m) { g_orig_PUGCur = method_getImplementation(m); method_setImplementation(m, (IMP)hook_PUGCur); }
            m = class_getInstanceMethod(c1, NSSelectorFromString(@"lastLocation"));
            if (m) { g_orig_PUGLast = method_getImplementation(m); method_setImplementation(m, (IMP)hook_PUGLast); }
        }
        Class c2 = objc_getClass("PUGBackgroundLocationManager");
        if (c2) {
            Method m = class_getInstanceMethod(c2, NSSelectorFromString(@"currentLocation"));
            if (m) { g_orig_PUGBGCur = method_getImplementation(m); method_setImplementation(m, (IMP)hook_PUGBGCur); }
            m = class_getInstanceMethod(c2, NSSelectorFromString(@"lastLocation"));
            if (m) { g_orig_PUGBGLast = method_getImplementation(m); method_setImplementation(m, (IMP)hook_PUGBGLast); }
        }
        LH_log([NSString stringWithFormat:@"hook 已挂载, 开关=%@ (关=回落真实定位)",
                LH_switchOn() ? @"开" : @"关"]);
    });
}
