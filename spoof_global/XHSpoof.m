// ============================================================
// XHSpoof — 通用设备指纹随机化 tweak（纯自写，无卡密、无业务 hook）
// ============================================================
// 目标：注入任意 App 后，把该 App 能读取到的全部设备指纹替换为
//       一套自洽的随机值。不依赖任何第三方框架，不联网，不校验。
// 覆盖：
//   身份标识: IDFV / IDFA / UDID / 序列号 / IMEI / ICCID / chipid / oneid
//   机型系统: 机型/product/model/os/build/内存/CPU/磁盘/开机时间/内核版本
//   网络:     机型 MAC / WiFi MAC / 蓝牙 MAC / pdp_ip / SSID / BSSID / 运营商
//   隐私:     剪贴板读取清空 / ATT 授权态 / 传感器可用性
// 入口: constructor，仅一次，幂等。
// ============================================================

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <sys/types.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <sys/mount.h>
#import <sys/stat.h>
#import <netdb.h>
#import <dlfcn.h>
#import <signal.h>
#import <unistd.h>
#import <stdlib.h>
#import <string.h>
#import <ifaddrs.h>
#import <net/if.h>
#import <net/if_dl.h>
#import <net/ethernet.h>
#import <mach/mach.h>
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <CoreTelephony/CTCarrier.h>
#import <IOKit/IOKitLib.h>
#include "fishhook.h"

#define XHLOG(fmt, ...) NSLog(@"[XHSpoof] " fmt, ##__VA_ARGS__)

// ============================================================
// 1. 随机值生成
// ============================================================
static NSString *RandHex(NSUInteger n) {
    NSMutableString *s = [NSMutableString stringWithCapacity:n];
    for (NSUInteger i = 0; i < n; i++) [s appendFormat:@"%x", arc4random_uniform(16)];
    return s;
}
static NSString *RandUUID(void) {
    NSString *h = RandHex(32);
    return [NSString stringWithFormat:@"%@-%@-%@-%@-%@",
            [h substringWithRange:NSMakeRange(0,8)],
            [h substringWithRange:NSMakeRange(8,4)],
            [h substringWithRange:NSMakeRange(12,4)],
            [h substringWithRange:NSMakeRange(16,4)],
            [h substringWithRange:NSMakeRange(20,12)]];
}
static NSString *RandDigits(NSUInteger n) {
    NSMutableString *s = [NSMutableString stringWithCapacity:n];
    for (NSUInteger i = 0; i < n; i++) [s appendFormat:@"%u", arc4random_uniform(10)];
    return s;
}
static NSString *RandSerial(void) {
    // 苹果序列号风格 12 位，排除易混淆 I/O/Q
    const char *a = "ABCDEFGHJKLMNPRSTUVWXYZ0123456789";
    NSMutableString *s = [NSMutableString stringWithCapacity:12];
    for (int i = 0; i < 12; i++) [s appendFormat:@"%c", a[arc4random_uniform(strlen(a))]];
    return s;
}
static NSString *RandMAC(void) {
    // 本地管理位 02/06/0A/0E
    NSArray *p = @[@"02",@"06",@"0A",@"0E"];
    return [NSString stringWithFormat:@"%@:%02x:%02x:%02x:%02x:%02x",
         p[arc4random_uniform(p.count)],
         arc4random_uniform(256), arc4random_uniform(256), arc4random_uniform(256),
         arc4random_uniform(256), arc4random_uniform(256)];
}
static NSString *RandIMEI(void) {
    NSMutableString *s = [NSMutableString stringWithCapacity:15];
    [s appendFormat:@"%u", 1 + arc4random_uniform(9)];
    for (int i = 1; i < 15; i++) [s appendFormat:@"%u", arc4random_uniform(10)];
    return s;
}

// ============================================================
// 2. 自洽机型池（机型 / 系统 / 内存 / CPU 对齐，规避交叉校验）
// ============================================================
// 真机 iPhone 11 系列硬件同代（A13，4GB），避免 ZIM 类交叉校验闪退
static NSArray *ModelPool(void) {
    static NSArray *pool;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        pool = @[
            @{@"machine":@"iPhone12,1", @"model":@"iPhone 11",        @"name":@"iPhone", @"os":@"13.6", @"build":@"17G68", @"mem":@(4ULL*1024*1024*1024), @"cpu":@6, @"devid":@"iPhone12,1", @"regModel":@"A2223"},
            @{@"machine":@"iPhone12,3", @"model":@"iPhone 11 Pro",    @"name":@"iPhone", @"os":@"13.6", @"build":@"17G68", @"mem":@(4ULL*1024*1024*1024), @"cpu":@6, @"devid":@"iPhone12,3", @"regModel":@"A2217"},
            @{@"machine":@"iPhone12,5", @"model":@"iPhone 11 Pro Max",@"name":@"iPhone", @"os":@"13.6", @"build":@"17G68", @"mem":@(4ULL*1024*1024*1024), @"cpu":@6, @"devid":@"iPhone12,5", @"regModel":@"A2220"},
            @{@"machine":@"iPhone12,8", @"model":@"iPhone SE (2nd)",  @"name":@"iPhone", @"os":@"13.6", @"build":@"17G68", @"mem":@(3ULL*1024*1024*1024), @"cpu":@6, @"devid":@"iPhone12,8", @"regModel":@"A2275"},
            @{@"machine":@"iPhone13,1", @"model":@"iPhone 12 mini",   @"name":@"iPhone", @"os":@"14.6", @"build":@"18F72", @"mem":@(4ULL*1024*1024*1024), @"cpu":@6, @"devid":@"iPhone13,1", @"regModel":@"A2399"},
            @{@"machine":@"iPhone13,2", @"model":@"iPhone 12",        @"name":@"iPhone", @"os":@"14.6", @"build":@"18F72", @"mem":@(4ULL*1024*1024*1024), @"cpu":@6, @"devid":@"iPhone13,2", @"regModel":@"A2403"},
            @{@"machine":@"iPhone13,3", @"model":@"iPhone 12 Pro",    @"name":@"iPhone", @"os":@"14.6", @"build":@"18F72", @"mem":@(6ULL*1024*1024*1024), @"cpu":@6, @"devid":@"iPhone13,3", @"regModel":@"A2407"},
            @{@"machine":@"iPhone14,2", @"model":@"iPhone 13 Pro",    @"name":@"iPhone", @"os":@"15.5", @"build":@"19F75", @"mem":@(6ULL*1024*1024*1024), @"cpu":@6, @"devid":@"iPhone14,2", @"regModel":@"A2639"},
            @{@"machine":@"iPhone14,3", @"model":@"iPhone 13 Pro Max",@"name":@"iPhone", @"os":@"15.5", @"build":@"19F75", @"mem":@(6ULL*1024*1024*1024), @"cpu":@6, @"devid":@"iPhone14,3", @"regModel":@"A2644"},
            @{@"machine":@"iPhone15,2", @"model":@"iPhone 14 Pro",    @"name":@"iPhone", @"os":@"16.6", @"build":@"20G75", @"mem":@(6ULL*1024*1024*1024), @"cpu":@6, @"devid":@"iPhone15,2", @"regModel":@"A2650"},
            @{@"machine":@"iPhone15,3", @"model":@"iPhone 14 Pro Max",@"name":@"iPhone", @"os":@"16.6", @"build":@"20G75", @"mem":@(6ULL*1024*1024*1024), @"cpu":@6, @"devid":@"iPhone15,3", @"regModel":@"A2651"},
            @{@"machine":@"iPhone15,4", @"model":@"iPhone 15",        @"name":@"iPhone", @"os":@"17.0", @"build":@"21A329", @"mem":@(6ULL*1024*1024*1024), @"cpu":@6, @"devid":@"iPhone15,4", @"regModel":@"A2846"},
            @{@"machine":@"iPhone15,5", @"model":@"iPhone 15 Plus",   @"name":@"iPhone", @"os":@"17.0", @"build":@"21A329", @"mem":@(6ULL*1024*1024*1024), @"cpu":@6, @"devid":@"iPhone15,5", @"regModel":@"A2849"},
            @{@"machine":@"iPhone16,1", @"model":@"iPhone 15 Pro",    @"name":@"iPhone", @"os":@"17.0", @"build":@"21A329", @"mem":@(8ULL*1024*1024*1024), @"cpu":@6, @"devid":@"iPhone16,1", @"regModel":@"A2894"},
            @{@"machine":@"iPhone16,2", @"model":@"iPhone 15 Pro Max",@"name":@"iPhone", @"os":@"17.0", @"build":@"21A329", @"mem":@(8ULL*1024*1024*1024), @"cpu":@6, @"devid":@"iPhone16,2", @"regModel":@"A2896"},
            @{@"machine":@"iPhone17,1", @"model":@"iPhone 16 Pro",    @"name":@"iPhone", @"os":@"18.0", @"build":@"22A3354", @"mem":@(8ULL*1024*1024*1024), @"cpu":@6, @"devid":@"iPhone17,1", @"regModel":@"A2863"},
            @{@"machine":@"iPhone17,2", @"model":@"iPhone 16 Pro Max",@"name":@"iPhone", @"os":@"18.0", @"build":@"22A3354", @"mem":@(8ULL*1024*1024*1024), @"cpu":@6, @"devid":@"iPhone17,2", @"regModel":@"A2864"},
            @{@"machine":@"iPhone17,3", @"model":@"iPhone 16",        @"name":@"iPhone", @"os":@"18.0", @"build":@"22A3354", @"mem":@(8ULL*1024*1024*1024), @"cpu":@6, @"devid":@"iPhone17,3", @"regModel":@"A2846"},
            @{@"machine":@"iPhone17,4", @"model":@"iPhone 16 Plus",   @"name":@"iPhone", @"os":@"18.0", @"build":@"22A3354", @"mem":@(8ULL*1024*1024*1024), @"cpu":@6, @"devid":@"iPhone17,4", @"regModel":@"A2849"},
            @{@"machine":@"iPhone18,1", @"model":@"iPhone 17 Pro",    @"name":@"iPhone", @"os":@"26.0", @"build":@"23A341", @"mem":@(8ULL*1024*1024*1024), @"cpu":@6, @"devid":@"iPhone18,1", @"regModel":@"A2925"},
            @{@"machine":@"iPhone18,2", @"model":@"iPhone 17 Pro Max",@"name":@"iPhone", @"os":@"26.0", @"build":@"23A341", @"mem":@(8ULL*1024*1024*1024), @"cpu":@6, @"devid":@"iPhone18,2", @"regModel":@"A2926"},
            @{@"machine":@"iPhone18,3", @"model":@"iPhone 17",        @"name":@"iPhone", @"os":@"26.0", @"build":@"23A341", @"mem":@(8ULL*1024*1024*1024), @"cpu":@6, @"devid":@"iPhone18,3", @"regModel":@"A2924"},
            @{@"machine":@"iPhone18,4", @"model":@"iPhone Air",       @"name":@"iPhone", @"os":@"26.0", @"build":@"23A341", @"mem":@(8ULL*1024*1024*1024), @"cpu":@6, @"devid":@"iPhone18,4", @"regModel":@"A2921"},
            @{@"machine":@"iPhone19,3", @"model":@"iPhone 18 Pro",    @"name":@"iPhone", @"os":@"27.0", @"build":@"24A327", @"mem":@(12ULL*1024*1024*1024), @"cpu":@6, @"devid":@"iPhone19,3", @"regModel":@"A2927"},
            @{@"machine":@"iPhone19,4", @"model":@"iPhone 18 Pro Max",@"name":@"iPhone", @"os":@"27.0", @"build":@"24A327", @"mem":@(12ULL*1024*1024*1024), @"cpu":@6, @"devid":@"iPhone19,4", @"regModel":@"A2928"},
        ];
    });
    return pool;
}

// ============================================================
// 3. 指纹身份（首次生成，持久化，保证一次安装内自洽不变）
//    存到 App 沙盒 Documents/.xh_spoof_identity.plist
// ============================================================
static NSDictionary *gIdent = nil;

static NSString *IdentPath(void) {
    NSArray *p = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *dir = p.count ? p[0] : @"/var/mobile/Documents";
    return [[dir stringByAppendingPathComponent:@".xh_spoof_identity.plist"] stringByStandardizingPath];
}

// 机型指定文件路径（云连容器设置页写入，内容为 machine 标识，如 "iPhone16,1"）
static NSString *ModelSpecPath(void) {
    NSArray *p = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *dir = p.count ? p[0] : @"/var/mobile/Documents";
    return [[dir stringByAppendingPathComponent:@".xh_spoof_model.txt"] stringByStandardizingPath];
}

// 按 machine 标识从机型池取机型；没有则返回 nil
static NSDictionary *ModelByMachine(NSString *machine) {
    NSString *m = [machine stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (m.length == 0) return nil;
    for (NSDictionary *entry in ModelPool()) {
        if ([entry[@"machine"] isEqualToString:m]) return entry;
    }
    return nil;
}

static NSDictionary *Ident(void) {
    if (gIdent) return gIdent;
    NSString *path = IdentPath();
    NSDictionary *saved = [NSDictionary dictionaryWithContentsOfFile:path];
    if (saved && saved[@"idfv"] && saved[@"machine"] && saved[@"serial"]) {
        gIdent = saved;
        return gIdent;
    }
    // 优先使用用户指定机型（容器设置页写入 .xh_spoof_model.txt）
    NSDictionary *m = nil;
    NSString *specMachine = [NSString stringWithContentsOfFile:ModelSpecPath() encoding:NSUTF8StringEncoding error:NULL];
    m = ModelByMachine(specMachine);
    if (!m) {
        m = ModelPool()[arc4random_uniform((uint32_t)ModelPool().count)];
    }
    NSNumber *diskNum = @[@(128ULL*1024*1024*1024), @(256ULL*1024*1024*1024), @(512ULL*1024*1024*1024)][arc4random_uniform(3)];
    uint64_t disk = diskNum.unsignedLongLongValue;
    NSArray *ssids = @[@"HomeNetwork", @"TP-LINK_5G", @"CMCC-WiFi", @"ChinaNet", @"MiWiFi", @"HUAWEI_4G", @"Router_2.4G"];
    NSArray *carriers = @[@"中国移动", @"中国联通", @"中国电信"];
    uint8_t chipBuf[4]; arc4random_buf(chipBuf, 4);
    NSString *chipid = [NSString stringWithFormat:@"%08X", (uint32_t)(chipBuf[0]<<24|chipBuf[1]<<16|chipBuf[2]<<8|chipBuf[3])];
    // 已连 WiFi -> RAT 报 WiFi；否则报蜂窝。SSID 与 RAT 联动，消除交叉矛盾
    NSString *ssid = ssids[arc4random_uniform((uint32_t)ssids.count)];
    BOOL onWifi = (arc4random_uniform(10) < 7);   // 70% 概率联网走 WiFi
    NSString *rat = onWifi ? @"CTRadioAccessTechnologyWiFi"
                           : @[@"CTRadioAccessTechnologyLTE", @"CTRadioAccessTechnologyUME",
                              @"CTRadioAccessTechnologyHSDPA"][arc4random_uniform(3)];
    gIdent = @{
        @"idfv": RandUUID(),
        @"idfa": RandUUID(),
        @"oneid": RandDigits(19),
        @"localid": RandHex(40),
        @"serial": RandSerial(),
        @"mlb": RandSerial(),
        @"udid": RandHex(40),
        @"chipid": chipid,
        @"imei": RandIMEI(),
        @"iccid": [@"898600" stringByAppendingString:RandDigits(14)],
        @"wifiMAC": RandMAC(),
        @"btMAC": RandMAC(),
        @"en0MAC": RandMAC(),
        @"dieid": RandHex(16),
        @"ioupuid": RandHex(32),
        @"bootuuid": [RandUUID() uppercaseString],
        @"msmid": RandHex(40),
        @"weibosdkid": [NSString stringWithFormat:@"%@-%@-%@-%@-%@", RandHex(6), RandHex(4), RandHex(5), RandHex(4), RandHex(12)],
        @"appsflyerid": [NSString stringWithFormat:@"%lld-%@", (long long)[[NSDate date] timeIntervalSince1970]*1000, RandDigits(7)],
        @"cmccid": RandHex(32),
        @"momouuid": [RandUUID() uppercaseString],
        @"cdid": RandHex(32),
        @"apptoken": RandHex(32),
        @"vendortoken": RandHex(32),
        @"machine": m[@"machine"],
        @"model": m[@"model"],
        @"name": m[@"name"],
        @"os": m[@"os"],
        @"build": m[@"build"],
        @"regmodel": m[@"regModel"],
        @"mem": m[@"mem"],
        @"cpu": m[@"cpu"],
        @"disk": @(disk),
        @"boottime": @((uint64_t)([[NSDate date] timeIntervalSince1970] - (86400.0*(1+arc4random_uniform(14))))),
        @"ssid": ssid,
        @"bssid": RandMAC(),
        @"carrier": carriers[arc4random_uniform((uint32_t)carriers.count)],
        @"battery": @(40 + arc4random_uniform(60)),
        @"rat": rat,
        @"onwifi": @(onWifi),
    };
    [gIdent writeToFile:path atomically:YES];
    XHLOG(@"生成随机指纹: %@ / %@(%@) / IDFV=%@ / serial=%@", gIdent[@"model"], gIdent[@"os"], gIdent[@"build"], gIdent[@"idfv"], gIdent[@"serial"]);
    return gIdent;
}

static NSString *S(id key) { return Ident()[key]; }
static uint64_t UNum(id key) { return [Ident()[key] unsignedLongLongValue]; }
static int INum(id key) { return [Ident()[key] intValue]; }

// ============================================================
// 3b. 对齐探探包内插件留下的身份文件
//     deep_env.plist / spoof_identity.plist 由探探 xh.dylib 写入，
//     若与 XHSpoof 身份不一致会造成交叉校验矛盾。这里在启动时
//     把两文件的硬件字段同步为 XHSpoof 的同一套随机值。
// ============================================================
static void SyncTantanPlists(void) {
    NSDictionary *I = Ident();
    NSArray *p = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *dir = p.count ? p[0] : @"/var/mobile/Documents";

    // ---- deep_env.plist ----
    NSString *deepPath = [[dir stringByAppendingPathComponent:@"deep_env.plist"] stringByStandardizingPath];
    NSMutableDictionary *deep = [[NSDictionary dictionaryWithContentsOfFile:deepPath] mutableCopy];
    if (!deep) deep = [NSMutableDictionary dictionary];
    deep[@"batteryPct"] = I[@"battery"];
    deep[@"blueAddr"]   = I[@"btMAC"];
    deep[@"bootTime"]   = I[@"boottime"];
    deep[@"bootUuid"]   = I[@"bootuuid"];
    deep[@"dieId"]      = I[@"dieid"];
    deep[@"iccid"]      = I[@"iccid"];
    deep[@"imei"]       = I[@"imei"];
    deep[@"ioupuid"]    = I[@"ioupuid"];
    deep[@"mlbSerial"]  = I[@"mlb"];
    deep[@"regModel"]   = I[@"regmodel"];
    deep[@"serial"]     = I[@"serial"];
    deep[@"wifiBSSID"]  = I[@"bssid"];
    deep[@"wifiMac"]    = I[@"wifiMAC"];
    deep[@"wifiSSID"]   = I[@"ssid"];
    NSString *car = I[@"carrier"];
    deep[@"carrierIdx"] = [car containsString:@"联通"] ? @(2) : ([car containsString:@"电信"] ? @(3) : @(1));
    [deep writeToFile:deepPath atomically:YES];

    // ---- spoof_identity.plist ----
    NSString *spPath = [[dir stringByAppendingPathComponent:@"spoof_identity.plist"] stringByStandardizingPath];
    NSMutableDictionary *sp = [[NSDictionary dictionaryWithContentsOfFile:spPath] mutableCopy];
    if (!sp) sp = [NSMutableDictionary dictionary];
    sp[@"idfv"]       = I[@"idfv"];
    sp[@"idfa"]       = I[@"idfa"];
    sp[@"oneId"]      = I[@"oneid"];
    sp[@"localId"]    = I[@"localid"];
    sp[@"product"]    = I[@"machine"];
    sp[@"model"]      = I[@"model"];
    sp[@"os"]         = I[@"os"];
    sp[@"build"]      = I[@"build"];
    sp[@"disk"]       = @(UNum(@"disk") / (1024ULL*1024ULL*1024ULL));
    sp[@"uptime"]     = @((uint64_t)[[NSDate date] timeIntervalSince1970] - UNum(@"boottime"));
    sp[@"devidOn"]    = @YES;
    sp[@"msMid"]      = I[@"msmid"];
    sp[@"wPlatform"]  = [NSString stringWithFormat:@"%@__weibosdk__663233417__iphone__os%@", I[@"machine"], I[@"os"]];
    [sp writeToFile:spPath atomically:YES];

    // ---- Library/Preferences 里的第三方 SDK 持久标识（NSUserDefaults 层）----
    // 这些是"每次重启都一样"的元凶，用同一套随机身份覆写
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    NSDictionary *sdkKeys = @{
        @"idfa": I[@"idfa"],
        @"oneId": I[@"oneid"],
        @"oneid": I[@"oneid"],
        @"localId": I[@"localid"],
        @"ms_mid": I[@"msmid"],
        @"ms_n_mid": I[@"msmid"],
        @"WEIBOSDKAID": I[@"weibosdkid"],
        @"AppsFlyerUserId": I[@"appsflyerid"],
        @"radar_momo_uuid": I[@"momouuid"],
        @"tantan_shuzilm_cn_cdid_du": I[@"cdid"],
        @"APP_TOKEN": I[@"apptoken"],
        @"VENDOR_TOKEN": I[@"vendortoken"],
        @"machinePlatForm": [NSString stringWithFormat:@"%@__weibosdk__663233417__iphone__os%@", I[@"machine"], I[@"os"]],
        @"wPlatform": [NSString stringWithFormat:@"%@__weibosdk__663233417__iphone__os%@", I[@"machine"], I[@"os"]],
    };
    for (NSString *k in sdkKeys) [ud setObject:sdkKeys[k] forKey:k];
    [ud synchronize];

    // AppGroup 共享偏好（文件层双保险）
    NSString *libPrefs = [[dir stringByAppendingPathComponent:@"../Library/Preferences"] stringByStandardizingPath];
    for (NSString *name in @[@"group.com.yaymedialabs.putong.shareddata.plist",
                             @"com.yaymedialabs.putong.shareddata.plist",
                             @"com.cmcc.unique.id.plist"]) {
        NSString *fp = [libPrefs stringByAppendingPathComponent:name];
        NSMutableDictionary *d = [[NSDictionary dictionaryWithContentsOfFile:fp] mutableCopy];
        if (!d) d = [NSMutableDictionary dictionary];
        for (NSString *k in sdkKeys) if (d[k]) d[k] = sdkKeys[k];
        if ([name isEqualToString:@"com.cmcc.unique.id.plist"]) d[@"uniqueId"] = I[@"cmccid"];
        [d writeToFile:fp atomically:YES];
    }

    XHLOG(@"已对齐探探身份文件与SDK标识: deep_env / spoof_identity / 第三方SDK -> 统一机型 %@ / 序列号 %@", I[@"machine"], I[@"serial"]);
}

// ============================================================
// 4. Objective-C 方法替换工具
// ============================================================
static void Swizzle(Class cls, SEL sel, IMP imp, BOOL classMethod) {
    if (!cls) return;
    Method m = classMethod ? class_getClassMethod(cls, sel) : class_getInstanceMethod(cls, sel);
    if (!m) return;
    method_setImplementation(m, imp);
}
static void SwizzleNames(NSArray *names, SEL sel, IMP imp, BOOL classMethod) {
    for (NSString *n in names) Swizzle(objc_getClass(n.UTF8String), sel, imp, classMethod);
}

// ---- UIDevice ----
static id sp_idfv(id self, SEL _cmd) { return [[NSUUID alloc] initWithUUIDString:S(@"idfv")]; }
static id sp_idfa(id self, SEL _cmd) { return [[NSUUID alloc] initWithUUIDString:S(@"idfa")]; }
static NSString *sp_name(id self, SEL _cmd) { return S(@"name"); }
static NSString *sp_model(id self, SEL _cmd) { return S(@"model"); }
static NSString *sp_localizedModel(id self, SEL _cmd) { return S(@"model"); }
static NSString *sp_sysver(id self, SEL _cmd) { return S(@"os"); }
static NSString *sp_sysname(id self, SEL _cmd) { return @"iPhone OS"; }
static NSString *sp_udid(id self, SEL _cmd) { return S(@"udid"); }

// ---- NSProcessInfo ----
static uint64_t sp_physmem(id self, SEL _cmd) { return UNum(@"mem"); }
static NSUInteger sp_cpucount(id self, SEL _cmd) { return (NSUInteger)INum(@"cpu"); }
static NSString *sp_osverstr(id self, SEL _cmd) {
    return [NSString stringWithFormat:@"Version %@ (Build %@)", S(@"os"), S(@"build")];
}
static NSOperatingSystemVersion sp_osver(id self, SEL _cmd) {
    NSArray *p = [S(@"os") componentsSeparatedByString:@"."];
    NSOperatingSystemVersion v = {0};
    v.majorVersion = p.count>0 ? [p[0] intValue] : 13;
    v.minorVersion = p.count>1 ? [p[1] intValue] : 6;
    v.patchVersion = p.count>2 ? [p[2] intValue] : 0;
    return v;
}

// ---- NSFileManager 磁盘容量 ----
// 保存原始 IMP，避免 objc_msgSend 递归调用自身
typedef NSDictionary *(*fn_attrsFS)(id, SEL, NSString *, NSError **);
static fn_attrsFS orig_attrsFS = NULL;
static NSDictionary *sp_attrsFS(id self, SEL _cmd, NSString *path, NSError **err) {
    NSDictionary *real = orig_attrsFS ? orig_attrsFS(self, _cmd, path, err) : nil;
    NSMutableDictionary *m = real ? [real mutableCopy] : [NSMutableDictionary dictionary];
    m[NSFileSystemSize] = @(UNum(@"disk"));
    m[NSFileSystemFreeSize] = @(UNum(@"disk") / 3);
    m[NSFileSystemNodes] = @(1000000);
    m[NSFileSystemFreeNodes] = @(700000);
    return m;
}

// ============================================================
// 5. fishhook — C 层系统函数拦截
// ============================================================

// ---- sysctlbyname ----
typedef int (*fn_sysctlbyname)(const char *, void *, size_t *, void *, size_t);
static fn_sysctlbyname orig_sysctlbyname = NULL;
static int sp_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (name) {
        const char *val = NULL;
        uint64_t u64 = 0; int i32 = 0;
        // 机型
        if (!strcmp(name,"hw.machine")||!strcmp(name,"hw.model")||!strcmp(name,"hw.product")||!strcmp(name,"hw.board_id"))
            val = S(@"machine").UTF8String;
        else if (!strcmp(name,"kern.osversion")) val = S(@"build").UTF8String;
        else if (!strcmp(name,"kern.osrelease")) val = @"19.0.0".UTF8String;
        else if (!strcmp(name,"kern.osproductversion")) val = S(@"os").UTF8String;
        else if (!strcmp(name,"kern.boottime")) {
            struct timeval tv = {(time_t)UNum(@"boottime"), 0};
            if (oldlenp) { if (!oldp) {*oldlenp=sizeof(tv);return 0;} if (*oldlenp>=sizeof(tv)){memcpy(oldp,&tv,sizeof(tv));*oldlenp=sizeof(tv);return 0;} *oldlenp=sizeof(tv);return -1; }
            return 0;
        }
        else if (!strcmp(name,"hw.memsize")) u64 = UNum(@"mem");
        else if (!strcmp(name,"hw.ncpu")||!strcmp(name,"hw.physicalcpu")||!strcmp(name,"hw.logicalcpu")||!strcmp(name,"hw.physicalcpu_max")) i32 = INum(@"cpu");
        else if (!strcmp(name,"hw.byteorder")) i32 = 1234;
        else if (!strcmp(name,"hw.optional.arm64")) i32 = 1;
        if (val) {
            size_t need = strlen(val)+1;
            if (oldlenp) { if (!oldp){*oldlenp=need;return 0;} if (*oldlenp>=need){strcpy((char*)oldp,val);*oldlenp=need;return 0;} *oldlenp=need;return -1; }
            return 0;
        }
        if (u64) {
            if (oldlenp) { if (!oldp){*oldlenp=sizeof(u64);return 0;} if (*oldlenp>=sizeof(u64)){memcpy(oldp,&u64,sizeof(u64));*oldlenp=sizeof(u64);return 0;} *oldlenp=sizeof(u64);return -1; }
            return 0;
        }
        if (i32) {
            if (oldlenp) { if (!oldp){*oldlenp=sizeof(i32);return 0;} if (*oldlenp>=sizeof(i32)){memcpy(oldp,&i32,sizeof(i32));*oldlenp=sizeof(i32);return 0;} *oldlenp=sizeof(i32);return -1; }
            return 0;
        }
    }
    return orig_sysctlbyname ? orig_sysctlbyname(name,oldp,oldlenp,newp,newlen) : -1;
}

// ---- sysctl（按 name 数组形式）----
typedef int (*fn_sysctl)(int *, unsigned int *, void *, size_t *, void *, size_t);
static fn_sysctl orig_sysctl = NULL;
static int sp_sysctl(int *name, unsigned int *namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    // 数组版 sysctl 在探探 dyld 初始化极早期会被以异常 name 指针调用，
    // 访问 name[1] 触发 SIGSEGV(0x4)，导致启动即闪退。
    // 机型/内存/CPU 伪装已由字符串版 sp_sysctlbyname 完整覆盖，
    // 这里改为纯透传，彻底消除该崩溃点；不移除 hook 以免破坏 rebind 布局。
    return orig_sysctl ? orig_sysctl(name,namelen,oldp,oldlenp,newp,newlen) : -1;
}

// ---- uname ----
typedef int (*fn_uname)(struct utsname *);
static fn_uname orig_uname = NULL;
static int sp_uname(struct utsname *u) {
    int r = orig_uname ? orig_uname(u) : -1;
    if (r == 0 && u) {
        strncpy(u->machine, S(@"machine").UTF8String, sizeof(u->machine)-1);
        strncpy(u->nodename, S(@"name").UTF8String, sizeof(u->nodename)-1);
        strncpy(u->release, "19.0.0", sizeof(u->release)-1);
        strncpy(u->version, S(@"build").UTF8String, sizeof(u->version)-1);
    }
    return r;
}

// ---- gethostname ----
typedef int (*fn_gethostname)(char *, size_t);
static fn_gethostname orig_gethostname = NULL;
static int sp_gethostname(char *buf, size_t len) {
    const char *n = S(@"name").UTF8String;
    if (buf && len > strlen(n)) { strcpy(buf, n); return 0; }
    return orig_gethostname ? orig_gethostname(buf, len) : -1;
}

// ---- sysconf ----
typedef long (*fn_sysconf)(int);
static fn_sysconf orig_sysconf = NULL;
static long sp_sysconf(int name) {
    if (name == _SC_NPROCESSORS_ONLN || name == _SC_NPROCESSORS_CONF) return INum(@"cpu");
    if (name == _SC_PHYS_PAGES) return (long)(UNum(@"mem") / 4096);
    return orig_sysconf ? orig_sysconf(name) : -1;
}

// ---- host_statistics64 ----
typedef kern_return_t (*fn_host_stat64)(host_t, host_flavor_t, host_info64_t, mach_msg_type_number_t *);
static fn_host_stat64 orig_host_stat64 = NULL;
static kern_return_t sp_host_stat64(host_t h, host_flavor_t f, host_info64_t info, mach_msg_type_number_t *count) {
    kern_return_t r = orig_host_stat64 ? orig_host_stat64(h, f, info, count) : KERN_FAILURE;
    return r;
}

// ---- statfs（arm64 上 statfs/statfs64 同一实现）----
typedef int (*fn_statfs)(const char *, struct statfs *);
static fn_statfs orig_statfs = NULL;
static int sp_statfs(const char *path, struct statfs *buf) {
    int r = orig_statfs ? orig_statfs(path, buf) : -1;
    if (r == 0 && buf) {
        buf->f_blocks = (fsblkcnt_t)(UNum(@"disk") / 4096);
        buf->f_bfree = buf->f_blocks / 3;
        buf->f_bavail = buf->f_bfree;
    }
    return r;
}

// ---- access（隐藏越狱路径）----
typedef int (*fn_access)(const char *, int);
static fn_access orig_access = NULL;
static int sp_access(const char *path, int mode) {
    if (path) {
        static const char *deny[] = {"/Applications/Cydia.app","/Library/MobileSubstrate","/usr/bin/ssh","/etc/apt","/bin/bash","/private/var/stash","/.installed_yaluX","/jb","/usr/bin/cycript",NULL};
        for (int i=0; deny[i]; i++) if (strstr(path, deny[i])) return -1;
    }
    return orig_access ? orig_access(path, mode) : -1;
}

// ---- getifaddrs：改写 en0 / pdp_ip / bnep 的 MAC ----
typedef int (*fn_getifaddrs)(struct ifaddrs **);
static fn_getifaddrs orig_getifaddrs = NULL;
static int sp_getifaddrs(struct ifaddrs **ifap) {
    int r = orig_getifaddrs ? orig_getifaddrs(ifap) : -1;
    if (r == 0 && ifap && *ifap) {
        for (struct ifaddrs *a = *ifap; a; a = a->ifa_next) {
            if (!a->ifa_addr) continue;
            if (a->ifa_addr->sa_family != AF_LINK) continue;
            const char *ifname = a->ifa_name ? a->ifa_name : "";
            NSString *mac = nil;
            if (!strncmp(ifname,"en0",3)) mac = S(@"en0MAC");
            else if (!strncmp(ifname,"pdp_ip",6)) mac = S(@"wifiMAC");
            else if (!strncmp(ifname,"bnep",4)) mac = S(@"btMAC");
            if (mac) {
                struct sockaddr_dl *sdl = (struct sockaddr_dl *)a->ifa_addr;
                unsigned char *addr = (unsigned char *)LLADDR(sdl);
                NSArray *parts = [mac componentsSeparatedByString:@":"];
                for (int i=0; i<6 && i<sdl->sdl_alen; i++) addr[i] = (unsigned char)[parts[i] intValue];
            }
        }
    }
    return r;
}

// ---- IORegistryEntryCreateCFProperty（序列号 / MAC / chipid / UDID）----
typedef CFTypeRef (*fn_IOReg)(void *, CFStringRef, CFAllocatorRef, IOOptionBits);
static fn_IOReg orig_IOReg = NULL;
static CFTypeRef sp_IOReg(void *entry, CFStringRef key, CFAllocatorRef alloc, IOOptionBits opts) {
    if (key) {
        NSString *k = (__bridge NSString *)key;
        NSString *val = nil;
        if ([k isEqualToString:@"IOPlatformSerialNumber"]) val = S(@"serial");
        else if ([k isEqualToString:@"MLBSerialNumber"] || [k isEqualToString:@"sysinfo_mlb_serial"]) val = S(@"mlb");
        else if ([k isEqualToString:@"IOMACAddress"] || [k isEqualToString:@"sysinfo_mac_address"]) {
            // MAC 是 6 字节数据，返回 CFData
            NSArray *parts = [S(@"wifiMAC") componentsSeparatedByString:@":"];
            uint8_t b[6]; for (int i=0;i<6;i++) b[i]=(uint8_t)[parts[i] intValue];
            CFDataRef d = CFDataCreate(kCFAllocatorDefault, b, 6);
            return d;
        }
        else if ([k isEqualToString:@"chipid"] || [k isEqualToString:@"cpufamily"]) val = S(@"chipid");
        else if ([k isEqualToString:@"UUID"] || [k isEqualToString:@"IOPlatformUUID"]) val = S(@"udid");
        if (val) return CFBridgingRetain(val);
    }
    return orig_IOReg ? orig_IOReg(entry, key, alloc, opts) : NULL;
}

// ---- MobileGestalt MGCopyAnswer（UDID / 序列号 / 机型 / IMEI 等）----
typedef CFTypeRef (*fn_MGCopy)(CFStringRef);
static fn_MGCopy orig_MGCopy = NULL;
static CFTypeRef sp_MGCopy(CFStringRef q) {
    if (q) {
        NSString *qq = (__bridge NSString *)q;
        NSString *val = nil;
        if ([qq isEqualToString:@"UniqueDeviceID"]) val = S(@"udid");
        else if ([qq isEqualToString:@"SerialNumber"]) val = S(@"serial");
        else if ([qq isEqualToString:@"ProductType"]) val = S(@"machine");
        else if ([qq isEqualToString:@" HWModelStr"] || [qq isEqualToString:@"HWModelStr"]) val = S(@"machine");
        else if ([qq isEqualToString:@"DeviceName"]) val = S(@"model");
        else if ([qq isEqualToString:@"ProductVersion"]) val = S(@"os");
        else if ([qq isEqualToString:@"BuildVersion"]) val = S(@"build");
        else if ([qq isEqualToString:@"IMEI"]) val = S(@"imei");
        else if ([qq isEqualToString:@"ICCID"]) val = S(@"iccid");
        else if ([qq isEqualToString:@"MobileEquipmentIdentifier"]) val = S(@"imei");
        else if ([qq isEqualToString:@"ChipID"]) val = S(@"chipid");
        else if ([qq isEqualToString:@"WifiAddress"]) val = S(@"wifiMAC");
        else if ([qq isEqualToString:@"BluetoothAddress"]) val = S(@"btMAC");
        // 补：监管型号 / dieid / 开机UUID / 各类持久标识
        else if ([qq isEqualToString:@"RegulatoryModelNumber"] || [qq isEqualToString:@"regulatory-model-number"]) val = S(@"regmodel");
        else if ([qq isEqualToString:@"DieID"] || [qq isEqualToString:@"dieId"]) val = S(@"dieid");
        else if ([qq isEqualToString:@"BootUUID"] || [qq isEqualToString:@"bootUuid"]) val = S(@"bootuuid");
        else if ([qq isEqualToString:@"IOPlatformUUID"]) val = S(@"ioupuid");
        else if ([qq isEqualToString:@"OneID"] || [qq isEqualToString:@"oneId"]) val = S(@"oneid");
        else if ([qq isEqualToString:@"LocalID"] || [qq isEqualToString:@"localId"]) val = S(@"localid");
        else if ([qq isEqualToString:@"ms_mid"] || [qq isEqualToString:@"msMid"]) val = S(@"msmid");
        else if ([qq isEqualToString:@"WEIBOSDKAID"]) val = S(@"weibosdkid");
        else if ([qq isEqualToString:@"AppsFlyerUserId"]) val = S(@"appsflyerid");
        else if ([qq isEqualToString:@"cmcc_unique_id"]) val = S(@"cmccid");
        else if ([qq isEqualToString:@"momo_uuid"]) val = S(@"momouuid");
        else if ([qq isEqualToString:@"cdid"] || [qq isEqualToString:@"cdid_du"]) val = S(@"cdid");
        if (val) return CFBridgingRetain(val);
    }
    return orig_MGCopy ? orig_MGCopy(q) : NULL;
}

// ---- CNCopyCurrentNetworkInfo（WiFi SSID/BSSID）----
typedef CFDictionaryRef (*fn_CNCopy)(CFStringRef);
static fn_CNCopy orig_CNCopy = NULL;
static CFDictionaryRef sp_CNCopy(CFStringRef ifname) {
    CFDictionaryRef real = orig_CNCopy ? orig_CNCopy(ifname) : NULL;
    NSMutableDictionary *m = real ? [(__bridge NSDictionary *)real mutableCopy] : [NSMutableDictionary dictionary];
    m[@"SSID"] = S(@"ssid");
    m[@"BSSID"] = S(@"bssid");
    return CFBridgingRetain(m);
}

// ---- CTCarrier 运营商 ----
static NSString *sp_carrierName(id self, SEL _cmd) { return S(@"carrier"); }
static NSString *sp_isoCountryCode(id self, SEL _cmd) { return @"cn"; }
static NSString *sp_mobileCountryCode(id self, SEL _cmd) { return @"460"; }
static NSString *sp_mobileNetworkCode(id self, SEL _cmd) {
    NSString *c = S(@"carrier");
    if ([c containsString:@"联通"]) return @"01";
    if ([c containsString:@"电信"]) return @"03";
    return @"00";
}

// ---- 补：电池电量/状态（真读的 batteryPct）----
static float sp_batteryLevel(id self, SEL _cmd) { return INum(@"battery") / 100.0f; }
static long sp_batteryState(id self, SEL _cmd) { return 2; /* UIDeviceBatteryStateUnplugged */ }

// ---- 补：网络制式 RAT（与 onwifi 联动，消除 wifi/4G 矛盾）----
static NSString *sp_rat(id self, SEL _cmd) {
    if ([S(@"onwifi") boolValue]) return nil;   // 已连 WiFi -> 蜂窝制式为空
    return S(@"rat");
}
static NSDictionary *sp_serviceRat(id self, SEL _cmd) {
    if ([S(@"onwifi") boolValue]) return @{};
    return @{@"0": S(@"rat")};
}

// ---- 补：屏幕亮度 ----
static float sp_brightness(id self, SEL _cmd) { return 0.3f + arc4random_uniform(60)/100.0f; }

// ---- 剪贴板：读取一律返回空 ----
static NSString *sp_pasteboardString(id self, SEL _cmd) { return @""; }
static NSData *sp_pasteboardData(id self, SEL _cmd) { return [NSData data]; }
static NSURL *sp_pasteboardURL(id self, SEL _cmd) { return nil; }
static NSInteger sp_pasteboardChangeCount(id self, SEL _cmd) { return 0; }

// ---- ATT 授权态：未授权(3) ----
static long sp_attStatus(id self, SEL _cmd) { return 3; }
static void sp_requestAtt(id self, SEL _cmd, id handler) { /* no-op */ }

// ---- 传感器：不可用 ----
static BOOL sp_no(id self, SEL _cmd) { return NO; }

// ============================================================
// 6. 安装所有 hook（constructor 只跑一次，幂等）
// ============================================================
static void InstallAll(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        // 先固化身份（生成/读取 plist），后续所有 hook 都用同一套值
        Ident();
        // 对齐探探包内插件的身份文件，消除两套身份交叉矛盾
        SyncTantanPlists();

        // ---- ObjC swizzle ----
        SwizzleNames(@[@"UIDevice"], @selector(identifierForVendor), (IMP)sp_idfv, NO);
        SwizzleNames(@[@"UIDevice"], @selector(name), (IMP)sp_name, NO);
        SwizzleNames(@[@"UIDevice"], @selector(model), (IMP)sp_model, NO);
        SwizzleNames(@[@"UIDevice"], @selector(localizedModel), (IMP)sp_localizedModel, NO);
        SwizzleNames(@[@"UIDevice"], @selector(systemVersion), (IMP)sp_sysver, NO);
        SwizzleNames(@[@"UIDevice"], @selector(systemName), (IMP)sp_sysname, NO);
        SwizzleNames(@[@"UIDevice"], @selector(uniqueIdentifier), (IMP)sp_udid, NO);
        // 补：电池（batteryPct 真读入口）
        SwizzleNames(@[@"UIDevice"], @selector(batteryLevel), (IMP)sp_batteryLevel, NO);
        SwizzleNames(@[@"UIDevice"], @selector(batteryState), (IMP)sp_batteryState, NO);
        SwizzleNames(@[@"UIScreen"], @selector(brightness), (IMP)sp_brightness, NO);
        SwizzleNames(@[@"ASIdentifierManager"], @selector(advertisingIdentifier), (IMP)sp_idfa, NO);
        SwizzleNames(@[@"ASIdentifierManager"], @selector(isAdvertisingTrackingEnabled), (IMP)sp_no, NO);
        SwizzleNames(@[@"NSProcessInfo"], @selector(physicalMemory), (IMP)sp_physmem, NO);
        SwizzleNames(@[@"NSProcessInfo"], @selector(processorCount), (IMP)sp_cpucount, NO);
        SwizzleNames(@[@"NSProcessInfo"], @selector(activeProcessorCount), (IMP)sp_cpucount, NO);
        SwizzleNames(@[@"NSProcessInfo"], @selector(operatingSystemVersionString), (IMP)sp_osverstr, NO);
        SwizzleNames(@[@"NSProcessInfo"], @selector(operatingSystemVersion), (IMP)sp_osver, NO);
        // NSFileManager 需要保存原始 IMP 避免递归
        {
            Class fcls = objc_getClass("NSFileManager");
            Method fm = class_getInstanceMethod(fcls, @selector(attributesOfFileSystemForPath:error:));
            if (fm) { orig_attrsFS = (fn_attrsFS)method_getImplementation(fm); method_setImplementation(fm, (IMP)sp_attrsFS); }
        }

        // 运营商
        SwizzleNames(@[@"CTCarrier"], @selector(carrierName), (IMP)sp_carrierName, NO);
        SwizzleNames(@[@"CTCarrier"], @selector(isoCountryCode), (IMP)sp_isoCountryCode, NO);
        SwizzleNames(@[@"CTCarrier"], @selector(mobileCountryCode), (IMP)sp_mobileCountryCode, NO);
        SwizzleNames(@[@"CTCarrier"], @selector(mobileNetworkCode), (IMP)sp_mobileNetworkCode, NO);
        // 补：RAT 网络制式（与 onwifi 联动）
        {
            Class tn = objc_getClass("CTTelephonyNetworkInfo");
            Swizzle(tn, @selector(currentRadioAccessTechnology), (IMP)sp_rat, NO);
            Swizzle(tn, @selector(serviceCurrentRadioAccessTechnology), (IMP)sp_serviceRat, NO);
        }

        // 剪贴板
        Class pb = objc_getClass("UIPasteboard");
        SwizzleNames(@[@"UIPasteboard"], @selector(string), (IMP)sp_pasteboardString, NO);
        SwizzleNames(@[@"UIPasteboard"], @selector(data), (IMP)sp_pasteboardData, NO);
        SwizzleNames(@[@"UIPasteboard"], @selector(url), (IMP)sp_pasteboardURL, NO);
        SwizzleNames(@[@"UIPasteboard"], @selector(changeCount), (IMP)sp_pasteboardChangeCount, NO);

        // ATT
        Class att = objc_getClass("ATTrackingManager");
        if (att) {
            Method m = class_getClassMethod(att, @selector(trackingAuthorizationStatus));
            if (m) method_setImplementation(m, (IMP)sp_attStatus);
            m = class_getClassMethod(att, @selector(requestTrackingAuthorizationWithCompletionHandler:));
            if (m) method_setImplementation(m, (IMP)sp_requestAtt);
        }

        // 传感器（可用性返回 NO）
        SwizzleNames(@[@"CMMotionManager"], @selector(isAccelerometerAvailable), (IMP)sp_no, NO);
        SwizzleNames(@[@"CMMotionManager"], @selector(isGyroAvailable), (IMP)sp_no, NO);
        SwizzleNames(@[@"CMMotionManager"], @selector(isMagnetometerAvailable), (IMP)sp_no, NO);
        SwizzleNames(@[@"CMMotionManager"], @selector(isDeviceMotionAvailable), (IMP)sp_no, NO);

        // ---- C 层 fishhook ----
        rebind_symbols((struct rebinding[]){
            {"sysctlbyname", (void *)sp_sysctlbyname, (void **)&orig_sysctlbyname},
            {"sysctl", (void *)sp_sysctl, (void **)&orig_sysctl},
            {"uname", (void *)sp_uname, (void **)&orig_uname},
            {"gethostname", (void *)sp_gethostname, (void **)&orig_gethostname},
            {"sysconf", (void *)sp_sysconf, (void **)&orig_sysconf},
            {"host_statistics64", (void *)sp_host_stat64, (void **)&orig_host_stat64},
            {"statfs", (void *)sp_statfs, (void **)&orig_statfs},
            {"access", (void *)sp_access, (void **)&orig_access},
            {"getifaddrs", (void *)sp_getifaddrs, (void **)&orig_getifaddrs},
            {"IORegistryEntryCreateCFProperty", (void *)sp_IOReg, (void **)&orig_IOReg},
            {"CNCopyCurrentNetworkInfo", (void *)sp_CNCopy, (void **)&orig_CNCopy},
        }, 12);

        // MGCopyAnswer 是 dlsym 动态解析的私有符号，单独弱绑定
        orig_MGCopy = (fn_MGCopy)dlsym(RTLD_DEFAULT, "MGCopyAnswer");
        if (orig_MGCopy) {
            struct rebinding rb = {"MGCopyAnswer", (void *)sp_MGCopy, (void **)&orig_MGCopy};
            rebind_symbols(&rb, 1);
        }

        XHLOG(@"安装完成: 机型=%@ 系统=%@ IDFV=%@ serial=%@ MAC=%@",
              S(@"model"), S(@"os"), S(@"idfv"), S(@"serial"), S(@"wifiMAC"));
    });
}

__attribute__((constructor))
static void xhspoof_init(void) {
    @autoreleasepool {
        InstallAll();
    }
}
