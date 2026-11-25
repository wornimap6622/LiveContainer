// ============================================================
// 探探 7.6.4 反越狱对抗 + 认证跳过 + 会员插件 (纯 Runtime Hook 版)
// ============================================================
// 适配版本: 探探 7.6.4 (app.kale3184.meteor7979)
//
// 【7.4.2 → 7.6.4 关键变更】(逆向确认):
//   1. 会员判断从 PUGUser-isVip / PUGCommercializeService+hasSVIPPrivilege
//      迁移到多类型会员体系:
//         isMembershipUser / isMembershipDiamondUser / isMembershipPlatinumUser /
//         isMembershipPartnerUser / isUltraSvip / isOtherVip /
//         hasMembershipDiamond / hasMembershipPlatinum /
//         hasAIChatAssistantMembership / hasSeeWhoLikedMeMembership /
//         hasExpQuickChatMembership / hasQuickChatMembershipPrivilege /
//         hasPrivacyMembership / hasIntlMembership 等
//   2. showSelectVC: 改名为 showSelectVCIfNeeded:
//   3. 反越狱方法 (isJailed/isBanned/isAvatarUnReal) 仍在, 但已变为
//      MTLModel 属性 getter (selector 不变, 仍可 hook)
//   4. svipExpiredDate 已从 PUGPrivilegeUseCase 类方法变为
//      PUGChatGroupDetailViewModel 属性 (语义无关, 已移除该 hook)
//
// 方式方法: 纯 ObjC runtime API 替换方法实现, 不依赖 Cydia Substrate,
// 可运行于免越狱环境 (注入 IPA + 开发者证书签名)。
// ============================================================

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import "HelloXihuanManager.h"
#import "HelloXihuanMainViewController.h"
#import "HelloSendMgr.h"
#import "HelloHelper.h"
#import "HelloCountdownLabel.h"
#import "HelloGlobalBall.h"
#import "HelloGuowai.h"
#import "HelloAuth.h"
#import <objc/runtime.h>
#import <objc/message.h>
#import <sys/types.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <netdb.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <signal.h>
#import <unistd.h>
#include <stdlib.h>
#include "fishhook.h"
#include <sys/sysctl.h>
#include <sys/mount.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/ethernet.h>
#include <string.h>
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <CoreTelephony/CTCarrier.h>
#import <IOKit/IOKitLib.h>

// Dobby inline hook (支持 arm64e PAC)
int DobbyHook(void *address, void *fake_func, void **out_origin_func);

// ============================================================
// 认证跳过开关: 1=启用认证跳过(吞掉验证弹窗), 0=禁用(让弹窗正常弹出)
// 临时调试用: 设为 0 可观察弹窗到底是"实名认证"还是"真人头像认证"
// ============================================================
#define ENABLE_AUTH_SKIP 1

// ============================================================
// 统一功能开关系统 (供悬浮球面板控制, NSUserDefaults 持久化)
// 各功能开关 key, 默认全部关闭 (装好不自作主张, 需要哪个在面板里手动开):
//   xh_switch.vip    会员/VIP 伪装 (默认关)
//   xh_switch.chat   聊天/发消息/打招呼权限 (默认关)
//   xh_switch.popup  认证/实名/绑定等弹窗跳过 (默认关)
//   xh_switch.pick   四选一(极限四选一, 含次数限制 + 接口对接, 关=正常匹配) (默认关)
//   xh_switch.spoofver 版本号伪装 (默认关)
//   xh_switch.device 设备改机/指纹伪装 (默认关)
// ============================================================
#define XH_SW_VIP       @"xh_switch.vip"
#define XH_SW_MATCH_LIMIT @"xh_switch.match_limit"  // 解除匹配限制(默认开)
#define XH_SW_CHAT      @"xh_switch.chat"
#define XH_SW_POPUP     @"xh_switch.popup"
#define XH_SW_PICK      @"xh_switch.pick"
#define XH_SW_SPOOFVER  @"xh_switch.spoofver"
#define XH_SW_DEVICE    @"xh_switch.device"
#define XH_SW_GUOWAI    @"xh_switch.guowai"
#define XH_SW_VERIFY    @"xh_switch.verify"
#define XH_SW_VERIFY_PICTURE @"xh_switch.verify_picture"  // 人脸(头像)认证
#define XH_SW_VERIFY_ID      @"xh_switch.verify_id"       // 实名(身份证)认证
#define XH_SW_BLOCK_CLEAR @"xh_switch.block_clear"         // 拦截清空登录态(注册后保留currentUser, 默认关)
#define XH_SW_V2_MSG @"xh_switch.v2_msg"                  // 发消息改V2接口(v3普通聊天限流->改走v2, 默认开)
#define XH_SW_SSL @"xh_switch.ssl"                        // 强制开启低版本网络(绕过 SSL Pinning, 允许抓包/代理)
#define XH_SW_LOCATION @"xh_switch.location"              // 地图定位(坐标伪造, 默认关)

// 设备改机开关的进程内缓存。
// 原因: NSUserDefaults 的 objectForKey/setObject 被 hook 后, 若在 hook 内部调 _devSpoofOn()
//       -> _swOn -> XHGetSwitch -> [ud objectForKey:] -> 又进 hook -> 无限递归 -> 栈溢出闪退(v70 事故)。
// 解决: 开关值只在两处更新(启动时读一次 / XHSetSwitch 写入时), hook 内部只读这个 BOOL。
static BOOL _gDevSpoofOn = NO;

// 跨文件可见: 读取开关 (默认值 defaultVal 用于未设置时)
BOOL XHGetSwitch(NSString *key, BOOL defaultVal);
// 跨文件可见: 写入开关
void XHSetSwitch(NSString *key, BOOL on);

// 内部: 开关是否开启 (未设置时默认 NO —— 所有功能默认关闭)
static inline BOOL _swOn(NSString *key) {
    return XHGetSwitch(key, NO);
}

// 无参数 unsigned long long hook 的开关守卫
#define XH_GUARD_ULL(key) \
    do { \
        if (!_swOn(key)) { \
            IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd); \
            if (o) return ((unsigned long long(*)(id,SEL))o)(self, _cmd); \
        } \
    } while(0)

// 无参数 id hook 的开关守卫
#define XH_GUARD_ID(key) \
    do { \
        if (!_swOn(key)) { \
            IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd); \
            if (o) return ((id(*)(id,SEL))o)(self, _cmd); \
        } \
    } while(0)

// 无参数 BOOL hook 的开关守卫: 开关关闭时调用原 IMP 返回真实值
#define XH_GUARD_BOOL(key) \
    do { \
        if (!_swOn(key)) { \
            IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd); \
            if (o) return ((BOOL(*)(id,SEL))o)(self, _cmd); \
        } \
    } while(0)

// 无参数 void hook 的开关守卫: 开关关闭时调用原 IMP (不做拦截)
#define XH_GUARD_VOID(key) \
    do { \
        if (!_swOn(key)) { \
            IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd); \
            if (o) { ((void(*)(id,SEL))o)(self, _cmd); return; } \
        } \
    } while(0)

// 原 IMP 保存表 (key: "类名#selector名", 用于开关关闭时回退到真实实现)
static NSMutableDictionary *g_origImpMap = nil;
static IMP _saveOrigImp(NSString *clsName, SEL sel, IMP orig) {
    if (!g_origImpMap) g_origImpMap = [NSMutableDictionary dictionary];
    if (orig) {
        NSString *k = [NSString stringWithFormat:@"%@#%@", clsName, NSStringFromSelector(sel)];
        g_origImpMap[k] = [NSValue valueWithPointer:orig];
    }
    return orig;
}
static IMP _getOrigImp(NSString *clsName, SEL sel) {
    if (!g_origImpMap) return NULL;
    NSString *k = [NSString stringWithFormat:@"%@#%@", clsName, NSStringFromSelector(sel)];
    NSValue *v = g_origImpMap[k];
    return v ? (IMP)[v pointerValue] : NULL;
}

// ============================================================
// 文件日志工具 (写到沙盒 Documents, 便于从设备拉取)
// 【干净版】XH_DEBUG_LOG=0 时完全静音(不写文件不 NSLog), 排查时改 1 重新开启
// 【验证模式】XH_DEBUG_LOG_KEYWORD=1 时只记录"招呼/对接"链路, 量极小,
//            用于确认自动招呼是否触发/发送成功, 不会像全量日志那样触发系统资源限制。
// ============================================================
#define XH_DEBUG_LOG 0
#define XH_DEBUG_LOG_KEYWORD 1

static void XLog(NSString *fmt, ...) {
#if XH_DEBUG_LOG
    // 全量日志模式
#elif XH_DEBUG_LOG_KEYWORD
    // 先判断格式串本身, 不含关键词直接返回 (高频调用如 [登录态] 零开销)
    if (!fmt) return;
    if (!([fmt containsString:@"[招呼]"] || [fmt containsString:@"[对接]"] || [fmt containsString:@"[喜欢我→划卡]"] || [fmt containsString:@"[喜欢我匹配]"] || [fmt containsString:@"[网络]"] || [fmt containsString:@"[原生网络]"] || [fmt containsString:@"[诊断]"] || [fmt containsString:@"[真实列表]"] || [fmt containsString:@"[关系真相]"] || [fmt containsString:@"[探针]"] || [fmt containsString:@"[桃心对接]"] || [fmt containsString:@"[动态赞]"] || [fmt containsString:@"[划卡名单]"] || [fmt containsString:@"[资料响应]"] || [fmt containsString:@"[关系JSON]"] || [fmt containsString:@"[登录模式]"] || [fmt containsString:@"[登录入口]"] || [fmt containsString:@"[改机]"] || [fmt containsString:@"[一键新机]"] || [fmt containsString:@"[随机指纹]"] || [fmt containsString:@"[深度环境]"])) return;
#else
    return;
#endif
    va_list args;
    va_start(args, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    @try {
        NSArray *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        NSString *p = [docs[0] stringByAppendingPathComponent:@"xh_debug.log"];
        NSString *line = [NSString stringWithFormat:@"%@ %@\n", [NSDate date], msg];
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:p];
        if (!fh) {
            [[NSFileManager defaultManager] createFileAtPath:p contents:nil attributes:nil];
            fh = [NSFileHandle fileHandleForWritingAtPath:p];
        }
        if (fh) {
            [fh seekToEndOfFile];
            [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
            [fh closeFile];
        }
    } @catch (NSException *e) {}
}

// ============================================================
// 随机指纹生成器 + 首次启动清理 (随机不重复)
// ============================================================
// 设计:
//   1. 首次启动(无 spoof_identity.plist)时, 随机生成 IDFV/IDFA/localId/oneid,
//      写入探探沙盒 Documents/spoof_identity.plist 持久化, 之后每次启动复用同一份。
//   2. 首次启动时清理 keychain / NSUserDefaults / MMKV 里的旧设备指纹残留,
//      确保换机后服务端拿到的是全新指纹(不关联旧号)。
//   3. 重新换机 = 删除 spoof_identity.plist + 触发首次启动清理, 重新随机。
// ============================================================

// 随机 UUID (v4 格式, 8-4-4-4-12)
static NSString *_randUUID(void) {
    NSMutableString *s = [NSMutableString string];
    for (int i = 0; i < 32; i++) {
        [s appendFormat:@"%x", (unsigned)arc4random_uniform(16)];
    }
    return [NSString stringWithFormat:@"%@-%@-%@-%@-%@",
            [s substringWithRange:NSMakeRange(0,8)],
            [s substringWithRange:NSMakeRange(8,4)],
            [s substringWithRange:NSMakeRange(12,4)],
            [s substringWithRange:NSMakeRange(16,4)],
            [s substringWithRange:NSMakeRange(20,12)]];
}

// 随机 localId: 32位十六进制(小写) + 固定后缀(对齐旧格式长度)
static NSString *_randLocalId(void) {
    NSMutableString *s = [NSMutableString string];
    for (int i = 0; i < 48; i++) {
        [s appendFormat:@"%x", (unsigned)arc4random_uniform(16)];
    }
    return s;
}

// 随机 oneid: 19位数字(探探 oneid 是 19 位十进制)
static NSString *_randOneId(void) {
    NSMutableString *s = [NSMutableString string];
    // 首位非0, 共19位
    [s appendFormat:@"%d", 1 + (int)arc4random_uniform(9)];
    for (int i = 1; i < 19; i++) {
        [s appendFormat:@"%d", (int)arc4random_uniform(10)];
    }
    return s;
}

// 数美 TXTOneId 的 ms_mid: 实测为 base64 串(64字节原始数据 -> 88字符左右)。
// 生成同长度同格式的随机 base64, 保证数美侧不会因格式异常直接判定篡改。
static NSString *_randMSMid(void) {
    uint8_t buf[64];
    arc4random_buf(buf, sizeof(buf));
    NSData *d = [NSData dataWithBytes:buf length:sizeof(buf)];
    return [d base64EncodedStringWithOptions:0];
}

// 微博 SDK 的 machinePlatForm: 实测格式 "<product>__weibosdk__<9位数字>__iphone__os<版本>"
static NSString *_randWPlatform(NSString *product, NSString *osVer) {
    return [NSString stringWithFormat:@"%@__weibosdk__%09u__iphone__os%@",
            product ?: @"iPhone12,1",
            (unsigned)(arc4random_uniform(1000000000)),
            osVer ?: @"13.6"];
}

// ============================================================
// 统一开关读写实现 (NSUserDefaults 持久化, 默认开)
// ============================================================
BOOL XHGetSwitch(NSString *key, BOOL defaultVal) {
    if (!key || key.length == 0) return defaultVal;
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    id v = [ud objectForKey:key];
    if (v == nil) return defaultVal;
    return [v boolValue];
}

void XHSetSwitch(NSString *key, BOOL on) {
    if (!key || key.length == 0) return;
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    [ud setBool:on forKey:key];
    [ud synchronize];
    // 同步更新缓存, 保证面板切换后 hook 立即按新状态工作
    if ([key isEqualToString:XH_SW_DEVICE]) _gDevSpoofOn = on;
}

// ============================================================
// 一次性迁移: 旧版所有开关默认开启, 升级后统一归零
// 只执行一次, 之后用户在面板里手动打开的开关会正常保留
// ============================================================
static void _migrate_switches_default_off(void) {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    // v3: 全量归零 —— 包括"设备改机"和"地图定位", 所有功能默认关闭, 用时在面板手动开。
    // 只在第一次执行(v3 标记), 之后用户在面板手动开/关的状态永久保留(一键新机也保留)。
    static NSString *const kMarkV3 = @"xh_switch.default_off_v3";
    if (![ud boolForKey:kMarkV3]) {
        NSArray *allKeys = @[XH_SW_VIP, XH_SW_CHAT, XH_SW_POPUP, XH_SW_PICK, XH_SW_SPOOFVER,
                             XH_SW_DEVICE, XH_SW_GUOWAI, XH_SW_VERIFY, XH_SW_VERIFY_PICTURE,
                             XH_SW_VERIFY_ID, XH_SW_BLOCK_CLEAR, XH_SW_V2_MSG,
                             XH_SW_MATCH_LIMIT, XH_SW_SSL, XH_SW_LOCATION];
        for (NSString *k in allKeys) [ud setBool:NO forKey:k];
        [ud setObject:@"1" forKey:@"mineIsChinese"];
        [ud setBool:YES forKey:kMarkV3];
        [ud setBool:YES forKey:@"xh_switch.default_off_v2"];
        [ud setBool:YES forKey:@"xh_switch.default_off_migrated"];
        [ud synchronize];
        XLog(@"[初始化] v3 开关归位完成: 全部关闭(共 %lu 项), 含设备改机/地图定位", (unsigned long)allKeys.count);
    }
}

// 探探沙盒 Documents 目录(命令行工具用 /var/mobile/Documents, 但 dylib 注入时用探探自己的沙盒)
static NSString *_docDir(void) {
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    return paths.count > 0 ? paths[0] : @"/var/mobile/Documents";
}

static NSArray *_spoofModelPool(void);
static NSDictionary *_spoofModelInfo(void);

// 指纹存储文件路径
static NSString *_spoofStorePath(void) {
    return [[_docDir() stringByAppendingPathComponent:@"spoof_identity.plist"] stringByStandardizingPath];
}

// 运行时指纹存储(懒加载, 首次启动随机生成并持久化)
static NSDictionary *_spoofIdentityCache = nil;   // 可重置缓存(一键新机时置 nil 强制重新随机)
static NSDictionary *_spoofIdentity(void) {
    if (_spoofIdentityCache) return _spoofIdentityCache;

    NSString *path = _spoofStorePath();
    NSDictionary *loaded = [NSDictionary dictionaryWithContentsOfFile:path];
    if (loaded[@"idfv"] && loaded[@"idfa"] && loaded[@"localId"] && loaded[@"product"]) {
        // 复用已有指纹, 但补齐后加的字段(老文件没有 msMid/wPlatform, 需补种)
        NSMutableDictionary *m = [loaded mutableCopy];
        BOOL dirty = NO;
        if (![m[@"msMid"] isKindOfClass:[NSString class]] || [m[@"msMid"] length] < 40) {
            m[@"msMid"] = _randMSMid(); dirty = YES;
        }
        if (![m[@"wPlatform"] isKindOfClass:[NSString class]] || [m[@"wPlatform"] length] == 0) {
            m[@"wPlatform"] = _randWPlatform(m[@"product"], m[@"os"]); dirty = YES;
        }
        if (dirty) { [m writeToFile:path atomically:YES]; }
        _spoofIdentityCache = m;
        XLog(@"[随机指纹] 复用已有指纹 idfv=%@ (补齐字段=%d)", m[@"idfv"], dirty);
        return _spoofIdentityCache;
    }

    // 首次启动: 随机生成全新指纹(不重复)
    NSArray *pool = _spoofModelPool();
    NSDictionary *model = pool[arc4random_uniform((uint32_t)pool.count)];
    NSDictionary *fresh = @{
        @"idfv":    _randUUID(),
        @"idfa":    _randUUID(),
        @"localId": _randLocalId(),
        @"oneId":   _randOneId(),
        @"product": model[@"p"],
        @"model":   model[@"n"],
        @"os":      model[@"os"],
        @"build":   model[@"b"],
        @"disk":    @(({ uint32_t idx = arc4random_uniform(3); idx == 0 ? 128 : (idx == 1 ? 256 : 512); })),
        @"uptime":  @((uint64_t)(arc4random_uniform(8 * 24 * 3600) + 24 * 3600)),
        @"devidOn": @YES,
        @"msMid":      _randMSMid(),
        @"wPlatform":  _randWPlatform(model[@"p"], model[@"os"]),
    };
    [fresh writeToFile:path atomically:YES];
    _spoofIdentityCache = fresh;
    XLog(@"[随机指纹] 首次启动生成全新指纹 idfv=%@ idfa=%@ localId=%@ oneId=%@",
         fresh[@"idfv"], fresh[@"idfa"], fresh[@"localId"], fresh[@"oneId"]);
    return _spoofIdentityCache;
}

// 取随机指纹各字段
static NSString *_spoofIDFV(void)   { return _spoofIdentity()[@"idfv"]; }
static NSString *_spoofIDFA(void)   { return _spoofIdentity()[@"idfa"]; }
static NSString *_spoofLocalId(void){ return _spoofIdentity()[@"localId"]; }
static NSString *_spoofOneId(void)  { return _spoofIdentity()[@"oneId"]; }

// ============================================================
// 随机机型池 (方案1: A13 同代, 与真机 iPhone 11 硬件对齐, 规避阿里ZIM交叉校验闪退)
// ============================================================
static NSArray *_spoofModelPool(void) {
    static NSArray *pool;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        pool = @[
            @{@"p": @"iPhone12,1", @"n": @"iPhone 11",        @"os": @"13.6", @"b": @"17G68", @"mem": @4294967296ULL, @"cpu": @6},
            @{@"p": @"iPhone12,3", @"n": @"iPhone 11 Pro",    @"os": @"13.6", @"b": @"17G68", @"mem": @4294967296ULL, @"cpu": @6},
            @{@"p": @"iPhone12,5", @"n": @"iPhone 11 Pro Max", @"os": @"13.6", @"b": @"17G68", @"mem": @4294967296ULL, @"cpu": @6},
            @{@"p": @"iPhone12,8", @"n": @"iPhone SE (2nd)",  @"os": @"13.6", @"b": @"17G68", @"mem": @3221225472ULL, @"cpu": @6},
        ];
    });
    return pool;
}

static NSDictionary *_spoofModelInfo(void) {
    NSDictionary *idn = _spoofIdentity();
    NSString *p = idn[@"product"];
    if (p.length) {
        for (NSDictionary *m in _spoofModelPool()) {
            if ([m[@"p"] isEqualToString:p]) return m;
        }
    }
    return _spoofModelPool()[0];
}

static NSString *_spoofProduct(void) { return _spoofModelInfo()[@"p"]; }
static NSString *_spoofModelName(void) { return _spoofModelInfo()[@"n"]; }
static NSString *_spoofOSString(void) { return _spoofModelInfo()[@"os"]; }
static NSString *_spoofBuildString(void) { return _spoofModelInfo()[@"b"]; }
static uint64_t _spoofMemBytes(void) { return [_spoofModelInfo()[@"mem"] unsignedLongLongValue]; }
static int _spoofCPUCount(void) { return [_spoofModelInfo()[@"cpu"] intValue]; }
static uint64_t _spoofDiskBytes(void) {
    NSNumber *n = _spoofIdentity()[@"disk"];
    uint64_t gb = n ? n.unsignedLongLongValue : 256;
    return gb * 1024ULL * 1024ULL * 1024ULL;
}
static uint64_t _spoofBootEpoch(void) {
    // 开机时间 = 现在 - 随机运行时长(1~9天), 每次换机重随机
    NSNumber *n = _spoofIdentity()[@"uptime"];
    uint64_t up = n ? n.unsignedLongLongValue : (uint64_t)(arc4random_uniform(8 * 24 * 3600) + 24 * 3600);
    return (uint64_t)time(NULL) - up;
}

// ============================================================
// 首次启动清理: 清 keychain / NSUserDefaults / MMKV 残留
// ============================================================
static void _clearKeychainItem(NSString *service, NSString *account, NSString *accessGroup) {
    @try {
        NSMutableDictionary *q = [NSMutableDictionary dictionary];
        q[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
        q[(__bridge id)kSecAttrService] = service;
        q[(__bridge id)kSecAttrAccount] = account;
        if (accessGroup && accessGroup.length > 0) {
            q[(__bridge id)kSecAttrAccessGroup] = accessGroup;
        }
        OSStatus st = SecItemDelete((__bridge CFDictionaryRef)q);
        XLog(@"[首次清理] keychain 删除 service=%@ account=%@ => %d", service, account, (int)st);
    } @catch (NSException *e) {
        XLog(@"[首次清理] keychain 删除异常: %@", e);
    }
}

// 枚举删除某 access group 下的所有 keychain 项(通用密码类)。
// 探探的 keychain svce/acct 是加密二进制, 无法用明文匹配, 只能用枚举+批量删。
static void _clearAllKeychainForAccessGroup(NSString *accessGroup) {
    @try {
        NSMutableDictionary *query = [NSMutableDictionary dictionary];
        query[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
        if (accessGroup && accessGroup.length > 0) {
            query[(__bridge id)kSecAttrAccessGroup] = accessGroup;
        }
        query[(__bridge id)kSecReturnAttributes] = (__bridge id)kCFBooleanTrue;
        query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitAll;

        CFTypeRef result = NULL;
        OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
        if (st == errSecItemNotFound || result == NULL) {
            XLog(@"[首次清理] access group %@ 无 keychain 项 (st=%d)", accessGroup, (int)st);
            return;
        }
        if (st != errSecSuccess) {
            XLog(@"[首次清理] 枚举 keychain 失败 access group=%@ st=%d", accessGroup, (int)st);
            return;
        }

        NSArray *items = (__bridge_transfer NSArray *)result;
        if (![items isKindOfClass:[NSArray class]]) {
            XLog(@"[首次清理] 枚举结果非数组: %@", items);
            return;
        }

        int deleted = 0;
        for (id item in items) {
            if (![item isKindOfClass:[NSDictionary class]]) continue;
            NSDictionary *attrs = (NSDictionary *)item;
            id svce = attrs[(__bridge id)kSecAttrService];
            id acct = attrs[(__bridge id)kSecAttrAccount];

            NSMutableDictionary *del = [NSMutableDictionary dictionary];
            del[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
            if (accessGroup && accessGroup.length > 0) {
                del[(__bridge id)kSecAttrAccessGroup] = accessGroup;
            }
            if (svce) del[(__bridge id)kSecAttrService] = svce;
            if (acct) del[(__bridge id)kSecAttrAccount] = acct;

            OSStatus ds = SecItemDelete((__bridge CFDictionaryRef)del);
            if (ds == errSecSuccess) {
                deleted++;
            } else {
                XLog(@"[首次清理] keychain 单条删除失败 st=%d", (int)ds);
            }
        }
        XLog(@"[首次清理] access group %@ 共枚举 %lu 项, 删除 %d 项", accessGroup, (unsigned long)items.count, deleted);
    } @catch (NSException *e) {
        XLog(@"[首次清理] 枚举 keychain 异常: %@", e);
    }
}

// 递归删除目录内的所有内容(文件+子目录), 但保留目录本身。
// 关键: 探探以 mobile 用户运行, 删 Preferences/Caches 等系统保护的"目录本身"会 513,
// 但删目录"里面"的文件(mobile 属主)不会 513。所以逐层清空内容, 不删目录。
static __attribute__((unused)) void _clearDirectoryContents(NSString *dirPath) {
    NSFileManager *fm = [NSFileManager defaultManager];
    if (!dirPath || ![fm fileExistsAtPath:dirPath]) return;
    NSArray *children = [fm contentsOfDirectoryAtPath:dirPath error:nil];
    for (NSString *child in children) {
        NSString *full = [dirPath stringByAppendingPathComponent:child];
        NSError *err = nil;
        // removeItemAtPath 本身是递归的: 对文件直接删, 对子目录递归删整个子目录
        [fm removeItemAtPath:full error:&err];
        if (err) {
            // 如果子目录也删不掉(系统保护), 递归清空它的内容
            BOOL isDir = NO;
            if ([fm fileExistsAtPath:full isDirectory:&isDir] && isDir) {
                _clearDirectoryContents(full);
            }
        }
    }
}

static void __attribute__((unused)) _cleanupFirstLaunch(void) {
    @try {
        XLog(@"[首次清理] 开始清理设备指纹 + 登录态残留");

        // 1) keychain: 探探的 svce/acct 是加密二进制, 用枚举方式删除 access group 下所有项
        //    (覆盖 oneid/localid/TTUDID/登录 token 等全部 keychain 残留)
        _clearAllKeychainForAccessGroup(@"F6QSEMKSK2.com.tantan.access");
        _clearAllKeychainForAccessGroup(@"F6QSEMKSK2.com.yaymedialabs.putong");
        // 兜底: 明文删除(兼容旧版本明文 keychain 项)
        _clearKeychainItem(@"com.tantan.statistics.service", @"com.tantan.statistics.oneId.account", @"F6QSEMKSK2.com.tantan.access");
        _clearKeychainItem(@"com.tantan.statistics.service", @"com.tantan.statistics.localId.account", @"F6QSEMKSK2.com.tantan.access");
        _clearKeychainItem(@"com.tantan.statistics.service", @"com.tantan.statistics.deviceOnlyStorage.account", @"F6QSEMKSK2.com.tantan.access");
        _clearKeychainItem(@"com.yaymedialabs.putong", @"TTUDID", @"F6QSEMKSK2.com.tantan.access");
        _clearKeychainItem(@"com.yaymedialabs.putong", @"TTUDID", @"F6QSEMKSK2.com.yaymedialabs.putong");

        // 2) NSUserDefaults: oneid suite
        NSUserDefaults *oneidDefaults = [[NSUserDefaults alloc] initWithSuiteName:@"com.tantan.satistics_oneid_userdefaults"];
        if (oneidDefaults) {
            [oneidDefaults removeObjectForKey:@"com.tantan.statistics.oneId.account"];
            [oneidDefaults removeObjectForKey:@"com.tantan.statistics.localId.account"];
            [oneidDefaults removeObjectForKey:@"com.tantan.statistics.oneId.account.updateTime"];
            [oneidDefaults removeObjectForKey:@"com.tantan.statistics.localId.account.updateTime"];
            [oneidDefaults synchronize];
            XLog(@"[首次清理] 已清 oneid NSUserDefaults suite");
        }

        // 3) 主 NSUserDefaults: 只清登录态/账号相关 key, 不清空整个 domain
        //    (之前 removePersistentDomainForName 全清会连插件开关/探探UI偏好一起删, 且删正在使用的
        //     plist 导致文件损坏 -> 下次启动空指针崩溃)
        NSUserDefaults *mainDefaults = [NSUserDefaults standardUserDefaults];
        // 探探登录态相关的 key (只删这些, 保留插件开关 xh_switch.* 和探探其它配置)
        NSArray *loginKeys = @[@"currentUserId", @"currentUser", @"accessToken", @"refreshToken",
                               @"loginUserId", @"loginToken", @"userId", @"token", @"session",
                               @"lastUserId", @"lastAccount", @"PUGLoginUser", @"PUGCurrentUser"];
        for (NSString *k in loginKeys) {
            [mainDefaults removeObjectForKey:k];
        }
        [mainDefaults synchronize];
        XLog(@"[首次清理] 已清登录态相关 NSUserDefaults key (保留插件开关与探探配置)");

        // 4) 精准清理沙盒: 只删登录态/会话相关的缓存文件, 不递归清空 Library/Documents
        //    (之前递归清空 Library 会删除探探正在 mmap 的数据库/MMKV/WebKit 缓存,
        //     导致文件系统状态损坏 -> 探探下次启动读损坏数据在 putong 固定偏移跳空崩溃)
        NSFileManager *fm = [NSFileManager defaultManager];
        NSString *docDir = _docDir();
        NSString *libDir = [docDir stringByDeletingLastPathComponent]; // 沙盒根
        // 4a) 只删 Documents 下的登录态缓存文件(spoof_identity.plist / 日志保留)
        NSString *docReal = [libDir stringByAppendingPathComponent:@"Documents"];
        NSArray *docChildren = [fm contentsOfDirectoryAtPath:docReal error:nil];
        for (NSString *child in docChildren) {
            if ([child isEqualToString:@"spoof_identity.plist"]) continue;
            if ([child isEqualToString:@"xihuan_verify.log"]) continue;
            if ([child isEqualToString:@"xh_debug.log"]) continue;
            // 只删明确的登录态/会话缓存, 保留数据库等其它文件
            NSString *low = child.lowercaseString;
            BOOL isSession = [low containsString:@"login"] || [low containsString:@"session"] ||
                             [low containsString:@"token"] || [low containsString:@"account"] ||
                             [low containsString:@"come"] || [low containsString:@"first"] ||
                             [low containsString:@"last"];
            if (!isSession) continue;
            NSString *full = [docReal stringByAppendingPathComponent:child];
            [fm removeItemAtPath:full error:nil];
            XLog(@"[首次清理] 已删登录态文件: %@", child);
        }
        // 4b) 清 tmp 目录(临时文件, 删除安全)
        NSString *tmpPath = [libDir stringByAppendingPathComponent:@"tmp"];
        NSArray *tmpChildren = [fm contentsOfDirectoryAtPath:tmpPath error:nil];
        for (NSString *child in tmpChildren) {
            NSString *full = [tmpPath stringByAppendingPathComponent:child];
            [fm removeItemAtPath:full error:nil];
        }
        XLog(@"[首次清理] 已清 tmp 目录");

        XLog(@"[首次清理] 清理完成 (设备指纹 + 登录态已清除, 保留数据库/缓存避免损坏)");
    } @catch (NSException *e) {
        XLog(@"[首次清理] 异常: %@", e);
    }
}

// 是否首次启动(无 spoof_identity.plist 且无清理标记)
static BOOL __attribute__((unused)) _isFirstLaunch(void) {
    NSString *path = _spoofStorePath();
    return ![[NSFileManager defaultManager] fileExistsAtPath:path];
}

// 待彻底清理标记文件 (一键新机时写入, 下次启动 constructor 早期检测到后彻底清空沙盒)
static NSString *_pendingFullCleanupPath(void) {
    return [[_docDir() stringByAppendingPathComponent:@"pending_full_cleanup.flag"] stringByStandardizingPath];
}
static BOOL _hasPendingFullCleanup(void) {
    return [[NSFileManager defaultManager] fileExistsAtPath:_pendingFullCleanupPath()];
}

// 彻底清空沙盒(像卸载重装): 主 NSUserDefaults 全清 + keychain + oneid suite + Library/Documents/tmp/App Group。
// 只在 constructor 早期(探探尚未打开数据库/缓存时)调用, 避免删正在 mmap 的文件导致闪退。
static void _fullCleanupSandbox(void) {
    @try {
        NSFileManager *fm = [NSFileManager defaultManager];

        // 0) 先读标记文件里的开关快照(清空主 NSUserDefaults 前), 清完后恢复
        NSDictionary *flagData = [NSDictionary dictionaryWithContentsOfFile:_pendingFullCleanupPath()];
        NSString *spoofVerSnap = flagData[@"spoofVer"] ?: @"";

        // 1) 主 NSUserDefaults 全清 (登录态/账号 token 全部清掉, 此时 constructor 早期安全)
        NSUserDefaults *mainDefaults = [NSUserDefaults standardUserDefaults];
        NSString *mainBundleId = [[NSBundle mainBundle] bundleIdentifier];
        if (mainDefaults && mainBundleId && mainBundleId.length > 0) {
            [mainDefaults removePersistentDomainForName:mainBundleId];
            [mainDefaults synchronize];
            XLog(@"[彻底清理] 已清空主 NSUserDefaults (%@)", mainBundleId);
        }

        // 1.5) 第三方 SDK 设备指纹逐键强清。
        //      实测: removePersistentDomainForName 后 cfprefsd 会把内存缓存写回, 数美 ms_mid /
        //      AppsFlyer 计数等顽固残留(实测 ReInstallCounter=41)。这里逐键删除并同步,
        //      再在后文直接删文件, 双保险。
        {
            NSArray *sdkKeys = @[
                // 数美 TXTOneId 设备指纹
                @"ms_mid", @"ms_n_mid", @"ms_installTime", @"ms_seq", @"ms_runTime", @"ms_appVer",
                // AppsFlyer 安装/启动计数与身份
                @"AppsFlyerReInstallCounter", @"AppsFlyerCounter", @"AppsFlyerRealLaunchCounter",
                @"AppsFlyerInstallDate", @"AppsFlyerInstallTimestamp", @"AppsFlyerCurrentLastInstallDate",
                @"AppsFlyerFirstLaunchDate", @"AppsFlyerInitDate", @"AppsFlyerUserId",
                @"AppsFlyerLaunchKey", @"AppsFlyerTimePassedSincePrevLaunch",
                @"AppsFlyerDate3", @"AppsFlyerLastSessionDuration",
                // 机型拼接串(嵌微博SDK设备号)
                @"machinePlatForm",
                // 微博 SDK 设备号
                @"WEIBOSDKAID",
            ];
            NSInteger cleared = 0;
            for (NSString *k in sdkKeys) {
                if ([mainDefaults objectForKey:k] != nil) { cleared++; }
                [mainDefaults removeObjectForKey:k];
            }
            [mainDefaults synchronize];
            XLog(@"[彻底清理] SDK 指纹键已逐键清除 %ld 项 (数美/AppsFlyer/machinePlatForm)", (long)cleared);
        }

        // 2) keychain 全清 (登录 token / oneid / TTUDID)
        _clearAllKeychainForAccessGroup(@"F6QSEMKSK2.com.tantan.access");
        _clearAllKeychainForAccessGroup(@"F6QSEMKSK2.com.yaymedialabs.putong");
        // 不指定 access group: 枚举 App 默认可访问组的全部项, 覆盖数美等用默认组存的指纹
        _clearAllKeychainForAccessGroup(nil);
        XLog(@"[彻底清理] 已清空 keychain");

        // 3) oneid suite
        NSUserDefaults *oneidDefaults = [[NSUserDefaults alloc] initWithSuiteName:@"com.tantan.satistics_oneid_userdefaults"];
        if (oneidDefaults) {
            [oneidDefaults removeObjectForKey:@"com.tantan.statistics.oneId.account"];
            [oneidDefaults removeObjectForKey:@"com.tantan.statistics.localId.account"];
            [oneidDefaults removeObjectForKey:@"com.tantan.statistics.oneId.account.updateTime"];
            [oneidDefaults removeObjectForKey:@"com.tantan.statistics.localId.account.updateTime"];
            [oneidDefaults synchronize];
            XLog(@"[彻底清理] 已清 oneid NSUserDefaults suite");
        }
        // 3.5) 直接删除 oneid suite 的磁盘文件 + Facebook 匿名ID 文件。
        //      实测 oneid suite plist 里仍留有真实 oneId(432347074609737728), 只清读取路径不够。
        {
            NSFileManager *fm0 = [NSFileManager defaultManager];
            NSString *libRoot0 = [_docDir() stringByDeletingLastPathComponent];
            NSArray *filesToDelete = @[
                @"Library/Preferences/com.tantan.satistics_oneid_userdefaults.plist",
                @"Library/com.tantan.satistics_oneid_userdefaults.plist",
                @"Library/com-facebook-sdk-PersistedAnonymousID.json",
                @"Library/Preferences/com.facebook.sdk.plist",
            ];
            for (NSString *rel in filesToDelete) {
                NSString *p = [libRoot0 stringByAppendingPathComponent:rel];
                if ([fm0 fileExistsAtPath:p]) {
                    BOOL ok = [fm0 removeItemAtPath:p error:nil];
                    XLog(@"[彻底清理] 删除 %@ = %d", rel, ok);
                }
            }
        }

        // 4) 沙盒文件全清 (容错: 删不掉的正在 mmap 文件/目录就跳过, 避免闪退)
        NSString *docDir = _docDir();
        NSString *libDir = [docDir stringByDeletingLastPathComponent]; // 沙盒根
        XLog(@"[彻底清理] 开始清空沙盒 %@", libDir);
        // Library: 只删顶层子项, 删失败(正在用)就跳过, 不递归强删
        NSString *libPath = [libDir stringByAppendingPathComponent:@"Library"];
        if ([fm fileExistsAtPath:libPath]) {
            NSArray *children = [fm contentsOfDirectoryAtPath:libPath error:nil];
            for (NSString *c in children) {
                [fm removeItemAtPath:[libPath stringByAppendingPathComponent:c] error:nil];
            }
            XLog(@"[彻底清理] 已清空 Library (删不掉的自会跳过)");
        }
        // Documents 全清
        NSString *docReal = [libDir stringByAppendingPathComponent:@"Documents"];
        if ([fm fileExistsAtPath:docReal]) {
            NSArray *children = [fm contentsOfDirectoryAtPath:docReal error:nil];
            for (NSString *c in children) {
                [fm removeItemAtPath:[docReal stringByAppendingPathComponent:c] error:nil];
            }
            XLog(@"[彻底清理] 已清空 Documents");
        }
        // tmp 全清
        NSString *tmpPath = [libDir stringByAppendingPathComponent:@"tmp"];
        if ([fm fileExistsAtPath:tmpPath]) {
            NSArray *children = [fm contentsOfDirectoryAtPath:tmpPath error:nil];
            for (NSString *c in children) {
                [fm removeItemAtPath:[tmpPath stringByAppendingPathComponent:c] error:nil];
            }
            XLog(@"[彻底清理] 已清空 tmp");
        }
        // App Group 共享容器
        NSArray *groupIDs = @[@"group.com.yaymedialabs.putong.shareddata",
                              @"group.com.yaymedialabs.putong.shareddata08"];
        for (NSString *gid in groupIDs) {
            @try {
                NSURL *groupURL = [fm containerURLForSecurityApplicationGroupIdentifier:gid];
                if (groupURL.path.length > 0 && [fm fileExistsAtPath:groupURL.path]) {
                    NSArray *children = [fm contentsOfDirectoryAtPath:groupURL.path error:nil];
                    for (NSString *c in children) {
                        [fm removeItemAtPath:[groupURL.path stringByAppendingPathComponent:c] error:nil];
                    }
                    XLog(@"[彻底清理] 已清空 App Group: %@", gid);
                }
            } @catch (NSException *e) {}
        }
        // 恢复开关快照(清空主 NSUserDefaults 后, 恢复用户之前勾选的开关)
        {
            NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
            NSArray *keys = @[XH_SW_VIP, XH_SW_CHAT, XH_SW_POPUP, XH_SW_PICK, XH_SW_SPOOFVER,
                              XH_SW_DEVICE, XH_SW_GUOWAI, XH_SW_VERIFY, XH_SW_VERIFY_PICTURE,
                              XH_SW_VERIFY_ID, XH_SW_BLOCK_CLEAR, XH_SW_V2_MSG,
                              XH_SW_MATCH_LIMIT, XH_SW_SSL];
            for (NSString *k in keys) {
                if (flagData[k] != nil) [ud setBool:[flagData[k] boolValue] forKey:k];
            }
            if (spoofVerSnap.length) [ud setObject:spoofVerSnap forKey:@"xh_spoof_version"];
            // 补种迁移标记, 防止下次启动迁移逻辑误把开关归零
            [ud setBool:YES forKey:@"xh_switch.default_off_migrated"];
            [ud setBool:YES forKey:@"xh_switch.default_off_v2"];
            [ud synchronize];
            XLog(@"[彻底清理] 已恢复开关快照(设备改机=%@)", [ud boolForKey:XH_SW_DEVICE] ? @"开" : @"关");
            // 同步刷新 hook 用的开关缓存, 避免清理后缓存与实际值不一致
            _gDevSpoofOn = [ud boolForKey:XH_SW_DEVICE];
        }

        // 删除标记文件
        [fm removeItemAtPath:_pendingFullCleanupPath() error:nil];
        XLog(@"[彻底清理] 沙盒清空完成");
    } @catch (NSException *e) {
        XLog(@"[彻底清理] 异常: %@", e);
    }
}


// ============================================================
// oneid 伪造: hook TXTOneID 所有返回字符串的 oneId 类/实例方法
// 受「设备改机」开关控制, 关闭时走原实现
// ============================================================
static BOOL _devSpoofOn(void) {
    // 简化: 只跟随"设备改机"开关(首次打开不伪装)
    return _swOn(XH_SW_DEVICE);
}

static id spoof_oneId_generic(id self, SEL _cmd) {
    IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd);
    id orig = o ? ((id(*)(id, SEL))o)(self, _cmd) : nil;
    if (!_devSpoofOn()) return orig;
    // 只有原实现返回字符串才替换, 其它类型(字典/模型/数组)原样返回, 避免类型不匹配崩溃
    if ([orig isKindOfClass:[NSString class]]) return _spoofOneId();
    return orig;
}

static __attribute__((unused)) void XHInstallOneIdHook(void) {
    NSArray *names = @[@"TXTOneID", @"TXTOneId", @"TXTOneIdStorageManager", @"TXTOneIdUtils"];
    int hit = 0;
    for (NSString *cn in names) {
        Class cls = objc_getClass(cn.UTF8String);
        if (!cls) continue;
        for (int meta = 0; meta < 2; meta++) {
            Class target = meta ? object_getClass(cls) : cls;
            unsigned int n = 0;
            Method *ms = class_copyMethodList(target, &n);
            for (unsigned int i = 0; i < n; i++) {
                SEL sel = method_getName(ms[i]);
                NSString *sn = NSStringFromSelector(sel);
                NSString *low = sn.lowercaseString;
                if (![low containsString:@"oneid"]) continue;
                if ([low containsString:@"set"] || [low containsString:@"update"] ||
                    [low containsString:@"request"] || [low containsString:@"serve"]) continue;
                const char *types = method_getTypeEncoding(ms[i]);
                if (!types || types[0] != '@') continue;      // 只处理返回对象的方法
                if (method_getNumberOfArguments(ms[i]) != 2) continue;  // 只处理无参
                IMP orig = method_getImplementation(ms[i]);
                method_setImplementation(ms[i], (IMP)spoof_oneId_generic);
                _saveOrigImp(cn, sel, orig);
                hit++;
                XLog(@"[oneid] 已 hook %@ %@", cn, sn);
            }
            free(ms);
        }
    }
    XLog(@"[oneid] 共 hook %d 个方法", hit);
}

// ============================================================
// 一键新机 (供设置面板按钮调用, 非 static, 跨文件可见)
// 流程: 删除旧指纹 -> 清空运行时指纹缓存 -> 清理 keychain/沙盒数据/登录态 -> 重新随机生成全新指纹
// ============================================================
void XHResetLocation(void);   // 定义在 HelloLocation.m: 清除保存的定位坐标, 重置回默认
void XHDeepEnvReset(void);    // 定义在下方深度环境模块: 清空深度指纹缓存
void XHNewDevice(void) {
    @autoreleasepool {
        XLog(@"===== 开始一键新机 =====");

        // 重置地图定位坐标到默认(深圳)
        XHResetLocation();

        // 清空深度环境指纹缓存(序列号/运营商/WiFi/电池, 随 deep_env.plist 一起重新随机)
        XHDeepEnvReset();

        // 先备份插件开关状态(清理会清空 NSUserDefaults, 否则开关全回默认=关)
        NSArray *swKeys = @[XH_SW_VIP, XH_SW_CHAT, XH_SW_POPUP, XH_SW_PICK, XH_SW_SPOOFVER,
                            XH_SW_DEVICE, XH_SW_GUOWAI, XH_SW_VERIFY, XH_SW_VERIFY_PICTURE,
                            XH_SW_VERIFY_ID, XH_SW_BLOCK_CLEAR, XH_SW_V2_MSG,
                            XH_SW_MATCH_LIMIT, XH_SW_SSL, XH_SW_LOCATION];
        NSMutableDictionary *swSnap = [NSMutableDictionary dictionary];
        NSUserDefaults *sud = [NSUserDefaults standardUserDefaults];
        for (NSString *k in swKeys) {
            if ([sud objectForKey:k] != nil) swSnap[k] = @([sud boolForKey:k]);
        }
        NSString *spoofVerSnap = [sud stringForKey:@"xh_spoof_version"];

        // 1) 删除旧指纹文件, 强制下次 _spoofIdentity 重新随机
        NSString *storePath = _spoofStorePath();
        [[NSFileManager defaultManager] removeItemAtPath:storePath error:nil];

        // 2) 清空运行时指纹缓存
        _spoofIdentityCache = nil;
        // 清掉版本守卫用的设备ID(下次请求自动重新生成)
        [[NSUserDefaults standardUserDefaults] removeObjectForKey:@"xh_spoof_devid"];
        [[NSUserDefaults standardUserDefaults] removeObjectForKey:@"xh_spoof_devident"];
        [[NSUserDefaults standardUserDefaults] synchronize];

        // 3) 写入"待彻底清理"标记(含开关快照), 下次启动 constructor 早期彻底清空后恢复开关
        //    (不在探探运行中删正在 mmap 的数据库/缓存, 避免闪退; 而是标记后让探探重启时清)
        NSString *flagPath = _pendingFullCleanupPath();
        NSMutableDictionary *flagData = [NSMutableDictionary dictionaryWithDictionary:swSnap];
        flagData[@"spoofVer"] = spoofVerSnap ?: @"";
        [flagData writeToFile:flagPath atomically:YES];
        XLog(@"[一键新机] 已标记待彻底清理(下次启动清空沙盒, 已存 %lu 个开关快照)", (unsigned long)swSnap.count);

        // 3.5) 恢复插件开关 + 版本号设置(清理会清空)
        for (NSString *k in swSnap) [sud setBool:[swSnap[k] boolValue] forKey:k];
        if (spoofVerSnap.length) [sud setObject:spoofVerSnap forKey:@"xh_spoof_version"];
        // 关键修复: 清理会清掉"开关迁移标记", 重新种上, 否则下次启动迁移逻辑误把开关归零
        [sud setBool:YES forKey:@"xh_switch.default_off_migrated"];
        [sud setBool:YES forKey:@"xh_switch.default_off_v2"];
        // 一键新机不再强制改"设备改机"开关, 保持用户当前勾选状态:
        //   勾选设备改机 -> 下次启动系统级+网络层+深度环境全开
        //   未勾选 -> 下次启动只清理数据不伪装
        [sud synchronize];
        XLog(@"[一键新机] 已恢复 %lu 个开关, 版本=%@, 设备改机=保持原状态(%@)", (unsigned long)swSnap.count, spoofVerSnap ?: @"(无)", [sud boolForKey:XH_SW_DEVICE] ? @"开" : @"关");

        // 4) 立即重新随机生成全新指纹并持久化
        NSDictionary *fresh = _spoofIdentity();
        XLog(@"===== 一键新机完成, 新指纹 idfv=%@ idfa=%@ localId=%@ oneId=%@ =====",
             fresh[@"idfv"], fresh[@"idfa"], fresh[@"localId"], fresh[@"oneId"]);

        // 5) 立即执行"安全彻底清理"(清空主 NSUserDefaults 登录态 + keychain + oneid suite)。
        //    这部分不会闪退(不删正在 mmap 的数据库文件), 让登录态立即清掉。
        //    沙盒数据库/缓存文件已标记, 下次启动 constructor 早期再删(那时才安全)。
        XLog(@"[一键新机] 立即清空登录态(keychain + 主NSUserDefaults + oneid)");
        [sud removePersistentDomainForName:[[NSBundle mainBundle] bundleIdentifier]];
        [sud synchronize];
        _clearAllKeychainForAccessGroup(@"F6QSEMKSK2.com.tantan.access");
        _clearAllKeychainForAccessGroup(@"F6QSEMKSK2.com.yaymedialabs.putong");
        NSUserDefaults *oneidDefaults = [[NSUserDefaults alloc] initWithSuiteName:@"com.tantan.satistics_oneid_userdefaults"];
        if (oneidDefaults) {
            [oneidDefaults removeObjectForKey:@"com.tantan.statistics.oneId.account"];
            [oneidDefaults removeObjectForKey:@"com.tantan.statistics.localId.account"];
            [oneidDefaults removeObjectForKey:@"com.tantan.statistics.oneId.account.updateTime"];
            [oneidDefaults removeObjectForKey:@"com.tantan.statistics.localId.account.updateTime"];
            [oneidDefaults synchronize];
        }
        // 重新恢复开关(刚清空了主 NSUserDefaults)
        for (NSString *k in swSnap) [sud setBool:[swSnap[k] boolValue] forKey:k];
        if (spoofVerSnap.length) [sud setObject:spoofVerSnap forKey:@"xh_spoof_version"];
        [sud setBool:YES forKey:@"xh_switch.default_off_migrated"];
        [sud setBool:YES forKey:@"xh_switch.default_off_v2"];
        [sud synchronize];

        // 6) 立即彻底清空沙盒(容错删除: 删不掉正在 mmap 的文件就跳过, 不闪退)。
        //    清掉 Library/Documents/tmp/App Group 里探探的登录态/会话/缓存/统计数据库。
        //    删完不自杀, 探探会按需重建缓存; 若有文件删不掉, 下次启动 constructor 会再补清。
        XLog(@"[一键新机] 立即彻底清空沙盒(容错删除)");
        _fullCleanupSandbox();

        // 6.5) 清掉 SyncedPreferences 里的登录 token (access_token_dict)。
        //      Library/SyncedPreferences/com.yaymedialabs.putong.plist 是 NSUbiquitousKeyValueStore
        //      (iCloud 键值同步) 的本地缓存, 被 cfprefsd 守护进程持有, 直接删文件会被写回。
        //      正确做法: 操作 NSUbiquitousKeyValueStore 删 key + 清空缓存文件。
        @try {
            NSUbiquitousKeyValueStore *ubiq = [NSUbiquitousKeyValueStore defaultStore];
            [ubiq removeObjectForKey:@"access_token_dict"];
            [ubiq synchronize];
            XLog(@"[一键新机] 已清 NSUbiquitousKeyValueStore access_token_dict");
        } @catch (NSException *e) {
            XLog(@"[一键新机] 清 NSUbiquitousKeyValueStore 异常: %@", e);
        }
        // 兜底: 清掉 SyncedPreferences 的本地缓存文件。
        // 实测结论(2026-11-24): App 沙盒内 writeToFile 写该文件返回 0 失败(cfprefsd 持有句柄),
        //   但 removeItemAtPath 删除可靠, 且删后 cfprefsd 不会立刻重建(已用 NSUbiquitousKeyValueStore
        //   removeObjectForKey 清过内存值, 重建也不会带 token)。所以优先"删除文件", 删不掉才退化"写空"。
        {
            NSFileManager *fm2 = [NSFileManager defaultManager];
            NSString *libRoot = [_docDir() stringByDeletingLastPathComponent];
            NSString *syncedDir = [libRoot stringByAppendingPathComponent:@"Library/SyncedPreferences"];
            NSString *syncedPath = [syncedDir stringByAppendingPathComponent:@"com.yaymedialabs.putong.plist"];

            // 方案A(首选): 直接删除缓存文件
            NSError *delErr = nil;
            BOOL okDel = NO;
            if ([fm2 fileExistsAtPath:syncedPath]) {
                okDel = [fm2 removeItemAtPath:syncedPath error:&delErr];
            } else {
                okDel = YES; // 本来就不存在, 视为已达成目标
            }
            XLog(@"[一键新机] SyncedPreferences 删除=%d err=%@", okDel, delErr ?: @"(无)");

            if (!okDel) {
                // 方案B(退化): 删除失败则写空文件, 三级兜底
                if (![fm2 fileExistsAtPath:syncedDir]) {
                    NSError *dirErr = nil;
                    [fm2 createDirectoryAtPath:syncedDir withIntermediateDirectories:YES attributes:nil error:&dirErr];
                    XLog(@"[一键新机] SyncedPreferences 目录重建 err=%@", dirErr ?: @"(无)");
                }
                NSDictionary *emptyDict = @{@"changecount": @0, @"dirtykeys": @[], @"values": @{}};
                NSData *plistData = [NSPropertyListSerialization dataWithPropertyList:emptyDict
                                                                              format:NSPropertyListBinaryFormat_v1_0
                                                                             options:0
                                                                               error:nil];
                BOOL okWrite = NO; NSString *how = @"none";
                if (plistData) {
                    okWrite = [plistData writeToFile:syncedPath options:NSDataWritingAtomic error:nil]; how=@"atomic";
                    if (!okWrite) { okWrite = [plistData writeToFile:syncedPath options:0 error:nil]; how=@"plain"; }
                    if (!okWrite) { okWrite = [fm2 createFileAtPath:syncedPath contents:plistData attributes:nil]; how=@"createFile"; }
                }
                XLog(@"[一键新机] SyncedPreferences 写空=%d 方式=%@", okWrite, how);
            }

            // 最终校验: 文件不存在 = 干净; 存在则 values 里不能有 access_token_dict
            BOOL exists = [fm2 fileExistsAtPath:syncedPath];
            if (exists) {
                NSDictionary *chk = [NSDictionary dictionaryWithContentsOfFile:syncedPath];
                id v = chk[@"values"];
                BOOL hasTok = ([v isKindOfClass:[NSDictionary class]] && [v objectForKey:@"access_token_dict"] != nil);
                XLog(@"[一键新机] SyncedPreferences 校验 存在=1 hasToken=%d 内容=%@", hasTok, chk ?: @"(读不到)");
            } else {
                XLog(@"[一键新机] SyncedPreferences 校验 文件已删除(干净)");
            }
        }

        XLog(@"[一键新机] 完成: 登录态+沙盒数据已清空, 若探探异常请重开一次");
    }
}

// ============================================================
// Runtime Hook 工具
// ============================================================
static IMP SwapMethod(Class cls, SEL sel, IMP newImp, BOOL isClassMethod) {
    if (!cls || !sel) {
        return NULL;
    }
    Class target = isClassMethod ? object_getClass(cls) : cls;
    if (!target) {
        return NULL;
    }
    Method m = class_getInstanceMethod(target, sel);
    if (!m) {
        return NULL;
    }
    IMP orig = method_getImplementation(m);
    method_setImplementation(m, newImp);
    // 保存原 IMP, 供开关关闭时回退到真实实现
    _saveOrigImp(NSStringFromClass(cls), sel, orig);
    return orig;
}

// ============================================================
// Hook 函数实现
// ============================================================

// ---------- SentrySDK 瘫痪 ----------
static id _SentrySDK_sharedInstance(id self, SEL _cmd) { return nil; }
static void _SentrySDK_startWithConfigureOptions(id self, SEL _cmd, id options) { return; }

// ---------- PUGUser 认证 (受弹窗/聊天开关控制) ----------
static BOOL _isJailed(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_POPUP); return NO; }
static BOOL _isBanned(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_POPUP); return NO; }
static BOOL _isAvatarUnReal(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_POPUP); return NO; }
// 头像本人认证: isRealAvatar -> YES (让认证中心显示"已认证", 关闭"立即认证"通道)
static BOOL _isRealAvatar_YES(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_VERIFY_PICTURE); return YES; }

// ---------- PUGUserStateInfo ----------
static BOOL _isPermanentBanned(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_POPUP); return NO; }
// 注意: 7.6.4 中 stateInfoType 返回 unsigned long long (TQ), 非对象
static unsigned long long _stateInfoType(id self, SEL _cmd) { XH_GUARD_ULL(XH_SW_POPUP); return 0; }
// 注意: 7.6.4 中 active 返回对象 (T@), 非 BOOL
static id _active(id self, SEL _cmd) { XH_GUARD_ID(XH_SW_POPUP); return nil; }

// ---------- AFSecurityPolicy 绕过 SSL Pinning ----------
static void _setSSLPinningMode(id self, SEL _cmd, NSInteger mode) {
    // 强制开启低版本网络: 不设 SSL Pinning 模式(保持 None), 允许抓包/代理/低版本 TLS。
    // 开关: xh_switch.ssl (工具面板: "强制开启低版本网络")
    if (!_swOn(XH_SW_SSL)) {
        IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd);
        if (o) { ((void(*)(id,SEL,NSInteger))o)(self, _cmd, mode); return; }
    }
    return;
}

// ---------- 认证弹窗控制器 ----------
#if ENABLE_AUTH_SKIP
static id _init_nil(id self, SEL _cmd) { XH_GUARD_ID(XH_SW_POPUP); return nil; }
static void _viewDidAppear_noop(id self, SEL _cmd, BOOL animated) {
    if (!_swOn(XH_SW_POPUP)) {
        IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd);
        if (o) { ((void(*)(id,SEL,BOOL))o)(self, _cmd, animated); return; }
    }
    return;
}

// ---------- 真实头像认证弹窗: viewDidLoad 时立即 dismiss ----------
static void _alert_viewDidLoad_dismiss(id self, SEL _cmd) {
    if (!_swOn(XH_SW_POPUP)) {
        IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd);
        if (o) { ((void(*)(id,SEL))o)(self, _cmd); return; }
        return;
    }
    XLog(@"[RealAvatarAlert] intercept viewDidLoad: %@", NSStringFromClass([self class]));
    @try {
        if ([self respondsToSelector:@selector(dismissViewControllerAnimated:completion:)]) {
            [(UIViewController *)self dismissViewControllerAnimated:NO completion:nil];
        }
        if ([self respondsToSelector:@selector(presentingViewController)]) {
            UIViewController *pv = [(UIViewController *)self presentingViewController];
            if (pv) { [pv dismissViewControllerAnimated:NO completion:nil]; }
        }
    } @catch (NSException *e) {
        XLog(@"[RealAvatarAlert] dismiss exception: %@", e);
    }
}

// ---------- 强制认证弹窗总开关 (精确签名, 避免栈参数不匹配) ----------
static void _showMandatoryVerificationIfNeededWithData_noop(id self, SEL _cmd, id data) {
    if (!_swOn(XH_SW_POPUP)) { IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd); if (o) { ((void(*)(id,SEL,id))o)(self, _cmd, data); return; } }
    return;
}
static void _showSelectVC_noop(id self, SEL _cmd, id vc) {
    if (!_swOn(XH_SW_POPUP)) { IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd); if (o) { ((void(*)(id,SEL,id))o)(self, _cmd, vc); return; } }
    return;
}
static void _showSelectVCIfNeeded_noop(id self, SEL _cmd, id vc) {
    if (!_swOn(XH_SW_POPUP)) { IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd); if (o) { ((void(*)(id,SEL,id))o)(self, _cmd, vc); return; } }
    return;
}
static void _showIdentifierViewController_noop(id self, SEL _cmd, id vc) {
    if (!_swOn(XH_SW_POPUP)) { IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd); if (o) { ((void(*)(id,SEL,id))o)(self, _cmd, vc); return; } }
    return;
}
static void _showPicturePopViewController_noop(id self, SEL _cmd, id vc) {
    if (!_swOn(XH_SW_POPUP)) { IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd); if (o) { ((void(*)(id,SEL,id))o)(self, _cmd, vc); return; } }
    return;
}
static void _showJuvenileVerificationViewControllerIfNeeded_noop(id self, SEL _cmd) {
    if (!_swOn(XH_SW_POPUP)) { IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd); if (o) { ((void(*)(id,SEL))o)(self, _cmd); return; } }
    return;
}
#endif

// ---------- 手机号绑定弹窗 (受弹窗开关控制) ----------
static BOOL _hasBindPhoneNumber_YES(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_POPUP); return YES; }
static BOOL _shouldEnableBind_after_NO(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_POPUP); return NO; }
static BOOL _shouldEnableBind_during_NO(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_POPUP); return NO; }
static BOOL _isShowingForceBindAlerView_NO(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_POPUP); return NO; }
static BOOL _hasBindPhone_YES(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_POPUP); return YES; }

// ---------- 会员 (7.6.4 多类型会员体系) ----------
static BOOL _isSelfCurrentUser(id self);
static BOOL _isVip_YES(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_VIP); return YES; }
static BOOL _isLiveCampaignVip_YES(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_VIP); return YES; }
static BOOL _isMembershipUser_YES(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_VIP); return YES; }
static BOOL _isMembershipDiamondUser_YES(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_VIP); return YES; }
static BOOL _isMembershipPlatinumUser_YES(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_VIP); return YES; }
static BOOL _isMembershipPartnerUser_YES(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_VIP); return YES; }
static BOOL _isUltraSvip_YES(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_VIP); return YES; }
// 会员总开关: 带参数的类方法 (判断某 user 是否某类会员) -> YES
// 会员总开关: 带参数的类方法 (判断某 user 是否某类会员)
// 只在传入 user 是当前用户时返回 YES, 避免全局所有用户都显示会员
static BOOL _isMembershipUser_arg_YES(id self, SEL _cmd, id user) {
    if (!_swOn(XH_SW_VIP)) {
        IMP o = _getOrigImp(NSStringFromClass(self), _cmd);
        if (o) return ((BOOL(*)(id, SEL, id))o)(self, _cmd, user);
        return NO;
    }
    if (_isSelfCurrentUser(user)) return YES;
    IMP o = _getOrigImp(NSStringFromClass(self), _cmd);
    if (o) return ((BOOL(*)(id, SEL, id))o)(self, _cmd, user);
    return NO;
}
// 资料页"审核中"修复: isInAuditArea -> NO (不在审核中)
static BOOL _isInAuditArea_NO(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_VERIFY_PICTURE); return NO; }
// 会员图标隐藏修复: hideMembershipIcon / hideMembershipIconIncludeSelf -> NO (不隐藏会员图标)
static BOOL _hideMembershipIcon_NO(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_VIP); return NO; }
// displayAudit -> NO (不显示"审核中"标识)
static BOOL _displayAudit_NO(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_VERIFY_PICTURE); return NO; }

// ---------- 发消息/打招呼权限 (已删除: 未解决实名聊天问题) ----------
// 前置声明: 判断 self 是否是当前用户
static BOOL _isSelfCurrentUser(id self);
static BOOL _isAudited_YES(id self, SEL _cmd) {
    if (!_swOn(XH_SW_VERIFY_PICTURE)) { IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd); if (o) return ((BOOL(*)(id,SEL))o)(self, _cmd); return NO; }
    if (_isSelfCurrentUser(self)) return YES;
    IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd); if (o) return ((BOOL(*)(id,SEL))o)(self, _cmd); return NO;
}
static BOOL _currentUserIsAudited_YES(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_VERIFY_PICTURE); return YES; }
// 判断 self 是否是当前用户 (避免"全局通用"——只让当前用户显示已认证, 别人的返回真实值)
static BOOL _isSelfCurrentUser(id self) {
    @try {
        // 方式1: isCurrentUser 标志
        if ([self respondsToSelector:@selector(isCurrentUser)]) {
            BOOL r = ((BOOL(*)(id, SEL))objc_msgSend)(self, @selector(isCurrentUser));
            if (r) return YES;
        }
        // 方式2: 对比 userId (更可靠, 不依赖 isCurrentUser 标志)
        // 先拿 self 的 uid (多方法兜底)
        id selfUid = nil;
        for (NSString *selName in @[@"userId", @"userID", @"objectID", @"identifier", @"uid", @"localId"]) {
            SEL s = NSSelectorFromString(selName);
            if ([self respondsToSelector:s]) {
                id v = ((id(*)(id, SEL))objc_msgSend)(self, s);
                if (v) { selfUid = v; break; }
            }
        }
        if (!selfUid) return NO;
        // 拿当前用户 uid (多种方式兜底)
        Class am = NSClassFromString(@"PUGAccountManager");
        id curUid = nil;
        id curUser = nil;
        // 方式A: PUGAccountManager currentUser 类方法
        if (am) {
            Method m = class_getClassMethod(am, @selector(currentUser));
            if (m) {
                curUser = ((id(*)(id, SEL))objc_msgSend)(am, @selector(currentUser));
            }
        }
        // 方式B: PUGAccountManager sharedInstance + currentUser 实例方法
        if (!curUser && am) {
            id inst = nil;
            for (NSString *sName in @[@"sharedInstance", @"sharedManager", @"defaultManager", @"shared"]) {
                SEL s = NSSelectorFromString(sName);
                if (class_getClassMethod(am, s)) {
                    inst = ((id(*)(id, SEL))objc_msgSend)(am, s);
                    if (inst) break;
                }
            }
            if (inst && [inst respondsToSelector:@selector(currentUser)]) {
                curUser = ((id(*)(id, SEL))objc_msgSend)(inst, @selector(currentUser));
            }
        }
        // 方式C: 直接从 currentUser 对象拿 uid (多方法兜底)
        if (curUser) {
            for (NSString *selName in @[@"modelIdentifier", @"userId", @"userID", @"objectID", @"identifier", @"uid", @"localId"]) {
                SEL s = NSSelectorFromString(selName);
                if ([curUser respondsToSelector:s]) {
                    id v = ((id(*)(id, SEL))objc_msgSend)(curUser, s);
                    if (v) {
                        NSString *vs = [v description];
                        if ([vs containsString:@"_"]) vs = [[vs componentsSeparatedByString:@"_"] lastObject];
                        curUid = vs;
                        break;
                    }
                }
            }
        }
        NSString *selfUidStr = [selfUid description];
        if ([selfUidStr containsString:@"_"]) selfUidStr = [[selfUidStr componentsSeparatedByString:@"_"] lastObject];
        if (selfUidStr && curUid && [selfUidStr isEqual:curUid]) return YES;
    } @catch (NSException *e) {
    }
    return NO;
}

// 换号伪装认证: 强制"已认证"状态 (isVerified/isPictureVerified/isVerificationPassed -> YES)
// 只在 self 是当前用户时返回 YES, 避免全局所有用户都显示已认证
static BOOL _isVerified_YES(id self, SEL _cmd) {
    if (!_swOn(XH_SW_VERIFY_PICTURE)) { IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd); if (o) return ((BOOL(*)(id,SEL))o)(self, _cmd); return NO; }
    if (_isSelfCurrentUser(self)) return YES;
    IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd); if (o) return ((BOOL(*)(id,SEL))o)(self, _cmd); return NO;
}
static BOOL _isPictureVerified_YES(id self, SEL _cmd) {
    if (!_swOn(XH_SW_VERIFY_PICTURE)) { IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd); if (o) return ((BOOL(*)(id,SEL))o)(self, _cmd); return NO; }
    if (_isSelfCurrentUser(self)) return YES;
    IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd); if (o) return ((BOOL(*)(id,SEL))o)(self, _cmd); return NO;
}
static BOOL _isVerificationPassed_YES(id self, SEL _cmd) {
    if (!_swOn(XH_SW_VERIFY_PICTURE)) { IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd); if (o) return ((BOOL(*)(id,SEL))o)(self, _cmd); return NO; }
    if (_isSelfCurrentUser(self)) return YES;
    IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd); if (o) return ((BOOL(*)(id,SEL))o)(self, _cmd); return NO;
}
// PUGUser 认证总开关: 所有认证类型 -> YES (仅当前用户)
static BOOL _isIDCardVerified_YES(id self, SEL _cmd) {
    if (!_swOn(XH_SW_VERIFY_ID)) { IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd); if (o) return ((BOOL(*)(id,SEL))o)(self, _cmd); return NO; }
    if (_isSelfCurrentUser(self)) return YES;
    IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd); if (o) return ((BOOL(*)(id,SEL))o)(self, _cmd); return NO;
}
static BOOL _isAvatarAudited_YES(id self, SEL _cmd) {
    if (!_swOn(XH_SW_VERIFY_PICTURE)) { IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd); if (o) return ((BOOL(*)(id,SEL))o)(self, _cmd); return NO; }
    if (_isSelfCurrentUser(self)) return YES;
    IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd); if (o) return ((BOOL(*)(id,SEL))o)(self, _cmd); return NO;
}
static BOOL _isNameAudited_YES(id self, SEL _cmd) {
    if (!_swOn(XH_SW_VERIFY_ID)) { IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd); if (o) return ((BOOL(*)(id,SEL))o)(self, _cmd); return NO; }
    if (_isSelfCurrentUser(self)) return YES;
    IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd); if (o) return ((BOOL(*)(id,SEL))o)(self, _cmd); return NO;
}
static BOOL _isAnchorVerified_YES(id self, SEL _cmd) {
    if (!_swOn(XH_SW_VERIFY_ID)) { IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd); if (o) return ((BOOL(*)(id,SEL))o)(self, _cmd); return NO; }
    if (_isSelfCurrentUser(self)) return YES;
    IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd); if (o) return ((BOOL(*)(id,SEL))o)(self, _cmd); return NO;
}
static BOOL _isVoiceAnchorVerified_YES(id self, SEL _cmd) {
    if (!_swOn(XH_SW_VERIFY_ID)) { IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd); if (o) return ((BOOL(*)(id,SEL))o)(self, _cmd); return NO; }
    if (_isSelfCurrentUser(self)) return YES;
    IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd); if (o) return ((BOOL(*)(id,SEL))o)(self, _cmd); return NO;
}
// 认证状态方法返回 "verified" (verificationStatus/verificationStatusForType/verificationStatusPicture)
static id _verificationStatus_verified(id self, SEL _cmd) { XH_GUARD_ID(XH_SW_VERIFY_PICTURE); return @"verified"; }

// ============ MMKV 认证字段拦截: need_avatar_verification/need_pic_verification -> false, pic/id_verification_status -> verified ============
// 认证页"头像本人认证"显示"已认证/开始认证"读的是 MMKV 里的这些 key (服务端下发缓存)
static IMP _orig_mmkvGetBool = NULL;
static IMP _orig_mmkvGetString = NULL;
static BOOL _mmkvGetBool_probe(id self, SEL _cmd, id key) {
    BOOL r = NO;
    if (_orig_mmkvGetBool) r = ((BOOL(*)(id,SEL,id))_orig_mmkvGetBool)(self, _cmd, key);
    if (_swOn(XH_SW_VERIFY_PICTURE) && key && [key isKindOfClass:[NSString class]]) {
        NSString *k = (NSString *)key;
        if ([k isEqualToString:@"need_avatar_verification"] || [k isEqualToString:@"need_pic_verification"]) {
            return NO;
        }
    }
    return r;
}
static id _mmkvGetString_probe(id self, SEL _cmd, id key) {
    id r = nil;
    if (_orig_mmkvGetString) r = ((id(*)(id,SEL,id))_orig_mmkvGetString)(self, _cmd, key);
    if (_swOn(XH_SW_VERIFY_PICTURE) && key && [key isKindOfClass:[NSString class]]) {
        NSString *k = (NSString *)key;
        if ([k isEqualToString:@"pic_verification_status"] || [k isEqualToString:@"id_verification_status"]) {
            return @"verified";
        }
    }
    return r;
}
static BOOL _isOtherVip_YES(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_VIP); return YES; }
static BOOL _hasMembershipDiamond_YES(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_VIP); return YES; }
static BOOL _hasMembershipPlatinum_YES(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_VIP); return YES; }
static BOOL _hasSVIPPrivilege_YES(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_VIP); return YES; }
static BOOL _hasAIChatAssistantMembership_YES(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_VIP); return YES; }
static BOOL _hasSeeWhoLikedMeMembership_YES(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_VIP); return YES; }
static BOOL _hasExpQuickChatMembership_YES(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_VIP); return YES; }
static BOOL _hasQuickChatMembershipPrivilege_YES(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_VIP); return YES; }
static BOOL _hasPrivacyMembership_YES(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_VIP); return YES; }
static BOOL _hasIntlMembership_YES(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_VIP); return YES; }
static BOOL _hasEnjoySwipeMembership_YES(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_VIP); return YES; }

// 会员过期判断 -> 永不过期 (返回 NO 表示"未过期")
static BOOL _isMembershipExpired_NO(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_VIP); return NO; }
static BOOL _isCurrentUserMembershipDiamondExpired_NO(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_VIP); return NO; }
static BOOL _isCurrentUserMembershipPlatinumExpired_NO(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_VIP); return NO; }
static BOOL _isCurrentUserMembershipPartnerExpired_NO(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_VIP); return NO; }
static BOOL _isAIChatAssistantMembershipExpired_NO(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_VIP); return NO; }
static BOOL _isSeeWhoLikedMeMembershipExpired_NO(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_VIP); return NO; }
static BOOL _isExpQuickChatMembershipExpired_NO(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_VIP); return NO; }
static BOOL _isIntlMembershipExpired_NO(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_VIP); return NO; }
static BOOL _isEnjoySwipeMembershipExpired_NO(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_VIP); return NO; }

// ---------- 看到上限/超级喜欢计数器 ----------
// 由独立开关"解除匹配限制"控制, 默认开; 不再依赖会员开关
static unsigned long long _total_max(id self, SEL _cmd) { XH_GUARD_ULL(XH_SW_MATCH_LIMIT); return 999999; }
static unsigned long long _remaining_max(id self, SEL _cmd) { XH_GUARD_ULL(XH_SW_MATCH_LIMIT); return 999999; }
static BOOL _isSeeValid_YES(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_MATCH_LIMIT); return YES; }
static BOOL _exhausted_NO(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_MATCH_LIMIT); return NO; }

// ---------- 会员付费权限放行 (对齐 putongTK) ----------
static BOOL _hasLetterPrivilege_YES(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_MATCH_LIMIT); return YES; }
static BOOL _canCostTantanCoinForLetter_YES(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_MATCH_LIMIT); return YES; }
static BOOL _canCostTantanCoinForSuperLike_YES(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_MATCH_LIMIT); return YES; }
static id _svipExpiredDate_future(id self, SEL _cmd) {
    XH_GUARD_ID(XH_SW_MATCH_LIMIT);
    return [NSDate dateWithTimeIntervalSinceNow:10.0 * 365.0 * 24.0 * 3600.0];
}

// ---------- 四选一(极限四选一/Picks) 次数限制解除 ----------
// "今日选择已结束" 的根因: freePicksCount/dailyFreePicksCount 归零 + picksExpiredTimestamp 过期
static unsigned long long _freePicksCount_max(id self, SEL _cmd) { XH_GUARD_ULL(XH_SW_PICK); return 999999; }
static unsigned long long _dailyFreePicksCount_max(id self, SEL _cmd) { XH_GUARD_ULL(XH_SW_PICK); return 999999; }
static id _picksExpiredTimestamp_nil(id self, SEL _cmd) { XH_GUARD_ID(XH_SW_PICK); return nil; }  // 永不过期
static BOOL _hasUsedPicksFree_NO(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_PICK); return NO; }       // 从未用过免费次数
static BOOL _isEnableExtremePick_YES(id self, SEL _cmd) { XH_GUARD_BOOL(XH_SW_PICK); return YES; }  // 四选一永远可用


// ============================================================
// 四选一接口对接: 把"正常划卡喜欢"改导到"四选一(超速配)匹配"接口
// ============================================================
// 背景: 正常喜欢走 /like 接口, 服务端被风控(匹配不到人);
//       四选一走 UltraInstantMatch 接口, 服务端没风控(能真匹配, 免费)。
// 目标: hook 正常喜欢的执行点, 改成调四选一匹配接口
// ============================================================

// 保存原 performLikeOnUser:actionType:completionBlock: 的 IMP
static IMP _orig_performLikeOnUser = NULL;
static IMP _orig_tryPerformLike = NULL;
static IMP _orig_pluginLikeAction = NULL;
static IMP _orig_pluginPerformAction = NULL;
// 开关: 四选一接口对接 (合并到"四选一"开关 xh_switch.pick, 默认开)
// 关闭时走正常匹配(原 likeUser 逻辑), 不重定向到四选一 pick 接口
#define _ultraMatchRedirectEnabled _swOn(XH_SW_PICK)

// 前置声明 (定义在后面)
static void _fetchExtremeQuestion(void (^done)(NSString *questionID, NSArray *allIds));
static void _sendRESTRequest(NSString *url, NSString *method, NSDictionary *body,
                             void (^success)(id result), void (^failure)(NSError *err));

// ============ 自动招呼 (四选一成功后延迟发送) ============
// 开关: xh_switch.auto_greet (喜欢面板里的"划卡自动发招呼")
// 话术: XH_AutoGreetText
static NSMutableSet *g_greetSet = nil;

static NSString *XH_GreetText(void) {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    NSString *t = [ud stringForKey:@"XH_AutoGreetText"];
    // 未设置 / 仍是旧默认话术 -> 迁移为"你好"
    if (!t.length || [t isEqualToString:@"你好，看到你的资料觉得挺合眼缘，能认识一下吗？"]) {
        [ud setObject:@"你好" forKey:@"XH_AutoGreetText"];
        [ud synchronize];
        return @"你好";
    }
    return t;
}

static void XH_AutoGreet(NSString *uid) {
    if (!uid || uid.length == 0) return;
    // 只接受纯数字 uid, 过滤 "(null)"/"<null>"/"?" 等无效值
    for (NSUInteger i = 0; i < uid.length; i++) {
        unichar c = [uid characterAtIndex:i];
        if (c < '0' || c > '9') {
            XLog(@"[招呼] 跳过无效 uid=%@", uid);
            return;
        }
    }
    if (!g_greetSet) g_greetSet = [NSMutableSet set];
    @synchronized (g_greetSet) {
        if ([g_greetSet containsObject:uid]) return;
        [g_greetSet addObject:uid];
    }
    NSString *text = XH_GreetText();
    XLog(@"[招呼] 开始 uid=%@ text=%@", uid, text);
    // 1) 文本审核
    _sendRESTRequest(@"https://core.tantanapp.com/v2/letters-verify", @"POST", @{@"letter": text},
        ^(id r) {
            XLog(@"[招呼] verify 成功: %@", r);
            // 2) 发招呼 (relationships)
            NSString *url = [NSString stringWithFormat:@"https://core.tantanapp.com/v2/users/me/relationships/%@", uid];
            _sendRESTRequest(url, @"PUT",
                @{@"status": @[@"letter"], @"state": @"liked", @"extensions": @{@"letter": text}},
                ^(id r2) { XLog(@"[招呼] 发送成功 uid=%@", uid); },
                ^(NSError *e2) { XLog(@"[招呼] 发送失败 uid=%@ err=%@", uid, e2); });
        },
        ^(NSError *e) { XLog(@"[招呼] verify 失败 err=%@", e); });
}

// 从 PUGSuggestedUser 提取 userID (modelIdentifier 格式 "PUGSuggestedUser_<userID>")
static NSString *_userIDOf(id user) {
    if (!user) return nil;
    @try {
        for (NSString *key in @[@"modelIdentifier", @"objectID", @"userID", @"userId", @"uid"]) {
            if ([user respondsToSelector:NSSelectorFromString(key)]) {
                id v = [user valueForKey:key];
                if (v) {
                    NSString *s = [v description];
                    // modelIdentifier 格式 "PUGSuggestedUser_663813853" -> 取 _ 后面的数字
                    if ([s containsString:@"_"]) {
                        NSArray *parts = [s componentsSeparatedByString:@"_"];
                        if (parts.count > 0) {
                            s = [parts lastObject];
                        }
                    }
                    // 只接受纯数字: 过滤 "(null)"/"<null>"/"?" 等无效值
                    // (之前 PUGSuggestedUser_(null) 会切出字符串 "(null)", 长度非 0,
                    //  于是对 relationships/(null) 发了无意义请求)
                    if (s.length == 0) continue;
                    BOOL allDigits = YES;
                    for (NSUInteger i = 0; i < s.length; i++) {
                        unichar c = [s characterAtIndex:i];
                        if (c < '0' || c > '9') { allDigits = NO; break; }
                    }
                    if (!allDigits) continue;
                    return s;
                }
            }
        }
    } @catch (NSException *e) {}
    return nil;
}

// 首页划卡点喜欢 -> 对接四选一 pick 接口 (把首页用户ID塞进 pick 的 allIds+pickedID)
static void _doUltraMatchWithUID(NSString *uid);
static void _doLikeRelationshipWithUID(NSString *uid, void (^done)(BOOL matched, NSString *detail));
static void _doUltraMatch(id user) {
    NSString *uid = _userIDOf(user);
    XLog(@"[对接] 首页划卡喜欢 user=%@ userID=%@, 开始对接四选一 pick 接口", user, uid);
    if (!uid || [uid isEqualToString:@"?"] || [uid length] == 0) {
        XLog(@"[对接] 无法获取 userID, 放弃对接");
        return;
    }
    // 自动招呼: 划卡点喜欢后延迟 2 秒发送, 直接发, 不依赖四选一 pick 的结果。
    // (之前挂在 pick 成功回调里, 但 /v2/extreme-picks/question 经常取不到题目,
    //  pick 发不出去 -> 招呼永远不触发。所以改成划卡即触发。)
    if ([[NSUserDefaults standardUserDefaults] boolForKey:@"xh_switch.auto_greet"]) {
        NSString *gUid = [uid copy];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            XH_AutoGreet(gUid);
        });
    }
    _doUltraMatchWithUID(uid);
}

// 直接按 uid 对接四选一 pick 接口 (用于"喜欢我的人"桃心等场景, 已有明确 uid)
static void _doUltraMatchWithUID(NSString *uid) {
    if (!uid || [uid isEqualToString:@"?"] || [uid length] == 0) {
        XLog(@"[对接] 无法获取 userID, 放弃对接");
        return;
    }
    // v21 去重: 网络 hook 和状态机会对同一 uid 各触发一次 pick, 10 秒内同 uid 只发一次
    static NSString *g_lastPickUid = nil;
    static CFAbsoluteTime g_lastPickTs = 0;
    CFAbsoluteTime now = CFAbsoluteTimeGetCurrent();
    if ([uid isEqualToString:g_lastPickUid] && (now - g_lastPickTs) < 10.0) {
        XLog(@"[对接] pick 去重: 10秒内已对 %@ 发过 pick, 跳过重复触发", uid);
        return;
    }
    g_lastPickUid = [uid copy];
    g_lastPickTs = now;
    // 先拿 question (拿 questionID + 真实 allIds 作为模板)
    _fetchExtremeQuestion(^(NSString *qid, NSArray *allIds) {
        if (!qid || !allIds || allIds.count == 0) {
            XLog(@"[对接] 拿题目失败, 无法对接");
            return;
        }
        // 把 allIds 的第一个替换成目标用户ID
        NSMutableArray *newAllIds = [allIds mutableCopy];
        [newAllIds replaceObjectAtIndex:0 withObject:uid];
        // 构造 pick body
        NSDictionary *body = @{
            @"pickIndex": @"1",
            @"questionID": qid,
            @"pickedID": uid,
            @"allIds": newAllIds,
            @"type": @"normal"
        };
        XLog(@"[对接] 发起 pick: questionID=%@ pickedID=%@(喜欢我的人) allIds=%@", qid, uid, newAllIds);
        _sendRESTRequest(@"https://core.tantanapp.com/v2/extreme-picks/pick", @"POST", body,
            ^(id result) {
                // 打印完整结果(含 meta.code / match 信息)
                NSString *full = result ? [result description] : @"(nil)";
                XLog(@"[对接] pick 返回成功! 完整结果=%@", full);
                // 解析 meta.code 判断是否真的匹配
                @try {
                    if ([result isKindOfClass:[NSDictionary class]]) {
                        NSDictionary *d = (NSDictionary *)result;
                        id meta = d[@"meta"];
                        id data = d[@"data"];
                        XLog(@"[对接] pick 结果解析: meta=%@ data=%@", meta, data);
                        // 重点: 解析 data.relationships 数组, 看 relationType 是 LIKED 还是 MATCHED
                        if ([data isKindOfClass:[NSDictionary class]]) {
                            NSArray *rels = data[@"relationships"];
                            if ([rels isKindOfClass:[NSArray class]] && rels.count > 0) {
                                for (id r in rels) {
                                    if ([r isKindOfClass:[NSDictionary class]]) {
                                        NSDictionary *rd = (NSDictionary *)r;
                                        id ext = rd[@"extensions"];
                                        id statusArr = rd[@"status"];
                                        id rid = rd[@"id"];
                                        XLog(@"[对接] ★ relationship: id=%@ extensions=%@ status=%@", rid, ext, statusArr);
                                        // 判断是否 MATCHED
                                        if ([ext isKindOfClass:[NSDictionary class]]) {
                                            NSString *rt = [ext[@"relationType"] description];
                                            BOOL isMatched = [rt isEqualToString:@"MATCHED"] || [rt isEqualToString:@"matched"] || [rt containsString:@"MATCH"];
                                            XLog(@"[对接] ★★ relationType=%@ 是否互相匹配=%@", rt, isMatched ? @"YES✅" : @"NO(仅单向LIKED)");
                                            // 四选一成功 -> 延迟 2 秒发招呼 (开关: xh_switch.auto_greet)
                                            if ([[NSUserDefaults standardUserDefaults] boolForKey:@"xh_switch.auto_greet"]) {
                                                NSString *gUid = [uid copy];
                                                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                                                    XH_AutoGreet(gUid);
                                                });
                                            }
                                        }
                                    }
                                }
                            } else {
                                XLog(@"[对接] pick 返回无 relationships 数组(可能匹配失败)");
                            }
                        }
                    }
                } @catch (NSException *e) {
                    XLog(@"[对接] pick 结果解析异常: %@", e);
                }
            },
            ^(NSError *err) {
                XLog(@"[对接] pick 失败: %@", err);
            });
    });
}

// ============================================================
// 喜欢我的人 -> 划卡对接 (开关: xh_switch.seelikes_swipe, 默认关)
// ============================================================
// 流程:
//   1) "喜欢我的人"页面每次刷新/加载更多, 从
//      PUGMyEncounterSeeLikesAllUserUseCase.seeLikesUsers 收集全部 user 的 uid
//      (批量拉取靠页面自身翻页, 这里只负责"看到多少收多少", 去重持久化)
//   2) 开关打开时:
//      a. 把收集到的 user 构造成 PUGSuggestedUser, 用
//         PUGSuggestedUserUseCase addSuggestUser:index: 插进划卡数据模型
//         -> 这些人出现在划卡(匹配)界面
//      b. 逐个调 _doUltraMatchWithUID(uid), 走四选一 extreme-picks/pick 接口
//         建立真实匹配关系 (与"桃心强制匹配"同一接口, 服务端不限流)
//   3) 开关关闭时: 抽走插入的卡片(tryRemoveSuggestedUser:), 中止后续对接
// 说明: 插卡是探探自己的 "isLikeInsertUser" 机制, 不会污染推荐池持久数据。
// ============================================================
#define XH_SW_SEELIKES_SWIPE @"xh_switch.seelikes_swipe"
#define XH_SEELIKES_UID_KEY   @"xh.seelikes.uids.v2"  // 收集到的 uid 数组(持久化, v2=以 publicId 为准)
#define XH_SEELIKES_MATCH_KEY @"xh.seelikes.matched.v2"// 已对接过的 uid 数组

static NSMutableOrderedSet  *g_likedMeUIDs = nil;    // 有序去重
static __weak id             g_seeLikesUC = nil;      // PUGSeeLikesUseCase 实例(挂 setSeeLikesUsers: 时记下)
static NSString             *g_sl_cur_sel = nil;    // 当前正在跑的收集 hook 方法名(区分数据来源)
static NSMutableOrderedSet   *g_likedMeOnly = nil;    // 只来自 PUGSeeLikesUseCase setSeeLikesUsers: 的 uid (真正的"喜欢我"列表)
static NSMutableDictionary  *g_likedMeUserMap = nil; // uid -> user 对象(强引用, 防列表刷新后失效)
static NSMutableSet         *g_likedMeMatched = nil; // 已对接
static NSMutableSet         *g_likedMeInjected = nil;// 已插入划卡
static __weak id             g_swipeUseCase = nil;   // PUGSuggestedUserUseCase 实例
static BOOL                  g_likedMeBatchRunning = NO;
static BOOL                  g_likedMeAutoInjected = NO; // 本会话已自动插过卡(防每批刷新重复堆卡)

// 前置声明 (定义在下面, XHSeelikesCollect 里要用)
static void XHSeelikesInjectToSwipe(void);
static void XHSeelikesStartBatchMatch(void);

static void XHSeelikesPersist(void) {
    if (!g_likedMeUIDs) return;
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    [ud setObject:g_likedMeUIDs.array forKey:XH_SEELIKES_UID_KEY];
    [ud setObject:g_likedMeMatched.allObjects ?: @[] forKey:XH_SEELIKES_MATCH_KEY];
    [ud synchronize];
}

static void XHSeelikesInit(void) {
    if (g_likedMeUIDs) return;
    g_likedMeUIDs = [NSMutableOrderedSet orderedSet];
    g_likedMeUserMap = [NSMutableDictionary dictionary];
    g_likedMeMatched = [NSMutableSet set];
    g_likedMeInjected = [NSMutableSet set];
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    NSArray *saved = [ud arrayForKey:XH_SEELIKES_UID_KEY];
    if ([saved isKindOfClass:[NSArray class]]) {
        for (id v in saved) { if ([v isKindOfClass:[NSString class]]) [g_likedMeUIDs addObject:v]; }
    }
    NSArray *matched = [ud arrayForKey:XH_SEELIKES_MATCH_KEY];
    if ([matched isKindOfClass:[NSArray class]]) {
        for (id v in matched) { if ([v isKindOfClass:[NSString class]]) [g_likedMeMatched addObject:v]; }
    }
}

// 从任意对象提 uid: 兼容 PUGIntlEncounterSeeLikeModel(取 .user)、PUGUser(objectId)、
// PUGSuggestedUser(modelIdentifier "PUGSuggestedUser_123")
static NSString *XHSeelikesUIDOf(id obj) {
    if (!obj) return nil;
    @try {
        // v24: 裸字典(接口原始JSON)支持 — {user:{...}} 包裹 或 直接 {id:"660905401"}
        if ([obj isKindOfClass:[NSDictionary class]]) {
            NSDictionary *od = (NSDictionary *)obj;
            id w = od[@"user"];
            if ([w isKindOfClass:[NSDictionary class]]) {
                NSString *r = XHSeelikesUIDOf(w);
                if (r.length) return r;
            }
            for (NSString *key in @[@"publicId", @"objectId", @"objectID", @"userID", @"userId", @"uid", @"id"]) {
                id v = od[key];
                if (!v) continue;
                NSString *s = [v description];
                if ([s containsString:@"_"]) s = [[s componentsSeparatedByString:@"_"] lastObject];
                BOOL digits = s.length > 0;
                for (NSUInteger i = 0; i < s.length; i++) {
                    unichar c = [s characterAtIndex:i];
                    if (c < '0' || c > '9') { digits = NO; break; }
                }
                if (digits) return s;
            }
            return nil;
        }
        // 包裹对象(model)先取 user
        if ([obj respondsToSelector:NSSelectorFromString(@"user")]) {
            id u = [obj valueForKey:@"user"];
            if (u && u != obj) {
                NSString *r = XHSeelikesUIDOf(u);
                if (r.length) return r;
            }
        }
        // publicId 是 PUGUser 自己的数值 id(和接口 relationship.id 同一套), 放最前面
        for (NSString *key in @[@"publicId", @"objectId", @"objectID", @"userID", @"userId", @"uid", @"modelIdentifier"]) {
            if (![obj respondsToSelector:NSSelectorFromString(key)]) continue;
            id v = [obj valueForKey:key];
            if (!v) continue;
            NSString *s = [v description];
            if (![s isKindOfClass:[NSString class]] || s.length == 0) continue;
            if ([s containsString:@"_"]) s = [[s componentsSeparatedByString:@"_"] lastObject];
            BOOL digits = YES;
            for (NSUInteger i = 0; i < s.length; i++) {
                unichar c = [s characterAtIndex:i];
                if (c < '0' || c > '9') { digits = NO; break; }
            }
            if (!digits || s.length == 0) continue;
            return s;
        }
    } @catch (NSException *e) {}
    return nil;
}

// 只认真正的 PUGUser 实例 —— 有些列表 model 的 user 属性返回的是 NSNumber(userId),
// 直接拿去构造 PUGSuggestedUser 会在 [user userId] 上崩。
static id _sl_real_puguser(id item) {
    Class PU = NSClassFromString(@"PUGUser");
    if (!PU || !item) return nil;
    if ([item isKindOfClass:PU]) return item;
    for (NSString *k in @[@"user", @"pugUser", @"userModel", @"userInfo"]) {
        @try {
            if ([item respondsToSelector:NSSelectorFromString(k)]) {
                id u = [item valueForKey:k];
                if ([u isKindOfClass:PU]) return u;
            }
        } @catch (NSException *e) {}
    }
    return nil;
}

// 一次性探针: 把列表元素真实结构打进日志, 用来确定 user 藏在哪个 ivar
static void _sl_probe_once(NSArray *arr) {
    static BOOL probed = NO;
    if (probed || ![arr isKindOfClass:[NSArray class]] || arr.count == 0) return;
    probed = YES;
    id it = arr.firstObject;
    NSMutableString *s = [NSMutableString string];
    [s appendFormat:@"元素类=%@", NSStringFromClass([it class])];
    if ([it isKindOfClass:[NSDictionary class]]) {
        [s appendFormat:@" keys=%@", [[(NSDictionary *)it allKeys] componentsJoinedByString:@","]];
    } else if (![it isKindOfClass:[NSString class]] && ![it isKindOfClass:[NSNumber class]]) {
        unsigned int n = 0;
        Ivar *ivs = class_copyIvarList([it class], &n);
        NSMutableArray *names = [NSMutableArray array];
        for (unsigned i = 0; i < n; i++) {
            const char *nm = ivar_getName(ivs[i]);
            if (!nm) continue;
            [names addObject:[NSString stringWithUTF8String:nm]];
        }
        free(ivs);
        if (names.count) [s appendFormat:@" ivars=%@", [names componentsJoinedByString:@","]];
    }
    for (NSString *k in @[@"user", @"userId", @"identifier", @"objectId"]) {
        @try {
            if ([it respondsToSelector:NSSelectorFromString(k)]) {
                id v = [it valueForKey:k];
                [s appendFormat:@" | %@=<%@>", k, NSStringFromClass([v class])];
            }
        } @catch (NSException *e) {}
    }
    XLog(@"[喜欢我→划卡] 列表元素结构: %@", s);
}

// 收集数组里的 user (元素可能是 model, 也可能是 user 本身)
static NSInteger XHSeelikesCollect(NSArray *arr) {
    if (![arr isKindOfClass:[NSArray class]] || arr.count == 0) return 0;
    XHSeelikesInit();
    @try { _sl_probe_once(arr); } @catch (NSException *e) {}
    NSInteger added = 0;
    @synchronized (g_likedMeUIDs) {
        // 每批第一个元素把 id 相关字段全打一遍, 用来确认哪个字段是稳定身份
        if (arr.count > 0) {
            id probe = arr.firstObject;
            NSMutableString *dump = [NSMutableString string];
            for (NSString *k in @[@"publicId", @"objectId", @"objectID", @"userID", @"userId", @"uid",
                                  @"modelIdentifier", @"name", @"anchorID"]) {
                NSString *v = @"(无此方法)";
                @try {
                    if ([probe respondsToSelector:NSSelectorFromString(k)]) {
                        id x = [probe valueForKey:k];
                        v = x ? [NSString stringWithFormat:@"<%@>%@", NSStringFromClass([x class]), x] : @"(nil)";
                    }
                } @catch (NSException *e) { v = [@"ERR:" stringByAppendingString:e.reason ?: @""]; }
                [dump appendFormat:@" %@=%@ |", k, v];
            }
            XLog(@"[喜欢我→划卡] 字段核对 批=%lu 元素=%@ 取到uid=%@ {%@}", (unsigned long)arr.count,
                 NSStringFromClass([probe class]), XHSeelikesUIDOf(probe) ?: @"(nil)", dump);
        }
        for (id item in arr) {
            NSString *uid = XHSeelikesUIDOf(item);
            if (!uid) continue;
            // 只存真 PUGUser, 拿不到就留着之前已存的, 绝不塞 NSNumber
            id user = _sl_real_puguser(item);
            if (user && !g_likedMeUserMap[uid]) g_likedMeUserMap[uid] = user;
            // 只有"喜欢我"列表(setSeeLikesUsers:)才算进 g_likedMeOnly, 访客/我喜欢的不算
            if (user && [g_sl_cur_sel isEqualToString:@"setSeeLikesUsers:"]) {
                if (!g_likedMeOnly) g_likedMeOnly = [NSMutableOrderedSet orderedSet];
                [g_likedMeOnly addObject:uid];
            }
            if (![g_likedMeUIDs containsObject:uid]) { [g_likedMeUIDs addObject:uid]; added++; }
        }
    }
    if (added > 0) {
        XHSeelikesPersist();
        XLog(@"[喜欢我→划卡] 收集 +%ld, 累计 %lu 人", (long)added, (unsigned long)g_likedMeUIDs.count);
        // 开关打开时, 新收集到的人立即插卡 + 排队对接 (每会话只自动插一次, 之后靠手动按钮)
        if (_swOn(XH_SW_SEELIKES_SWIPE) && !g_likedMeAutoInjected) {
            dispatch_async(dispatch_get_main_queue(), ^{
                XHSeelikesInjectToSwipe();
                XHSeelikesStartBatchMatch();
            });
        }
    }
    return added;
}

// 把收集到的人插进划卡数据模型
static void XHSeelikesInjectToSwipe(void) {
    if (!_swOn(XH_SW_SEELIKES_SWIPE)) return;
    id uc = g_swipeUseCase;
    if (!uc) { XLog(@"[喜欢我→划卡] 划卡 use case 未就绪, 等下次刷新再插"); return; }
    Class SU = NSClassFromString(@"PUGSuggestedUser");
    if (!SU) { XLog(@"[喜欢我→划卡] 无 PUGSuggestedUser 类"); return; }
    XHSeelikesInit();
    SEL selExist = NSSelectorFromString(@"suggestedUserWithUserID:");
    SEL selAdd   = NSSelectorFromString(@"addSuggestUser:index:");
    SEL selInsert= NSSelectorFromString(@"insertUsers:positions:");
    SEL selLike  = NSSelectorFromString(@"setIsLikeInsertUser:");
    NSInteger added = 0, failed = 0, noUser = 0;
    NSArray *uids = g_likedMeUIDs.array;
    // 先扫一遍划卡现有队列里所有人的 publicId, 已经在了就不重复插
    NSMutableSet *inDeck = [NSMutableSet set];
    @try {
        SEL selUnswiped = NSSelectorFromString(@"unswipedUsers");
        if ([uc respondsToSelector:selUnswiped]) {
            NSArray *cur = ((id(*)(id, SEL))objc_msgSend)(uc, selUnswiped);
            if ([cur isKindOfClass:[NSArray class]]) {
                for (id su in cur) {
                    @try {
                        id u = [su valueForKey:@"user"];
                        id pid = [u valueForKey:@"publicId"];
                        if (pid) [inDeck addObject:[pid description]];
                    } @catch (NSException *e) {}
                }
            }
        }
    } @catch (NSException *e) {}
    if (inDeck.count) XLog(@"[喜欢我→划卡] 划卡队列已有 %lu 人, 将跳过重复", (unsigned long)inDeck.count);
    for (NSString *uid in uids) {
        @autoreleasepool {
            if ([g_likedMeInjected containsObject:uid]) continue;
            if ([inDeck containsObject:uid]) { [g_likedMeInjected addObject:uid]; continue; }
            id user = g_likedMeUserMap[uid];
            if (!user) { noUser++; continue; }
            // 划卡里已经有了 -> 记为已注入, 不重复插
            @try {
                if ([uc respondsToSelector:selExist]) {
                    id exist = ((id(*)(id, SEL, id))objc_msgSend)(uc, selExist, uid);
                    if (exist) { [g_likedMeInjected addObject:uid]; continue; }
                }
            } @catch (NSException *e) {}
            id su = nil;
            @try {
                su = [[SU alloc] init];
                [su setValue:user forKey:@"user"];
                if ([su respondsToSelector:selLike]) {
                    ((void(*)(id, SEL, BOOL))objc_msgSend)(su, selLike, YES);
                }
            } @catch (NSException *e) {
                XLog(@"[喜欢我→划卡] 构造卡片异常 uid=%@ %@", uid, e.reason);
                su = nil;
            }
            if (!su) { failed++; continue; }
            // 一次性体检: 卡片关键字段是否齐, 定位内部校验抛异常的点
            static int _cardChk = 0;
            if (_cardChk < 2) {
                _cardChk++;
                NSString *ident = @"?";
                @try { ident = [NSString stringWithFormat:@"%@", [su valueForKey:@"identifier"]]; } @catch (NSException *e) { ident = [@"ERR:" stringByAppendingString:e.reason ?: @""]; }
                XLog(@"[喜欢我→划卡] 卡片体检 uid=%@ su=%@ user=<%@> ident=%@", uid,
                     NSStringFromClass([su class]), NSStringFromClass([user class]), ident);
            }
            BOOL ok = NO;
            // 两条路分开 try: insertUsers 抛异常时仍能退回 addSuggestUser
            @try {
                // 优先 insertUsers:positions: (返回 BOOL, 能确认插进去了)
                if ([uc respondsToSelector:selInsert]) {
                    ok = ((BOOL(*)(id, SEL, id, id))objc_msgSend)(uc, selInsert, @[su], @[@(0)]);
                }
            } @catch (NSException *e) {
                static int _stackLogged = 0;
                if (_stackLogged < 2) {
                    _stackLogged++;
                    NSArray *st = [NSThread callStackSymbols];
                    NSUInteger lim = st.count < 16 ? st.count : 16;
                    XLog(@"[喜欢我→划卡] insertUsers 异常 uid=%@ %@\n%@", uid, e.reason,
                         [[st subarrayWithRange:NSMakeRange(0, lim)] componentsJoinedByString:@"\n"]);
                }
            }
            if (!ok) {
                @try {
                    if ([uc respondsToSelector:selAdd]) {
                        ((void(*)(id, SEL, id, long long))objc_msgSend)(uc, selAdd, su, 0);
                        ok = YES;
                    }
                } @catch (NSException *e) {
                    static int _stackLogged2 = 0;
                    if (_stackLogged2 < 2) {
                        _stackLogged2++;
                        NSArray *st = [NSThread callStackSymbols];
                        NSUInteger lim = st.count < 16 ? st.count : 16;
                        XLog(@"[喜欢我→划卡] addSuggestUser 异常 uid=%@ %@\n%@", uid, e.reason,
                             [[st subarrayWithRange:NSMakeRange(0, lim)] componentsJoinedByString:@"\n"]);
                    } else {
                        XLog(@"[喜欢我→划卡] 插卡异常 uid=%@ %@", uid, e.reason);
                    }
                }
            }
            if (ok) { [g_likedMeInjected addObject:uid]; added++; } else failed++;
        }
    }
    XLog(@"[喜欢我→划卡] 插卡 +%ld 失败 %ld 缺user %ld (已插 %lu / 收集 %lu)",
         (long)added, (long)failed, (long)noUser,
         (unsigned long)g_likedMeInjected.count, (unsigned long)g_likedMeUIDs.count);
    // 本会话自动插过就不再自动插, 后续新增只能手动按钮触发, 避免每批刷新重复堆卡
    if (added > 0) g_likedMeAutoInjected = YES;
    // 通知划卡界面刷新, 否则开着划卡页时新卡不显示
    if (added > 0) {
        @try {
            SEL selChanged = NSSelectorFromString(@"suggestedUsersChangedWithSource:");
            if ([uc respondsToSelector:selChanged]) {
                ((void(*)(id, SEL, unsigned long long))objc_msgSend)(uc, selChanged, 0ULL);
                XLog(@"[喜欢我→划卡] 已通知界面刷新");
            }
        } @catch (NSException *e) {}
    }
}

// 开关关闭: 抽走插进划卡的卡片
static void XHSeelikesRemoveFromSwipe(void) {
    id uc = g_swipeUseCase;
    XHSeelikesInit();
    if (!uc || g_likedMeInjected.count == 0) { [g_likedMeInjected removeAllObjects]; return; }
    SEL selExist = NSSelectorFromString(@"suggestedUserWithUserID:");
    SEL selRemove = NSSelectorFromString(@"tryRemoveSuggestedUser:");
    NSInteger n = 0;
    for (NSString *uid in [g_likedMeInjected copy]) {
        @try {
            if (![uc respondsToSelector:selExist] || ![uc respondsToSelector:selRemove]) break;
            id su = ((id(*)(id, SEL, id))objc_msgSend)(uc, selExist, uid);
            if (su) { ((id(*)(id, SEL, id))objc_msgSend)(uc, selRemove, su); n++; }
        } @catch (NSException *e) {}
    }
    XLog(@"[喜欢我→划卡] 已抽走 %ld 张卡", (long)n);
    [g_likedMeInjected removeAllObjects];
}

// 批量对接四选一 pick 接口(串行, 1.5s 间隔, 单次上限 60)
static void XHSeelikesStartBatchMatch(void) {
    if (!_swOn(XH_SW_SEELIKES_SWIPE)) return;
    if (g_likedMeBatchRunning) return;
    XHSeelikesInit();
    NSMutableArray *todo = [NSMutableArray array];
    @synchronized (g_likedMeUIDs) {
        for (NSString *uid in g_likedMeUIDs) {
            if ([g_likedMeMatched containsObject:uid]) continue;
            [todo addObject:uid];
        }
    }
    if (todo.count == 0) { XLog(@"[喜欢我→划卡] 无待对接(全部已处理)"); return; }
    if (todo.count > 60) todo = [[todo subarrayWithRange:NSMakeRange(0, 60)] mutableCopy];
    g_likedMeBatchRunning = YES;
    XLog(@"[喜欢我→划卡] 开始批量对接 %lu 个", (unsigned long)todo.count);
    __block NSInteger idx = 0;
    // 用 weak 自引用, 避免 ARC retain cycle (编译 -Werror=arc-retain-cycles)
    __block __weak void (^weakStep)(void);
    void (^step)(void);
    weakStep = step = ^{
        if (!_swOn(XH_SW_SEELIKES_SWIPE)) {
            g_likedMeBatchRunning = NO;
            XLog(@"[喜欢我→划卡] 开关已关, 中止批量对接");
            return;
        }
        if (idx >= todo.count) {
            g_likedMeBatchRunning = NO;
            XLog(@"[喜欢我→划卡] 批量对接结束");
            return;
        }
        NSString *uid = todo[idx++];
        [g_likedMeMatched addObject:uid];
        XHSeelikesPersist();
        XLog(@"[喜欢我→划卡] 对接 %ld/%lu uid=%@", (long)idx, (unsigned long)todo.count, uid);
        _doLikeRelationshipWithUID(uid, nil);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            void (^s)(void) = weakStep;
            if (s) s();
        });
    };
    step();
}

// ============================================================
// 探探真实"喜欢"接口: PUT /v2/users/me/relationships/{uid}
//   对方已在"喜欢我"列表里(对方 liked 我) -> 服务端判定互相喜欢 -> relationType=MATCHED
//   extreme-picks/pick 只建单向 LIKED, 拿不到互配, 所以这里换成 relationships
// ============================================================
// 把一个响应/错误对象里的状态码和正文全打出来 (TXTResponse 等)
static NSString *XHDumpResp(id o) {
    if (!o) return @"(nil)";
    NSMutableString *s = [NSMutableString stringWithFormat:@"<%@", NSStringFromClass([o class])];
    // v22: error/responseString 排前面, urlResponse 的 Headers 说明太长放最后并截断
    for (NSString *k in @[@"statusCode", @"statuscode", @"code", @"httpStatusCode",
                          @"errorCode", @"message", @"errorMessage",
                          @"error", @"responseString", @"responseObject", @"responseData",
                          @"requestUrl", @"rawResponseObject", @"urlResponse"]) {
        @try {
            if ([o respondsToSelector:NSSelectorFromString(k)]) {
                id v = [o valueForKey:k];
                if ([v isKindOfClass:[NSData class]]) {
                    NSString *t = [[NSString alloc] initWithData:(NSData *)v encoding:NSUTF8StringEncoding];
                    v = t.length > 600 ? [[t substringToIndex:600] stringByAppendingString:@"..."] : (t ?: [NSString stringWithFormat:@"<%luB 非UTF8>", (unsigned long)[(NSData *)v length]]);
                }
                if ([v isKindOfClass:[NSDictionary class]] || [v isKindOfClass:[NSArray class]]) {
                    NSString *t = [v description];
                    v = t.length > 800 ? [[t substringToIndex:800] stringByAppendingString:@"..."] : t;
                }
                // v22: 通用截断, 防 NSError/NSHTTPURLResponse 的长 description 淹没正文
                {
                    NSString *t = [v description];
                    if (t.length > 1200) v = [[t substringToIndex:1200] stringByAppendingString:@"...(截断)"];
                }
                [s appendFormat:@" %@=%@", k, v];
            }
        } @catch (NSException *e) {}
    }
    if (s.length < 40) {
        // 一个字段都没探到 -> 把所有方法名打出来
        unsigned int n = 0;
        Method *ms = class_copyMethodList([o class], &n);
        NSMutableString *names = [NSMutableString string];
        for (unsigned int i = 0; i < n && i < 40; i++) {
            [names appendFormat:@"%@ ", NSStringFromSelector(method_getName(ms[i]))];
        }
        if (ms) free(ms);
        [s appendFormat:@" 方法列表=[%@]", names];
    }
    [s appendString:@">"];
    return s;
}

// ============================================================
// 诊断: 400313 identity verify 挡住了 PUT relationships
//   对同一个人依次试 4 条通道/写法, 看哪条不被风控:
//   1) GET  relationships (原生, 看对方是否真的 liked 我)
//   2) PUT  relationships (原生, 不带 WebBridge)
//   3) POST /v2/likes
//   4) POST /v2/users/me/likes
// ============================================================
static void _sendRESTRequestWB(NSString *url, NSString *method, NSDictionary *body, BOOL webBridge,
                               void (^success)(id result), void (^failure)(id err));

static NSArray  *g_diagSteps = nil;
static NSInteger g_diagIdx = 0;
static NSString *g_diagUID = nil;
static void (^g_diagDone)(void) = nil;

static void XHDiagStep(void) {
    if (!g_diagSteps || g_diagIdx >= g_diagSteps.count) {
        XLog(@"[诊断] === 全部结束 ===");
        void (^d)(void) = g_diagDone;
        g_diagDone = nil;
        if (d) d();
        return;
    }
    NSDictionary *st = g_diagSteps[g_diagIdx];
    g_diagIdx++;
    NSString *m = st[@"m"];
    NSString *url = [st[@"u"] stringByReplacingOccurrencesOfString:@"{uid}" withString:g_diagUID];
    BOOL wb = [st[@"wb"] boolValue];
    NSDictionary *rawBody = st[@"b"];
    NSMutableDictionary *b = nil;
    if (rawBody) {
        b = [NSMutableDictionary dictionary];
        for (NSString *k in rawBody) {
            id v = rawBody[k];
            if ([v isKindOfClass:[NSString class]] && [v isEqualToString:@"{uid}"]) v = g_diagUID;
            b[k] = v;
        }
    }
    XLog(@"[诊断] %ld/%lu %@ %@ webBridge=%@ body=%@", (long)g_diagIdx, (unsigned long)g_diagSteps.count, m, url, wb ? @"Y" : @"N", b);
    _sendRESTRequestWB(url, m, b, wb, ^(id r) {
        XLog(@"[诊断] ✔ %@ %@ 返回=%@", m, url, r);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ XHDiagStep(); });
    }, ^(id e) {
        XLog(@"[诊断] ✘ %@ %@ 详情=%@", m, url, XHDumpResp(e));
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ XHDiagStep(); });
    });
}

__attribute__((unused)) static void XHDiagRun(NSString *uid, void (^done)(void)) {
    g_diagSteps = @[
        @{@"m": @"GET",  @"u": @"https://core.tantanapp.com/v2/users/me/relationships/{uid}", @"wb": @NO},
        @{@"m": @"PUT",  @"u": @"https://core.tantanapp.com/v2/users/me/relationships/{uid}", @"wb": @NO,
          @"b": @{@"status": @[@"like"], @"state": @"liked"}},
        @{@"m": @"POST", @"u": @"https://core.tantanapp.com/v2/likes", @"wb": @NO,
          @"b": @{@"userId": @"{uid}"}},
        @{@"m": @"POST", @"u": @"https://core.tantanapp.com/v2/users/me/likes", @"wb": @NO,
          @"b": @{@"userId": @"{uid}"}},
    ];
    g_diagIdx = 0;
    g_diagUID = uid;
    g_diagDone = done;
    XHDiagStep();
}

// 探测: 哪种 body 能被服务端接受 (一次运行只探一次, 结果缓存)
static NSDictionary *g_okLikeBody = nil;
static NSArray      *g_probeCands = nil;
static NSInteger     g_probeIdx = 0;
static NSString     *g_probeUID = nil;
static void (^g_probeDone)(NSDictionary *body) = nil;

static void XHProbeLikeStep(void) {
    if (!g_probeCands || g_probeIdx >= g_probeCands.count) {
        XLog(@"[喜欢我匹配] 探测结束: 全部 body 都被拒");
        void (^d)(NSDictionary *) = g_probeDone;
        g_probeDone = nil;
        if (d) d(nil);
        return;
    }
    NSDictionary *b = g_probeCands[g_probeIdx];
    g_probeIdx++;
    NSString *url = [NSString stringWithFormat:@"https://core.tantanapp.com/v2/users/me/relationships/%@", g_probeUID];
    XLog(@"[喜欢我匹配] 探测 %ld/%lu body=%@", (long)g_probeIdx, (unsigned long)g_probeCands.count, b);
    _sendRESTRequestWB(url, @"PUT", b, NO, ^(id r) {
        XLog(@"[喜欢我匹配] ★探测通过 body=%@ 返回=%@", b, r);
        g_okLikeBody = b;
        void (^d)(NSDictionary *) = g_probeDone;
        g_probeDone = nil;
        if (d) d(b);
    }, ^(id e) {
        XLog(@"[喜欢我匹配] 探测失败 body=%@ 详情=%@", b, XHDumpResp(e));
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ XHProbeLikeStep(); });
    });
}

__attribute__((unused)) static void XHProbeLikeBody(NSString *uid, void (^done)(NSDictionary *body)) {
    g_probeCands = @[
        @{@"status": @[@"like"], @"state": @"liked"},
        @{@"status": @[@"liked"], @"state": @"liked"},
        @{@"status": @[@"like"]},
        @{@"status": @[@"liked"]},
        @{@"status": @[@"like"], @"state": @"liked", @"extensions": @{}},
        @{@"status": @[@"liked"], @"state": @"liked", @"extensions": @{}},
    ];
    g_probeIdx = 0;
    g_probeUID = uid;
    g_probeDone = done;
    XHProbeLikeStep();
}

static void _doLikeRelationshipWithUID(NSString *uid, void (^done)(BOOL matched, NSString *detail)) {
    if (!uid.length) { if (done) done(NO, @"empty uid"); return; }
    NSString *url = [NSString stringWithFormat:@"https://core.tantanapp.com/v2/users/me/relationships/%@", uid];
    // 官方手动抓包 body: {"isAiOrderPictureGroup":false,"state":"liked"} (ussTracker 为客户端埋点token, 可不带)
    NSDictionary *body = g_okLikeBody ?: @{@"isAiOrderPictureGroup": @NO, @"state": @"liked"};
    XLog(@"[喜欢我匹配] PUT %@ body=%@", url, body);
    _sendRESTRequestWB(url, @"PUT", body, NO, ^(id result) {
        BOOL matched = NO;
        NSString *rt = @"(无返回)";
        @try {
            if ([result isKindOfClass:[NSDictionary class]]) {
                NSDictionary *d = (NSDictionary *)result;
                NSArray *rels = nil;
                id data = d[@"data"];
                if ([data isKindOfClass:[NSDictionary class]]) {
                    id r1 = ((NSDictionary *)data)[@"relationship"];
                    id r2 = ((NSDictionary *)data)[@"relationships"];
                    if ([r1 isKindOfClass:[NSDictionary class]]) rels = @[r1];
                    else if ([r2 isKindOfClass:[NSArray class]]) rels = r2;
                }
                if (!rels && [d[@"relationships"] isKindOfClass:[NSArray class]]) rels = d[@"relationships"];
                for (id r in rels) {
                    if (![r isKindOfClass:[NSDictionary class]]) continue;
                    NSDictionary *rd = (NSDictionary *)r;
                    NSDictionary *ext = rd[@"extensions"];
                    NSString *other = @"-";
                    if ([ext isKindOfClass:[NSDictionary class]]) {
                        id v = ext[@"relationType"];
                        if (v) rt = [v description];
                        id ov = ext[@"otherRelationType"];
                        if (ov) other = [ov description];
                    }
                    // 原生头响应: 无 extensions, 只有 id/state。有记录+state=liked 即成功
                    NSString *st = [rd[@"state"] description];
                    if (st.length) rt = st;
                    if ([rt.uppercaseString containsString:@"MATCH"] || [st isEqualToString:@"liked"]) matched = YES;
                    XLog(@"[喜欢我匹配] ★ 关系返回 uid=%@ state=%@ relationType=%@ other=%@",
                         rd[@"id"], st, rt, other);
                }
                id meta = d[@"meta"];
                if ([meta isKindOfClass:[NSDictionary class]]) {
                    XLog(@"[喜欢我匹配] meta=%@" , meta);
                }
            }
        } @catch (NSException *e) { XLog(@"[喜欢我匹配] 解析异常 %@", e.reason); }
        XLog(@"[喜欢我匹配] 结果 uid=%@ matched=%@ relationType=%@",
             uid, matched ? @"YES" : @"NO", rt);
        if (done) done(matched, rt);
    }, ^(NSError *err) {
        XLog(@"[喜欢我匹配] 喜欢请求失败 uid=%@ 详情=%@", uid, XHDumpResp(err));
        if (done) done(NO, [err description] ?: @"err");
    });
}

// ============================================================
// 网络嗅探: 抓探探自己发的 relationships / like 请求, 用来核对正确 body
// ============================================================
static IMP g_net_start_orig = NULL;
static void xh_net_start(id self, SEL _cmd, id succ, id fail) {
    @try {
        NSString *u = nil;
        for (NSString *k in @[@"urlString", @"url", @"URLString", @"path", @"apiPath"]) {
            if ([self respondsToSelector:NSSelectorFromString(k)]) {
                id v = [self valueForKey:k];
                if ([v isKindOfClass:[NSString class]] && [v length]) { u = v; break; }
            }
        }
        if (u.length) {
            NSString *low = u.lowercaseString;
            if ([low containsString:@"relationship"] || [low containsString:@"/like"]
                || [low containsString:@"see-likes"] || [low containsString:@"liked-user"]
                || [low containsString:@"swipe"] || [low containsString:@"encounter"]
                || [low containsString:@"who-likes"] || [low containsString:@"admire"]) {
                NSString *m = @"?";
                if ([self respondsToSelector:@selector(httpMethod)]) {
                    id v = [self valueForKey:@"httpMethod"];
                    if (v) m = [v description];
                }
                NSDictionary *pd = nil;
                if ([self respondsToSelector:@selector(paramsDictionary)]) {
                    id v = [self valueForKey:@"paramsDictionary"];
                    if ([v isKindOfClass:[NSDictionary class]]) pd = v;
                }
                XLog(@"[网络] %@ %@ params=%@", m, u, pd);
            }
        }
    } @catch (NSException *e) {}
    if (g_net_start_orig) ((void(*)(id, SEL, id, id))g_net_start_orig)(self, _cmd, succ, fail);
}

static void XHInstallNetSniffer(void) {
    Class C = objc_getClass("TXTRESTApiRequest");
    if (!C) { XLog(@"[网络] TXTRESTApiRequest 运行时不存在, 嗅探跳过"); return; }
    SEL sel = NSSelectorFromString(@"startWithSuccessBlock:failureBlock:");
    Method m = class_getInstanceMethod(C, sel);
    if (!m) { XLog(@"[网络] 无 startWithSuccessBlock:failureBlock:"); return; }
    IMP cur = method_getImplementation(m);
    if (cur == (IMP)xh_net_start) return;
    g_net_start_orig = cur;
    method_setImplementation(m, (IMP)xh_net_start);
    XLog(@"[网络] 嗅探已装 (TXTRESTApiRequest)");
}

// ============================================================
// "喜欢我的人" 页面悬浮按钮: 一键强制匹配 (extreme-picks/pick) 对接列表里每个 ID
//   数据源: g_likedMeOnly —— 只来自 PUGSeeLikesUseCase setSeeLikesUsers:
//   点一下: 串行把没对接过的人逐个走 pick 接口 (1.5s 间隔), 按钮标题显示进度
// ============================================================
static void xh_installDragGesture(UIButton *btn, NSString *posKey);   // 定义在文件后面
static CGPoint xh_loadBallPos(NSString *key);                         // 定义在文件后面

#define XH_MATCH_BTN_TAG 987651
static NSString *const kXHMatchBtnPosKey = @"xh_ball_pos_match";

static void XHSeeLikesMatchRun(UIButton *btn);


// 当前"喜欢我"列表的真实 uid (优先问 PUGSeeLikesUseCase, 而不是我们 hook 攒的并集)
static NSArray *XHSeeLikesCurrentUIDs(void) {
    NSMutableOrderedSet *set = [NSMutableOrderedSet orderedSet];
    id uc = g_seeLikesUC;
    if (!uc) {
        @try {
            Class C = objc_getClass("PUGSeeLikesUseCase");
            if (C && [C respondsToSelector:@selector(sharedInstance)]) {
                uc = ((id(*)(id, SEL))objc_msgSend)((id)C, @selector(sharedInstance));
            }
        } @catch (NSException *e) {}
    }
    if (uc && [uc respondsToSelector:@selector(seeLikesUsers)]) {
        @try {
            NSArray *arr = ((id(*)(id, SEL))objc_msgSend)(uc, @selector(seeLikesUsers));
            if ([arr isKindOfClass:[NSArray class]]) {
                static NSInteger g_cardDumpCount = 0; // v27: 只 dump 前两张卡, 防刷屏
                BOOL doDump = g_cardDumpCount < 2;
                for (id u in arr) {
                    NSString *uid = XHSeelikesUIDOf(u);
                    if (uid) {
                        [set addObject:uid];
                        if (!g_likedMeUserMap[uid]) g_likedMeUserMap[uid] = u;  // 官方超速配接口需要 PUGUser 对象
                        // v27 诊断: 打印该对象所有候选 id 字段, 核对哪个是真实账号 ID
                        @try {
                            NSMutableString *cands = [NSMutableString string];
                            for (NSString *k in @[@"publicId", @"userID", @"userId", @"objectId", @"objectID", @"id", @"modelIdentifier", @"identifier"]) {
                                if ([u respondsToSelector:NSSelectorFromString(k)]) {
                                    id v = [u valueForKey:k];
                                    if (v) [cands appendFormat:@"%@=%@ ", k, [v description]];
                                }
                            }
                            XLog(@"[划卡名单] 卡片uid=%@ 候选字段[%@]", uid, cands);
                            if (doDump) {
                                NSString *desc = [u description];
                                XLog(@"[划卡名单] 卡片%d完整dump uid=%@: %@", g_cardDumpCount, uid,
                                     (desc.length > 1600 ? [[desc substringToIndex:1600] stringByAppendingString:@"...(截断)"] : desc));
                                g_cardDumpCount++;
                            }
                        } @catch (NSException *e) {}
                    }
                }
                XLog(@"[喜欢我匹配] use case 当前列表 %lu 条 -> uid %lu 个",
                     (unsigned long)arr.count, (unsigned long)set.count);
            }
        } @catch (NSException *e) { XLog(@"[喜欢我匹配] 读 use case 列表异常 %@", e.reason); }
    }
    if (set.count == 0 && g_likedMeOnly.count > 0) {
        [set addObjectsFromArray:g_likedMeOnly.array];
        XLog(@"[喜欢我匹配] use case 没数据, 退回 hook 收集 %lu 个", (unsigned long)set.count);
    }
    return set.array;
}

// 官方超速配通道: +[PUGUltraInstantMatchNetworkInterface postUltraInstantMatchWithUser:completion:]
//   这就是探探"桃心强制匹配"真正发请求的官方实现, 全部参数由官方自己构造
static void _doNativeUltraMatch(NSString *uid, void (^done)(BOOL ok, NSString *info)) {
    id user = g_likedMeUserMap[uid];
    if (!user) { if (done) done(NO, @"缺PUGUser对象"); return; }
    Class C = objc_getClass("PUGUltraInstantMatchUseCase");
    if (!C) {
        // 7.2.1 可能类名不同 -> 运行时扫描
        unsigned int n = 0;
        Class *cs = objc_copyClassList(&n);
        for (unsigned int i = 0; i < n; i++) {
            const char *nm = class_getName(cs[i]);
            if (strstr(nm, "UltraInstantMatchUseCase") || strstr(nm, "InstantMatchUseCase")) {
                C = cs[i];
                XLog(@"[喜欢我匹配] 扫描到超速配类 %s", nm);
                break;
            }
        }
        if (cs) free(cs);
    }
    if (!C) { if (done) done(NO, @"运行时无超速配类"); return; }
    id uc = nil;
    SEL sh = NSSelectorFromString(@"shared");
    if ([C respondsToSelector:sh]) uc = ((id(*)(id, SEL))objc_msgSend)((id)C, sh);
    if (!uc) { if (done) done(NO, @"无单例实例"); return; }
    SEL sel = NSSelectorFromString(@"requestUltraInstantMatchWithUser:matchSuccessBlock:fromPurchase:");
    if (![uc respondsToSelector:sel]) { if (done) done(NO, @"无请求方法"); return; }
    XLog(@"[喜欢我匹配] 官方桃心 uid=%@ useCase=%@", uid, NSStringFromClass([uc class]));
    ((void(*)(id, SEL, id, id, BOOL))objc_msgSend)(uc, sel, user, ^(id result) {
        XLog(@"[喜欢我匹配] 官方桃心回调 uid=%@ result=%@", uid, result ?: @"(nil)");
        if (done) done(YES, @"官方回调");
    }, NO);
}

// 真实"喜欢我"列表: GET /v2/liked-users?search=list (原生网络抓包确认的官方接口)
//   返回里的才是服务端眼里真的喜欢过我们的人 (otherRelationType=LIKED)
// v23 解析器: 从接口返回里剥 uid (whoLikedMe / liked-users 两种结构都兼容)
static void XHParseLikedUsersResult(id result, NSMutableOrderedSet *uids, NSMutableArray *raw, NSString *tag) {
    @try {
        XLog(@"[真实列表] %@ 原始返回=%@", tag, ([result description].length > 1500
             ? [[result description] substringToIndex:1500] : [result description]));
        NSDictionary *d = [result isKindOfClass:[NSDictionary class]] ? (NSDictionary *)result : nil;
        id data = d[@"data"];
        if (![data isKindOfClass:[NSDictionary class]]) data = d;
        if ([data isKindOfClass:[NSDictionary class]]) {
            XLog(@"[真实列表] %@ data keys=%@", tag, ((NSDictionary *)data).allKeys);
        }
        NSArray *users = nil;
        for (NSString *k in @[@"users", @"likedUsers", @"list", @"items", @"results"]) {
            id v = [data isKindOfClass:[NSDictionary class]] ? [data valueForKey:k] : nil;
            if ([v isKindOfClass:[NSArray class]]) { users = v; break; }
        }
        // v26: relationships 数组 — 服务端对名单里每个人的关系判定, 一锤定音
        if ([data isKindOfClass:[NSDictionary class]]) {
            id relsArr = [(NSDictionary *)data objectForKey:@"relationships"];
            if ([relsArr isKindOfClass:[NSArray class]]) {
                for (id r in relsArr) {
                    if (![r isKindOfClass:[NSDictionary class]]) continue;
                    NSDictionary *rd = (NSDictionary *)r;
                    NSDictionary *ext = [rd[@"extensions"] isKindOfClass:[NSDictionary class]] ? rd[@"extensions"] : nil;
                    XLog(@"[真实列表] ◆关系判定 id=%@ relationType=%@ other=%@ state=%@",
                         [rd[@"id"] description],
                         [ext[@"relationType"] description] ?: @"-",
                         [ext[@"otherRelationType"] description] ?: @"-",
                         [rd[@"state"] description] ?: @"-");
                }
            }
        }
        // v24: likedUsers 数组优先 — 每条 {id, status, otherStatus}, status=liked 才是真喜欢你的人
        if ([data isKindOfClass:[NSDictionary class]]) {
            id likedArr = [(NSDictionary *)data objectForKey:@"likedUsers"];
            if ([likedArr isKindOfClass:[NSArray class]]) {
                for (id lu in likedArr) {
                    if (![lu isKindOfClass:[NSDictionary class]]) continue;
                    NSDictionary *ld = (NSDictionary *)lu;
                    id v = ld[@"id"];
                    if (!v) continue;
                    NSString *s = [v description];
                    if (s.length) {
                        [uids addObject:s];
                        [raw addObject:lu];
                        XLog(@"[真实列表] likedUser条目 id=%@ status=%@ otherStatus=%@", s,
                             [ld[@"status"] description], [ld[@"otherStatus"] description]);
                    }
                }
                XLog(@"[真实列表] likedUsers 共 %lu 条(语义=我喜欢的人,对方未回应不计算)", (unsigned long)[(NSArray *)likedArr count]);
            }
        }
        if (users) {
            for (id u in users) {
                [raw addObject:u];
                // 元素可能是 {user:{...}, relationship:{...}} 包裹, XHSeelikesUIDOf 能剥壳
                NSString *uid = XHSeelikesUIDOf(u);
                if (uid) [uids addObject:uid];
            }
        }
    } @catch (NSException *e) { XLog(@"[真实列表] 解析异常 %@", e.reason); }
}

// 真实"喜欢我"列表: v23 改用 app 抓包确认的官方接口 search=whoLikedMe (喜欢我页面的数据源)
//   旧接口 /v2/liked-users?search=list 非 VIP 永远返回空, 作为回退保留
// v26: 划卡堆筛真 liker — 实证 655325004(真likers)不在 whoLikedMe 名单里, 而在划卡堆中
//   GET /v2/users?search=suggested&with=relationships → 每人 relationship.otherRelationType==LIKED 即真喜欢你
static void XHFetchEncounterLikers(NSMutableOrderedSet *uids, NSMutableArray *raw) {
    NSString *deckUrl = @"https://core.tantanapp.com/v2/users?is_encourage_user=false&search=suggested&with=user.publicMoments%2Cquestions%2Ccontacts%2Crelationships%2Cmoments%2Cfollowships";
    _sendRESTRequestWB(deckUrl, @"GET", nil, NO, ^(id result) {
        @try {
            NSDictionary *d = [result isKindOfClass:[NSDictionary class]] ? (NSDictionary *)result : nil;
            id data = d[@"data"] ?: d;
            NSArray *users = nil;
            if ([data isKindOfClass:[NSDictionary class]]) {
                id v = [(NSDictionary *)data objectForKey:@"users"];
                if ([v isKindOfClass:[NSArray class]]) users = v;
            } else if ([data isKindOfClass:[NSArray class]]) {
                users = (NSArray *)data;
            }
            XLog(@"[划卡名单] 共 %lu 张卡, 逐个查关系标记:", (unsigned long)users.count);
            NSInteger dumpIdx = 0;
            for (id u in users) {
                if (![u isKindOfClass:[NSDictionary class]]) continue;
                NSDictionary *ud = (NSDictionary *)u;
                // v27: 前3张卡完整 dump, 看真实账号 ID 藏在哪个字段
                if (dumpIdx < 3) {
                    NSString *desc = [ud description];
                    XLog(@"[划卡名单] deck卡%d完整dump: %@", dumpIdx,
                         (desc.length > 1600 ? [[desc substringToIndex:1600] stringByAppendingString:@"...(截断)"] : desc));
                    dumpIdx++;
                }
                NSString *uid = XHSeelikesUIDOf(ud);
                if (!uid.length) continue;
                // relationship 可能是单对象或数组, extensions 里找 otherRelationType
                NSString *ort = nil, *rt = nil;
                id rel = ud[@"relationship"] ?: ud[@"relations"];
                if ([rel isKindOfClass:[NSDictionary class]]) {
                    id ext = rel[@"extensions"];
                    if ([ext isKindOfClass:[NSDictionary class]]) {
                        ort = [ext[@"otherRelationType"] description];
                        rt = [ext[@"relationType"] description];
                    }
                } else if ([rel isKindOfClass:[NSArray class]]) {
                    for (id r in (NSArray *)rel) {
                        if (![r isKindOfClass:[NSDictionary class]]) continue;
                        id ext = ((NSDictionary *)r)[@"extensions"];
                        if ([ext isKindOfClass:[NSDictionary class]]) {
                            ort = [ext[@"otherRelationType"] description] ?: ort;
                            rt = [ext[@"relationType"] description] ?: rt;
                        }
                    }
                }
                if (!ort.length && !rt.length) {
                    // 兜底: 直接在 user 字典里搜 otherRelationType (结构未知, 深挖一层)
                    id ext = ud[@"extensions"];
                    if ([ext isKindOfClass:[NSDictionary class]]) {
                        ort = [ext[@"otherRelationType"] description];
                        rt = [ext[@"relationType"] description];
                    }
                }
                BOOL realLiker = [ort.uppercaseString containsString:@"LIKED"];
                XLog(@"[划卡名单] uid=%@ relationType=%@ other=%@ %@",
                     uid, rt ?: @"-", ort ?: @"-", realLiker ? @"★真LIKER" : @"");
                if (realLiker) {
                    [uids addObject:uid];
                    [raw addObject:u];
                }
            }
        } @catch (NSException *e) { XLog(@"[划卡名单] 解析异常 %@", e.reason); }
    }, ^(id e) {
        XLog(@"[划卡名单] 请求失败 %@", XHDumpResp(e));
    });
}

static void XHFetchRealLikedUsers(void (^done)(NSArray *uids, NSArray *rawUsers)) {
    NSMutableOrderedSet *uids = [NSMutableOrderedSet orderedSet];
    NSMutableArray *raw = [NSMutableArray array];
    void (^finish)(void) = ^{
        XLog(@"[真实列表] 共 %lu 人 uids=%@", (unsigned long)uids.count, uids.array);
        done(uids.array, raw);
    };
    // v26 第一优先: 划卡堆筛真 liker
    XHFetchEncounterLikers(uids, raw);
    // v25: 与 app 抓包参数完全一致 (缺 verified=true 时服务端返回空!)
    NSString *whoUrl = @"https://core.tantanapp.com/v2/users?with=relationships%2Cuser.publicMoments&search=whoLikedMe&verified=true&limit=30";
    // liked-users?search=list 语义更正: 这是"我喜欢的人"(PUGILikedUser), 不是"喜欢我的人"
    NSString *oldUrl = @"https://core.tantanapp.com/v2/liked-users?sortBy=latestLike&search=list&filter=all&distance=100000&age=18%2C50&limit=30&cursorIdx=1";
    void (^tryOld)(void) = ^{
        _sendRESTRequestWB(oldUrl, @"GET", nil, NO, ^(id result) {
            XHParseLikedUsersResult(result, uids, raw, @"liked-users回退");
            finish();
        }, ^(id e) {
            XLog(@"[真实列表] liked-users回退失败 %@", XHDumpResp(e));
            finish();
        });
    };
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        // 划卡堆筛出的真 liker 直接用, 不再叠加填充名单
        if (uids.count > 0) { finish(); return; }
        _sendRESTRequestWB(whoUrl, @"GET", nil, NO, ^(id result) {
            XHParseLikedUsersResult(result, uids, raw, @"whoLikedMe");
            if (uids.count > 0) { finish(); return; }
            XLog(@"[真实列表] whoLikedMe 为空, 回退旧接口");
            tryOld();
        }, ^(id e) {
            XLog(@"[真实列表] whoLikedMe 请求失败 %@, 回退旧接口", XHDumpResp(e));
            tryOld();
        });
    });
}

// 串行对接状态(静态变量; 每步靠 done 回调推进, 8 秒超时兜底)
static NSArray  *g_matchTodo = nil;
static NSInteger g_matchIdx = 0;
static NSInteger g_matchOk = 0;
static NSInteger g_matchFail = 0;
static NSInteger g_stepToken = 0;
static __weak UIButton *g_matchBtnW = nil;

// v23: 动态点赞通道 — 抓包确认的首页约会流真实接口, 不走 relationships 的配额 privilege check
//   1) GET /v2/users/{uid}/moments?search=profile&scene=profile&...limit=5 取最新动态
//   2) PUT /v2/users/{uid}/moments/{mid}/likes/me  body={"attitudeId":0,"source":"p_discover_dating"}
static void XHLikeMomentOfUID(NSString *uid) {
    if (!uid.length) return;
    NSString *murl = [NSString stringWithFormat:
        @"https://core.tantanapp.com/v2/users/%@/moments?search=profile&scene=profile&with=users%%2Cmessages%%2Crelationships%%2Cfollowships%%2Cmusics%%2Clives%%2CmomentTopics&limit=5", uid];
    _sendRESTRequestWB(murl, @"GET", nil, NO, ^(id result) {
        NSString *mid = nil;
        @try {
            NSDictionary *d = [result isKindOfClass:[NSDictionary class]] ? (NSDictionary *)result : nil;
            id data = d[@"data"] ?: d;
            NSArray *list = nil;
            if ([data isKindOfClass:[NSArray class]]) {
                list = (NSArray *)data;
            } else if ([data isKindOfClass:[NSDictionary class]]) {
                for (NSString *k in @[@"moments", @"list", @"items"]) {
                    id v = [(NSDictionary *)data objectForKey:k];
                    if ([v isKindOfClass:[NSArray class]]) { list = v; break; }
                }
            }
            for (id m in list) {
                if (![m isKindOfClass:[NSDictionary class]]) continue;
                NSDictionary *md = (NSDictionary *)m;
                id midv = md[@"momentID"] ?: md[@"momentId"] ?: md[@"id"];
                if (midv) { mid = [midv description]; break; }
            }
        } @catch (NSException *e) { XLog(@"[动态赞] 解析异常 %@", e.reason); }
        if (!mid.length) { XLog(@"[动态赞] uid=%@ 没取到动态ID, 跳过", uid); return; }
        NSString *purl = [NSString stringWithFormat:@"https://core.tantanapp.com/v2/users/%@/moments/%@/likes/me", uid, mid];
        NSDictionary *body = @{@"attitudeId": @0, @"source": @"p_discover_dating"};
        XLog(@"[动态赞] PUT %@ body=%@", purl, body);
        _sendRESTRequestWB(purl, @"PUT", body, NO, ^(id r2) {
            XLog(@"[动态赞] ★ uid=%@ moment=%@ 返回=%@", uid, mid,
                 ([r2 description].length > 800 ? [[r2 description] substringToIndex:800] : [r2 description]));
        }, ^(id e2) {
            XLog(@"[动态赞] ✘ uid=%@ moment=%@ 失败=%@", uid, mid, XHDumpResp(e2));
        });
    }, ^(id e) {
        XLog(@"[动态赞] 取动态失败 uid=%@ %@", uid, XHDumpResp(e));
    });
}

static void XHSeeLikesMatchStep(void);

static void XHSeeLikesMatchStep(void) {
    UIButton *btn = g_matchBtnW;
    if (!btn) { XLog(@"[喜欢我匹配] 按钮已释放, 停止对接"); g_matchTodo = nil; return; }
    if (!g_matchTodo || g_matchIdx >= g_matchTodo.count) {
        [btn setTitle:[NSString stringWithFormat:@"匹配%ld\n失败%ld", (long)g_matchOk, (long)g_matchFail]
             forState:UIControlStateNormal];
        XLog(@"[喜欢我匹配] 全部结束: 成功 %ld 失败 %ld / 共 %lu",
             (long)g_matchOk, (long)g_matchFail, (unsigned long)(g_matchTodo ? g_matchTodo.count : 0));
        g_matchTodo = nil;
        return;
    }
    NSString *uid = g_matchTodo[g_matchIdx];
    g_matchIdx++;
    NSUInteger total = g_matchTodo.count;
    [btn setTitle:[NSString stringWithFormat:@"匹配中\n%ld/%lu", (long)g_matchIdx, (unsigned long)total]
         forState:UIControlStateNormal];
    XLog(@"[喜欢我匹配] 开始 %ld/%lu uid=%@", (long)g_matchIdx, (unsigned long)total, uid);

    NSInteger myToken = ++g_stepToken;
    __block BOOL advanced = NO;
    void (^advance)(void) = ^{
        if (advanced) return;
        advanced = YES;
        if (myToken != g_stepToken) return;
        g_stepToken++;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ XHSeeLikesMatchStep(); });
    };
    @try {
        _doNativeUltraMatch(uid, ^(BOOL ok, NSString *info) {
            if (ok) {
                g_matchOk++;
                [g_likedMeMatched addObject:uid];
                XHSeelikesPersist();
                advance();
                return;
            }
            XLog(@"[喜欢我匹配] 官方通道不可用(%@), 走手动验证过的流程: PUT relationships + 动态赞 + pick", info);
            _doLikeRelationshipWithUID(uid, ^(BOOL matched, NSString *detail) {
                XLog(@"[喜欢我匹配] PUT 完成 uid=%@ matched=%@ (%@), 继续发动态赞+pick", uid, matched ? @"YES" : @"NO", detail);
                if (matched) {
                    g_matchOk++;
                    [g_likedMeMatched addObject:uid];
                    XHSeelikesPersist();
                } else {
                    // v23: PUT 被配额挡 -> 先走动态点赞通道 (约会流接口, 不吃配额)
                    XHLikeMomentOfUID(uid);
                }
                // 官方强制匹配的完整三步: PUT -> GET question -> POST pick, pick 才是配对判定
                _doUltraMatchWithUID(uid);
                // v21: PUT 没配上就老实计失败, 别再 +0 糊弄计数
                if (!matched) g_matchFail++;
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.2 * NSEC_PER_SEC)),
                               dispatch_get_main_queue(), ^{ advance(); });
            });
        });
    } @catch (NSException *e) {
        XLog(@"[喜欢我匹配] 异常 %@", e.reason);
        g_matchFail++;
        advance();
    }
    // 兜底: 8 秒内没回调也要往下走, 不能卡死
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(8.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ advance(); });
}

__attribute__((unused)) static BOOL g_diagRan = YES; // v11 诊断已确认: PUT relationships 用原生头(WebBridge=NO)即过风控, 不再重复诊断
static void XHDiagRun(NSString *uid, void (^done)(void));


// v31 还原: 老的"喜欢我匹配"流程保留(不再由按钮触发)
__attribute__((unused)) static void XHSeeLikesMatchRun(UIButton *btn) {
    XHSeelikesInit();
    if (g_matchTodo) { XLog(@"[喜欢我匹配] 上一轮还在跑, 忽略重复点击"); return; }
    [btn setTitle:@"查列表" forState:UIControlStateNormal];
    XHFetchRealLikedUsers(^(NSArray *uids, NSArray *rawUsers) {
        // v26: 页面 hook 收集的 uid 是用户亲眼看到的卡片, 优先级最高;
        //      whoLikedMe 接口名单已被实证掺假(手动匹配的 655325004 与点开的 491538431/543832470 都不在其中)
        NSArray *hookUids = XHSeeLikesCurrentUIDs();
        XLog(@"[喜欢我匹配] hook页面卡片 %lu 个: %@", (unsigned long)hookUids.count, hookUids);
        XLog(@"[喜欢我匹配] 接口名单 %lu 个: %@", (unsigned long)uids.count, uids);
        NSMutableOrderedSet *merged = [NSMutableOrderedSet orderedSet];
        [merged addObjectsFromArray:hookUids];        // 页面显示的优先
        for (NSString *u in uids) {                   // 接口名单仍附在后面试
            if (![hookUids containsObject:u]) [merged addObject:u];
        }
        NSArray *all = merged.array;
        XLog(@"[喜欢我匹配] 合并待测名单 %lu 人: %@", (unsigned long)all.count, all);
        // 顺便把真实列表的人的 PUGUser 存进 map, 给后续用
        for (id u in rawUsers) {
            NSString *uid = XHSeelikesUIDOf(u);
            if (uid && !g_likedMeUserMap[uid]) {
                id real = u;
                @try { id w = [u valueForKey:@"user"]; if (w && w != u) real = w; } @catch (NSException *e) {}
                g_likedMeUserMap[uid] = real;
            }
        }
        // 服务端关系真相: 我方账号 with=relationships, 看目标 uid 到底是 LIKED 还是 MATCHED
        _sendRESTRequestWB(@"https://core.tantanapp.com/v2/users/me?with=relationships", @"GET", nil, NO,
            ^(id r) {
                @try {
                    NSDictionary *d = [r isKindOfClass:[NSDictionary class]] ? (NSDictionary *)r : nil;
                    id data = d[@"data"] ?: d;
                    NSArray *rels = [data valueForKey:@"relationships"];
                    if (![rels isKindOfClass:[NSArray class]]) {
                        XLog(@"[关系真相] 无 relationships, keys=%@", [data isKindOfClass:[NSDictionary class]] ? ((NSDictionary *)data).allKeys : @"(非字典)");
                        return;
                    }
                    NSMutableString *sum = [NSMutableString stringWithFormat:@"[关系真相] 共 %lu 条(最多列60):\n", (unsigned long)rels.count];
                    NSInteger _n = 0;
                    for (id r2 in rels) {
                        if (_n++ >= 60) { [sum appendString:@"  ...(截断)\n"]; break; }
                        if (![r2 isKindOfClass:[NSDictionary class]]) continue;
                        NSDictionary *rd = (NSDictionary *)r2;
                        id ext = rd[@"extensions"];
                        NSString *rt = @"-", *ort = @"-";
                        if ([ext isKindOfClass:[NSDictionary class]]) {
                            id v1 = ext[@"relationType"];   if (v1) rt = [v1 description];
                            id v2 = ext[@"otherRelationType"]; if (v2) ort = [v2 description];
                        }
                        [sum appendFormat:@"  uid=%@ relationType=%@ other=%@ state=%@\n",
                         rd[@"id"], rt, ort, rd[@"state"]];
                    }
                    XLog(@"%@", sum);
                } @catch (NSException *e) { XLog(@"[关系真相] 解析异常 %@", e.reason); }
            },
            ^(id e) { XLog(@"[关系真相] 查询失败 %@", XHDumpResp(e)); });

        dispatch_async(dispatch_get_main_queue(), ^{
            NSMutableArray *todo = [NSMutableArray array];
            for (NSString *uid in all) {
                if ([g_likedMeMatched containsObject:uid]) continue;
                [todo addObject:uid];
            }
            XLog(@"[喜欢我匹配] 点击: 真实列表 %lu 人, 待对接 %lu 人", (unsigned long)all.count, (unsigned long)todo.count);
            if (todo.count == 0) { [btn setTitle:@"已全部\n对接" forState:UIControlStateNormal]; return; }
            g_matchTodo = [todo copy];
            g_matchIdx = 0;
            g_matchOk = 0;
            g_matchFail = 0;
            g_matchBtnW = btn;
            XHSeeLikesMatchStep();
        });
    });
}




// ---- viewWillAppear: hook ----
static NSMutableDictionary *g_matchvc_orig = nil;
static void xh_matchVC_appear(id self, SEL _cmd, BOOL animated) {
    IMP o = NULL;
    if (g_matchvc_orig) {
        NSValue *v = g_matchvc_orig[[NSString stringWithFormat:@"%s|viewWillAppear:", class_getName([self class])]];
        if (v) o = (IMP)[v pointerValue];
    }
    if (o && o != (IMP)xh_matchVC_appear) ((void(*)(id, SEL, BOOL))o)(self, _cmd, animated);
}

static void XHInstallSeeLikesMatchUI(void) {
    NSArray *names = @[@"PUGSeeLikesViewController",
                       @"PUGLikedUsersViewController",
                       @"PUGIntlLikedUsersViewController",
                       @"PUGSeeLikesWithoutPrivilegeViewController",
                       @"PUGMembershipZoneWhoLikeMeController"];
    for (NSString *n in names) {
        Class c = objc_getClass(n.UTF8String);
        if (!c) { XLog(@"[喜欢我匹配] 运行时无类 %@", n); continue; }
        SEL sel = @selector(viewWillAppear:);
        Method m = class_getInstanceMethod(c, sel);
        if (!m) { XLog(@"[喜欢我匹配] %@ 无 viewWillAppear:", n); continue; }
        IMP cur = method_getImplementation(m);
        if (cur == (IMP)xh_matchVC_appear) continue;
        if (!g_matchvc_orig) g_matchvc_orig = [NSMutableDictionary dictionary];
        NSString *k = [NSString stringWithFormat:@"%s|viewWillAppear:", class_getName(c)];
        if (g_matchvc_orig[k]) continue;
        g_matchvc_orig[k] = [NSValue valueWithPointer:cur];
        // 优先给本类加自己的实现, 避免改动共享的父类实现
        BOOL added = class_addMethod(c, sel, (IMP)xh_matchVC_appear, method_getTypeEncoding(m));
        if (!added) method_setImplementation(m, (IMP)xh_matchVC_appear);
        XLog(@"[喜欢我匹配] hook %@ viewWillAppear: (%@)", n, added ? @"addMethod" : @"setIMP");
    }
}

// ============================================================
// 收集 hook v2: 运行时扫类 + 多路 setter 收集
//   老做法直接 objc_getClass(@"PUGMyEncounterSeeLikesAllUserUseCase") 拿到 nil,
//   因为该符号只在 __objc_classrefs 里(定义在别的模块)。
//   现在用 objc_getClassList 扫全部已注册类, 命中关键字就挂白名单 setter,
//   命中一次就打一行日志, 方便直接看出数据实际流经哪个方法。
// ============================================================
static NSMutableDictionary *g_sl_orig = nil;   // "Class|sel" / "*|sel" -> NSValue(IMP)
static NSMutableSet        *g_sl_hit  = nil;   // 已打过日志的 key

static NSValue *_sl_orig_for(id self, SEL _cmd) {
    if (!g_sl_orig) return nil;
    NSString *k1 = [NSString stringWithFormat:@"%s|%s",
                    class_getName(object_getClass(self)), sel_getName(_cmd)];
    NSValue *v = g_sl_orig[k1];
    if (!v) v = g_sl_orig[[NSString stringWithFormat:@"*|%s", sel_getName(_cmd)]];
    return v;
}

// 从任意参数里挖 user/uid: 数组、集合、单个 model 都吃
static void _sl_set_sel(SEL s) { g_sl_cur_sel = s ? NSStringFromSelector(s) : nil; }

static void _sl_collect_arg(id a1) {
    if (!a1) return;
    @try {
        if ([a1 isKindOfClass:[NSArray class]]) { XHSeelikesCollect((NSArray *)a1); return; }
        if ([a1 isKindOfClass:[NSSet class]]) { XHSeelikesCollect([(NSSet *)a1 allObjects]); return; }
        if (XHSeelikesUIDOf(a1)) XHSeelikesCollect(@[a1]);
    } @catch (NSException *e) {}
}

static void _sl_note_hit(id self, SEL _cmd, NSInteger n) {
    if (_cmd && strcmp(sel_getName(_cmd), "setSeeLikesUsers:") == 0) g_seeLikesUC = self;
    NSString *k = [NSString stringWithFormat:@"%s|%s",
                   class_getName(object_getClass(self)), sel_getName(_cmd)];
    if (!g_sl_hit) g_sl_hit = [NSMutableSet set];
    if ([g_sl_hit containsObject:k]) return;
    [g_sl_hit addObject:k];
    XLog(@"[喜欢我→划卡] 命中 %@ (本批 %ld 条)", k, (long)n);
}

// 把真 PUGUser 补进 map (UI 渲染列表时按 uid 补全)
static void _sl_note_user(id u) {
    Class PU = NSClassFromString(@"PUGUser");
    if (!PU || !u || ![u isKindOfClass:PU]) return;
    NSString *uid = XHSeelikesUIDOf(u);
    if (!uid) return;
    XHSeelikesInit();
    @synchronized (g_likedMeUIDs) {
        if (g_likedMeUserMap[uid]) return;
        g_likedMeUserMap[uid] = u;
        if (![g_likedMeUIDs containsObject:uid]) [g_likedMeUIDs addObject:uid];
    }
    XHSeelikesPersist();
    XLog(@"[喜欢我→划卡] 补到 PUGUser uid=%@ (共 %lu)", uid, (unsigned long)g_likedMeUserMap.count);
}

// void (id) hook
static void _sl_hook_v1(id self, SEL _cmd, id a1) {
    NSValue *v = _sl_orig_for(self, _cmd);
    if (v) ((void(*)(id, SEL, id))[v pointerValue])(self, _cmd, a1);
    @try {
        _sl_set_sel(_cmd);
        _sl_collect_arg(a1);
        _sl_note_hit(self, _cmd, [a1 isKindOfClass:[NSArray class]] ? (NSInteger)[a1 count] : 1);
    } @catch (NSException *e) {}
}

// id (id, BOOL) hook —— configILikeWhoModelArrayWith:isNextPage:
static id _sl_hook_r2(id self, SEL _cmd, id a1, BOOL b1) {
    NSValue *v = _sl_orig_for(self, _cmd);
    id r = v ? ((id(*)(id, SEL, id, BOOL))[v pointerValue])(self, _cmd, a1, b1) : nil;
    @try {
        _sl_set_sel(_cmd);
        _sl_collect_arg(r);
        _sl_collect_arg(a1);
        _sl_note_hit(self, _cmd, [r isKindOfClass:[NSArray class]] ? (NSInteger)[r count] : 1);
    } @catch (NSException *e) {}
    return r;
}

// id (id, BOOL, long long) hook —— initWithILikedUserUser:isNextPage:index:
static id _sl_hook_r3(id self, SEL _cmd, id a1, BOOL b1, long long c1) {
    NSValue *v = _sl_orig_for(self, _cmd);
    id r = v ? ((id(*)(id, SEL, id, BOOL, long long))[v pointerValue])(self, _cmd, a1, b1, c1) : nil;
    @try {
        _sl_set_sel(_cmd); _sl_collect_arg(r); _sl_collect_arg(a1); _sl_note_hit(self, _cmd, 1); }
    @catch (NSException *e) {}
    return r;
}

// id (id) hook —— seeLikesListCommonTagWithUser: / sameHobbyArrayWithUser:
static id _sl_hook_r1(id self, SEL _cmd, id a1) {
    NSValue *v = _sl_orig_for(self, _cmd);
    id r = v ? ((id(*)(id, SEL, id))[v pointerValue])(self, _cmd, a1) : nil;
    @try { _sl_note_user(a1); } @catch (NSException *e) {}
    return r;
}

// unsigned long long (id) hook —— userImageIndexForUser:
static unsigned long long _sl_hook_q1(id self, SEL _cmd, id a1) {
    NSValue *v = _sl_orig_for(self, _cmd);
    unsigned long long r = v ? ((unsigned long long(*)(id, SEL, id))[v pointerValue])(self, _cmd, a1) : 0;
    @try { _sl_note_user(a1); } @catch (NSException *e) {}
    return r;
}

static void _sl_install(Class cls, NSString *selName, IMP imp, BOOL isClassMethod) {
    if (!cls || selName.length == 0) return;
    SEL sel = NSSelectorFromString(selName);
    Method m = isClassMethod ? class_getClassMethod(cls, sel) : class_getInstanceMethod(cls, sel);
    if (!m) return;
    IMP cur = method_getImplementation(m);
    if (!cur || cur == imp) return;
    // 已被自己挂过(继承链上重复) -> 跳过, 否则 orig 会指向钩子自身形成自递归
    if (cur == (IMP)_sl_hook_v1 || cur == (IMP)_sl_hook_r1 || cur == (IMP)_sl_hook_r2 ||
        cur == (IMP)_sl_hook_r3 || cur == (IMP)_sl_hook_q1) return;
    if (!g_sl_orig) g_sl_orig = [NSMutableDictionary dictionary];
    NSString *k1 = [NSString stringWithFormat:@"%s|%s", class_getName(cls), selName.UTF8String];
    NSString *k2 = [NSString stringWithFormat:@"*|%s", selName.UTF8String];
    g_sl_orig[k1] = [NSValue valueWithPointer:cur];
    if (!g_sl_orig[k2]) g_sl_orig[k2] = [NSValue valueWithPointer:cur];
    method_setImplementation(m, imp);
    XLog(@"[喜欢我→划卡] hook %@%@ %@", isClassMethod ? @"+" : @"-",
         [NSString stringWithUTF8String:class_getName(cls)], selName);
}

static void XHInstallSeelikesHooks(void) {
    XHSeelikesInit();
    int n = objc_getClassList(NULL, 0);
    if (n <= 0) { XLog(@"[喜欢我→划卡] 类列表为空"); return; }
    Class *buf = (Class *)malloc(sizeof(Class) * (size_t)n);
    if (!buf) return;
    n = objc_getClassList(buf, n);
    NSArray *keywords = @[@"SeeLike", @"LikedUser", @"SeeWhoLiked", @"MyEncounter", @"LikeMe"];
    NSMutableArray *matched = [NSMutableArray array];
    for (int i = 0; i < n; i++) {
        const char *cn = class_getName(buf[i]);
        if (!cn) continue;
        NSString *s = [NSString stringWithUTF8String:cn];
        if (!s) continue;
        for (NSString *kw in keywords) {
            if ([s containsString:kw]) { [matched addObject:s]; break; }
        }
    }
    free(buf);
    XLog(@"[喜欢我→划卡] 扫到候选类 %lu 个: %@",
         (unsigned long)matched.count, [matched componentsJoinedByString:@","]);

    NSArray *selV = @[@"setSeeLikesUsers:", @"setDataSource:", @"setModels:", @"setUsers:",
                      @"setLikedUsers:", @"setDataArray:", @"setSeeLikeUsers:", @"setItemModels:",
                      @"setAllUsers:", @"setLikeUsers:", @"setUserModels:", @"setSeeLikesModels:",
                      @"setLikedUserModels:", @"setMomentUserModels:", @"setCellModels:",
                      @"handleRefreshDataSuccess:", @"handleLoadMoreDataSuccess:", @"handleDataSuccess:"];
    for (NSString *cn in matched) {
        Class cls = objc_getClass(cn.UTF8String);
        if (!cls) continue;
        for (NSString *sn in selV) _sl_install(cls, sn, (IMP)_sl_hook_v1, NO);
        _sl_install(cls, @"configILikeWhoModelArrayWith:isNextPage:", (IMP)_sl_hook_r2, YES);
        _sl_install(cls, @"initWithILikedUserUser:isNextPage:index:", (IMP)_sl_hook_r3, NO);
        // 参数直接是真 PUGUser 的方法, 用来补全 map
        _sl_install(cls, @"seeLikesListCommonTagWithUser:", (IMP)_sl_hook_r1, NO);
        _sl_install(cls, @"sameHobbyArrayWithUser:", (IMP)_sl_hook_r1, NO);
        _sl_install(cls, @"userImageIndexForUser:", (IMP)_sl_hook_q1, NO);
    }
    // 恢复上次收集的 uid(重启后依然在)
    XLog(@"[喜欢我→划卡] 已恢复历史 uid %lu 个, 已对接 %lu 个",
         (unsigned long)g_likedMeUIDs.count, (unsigned long)g_likedMeMatched.count);
}

// 供面板调用
void XHSeelikesSetEnabled(BOOL on);
void XHSeelikesSetEnabled(BOOL on) {
    XHSetSwitch(XH_SW_SEELIKES_SWIPE, on);
    XHSeelikesInit();
    XLog(@"[喜欢我→划卡] 开关=%@ (收集 %lu / 已插 %lu / 已对接 %lu)",
         on ? @"开" : @"关",
         (unsigned long)g_likedMeUIDs.count,
         (unsigned long)g_likedMeInjected.count,
         (unsigned long)g_likedMeMatched.count);
    if (on) {
        g_likedMeAutoInjected = NO;
        XHSeelikesInjectToSwipe();
        XHSeelikesStartBatchMatch();
    } else {
        XHSeelikesRemoveFromSwipe();
    }
}

NSString *XHSeelikesSummary(void);
NSString *XHSeelikesSummary(void) {
    XHSeelikesInit();
    return [NSString stringWithFormat:@"收集 %lu · 已插卡 %lu · 已对接 %lu",
            (unsigned long)g_likedMeUIDs.count,
            (unsigned long)g_likedMeInjected.count,
            (unsigned long)g_likedMeMatched.count];
}

// 手动: 重新插卡(面板按钮用)
void XHSeelikesManualInject(void);
void XHSeelikesManualInject(void) {
    g_likedMeAutoInjected = NO;
    XHSeelikesInjectToSwipe();
    XHSeelikesStartBatchMatch();
}

// ============================================================
// 自动四选一匹配: 直接调探探网络层发 /v2/extreme-picks/ 请求
// ============================================================
// 四选一(极限四选一/one-out-of-four) 完整接口(抓包确认):
//   1. GET /v2/extreme-picks/question  -> 拿 questionID + 4个候选 allIds
//   2. POST /v2/extreme-picks/pick     -> 选人匹配
//      body: {"pickIndex":"1","questionID":"13","pickedID":"xxx","allIds":[...],"type":"normal"}
// 关键: 用 TXTNetwork 的 TXTRESTApiRequest 发请求, MAC签名/登录态自动带
// ============================================================

// 记录上一次拿到的 question 数据(questionID + allIds)
static NSMutableDictionary *_extremeQuestionCache = nil;

// 从 TXTResponse 或 NSDictionary 提取真正的响应字典
static id _unwrapResponse(id result) {
    if (!result) return nil;
    // 如果是 TXTResponse, 取 responseObject
    if ([result respondsToSelector:@selector(responseObject)]) {
        id obj = ((id(*)(id, SEL))objc_msgSend)(result, @selector(responseObject));
        if (obj) return obj;
    }
    // 如果本身就是字典/数组, 直接返回
    return result;
}

// 发一个 REST 请求(复用探探网络层, 自动带签名)
static void _sendRESTRequest(NSString *url, NSString *method, NSDictionary *body,
                             void (^success)(id result), void (^failure)(NSError *err)) {
    Class reqCls = objc_getClass("TXTRESTApiRequest");
    if (!reqCls) {
        XLog(@"[自动四选一] TXTRESTApiRequest 类不存在");
        return;
    }
    id req = [[reqCls alloc] init];
    if (!req) {
        XLog(@"[自动四选一] 创建请求失败");
        return;
    }
    @try {
        // 设置 URL
        if ([req respondsToSelector:@selector(setUrlString:)]) {
            ((void(*)(id, SEL, id))objc_msgSend)(req, @selector(setUrlString:), url);
        }
        // 设置 HTTP 方法
        if ([req respondsToSelector:@selector(setHttpMethod:)]) {
            ((void(*)(id, SEL, id))objc_msgSend)(req, @selector(setHttpMethod:), method);
        }
        // 关键: 标记为 WebBridge 请求(对齐 H5 发 pick 的方式), 避免响应处理崩溃
        if ([req respondsToSelector:@selector(setIsWebBridge:)]) {
            ((void(*)(id, SEL, BOOL))objc_msgSend)(req, @selector(setIsWebBridge:), YES);
        }
        // 设置 body (POST 时): 优先用 setParamsDictionary (自动序列化), 其次 setBody
        if (body) {
            if ([req respondsToSelector:@selector(setParamsDictionary:)]) {
                ((void(*)(id, SEL, id))objc_msgSend)(req, @selector(setParamsDictionary:), body);
            } else if ([req respondsToSelector:@selector(setBody:)]) {
                ((void(*)(id, SEL, id))objc_msgSend)(req, @selector(setBody:), body);
            }
        }
        // 发送: 优先用 startWithSuccessBlock:failureBlock:
        SEL startSel = NSSelectorFromString(@"startWithSuccessBlock:failureBlock:");
        if ([req respondsToSelector:startSel]) {
            // success block: (id result), failure block: (NSError *err)
            ((void(*)(id, SEL, id, id))objc_msgSend)(req, startSel,
                ^(id result) {
                    id realData = _unwrapResponse(result);
                    // 打印原始 result 的完整信息(定位 question 返回空的根因)
                    XLog(@"[自动四选一] 请求成功 url=%@ result类=%@ data=%@", url, result ? NSStringFromClass([result class]) : @"(nil)", realData);
                    if ([url containsString:@"question"]) {
                        // question 特殊诊断: 打印 result 的所有字段
                        XLog(@"[自动四选一] question result 原始=%@", result ?: @"(nil)");
                        if ([result respondsToSelector:@selector(responseObject)]) {
                            id ro = ((id(*)(id, SEL))objc_msgSend)(result, @selector(responseObject));
                            XLog(@"[自动四选一] question responseObject=%@ 类=%@", ro ?: @"(nil)", ro ? NSStringFromClass([ro class]) : @"(nil)");
                        }
                        if ([result respondsToSelector:@selector(responseString)]) {
                            id rs = ((id(*)(id, SEL))objc_msgSend)(result, @selector(responseString));
                            XLog(@"[自动四选一] question responseString=%@", rs ?: @"(nil)");
                        }
                        if ([result respondsToSelector:@selector(responseData)]) {
                            id rd = ((id(*)(id, SEL))objc_msgSend)(result, @selector(responseData));
                            if ([rd isKindOfClass:[NSData class]]) {
                                NSString *s = [[NSString alloc] initWithData:rd encoding:NSUTF8StringEncoding];
                                XLog(@"[自动四选一] question responseData utf8=%@", s ?: @"(解码失败)");
                            } else {
                                XLog(@"[自动四选一] question responseData=%@ 类=%@", rd ?: @"(nil)", rd ? NSStringFromClass([rd class]) : @"(nil)");
                            }
                        }
                    }
                    if (success) success(realData);
                },
                ^(NSError *err) {
                    XLog(@"[自动四选一] 请求失败 url=%@ err=%@", url, err);
                    if (failure) failure(err);
                });
        } else {
            XLog(@"[自动四选一] 无 startWithSuccessBlock:failureBlock: 方法");
        }
    } @catch (NSException *e) {
        XLog(@"[自动四选一] 发送异常: %@", e);
    }
}

// 同 _sendRESTRequest, 但能指定是否走 WebBridge 头 (风控可能与它有关)
static void _sendRESTRequestWB(NSString *url, NSString *method, NSDictionary *body, BOOL webBridge,
                               void (^success)(id result), void (^failure)(id err)) {
    Class reqCls = objc_getClass("TXTRESTApiRequest");
    if (!reqCls) { XLog(@"[诊断] TXTRESTApiRequest 不存在"); return; }
    id req = [[reqCls alloc] init];
    if (!req) return;
    @try {
        if ([req respondsToSelector:@selector(setUrlString:)])
            ((void(*)(id, SEL, id))objc_msgSend)(req, @selector(setUrlString:), url);
        if ([req respondsToSelector:@selector(setHttpMethod:)])
            ((void(*)(id, SEL, id))objc_msgSend)(req, @selector(setHttpMethod:), method);
        if ([req respondsToSelector:@selector(setIsWebBridge:)])
            ((void(*)(id, SEL, BOOL))objc_msgSend)(req, @selector(setIsWebBridge:), webBridge);
        if (body) {
            if ([req respondsToSelector:@selector(setParamsDictionary:)])
                ((void(*)(id, SEL, id))objc_msgSend)(req, @selector(setParamsDictionary:), body);
            else if ([req respondsToSelector:@selector(setBody:)])
                ((void(*)(id, SEL, id))objc_msgSend)(req, @selector(setBody:), body);
        }
        SEL startSel = NSSelectorFromString(@"startWithSuccessBlock:failureBlock:");
        if (![req respondsToSelector:startSel]) { XLog(@"[诊断] 无 startWithSuccessBlock:"); return; }
        ((void(*)(id, SEL, id, id))objc_msgSend)(req, startSel,
            ^(id result) {
                id realData = _unwrapResponse(result);
                if (success) success(realData ?: result);
            },
            ^(id err) {
                if (failure) failure(err);
            });
    } @catch (NSException *e) {
        XLog(@"[诊断] 发送异常 %@", e);
    }
}


// ============ 6.9.9 验证流程 hook: 抓 400313 identity verify 后的处理 ============
// 注意: 这两个都是【类方法】(定义在 Meta Class 上), 必须用 class_getClassMethod
// identificationVerificationDealWithError: v24@0:8@16 (void, 1 对象参数 error), self=类对象

// errorWithStatusCode400: @24@0:8@16 (返回 id, 1 对象参数 response)

// ============ 6.9.24 认证状态底层数据注入: hook pictureVerificationType / pictureDictionary ============
static IMP _orig_pictureVerificationType = NULL;
static IMP _orig_pictureDictionary = NULL;
static __attribute__((unused)) unsigned long long _pictureVerificationType_probe(id self, SEL _cmd) {
    unsigned long long r = 0;
    if (_orig_pictureVerificationType) {
        r = ((unsigned long long(*)(id, SEL))_orig_pictureVerificationType)(self, _cmd);
    }
    // 认证伪装: 强制返回 verified 枚举值 (2)
    // 注: 认证中心只显示当前用户自己的认证, 全局返回 2 不影响别人的认证中心(别人看的是自己的)
    // 兼容: verify_picture 或 verify_picture2 任一开就生效
    if (_swOn(XH_SW_VERIFY_PICTURE)) {
        r = 2; // verified
    }
    return r;
}
static __attribute__((unused)) id _pictureDictionary_probe(id self, SEL _cmd) {
    id r = nil;
    if (_orig_pictureDictionary) {
        r = ((id(*)(id, SEL))_orig_pictureDictionary)(self, _cmd);
    }
    // 认证伪装: 基于原字典改 status=verified (保留 media 等字段, 避免下游崩溃)
    if (_swOn(XH_SW_VERIFY_PICTURE)) {
        NSMutableDictionary *m = (r && [r isKindOfClass:[NSDictionary class]]) ? [r mutableCopy] : [NSMutableDictionary dictionary];
        m[@"status"] = @"verified";
        return m;
    }
    return r;
}

// ============ 6.9.25 实名认证(身份证) 注入: hook isIDCardVerified / identityVerificationType / idCardDictionary / identityDictionary ============
static IMP _orig_isIDCardVerified = NULL;
static IMP _orig_identityVerificationType = NULL;
static IMP _orig_idCardDictionary = NULL;
static IMP _orig_identityDictionary = NULL;
static __attribute__((unused)) BOOL _isIDCardVerified_probe(id self, SEL _cmd) {
    BOOL r = NO;
    if (_orig_isIDCardVerified) {
        r = ((BOOL(*)(id, SEL))_orig_isIDCardVerified)(self, _cmd);
    }
    if (_swOn(XH_SW_VERIFY_ID)) {
        return YES;
    }
    return r;
}
static __attribute__((unused)) unsigned long long _identityVerificationType_probe(id self, SEL _cmd) {
    unsigned long long r = 0;
    if (_orig_identityVerificationType) {
        r = ((unsigned long long(*)(id, SEL))_orig_identityVerificationType)(self, _cmd);
    }
    if (_swOn(XH_SW_VERIFY_ID)) {
        r = 2; // verified
    }
    return r;
}
static __attribute__((unused)) id _idCardDictionary_probe(id self, SEL _cmd) {
    id r = nil;
    if (_orig_idCardDictionary) {
        r = ((id(*)(id, SEL))_orig_idCardDictionary)(self, _cmd);
    }
    // 注意: 不伪造 idCardDictionary (下游可能访问 certificate/name 等字段, 伪造空字典会崩)
    // 实名认证"已认证"显示由 identityVerificationType=2 驱动, 无需改字典
    return r;
}
static __attribute__((unused)) id _identityDictionary_probe(id self, SEL _cmd) {
    id r = nil;
    if (_orig_identityDictionary) {
        r = ((id(*)(id, SEL))_orig_identityDictionary)(self, _cmd);
    }
    // 注意: 不伪造 identityDictionary (下游可能访问 certificate/name 等字段, 伪造空字典会崩)
    return r;
}

// ============ 6.9.29 发消息实名认证拦截注入: isIdentityVerificationNoActive/Pending -> NO ============
// 发消息时探探读这两个方法判断"是否需实名", 强制返回 NO = 已实名, 跳过"填姓名身份证"弹窗
static IMP _orig_isIdentityNoActive = NULL;
static IMP _orig_isIdentityPending = NULL;
static BOOL _isIdentityNoActive_probe(id self, SEL _cmd) {
    BOOL r = NO;
    if (_orig_isIdentityNoActive) {
        r = ((BOOL(*)(id, SEL))_orig_isIdentityNoActive)(self, _cmd);
    }
    if (_swOn(XH_SW_VERIFY_ID)) {
        return NO;
    }
    return r;
}
static BOOL _isIdentityPending_probe(id self, SEL _cmd) {
    BOOL r = NO;
    if (_orig_isIdentityPending) {
        r = ((BOOL(*)(id, SEL))_orig_isIdentityPending)(self, _cmd);
    }
    if (_swOn(XH_SW_VERIFY_ID)) {
        return NO;
    }
    return r;
}

// ============ 6.9.28 认证中心新版 cell 观察: 抓 tableView:cellForRowAtIndexPath: 返回的 cell 真实类 ============

// ============ 6.9.27 认证中心 ViewModel type 注入 (认证中心真正读的状态源) ============
// 认证中心 ViewModel/CellModel 的 type getter 决定 configForXXXType 分支, 强制 type=2 显示"已认证"
// 用 _getOrigImp 按类名回退, 避免多类共享单例 orig 导致崩溃
static unsigned long long _vmType_probe(id self, SEL _cmd) {
    unsigned long long orig = 0;
    IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd);
    if (o) orig = ((unsigned long long(*)(id, SEL))o)(self, _cmd);
    // ViewModel type 同时影响人脸和实名, 任一认证开关开启即返回 verified
    if (!_swOn(XH_SW_VERIFY_PICTURE) && !_swOn(XH_SW_VERIFY_ID)) {
        return orig;
    }
    return 2; // verified
}

// ============ 6.9.30 弹窗定位观察: hook presentViewController 打印被 present 的 VC 类名 ============

// ============ 6.9.31 强制实名认证弹窗拦截: shouldShowMandatoryVerification -> NO ============
// 【补注册】isMandatoryVerification 挂在 PUGUser 模型层, 客户端 UI 读它判断"是否需要强制认证"。
// 受"屏蔽所有弹窗"开关 (xh_switch.popup) 控制 —— 之前定义了但没注册, 等于没拦截。
static BOOL _shouldShowMandatoryVerification_NO(id self, SEL _cmd) {
    XH_GUARD_BOOL(XH_SW_POPUP);
    return NO;
}
static BOOL _isMandatoryVerification_NO(id self, SEL _cmd) {
    XH_GUARD_BOOL(XH_SW_POPUP);
    return NO;
}
static void _showMandatoryVerificationIfNeeded_block(id self, SEL _cmd, id data) {
    // 不调用原实现, 直接返回 = 不弹实名认证弹窗
    if (!_swOn(XH_SW_POPUP)) {
        IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd);
        if (o) { ((void(*)(id,SEL,id))o)(self, _cmd, data); return; }
    }
    return;
}

// ============ 6.9.32 认证中心控制器 pictureVerificationType/identityVerificationType -> 2 ============
// 认证中心 UI 读的是控制器 PUGVerificationCenterViewController 的这两个方法(非模型层)
static unsigned long long _vcPictureVerificationType_probe(id self, SEL _cmd) {
    unsigned long long orig = 0;
    IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd);
    if (o) orig = ((unsigned long long(*)(id, SEL))o)(self, _cmd);
    if (!_swOn(XH_SW_VERIFY_PICTURE)) {
        return orig;
    }
    return 2; // verified
}
static unsigned long long _vcIdentityVerificationType_probe(id self, SEL _cmd) {
    unsigned long long orig = 0;
    IMP o = _getOrigImp(NSStringFromClass([self class]), _cmd);
    if (o) orig = ((unsigned long long(*)(id, SEL))o)(self, _cmd);
    if (!_swOn(XH_SW_VERIFY_ID)) {
        return orig;
    }
    return 2; // verified
}

// 第一步: 拉取四选一题目 (questionID + allIds)
static void _fetchExtremeQuestion(void (^done)(NSString *questionID, NSArray *allIds)) {
    NSString *url = @"https://core.tantanapp.com/v2/extreme-picks/question";
    _sendRESTRequest(url, @"GET", nil, ^(id data) {
        @try {
            NSArray *allIds = nil;
            NSString *qid = nil;
            if ([data isKindOfClass:[NSDictionary class]]) {
                NSDictionary *d = (NSDictionary *)data;
                NSDictionary *inner = d[@"data"];
                if ([inner isKindOfClass:[NSDictionary class]]) d = inner;
                NSDictionary *eq = d[@"extremeQuestions"];
                if ([eq isKindOfClass:[NSDictionary class]]) {
                    NSArray *questions = eq[@"questions"];
                    if ([questions isKindOfClass:[NSArray class]] && questions.count > 0) {
                        for (id qobj in questions) {
                            if (![qobj isKindOfClass:[NSDictionary class]]) continue;
                            NSDictionary *q = (NSDictionary *)qobj;
                            NSArray *uids = q[@"userIds"];
                            if ([uids isKindOfClass:[NSArray class]] && uids.count > 0) {
                                qid = [q[@"questionID"] description];
                                NSMutableArray *ids = [NSMutableArray array];
                                for (id u in uids) [ids addObject:[u description]];
                                allIds = ids;
                                break;
                            }
                        }
                    }
                }
                XLog(@"[自动四选一] 解析题目: questionID=%@ allIds=%@", qid, allIds);
            }
            if (done) done(qid, allIds);
        } @catch (NSException *e) {
            XLog(@"[自动四选一] 解析题目异常: %@", e);
            if (done) done(nil, nil);
        }
    }, ^(NSError *err) {
        XLog(@"[自动四选一] 拿题目失败: %@", err);
        if (done) done(nil, nil);
    });
}

// 第二步: 选人匹配 (pickedID 从 allIds 里选第一个)
static void _doExtremePick(NSString *questionID, NSArray *allIds, NSString *pickedID) {
    if (!questionID || !allIds || allIds.count == 0) {
        XLog(@"[自动四选一] 缺少 questionID 或 allIds, 无法匹配");
        return;
    }
    NSString *pickID = pickedID ?: [allIds firstObject];
    // pickIndex 是选中项的序号(从1开始?), 这里默认选第一个
    NSDictionary *body = @{
        @"pickIndex": @"1",
        @"questionID": questionID,
        @"pickedID": pickID,
        @"allIds": allIds,
        @"type": @"normal"
    };
    XLog(@"[自动四选一] 发起匹配: questionID=%@ pickedID=%@ allIds=%@", questionID, pickID, allIds);
    _sendRESTRequest(@"https://core.tantanapp.com/v2/extreme-picks/pick", @"POST", body,
        ^(id result) {
            XLog(@"[自动四选一] 匹配成功! 结果=%@", result);
        },
        ^(NSError *err) {
            XLog(@"[自动四选一] 匹配失败: %@", err);
        });
}

// 完整流程: 拿题 -> 选人 -> 匹配
__attribute__((unused)) static void _autoExtremePick(void) {
    XLog(@"[自动四选一] 开始自动四选一匹配流程");
    _fetchExtremeQuestion(^(NSString *qid, NSArray *allIds) {
        if (!qid || !allIds || allIds.count == 0) {
            XLog(@"[自动四选一] 拿题目失败或无候选, 流程中止");
            return;
        }
        _doExtremePick(qid, allIds, nil);
    });
}

// ---------- 探针: performLikeOnUser:actionType:completionBlock: ----------
static void _performLikeOnUser_redirect(id self, SEL _cmd, id user, id actionType, id completionBlock) {
    XLog(@"[探针] performLikeOnUser 被调用! user=%@ actionType=%@", user, actionType);
    if (_ultraMatchRedirectEnabled) {
        _doUltraMatch(user);
        return; // 不调原逻辑, 直接走四选一
    }
    if (_orig_performLikeOnUser) {
        ((void(*)(id, SEL, id, id, id))_orig_performLikeOnUser)(self, _cmd, user, actionType, completionBlock);
    }
}

// ---------- 探针: tryPerformLikeOnUser:actionType:shouldBlock:upgradedToSuperlike:completionBlock: ----------
static void _tryPerformLike_probe(id self, SEL _cmd, id user, id actionType, id shouldBlock, id upgraded, id completionBlock) {
    XLog(@"[探针] tryPerformLikeOnUser 被调用! user=%@ actionType=%@", user, actionType);
    if (_ultraMatchRedirectEnabled) {
        _doUltraMatch(user);
        return;
    }
    if (_orig_tryPerformLike) {
        ((void(*)(id, SEL, id, id, id, id, id))_orig_tryPerformLike)(self, _cmd, user, actionType, shouldBlock, upgraded, completionBlock);
    }
}

// ---------- 探针: pluginLikeAction:actionType:sourceType: (划卡页喜欢入口) ----------
static void _pluginLikeAction_probe(id self, SEL _cmd, id arg1, id actionType, unsigned long long sourceType) {
    XLog(@"[探针] pluginLikeAction 被调用! arg1=%@ actionType=%@ sourceType=%llu", arg1, actionType, sourceType);
    if (_orig_pluginLikeAction) {
        ((void(*)(id, SEL, id, id, unsigned long long))_orig_pluginLikeAction)(self, _cmd, arg1, actionType, sourceType);
    }
}

// ---------- 探针: pluginPerformAction:actionType:sourceType: (划卡页通用动作入口) ----------
static void _pluginPerformAction_probe(id self, SEL _cmd, long long actionType, id arg2, unsigned long long sourceType) {
    XLog(@"[探针] pluginPerformAction 被调用! actionType=%lld arg2=%@ sourceType=%llu", actionType, arg2, sourceType);
    if (_orig_pluginPerformAction) {
        ((void(*)(id, SEL, long long, id, unsigned long long))_orig_pluginPerformAction)(self, _cmd, actionType, arg2, sourceType);
    }
}

// ============ 真正的划卡喜欢核心: PUGSuggestedUserUseCase ============
static void _xhCacheOne(id su);   // 定义在下方活跃时间缓存区
// 保存原 IMP
static IMP _orig_suggested_likeUser_4 = NULL;  // likeUser:actionType:sourceType:completionBlock:
static IMP _orig_suggested_likeUser_3 = NULL;  // likeUser:sourceType:completionBlock:

// likeUser:actionType:sourceType:completionBlock:  v48@0:8@16@24Q32@?40
// 参数: (self, SEL, id user, id actionType, unsigned long long sourceType, id completionBlock)
static void _suggested_likeUser_4_redirect(id self, SEL _cmd, id user, id actionType, unsigned long long sourceType, id completionBlock) {
    // 提取 userID: PUGSuggestedUser 的 userID 在 modelIdentifier("PUGSuggestedUser_xxx") 或 objectID 里
    NSString *uid = @"?";
    @try {
        if (user) {
            // 尝试多种字段
            for (NSString *key in @[@"modelIdentifier", @"objectID", @"userID", @"userId", @"uid"]) {
                if ([user respondsToSelector:NSSelectorFromString(key)]) {
                    id v = [user valueForKey:key];
                    if (v) {
                        uid = [v description];
                        break;
                    }
                }
            }
        }
    } @catch (NSException *e) {}
    XLog(@"[探针] PUGSuggestedUserUseCase likeUser:actionType:sourceType: 被调用! user=%@ userID=%@ actionType=%@ sourceType=%llu", user, uid, actionType, sourceType);
    @try { _xhCacheOne(user); } @catch (NSException *e) {}
    if (_ultraMatchRedirectEnabled) {
        // 关键: 先发 pick 对接(绕过风控), 再调原 likeUser 逻辑(让卡片正常移除+列表刷新)
        _doUltraMatch(user);
        // 不 return, 继续走原逻辑, 让探探正常移除卡片、刷新列表
    }
    if (_orig_suggested_likeUser_4) {
        ((void(*)(id, SEL, id, id, unsigned long long, id))_orig_suggested_likeUser_4)(self, _cmd, user, actionType, sourceType, completionBlock);
    }
}

// likeUser:sourceType:completionBlock:  v40@0:8@16Q24@?32
static void _suggested_likeUser_3_redirect(id self, SEL _cmd, id user, unsigned long long sourceType, id completionBlock) {
    XLog(@"[探针] PUGSuggestedUserUseCase likeUser:sourceType: 被调用! user=%@ sourceType=%llu", user, sourceType);
    @try { _xhCacheOne(user); } @catch (NSException *e) {}
    if (_ultraMatchRedirectEnabled) {
        // 先发 pick 对接, 再走原逻辑(让卡片正常移除)
        _doUltraMatch(user);
    }
    if (_orig_suggested_likeUser_3) {
        ((void(*)(id, SEL, id, unsigned long long, id))_orig_suggested_likeUser_3)(self, _cmd, user, sourceType, completionBlock);
    }
}


// ============ 6.0.0 活跃时间缓存: PUGSuggestedUser.user.activityDate ============
// 6.0.0 的卡片模型是 PUGSuggestedUser, 活跃时间在 suggestedUser.user.activityDate
// 老插件走 card.cardViewModel.rawData.user 在 6.0.0 拿不到 -> 恒判活跃 -> 一直右滑
static NSMutableDictionary *_g_xhActMap = nil;

static void _xhActCacheInit(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        _g_xhActMap = [NSMutableDictionary new];
    });
}

static NSString *_xhObjID(id o) {
    if (!o) return nil;
    for (NSString *k in @[@"objectID", @"userID", @"uid"]) {
        SEL s = NSSelectorFromString(k);
        if (![o respondsToSelector:s]) continue;
        @try {
            id v = ((id(*)(id, SEL))objc_msgSend)(o, s);
            if ([v isKindOfClass:[NSString class]] && [(NSString *)v length] > 0) return v;
            if ([v isKindOfClass:[NSNumber class]]) return [(NSNumber *)v stringValue];
        } @catch (NSException *e) {}
    }
    return nil;
}

// 从 PUGSuggestedUser 或 PUGUser 上取 activityDate
static NSDate *_xhActDate(id o) {
    if (!o) return nil;
    SEL s = NSSelectorFromString(@"activityDate");
    @try {
        if ([o respondsToSelector:s]) {
            id d = ((id(*)(id, SEL))objc_msgSend)(o, s);
            if ([d isKindOfClass:[NSDate class]]) return d;
        }
    } @catch (NSException *e) {}
    SEL us = NSSelectorFromString(@"user");
    @try {
        if ([o respondsToSelector:us]) {
            id u = ((id(*)(id, SEL))objc_msgSend)(o, us);
            if (u && u != o) {
                SEL as = NSSelectorFromString(@"activityDate");
                if ([u respondsToSelector:as]) {
                    id d = ((id(*)(id, SEL))objc_msgSend)(u, as);
                    if ([d isKindOfClass:[NSDate class]]) return d;
                }
            }
        }
    } @catch (NSException *e) {}
    return nil;
}

// 供 HelloXihuanManager 调用: 拿卡片对象的活跃时间字符串, 取不到返回 nil
NSString *XHActivityStringForUser(id o) {
    if (!o) return nil;
    _xhActCacheInit();
    NSDate *d = _xhActDate(o);
    NSString *uid = _xhObjID(o);
    if (!d && uid) {
        @synchronized (_g_xhActMap) { d = _g_xhActMap[uid]; }
    }
    if (!d) {
        // card 可能是视图/包裹对象: 试 suggestedUser / cardModel / user / model
        for (NSString *k in @[@"suggestedUser", @"cardModel", @"user", @"model", @"modelObject"]) {
            SEL s = NSSelectorFromString(k);
            if (![o respondsToSelector:s]) continue;
            @try {
                id v = ((id(*)(id, SEL))objc_msgSend)(o, s);
                if (!v || v == o) continue;
                NSDate *d2 = _xhActDate(v);
                if (!d2) {
                    NSString *uid2 = _xhObjID(v);
                    if (uid2) { @synchronized (_g_xhActMap) { d2 = _g_xhActMap[uid2]; } }
                }
                if (d2) { d = d2; break; }
            } @catch (NSException *e) {}
        }
    }
    if (!d) return nil;
    NSDateFormatter *df = [[NSDateFormatter alloc] init];
    df.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    df.dateFormat = @"yyyy-MM-dd HH:mm:ss Z";
    return [df stringFromDate:d];
}

// 缓存整个卡片数组 (updateUserCardTimeIfNeededWithSuggestedUserArray: 的入参)
static void _xhCacheSuggestedUsers(NSArray *arr) {
    if (![arr isKindOfClass:[NSArray class]] || arr.count == 0) return;
    _xhActCacheInit();
    @synchronized (_g_xhActMap) {
        if (_g_xhActMap.count > 400) [_g_xhActMap removeAllObjects];
        for (id su in arr) {
            NSString *uid = _xhObjID(su);
            NSDate *d = _xhActDate(su);
            if (uid && d) _g_xhActMap[uid] = d;
        }
    }
}

static void _xhCacheOne(id su) {
    if (!su) return;
    _xhActCacheInit();
    NSString *uid = _xhObjID(su);
    NSDate *d = _xhActDate(su);
    if (uid && d) { @synchronized (_g_xhActMap) { _g_xhActMap[uid] = d; } }
}

static IMP _orig_suggested_updateTime = NULL;
// updateUserCardTimeIfNeededWithSuggestedUserArray:  v24@0:8@16
static void _suggested_updateTime_hook(id self, SEL _cmd, id arr) {
    @try { _xhCacheSuggestedUsers(arr); } @catch (NSException *e) {}
    // 记录划卡 use case 实例, 供"喜欢我的人→划卡"插卡使用
    @try { if (self) g_swipeUseCase = self; } @catch (NSException *e) {}
    // 划卡 use case 就绪后补插一次(用户先开开关、后进划卡页的场景)
    @try {
        if (_swOn(XH_SW_SEELIKES_SWIPE) && g_likedMeUIDs.count > g_likedMeInjected.count
            && !g_likedMeBatchRunning && !g_likedMeAutoInjected) {
            static NSTimeInterval _lastInjectTry = 0;
            NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
            if (now - _lastInjectTry > 5.0) {
                _lastInjectTry = now;
                dispatch_async(dispatch_get_main_queue(), ^{ XHSeelikesInjectToSwipe(); });
            }
        }
    } @catch (NSException *e) {}
    if (_orig_suggested_updateTime) {
        ((void(*)(id, SEL, id))_orig_suggested_updateTime)(self, _cmd, arr);
    }
}

static IMP _orig_suggested_dislike_4 = NULL;
// dislikeUser:actionType:sourceType:completionBlock:  v48@0:8@16@24Q32@?40
static void _suggested_dislike_4_hook(id self, SEL _cmd, id user, id actionType, unsigned long long sourceType, id cb) {
    @try { _xhCacheOne(user); XLog(@"[划卡] dislikeUser 跳过 user=%@", user); } @catch (NSException *e) {}
    if (_orig_suggested_dislike_4) {
        ((void(*)(id, SEL, id, id, unsigned long long, id))_orig_suggested_dislike_4)(self, _cmd, user, actionType, sourceType, cb);
    }
}

// ============ "喜欢我的人"页面桃心 -> 四选一 pick 对接 ============
// PUGMyEncounterSeeLikesActionHandler performLikeOnUser:sourcePage:actionType:  v40@0:8@16@24@32
static IMP _orig_encounter_likeUser = NULL;
static void _encounter_likeUser_redirect(id self, SEL _cmd, id user, id sourcePage, id actionType) {
    @try {
        XLog(@"[桃心对接] performLikeOnUser:sourcePage:actionType: user=%@ sourcePage=%@ actionType=%@", user, sourcePage, actionType);
    } @catch (NSException *e) {}
    if (_ultraMatchRedirectEnabled) {
        _doUltraMatch(user);  // 对接四选一 pick 接口, 绕过认证/VIP 限制
    }
    // 继续走原逻辑 (让探探正常移除列表项、刷新)
    if (_orig_encounter_likeUser) {
        ((void(*)(id, SEL, id, id, id))_orig_encounter_likeUser)(self, _cmd, user, sourcePage, actionType);
    }
}
// tryPerformLikeOnUser:sourcePage:actionType:  v40@0:8@16@24@32 (try 版本, 可能是真正执行点)
static IMP _orig_encounter_tryLikeUser = NULL;
static void _encounter_tryLikeUser_redirect(id self, SEL _cmd, id user, id sourcePage, id actionType) {
    @try {
        XLog(@"[桃心对接] tryPerformLikeOnUser:sourcePage:actionType: user=%@ sourcePage=%@ actionType=%@", user, sourcePage, actionType);
    } @catch (NSException *e) {}
    if (_ultraMatchRedirectEnabled) {
        _doUltraMatch(user);
    }
    if (_orig_encounter_tryLikeUser) {
        ((void(*)(id, SEL, id, id, id))_orig_encounter_tryLikeUser)(self, _cmd, user, sourcePage, actionType);
    }
}

// performAction:onUser:actionType:  v40@0:8q16@24@32 (actionType 是 long long, 桃心点击真正入口)
static IMP _orig_encounter_performAction3 = NULL;
static void _encounter_performAction3_redirect(id self, SEL _cmd, long long actionType, id user, id arg3) {
    @try {
        XLog(@"[桃心对接] performAction:onUser:actionType: actionType=%lld user=%@ arg3=%@", actionType, user, arg3);
    } @catch (NSException *e) {}
    // 判断是否"喜欢"动作 (actionType 通常是 1=like 或类似值)
    if (_ultraMatchRedirectEnabled && user) {
        _doUltraMatch(user);
    }
    if (_orig_encounter_performAction3) {
        ((void(*)(id, SEL, long long, id, id))_orig_encounter_performAction3)(self, _cmd, actionType, user, arg3);
    }
}
// performAction:onUser:sourcePage:actionType:  v48@0:8q16@24@32@40
static IMP _orig_encounter_performAction4 = NULL;
static void _encounter_performAction4_redirect(id self, SEL _cmd, long long actionType, id user, id sourcePage, id arg4) {
    @try {
        XLog(@"[桃心对接] performAction:onUser:sourcePage:actionType: actionType=%lld user=%@ sourcePage=%@ arg4=%@", actionType, user, sourcePage, arg4);
    } @catch (NSException *e) {}
    if (_ultraMatchRedirectEnabled && user) {
        _doUltraMatch(user);
    }
    if (_orig_encounter_performAction4) {
        ((void(*)(id, SEL, long long, id, id, id))_orig_encounter_performAction4)(self, _cmd, actionType, user, sourcePage, arg4);
    }
}

// PUGIntlEncounterSeeLikeCell 桃心按钮: usLikeButtonTraped (v16@0:8) + continueCardCellLikeAction:completion: (v28@0:8B16@?20)
static IMP _orig_cell_usLikeButtonTraped = NULL;
static IMP _orig_cell_continueCardCellLike = NULL;
static void _cell_usLikeButtonTraped_probe(id self, SEL _cmd) {
    @try {
        XLog(@"[桃心对接] usLikeButtonTraped 被调用 self=%@ model=%@", NSStringFromClass([self class]), [self valueForKey:@"model"]);
    } @catch (NSException *e) {}
    if (_orig_cell_usLikeButtonTraped) {
        ((void(*)(id, SEL))_orig_cell_usLikeButtonTraped)(self, _cmd);
    }
}
static void _cell_continueCardCellLike_probe(id self, SEL _cmd, BOOL flag, id completion) {
    @try {
        id model = nil; @try { model = [self valueForKey:@"model"]; } @catch (NSException *e) {}
        XLog(@"[桃心对接] continueCardCellLikeAction:completion: flag=%d self=%@ model=%@", flag, NSStringFromClass([self class]), model);
        if (_ultraMatchRedirectEnabled && model) {
            _doUltraMatch(model);
        }
    } @catch (NSException *e) {}
    if (_orig_cell_continueCardCellLike) {
        ((void(*)(id, SEL, BOOL, id))_orig_cell_continueCardCellLike)(self, _cmd, flag, completion);
    }
}

// PUGUltraInstantMatchUseCase 超速配(四选一)点击/请求 -> 对接四选一 pick 接口
// requestUltraInstantMatchWithUser:matchSuccessBlock:fromPurchase:  v36@0:8@16@?24B32
static IMP _orig_ultra_request = NULL;
static void _ultra_request_redirect(id self, SEL _cmd, id user, id matchSuccessBlock, BOOL fromPurchase) {
    @try {
        XLog(@"[桃心对接] requestUltraInstantMatchWithUser:matchSuccessBlock:fromPurchase: user=%@ fromPurchase=%d", user, fromPurchase);
    } @catch (NSException *e) {}
    if (_ultraMatchRedirectEnabled && user) {
        _doUltraMatch(user);  // 对接四选一 pick 接口, 绕过认证/VIP
    }
    if (_orig_ultra_request) {
        ((void(*)(id, SEL, id, id, BOOL))_orig_ultra_request)(self, _cmd, user, matchSuccessBlock, fromPurchase);
    }
}
// handleUltraInstantMatchClickActionWithUser:purchaseShowFrom:matchSuccessBlock:  v40@0:8@16@24@?32
static IMP _orig_ultra_handle3 = NULL;
static void _ultra_handle3_redirect(id self, SEL _cmd, id user, id purchaseShowFrom, id matchSuccessBlock) {
    @try {
        XLog(@"[桃心对接] handleUltraInstantMatchClickActionWithUser:purchaseShowFrom:matchSuccessBlock: user=%@", user);
    } @catch (NSException *e) {}
    if (_ultraMatchRedirectEnabled && user) {
        _doUltraMatch(user);
    }
    if (_orig_ultra_handle3) {
        ((void(*)(id, SEL, id, id, id))_orig_ultra_handle3)(self, _cmd, user, purchaseShowFrom, matchSuccessBlock);
    }
}

// ============ 发消息改造: 全局状态 ============
// 普通聊天发消息被 400 风控; 打招呼接口 /v2/greetings/{userID}/messages?channel=heartbeat_oneside 返回 201。
// 方案: 检测到普通发消息 POST 时, 从 URL 提取 conversation ID, 直接用作打招呼接口的 userID。
static NSString *_lastMessageValue = nil;      // 最近一次发消息的明文内容 (value)
static BOOL _isSendingGreeting = NO;          // 防重入: 正在发打招呼请求时置 YES, 避免递归


// ============ Window 根控制器切换观察 (定位"重新登录"跳转 + 主界面入口) ============
static IMP _orig_setCurrentUser = NULL;    // PUGAccountManager setCurrentUser:



// PUGAccountManager setCurrentUser: (登录态设置, 观察 + 拦截清空)
static void _setCurrentUser_probe(id self, SEL _cmd, id user) {
    @try {
        NSString *uid = nil;
        if (user && [user respondsToSelector:@selector(userId)]) uid = ((id(*)(id, SEL))objc_msgSend)(user, @selector(userId));
        else if (user && [user respondsToSelector:@selector(uid)]) uid = ((id(*)(id, SEL))objc_msgSend)(user, @selector(uid));
        // 【拦截清空 + 记录恢复】开关 xh_switch.block_clear 默认关闭。开启时: user 为 nil 记录清空前 currentUser, 让探探正常清空再立即恢复(保留登录态又不卡住)
        if (user == nil && XHGetSwitch(XH_SW_BLOCK_CLEAR, NO)) {
            id cur = nil;
            @try {
                if ([self respondsToSelector:@selector(currentUser)]) {
                    cur = ((id(*)(id, SEL))objc_msgSend)(self, @selector(currentUser));
                }
            } @catch (NSException *e2) {}
            XLog(@"[登录态拦截] setCurrentUser(nil), 清空前 currentUser=%@ class=%@", cur ?: @"(nil)", cur ? NSStringFromClass([cur class]) : @"(nil)");
            // 执行原实现(清空, 让探探流程正常不卡住)
            if (_orig_setCurrentUser) {
                ((void(*)(id, SEL, id))_orig_setCurrentUser)(self, _cmd, user);
            }
            // 清空后立即恢复(如果之前有值)
            if (cur) {
                if (_orig_setCurrentUser) {
                    ((void(*)(id, SEL, id))_orig_setCurrentUser)(self, _cmd, cur);
                }
                XLog(@"[登录态拦截] 已恢复 currentUser=%@", cur);
            }
            return;
        }
        XLog(@"[登录态] setCurrentUser user=%@ class=%@ uid=%@", user ?: @"(nil)", user ? NSStringFromClass([user class]) : @"(nil)", uid ?: @"(nil)");
    } @catch (NSException *e) {}
    if (_orig_setCurrentUser) {
        ((void(*)(id, SEL, id))_orig_setCurrentUser)(self, _cmd, user);
    }
}

// PUGAccountManager initlizeAccountInfo (初始化账号信息, 仅观察; 不再自动切主界面, 改为按钮手动触发)

// 强制进入主界面: 主动调用 unlockWindow 切到 PUGMainTabBarController
// 导出为公开函数, 供悬浮球面板按钮直接调用(手动触发)

// 回到登录页: 调用 lockWindow 切到登录页(与强制进主界面相反)

// ============ 发消息改造: 普通发消息 -> 打招呼接口 (绕过 400 风控) ============
// 关键结论(已验证): conversation ID == 对方 userID (单聊会话 ID 就是对方用户 ID)
//   证据: 日志 otherID=555856798 且 userID=555856798; greetings/655650830 和 conversations/655650830 同值。
// 普通发消息: POST /v3/users/me/conversations/{id}/messages  (body 加密, 400 风控)
// 打招呼接口: POST /v2/users/me/greetings/{id}/messages?channel=heartbeat_oneside  (body 明文, 201 成功)
// 方案: 在 NSURLSession 层检测普通发消息, 直接改 URL + 明文 body, 不额外发请求(避免递归卡死)。
// 明文消息内容 value 已在 _encryptAES256Base64Data_probe 里缓存到 _lastMessageValue。

// ============ 拦截 counter-verifications 上报: 把 blocked 改成 default ============
// 目的: 验证 blocked 标记是「客户端上报」还是「服务端独立判断」。
// 如果 hook 掉 blocked 上报后发消息不再 400, 说明服务端靠客户端上报才标记风控。

// ============ 统一伪造设备指纹: 改上报里的 oneid/idfv/idfa/identifier ============
// 目的: 让服务器以为是全新设备, 避免设备连坐风控。
// 拦截设备指纹上报接口(oneid/createid, devices/activate, devices/bind), 替换指纹字段。
// 指纹值已改为随机生成(见文件顶部 _spoofIdentity), 此处用 _spoofLocalId() 等动态取。

static BOOL _tryFakeDeviceFingerprint(id request) {
    // 网络层设备指纹伪装: 跟随"设备改机"开关(勾选才生效)
    if (!_swOn(XH_SW_DEVICE)) return NO;
    @try {
        NSURL *url = [request valueForKey:@"URL"];
        NSString *urlStr = [url absoluteString];
        if (!urlStr) return NO;
        // 关键: oneid/createid 接口无需 MAC 签名(鉴权header为空), 可直接改 body。
        // 只处理 oneid/createid, 让服务端下发全新 oneid。
        BOOL isOneIdCreate = [urlStr containsString:@"oneid/createid"];
        if (!isOneIdCreate) return NO;

        id body = [request valueForKey:@"HTTPBody"];
        if (!body) return NO;
        NSString *bodyStr = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
        if (!bodyStr) return NO;

        // 替换各指纹字段的值（用 JSON 解析后替换）
        NSData *jd = [bodyStr dataUsingEncoding:NSUTF8StringEncoding];
        NSMutableDictionary *dict = [[NSJSONSerialization JSONObjectWithData:jd options:NSJSONReadingMutableContainers error:nil] mutableCopy];
        if (!dict) return NO;

        BOOL changed = NO;
        // last_oneid 设为空, 让服务端走"全新设备首次注册"下发新 oneid。
        // localid 设为新值(避免服务端按旧 localid 匹配回旧 oneid)。
        if (dict[@"last_oneid"]) {
            dict[@"last_oneid"] = @"";
            changed = YES;
        }
        if (dict[@"localid"]) {
            dict[@"localid"] = _spoofLocalId();
            changed = YES;
        }

        if (changed) {
            NSData *newBody = [NSJSONSerialization dataWithJSONObject:dict options:0 error:nil];
            [request setValue:newBody forKey:@"HTTPBody"];
            XLog(@"[设备伪装] 已替换指纹: %@", [[NSString alloc] initWithData:newBody encoding:NSUTF8StringEncoding]);
        }
        return YES;
    } @catch (NSException *e) {
        XLog(@"[设备伪装] 异常: %@", e);
        return NO;
    }
}

// ============ 修复 autoupdate 请求 devive_id 泄露真实 IDFV ============
// 现象: PUGPatchEngine 在 App 启动极早期缓存了真实 IDFV(217519C3-...),
//       拼进 autoupdate.tantanapp.com/v1/ios/patch 的 URL query 参数 devive_id,
//       该值早于 UIDevice.identifierForVendor hook 生效, 导致换机后仍泄露真实 IDFV。
// 方案: 在网络层对所有请求 URL 做兜底替换, 把 devive_id=真实值 换成 devive_id=伪IDFV。
static BOOL _tryFixDeviveIdInURL(id request) {
    // 网络层 IDFV 泄露修复: 跟随"设备改机"开关(勾选才生效)
    if (!_swOn(XH_SW_DEVICE)) return NO;
    @try {
        NSURL *url = [request valueForKey:@"URL"];
        if (!url) return NO;
        NSString *urlStr = [url absoluteString];
        if (!urlStr || urlStr.length == 0) return NO;
        // 只处理含 devive_id 的请求 (autoupdate patch / 其它带该参数的接口)
        if (![urlStr containsString:@"devive_id="]) return NO;

        // 用正则把 devive_id=<uuid> 替换为 devive_id=<伪IDFV>
        NSString *pattern = @"(devive_id=)[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}";
        NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:pattern options:0 error:nil];
        if (!regex) return NO;
        NSString *replacement = [NSString stringWithFormat:@"$1%@", _spoofIDFV()];
        NSString *newStr = [regex stringByReplacingMatchesInString:urlStr options:0 range:NSMakeRange(0, urlStr.length) withTemplate:replacement];
        if ([newStr isEqualToString:urlStr]) return NO;  // 未替换成功

        NSURL *newURL = [NSURL URLWithString:newStr];
        if (!newURL) return NO;
        [request setValue:newURL forKey:@"URL"];
        XLog(@"[devive_id修复] 已替换: %@", newStr);
        return YES;
    } @catch (NSException *e) {
        XLog(@"[devive_id修复] 异常: %@", e);
        return NO;
    }
}

// ============ 修复上报参数 net 泄露真实网络类型 ============
// 现象: RAT 已被伪装成 LTE(4G), 但监控上报 URL 里 net=wifi 仍是真实接口类型,
//       形成 "RAT=4G 但 net=wifi" 的交叉矛盾, 风控可据此识别改机。
// 方案: 在请求 URL 层把 net=wifi 统一改成 net=4g, 与 RAT 保持一致。
//       受"设备改机"开关控制, 关闭时完全不动。
static BOOL _tryFixNetParam(id request) {
    if (!_swOn(XH_SW_DEVICE)) return NO;
    @try {
        NSURL *url = [request valueForKey:@"URL"];
        if (!url) return NO;
        NSString *urlStr = [url absoluteString];
        if (!urlStr || urlStr.length == 0) return NO;
        // 只处理确实带 net=wifi 的请求(大小写两种都覆盖)
        BOOL hasLower = [urlStr containsString:@"net=wifi"];
        BOOL hasUpper = [urlStr containsString:@"net=WIFI"];
        if (!hasLower && !hasUpper) return NO;
        NSString *newStr = urlStr;
        if (hasLower) newStr = [newStr stringByReplacingOccurrencesOfString:@"net=wifi" withString:@"net=4g"];
        if (hasUpper) newStr = [newStr stringByReplacingOccurrencesOfString:@"net=WIFI" withString:@"net=4G"];
        if ([newStr isEqualToString:urlStr]) return NO;
        NSURL *newURL = [NSURL URLWithString:newStr];
        if (!newURL) return NO;
        [request setValue:newURL forKey:@"URL"];
        static int onceN = 0;
        if (onceN < 3) { onceN++; XLog(@"[net修复] net=wifi -> net=4g 已替换"); }
        return YES;
    } @catch (NSException *e) {
        XLog(@"[net修复] 异常: %@", e);
        return NO;
    }
}

// 改造核心(v2版): 检测到 v3 普通发消息 POST 时, 直接把请求 URL 从 /v3/ 改成 /v2/。
// 原因: v3 conversations 发消息被服务端限流(额度0, 400), 而 v2 同路径接口返回 201 成功。
// 原地改 URL 后, 原请求走 v2 接口, 客户端收到 201 显示成功(不再显示感叹号)。

// 改造核心: 检测到普通发消息 POST 时, 额外发明文打招呼接口(用缓存的 value)。
// 关键: 不在 NSURLSession hook 里同步发(会递归), 用 dispatch_async 延迟 + 防重入标志。
// 返回 YES 表示已触发改造(原请求照常发出, 额外发明文打招呼请求)。
static __attribute__((unused)) BOOL _tryRewriteToGreeting(id request) {
    if (!_swOn(XH_SW_V2_MSG)) return NO;  // 受"发消息改V2"开关控制, 默认开
    if (_isSendingGreeting) return NO;  // 防重入: 打招呼请求自身不再触发
    @try {
        NSURL *url = [request valueForKey:@"URL"];
        NSString *urlStr = [url absoluteString];
        if (!urlStr) return NO;
        NSString *method = [request valueForKey:@"HTTPMethod"] ?: @"";
        if (![method isEqualToString:@"POST"]) return NO;
        // 只匹配普通发消息: /v3/users/me/conversations/{id}/messages
        NSRange convRange = [urlStr rangeOfString:@"/v3/users/me/conversations/"];
        if (convRange.location == NSNotFound) return NO;
        if (![urlStr containsString:@"/messages"]) return NO;
        // 提取 conversation ID (== 对方 userID)
        NSString *sub = [urlStr substringFromIndex:convRange.location + convRange.length];
        NSString *userID = sub;
        NSRange slash = [sub rangeOfString:@"/"];
        if (slash.location != NSNotFound) userID = [sub substringToIndex:slash.location];
        if (!userID || userID.length == 0) return NO;
        // 优先用缓存的 _lastMessageValue(加密路径), 否则直接从 request.HTTPBody 明文提取 value
        // (6.0.0 发消息 body 是明文, 不经过加密探针, 所以 _lastMessageValue 拿不到, 需直接读 HTTPBody)
        NSString *msgValue = _lastMessageValue;
        if (!msgValue) {
            @try {
                id rawBody = [request valueForKey:@"HTTPBody"];
                if (rawBody && [rawBody isKindOfClass:[NSData class]]) {
                    NSDictionary *d = [NSJSONSerialization JSONObjectWithData:(NSData *)rawBody options:0 error:nil];
                    if (d && d[@"value"]) {
                        msgValue = [NSString stringWithFormat:@"%@", d[@"value"]];
                    }
                }
            } @catch (NSException *e) {}
        }
        if (!msgValue || msgValue.length == 0) return NO;

        // 快照当前 value 和 userID, 避免延迟发送时被覆盖
        NSString *snapValue = [msgValue copy];
        NSString *snapUserID = [userID copy];

        _isSendingGreeting = YES;
        // 延迟到下一个 runloop 发送, 避免当前 NSURLSession hook 调用栈里递归
        dispatch_async(dispatch_get_main_queue(), ^{
            @try {
                NSString *uuid = [[NSUUID UUID] UUIDString];
                NSDictionary *greetBody = @{
                    @"msgType": @"text",
                    @"idempotentInfo": @{@"id": uuid},
                    @"page_id": @"p_chat_view",
                    @"value": snapValue
                };
                // 【换V2接口】v3 conversations 限流(额度0), 改走 v2 conversations 试试
                NSString *greetURL = [NSString stringWithFormat:@"https://core.tantanapp.com/v2/users/me/conversations/%@/messages", snapUserID];
                XLog(@"[发消息改造] 改走v2普通聊天接口: userID=%@ value=%@", snapUserID, snapValue);
                _sendRESTRequest(greetURL, @"POST", greetBody,
                    ^(id result) {
                        XLog(@"[发消息改造] 打招呼接口成功! 结果=%@", result);
                        _isSendingGreeting = NO;
                    },
                    ^(NSError *err) {
                        XLog(@"[发消息改造] 打招呼接口失败: %@", err);
                        _isSendingGreeting = NO;
                    });
            } @catch (NSException *e) {
                _isSendingGreeting = NO;
            }
        });
        return YES;
    } @catch (NSException *e) {
        XLog(@"[发消息改造] 改造失败: %@", e);
        return NO;
    }
}

// ============ 强制验证关闭: hook fetchRemoteNeedShowForceVerificationStatus (篡改 needShow=NO) ============
static IMP _orig_fetchRemoteForceVerification = NULL;
static void _fetchRemoteForceVerification_probe(id self, SEL _cmd, id completion) {
    // 【篡改版】包装 completion 回调, 强制把「是否需要强制验证」改成 NO
    id wrapped = completion;
    @try {
        if (completion) {
            void (^origBlock)(id) = completion;
            wrapped = ^(id result) {
                @try {
                    id originalNeedShow = nil;
                    if (result) {
                        @try { originalNeedShow = [result valueForKey:@"needShow"]; } @catch (NSException *e) {}
                    }
                    XLog(@"[验证状态] fetchRemoteNeedShowForceVerification 原始返回: %@ (needShow=%@)", result ?: @"(nil)", originalNeedShow ?: @"?");

                    // 尝试就地篡改 needShow/force/status
                    id finalResult = result;
                    @try {
                        if ([result isKindOfClass:[NSMutableDictionary class]]) {
                            [result setObject:@NO forKey:@"needShow"];
                            [result setObject:@NO forKey:@"force"];
                            if ([result objectForKey:@"status"]) [result setObject:@"none" forKey:@"status"];
                            XLog(@"[验证状态] 已篡改 needShow=NO force=NO status=none");
                        } else if (result) {
                            // 非可变字典, 尝试 KVC 设置
                            @try { [result setValue:@NO forKey:@"needShow"]; } @catch (NSException *e) {}
                            @try { [result setValue:@NO forKey:@"force"]; } @catch (NSException *e) {}
                            XLog(@"[验证状态] 尝试KVC篡改 needShow=NO force=NO");
                        } else {
                            // result 为 nil, 直接构造一个「不需要强制」的结果
                            finalResult = @{@"needShow":@NO, @"force":@NO, @"status":@"none"};
                            XLog(@"[验证状态] result为nil, 构造 needShow=NO");
                        }
                    } @catch (NSException *e) {
                        XLog(@"[验证状态] 篡改异常: %@", e);
                    }

                    if (origBlock) origBlock(finalResult);
                } @catch (NSException *e) {}
            };
        }
    } @catch (NSException *e) {}
    if (_orig_fetchRemoteForceVerification) {
        ((void(*)(id, SEL, id))_orig_fetchRemoteForceVerification)(self, _cmd, wrapped);
    }
}

// ============ 强制验证开关探针: hook shouldEnableForceVerification 系列 ============
// 目的: 抓「是否启用强制验证」的判断, 研究能否关闭强制验证。
static IMP _orig_shouldEnableForceVerification = NULL;
static IMP _orig_shouldEnableForceVerificationHaveSkip = NULL;
static IMP _orig_shouldEnableForceVerificationNoneSkip = NULL;

static BOOL _shouldEnableForceVerification_probe(id self, SEL _cmd) {
    BOOL r = NO;
    if (_orig_shouldEnableForceVerification) {
        r = ((BOOL(*)(id, SEL))_orig_shouldEnableForceVerification)(self, _cmd);
    }
    XLog(@"[强制验证] shouldEnableForceVerification 原始=%d, 强制返回=NO", r);
    return NO;  // 【篡改】强制关闭强制验证
}
static BOOL _shouldEnableForceVerificationHaveSkip_probe(id self, SEL _cmd) {
    BOOL r = NO;
    if (_orig_shouldEnableForceVerificationHaveSkip) {
        r = ((BOOL(*)(id, SEL))_orig_shouldEnableForceVerificationHaveSkip)(self, _cmd);
    }
    XLog(@"[强制验证] shouldEnableForceVerificationHaveSkip 原始=%d, 强制返回=NO", r);
    return NO;  // 【篡改】强制关闭
}
static BOOL _shouldEnableForceVerificationNoneSkip_probe(id self, SEL _cmd) {
    BOOL r = NO;
    if (_orig_shouldEnableForceVerificationNoneSkip) {
        r = ((BOOL(*)(id, SEL))_orig_shouldEnableForceVerificationNoneSkip)(self, _cmd);
    }
    XLog(@"[强制验证] shouldEnableForceVerificationNoneSkip 原始=%d, 强制返回=NO", r);
    return NO;  // 【篡改】强制关闭
}

// ============ blockStatus 探针: hook setBlockStatus: 抓 blocked 标记来源 ============
// 目的: 搞清楚 blockStatus="blocked" 是服务端下发还是客户端本地设置。

// ============ 推荐会话发消息探针: hook sendMessagesWithItems + generateGreeting ============
// 目的: 抓「推荐会话」发消息的 items 参数结构, 验证这个通道是否查实名。

// sendMessagesWithItems:completion:  @32@0:8@16@?24

// generateGreetingWithOtherUserID:reason:currentGreeting:completion:  @48@0:8@16@24@32@?40

// PUGChatService sendMessage:userID:completion:  v40@0:8@16@24@?32 (self,_cmd,message,userID,completion)

// ============ 网络层 hook (功能骨干: 发消息改V2 / 四选一对接 / 设备指纹伪装 / devive_id修复) ============
static IMP _orig_dataTaskWithRequest = NULL;
static IMP _orig_dataTaskWithRequestHandler = NULL;
static BOOL _NET_HOOK_ENABLED = YES;

// 过滤: 只处理探探业务接口
static BOOL _shouldLogRequest(NSURL *url) {
    NSString *s = [url absoluteString];
    if (!s) return NO;
    if ([s containsString:@"extreme"] || [s containsString:@"picks"] || [s containsString:@"greeting"] ||
        [s containsString:@"like"] || [s containsString:@"match"] || [s containsString:@"recommend"] ||
        [s containsString:@"tantan"] || [s containsString:@"yaymedialabs"] || [s containsString:@"pingma"]) {
        return YES;
    }
    return NO;
}

// v28: 包装 viewer 资料请求的 completionHandler, 抓响应原文 (看对方是否喜欢你标记)
static NSInteger g_viewerRespDumped = 0;
typedef void (^URLDataComp)(NSData *, NSURLResponse *, NSError *);
static id _wrapViewerRespBlock(id origBlock, NSString *urlStr) {
    if (!origBlock) return nil;
    URLDataComp orig = origBlock;
    void (^wrapper)(NSData *, NSURLResponse *, NSError *) = ^(NSData *data, NSURLResponse *resp, NSError *err) {
        if (orig) orig(data, resp, err);
        @try {
            if (g_viewerRespDumped >= 40) return;   // 防刷屏
            g_viewerRespDumped++;
            NSString *s = data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : nil;
            if (s.length > 2400) s = [[s substringToIndex:2400] stringByAppendingString:@"..."];
            XLog(@"[资料响应] %@\n body=%@ err=%@", urlStr, s ?: @"(nil)", err);
        } @catch (NSException *e) {}
    };
    return wrapper;
}

// v29: viewer 资料请求 -> 自发同款 GET with=relationships, 抓关系数据原文
static NSMutableSet *g_viewerProbed = nil;
static void _probeViewerRelationship(NSString *uid) {
    if (!uid.length) return;
    if (!g_viewerProbed) g_viewerProbed = [NSMutableSet set];
    if ([g_viewerProbed containsObject:uid]) return;
    [g_viewerProbed addObject:uid];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        NSString *url = [NSString stringWithFormat:@"https://core.tantanapp.com/v2/users/%@?with=relationships", uid];
        _sendRESTRequestWB(url, @"GET", nil, NO, ^(id result) {
            NSString *d = [result isKindOfClass:[NSDictionary class]] || [result isKindOfClass:[NSArray class]]
                          ? [result description] : [NSString stringWithFormat:@"<%@>%@", NSStringFromClass([result class]), result];
            if (d.length > 2400) d = [[d substringToIndex:2400] stringByAppendingString:@"..."];
            XLog(@"[资料响应] uid=%@ 关系数据=%@", uid, d);
        }, ^(id e) {
            XLog(@"[资料响应] uid=%@ 请求失败 %@", uid, XHDumpResp(e));
        });
    });
}
// 从 URL 提取 /v2/users/{uid} 的数字 uid
static NSString *_viewerUIDFromURL(NSURL *u) {
    NSString *abs = [u absoluteString] ?: @"";
    NSRange r = [abs rangeOfString:@"/v2/users/"];
    if (r.location == NSNotFound) return nil;
    NSString *tail = [abs substringFromIndex:r.location + r.length];
    NSRange q = [tail rangeOfString:@"?"];
    if (q.location != NSNotFound) tail = [tail substringToIndex:q.location];
    NSRange s = [tail rangeOfString:@"/"];
    if (s.location != NSNotFound && s.location == 0) return nil;  // users/me/... 排除
    if ([tail isEqualToString:@"me"]) return nil;
    if ([tail rangeOfCharacterFromSet:[[NSCharacterSet decimalDigitCharacterSet] invertedSet]].location != NSNotFound) return nil;
    return tail;
}

// NSURLSession dataTaskWithRequest: (实例方法)
static id _dataTaskWithRequest_probe(id self, SEL _cmd, id request) {
    if (!_NET_HOOK_ENABLED) {
        if (_orig_dataTaskWithRequest) return ((id(*)(id, SEL, id))_orig_dataTaskWithRequest)(self, _cmd, request);
        return nil;
    }
    @try {
        NSURL *url = [request valueForKey:@"URL"];
        if (_shouldLogRequest(url)) {
            NSString *method = [request valueForKey:@"HTTPMethod"] ?: @"?";
            id body = [request valueForKey:@"HTTPBody"];
            NSString *bodyStr = @"";
            if (body) {
                bodyStr = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding] ?: @"(binary)";
                if (bodyStr.length > 400) bodyStr = [bodyStr substringToIndex:400];
            }
            {
                NSString *abs = [url absoluteString] ?: @"";
                if ([abs containsString:@"relationship"] || [abs containsString:@"/like"]
                    || [abs containsString:@"picks"] || [abs containsString:@"verify"]
                    || [abs containsString:@"liked-user"] || [abs containsString:@"see-likes"]
                    || [abs containsString:@"who-likes"] || [abs containsString:@"admire"]) {
                    XLog(@"[原生网络] %@ %@ body=%@", method, abs, bodyStr);
                }
            }
            // 修复 autoupdate devive_id 泄露真实 IDFV
            _tryFixDeviveIdInURL(request);
            _tryFixNetParam(request);
            // v29: viewer 资料 -> 自发同款请求抓关系数据
            {
                NSString *vuid = _viewerUIDFromURL(url);
                if (vuid && [[url absoluteString] containsString:@"source=viewer"]) _probeViewerRelationship(vuid);
            }
            // 伪造设备指纹: 改 oneid/idfv/idfa/identifier
            if ([method isEqualToString:@"POST"]) {
                _tryFakeDeviceFingerprint(request);
            }
            if (_ultraMatchRedirectEnabled && [url.absoluteString containsString:@"/me/relationships/"] && bodyStr && [bodyStr containsString:@"liked"]) {
                NSString *abs = url.absoluteString;
                NSRange rr = [abs rangeOfString:@"/me/relationships/"];
                if (rr.location != NSNotFound) {
                    NSString *tail = [abs substringFromIndex:rr.location + rr.length];
                    NSRange q = [tail rangeOfString:@"?"];
                    if (q.location != NSNotFound) tail = [tail substringToIndex:q.location];
                    tail = [tail stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"/"]];
                    if (tail.length > 0 && [tail rangeOfCharacterFromSet:[[NSCharacterSet decimalDigitCharacterSet] invertedSet]].location == NSNotFound) {
                        _doUltraMatchWithUID(tail);
                    }
                }
            }
        }
    } @catch (NSException *e) {}
    if (_orig_dataTaskWithRequest) {
        return ((id(*)(id, SEL, id))_orig_dataTaskWithRequest)(self, _cmd, request);
    }
    return nil;
}

// NSURLSession dataTaskWithRequest:completionHandler: (实例方法)
static id _dataTaskWithRequestHandler_probe(id self, SEL _cmd, id request, id completionHandler) {
    if (!_NET_HOOK_ENABLED) {
        if (_orig_dataTaskWithRequestHandler) return ((id(*)(id, SEL, id, id))_orig_dataTaskWithRequestHandler)(self, _cmd, request, completionHandler);
        return nil;
    }
    @try {
        NSURL *url = [request valueForKey:@"URL"];
        if (_shouldLogRequest(url)) {
            NSString *method = [request valueForKey:@"HTTPMethod"] ?: @"?";
            // 修复 autoupdate devive_id 泄露真实 IDFV
            _tryFixDeviveIdInURL(request);
            _tryFixNetParam(request);
            // v29: viewer 资料 -> 自发同款请求抓关系数据
            {
                NSString *vuid = _viewerUIDFromURL(url);
                if (vuid && [[url absoluteString] containsString:@"source=viewer"]) _probeViewerRelationship(vuid);
            }
            // 伪造设备指纹: 改 oneid/idfv/idfa/identifier
            if ([method isEqualToString:@"POST"]) {
                _tryFakeDeviceFingerprint(request);
            }
            // 发消息改造: v3 限流 -> 额外发 v2 接口(受开关控制)
            if ([method isEqualToString:@"POST"]) {
                _tryRewriteToGreeting(request);
            }
        }
    } @catch (NSException *e) {}
    if (_orig_dataTaskWithRequestHandler) {
        // v28: viewer 资料请求 -> 包装 completionHandler 抓响应原文
        @try {
            NSURL *u = [request valueForKey:@"URL"];
            NSString *abs = [u absoluteString] ?: @"";
            if ([abs containsString:@"source=viewer"]) {
                id wrapped = _wrapViewerRespBlock(completionHandler, abs);
                if (wrapped) completionHandler = wrapped;
            }
        } @catch (NSException *e) {}
        return ((id(*)(id, SEL, id, id))_orig_dataTaskWithRequestHandler)(self, _cmd, request, completionHandler);
    }
    return nil;
}


// ============================================================
// Hook 注册辅助: 对"多个候选类"都尝试 hook 同一个 selector
// (7.6.4 会员判断分散在多个类, 用多类兜底提升命中率)
// ============================================================
// v30: hook NSJSONSerialization, 抓解密后的关系数据 (绕过响应加密)
static IMP _orig_jsonObj = NULL;
static NSInteger g_relJsonLogged = 0;
static __attribute__((unused)) id _jsonObj_probe(id self, SEL _cmd, NSData *data, NSUInteger opt, NSError **err) {
    id r = ((id(*)(id, SEL, id, NSUInteger, NSError **))_orig_jsonObj)(self, _cmd, data, opt, err);
    @try {
        if (g_relJsonLogged < 60 && data.length > 200) {
            NSString *s = [r description];
            if ([s containsString:@"otherRelationType"] || [s containsString:@"otherStatus"]) {
                g_relJsonLogged++;
                if (s.length > 2500) s = [[s substringToIndex:2500] stringByAppendingString:@"..."];
                XLog(@"[关系JSON] %@", s);
            }
        }
        // 探针: 确认 hook 本身在工作 (只打前3条大响应)
        static NSInteger g_jsonProbe = 0;
        if (g_jsonProbe < 3 && data.length > 500) {
            g_jsonProbe++;
            NSString *s = r ? [r description] : @"(nil)";
            if (s.length > 400) s = [[s substringToIndex:400] stringByAppendingString:@"..."];
            XLog(@"[JSON探针] #%ld %luB %@", (long)g_jsonProbe, (unsigned long)data.length, s);
        }
    } @catch (NSException *e) {}
    return r;
}

static void TryHook(NSArray *classNames, SEL sel, IMP imp, BOOL isClassMethod) {
    for (NSString *name in classNames) {
        Class cls = objc_getClass(name.UTF8String);
        if (cls) {
            SwapMethod(cls, sel, imp, isClassMethod);
        }
    }
}

// 跨类 hook: 遍历所有类, 找到实现指定 selector 的类并 hook (用于定位认证状态方法的确切类)
static __attribute__((unused)) void TryHookAcrossAllClasses(SEL sel, IMP imp, NSString *logName) {
    int num = objc_getClassList(NULL, 0);
    if (num <= 0) return;
    Class *classes = (Class *)malloc(sizeof(Class) * num);
    num = objc_getClassList(classes, num);
    int hooked = 0;
    for (int i = 0; i < num && hooked < 20; i++) {
        Class cls = classes[i];
        if (!cls) continue;
        // 只 hook 探探自己的类 (PUG/TXT 前缀), 避免 hook 系统类
        const char *cname = class_getName(cls);
        if (!cname) continue;
        if (strncmp(cname, "PUG", 3) != 0 && strncmp(cname, "TXT", 3) != 0) continue;
        Method m = class_getInstanceMethod(cls, sel);
        if (!m) continue;
        IMP orig = method_getImplementation(m);
        if (orig == imp) continue;
        method_setImplementation(m, imp);
        XLog(@"[认证伪装] hook %@ 于类 %s", logName, cname);
        hooked++;
    }
    free(classes);
    if (hooked == 0) XLog(@"[认证伪装] 未找到实现 %@ 的类", logName);
}

// ============================================================
// 带日志的改机代码 (诊断版)
static NSString *kSpoofName = @"iPhone";
// 注意: IDFV/IDFA/oneid/localId 已改为随机生成(见文件顶部 _spoofIdentity/_spoofIDFV 等),
//       不再使用硬编码常量, 每次换机首次启动随机生成不重复指纹。
// IDFA 伪装: 广告标识符, 服务端识别同一物理设备的核心凭据
static NSUUID *spoof_idfa(id self, SEL _cmd) { XLog(@"[改机DEBUG] ASIdentifierManager.advertisingIdentifier 被调用 -> 返回伪IDFA"); return [[NSUUID alloc] initWithUUIDString:_spoofIDFA()]; }

// oneid 伪装: 探探设备唯一ID, 存于 NSUserDefaults suite "com.tantan.satistics_oneid_userdefaults"
// 现在随机生成, 见 _spoofOneId()
static id (*orig_NSUserDefaults_objectForKey)(id, SEL, NSString*) = NULL;

static id spoof_objectForKey(id self, SEL _cmd, NSString *key) {
    // 开关关闭时完全透传(行为与未 hook 一致)。读缓存, 绝不在此处读 NSUserDefaults(会递归闪退)
    if (!_gDevSpoofOn) {
        return orig_NSUserDefaults_objectForKey ? orig_NSUserDefaults_objectForKey(self, _cmd, key) : nil;
    }
    if (key) {
        // 精确匹配, 避免误拦 updateTime (它含 oneId.account 子串但值是 NSDate)
        if ([key isEqualToString:@"com.tantan.statistics.oneId.account"]) {
            // 诊断: 打印 self 类, 看探探读 oneid 用的什么实例
            id real = orig_NSUserDefaults_objectForKey ? orig_NSUserDefaults_objectForKey(self, _cmd, key) : nil;
            XLog(@"[改机] oneid读取 self类=%@ 真实值=%@ 返回伪值=%@", NSStringFromClass([self class]), real, _spoofOneId());
            return _spoofOneId();
        }
        if ([key isEqualToString:@"com.tantan.statistics.localId.account"]) {
            id real = orig_NSUserDefaults_objectForKey ? orig_NSUserDefaults_objectForKey(self, _cmd, key) : nil;
            XLog(@"[改机] localid读取 self类=%@ 真实值=%@ 返回伪值=%@", NSStringFromClass([self class]), real, _spoofLocalId());
            return _spoofLocalId();
        }
        // 数美 TXTOneId 设备指纹主键: 实测清完偏好+keychain 后仍会被 SDK 从别处恢复,
        // 因此直接在读取层接管, 保证数美上报的永远是新机的伪值。
        if ([key isEqualToString:@"ms_mid"] || [key isEqualToString:@"ms_n_mid"]) {
            NSString *fake = _spoofIdentity()[@"msMid"];
            XLog(@"[改机] %@读取 -> 返回伪值(数美新机)", key);
            return fake;
        }
        // 微博 SDK 机型拼接串: 实测值为真实机型(如 iPhone12,1), 会泄漏真机型号
        if ([key isEqualToString:@"machinePlatForm"]) {
            NSString *fake = _spoofIdentity()[@"wPlatform"];
            XLog(@"[改机] machinePlatForm读取 -> %@", fake);
            return fake;
        }
    }
    return orig_NSUserDefaults_objectForKey ? orig_NSUserDefaults_objectForKey(self, _cmd, key) : nil;
}

// 数美 ms_mid 写入接管: 无论 SDK 从哪读回来的, 最终落盘的都是伪值
static void (*orig_NSUserDefaults_setObject)(id, SEL, id, NSString*) = NULL;
static void spoof_setObject(id self, SEL _cmd, id value, NSString *key) {
    if (!_gDevSpoofOn) {
        if (orig_NSUserDefaults_setObject) orig_NSUserDefaults_setObject(self, _cmd, value, key);
        return;
    }
    if (key) {
        if ([key isEqualToString:@"ms_mid"] || [key isEqualToString:@"ms_n_mid"]) {
            NSString *fake = _spoofIdentity()[@"msMid"];
            NSString *show = [value isKindOfClass:[NSString class]] ? (NSString *)value : [value description];
            if (show.length > 24) show = [show substringToIndex:24];
            static int once = 0;
            if (once < 3) { once++; XLog(@"[改机] ms_mid写入拦截 原=%@... -> 伪值", show); }
            value = fake;
        } else if ([key isEqualToString:@"machinePlatForm"]) {
            value = _spoofIdentity()[@"wPlatform"];
        }
    }
    if (orig_NSUserDefaults_setObject) orig_NSUserDefaults_setObject(self, _cmd, value, key);
}

// 数美可能用 dictionaryRepresentation 一次性取全量键, 这里替换返回值里的设备指纹字段
static NSDictionary* (*orig_NSUserDefaults_dictRep)(id, SEL) = NULL;
static NSDictionary* spoof_dictionaryRepresentation(id self, SEL _cmd) {
    NSDictionary *d = orig_NSUserDefaults_dictRep ? orig_NSUserDefaults_dictRep(self, _cmd) : nil;
    if (!_gDevSpoofOn) return d;
    if (![d isKindOfClass:[NSDictionary class]]) return d;
    BOOL hasMS = (d[@"ms_mid"] != nil || d[@"ms_n_mid"] != nil);
    BOOL hasMP = (d[@"machinePlatForm"] != nil);
    if (!hasMS && !hasMP) return d;
    NSMutableDictionary *m = [d mutableCopy];
    NSString *fm = _spoofIdentity()[@"msMid"];
    NSString *fw = _spoofIdentity()[@"wPlatform"];
    if (m[@"ms_mid"]) m[@"ms_mid"] = fm;
    if (m[@"ms_n_mid"]) m[@"ms_n_mid"] = fm;
    if (m[@"machinePlatForm"]) m[@"machinePlatForm"] = fw;
    static int once2 = 0;
    if (once2 < 3) { once2++; XLog(@"[改机] dictionaryRepresentation 命中 ms_mid/machinePlatForm, 已替换为伪值"); }
    return m;
}

// ============================================================
// CFPreferences 写入拦截
// 实测(2026-11-24): ms_mid 走 NSUserDefaults 写入(已拦), 但 ms_n_mid / machinePlatForm
// 绕过 NSUserDefaults 直接调 CFPreferences 落盘, 所以磁盘上仍是真值。这里用 fishhook 截住。
// ============================================================
static void (*orig_CFPreferencesSetAppValue)(CFStringRef, CFPropertyListRef, CFStringRef) = NULL;
static void (*orig_CFPreferencesSetValue)(CFStringRef, CFPropertyListRef, CFStringRef, CFStringRef, CFStringRef) = NULL;

static CFPropertyListRef _xh_fix_pref_value(CFStringRef key, CFPropertyListRef value) {
    if (!_gDevSpoofOn || !key) return value;
    NSString *k = (__bridge NSString *)key;
    if ([k isEqualToString:@"ms_mid"] || [k isEqualToString:@"ms_n_mid"]) {
        static int o1 = 0;
        if (o1 < 3) { o1++; XLog(@"[改机] CFPreferences 写入拦截 %@ -> 伪值", k); }
        return (__bridge CFPropertyListRef)_spoofIdentity()[@"msMid"];
    }
    if ([k isEqualToString:@"machinePlatForm"]) {
        static int o2 = 0;
        if (o2 < 3) { o2++; XLog(@"[改机] CFPreferences 写入拦截 machinePlatForm -> 伪值"); }
        return (__bridge CFPropertyListRef)_spoofIdentity()[@"wPlatform"];
    }
    return value;
}
static void xh_CFPreferencesSetAppValue(CFStringRef key, CFPropertyListRef value, CFStringRef app) {
    if (orig_CFPreferencesSetAppValue) orig_CFPreferencesSetAppValue(key, _xh_fix_pref_value(key, value), app);
}
static void xh_CFPreferencesSetValue(CFStringRef key, CFPropertyListRef value, CFStringRef app, CFStringRef user, CFStringRef host) {
    if (orig_CFPreferencesSetValue) orig_CFPreferencesSetValue(key, _xh_fix_pref_value(key, value), app, user, host);
}

static void hook_oneid(void) {
    Class c = NSClassFromString(@"NSUserDefaults");
    if (!c) return;
    Method m = class_getInstanceMethod(c, @selector(objectForKey:));
    if (m) {
        orig_NSUserDefaults_objectForKey = (id(*)(id, SEL, NSString*))method_getImplementation(m);
        method_setImplementation(m, (IMP)spoof_objectForKey);
        XLog(@"[改机] oneid hook 完成 (objectForKey:)");
    }
    // 数美 ms_mid 实测不走 objectForKey:, 追加两条更宽的路径:
    //   setObject:forKey:            -> 接管写入, 让磁盘里存的就是伪值
    //   dictionaryRepresentation     -> 接管全量读取(SDK 常用 dictionaryRepresentation 取一堆键)
    Method ms = class_getInstanceMethod(c, @selector(setObject:forKey:));
    if (ms) {
        orig_NSUserDefaults_setObject = (void(*)(id, SEL, id, NSString*))method_getImplementation(ms);
        method_setImplementation(ms, (IMP)spoof_setObject);
        XLog(@"[改机] ms_mid hook 完成 (setObject:forKey:)");
    }
    Method md = class_getInstanceMethod(c, @selector(dictionaryRepresentation));
    if (md) {
        orig_NSUserDefaults_dictRep = (NSDictionary*(*)(id, SEL))method_getImplementation(md);
        method_setImplementation(md, (IMP)spoof_dictionaryRepresentation);
        XLog(@"[改机] ms_mid hook 完成 (dictionaryRepresentation)");
    }
    // CFPreferences 写入路径(数美 ms_n_mid / 微博 machinePlatForm 走这条)
    rebind_symbols((struct rebinding[]){
        {"CFPreferencesSetAppValue", (void *)xh_CFPreferencesSetAppValue, (void **)&orig_CFPreferencesSetAppValue},
        {"CFPreferencesSetValue",    (void *)xh_CFPreferencesSetValue,    (void **)&orig_CFPreferencesSetValue},
    }, 2);
    XLog(@"[改机] CFPreferences 写入 hook 完成");

    // ------------------------------------------------------------------
    // 补清 +load 阶段写入的残留。
    // 微博 SDK 静态链接在主二进制里, 通过 +load 初始化并写 machinePlatForm,
    // +load 的执行早于本 dylib 的 constructor -> 我们 hook 注册时它已经写完了。
    // 这里用 orig 直接读一次(绕过自己的 hook), 验证假设并立即清掉, 之后 SDK 再写会被 hook 改成伪值。
    // ------------------------------------------------------------------
    if (_gDevSpoofOn && orig_NSUserDefaults_objectForKey) {
        NSUserDefaults *ud0 = [NSUserDefaults standardUserDefaults];
        id mpRaw = orig_NSUserDefaults_objectForKey(ud0, @selector(objectForKey:), @"machinePlatForm");
        id msnRaw = orig_NSUserDefaults_objectForKey(ud0, @selector(objectForKey:), @"ms_n_mid");
        XLog(@"[诊断] hook 注册瞬间: machinePlatForm=%@ ms_n_mid=%@ (有值=早于hook写入, 证实+load时序)",
             mpRaw ? @"有" : @"无", msnRaw ? @"有" : @"无");
        [ud0 removeObjectForKey:@"machinePlatForm"];
        [ud0 removeObjectForKey:@"ms_mid"];
        [ud0 removeObjectForKey:@"ms_n_mid"];
        [ud0 synchronize];
        XLog(@"[改机] 已补清 +load 阶段残留(machinePlatForm/ms_mid/ms_n_mid)");
    }
    // 注意: 不再 hook stringForKey:。
    //       stringForKey: 内部就是调 objectForKey:, hook objectForKey 已覆盖;
    //       重复 hook stringForKey: 会导致 IMP 与 selector 错配(_cmd=stringForKey: 却调 objectForKey 的 orig),
    //       在 TXTOneId(数美指纹SDK) 大量调用 stringForKey: 时栈破坏 -> 跳空指针闪退。
}

static NSUUID *spoof_idfv(id self, SEL _cmd) { XLog(@"[改机DEBUG] UIDevice.identifierForVendor 被调用 -> 返回伪IDFV"); return [[NSUUID alloc] initWithUUIDString:_spoofIDFV()]; }
static NSString *spoof_name(id self, SEL _cmd) { return kSpoofName; }
static NSString *spoof_model(id self, SEL _cmd) { return _spoofModelName(); }
static NSString *spoof_sysver(id self, SEL _cmd) { return _spoofOSString(); }
static NSString *spoof_localizedModel(id self, SEL _cmd) { return _spoofModelName(); }
static NSString *spoof_sysname(id self, SEL _cmd) { return @"iOS"; }

// 伪装: 拦截 SecItemCopyMatching, 替换探探从 keychain 读的 oneid/localid。
typedef int (*sysctl_fn)(int *, unsigned int, void *, size_t *, const void *, size_t);
static sysctl_fn orig_sysctl = NULL;
static int spoof_sysctl(int *name, unsigned int namelen, void *oldp, size_t *oldlenp, const void *newp, size_t newlen) {
    // CTL_HW = 6
    if (name && namelen >= 2 && name[0] == 6) {
        // HW_MACHINE=1 / HW_MODEL=2: 机器型号字符串
        if (name[1] == 1 || name[1] == 2) {
            const char *v = _spoofProduct().UTF8String;
            XLog(@"[改机DEBUG] sysctl(hw.machine/hw.model) -> 返回 %s", v);
            size_t need = strlen(v) + 1;
            if (oldlenp) {
                if (oldp == NULL) { *oldlenp = need; return 0; }
                if (*oldlenp >= need) { strcpy((char *)oldp, v); *oldlenp = need; return 0; }
                *oldlenp = need; return -1;
            }
            return 0;
        }
        // HW_MEMSIZE=24: 物理内存字节数 (方案1: A13 同代, 动态取伪机型)
        if (name[1] == 24) {
            uint64_t v = _spoofMemBytes();
            XLog(@"[改机DEBUG] sysctl(hw.memsize) -> 返回 %llu MB", v / 1048576ULL);
            if (oldlenp) {
                if (oldp == NULL) { *oldlenp = sizeof(v); return 0; }
                if (*oldlenp >= sizeof(v)) { memcpy(oldp, &v, sizeof(v)); *oldlenp = sizeof(v); return 0; }
                *oldlenp = sizeof(v); return -1;
            }
            return 0;
        }
        // HW_NCPU=3: 逻辑CPU核数
        if (name[1] == 3 || name[1] == 25 || name[1] == 28 || name[1] == 29) {
            int v = _spoofCPUCount();
            XLog(@"[改机DEBUG] sysctl(hw.ncpu/physicalcpu) -> 返回 %d", v);
            if (oldlenp) {
                if (oldp == NULL) { *oldlenp = sizeof(v); return 0; }
                if (*oldlenp >= sizeof(v)) { memcpy(oldp, &v, sizeof(v)); *oldlenp = sizeof(v); return 0; }
                *oldlenp = sizeof(v); return -1;
            }
            return 0;
        }
    }
    // CTL_KERN=1, KERN_BOOTTIME=21
    if (name && namelen >= 2 && name[0] == 1 && name[1] == 21) {
        struct timeval tv;
        tv.tv_sec = (time_t)_spoofBootEpoch();
        tv.tv_usec = 0;
        if (oldlenp) {
            if (oldp == NULL) { *oldlenp = sizeof(tv); return 0; }
            if (*oldlenp >= sizeof(tv)) { memcpy(oldp, &tv, sizeof(tv)); *oldlenp = sizeof(tv); return 0; }
            *oldlenp = sizeof(tv); return -1;
        }
        return 0;
    }
    return orig_sysctl ? orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen) : -1;
}

// sysctlbyname 是 CAID/设备指纹 SDK 最常用的采集入口 (sysctlbyname("hw.machine", ...))
typedef int (*sysctlbyname_fn)(const char *, void *, size_t *, void *, size_t);
static sysctlbyname_fn orig_sysctlbyname = NULL;
static int spoof_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (name) {
        // 机器型号字符串
        if (strcmp(name, "hw.machine") == 0 || strcmp(name, "hw.model") == 0 || strcmp(name, "hw.product") == 0) {
            const char *v = _spoofProduct().UTF8String;
            XLog(@"[改机DEBUG] sysctlbyname(%s) 被调用 -> 返回 %s", name, v);
            size_t need = strlen(v) + 1;
            if (oldlenp) {
                if (oldp == NULL) { *oldlenp = need; return 0; }
                if (*oldlenp >= need) { strcpy((char *)oldp, v); *oldlenp = need; return 0; }
                *oldlenp = need; return -1;
            }
            return 0;
        }
        // 物理内存
        if (strcmp(name, "hw.memsize") == 0) {
            uint64_t v = _spoofMemBytes();
            XLog(@"[改机DEBUG] sysctlbyname(hw.memsize) -> 返回 %llu MB", v / 1048576ULL);
            if (oldlenp) {
                if (oldp == NULL) { *oldlenp = sizeof(v); return 0; }
                if (*oldlenp >= sizeof(v)) { memcpy(oldp, &v, sizeof(v)); *oldlenp = sizeof(v); return 0; }
                *oldlenp = sizeof(v); return -1;
            }
            return 0;
        }
        // CPU 核数
        if (strcmp(name, "hw.ncpu") == 0 || strcmp(name, "hw.physicalcpu") == 0 || strcmp(name, "hw.logicalcpu") == 0) {
            int v = _spoofCPUCount();
            XLog(@"[改机DEBUG] sysctlbyname(%s) -> 返回 %d", name, v);
            if (oldlenp) {
                if (oldp == NULL) { *oldlenp = sizeof(v); return 0; }
                if (*oldlenp >= sizeof(v)) { memcpy(oldp, &v, sizeof(v)); *oldlenp = sizeof(v); return 0; }
                *oldlenp = sizeof(v); return -1;
            }
            return 0;
        }
        // 内核版本号 (方案1: iOS 13.6 -> kern.osversion=17G68, 与伪机型一致)
        if (strcmp(name, "kern.osversion") == 0 || strcmp(name, "kern.osrelease") == 0) {
            const char *v = _spoofBuildString().UTF8String;
            size_t need = strlen(v) + 1;
            XLog(@"[改机DEBUG] sysctlbyname(%s) -> 返回 %s", name, v);
            if (oldlenp) {
                if (oldp == NULL) { *oldlenp = need; return 0; }
                if (*oldlenp >= need) { strcpy((char *)oldp, v); *oldlenp = need; return 0; }
                *oldlenp = need; return -1;
            }
            return 0;
        }
        if (strcmp(name, "kern.boottime") == 0) {
            struct timeval tv;
            tv.tv_sec = (time_t)_spoofBootEpoch();
            tv.tv_usec = 0;
            if (oldlenp) {
                if (oldp == NULL) { *oldlenp = sizeof(tv); return 0; }
                if (*oldlenp >= sizeof(tv)) { memcpy(oldp, &tv, sizeof(tv)); *oldlenp = sizeof(tv); return 0; }
                *oldlenp = sizeof(tv); return -1;
            }
            return 0;
        }
    }
    return orig_sysctlbyname ? orig_sysctlbyname(name, oldp, oldlenp, newp, newlen) : -1;
}

// ---- NSProcessInfo: 内存 / CPU ----
static uint64_t spoof_physmem(id self, SEL _cmd) { return _spoofMemBytes(); }
static NSUInteger spoof_cpucount(id self, SEL _cmd) { return (NSUInteger)_spoofCPUCount(); }

// ---- NSFileManager: 磁盘容量 ----
static id (*orig_attrsFS)(id, SEL, NSString *, NSError **);
static id spoof_attrsFS(id self, SEL _cmd, NSString *path, NSError **err) {
    NSDictionary *real = orig_attrsFS ? orig_attrsFS(self, _cmd, path, err) : nil;
    if (![real isKindOfClass:[NSDictionary class]]) return real;
    NSMutableDictionary *m = [real mutableCopy];
    uint64_t total = _spoofDiskBytes();
    m[NSFileSystemSize] = @(total);
    m[NSFileSystemFreeSize] = @(total / 3);
    return m;
}

typedef int (*uname_fn)(struct utsname *);
static uname_fn orig_uname = NULL;
static int spoof_uname(struct utsname *u) {
    int ret = orig_uname ? orig_uname(u) : -1;
    XLog(@"[改机DEBUG] uname 被调用");
    if (ret == 0 && u) {
        const char *m = _spoofProduct().UTF8String;
        if (m) snprintf(u->machine, sizeof(u->machine), "%s", m);
        strcpy(u->sysname, "Darwin");
    }
    return ret;
}

// host_statistics64: Mach 底层内存/CPU 统计 (探探 physicalMemory 可能来自这里)
#include <mach/mach.h>
#include <mach/host_info.h>
typedef kern_return_t (*host_statistics64_fn)(host_t, host_flavor_t, host_info64_t, mach_msg_type_number_t *);
static host_statistics64_fn orig_host_statistics64 = NULL;

static kern_return_t spoof_host_statistics64(host_t host_priv, host_flavor_t flavor, host_info64_t info, mach_msg_type_number_t *count) {
    kern_return_t ret = orig_host_statistics64 ? orig_host_statistics64(host_priv, flavor, info, count) : KERN_FAILURE;
    if (ret == KERN_SUCCESS && info) {
        // HOST_VM_INFO64 = 4: 返回 vm_statistics64, 但物理内存总量在 HOST_BASIC_INFO
        // HOST_BASIC_INFO = 1
        if (flavor == HOST_BASIC_INFO) {
            host_basic_info_data_t *basic = (host_basic_info_data_t *)info;
            XLog(@"[改机DEBUG] host_statistics64(HOST_BASIC_INFO) -> max_mem=%llu 原值", (unsigned long long)basic->max_mem);
            // 方案1: 与伪机型池对齐 (A13 同代 4GB / SE2 3GB)
            basic->max_mem = _spoofMemBytes();
            XLog(@"[改机DEBUG] host_statistics64 -> max_mem 改为 %llu", (unsigned long long)basic->max_mem);
        }
    }
    return ret;
}

// sysconf: libc 系统配置查询 (物理内存页数、CPU 核数等)
typedef long (*sysconf_fn)(int);
static sysconf_fn orig_sysconf = NULL;
static long spoof_sysconf(int name) {
    // 方案1: 与 A13 同代对齐 (4GB/16KB 页 = 262144 页; SE2 3GB = 196608)
    uint64_t mem = _spoofMemBytes();
    long pages = (long)(mem / 16384ULL);
    if (name == 200) { // _SC_PHYS_PAGES
        XLog(@"[改机DEBUG] sysconf(_SC_PHYS_PAGES) -> 返回 %ld (%.0fGB/16KB)", pages, mem / 1073741824.0);
        return pages;
    }
    if (name == 58) { // _SC_NPROCESSORS_CONF
        return _spoofCPUCount();
    }
    if (name == 57) { // _SC_NPROCESSORS_ONLN
        return _spoofCPUCount();
    }
    return orig_sysconf ? orig_sysconf(name) : -1;
}

typedef int (*gethostname_fn)(char *, size_t);
static gethostname_fn orig_gethostname = NULL;
static int spoof_gethostname(char *n, size_t l) {
    int ret = orig_gethostname ? orig_gethostname(n, l) : -1;
    XLog(@"[改机DEBUG] gethostname 被调用");
    if (ret == 0 && n && l > 16) strcpy(n, "iPhone");
    return ret;
}

typedef int (*access_fn)(const char *, int);
static access_fn orig_access = NULL;
static int spoof_access(const char *p, int m) {
    if (p) {
        const char *jp[] = {"/Applications/Cydia.app","/Library/MobileSubstrate","/usr/bin/ssh","/usr/sbin/sshd","/etc/apt","/bin/bash","/private/var/stash","/usr/libexec/cydia","/.installed_yaluX","/jb","/usr/bin/cycript","/usr/lib/libcycript.dylib",NULL};
        for (int i=0; jp[i]; i++) if (strcmp(p, jp[i])==0) { XLog(@"[改机DEBUG] access(越狱路径=%s) 被拦截", p); errno = ENOENT; return -1; }
    }
    return orig_access ? orig_access(p, m) : -1;
}

static NSString *spoof_osverstr(id self, SEL _cmd) {
    // 必须与伪机型匹配 (方案1: A13 同代 iOS 13.6), 否则交叉校验露馅
    return [NSString stringWithFormat:@"Version %@ (Build %@)", _spoofOSString(), _spoofBuildString()];
}

static unsigned long long spoof_physicalMemory(id self, SEL _cmd) {
    // 按伪机型返回对应内存 (方案1: 3~4GB), 与机型池保持一致
    return _spoofMemBytes();
}

static unsigned long long spoof_processorCount(id self, SEL _cmd) {
    return (unsigned long long)_spoofCPUCount();
}

// ============ 版本号伪造 ============
// 探探服务端对 7.6.4 的第三方登录(微信 signin)返回 403(强制升级),
// 把版本号伪装成 7.6.4(764 适配版)
// 版本号可配置: 用户可在设置面板自定义, 持久化到 NSUserDefaults。
// 版本伪装开关已由 XH_SW_SPOOFVER 统一控制 (见顶部开关系统)
static NSString *kSpoofBuildVersion = @"6.9.9.0"; // 伪装的构建版本(699 适配)

// 版本号存储 key (NSUserDefaults)
static NSString *const kSpoofVersionDefaultsKey = @"xh_spoof_version";

// 读取当前伪装版本号 (用户自定义优先, 否则默认 6.9.9)
static NSString *_currentSpoofVersion(void) {
    NSString *v = [[NSUserDefaults standardUserDefaults] stringForKey:kSpoofVersionDefaultsKey];
    if (v && v.length > 0) return v;
    return @"6.9.9";
}

// 导出: 设置伪装版本号 (供设置面板调用, 持久化到 NSUserDefaults)
void XHSetSpoofVersion(NSString *version) {
    if (!version || version.length == 0) {
        [[NSUserDefaults standardUserDefaults] removeObjectForKey:kSpoofVersionDefaultsKey];
    } else {
        [[NSUserDefaults standardUserDefaults] setObject:version forKey:kSpoofVersionDefaultsKey];
    }
    [[NSUserDefaults standardUserDefaults] synchronize];
    XLog(@"[版本伪造] 已设置伪装版本号为 %@", version ?: @"(默认 6.9.9)");
}

// 导出: 获取当前伪装版本号
NSString *XHGetSpoofVersion(void) {
    return _currentSpoofVersion();
}

static IMP _orig_objectForInfoDictionaryKey = NULL;
// objectForInfoDictionaryKey: 是 NSBundle 的实例方法, 探探读 CFBundleShortVersionString 的底层入口
static id spoof_objectForInfoDictionaryKey(id self, SEL _cmd, id key) {
    id result = nil;
    if (_orig_objectForInfoDictionaryKey) {
        result = ((id(*)(id, SEL, id))_orig_objectForInfoDictionaryKey)(self, _cmd, key);
    }
    if (_swOn(XH_SW_SPOOFVER) && key && [key isKindOfClass:[NSString class]]) {
        NSString *k = (NSString *)key;
        if ([k isEqualToString:@"CFBundleShortVersionString"] || [k isEqualToString:@"CFBundleVersion"]) {
            NSString *spoofV = _currentSpoofVersion();
            return spoofV;
        }
    }
    return result;
}

// 补: infoDictionary (AppsFlyer/其它 SDK 常直接拿整个字典再取 key, 绕过 objectForInfoDictionaryKey:)
static IMP _orig_infoDictionary = NULL;
static id spoof_infoDictionary(id self, SEL _cmd) {
    id result = nil;
    if (_orig_infoDictionary) {
        result = ((id(*)(id, SEL))_orig_infoDictionary)(self, _cmd);
    }
    if (_swOn(XH_SW_SPOOFVER) && result && [result isKindOfClass:[NSDictionary class]]) {
        NSMutableDictionary *md = [result mutableCopy];
        NSString *spoofV = _currentSpoofVersion();
        // 同时伪造短版本号和构建号, 覆盖所有读版本的路径
        md[@"CFBundleShortVersionString"] = spoofV;
        md[@"CFBundleVersion"] = kSpoofBuildVersion;
        return md;
    }
    return result;
}
// localizedInfoDictionary 同理(某些 SDK 用)
static IMP _orig_localizedInfoDictionary = NULL;
static id spoof_localizedInfoDictionary(id self, SEL _cmd) {
    id result = nil;
    if (_orig_localizedInfoDictionary) {
        result = ((id(*)(id, SEL))_orig_localizedInfoDictionary)(self, _cmd);
    }
    if (_swOn(XH_SW_SPOOFVER) && result && [result isKindOfClass:[NSDictionary class]]) {
        NSMutableDictionary *md = [result mutableCopy];
        NSString *spoofV = _currentSpoofVersion();
        md[@"CFBundleShortVersionString"] = spoofV;
        md[@"CFBundleVersion"] = kSpoofBuildVersion;
        return md;
    }
    return result;
}

// 兼容: 探探可能直接用 infoDictionary 字典再取 key, 这里不拦(性能考虑), 仅拦 objectForInfoDictionaryKey:
// 同时伪造 [[NSBundle mainBundle] infoDictionary][@"CFBundleShortVersionString"] 需 hook infoDictionary,
// 但先只做 objectForInfoDictionaryKey:, 若不够再补 infoDictionary。



// 【认证闪退修复】改机硬开关: 认证活体SDK(阿里ZIM)检测到伪型号/伪iOS版本/越狱hook就闪退
// 机型池已换成 A13 同代(与真机 iPhone 11 硬件对齐), 全套系统级改机不再触发 ZIM 交叉校验, 设为 1
// 注意: 版本号伪装(只改 CFBundleShortVersionString/CFBundleVersion)不影响活体SDK, 独立于本开关
#define ENABLE_DEVICE_SPOOF 1

static void spoof_version_init(void) {
    // 版本号伪造独立注册 (受 XH_SW_SPOOFVER 开关控制), 不依赖设备改机开关
    if (!_swOn(XH_SW_SPOOFVER)) {
        XLog(@"[版本伪造] 版本伪装开关已关闭, 跳过 hook");
        return;
    }
    Class bundleCls = objc_getClass("NSBundle");
    if (bundleCls) {
        Method vm = class_getInstanceMethod(bundleCls, @selector(objectForInfoDictionaryKey:));
        if (vm) {
            if (!_orig_objectForInfoDictionaryKey) {
                _orig_objectForInfoDictionaryKey = method_getImplementation(vm);
                method_setImplementation(vm, (IMP)spoof_objectForInfoDictionaryKey);
                XLog(@"[版本伪造] 已 hook NSBundle objectForInfoDictionaryKey: -> %@", _currentSpoofVersion());
            }
        } else {
            XLog(@"[版本伪造] NSBundle objectForInfoDictionaryKey: 方法不存在");
        }
        // 补 hook infoDictionary (AppsFlyer 等 SDK 拿整个字典再取 key 会绕过上面那个)
        Method im = class_getInstanceMethod(bundleCls, @selector(infoDictionary));
        if (im) {
            if (!_orig_infoDictionary) {
                _orig_infoDictionary = method_getImplementation(im);
                method_setImplementation(im, (IMP)spoof_infoDictionary);
                XLog(@"[版本伪造] 已 hook NSBundle infoDictionary -> %@", _currentSpoofVersion());
            }
        }
        // localizedInfoDictionary
        Method lm = class_getInstanceMethod(bundleCls, @selector(localizedInfoDictionary));
        if (lm) {
            if (!_orig_localizedInfoDictionary) {
                _orig_localizedInfoDictionary = method_getImplementation(lm);
                method_setImplementation(lm, (IMP)spoof_localizedInfoDictionary);
                XLog(@"[版本伪造] 已 hook NSBundle localizedInfoDictionary");
            }
        }
    }
}

// ============================================================
// 剪贴板读取阻断
// 探探可读取 UIPasteboard(你复制过的文本/链接), 是唯一的跨 App 信息通道。
// 这里只拦"读取", 不动"写入", 因此你自己复制内容的功能不受影响。
// 受"设备改机"开关控制: 关闭时完全透传。
// ============================================================
static NSString* (*orig_pb_string)(id,SEL) = NULL;
static NSArray*  (*orig_pb_strings)(id,SEL) = NULL;
static NSURL*    (*orig_pb_URL)(id,SEL) = NULL;
static NSArray*  (*orig_pb_URLs)(id,SEL) = NULL;
static BOOL      (*orig_pb_hasStrings)(id,SEL) = NULL;
static BOOL      (*orig_pb_hasURLs)(id,SEL) = NULL;
static NSArray*  (*orig_pb_items)(id,SEL) = NULL;
static NSArray*  (*orig_pb_pasteboardItems)(id,SEL) = NULL;
static NSInteger (*orig_pb_numberOfItems)(id,SEL) = NULL;
static BOOL      (*orig_pb_containsTypes)(id,SEL,NSArray*) = NULL;
static NSData*   (*orig_pb_dataForType)(id,SEL,NSString*) = NULL;

static int _pbLogCount = 0;
static void _pbLog(NSString *tag) {
    if (_pbLogCount < 6) { _pbLogCount++; XLog(@"[改机] 剪贴板读取拦截: %@", tag); }
}

static NSString* spoof_pb_string(id self, SEL _cmd) {
    if (!_gDevSpoofOn) return orig_pb_string ? orig_pb_string(self,_cmd) : nil;
    _pbLog(@"string"); return nil;
}
static NSArray* spoof_pb_strings(id self, SEL _cmd) {
    if (!_gDevSpoofOn) return orig_pb_strings ? orig_pb_strings(self,_cmd) : nil;
    _pbLog(@"strings"); return nil;
}
static NSURL* spoof_pb_URL(id self, SEL _cmd) {
    if (!_gDevSpoofOn) return orig_pb_URL ? orig_pb_URL(self,_cmd) : nil;
    _pbLog(@"URL"); return nil;
}
static NSArray* spoof_pb_URLs(id self, SEL _cmd) {
    if (!_gDevSpoofOn) return orig_pb_URLs ? orig_pb_URLs(self,_cmd) : nil;
    _pbLog(@"URLs"); return nil;
}
static BOOL spoof_pb_hasStrings(id self, SEL _cmd) {
    if (!_gDevSpoofOn) return orig_pb_hasStrings ? orig_pb_hasStrings(self,_cmd) : NO;
    _pbLog(@"hasStrings"); return NO;
}
static BOOL spoof_pb_hasURLs(id self, SEL _cmd) {
    if (!_gDevSpoofOn) return orig_pb_hasURLs ? orig_pb_hasURLs(self,_cmd) : NO;
    _pbLog(@"hasURLs"); return NO;
}
static NSArray* spoof_pb_items(id self, SEL _cmd) {
    if (!_gDevSpoofOn) return orig_pb_items ? orig_pb_items(self,_cmd) : nil;
    _pbLog(@"items"); return nil;
}
static NSArray* spoof_pb_pasteboardItems(id self, SEL _cmd) {
    if (!_gDevSpoofOn) return orig_pb_pasteboardItems ? orig_pb_pasteboardItems(self,_cmd) : nil;
    _pbLog(@"pasteboardItems"); return nil;
}
static NSInteger spoof_pb_numberOfItems(id self, SEL _cmd) {
    if (!_gDevSpoofOn) return orig_pb_numberOfItems ? orig_pb_numberOfItems(self,_cmd) : 0;
    _pbLog(@"numberOfItems"); return 0;
}
static BOOL spoof_pb_containsTypes(id self, SEL _cmd, NSArray *types) {
    if (!_gDevSpoofOn) return orig_pb_containsTypes ? orig_pb_containsTypes(self,_cmd,types) : NO;
    _pbLog(@"containsPasteboardTypes"); return NO;
}
static NSData* spoof_pb_dataForType(id self, SEL _cmd, NSString *type) {
    if (!_gDevSpoofOn) return orig_pb_dataForType ? orig_pb_dataForType(self,_cmd,type) : nil;
    _pbLog(@"dataForPasteboardType"); return nil;
}

static void XHInstallPasteboardHooks(void) {
    static BOOL done = NO;
    if (done) return;
    if (!NSClassFromString(@"UIPasteboard")) return;
    done = YES;
    TryHook(@[@"UIPasteboard"], @selector(string), (IMP)spoof_pb_string, NO);
    TryHook(@[@"UIPasteboard"], @selector(strings), (IMP)spoof_pb_strings, NO);
    TryHook(@[@"UIPasteboard"], @selector(URL), (IMP)spoof_pb_URL, NO);
    TryHook(@[@"UIPasteboard"], @selector(URLs), (IMP)spoof_pb_URLs, NO);
    TryHook(@[@"UIPasteboard"], @selector(hasStrings), (IMP)spoof_pb_hasStrings, NO);
    TryHook(@[@"UIPasteboard"], @selector(hasURLs), (IMP)spoof_pb_hasURLs, NO);
    TryHook(@[@"UIPasteboard"], @selector(items), (IMP)spoof_pb_items, NO);
    TryHook(@[@"UIPasteboard"], @selector(pasteboardItems), (IMP)spoof_pb_pasteboardItems, NO);
    TryHook(@[@"UIPasteboard"], @selector(numberOfItems), (IMP)spoof_pb_numberOfItems, NO);
    TryHook(@[@"UIPasteboard"], @selector(containsPasteboardTypes:), (IMP)spoof_pb_containsTypes, NO);
    TryHook(@[@"UIPasteboard"], @selector(dataForPasteboardType:), (IMP)spoof_pb_dataForType, NO);
    XLog(@"[改机] 剪贴板读取 hook 完成 (11 个入口)");
}

// ============================================================
// ATT 授权状态 + 传感器可用性伪装
// ATT: 改了 IDFA 但授权状态没改会自相矛盾 -> 统一返回 Authorized(3)
// 传感器: 返回"不可用", 让探探拿不到加速度/陀螺/磁力计数据(硬件特征指纹)
// ============================================================
static NSInteger (*orig_attStatus)(id,SEL) = NULL;
static BOOL (*orig_accelAvail)(id,SEL) = NULL;
static BOOL (*orig_gyroAvail)(id,SEL) = NULL;
static BOOL (*orig_magAvail)(id,SEL) = NULL;
static BOOL (*orig_motionAvail)(id,SEL) = NULL;

static NSInteger spoof_attStatus(id self, SEL _cmd) {
    if (!_gDevSpoofOn) return orig_attStatus ? orig_attStatus(self,_cmd) : 2;
    static int o = 0;
    if (o < 2) { o++; XLog(@"[改机] ATTrackingManager.trackingAuthorizationStatus -> Authorized(3)"); }
    return 3; // ATTrackingManagerAuthorizationStatusAuthorized
}
static BOOL spoof_accelAvail(id self, SEL _cmd) {
    if (!_gDevSpoofOn) return orig_accelAvail ? orig_accelAvail(self,_cmd) : NO;
    return NO;
}
static BOOL spoof_gyroAvail(id self, SEL _cmd) {
    if (!_gDevSpoofOn) return orig_gyroAvail ? orig_gyroAvail(self,_cmd) : NO;
    return NO;
}
static BOOL spoof_magAvail(id self, SEL _cmd) {
    if (!_gDevSpoofOn) return orig_magAvail ? orig_magAvail(self,_cmd) : NO;
    return NO;
}
static BOOL spoof_motionAvail(id self, SEL _cmd) {
    if (!_gDevSpoofOn) return orig_motionAvail ? orig_motionAvail(self,_cmd) : NO;
    return NO;
}

static void XHInstallTrackerAndMotionHooks(void) {
    static BOOL done = NO;
    if (done) return;
    done = YES;
    Class att = NSClassFromString(@"ATTrackingManager");
    if (att) {
        orig_attStatus = (NSInteger(*)(id,SEL))SwapMethod(att, @selector(trackingAuthorizationStatus), (IMP)spoof_attStatus, YES);
    }
    Class mc = NSClassFromString(@"CMMotionManager");
    if (mc) {
        orig_accelAvail  = (BOOL(*)(id,SEL))SwapMethod(mc, @selector(isAccelerometerAvailable), (IMP)spoof_accelAvail, NO);
        orig_gyroAvail   = (BOOL(*)(id,SEL))SwapMethod(mc, @selector(isGyroAvailable), (IMP)spoof_gyroAvail, NO);
        orig_magAvail    = (BOOL(*)(id,SEL))SwapMethod(mc, @selector(isMagnetometerAvailable), (IMP)spoof_magAvail, NO);
        orig_motionAvail = (BOOL(*)(id,SEL))SwapMethod(mc, @selector(isDeviceMotionAvailable), (IMP)spoof_motionAvail, NO);
    }
    XLog(@"[改机] ATT授权/传感器 hook 完成 (ATT=%d Motion=%d)", att != nil, mc != nil);
}

// 前置声明: spoof_statfs/orig_statfs 实际定义在 deep 模块(靠后), 此处 fishhook 注册需要
static int (*orig_statfs)(const char *, struct statfs *);
static int spoof_statfs(const char *path, struct statfs *buf);

static void spoof_device_init(void) {
#if !ENABLE_DEVICE_SPOOF
    XLog(@"[改机] 设备改机已硬禁用 (认证安全模式), 版本伪装独立生效");
    return;
#endif
    XLog(@"[改机] 开始系统级设备指纹伪造");
    // 剪贴板读取阻断: 无条件注册 hook(内部按开关判断), 保证面板切换即时生效
    XHInstallPasteboardHooks();
    // ATT 授权状态 + 传感器可用性(内部同样按开关判断)
    XHInstallTrackerAndMotionHooks();
    // 系统级改机跟随"设备改机"开关: 首次打开(未勾选)不伪装, 只清理数据
    if (!_swOn(XH_SW_DEVICE)) {
        XLog(@"[改机] 设备改机开关未开启, 跳过系统级指纹伪造 (首次打开仅清理数据)");
        return;
    }

    // ---- 系统级指纹 hook 全开 (机型池 A13 同代, 规避 ZIM 交叉校验) ----
    // 组1: IDFV
    {
        TryHook(@[@"UIDevice"], @selector(identifierForVendor), (IMP)spoof_idfv, NO);
    }
    // 组2: IDFA
    TryHook(@[@"ASIdentifierManager"], @selector(advertisingIdentifier), (IMP)spoof_idfa, NO);
    // 组3: oneid
    // 注: hook_oneid() 已改到 constructor 最开头无条件注册(避免漏拦早期 SDK 写入),
    //     这里不能再调用, 否则 orig 指针指向自身造成无限递归。
    // hook_oneid();
    // 组4: UIDevice 机型/系统版本/设备名
    TryHook(@[@"UIDevice"], @selector(name), (IMP)spoof_name, NO);
    TryHook(@[@"UIDevice"], @selector(model), (IMP)spoof_model, NO);
    TryHook(@[@"UIDevice"], @selector(systemVersion), (IMP)spoof_sysver, NO);
    TryHook(@[@"UIDevice"], @selector(localizedModel), (IMP)spoof_localizedModel, NO);
    TryHook(@[@"UIDevice"], @selector(systemName), (IMP)spoof_sysname, NO);
    // 组5: NSProcessInfo 内存/CPU/版本串
    TryHook(@[@"NSProcessInfo"], @selector(physicalMemory), (IMP)spoof_physmem, NO);
    TryHook(@[@"NSProcessInfo"], @selector(processorCount), (IMP)spoof_cpucount, NO);
    TryHook(@[@"NSProcessInfo"], @selector(activeProcessorCount), (IMP)spoof_cpucount, NO);
    TryHook(@[@"NSProcessInfo"], @selector(operatingSystemVersionString), (IMP)spoof_osverstr, NO);
    TryHook(@[@"NSProcessInfo"], @selector(physicalMemory), (IMP)spoof_physicalMemory, NO);
    TryHook(@[@"NSProcessInfo"], @selector(processorCount), (IMP)spoof_processorCount, NO);
    // 组6: NSFileManager 磁盘容量
    {
        Class fcls = objc_getClass("NSFileManager");
        Method m = class_getInstanceMethod(fcls, @selector(attributesOfFileSystemForPath:error:));
        if (m) {
            orig_attrsFS = (void *)method_getImplementation(m);
            method_setImplementation(m, (IMP)spoof_attrsFS);
        }
    }
    // 组7: fishhook 七个 C 函数
    rebind_symbols((struct rebinding[]){
        {"sysctlbyname", (void *)spoof_sysctlbyname, (void **)&orig_sysctlbyname},
        {"sysctl", (void *)spoof_sysctl, (void **)&orig_sysctl},
        {"uname", (void *)spoof_uname, (void **)&orig_uname},
        {"gethostname", (void *)spoof_gethostname, (void **)&orig_gethostname},
        {"access", (void *)spoof_access, (void **)&orig_access},
        {"sysconf", (void *)spoof_sysconf, (void **)&orig_sysconf},
        {"host_statistics64", (void *)spoof_host_statistics64, (void **)&orig_host_statistics64},
        {"statfs", (void *)spoof_statfs, (void **)&orig_statfs},
        {"statfs64", (void *)spoof_statfs, (void **)&orig_statfs},
    }, 9);
    XLog(@"[改机] 伪造设备: %@ / %@ / %@(%@) / IDFV=%@", _spoofModelName(), _spoofProduct(), _spoofOSString(), _spoofBuildString(), _spoofIDFV());
}

// ============================================================
// 深度环境模拟 (Thor 同款): 序列号 / 运营商 / WiFi / 电池
// 开关: xh_switch.deepenv (悬浮球面板"深度环境", 默认关, 切换后重启探探生效)
// 指纹持久化: Documents/deep_env.plist (一键新机时 Documents 全清 -> 自动重新随机)
//   - serial               12位苹果序列号风格(排除易混淆 I/O/Q)
//   - wifiSSID / wifiBSSID 家用路由器风格 SSID + 本地管理位 MAC
//   - carrierIdx           运营商池下标(移动/联通/电信 MCC=460)
//   - batteryPct           电池电量 35~90%
// ============================================================
static CFStringRef kCNNetworkInfoKeySSID  = CFSTR("SSID");
static CFStringRef kCNNetworkInfoKeyBSSID = CFSTR("BSSID");

static NSMutableDictionary *_deepEnvCache = nil;

static BOOL _deepOn(void) {
    // 深度环境跟随"设备改机"开关(不单独显示在面板), 勾选设备改机即启用
    return _swOn(XH_SW_DEVICE);
}

static NSString *_deepSerialGen(void) {
    NSString *alpha = @"ABCDEFGHJKLMNPRSTUVWXYZ0123456789";
    NSMutableString *s = [NSMutableString string];
    for (int i = 0; i < 12; i++) {
        unichar c = [alpha characterAtIndex:arc4random_uniform((uint32_t)alpha.length)];
        [s appendFormat:@"%C", c];
    }
    return s;
}

static NSArray *_deepCarrierPool(void) {
    static NSArray *pool;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        pool = @[
            @{@"name": @"中国移动", @"iso": @"cn", @"mcc": @"460", @"mnc": @"00"},
            @{@"name": @"中国移动", @"iso": @"cn", @"mcc": @"460", @"mnc": @"02"},
            @{@"name": @"中国移动", @"iso": @"cn", @"mcc": @"460", @"mnc": @"07"},
            @{@"name": @"中国联通", @"iso": @"cn", @"mcc": @"460", @"mnc": @"01"},
            @{@"name": @"中国电信", @"iso": @"cn", @"mcc": @"460", @"mnc": @"03"},
        ];
    });
    return pool;
}

static NSString *_deepStorePath(void) {
    return [[_docDir() stringByAppendingPathComponent:@"deep_env.plist"] stringByStandardizingPath];
}

static NSDictionary *_deepIdentity(void) {
    if (_deepEnvCache) return _deepEnvCache;
    NSString *path = _deepStorePath();
    NSMutableDictionary *d = [[NSDictionary dictionaryWithContentsOfFile:path] mutableCopy];
    if (!d) d = [NSMutableDictionary dictionary];
    BOOL dirty = NO;
    if (![d objectForKey:@"serial"]) { d[@"serial"] = _deepSerialGen(); dirty = YES; }
    if (![d objectForKey:@"mlbSerial"]) { d[@"mlbSerial"] = _deepSerialGen(); dirty = YES; }
    if (![d objectForKey:@"wifiSSID"]) {
        NSArray *prefixes = @[@"TP-LINK_", @"Xiaomi_", @"HUAWEI-", @"Tenda_", @"MERCURY_", @"ZTE-"];
        d[@"wifiSSID"] = [NSString stringWithFormat:@"%@%04X",
                          prefixes[arc4random_uniform((uint32_t)prefixes.count)],
                          arc4random_uniform(0xFFFF)];
        d[@"wifiBSSID"] = [NSString stringWithFormat:@"AA:%02X:%02X:%02X:%02X:%02X",
                           arc4random_uniform(256), arc4random_uniform(256),
                           arc4random_uniform(256), arc4random_uniform(256),
                           arc4random_uniform(256)];
        dirty = YES;
    }
    if (![d objectForKey:@"carrierIdx"]) { d[@"carrierIdx"] = @(arc4random_uniform((uint32_t)_deepCarrierPool().count)); dirty = YES; }
    if (![d objectForKey:@"batteryPct"]) { d[@"batteryPct"] = @(35 + arc4random_uniform(56)); dirty = YES; }
    // IMEI: 15位 (TAC 8位 + 序列号6位 + 校验1位), 用合法 TAC 前缀
    if (![d objectForKey:@"imei"]) {
        NSArray *tacs = @[@"35161041", @"35220803", @"35323908", @"86754303", @"86872604", @"86524305"];
        NSString *tac = tacs[arc4random_uniform((uint32_t)tacs.count)];
        NSMutableString *imei = [NSMutableString stringWithString:tac];
        for (int i = 0; i < 6; i++) [imei appendFormat:@"%d", arc4random_uniform(10)];
        [imei appendFormat:@"%d", arc4random_uniform(10)]; // 校验位
        d[@"imei"] = imei;
        dirty = YES;
    }
    // ICCID: 20位 (8986 + 运营商 + 卡号), 中国移动 898600/898602, 联通 898601, 电信 898603
    if (![d objectForKey:@"iccid"]) {
        NSArray *prefixes = @[@"898600", @"898602", @"898601", @"898603"];
        NSString *prefix = prefixes[arc4random_uniform((uint32_t)prefixes.count)];
        NSMutableString *iccid = [NSMutableString stringWithString:prefix];
        while (iccid.length < 20) [iccid appendFormat:@"%d", arc4random_uniform(10)];
        d[@"iccid"] = iccid;
        dirty = YES;
    }
    // IOPlatformUUID / UDID (大写 UUID 无连字符)
    if (![d objectForKey:@"ioupuid"]) {
        NSString *u = [[[NSUUID UUID] UUIDString] stringByReplacingOccurrencesOfString:@"-" withString:@""];
        d[@"ioupuid"] = [u uppercaseString];
        d[@"bootUuid"] = [[[NSUUID UUID] UUIDString] uppercaseString];
        dirty = YES;
    }
    // 芯片ID (DieId / ChipID): 16 位十六进制, 稳定持久化
    if (![d objectForKey:@"dieId"]) {
        NSMutableString *die = [NSMutableString string];
        for (int i = 0; i < 16; i++) [die appendFormat:@"%X", arc4random_uniform(16)];
        d[@"dieId"] = die;
        dirty = YES;
    }
    // 认证型号 (regulatory-model-number): 形如 A2111 的监管型号, IORegistry/合规接口会读
    if (![d objectForKey:@"regModel"]) {
        d[@"regModel"] = [NSString stringWithFormat:@"A%d", 1900 + arc4random_uniform(1200)];
        dirty = YES;
    }
    // BootTime: 用当前时间戳减一个合理 uptime (几天到几周)
    if (![d objectForKey:@"bootTime"]) {
        long long now = (long long)[[NSDate date] timeIntervalSince1970];
        long long uptime = 86400LL * (1 + arc4random_uniform(14)); // 1~14 天
        d[@"bootTime"] = @(now - uptime);
        dirty = YES;
    }
    // 蓝牙地址 (AA: 前缀 + 5 字节随机)
    if (![d objectForKey:@"blueAddr"]) {
        d[@"blueAddr"] = [NSString stringWithFormat:@"AA:%02X:%02X:%02X:%02X:%02X",
                          arc4random_uniform(256), arc4random_uniform(256),
                          arc4random_uniform(256), arc4random_uniform(256),
                          arc4random_uniform(256)];
        dirty = YES;
    }
    // WiFi MAC 地址 (本地管理位: 第二个字节最低位 = 0x2)
    if (![d objectForKey:@"wifiMac"]) {
        d[@"wifiMac"] = [NSString stringWithFormat:@"%02X:%02X:%02X:%02X:%02X:%02X",
                         0x02, arc4random_uniform(256), arc4random_uniform(256),
                         arc4random_uniform(256), arc4random_uniform(256), arc4random_uniform(256)];
        dirty = YES;
    }
    if (dirty) [d writeToFile:path atomically:YES];
    _deepEnvCache = d;
    XLog(@"[深度环境] 指纹就绪 serial=%@ mlb=%@ imei=%@ iccid=%@ ioupuid=%@ wifi=%@(%@) mac=%@ 运营商=%@ 电量=%d%% boot=%@",
         d[@"serial"], d[@"mlbSerial"], d[@"imei"], d[@"iccid"], d[@"ioupuid"],
         d[@"wifiSSID"], d[@"wifiBSSID"], d[@"wifiMac"],
         _deepCarrierPool()[[d[@"carrierIdx"] unsignedIntValue]][@"name"],
         [d[@"batteryPct"] intValue], d[@"bootTime"]);
    return d;
}

void XHDeepEnvReset(void) {
    _deepEnvCache = nil;
    [[NSFileManager defaultManager] removeItemAtPath:_deepStorePath() error:nil];
    XLog(@"[深度环境] 指纹缓存已清空, 下次启动重新随机");
}

static NSDictionary *_deepCarrier(void) {
    NSDictionary *d = _deepIdentity();
    unsigned int idx = [d[@"carrierIdx"] unsignedIntValue];
    NSArray *pool = _deepCarrierPool();
    if (idx >= pool.count) idx = 0;
    return pool[idx];
}

// 伪 CTCarrier (子类, SDK 的 isKindOfClass:CTCarrier 校验可通过)
@interface XHFakeCarrier : CTCarrier
@end
@implementation XHFakeCarrier
- (NSString *)carrierName       { return _deepCarrier()[@"name"]; }
- (NSString *)isoCountryCode    { return _deepCarrier()[@"iso"]; }
- (NSString *)mobileCountryCode { return _deepCarrier()[@"mcc"]; }
- (NSString *)mobileNetworkCode { return _deepCarrier()[@"mnc"]; }
- (BOOL)allowsVOIP              { return YES; }
@end

static id _deep_subscriberCarrier(id self, SEL _cmd) {
    IMP o = _getOrigImp(@"CTTelephonyNetworkInfo", _cmd);
    id orig = o ? ((id(*)(id, SEL))o)(self, _cmd) : nil;
    if (!_deepOn()) return orig;
    return [[XHFakeCarrier alloc] init];
}
static id _deep_serviceProviders(id self, SEL _cmd) {
    IMP o = _getOrigImp(@"CTTelephonyNetworkInfo", _cmd);
    id orig = o ? ((id(*)(id, SEL))o)(self, _cmd) : nil;
    if (!_deepOn()) return orig;
    return @{ @"0000000100000001": [[XHFakeCarrier alloc] init] };
}

// 网络接入技术 RAT: 返回 LTE(4G), 让探探/数美读到"有 SIM 卡的正常 4G 网络"
static id _deep_currentRadioAccessTechnology(id self, SEL _cmd) {
    IMP o = _getOrigImp(@"CTTelephonyNetworkInfo", _cmd);
    id orig = o ? ((id(*)(id, SEL))o)(self, _cmd) : nil;
    if (!_deepOn()) return orig;
    XLog(@"[深度环境] currentRadioAccessTechnology -> LTE(4G)");
    return @"CTRadioAccessTechnologyLTE";
}
static id _deep_serviceCurrentRadioAccessTechnology(id self, SEL _cmd) {
    IMP o = _getOrigImp(@"CTTelephonyNetworkInfo", _cmd);
    id orig = o ? ((id(*)(id, SEL))o)(self, _cmd) : nil;
    if (!_deepOn()) return orig;
    return @{ @"0000000100000001": @"CTRadioAccessTechnologyLTE" };
}

// CoreTelephony 私有 C 函数: IMEI / ICCID (数美/探探越狱检测后调用)
// CTRegistrationGetIMEI / CTRegistrationGetICCID / CTRegistrationCopyIMEI 等
static CFStringRef deep_CTRegistrationGetIMEI(void) {
    if (!_deepOn()) return NULL;
    XLog(@"[深度环境] IMEI -> %@", _deepIdentity()[@"imei"]);
    return (__bridge_retained CFStringRef)_deepIdentity()[@"imei"];
}
static CFStringRef deep_CTRegistrationGetICCID(void) {
    if (!_deepOn()) return NULL;
    XLog(@"[深度环境] ICCID -> %@", _deepIdentity()[@"iccid"]);
    return (__bridge_retained CFStringRef)_deepIdentity()[@"iccid"];
}

// IOKit: IOPlatformUUID / 序列号 (IOPlatformExpertDevice 的属性)
// 签名: CFTypeRef IORegistryEntryCreateCFProperty(io_registry_entry_t, CFStringRef, CFAllocatorRef, IOOptionBits)
typedef CFTypeRef (*deep_IORegistryEntryCreateCFProperty_fn)(void *, CFStringRef, void *, uint32_t);
static deep_IORegistryEntryCreateCFProperty_fn deep_orig_IORegEntryCFProp = NULL;
static CFTypeRef deep_IORegistryEntryCreateCFProperty(void *entry, CFStringRef key, void *allocator, uint32_t options) {
    CFTypeRef orig = deep_orig_IORegEntryCFProp ? deep_orig_IORegEntryCFProp(entry, key, allocator, options) : NULL;
    if (!_deepOn()) return orig;
    if (key) {
        NSString *k = (__bridge NSString *)key;
        // 序列号 / 主板号 (多个别名都覆盖, 防止换 key 绕过)
        if ([k isEqualToString:@"IOPlatformSerialNumber"] ||
            [k isEqualToString:@"MLBSerialNumber"] ||
            [k isEqualToString:@"serial-number"] ||
            [k isEqualToString:@"IOPlatformSystemSerialNumber"] ||
            [k isEqualToString:@"device_serial_number"]) {
            if (orig) CFRelease(orig);
            XLog(@"[深度环境] %@ -> %@", k, _deepIdentity()[@"serial"]);
            return (__bridge_retained CFTypeRef)_deepIdentity()[@"serial"];
        }
        if ([k isEqualToString:@"IOPlatformUUID"]) {
            if (orig) CFRelease(orig);
            XLog(@"[深度环境] IOPlatformUUID -> %@", _deepIdentity()[@"ioupuid"]);
            return (__bridge_retained CFTypeRef)_deepIdentity()[@"ioupuid"];
        }
        // 芯片/主板标识
        if ([k isEqualToString:@"IOPlatformDeviceID"] || [k isEqualToString:@"board-id"] ||
            [k isEqualToString:@"IOPlatformBoardID"] || [k isEqualToString:@"chip-id"]) {
            if (orig) CFRelease(orig);
            XLog(@"[深度环境] %@ -> dieId %@", k, _deepIdentity()[@"dieId"]);
            return (__bridge_retained CFTypeRef)_deepIdentity()[@"dieId"];
        }
        // 机型/产品名 (与伪装机型保持一致, 否则 IORegistry 与 UIDevice 对不上反而露馅)
        if ([k isEqualToString:@"model"] || [k isEqualToString:@"Model"] ||
            [k isEqualToString:@"target-type"] || [k isEqualToString:@"device_type"] ||
            [k isEqualToString:@"product-name"] || [k isEqualToString:@"ProductName"]) {
            NSString *prod = _spoofModelInfo()[@"p"] ?: @"iPhone12,1";
            if (orig) CFRelease(orig);
            XLog(@"[深度环境] %@ -> %@", k, prod);
            return (__bridge_retained CFTypeRef)prod;
        }
        // 监管型号 (A2xxx)
        if ([k isEqualToString:@"regulatory-model-number"] || [k isEqualToString:@"RegulatoryModelNumber"]) {
            if (orig) CFRelease(orig);
            XLog(@"[深度环境] %@ -> %@", k, _deepIdentity()[@"regModel"]);
            return (__bridge_retained CFTypeRef)_deepIdentity()[@"regModel"];
        }
    }
    return orig;
}

// UIDevice uniqueIdentifier (旧版私有, 返回 UDID 风格) — 已废弃, 但部分 SDK 仍调用
static id _deep_uniqueIdentifier(id self, SEL _cmd) {
    IMP o = _getOrigImp(@"UIDevice", _cmd);
    id orig = o ? ((id(*)(id, SEL))o)(self, _cmd) : nil;
    if (!_deepOn()) return orig;
    return _deepIdentity()[@"ioupuid"];
}

// libMobileGestalt MGCopyAnswer: 数美/探探读 IMEI/序列号/UDID/机型等最常走的路径
// 签名: CFStringRef MGCopyAnswer(CFStringRef question)
static CFStringRef (*deep_orig_MGCopyAnswer)(CFStringRef) = NULL;
static CFStringRef deep_MGCopyAnswer(CFStringRef question) {
    if (_deepOn() && question) {
        NSString *q = (__bridge NSString *)question;
        NSString *v = nil;
        if ([q isEqualToString:@"SerialNumber"]) v = _deepIdentity()[@"serial"];
        else if ([q isEqualToString:@"UniqueDeviceID"]) v = _deepIdentity()[@"ioupuid"];
        else if ([q isEqualToString:@"UniqueDeviceIDForSubmission"]) v = _deepIdentity()[@"ioupuid"];
        else if ([q isEqualToString:@"InternationalMobileEquipmentIdentity"]) v = _deepIdentity()[@"imei"];
        else if ([q isEqualToString:@"DieId"] || [q isEqualToString:@"ChipID"]) v = _deepIdentity()[@"dieId"];
        else if ([q isEqualToString:@"MLBSerialNumber"]) v = _deepIdentity()[@"mlbSerial"];
        else if ([q isEqualToString:@"BluetoothAddress"]) v = _deepIdentity()[@"blueAddr"];
        else if ([q isEqualToString:@"WifiAddress"] || [q isEqualToString:@"WiFiAddress"]) v = _deepIdentity()[@"wifiMac"];
        else if ([q isEqualToString:@"IOPlatformUUID"]) v = _deepIdentity()[@"ioupuid"];
        if (v) {
            XLog(@"[深度环境] MGCopyAnswer(%@) -> %@", q, v);
            return (__bridge_retained CFStringRef)v;
        }
    }
    return deep_orig_MGCopyAnswer ? deep_orig_MGCopyAnswer(question) : NULL;
}

// 蓝牙地址: 探探/数美通过 CoreBluetooth 或私有 API 读, 常见是 BTMachPort / CBAdvertisement
// 这里 hook UIDevice 的私有 + 留待实际采集路径确认

static float _deep_batteryLevel(id self, SEL _cmd) {
    IMP o = _getOrigImp(@"UIDevice", _cmd);
    float orig = o ? ((float(*)(id, SEL))o)(self, _cmd) : -1.0f;
    if (!_deepOn()) return orig;
    return [_deepIdentity()[@"batteryPct"] floatValue] / 100.0f;
}
static long _deep_batteryState(id self, SEL _cmd) {
    IMP o = _getOrigImp(@"UIDevice", _cmd);
    long orig = o ? ((long(*)(id, SEL))o)(self, _cmd) : 0;
    if (!_deepOn()) return orig;
    return 2; // UIDeviceBatteryStateCharging
}

static CFArrayRef (*deep_orig_CNCopy)(CFStringRef) = NULL;
static CFArrayRef deep_CNCopy(CFStringRef ifName) {
    CFArrayRef orig = deep_orig_CNCopy ? deep_orig_CNCopy(ifName) : NULL;
    if (!_deepOn()) return orig;
    NSDictionary *info = @{(__bridge id)kCNNetworkInfoKeySSID: _deepIdentity()[@"wifiSSID"],
                           (__bridge id)kCNNetworkInfoKeyBSSID: _deepIdentity()[@"wifiBSSID"]};
    if (orig) CFRelease(orig);
    XLog(@"[深度环境] CNCopyCurrentNetworkInfo -> SSID=%@ BSSID=%@",
         _deepIdentity()[@"wifiSSID"], _deepIdentity()[@"wifiBSSID"]);
    return (__bridge_retained CFArrayRef)@[info];
}

// 缺口补齐: WiFi MAC / 蓝牙 MAC 的公开读取入口 getifaddrs。
// SDK 常遍历网卡链表读 AF_LINK 的 sdl_data 拿 MAC (en0=WiFi, en2/en3/bnep0=蓝牙PAN)。
// 这里在返回前把对应网卡的 6 字节 MAC 改成伪值。
static int (*deep_orig_getifaddrs)(struct ifaddrs **) = NULL;
static void _deepMACBytes(NSString *hex, unsigned char out[6]) {
    memset(out, 0, 6);
    if (!hex) return;
    NSArray *parts = [hex componentsSeparatedByString:@":"];
    if (parts.count != 6) return;
    for (int i = 0; i < 6; i++) out[i] = (unsigned char)strtol([parts[i] UTF8String], NULL, 16);
}
static int deep_getifaddrs(struct ifaddrs **ifap) {
    int ret = deep_orig_getifaddrs ? deep_orig_getifaddrs(ifap) : -1;
    if (ret != 0 || !_deepOn() || !ifap || !*ifap) return ret;
    NSDictionary *idn = _deepIdentity();
    unsigned char wifiMAC[6], blueMAC[6];
    _deepMACBytes(idn[@"wifiMac"], wifiMAC);
    _deepMACBytes(idn[@"blueAddr"], blueMAC);
    for (struct ifaddrs *ifa = *ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_LINK) continue;
        struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa->ifa_addr;
        unsigned char *mac = (unsigned char *)LLADDR(sdl);
        const char *ifname = ifa->ifa_name ?: "";
        if (strcmp(ifname, "en0") == 0) {
            memcpy(mac, wifiMAC, 6);
        } else if (strncmp(ifname, "en", 2) == 0 || strncmp(ifname, "bnep", 4) == 0) {
            memcpy(mac, blueMAC, 6);  // 蓝牙 PAN 网卡
        } else if (strncmp(ifname, "pdp_ip", 6) == 0) {
            memcpy(mac, wifiMAC, 6);  // 蜂窝网卡(pdp_ip0/1), 原来会漏真 MAC
        }
    }
    return ret;
}

// ============================================================
// statfs 磁盘容量伪装
// 探探会直接调 statfs/statfs64 读总容量(实测主二进制 5 处), 绕过 NSFileManager。
// 这里在系统调用层改 f_blocks/f_bfree, 与伪造的 disk(128/256/512GB) 保持一致。
// ============================================================
static int (*orig_statfs)(const char *, struct statfs *) = NULL;
static int spoof_statfs(const char *path, struct statfs *buf) {
    int ret = orig_statfs ? orig_statfs(path, buf) : -1;
    if (ret == 0 && buf && _gDevSpoofOn) {
        uint64_t total = _spoofDiskBytes();
        uint32_t bs = buf->f_bsize ? buf->f_bsize : 4096;
        buf->f_blocks = total / bs;
        buf->f_bfree  = buf->f_blocks / 3;
        buf->f_bavail = buf->f_bfree;
        static int o = 0;
        if (o < 2) { o++; XLog(@"[改机] statfs 磁盘容量 -> %llu GB", total / (1024ULL*1024ULL*1024ULL)); }
    }
    return ret;
}

typedef int (*deep_sysctlbyname_fn)(const char *, void *, size_t *, void *, size_t);
static deep_sysctlbyname_fn deep_orig_sysctlbyname = NULL;
static int deep_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (_deepOn() && name) {
        // 序列号 (kern.serialno / hw.serialno)
        if (strcmp(name, "kern.serialno") == 0 || strcmp(name, "hw.serialno") == 0) {
            const char *s = [_deepIdentity()[@"serial"] UTF8String];
            if (s && oldp && oldlenp && strlen(s) + 1 <= *oldlenp) {
                memcpy(oldp, s, strlen(s) + 1); *oldlenp = strlen(s) + 1;
                XLog(@"[深度环境] sysctlbyname(%s) -> 伪序列号 %s", name, s);
                return 0;
            }
        }
        // 主板序列号 (hw.mlbserialnumber)
        if (strcmp(name, "hw.mlbserialnumber") == 0) {
            const char *s = [_deepIdentity()[@"mlbSerial"] UTF8String];
            if (s && oldp && oldlenp && strlen(s) + 1 <= *oldlenp) {
                memcpy(oldp, s, strlen(s) + 1); *oldlenp = strlen(s) + 1;
                XLog(@"[深度环境] sysctlbyname(hw.mlbserialnumber) -> 伪主板序列号 %s", s);
                return 0;
            }
        }
        // 开机时间 (kern.boottime -> struct timeval)
        if (strcmp(name, "kern.boottime") == 0) {
            if (oldp && oldlenp && *oldlenp >= sizeof(struct timeval)) {
                struct timeval tv;
                tv.tv_sec = [_deepIdentity()[@"bootTime"] longLongValue];
                tv.tv_usec = 0;
                memcpy(oldp, &tv, sizeof(struct timeval));
                *oldlenp = sizeof(struct timeval);
                XLog(@"[深度环境] sysctlbyname(kern.boottime) -> 伪开机时间 %lld", (long long)tv.tv_sec);
                return 0;
            }
        }
    }
    return deep_orig_sysctlbyname ? deep_orig_sysctlbyname(name, oldp, oldlenp, newp, newlen) : -1;
}

static void XHInstallDeepEnvHooks(void) {
    if (!_deepOn()) {
        XLog(@"[深度环境] 开关未开启, 跳过 hook");
        return;
    }
    _deepIdentity();
    if (objc_getClass("CTTelephonyNetworkInfo")) {
        TryHook(@[@"CTTelephonyNetworkInfo"], @selector(subscriberCellularProvider), (IMP)_deep_subscriberCarrier, NO);
        TryHook(@[@"CTTelephonyNetworkInfo"], @selector(serviceSubscriberCellularProviders), (IMP)_deep_serviceProviders, NO);
        TryHook(@[@"CTTelephonyNetworkInfo"], @selector(subscriberCellularProviders), (IMP)_deep_serviceProviders, NO);
        TryHook(@[@"CTTelephonyNetworkInfo"], @selector(currentRadioAccessTechnology), (IMP)_deep_currentRadioAccessTechnology, NO);
        TryHook(@[@"CTTelephonyNetworkInfo"], @selector(serviceCurrentRadioAccessTechnology), (IMP)_deep_serviceCurrentRadioAccessTechnology, NO);
        XLog(@"[深度环境] CTTelephonyNetworkInfo hook 完成 (运营商=%@ RAT=LTE)", _deepCarrier()[@"name"]);
    }
    TryHook(@[@"UIDevice"], @selector(batteryLevel), (IMP)_deep_batteryLevel, NO);
    TryHook(@[@"UIDevice"], @selector(batteryState), (IMP)_deep_batteryState, NO);
    TryHook(@[@"UIDevice"], @selector(uniqueIdentifier), (IMP)_deep_uniqueIdentifier, NO);
    rebind_symbols((struct rebinding[]){
        {"CNCopyCurrentNetworkInfo", (void *)deep_CNCopy, (void **)&deep_orig_CNCopy},
        {"sysctlbyname", (void *)deep_sysctlbyname, (void **)&deep_orig_sysctlbyname},
        {"IORegistryEntryCreateCFProperty", (void *)deep_IORegistryEntryCreateCFProperty, (void **)&deep_orig_IORegEntryCFProp},
        {"MGCopyAnswer", (void *)deep_MGCopyAnswer, (void **)&deep_orig_MGCopyAnswer},
        {"getifaddrs", (void *)deep_getifaddrs, (void **)&deep_orig_getifaddrs},
        {"CTRegistrationGetIMEI", (void *)deep_CTRegistrationGetIMEI, NULL},
        {"CTRegistrationCopyIMEI", (void *)deep_CTRegistrationGetIMEI, NULL},
        {"CTRegistrationGetICCID", (void *)deep_CTRegistrationGetICCID, NULL},
        {"CTRegistrationCopyICCID", (void *)deep_CTRegistrationGetICCID, NULL},
    }, 9);
    XLog(@"[深度环境] hook 完成: serial=%@ mlb=%@ imei=%@ iccid=%@ ioupuid=%@ dieId=%@ 运营商=%@(%@/%@) RAT=LTE wifi=%@ mac=%@ blue=%@ 电量=%d%% boot=%@",
         _deepIdentity()[@"serial"], _deepIdentity()[@"mlbSerial"], _deepIdentity()[@"imei"], _deepIdentity()[@"iccid"], _deepIdentity()[@"ioupuid"], _deepIdentity()[@"dieId"],
         _deepCarrier()[@"name"], _deepCarrier()[@"mcc"], _deepCarrier()[@"mnc"],
         _deepIdentity()[@"wifiSSID"], _deepIdentity()[@"wifiMac"], _deepIdentity()[@"blueAddr"], [_deepIdentity()[@"batteryPct"] intValue], _deepIdentity()[@"bootTime"]);
}

// ============================================================
// 基础设备指纹 hook (轻量版, 只开 UIDevice / ASIdentifierManager / NSProcessInfo 这 10 项)
// 用途: 一键新机后让 IDFV/IDFA/机型/系统版本/内存/CPU 全部变成新指纹。
// 说明: 完整改机(含 fishhook sysctl/uname/access + 磁盘容量) 仍被 ENABLE_DEVICE_SPOOF 禁用,
//       因为鱼叉层 hook 会被认证活体SDK(阿里ZIM)检测到并闪退。
// 控制: 受"设备改机"开关 (xh_switch.device) 控制; 切换后需重启探探才重新注册。
// ============================================================
// ============================================================
// PUGDeviceInfo: 探探自己的设备信息接口 (类方法), 优先级高于 UIDevice。
// 探探的"个人信息收集清单"里 idfv/idfa/uuid/硬件型号/系统版本/mac 都从这里取,
// 只 hook UIDevice 会被它绕过(它可能读 keychain 缓存或自己算)。
// ============================================================
// 前 5 次调用打日志(验证探探确实走这里且拿到伪值), 之后静默避免刷盘
#define XH_PUG_LOG_ONCE(expr, tag) do { \
    static int _c = 0; \
    if (_c < 5) { XLog(@"[改机] PUGDeviceInfo." tag @" -> %@", (expr)); _c++; } \
} while(0)

static NSString *_pug_idfv(id self, SEL _cmd) {
    NSString *v = _spoofIDFV(); XH_PUG_LOG_ONCE(v, @"idfv"); return v;
}
static NSString *_pug_idfa(id self, SEL _cmd) {
    NSString *v = _spoofIDFA(); XH_PUG_LOG_ONCE(v, @"idfa"); return v;
}
static NSString *_pug_uuid(id self, SEL _cmd) {
    NSString *v = _spoofIDFV(); XH_PUG_LOG_ONCE(v, @"uuidString"); return v;
}
static NSString *_pug_machineCode(id self, SEL _cmd) {
    NSString *v = _spoofProduct(); XH_PUG_LOG_ONCE(v, @"machineCode"); return v;
}
static NSString *_pug_machineName(id self, SEL _cmd) {
    NSString *v = _spoofModelName(); XH_PUG_LOG_ONCE(v, @"readableMachineName"); return v;
}
static NSString *_pug_sysver(id self, SEL _cmd) {
    NSString *v = _spoofOSString(); XH_PUG_LOG_ONCE(v, @"systemVersion"); return v;
}
static NSString *_pug_sysname(id self, SEL _cmd) { return @"iOS"; }
static NSString *_pug_mac(id self, SEL _cmd) {
    // 原来返回 @"02:00:00:00:00:00" —— 全零占位值比真值更像假机, 反而容易被风控标记。
    // 改为返回持久伪 WiFi MAC(与 getifaddrs en0 / MGCopyAnswer WifiAddress 同一来源, 保持自洽)。
    NSString *m = _deepIdentity()[@"wifiMac"];
    if (m.length == 0) m = @"02:00:00:00:00:00";
    XH_PUG_LOG_ONCE(m, @"macAddress");
    return m;
}

static void XHInstallPUGDeviceInfoHooks(void) {
    TryHook(@[@"PUGDeviceInfo"], @selector(idfv), (IMP)_pug_idfv, YES);
    TryHook(@[@"PUGDeviceInfo"], @selector(idfa), (IMP)_pug_idfa, YES);
    TryHook(@[@"PUGDeviceInfo"], @selector(uuidString), (IMP)_pug_uuid, YES);
    TryHook(@[@"PUGDeviceInfo"], @selector(machineCode), (IMP)_pug_machineCode, YES);
    TryHook(@[@"PUGDeviceInfo"], @selector(readableMachineName), (IMP)_pug_machineName, YES);
    TryHook(@[@"PUGDeviceInfo"], @selector(systemVersion), (IMP)_pug_sysver, YES);
    TryHook(@[@"PUGDeviceInfo"], @selector(systemName), (IMP)_pug_sysname, YES);
    TryHook(@[@"PUGDeviceInfo"], @selector(macAddress), (IMP)_pug_mac, YES);
    TryHook(@[@"PUGDeviceInfo"], @selector(deviceMACaddress), (IMP)_pug_mac, YES);
    XLog(@"[改机] PUGDeviceInfo hook 完成: idfv/idfa/uuid/机型/版本/mac");
}

static __attribute__((unused)) void XHInstallBasicSpoofHooks(void) {
    if (!_swOn(XH_SW_DEVICE)) {
        XLog(@"[改机] 设备改机开关关闭, 跳过基础指纹 hook");
        return;
    }
    // 一层: 探探自己的设备信息接口(优先)
    XHInstallPUGDeviceInfoHooks();
    // 【已移除】v30 JSON 解析 hook (_jsonObj_probe): 它 hook 全局 NSJSONSerialization 类方法,
    //   数美 TXTOneId SDK 在设备指纹采集时会调 JSONObjectWithData:, 命中此 hook 后对特殊 data
    //   调 [r description] 崩溃(跳空指针)。该 hook 仅用于抓关系数据日志, 与改机无关, 直接移除。
    // UIDevice: IDFV / 机型 / 系统版本 / 设备名 / 系统名 / 本地化机型
    TryHook(@[@"UIDevice"], @selector(identifierForVendor), (IMP)spoof_idfv, NO);
    TryHook(@[@"UIDevice"], @selector(model), (IMP)spoof_model, NO);
    TryHook(@[@"UIDevice"], @selector(systemVersion), (IMP)spoof_sysver, NO);
    TryHook(@[@"UIDevice"], @selector(name), (IMP)spoof_name, NO);
    TryHook(@[@"UIDevice"], @selector(systemName), (IMP)spoof_sysname, NO);
    TryHook(@[@"UIDevice"], @selector(localizedModel), (IMP)spoof_localizedModel, NO);
    // ASIdentifierManager: IDFA
    TryHook(@[@"ASIdentifierManager"], @selector(advertisingIdentifier), (IMP)spoof_idfa, NO);
    // NSProcessInfo: 物理内存 / CPU 核数 / 系统版本串
    TryHook(@[@"NSProcessInfo"], @selector(physicalMemory), (IMP)spoof_physmem, NO);
    TryHook(@[@"NSProcessInfo"], @selector(processorCount), (IMP)spoof_cpucount, NO);
    TryHook(@[@"NSProcessInfo"], @selector(operatingSystemVersionString), (IMP)spoof_osverstr, NO);
    XLog(@"[改机] 基础指纹 hook 已注册: IDFV=%@ 机型=%@ 版本=%@", _spoofIDFV(), _spoofModelName(), _spoofOSString());
}

// ============================================================
// 构造函数
// ============================================================
static void installXihuanBalls(void);
void XHInstallGlobalBall(void);

// ==================== 反检测: 隐藏越狱 / 重签特征 ====================
static BOOL xh_pathIsSuspicious(NSString *path) {
    if (!path.length) return NO;
    static NSArray *pats;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        pats = @[
            @"/Applications/Cydia.app", @"/Applications/Sileo.app", @"/Applications/Zebra.app",
            @"/var/lib/dpkg", @"/private/var/lib/dpkg", @"/etc/apt",
            @"/usr/lib/libsubstrate.dylib", @"/Library/MobileSubstrate", @"/Library/TweakInject",
            @"/usr/sbin/frida-server", @"/usr/bin/frida-server", @"/usr/bin/ssh", @"/bin/bash",
            @"embedded.mobileprovision"
        ];
    });
    for (NSString *pat in pats) {
        if ([path rangeOfString:pat].location != NSNotFound) return YES;
    }
    return NO;
}

static BOOL (*xh_orig_fileExists)(id, SEL, NSString *);
static BOOL xh_hook_fileExists(id self, SEL _cmd, NSString *path) {
    if (xh_pathIsSuspicious(path)) return NO;
    return xh_orig_fileExists(self, _cmd, path);
}

static NSURL *(*xh_orig_receipt)(id, SEL);
static NSURL *xh_hook_receipt(id self, SEL _cmd) {
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    if (!docs.length) return xh_orig_receipt ? xh_orig_receipt(self, _cmd) : nil;
    NSString *p = [docs stringByAppendingPathComponent:@".storekit_receipt"];
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:p]) {
        NSMutableData *d = [NSMutableData dataWithLength:512];
        (void)SecRandomCopyBytes(kSecRandomDefault, d.length, d.mutableBytes);
        [d writeToFile:p atomically:YES];
    }
    return [NSURL fileURLWithPath:p];
}

// ---- 隐藏自己的镜像，避免 _dyld_image_count 枚举到插件 ----
static uint32_t (*xh_orig_dyld_count)(void);
static const struct mach_header *(*xh_orig_dyld_hdr)(uint32_t);
static const char *(*xh_orig_dyld_name)(uint32_t);
static int xh_self_image_index = -1;

static uint32_t xh_hook_dyld_count(void) {
    uint32_t n = xh_orig_dyld_count ? xh_orig_dyld_count() : 0;
    if (xh_self_image_index >= 0 && n > 0) return n - 1;
    return n;
}

static const struct mach_header *xh_hook_dyld_hdr(uint32_t idx) {
    if (!xh_orig_dyld_hdr) return NULL;
    if (xh_self_image_index >= 0 && (int)idx >= xh_self_image_index) idx += 1;
    return xh_orig_dyld_hdr(idx);
}

static const char *xh_hook_dyld_name(uint32_t idx) {
    if (!xh_orig_dyld_name) return NULL;
    if (xh_self_image_index >= 0 && (int)idx >= xh_self_image_index) idx += 1;
    return xh_orig_dyld_name(idx);
}

static void xh_setup_dyld_stealth(void) {
    Dl_info info;
    if (dladdr((void *)&xh_setup_dyld_stealth, &info) && info.dli_fbase) {
        uint32_t n = _dyld_image_count();
        for (uint32_t i = 0; i < n; i++) {
            if (_dyld_get_image_header(i) == (const struct mach_header *)info.dli_fbase) {
                xh_self_image_index = (int)i;
                break;
            }
        }
    }
    rebind_symbols((struct rebinding[]){
        {"_dyld_image_count", (void *)xh_hook_dyld_count, (void **)&xh_orig_dyld_count},
        {"_dyld_get_image_header", (void *)xh_hook_dyld_hdr, (void **)&xh_orig_dyld_hdr},
        {"_dyld_get_image_name", (void *)xh_hook_dyld_name, (void **)&xh_orig_dyld_name},
    }, 3);
    XLog(@"[反检测] dyld 枚举已隐藏自身 (index=%d)", xh_self_image_index);
}

__attribute__((unused)) static void xh_installAntiDetect(void) {
    Class fmCls = NSClassFromString(@"NSFileManager");
    Method m = class_getInstanceMethod(fmCls, @selector(fileExistsAtPath:));
    if (m) {
        xh_orig_fileExists = (void *)method_getImplementation(m);
        method_setImplementation(m, (IMP)xh_hook_fileExists);
    }
    Class bCls = NSClassFromString(@"NSBundle");
    Method m2 = class_getInstanceMethod(bCls, @selector(appStoreReceiptURL));
    if (m2) {
        xh_orig_receipt = (void *)method_getImplementation(m2);
        method_setImplementation(m2, (IMP)xh_hook_receipt);
    }
    xh_setup_dyld_stealth();
    XLog(@"[反检测] 越狱/重签路径已隐藏, 收据已伪造, 镜像已隐藏");
}

__attribute__((constructor))
static void xihuan_verify_vip_init(void) {
    @autoreleasepool {
        // ============ 每次启动强制重置"拦截清空登录态"开关为关闭 ============
        // 该开关只应在单次注册会话内按需开启, 每次打开探探都回到默认关闭状态
        XHSetSwitch(XH_SW_BLOCK_CLEAR, NO);

        // ============ 一次性迁移: 所有功能开关归零 (默认全关, 用时手动开) ============
        // 必须在注册 NSUserDefaults hook 之前跑完, 否则迁移里的 setBool 会进 hook。
        _migrate_switches_default_off();

        // ============ 最早期注册 NSUserDefaults 读写 hook ============
        // 实测(2026-11-24): 数美 ms_n_mid / 微博 machinePlatForm 会在 constructor 后续初始化
        // (清理->版本伪造->设备改机) 的 2~3 秒窗口内写入, 若等到 spoof_device_init 才 hook 就漏了。
        // 先按迁移后的最终值缓存"设备改机"开关(hook 尚未注册, 此处读取安全), 再挂 hook。
        _gDevSpoofOn = _swOn(XH_SW_DEVICE);
        hook_oneid();
        XLog(@"[初始化] NSUserDefaults hook 已提前注册, 设备改机=%d", _gDevSpoofOn);

        // xh_installAntiDetect();  // 已停用: 隐藏路径/伪造收据会触发风控

        // 注: "解除匹配限制"不再补种默认值, 统一由 _migrate_switches_default_off 置为关闭,
        //     需要时在面板手动打开(手动开启的值会被 v3 标记保护, 不会每次启动被重置)。

        // ============ -1. 启动清理 (已关闭) ============
        // 只有"一键新机"按钮设置的 pending 标记才触发彻底清空;
        // 首次启动不再自动清理 —— 否则会递归清空 Library/Preferences,
        // 把 xh_switch.* 开关和登录态一起删掉, 表现为"关掉再开就恢复最初的样子"。
        if (_hasPendingFullCleanup()) {
            XLog(@"[初始化] 检测到一键新机待彻底清理标记, 执行彻底清空");
            _fullCleanupSandbox();
        } else {
            XLog(@"[初始化] 启动清理已关闭, 复用已有开关状态/数据/随机指纹");
        }

        // ============ 0. 版本号伪造 (独立于设备改机, 启动早期必须 hook) ============
        spoof_version_init();

        // ============ 0.1 设备改机 (系统级指纹伪造) ============
        spoof_device_init();
        // 探探自有设备信息接口(PUGDeviceInfo) + JSON 关系数据探针 (受设备改机开关控制)
        XHInstallBasicSpoofHooks();
        // 注意: XHInstallOneIdHook(枚举 TXTOneID 所有含 oneid 方法) 签名假设脆弱,
        //       会栈破坏导致 TXTOneId SDK 调用时跳空指针崩溃, 已移除。
        //       oneid/localid 伪装改由 spoof_device_init 内的 hook_oneid()(NSUserDefaults objectForKey 精确 hook) 承担。
        // 深度环境模拟 (Thor 同款): 序列号/运营商/WiFi/电池, 跟随设备改机开关
        XHInstallDeepEnvHooks();

        // ============ 0.0 远程授权校验 (HelloAuth): 内容 1=放行, 2=隐藏所有功能 ============
        [[HelloAuth shared] startCheck];

        // ============ 0.4 全局悬浮球 (一键新机 + 版本填写, 任意界面可见) ============
        // 监听 App 启动完成通知, 确保有 keyWindow 后再创建全局悬浮窗
        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
                                                          object:nil queue:nil usingBlock:^(NSNotification * _Nonnull note) {
            XHInstallGlobalBall();
        }];
        // 兜底: 延迟 1 秒再装一次 (防止通知未触发)
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            XHInstallGlobalBall();
        });

        // ============ 0.5 红球(自动点赞) + 蓝球(顺发) 移植自 xihuan_njb ============
        installXihuanBalls();




        // ============ 0.6 切国内外 (hook PUGDeviceInfo isChineseMobileNumber) ============
        HelloGuowaiInstall();

        // ============ 1. 反越狱 / 风控对抗 ============
        TryHook(@[@"PUGUser"], @selector(isJailed), (IMP)_isJailed, NO);
        TryHook(@[@"PUGUser"], @selector(isBanned), (IMP)_isBanned, NO);
        TryHook(@[@"PUGUser"], @selector(isAvatarUnReal), (IMP)_isAvatarUnReal, NO);
        // 【补注册】强制身份认证判断: PUGUser isMandatoryVerification -> NO
        // 客户端读它决定要不要弹"必须认证"页; 归入"屏蔽所有弹窗"开关控制
        TryHook(@[@"PUGUser"], @selector(isMandatoryVerification), (IMP)_isMandatoryVerification_NO, NO);
        // 头像本人认证: isRealAvatar -> YES (认证中心显示"已认证")
        TryHook(@[@"PUGUser", @"PUGCurrentUserInfo", @"PUGUserStateInfo"], @selector(isRealAvatar), (IMP)_isRealAvatar_YES, NO);

        TryHook(@[@"PUGUserStateInfo"], @selector(isPermanentBanned), (IMP)_isPermanentBanned, NO);
        TryHook(@[@"PUGUserStateInfo"], @selector(stateInfoType), (IMP)_stateInfoType, NO);
        TryHook(@[@"PUGUserStateInfo"], @selector(active), (IMP)_active, NO);

        TryHook(@[@"AFSecurityPolicy"], @selector(setSSLPinningMode:), (IMP)_setSSLPinningMode, NO);

        TryHook(@[@"SentrySDK"], @selector(sharedInstance), (IMP)_SentrySDK_sharedInstance, YES);
        TryHook(@[@"SentrySDK"], @selector(startWithConfigureOptions:), (IMP)_SentrySDK_startWithConfigureOptions, YES);

        // ============ 2. 认证跳过 ============
#if ENABLE_AUTH_SKIP
        TryHook(@[@"PUGMandatoryVerificationAlertController"], @selector(init), (IMP)_init_nil, NO);
        TryHook(@[@"PUGGrowthNewFakeAlertViewController"], @selector(viewDidAppear:), (IMP)_viewDidAppear_noop, NO);

        // 真实头像认证弹窗 (探探风控: 温馨提示 + 立即认证)
        NSArray *realAvatarAlerts = @[@"PUGChangeRealAvatarAlertViewController",
                                       @"PUGProfileRealAvatarTipViewController"];
        TryHook(realAvatarAlerts, @selector(viewDidLoad), (IMP)_alert_viewDidLoad_dismiss, NO);

        // 强制认证弹窗总开关 (7.6.4 showSelectVC: 已改名 showSelectVCIfNeeded:)
        NSArray *verificationHandlers = @[@"PUGMandatoryVerificationHandler"];
        TryHook(verificationHandlers, @selector(showMandatoryVerificationIfNeededWithData:), (IMP)_showMandatoryVerificationIfNeededWithData_noop, NO);
        TryHook(verificationHandlers, @selector(showSelectVC:), (IMP)_showSelectVC_noop, NO);
        TryHook(verificationHandlers, @selector(showSelectVCIfNeeded:), (IMP)_showSelectVCIfNeeded_noop, NO);
        TryHook(verificationHandlers, @selector(showIdentifierViewController:), (IMP)_showIdentifierViewController_noop, NO);
        TryHook(verificationHandlers, @selector(showPicturePopViewController:), (IMP)_showPicturePopViewController_noop, NO);
        TryHook(verificationHandlers, @selector(showJuvenileVerificationViewControllerIfNeeded), (IMP)_showJuvenileVerificationViewControllerIfNeeded_noop, NO);
#endif

        // ============ 3. 手机号绑定弹窗 ============
        TryHook(@[@"PUGBindPhoneNumberUseCase"], @selector(hasBindPhoneNumber), (IMP)_hasBindPhoneNumber_YES, NO);
        TryHook(@[@"PUGBindPhoneNumberUseCase"], @selector(shouldEnableBindPhoneNumberAfterSignup), (IMP)_shouldEnableBind_after_NO, NO);
        TryHook(@[@"PUGBindPhoneNumberUseCase"], @selector(shouldEnableBindPhoneNumberDuringSignup), (IMP)_shouldEnableBind_during_NO, NO);
        TryHook(@[@"PUGBindPhoneNumberUseCase"], @selector(isShowingForceBindAlerView), (IMP)_isShowingForceBindAlerView_NO, NO);
        TryHook(@[@"PUGQuickLoginBaseUseCase"], @selector(hasBindPhone), (IMP)_hasBindPhone_YES, NO);

        // 临时探测: 注册页入口 (定位完删除)

        // ============ 4. 会员权益 (7.6.4 多类型会员) ============
        // 核心用户类: PUGUser 及可能的子类/相关类
        NSArray *userClasses = @[@"PUGUser", @"PUGUserStateInfo", @"PUGMembershipInfo"];
        NSArray *membershipClasses = @[@"PUGUser", @"PUGMembershipInfo", @"PUGMembershipUsecase",
                                       @"PUGCommercializeService", @"PUGPrivilegeUseCase",
                                       @"PUGMembershipDiamondUsecase", @"PUGMembershipPlatinumUseCase",
                                       @"PUGMembershipPartnerUseCase",
                                       @"MembershipUsecase", @"Membership"];

        // 基础 VIP
        TryHook(userClasses, @selector(isVip), (IMP)_isVip_YES, NO);
        TryHook(userClasses, @selector(isLiveCampaignVip), (IMP)_isLiveCampaignVip_YES, NO);
        TryHook(userClasses, @selector(isUltraSvip), (IMP)_isUltraSvip_YES, NO);
        // 资料页"审核中"修复: isInAuditArea/displayAudit -> NO
        TryHook(userClasses, @selector(isInAuditArea), (IMP)_isInAuditArea_NO, NO);
        TryHook(userClasses, @selector(displayAudit), (IMP)_displayAudit_NO, NO);
        // 会员图标隐藏修复: hideMembershipIcon -> NO
        TryHook(userClasses, @selector(hideMembershipIcon), (IMP)_hideMembershipIcon_NO, NO);
        TryHook(userClasses, @selector(hideMembershipIconIncludeSelf), (IMP)_hideMembershipIcon_NO, NO);

        // ============ 4.5 发消息/打招呼权限 (已删除: 聊天权限伪装未解决实名聊天, 用户要求删除) ============
        TryHook(@[@"PUGSwipeCoreChangeRealAvatarPlugin"], @selector(currentUserIsAudited), (IMP)_currentUserIsAudited_YES, NO);
        // 换号伪装认证: 强制"已认证"状态
        // 【关键修正】只在 PUGUser(当前用户) 上 hook, 移除 PUGVerification(通用模型, 会导致全局所有用户都显示已认证)
        NSArray *verifiedClasses = @[@"PUGUser", @"PUGUserStateInfo", @"PUGCurrentUserInfo"];
        TryHook(verifiedClasses, @selector(isVerified), (IMP)_isVerified_YES, NO);
        TryHook(verifiedClasses, @selector(isPictureVerified), (IMP)_isPictureVerified_YES, NO);
        TryHook(verifiedClasses, @selector(isVerificationPassed), (IMP)_isVerificationPassed_YES, NO);
        // PUGUser 认证总开关: 当前用户所有认证类型 -> YES (头像/身份证/双重/审核)
        TryHook(@[@"PUGUser"], @selector(isIDCardVerified), (IMP)_isIDCardVerified_YES, NO);
        TryHook(@[@"PUGUser"], @selector(isIDCardAndPictureVerified), (IMP)_isIDCardVerified_YES, NO);
        TryHook(@[@"PUGUser"], @selector(isAvatarAudited), (IMP)_isAvatarAudited_YES, NO);
        TryHook(@[@"PUGUser"], @selector(isAudited), (IMP)_isAudited_YES, NO);
        TryHook(@[@"PUGUser"], @selector(isNameAudited), (IMP)_isNameAudited_YES, NO);
        // 【回退】shouldShowAuditedAtavar/auditedPictures hook 导致启动闪退, 已禁用(返回类型/内容不匹配)
        TryHook(@[@"PUGUser"], @selector(isAnchorVerified), (IMP)_isAnchorVerified_YES, NO);
        TryHook(@[@"PUGUser"], @selector(isVoiceAnchorVerified), (IMP)_isVoiceAnchorVerified_YES, NO);
        // 认证状态方法 -> "verified" (认证中心ViewModel)
        NSArray *verificationModelClasses = @[@"PUGVerification", @"PUGVerificationCenterBaseViewModel", @"PUGVerificationCenterPersonalPortraitViewModel"];
        TryHook(verificationModelClasses, @selector(verificationStatus), (IMP)_verificationStatus_verified, NO);
        TryHook(verificationModelClasses, @selector(verificationStatusPicture), (IMP)_verificationStatus_verified, NO);

        // MMKV 认证字段拦截: need_avatar_verification/need_pic_verification -> false, status -> verified
        // 认证页"头像本人认证"读的是 MMKV 里这些服务端下发的 key
        {
            Class mmkv = objc_getClass("MMKV");
            if (mmkv) {
                Method gb = class_getInstanceMethod(mmkv, NSSelectorFromString(@"getBoolForKey:"));
                if (gb) {
                    _orig_mmkvGetBool = method_getImplementation(gb);
                    method_setImplementation(gb, (IMP)_mmkvGetBool_probe);
                    XLog(@"[MMKV] 已 hook getBoolForKey:");
                } else XLog(@"[MMKV] 无 getBoolForKey:");
                Method gs = class_getInstanceMethod(mmkv, NSSelectorFromString(@"getStringForKey:"));
                if (gs) {
                    _orig_mmkvGetString = method_getImplementation(gs);
                    method_setImplementation(gs, (IMP)_mmkvGetString_probe);
                    XLog(@"[MMKV] 已 hook getStringForKey:");
                } else XLog(@"[MMKV] 无 getStringForKey:");
            } else {
                XLog(@"[MMKV] 类 MMKV 不存在");
            }
        }

        // 跨类兜底: hook isPictureVerified / pictureVerified
        // 【卡死修复】跨类遍历会导致探探卡死, 已禁用。改用上面的 PUGVerification 直接 hook。
#if 0
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            TryHookAcrossAllClasses(NSSelectorFromString(@"isPictureVerified"), (IMP)_isPictureVerified_YES, @"isPictureVerified");
            TryHookAcrossAllClasses(NSSelectorFromString(@"pictureVerified"), (IMP)_isPictureVerified_YES, @"pictureVerified");
        });
#endif
        // isAudited 在 PUGMoment/PUGComment (认证审核, 保留)
        NSArray *momentClasses = @[@"PUGMoment", @"PUGComment"];
        TryHook(momentClasses, @selector(isAudited), (IMP)_isAudited_YES, NO);
        TryHook(userClasses, @selector(isOtherVip), (IMP)_isOtherVip_YES, NO);

        // 通用会员
        TryHook(membershipClasses, @selector(isMembershipUser), (IMP)_isMembershipUser_YES, NO);
        TryHook(membershipClasses, @selector(isMembershipDiamondUser), (IMP)_isMembershipDiamondUser_YES, NO);
        TryHook(membershipClasses, @selector(isMembershipPlatinumUser), (IMP)_isMembershipPlatinumUser_YES, NO);
        TryHook(membershipClasses, @selector(isMembershipPartnerUser), (IMP)_isMembershipPartnerUser_YES, NO);

        // 各类型会员资格 (注意: 这些是【类方法】, 定义在 PUGCommercializeService/PUGPrivilegeUseCase 上, isClassMethod=YES)
        TryHook(membershipClasses, @selector(hasMembershipDiamond), (IMP)_hasMembershipDiamond_YES, YES);
        TryHook(membershipClasses, @selector(hasMembershipPlatinum), (IMP)_hasMembershipPlatinum_YES, YES);
        TryHook(membershipClasses, @selector(hasSVIPPrivilege), (IMP)_hasSVIPPrivilege_YES, YES);
        TryHook(membershipClasses, @selector(hasAIChatAssistantMembership), (IMP)_hasAIChatAssistantMembership_YES, YES);
        TryHook(membershipClasses, @selector(hasSeeWhoLikedMeMembership), (IMP)_hasSeeWhoLikedMeMembership_YES, YES);
        TryHook(membershipClasses, @selector(hasExpQuickChatMembership), (IMP)_hasExpQuickChatMembership_YES, YES);
        TryHook(membershipClasses, @selector(hasQuickChatMembershipPrivilege), (IMP)_hasQuickChatMembershipPrivilege_YES, YES);
        TryHook(membershipClasses, @selector(hasPrivacyMembership), (IMP)_hasPrivacyMembership_YES, YES);
        TryHook(membershipClasses, @selector(hasIntlMembership), (IMP)_hasIntlMembership_YES, YES);
        TryHook(membershipClasses, @selector(hasEnjoySwipeMembership), (IMP)_hasEnjoySwipeMembership_YES, YES);

        // 会员总开关: 带参数的类方法 (判断某 user 是否某类会员) -> YES
        // 这些是会员功能"是否可用"的核心判断, 类似认证的 verificationCategoryTypeWithUser:
        TryHook(membershipClasses, NSSelectorFromString(@"isMembershipDiamondUser:"), (IMP)_isMembershipUser_arg_YES, YES);
        TryHook(membershipClasses, NSSelectorFromString(@"isMembershipPartnerUser:"), (IMP)_isMembershipUser_arg_YES, YES);
        TryHook(membershipClasses, NSSelectorFromString(@"isMembershipPlatinumUser:"), (IMP)_isMembershipUser_arg_YES, YES);
        TryHook(membershipClasses, NSSelectorFromString(@"isUltraSVIPUser:"), (IMP)_isMembershipUser_arg_YES, YES);
        TryHook(membershipClasses, NSSelectorFromString(@"isSVIPUser:"), (IMP)_isMembershipUser_arg_YES, YES);
        TryHook(membershipClasses, NSSelectorFromString(@"isMembershipDiamondCard:"), (IMP)_isMembershipUser_arg_YES, YES);
        TryHook(membershipClasses, NSSelectorFromString(@"isMembershipDiamondPrivilegeGift:"), (IMP)_isMembershipUser_arg_YES, YES);

        // 会员过期 -> 永不过期
        TryHook(membershipClasses, @selector(isMembershipExpired), (IMP)_isMembershipExpired_NO, NO);
        TryHook(membershipClasses, @selector(isCurrentUserMembershipDiamondExpired), (IMP)_isCurrentUserMembershipDiamondExpired_NO, NO);
        TryHook(membershipClasses, @selector(isCurrentUserMembershipPlatinumExpired), (IMP)_isCurrentUserMembershipPlatinumExpired_NO, NO);
        TryHook(membershipClasses, @selector(isCurrentUserMembershipPartnerExpired), (IMP)_isCurrentUserMembershipPartnerExpired_NO, NO);
        TryHook(membershipClasses, @selector(isAIChatAssistantMembershipExpired), (IMP)_isAIChatAssistantMembershipExpired_NO, NO);
        TryHook(membershipClasses, @selector(isSeeWhoLikedMeMembershipExpired), (IMP)_isSeeWhoLikedMeMembershipExpired_NO, NO);
        TryHook(membershipClasses, @selector(isExpQuickChatMembershipExpired), (IMP)_isExpQuickChatMembershipExpired_NO, NO);
        TryHook(membershipClasses, @selector(isIntlMembershipExpired), (IMP)_isIntlMembershipExpired_NO, NO);
        TryHook(membershipClasses, @selector(isEnjoySwipeMembershipExpired), (IMP)_isEnjoySwipeMembershipExpired_NO, NO);

        // ============ 5. 次数限制解除 ============
        TryHook(@[@"PUGSeeLimitCounter"], @selector(total), (IMP)_total_max, NO);
        TryHook(@[@"PUGSeeLimitCounter"], @selector(remaining), (IMP)_remaining_max, NO);
        TryHook(@[@"PUGSeeLimitCounter"], @selector(isSeeValid), (IMP)_isSeeValid_YES, NO);
        TryHook(@[@"PUGSuperlikeCounter"], @selector(exhausted), (IMP)_exhausted_NO, NO);
        // 会员付费权限放行: 避免"匹配上限/开通会员"类提示继续走付费判断
        TryHook(@[@"PUGCommercializeService"], @selector(hasLetterPrivilege), (IMP)_hasLetterPrivilege_YES, YES);
        TryHook(@[@"PUGCommercializeService"], @selector(canCostTantanCoinForLetter), (IMP)_canCostTantanCoinForLetter_YES, YES);
        TryHook(@[@"PUGCommercializeService"], @selector(canCostTantanCoinForSuperLike), (IMP)_canCostTantanCoinForSuperLike_YES, YES);
        TryHook(@[@"PUGPrivilegeUseCase"], @selector(svipExpiredDate), (IMP)_svipExpiredDate_future, YES);

        // ============ 5.5 四选一(极限四选一/Picks) 次数限制解除 ============
        // 解决 "今日选择已结束" 的问题: 让免费次数永远不归零, 过期时间永远不到
        {
            TryHook(@[@"PUGMyEncounterFreePicksManager"], @selector(freePicksCount), (IMP)_freePicksCount_max, NO);
            TryHook(@[@"PUGMyEncounterFreePicksManager"], @selector(dailyFreePicksCount), (IMP)_dailyFreePicksCount_max, NO);
            TryHook(@[@"PUGUser"], @selector(picksExpiredTimestamp), (IMP)_picksExpiredTimestamp_nil, NO);
            TryHook(@[@"PUGDailyFeaturedListViewController"], @selector(hasUsedPicksFree), (IMP)_hasUsedPicksFree_NO, NO);
            TryHook(@[@"PUGQuickChatToConversationMediator"], @selector(isEnableExtremePick), (IMP)_isEnableExtremePick_YES, NO);
            XLog(@"[初始化] 已注册四选一次数限制解除 hook");
        }

        // ============ 6. 四选一接口对接 (广撒网探针) ============
        // hook 多个候选方法, 每个都写文件日志, 定位真实调用点
        {
            XLog(@"[初始化] 四选一对接插件加载, 开始注册 hook");

            // 6.1 hook performLikeOnUser:actionType:completionBlock: (正常喜欢执行点)
            SEL likeSel = NSSelectorFromString(@"performLikeOnUser:actionType:completionBlock:");
            NSArray *likeClasses = @[@"PUGIntlTribeSwipeUseCase", @"PUGSwipeUseCase",
                                     @"PUGIntlSwipeUseCase", @"PUGSwipeIntlUseCase",
                                     @"PUGTribeSwipeUseCase"];
            for (NSString *name in likeClasses) {
                Class cls = objc_getClass(name.UTF8String);
                if (cls) {
                    Method m = class_getInstanceMethod(cls, likeSel);
                    if (m) {
                        _orig_performLikeOnUser = method_getImplementation(m);
                        method_setImplementation(m, (IMP)_performLikeOnUser_redirect);
                        XLog(@"[初始化] 已 hook %@ performLikeOnUser:", name);
                    }
                }
            }

            // 6.2 hook tryPerformLikeOnUser:actionType:shouldBlock:upgradedToSuperlike:completionBlock:
            SEL trySel = NSSelectorFromString(@"tryPerformLikeOnUser:actionType:shouldBlock:upgradedToSuperlike:completionBlock:");
            for (NSString *name in likeClasses) {
                Class cls = objc_getClass(name.UTF8String);
                if (cls) {
                    Method m = class_getInstanceMethod(cls, trySel);
                    if (m) {
                        _orig_tryPerformLike = method_getImplementation(m);
                        method_setImplementation(m, (IMP)_tryPerformLike_probe);
                        XLog(@"[初始化] 已 hook %@ tryPerformLikeOnUser:", name);
                    }
                }
            }

            // 6.3 hook 划卡页 pluginLikeAction:actionType:sourceType:
            SEL plugLikeSel = NSSelectorFromString(@"pluginLikeAction:actionType:sourceType:");
            NSArray *swipeVCs = @[@"PUGSwipeViewControllerV1", @"PUGIntlTribeSwipeViewController", @"PUGSwipeViewController"];
            for (NSString *name in swipeVCs) {
                Class cls = objc_getClass(name.UTF8String);
                if (cls) {
                    Method m = class_getInstanceMethod(cls, plugLikeSel);
                    if (m) {
                        _orig_pluginLikeAction = method_getImplementation(m);
                        method_setImplementation(m, (IMP)_pluginLikeAction_probe);
                        XLog(@"[初始化] 已 hook %@ pluginLikeAction:", name);
                    }
                }
            }

            // 6.4 hook 划卡页 pluginPerformAction:actionType:sourceType:
            SEL plugPerfSel = NSSelectorFromString(@"pluginPerformAction:actionType:sourceType:");
            for (NSString *name in swipeVCs) {
                Class cls = objc_getClass(name.UTF8String);
                if (cls) {
                    Method m = class_getInstanceMethod(cls, plugPerfSel);
                    if (m) {
                        _orig_pluginPerformAction = method_getImplementation(m);
                        method_setImplementation(m, (IMP)_pluginPerformAction_probe);
                        XLog(@"[初始化] 已 hook %@ pluginPerformAction:", name);
                    }
                }
            }

            // 6.5 hook PUGSuggestedUserUseCase (真正的划卡喜欢核心类)
            SEL suggLike4 = NSSelectorFromString(@"likeUser:actionType:sourceType:completionBlock:");
            SEL suggLike3 = NSSelectorFromString(@"likeUser:sourceType:completionBlock:");
            NSArray *suggestedClasses = @[@"PUGSuggestedUserUseCase"];
            for (NSString *name in suggestedClasses) {
                Class cls = objc_getClass(name.UTF8String);
                if (cls) {
                    Method m4 = class_getInstanceMethod(cls, suggLike4);
                    if (m4) {
                        _orig_suggested_likeUser_4 = method_getImplementation(m4);
                        method_setImplementation(m4, (IMP)_suggested_likeUser_4_redirect);
                        XLog(@"[初始化] 已 hook %@ likeUser:actionType:sourceType:completionBlock:", name);
                    }
                    Method m3 = class_getInstanceMethod(cls, suggLike3);
                    if (m3) {
                        _orig_suggested_likeUser_3 = method_getImplementation(m3);
                        method_setImplementation(m3, (IMP)_suggested_likeUser_3_redirect);
                        XLog(@"[初始化] 已 hook %@ likeUser:sourceType:completionBlock:", name);
                    }
                }
            }

            // 6.6 hook 卡片列表更新: 缓存 userID -> activityDate (6.0.0 活跃时间真正来源)
            {
                Class suCls = objc_getClass("PUGSuggestedUserUseCase");
                if (suCls) {
                    Method mTime = class_getInstanceMethod(suCls, NSSelectorFromString(@"updateUserCardTimeIfNeededWithSuggestedUserArray:"));
                    if (mTime) {
                        _orig_suggested_updateTime = method_getImplementation(mTime);
                        method_setImplementation(mTime, (IMP)_suggested_updateTime_hook);
                        XLog(@"[初始化] 已 hook PUGSuggestedUserUseCase updateUserCardTimeIfNeededWithSuggestedUserArray:");
                    } else {
                        XLog(@"[初始化] 无 updateUserCardTimeIfNeededWithSuggestedUserArray:");
                    }
                    Method mDis = class_getInstanceMethod(suCls, NSSelectorFromString(@"dislikeUser:actionType:sourceType:completionBlock:"));
                    if (mDis) {
                        _orig_suggested_dislike_4 = method_getImplementation(mDis);
                        method_setImplementation(mDis, (IMP)_suggested_dislike_4_hook);
                        XLog(@"[初始化] 已 hook PUGSuggestedUserUseCase dislikeUser:actionType:sourceType:completionBlock:");
                    } else {
                        XLog(@"[初始化] 无 dislikeUser:actionType:sourceType:completionBlock:");
                    }
                }
            }

            // 6.5b hook "喜欢我的人"页面桃心 -> 四选一 pick 对接
            // PUGMyEncounterSeeLikesActionHandler performLikeOnUser:sourcePage:actionType: / tryPerformLikeOnUser:sourcePage:actionType:
            {
                Class encCls = objc_getClass("PUGMyEncounterSeeLikesActionHandler");
                if (encCls) {
                    Method mLike = class_getInstanceMethod(encCls, NSSelectorFromString(@"performLikeOnUser:sourcePage:actionType:"));
                    if (mLike) {
                        _orig_encounter_likeUser = method_getImplementation(mLike);
                        method_setImplementation(mLike, (IMP)_encounter_likeUser_redirect);
                        XLog(@"[初始化] 已 hook PUGMyEncounterSeeLikesActionHandler performLikeOnUser:sourcePage:actionType:");
                    } else {
                        XLog(@"[初始化] 喜欢我的人: 无 performLikeOnUser:sourcePage:actionType:");
                    }
                    Method mTry = class_getInstanceMethod(encCls, NSSelectorFromString(@"tryPerformLikeOnUser:sourcePage:actionType:"));
                    if (mTry) {
                        _orig_encounter_tryLikeUser = method_getImplementation(mTry);
                        method_setImplementation(mTry, (IMP)_encounter_tryLikeUser_redirect);
                        XLog(@"[初始化] 已 hook PUGMyEncounterSeeLikesActionHandler tryPerformLikeOnUser:sourcePage:actionType:");
                    } else {
                        XLog(@"[初始化] 喜欢我的人: 无 tryPerformLikeOnUser:sourcePage:actionType:");
                    }
                    // performAction:onUser:actionType: (q=actionType 是 long long)
                    Method mPerf3 = class_getInstanceMethod(encCls, NSSelectorFromString(@"performAction:onUser:actionType:"));
                    if (mPerf3) {
                        _orig_encounter_performAction3 = method_getImplementation(mPerf3);
                        method_setImplementation(mPerf3, (IMP)_encounter_performAction3_redirect);
                        XLog(@"[初始化] 已 hook PUGMyEncounterSeeLikesActionHandler performAction:onUser:actionType:");
                    } else {
                        XLog(@"[初始化] 喜欢我的人: 无 performAction:onUser:actionType:");
                    }
                    // performAction:onUser:sourcePage:actionType:
                    Method mPerf4 = class_getInstanceMethod(encCls, NSSelectorFromString(@"performAction:onUser:sourcePage:actionType:"));
                    if (mPerf4) {
                        _orig_encounter_performAction4 = method_getImplementation(mPerf4);
                        method_setImplementation(mPerf4, (IMP)_encounter_performAction4_redirect);
                        XLog(@"[初始化] 已 hook PUGMyEncounterSeeLikesActionHandler performAction:onUser:sourcePage:actionType:");
                    } else {
                        XLog(@"[初始化] 喜欢我的人: 无 performAction:onUser:sourcePage:actionType:");
                    }
                } else {
                    XLog(@"[初始化] 喜欢我的人: 类 PUGMyEncounterSeeLikesActionHandler 不存在");
                }
            }

            // 6.5c hook 桃心按钮 cell 层: PUGIntlEncounterSeeLikeCell usLikeButtonTraped / continueCardCellLikeAction:completion:
            {
                Class cellCls = objc_getClass("PUGIntlEncounterSeeLikeCell");
                if (cellCls) {
                    Method mTap = class_getInstanceMethod(cellCls, NSSelectorFromString(@"usLikeButtonTraped"));
                    if (mTap) {
                        _orig_cell_usLikeButtonTraped = method_getImplementation(mTap);
                        method_setImplementation(mTap, (IMP)_cell_usLikeButtonTraped_probe);
                        XLog(@"[初始化] 已 hook PUGIntlEncounterSeeLikeCell usLikeButtonTraped");
                    }
                    Method mCont = class_getInstanceMethod(cellCls, NSSelectorFromString(@"continueCardCellLikeAction:completion:"));
                    if (mCont) {
                        _orig_cell_continueCardCellLike = method_getImplementation(mCont);
                        method_setImplementation(mCont, (IMP)_cell_continueCardCellLike_probe);
                        XLog(@"[初始化] 已 hook PUGIntlEncounterSeeLikeCell continueCardCellLikeAction:completion:");
                    }
                } else {
                    XLog(@"[初始化] 喜欢我的人: 类 PUGIntlEncounterSeeLikeCell 不存在");
                }
            }

            // 6.5e 喜欢我的人 -> 划卡对接 (收集 seeLikesUsers + 插卡 + 批量四选一)
            XHInstallSeelikesHooks();
            XHInstallSeeLikesMatchUI();
            XHInstallNetSniffer();
            // 上次退出时开关是开的 -> 启动即恢复插卡与对接
            if (_swOn(XH_SW_SEELIKES_SWIPE)) {
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                               dispatch_get_main_queue(), ^{
                    XHSeelikesInjectToSwipe();
                    XHSeelikesStartBatchMatch();
                });
            }

            // 6.5d hook 超速配(四选一)点击/请求 -> 对接四选一 pick 接口
            {
                Class ultraCls = objc_getClass("PUGUltraInstantMatchUseCase");
                if (ultraCls) {
                    Method mReq = class_getInstanceMethod(ultraCls, NSSelectorFromString(@"requestUltraInstantMatchWithUser:matchSuccessBlock:fromPurchase:"));
                    if (mReq) {
                        _orig_ultra_request = method_getImplementation(mReq);
                        method_setImplementation(mReq, (IMP)_ultra_request_redirect);
                        XLog(@"[初始化] 已 hook PUGUltraInstantMatchUseCase requestUltraInstantMatchWithUser:matchSuccessBlock:fromPurchase:");
                    } else {
                        XLog(@"[初始化] 超速配: 无 requestUltraInstantMatchWithUser:matchSuccessBlock:fromPurchase:");
                    }
                    Method mHandle3 = class_getInstanceMethod(ultraCls, NSSelectorFromString(@"handleUltraInstantMatchClickActionWithUser:purchaseShowFrom:matchSuccessBlock:"));
                    if (mHandle3) {
                        _orig_ultra_handle3 = method_getImplementation(mHandle3);
                        method_setImplementation(mHandle3, (IMP)_ultra_handle3_redirect);
                        XLog(@"[初始化] 已 hook PUGUltraInstantMatchUseCase handleUltraInstantMatchClickActionWithUser:purchaseShowFrom:matchSuccessBlock:");
                    } else {
                        XLog(@"[初始化] 超速配: 无 handleUltraInstantMatchClickActionWithUser:purchaseShowFrom:matchSuccessBlock:");
                    }
                } else {
                    XLog(@"[初始化] 超速配: 类 PUGUltraInstantMatchUseCase 不存在");
                }
            }

            if (!_orig_performLikeOnUser && !_orig_tryPerformLike && !_orig_suggested_likeUser_4 && !_orig_suggested_likeUser_3) {
                XLog(@"[初始化] 警告: 未 hook 到任何 likeUser / performLikeOnUser 方法!");
            }

            // 6.8 hook NSURLSession (网络抓包, 抓四选一/greeting 请求)
            {
                Class sessionCls = NSClassFromString(@"NSURLSession");
                if (sessionCls) {
                    SEL sel1 = NSSelectorFromString(@"dataTaskWithRequest:");
                    Method m1 = class_getInstanceMethod(sessionCls, sel1);
                    if (m1) {
                        _orig_dataTaskWithRequest = method_getImplementation(m1);
                        method_setImplementation(m1, (IMP)_dataTaskWithRequest_probe);
                        XLog(@"[初始化] 已 hook NSURLSession dataTaskWithRequest:");
                    }
                    SEL sel2 = NSSelectorFromString(@"dataTaskWithRequest:completionHandler:");
                    Method m2 = class_getInstanceMethod(sessionCls, sel2);
                    if (m2) {
                        _orig_dataTaskWithRequestHandler = method_getImplementation(m2);
                        method_setImplementation(m2, (IMP)_dataTaskWithRequestHandler_probe);
                        XLog(@"[初始化] 已 hook NSURLSession dataTaskWithRequest:completionHandler:");
                    }
                }
            }
        }

            // 6.9 hook 划卡页 viewDidAppear: 首次自动触发一次四选一匹配
            // 注意: 自动 pick 请求会导致探探网络层 DSJSONSchemaValidation 崩溃, 暂默认关闭
            {
                static BOOL _autoPickTriggered = NO;
                Class swipeVC = objc_getClass("PUGSwipeViewControllerV1");
                if (swipeVC) {
                    Method m = class_getInstanceMethod(swipeVC, @selector(viewDidAppear:));
                    if (m) {
                        IMP orig = method_getImplementation(m);
                        // 用 block 保存 orig
                        static IMP _orig_swipe_viewDidAppear = NULL;
                        _orig_swipe_viewDidAppear = orig;
                        method_setImplementation(m, imp_implementationWithBlock(^(id self, BOOL animated) {
                            // 调原方法
                            if (_orig_swipe_viewDidAppear) {
                                ((void(*)(id, SEL, BOOL))_orig_swipe_viewDidAppear)(self, @selector(viewDidAppear:), animated);
                            }
                            // 首次进入划卡页(探探已完全就绪), 后台枚举四选一相关类和方法
                            if (!_autoPickTriggered) {
                                _autoPickTriggered = YES;
                                XLog(@"[自动四选一] 进入划卡页");
                            }
                        }));
                        XLog(@"[初始化] 已 hook PUGSwipeViewControllerV1 viewDidAppear:");
                    }
                }
            }

            // 6.9.24/6.9.25 认证状态注入: hook PUGVerification pictureVerificationType / pictureDictionary
            // 认证中心显示"已认证"读的是模型层这些方法(非 ViewModel type)。闪退根因是 _vmType_probe 无限递归,
            // 与本段无关, 已单独修复。这里恢复启用。
#if 1
            // 6.9.24 认证状态底层数据注入: hook PUGVerification pictureVerificationType / pictureDictionary / isPictureVerified
            {
                Class verModel = objc_getClass("PUGVerification");
                if (verModel) {
                    Method pt = class_getInstanceMethod(verModel, NSSelectorFromString(@"pictureVerificationType"));
                    if (pt) {
                        _orig_pictureVerificationType = method_getImplementation(pt);
                        method_setImplementation(pt, (IMP)_pictureVerificationType_probe);
                        XLog(@"[认证数据] 已 hook PUGVerification pictureVerificationType");
                    } else XLog(@"[认证数据] 无 pictureVerificationType");
                    Method pd = class_getInstanceMethod(verModel, NSSelectorFromString(@"pictureDictionary"));
                    if (pd) {
                        _orig_pictureDictionary = method_getImplementation(pd);
                        method_setImplementation(pd, (IMP)_pictureDictionary_probe);
                        XLog(@"[认证数据] 已 hook PUGVerification pictureDictionary");
                    } else XLog(@"[认证数据] 无 pictureDictionary");
                    // 补充: isPictureVerified (BOOL), 认证中心也可能读它
                    Method piv = class_getInstanceMethod(verModel, NSSelectorFromString(@"isPictureVerified"));
                    if (piv) {
                        method_setImplementation(piv, (IMP)_isPictureVerified_YES);
                        XLog(@"[认证数据] 已 hook PUGVerification isPictureVerified");
                    } else XLog(@"[认证数据] 无 isPictureVerified");
                } else {
                    XLog(@"[认证数据] 类 PUGVerification 不存在");
                }
            }

            // 6.9.25 实名认证(身份证) 注入: hook PUGVerification isIDCardVerified / identityVerificationType / idCardDictionary / identityDictionary
            {
                Class verModel = objc_getClass("PUGVerification");
                if (verModel) {
                    Method m1 = class_getInstanceMethod(verModel, NSSelectorFromString(@"isIDCardVerified"));
                    if (m1) {
                        _orig_isIDCardVerified = method_getImplementation(m1);
                        method_setImplementation(m1, (IMP)_isIDCardVerified_probe);
                        XLog(@"[实名注入] 已 hook PUGVerification isIDCardVerified");
                    } else XLog(@"[实名注入] 无 isIDCardVerified");
                    Method m2 = class_getInstanceMethod(verModel, NSSelectorFromString(@"identityVerificationType"));
                    if (m2) {
                        _orig_identityVerificationType = method_getImplementation(m2);
                        method_setImplementation(m2, (IMP)_identityVerificationType_probe);
                        XLog(@"[实名注入] 已 hook PUGVerification identityVerificationType");
                    } else XLog(@"[实名注入] 无 identityVerificationType");
                    Method m3 = class_getInstanceMethod(verModel, NSSelectorFromString(@"idCardDictionary"));
                    if (m3) {
                        _orig_idCardDictionary = method_getImplementation(m3);
                        method_setImplementation(m3, (IMP)_idCardDictionary_probe);
                        XLog(@"[实名注入] 已 hook PUGVerification idCardDictionary");
                    } else XLog(@"[实名注入] 无 idCardDictionary");
                    Method m4 = class_getInstanceMethod(verModel, NSSelectorFromString(@"identityDictionary"));
                    if (m4) {
                        _orig_identityDictionary = method_getImplementation(m4);
                        method_setImplementation(m4, (IMP)_identityDictionary_probe);
                        XLog(@"[实名注入] 已 hook PUGVerification identityDictionary");
                    } else XLog(@"[实名注入] 无 identityDictionary");
                } else {
                    XLog(@"[实名注入] 类 PUGVerification 不存在");
                }
            }
#endif

            // 6.9.29 发消息实名认证拦截注入: isIdentityVerificationNoActive/Pending -> NO
            {
                Class verModel = objc_getClass("PUGVerification");
                if (verModel) {
                    Method n1 = class_getInstanceMethod(verModel, NSSelectorFromString(@"isIdentityVerificationNoActive"));
                    if (n1) {
                        _orig_isIdentityNoActive = method_getImplementation(n1);
                        method_setImplementation(n1, (IMP)_isIdentityNoActive_probe);
                        XLog(@"[实名拦截] 已 hook isIdentityVerificationNoActive");
                    } else XLog(@"[实名拦截] 无 isIdentityVerificationNoActive");
                    Method n2 = class_getInstanceMethod(verModel, NSSelectorFromString(@"isIdentityVerificationPending"));
                    if (n2) {
                        _orig_isIdentityPending = method_getImplementation(n2);
                        method_setImplementation(n2, (IMP)_isIdentityPending_probe);
                        XLog(@"[实名拦截] 已 hook isIdentityVerificationPending");
                    } else XLog(@"[实名拦截] 无 isIdentityVerificationPending");
                } else {
                    XLog(@"[实名拦截] 类 PUGVerification 不存在");
                }
            }

            // 6.9.27 认证中心 ViewModel type 注入 (认证中心真正读的状态源)
            {
                // 【闪退修复】只 hook 基类 BaseViewModel + MetaCellModel(有独立 type 的类)。
                // 之前 hook 9 个类, 其中子类(RealnameCellModel/StudentCellModel 等)没有 override type,
                // class_getInstanceMethod 返回父类方法, 导致 method_setImplementation 重复 hook 到 _vmType_probe 自己,
                // orig 指向 _vmType_probe -> 无限递归 -> 主线程卡死被 watchdog 杀 = 闪退。
                NSArray *vmClasses = @[@"PUGVerificationCenterBaseViewModel", @"PUGVerificationCenterMetaCellModel"];
                for (NSString *clsName in vmClasses) {
                    Class cc = objc_getClass([clsName UTF8String]);
                    if (!cc) continue;
                    Method tm = class_getInstanceMethod(cc, NSSelectorFromString(@"type"));
                    if (tm) {
                        IMP cur = method_getImplementation(tm);
                        // 防重复 hook: 如果已经是 _vmType_probe 就跳过
                        if (cur != (IMP)_vmType_probe) {
                            SwapMethod(cc, NSSelectorFromString(@"type"), (IMP)_vmType_probe, NO);
                            XLog(@"[认证VM注入] 已 hook %@ type -> 2", clsName);
                        }
                    }
                }
            }

            // 6.9.31 强制实名认证弹窗拦截: shouldShowMandatoryVerification -> NO / showMandatoryVerificationIfNeededWithData 拦截
            {
                NSArray *mandatoryClasses = @[@"PUGMandatoryVerificationHandler", @"PUGMandatoryIdentifierVerificationUseCase",
                                              @"PUGMandatoryPictureVerificationUseCase", @"PUGMandatoryVerificationNetworkPlugin",
                                              @"PUGMessagesViewController", @"PUGMandatoryVerificationPopViewController"];
                for (NSString *clsName in mandatoryClasses) {
                    Class cc = objc_getClass([clsName UTF8String]);
                    if (!cc) continue;
                    Method m1 = class_getInstanceMethod(cc, NSSelectorFromString(@"shouldShowMandatoryVerification"));
                    if (m1) { method_setImplementation(m1, (IMP)_shouldShowMandatoryVerification_NO); XLog(@"[强制实名拦截] 已 hook %@ shouldShowMandatoryVerification", clsName); }
                    Method m2 = class_getInstanceMethod(cc, NSSelectorFromString(@"isMandatoryVerification"));
                    if (m2) { method_setImplementation(m2, (IMP)_isMandatoryVerification_NO); XLog(@"[强制实名拦截] 已 hook %@ isMandatoryVerification", clsName); }
                    Method m3 = class_getInstanceMethod(cc, NSSelectorFromString(@"showMandatoryVerificationIfNeededWithData:"));
                    if (m3) { method_setImplementation(m3, (IMP)_showMandatoryVerificationIfNeeded_block); XLog(@"[强制实名拦截] 已 hook %@ showMandatoryVerificationIfNeededWithData:", clsName); }
                }
            }

            // 6.9.32 认证中心控制器 pictureVerificationType/identityVerificationType -> 2
            {
                Class centerVC = objc_getClass("PUGVerificationCenterViewController");
                if (centerVC) {
                    Method p1 = class_getInstanceMethod(centerVC, NSSelectorFromString(@"pictureVerificationType"));
                    if (p1) { SwapMethod(centerVC, NSSelectorFromString(@"pictureVerificationType"), (IMP)_vcPictureVerificationType_probe, NO); XLog(@"[认证中心VC] 已 hook pictureVerificationType -> 2"); }
                    else XLog(@"[认证中心VC] 无 pictureVerificationType");
                    Method p2 = class_getInstanceMethod(centerVC, NSSelectorFromString(@"identityVerificationType"));
                    if (p2) { SwapMethod(centerVC, NSSelectorFromString(@"identityVerificationType"), (IMP)_vcIdentityVerificationType_probe, NO); XLog(@"[认证中心VC] 已 hook identityVerificationType -> 2"); }
                    else XLog(@"[认证中心VC] 无 identityVerificationType");
                } else {
                    XLog(@"[认证中心VC] 类 PUGVerificationCenterViewController 不存在");
                }
            }

            // PUGAccountManager 登录态 hook (拦截清空登录态功能, 受 xh_switch.block_clear 开关控制)
            {
                Class amCls = objc_getClass("PUGAccountManager");
                if (amCls) {
                    Method sc = class_getInstanceMethod(amCls, NSSelectorFromString(@"setCurrentUser:"));
                    if (sc) {
                        _orig_setCurrentUser = method_getImplementation(sc);
                        method_setImplementation(sc, (IMP)_setCurrentUser_probe);
                        XLog(@"[初始化] 已hook PUGAccountManager setCurrentUser:");
                    }
                }
            }

            // 强制验证关闭: hook fetchRemoteNeedShowForceVerificationStatusWithCompletion (篡改 needShow=NO)
            {
                SEL sel = NSSelectorFromString(@"fetchRemoteNeedShowForceVerificationStatusWithCompletion:");
                NSArray *vcClasses = @[@"PUGGrowthForceVerificationUseCase",
                                       @"PUGVerificationManager", @"PUGVerificationUseCase",
                                       @"PUGVerificationCenterUseCase", @"VerificationUseCase",
                                       @"PUGUserVerificationManager", @"PUGAccountVerificationManager"];
                for (NSString *name in vcClasses) {
                    Class cls = objc_getClass(name.UTF8String);
                    if (!cls) continue;
                    Method m = class_getInstanceMethod(cls, sel);
                    if (!m) m = class_getClassMethod(cls, sel);
                    if (m) {
                        _orig_fetchRemoteForceVerification = method_getImplementation(m);
                        method_setImplementation(m, (IMP)_fetchRemoteForceVerification_probe);
                        XLog(@"[初始化] 已hook %@ fetchRemoteNeedShowForceVerificationStatusWithCompletion:", name);
                    }
                }
            }

            // 强制验证开关 (shouldEnableForceVerification 系列 -> NO)
            {
                SEL sel1 = NSSelectorFromString(@"shouldEnableForceVerification");
                SEL sel2 = NSSelectorFromString(@"shouldEnableForceVerificationHaveSkip");
                SEL sel3 = NSSelectorFromString(@"shouldEnableForceVerificationNoneSkip");
                Class cls = objc_getClass("PUGGrowthForceVerificationUseCase");
                if (cls) {
                    Method m;
                    m = class_getInstanceMethod(cls, sel1);
                    if (m) { _orig_shouldEnableForceVerification = method_getImplementation(m); method_setImplementation(m, (IMP)_shouldEnableForceVerification_probe); XLog(@"[初始化] 已hook shouldEnableForceVerification"); }
                    m = class_getInstanceMethod(cls, sel2);
                    if (m) { _orig_shouldEnableForceVerificationHaveSkip = method_getImplementation(m); method_setImplementation(m, (IMP)_shouldEnableForceVerificationHaveSkip_probe); XLog(@"[初始化] 已hook shouldEnableForceVerificationHaveSkip"); }
                    m = class_getInstanceMethod(cls, sel3);
                    if (m) { _orig_shouldEnableForceVerificationNoneSkip = method_getImplementation(m); method_setImplementation(m, (IMP)_shouldEnableForceVerificationNoneSkip_probe); XLog(@"[初始化] 已hook shouldEnableForceVerificationNoneSkip"); }
                }
            }

    }
}


// ============================================================
// 红球(自动点赞/匹配) + 蓝球(顺发) 悬浮按钮 —— 移植自 xihuan_njb (纯 Runtime, 无授权)
// ============================================================
static IMP orig_SwipeVC_viewWillAppear = NULL;
static IMP orig_SwipeVC_viewWillDisappear = NULL;
static IMP orig_ConvList_viewWillAppear = NULL;

static void xh_showXihuan(id self, SEL _cmd) {
    XLog(@"[红球] 点击喜欢红球, 打开自动点赞面板");
    ((void(*)(id, SEL, id))objc_msgSend)(self, NSSelectorFromString(@"showXihuanMainVc:"), nil);
}
static void xh_showXihuanMainVc(id self, SEL _cmd, UIButton *sender) {
    HelloXihuanMainViewController *mainVc = [[HelloXihuanMainViewController alloc] init];
    mainVc.sourceVc = self;
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:mainVc];
    nav.modalPresentationStyle = UIModalPresentationFullScreen;
    ((void(*)(id, SEL, id, BOOL, id))objc_msgSend)(self, NSSelectorFromString(@"presentViewController:animated:completion:"), nav, YES, nil);
}
static void xh_showSendEntry(id self, SEL _cmd) {
    XLog(@"[蓝球] 点击顺发按钮, 打开顺发面板");
    ((void(*)(id, SEL, id))objc_msgSend)(self, NSSelectorFromString(@"showSendMainVc:"), nil);
}
static void xh_showSendMainVc(id self, SEL _cmd, UIButton *sender) {
    HelloXihuanMainViewController *mainVc = [[HelloXihuanMainViewController alloc] init];
    mainVc.sourceVc = self;
    mainVc.entryType = 1; // 1 = 顺发模式
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:mainVc];
    nav.modalPresentationStyle = UIModalPresentationFullScreen;
    ((void(*)(id, SEL, id, BOOL, id))objc_msgSend)(self, NSSelectorFromString(@"presentViewController:animated:completion:"), nav, YES, nil);
}

static inline UIView *xh_view(id obj) {
    return ((UIView *(*)(id, SEL))objc_msgSend)(obj, NSSelectorFromString(@"view"));
}

// ============ 悬浮按钮拖动 + 位置持久化 ============
static NSString *const kXHBallPosRedKey = @"xh_ball_pos_red";    // 红球位置 (x,y)
static NSString *const kXHBallPosBlueKey = @"xh_ball_pos_blue";  // 蓝球位置 (x,y)

static const void *kXHBallPosKeyAssoc = &kXHBallPosKeyAssoc;            // 关联: 位置存储 key
static const void *kXHBallStartFrameAssoc = &kXHBallStartFrameAssoc;    // 关联: 拖动起始 frame
static const void *kXHBallStartPointAssoc = &kXHBallStartPointAssoc;    // 关联: 拖动起始手势位移

// 读取持久化位置 (无则返回 CGPointZero, 表示用默认位置)
static CGPoint xh_loadBallPos(NSString *key) {
    NSString *str = [[NSUserDefaults standardUserDefaults] stringForKey:key];
    if (str && str.length > 0) {
        NSArray *parts = [str componentsSeparatedByString:@","];
        if (parts.count == 2) {
            return CGPointMake([parts[0] floatValue], [parts[1] floatValue]);
        }
    }
    return CGPointZero;
}

// 保存位置
static void xh_saveBallPos(NSString *key, CGPoint p) {
    [[NSUserDefaults standardUserDefaults] setObject:[NSString stringWithFormat:@"%.0f,%.0f", p.x, p.y] forKey:key];
    [[NSUserDefaults standardUserDefaults] synchronize];
}

// 拖动手势处理目标 (单例, 提供 handlePan: 供 UIPanGestureRecognizer 回调)
@interface XHBallGestureHandler : NSObject
+ (instancetype)shared;
- (void)handlePan:(UIPanGestureRecognizer *)pan;
@end

@implementation XHBallGestureHandler
+ (instancetype)shared {
    static XHBallGestureHandler *inst = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ inst = [[XHBallGestureHandler alloc] init]; });
    return inst;
}
- (void)handlePan:(UIPanGestureRecognizer *)pan {
    UIButton *btn = (UIButton *)pan.view;
    if (![btn isKindOfClass:[UIButton class]]) return;
    switch (pan.state) {
        case UIGestureRecognizerStateBegan: {
            objc_setAssociatedObject(btn, kXHBallStartFrameAssoc,
                [NSValue valueWithCGRect:btn.frame], OBJC_ASSOCIATION_RETAIN_NONATOMIC);
            objc_setAssociatedObject(btn, kXHBallStartPointAssoc,
                [NSValue valueWithCGPoint:[pan translationInView:btn.superview]], OBJC_ASSOCIATION_RETAIN_NONATOMIC);
            break;
        }
        case UIGestureRecognizerStateChanged: {
            NSValue *sfv = objc_getAssociatedObject(btn, kXHBallStartFrameAssoc);
            NSValue *spv = objc_getAssociatedObject(btn, kXHBallStartPointAssoc);
            if (!sfv || !spv) return;
            CGRect startFrame = [sfv CGRectValue];
            CGPoint startPoint = [spv CGPointValue];
            CGPoint trans = [pan translationInView:btn.superview];

            CGRect nf = startFrame;
            nf.origin.x = startFrame.origin.x + (trans.x - startPoint.x);
            nf.origin.y = startFrame.origin.y + (trans.y - startPoint.y);

            CGFloat sw = [UIScreen mainScreen].bounds.size.width;
            CGFloat sh = [UIScreen mainScreen].bounds.size.height;
            if (nf.origin.x < 0) nf.origin.x = 0;
            if (nf.origin.y < 0) nf.origin.y = 0;
            if (nf.origin.x + nf.size.width > sw) nf.origin.x = sw - nf.size.width;
            if (nf.origin.y + nf.size.height > sh) nf.origin.y = sh - nf.size.height;
            btn.frame = nf;
            break;
        }
        case UIGestureRecognizerStateEnded:
        case UIGestureRecognizerStateCancelled: {
            NSString *posKey = objc_getAssociatedObject(btn, kXHBallPosKeyAssoc);
            if (posKey) {
                xh_saveBallPos(posKey, btn.frame.origin);
                XLog(@"[拖动] 保存位置 %@ -> (%.0f, %.0f)", posKey, btn.frame.origin.x, btn.frame.origin.y);
            }
            break;
        }
        default: break;
    }
}
@end

// 给按钮加拖动手势, posKey 用于位置持久化
static void xh_installDragGesture(UIButton *btn, NSString *posKey) {
    objc_setAssociatedObject(btn, kXHBallPosKeyAssoc, posKey, OBJC_ASSOCIATION_COPY_NONATOMIC);
    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:[XHBallGestureHandler shared] action:@selector(handlePan:)];
    pan.cancelsTouchesInView = NO;  // 不拦截点击, 保持按钮 tap 事件可用
    [btn addGestureRecognizer:pan];
}

static void xh_new_SwipeVC_viewWillAppear(id self, SEL _cmd, BOOL animated) {
    if (orig_SwipeVC_viewWillAppear) ((void(*)(id, SEL, BOOL))orig_SwipeVC_viewWillAppear)(self, _cmd, animated);

    // 无论是否拦截都要绑定当前划卡VC: 否则任务启动后拿不到卡片, 会一直空转(表现为"一直划")
    if ([self isKindOfClass:[UIViewController class]]) {
        [HelloXihuanManager shared].vc = (UIViewController *)self;
    }

    // 授权拦截后不再挂载红球
    if (XHAuthBlocked()) return;

    UIButton *btn = [HelloXihuanManager shared].outActionBtn;
    if (!btn) {
        btn = [UIButton buttonWithType:UIButtonTypeCustom];
        CGFloat w = 56;
        CGFloat screenH = [UIScreen mainScreen].bounds.size.height;
        CGFloat screenW = [UIScreen mainScreen].bounds.size.width;
        // 默认位置: 左侧中部
        CGPoint defaultPos = CGPointMake(16, screenH * 0.55);
        // 读取持久化位置 (用户拖过则用保存的位置)
        CGPoint savedPos = xh_loadBallPos(kXHBallPosRedKey);
        if (savedPos.x != 0 || savedPos.y != 0) {
            // 校验在屏幕内
            if (savedPos.x >= 0 && savedPos.y >= 0 && savedPos.x + w <= screenW && savedPos.y + w <= screenH) {
                defaultPos = savedPos;
            }
        }
        btn.frame = CGRectMake(defaultPos.x, defaultPos.y, w, w);
        btn.layer.cornerRadius = w / 2;
        btn.backgroundColor = [UIColor colorWithRed:1.0 green:0.3 blue:0.3 alpha:0.85];
        [btn setTitle:[HelloHelper strWithUTF8Hex:@"e5969ce6aca2"] forState:UIControlStateNormal]; // 喜欢
        btn.titleLabel.font = [UIFont systemFontOfSize:13];
        [btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        [btn addTarget:self action:NSSelectorFromString(@"showXihuan") forControlEvents:UIControlEventTouchUpInside];
        // 拖动手势 (位置持久化)
        xh_installDragGesture(btn, kXHBallPosRedKey);
        [HelloXihuanManager shared].outActionBtn = btn;
    }
    // 每次出现都把 target 重绑到当前划卡页实例: 按钮是复用的, 页面会重建, 旧 target 会让任务拿到失效VC
    [btn removeTarget:nil action:NULL forControlEvents:UIControlEventAllEvents];
    [btn addTarget:self action:NSSelectorFromString(@"showXihuan") forControlEvents:UIControlEventTouchUpInside];
    [xh_view(self) addSubview:btn];
    [xh_view(self) bringSubviewToFront:btn];
    [HelloXihuanManager shared].vc = self;
    [[HelloXihuanManager shared] refreshCountdownIfRunning];
    XLog(@"[红球] 已挂到划卡页");
}

static void xh_new_SwipeVC_viewWillDisappear(id self, SEL _cmd, BOOL animated) {
    if (orig_SwipeVC_viewWillDisappear) ((void(*)(id, SEL, BOOL))orig_SwipeVC_viewWillDisappear)(self, _cmd, animated);
    UIButton *btn = [HelloXihuanManager shared].outActionBtn;
    if (btn && btn.superview == xh_view(self)) {
        [btn removeFromSuperview];
        XLog(@"[红球] 离开划卡页, 已移除");
    }
    [HelloCountdownLabel hide];
}

static void xh_new_ConvList_viewWillAppear(id self, SEL _cmd, BOOL animated) {
    if (orig_ConvList_viewWillAppear) ((void(*)(id, SEL, BOOL))orig_ConvList_viewWillAppear)(self, _cmd, animated);

    // 无论是否拦截都要绑定当前会话列表VC
    if ([self isKindOfClass:[UIViewController class]]) {
        [HelloSendMgr shared].listVC = (UIViewController *)self;
    }

    // 授权拦截后不再挂载蓝球
    if (XHAuthBlocked()) return;

    UIButton *btn = [HelloSendMgr shared].sendEntryBtn;
    if (!btn) {
        btn = [UIButton buttonWithType:UIButtonTypeCustom];
        CGFloat w = 56;
        CGFloat screenH = [UIScreen mainScreen].bounds.size.height;
        CGFloat screenW = [UIScreen mainScreen].bounds.size.width;
        // 默认位置: 右侧中部
        CGPoint defaultPos = CGPointMake(screenW - w - 16, screenH * 0.55);
        // 读取持久化位置 (用户拖过则用保存的位置)
        CGPoint savedPos = xh_loadBallPos(kXHBallPosBlueKey);
        if (savedPos.x != 0 || savedPos.y != 0) {
            if (savedPos.x >= 0 && savedPos.y >= 0 && savedPos.x + w <= screenW && savedPos.y + w <= screenH) {
                defaultPos = savedPos;
            }
        }
        btn.frame = CGRectMake(defaultPos.x, defaultPos.y, w, w);
        btn.layer.cornerRadius = w / 2;
        btn.backgroundColor = [UIColor colorWithRed:0.2 green:0.6 blue:1.0 alpha:0.85];
        [btn setTitle:[HelloHelper strWithUTF8Hex:@"e9a1bae58f91"] forState:UIControlStateNormal]; // 顺发
        btn.titleLabel.font = [UIFont systemFontOfSize:13];
        [btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        [btn addTarget:self action:NSSelectorFromString(@"showSendEntry") forControlEvents:UIControlEventTouchUpInside];
        // 拖动手势 (位置持久化)
        xh_installDragGesture(btn, kXHBallPosBlueKey);
        [HelloSendMgr shared].sendEntryBtn = btn;
    }
    // 每次出现都把 target 重绑到当前会话列表页实例
    [btn removeTarget:nil action:NULL forControlEvents:UIControlEventAllEvents];
    [btn addTarget:self action:NSSelectorFromString(@"showSendEntry") forControlEvents:UIControlEventTouchUpInside];
    [xh_view(self) addSubview:btn];
    [xh_view(self) bringSubviewToFront:btn];
    [HelloSendMgr shared].listVC = self;
    [[HelloSendMgr shared] refreshCountdownIfRunning];
    XLog(@"[蓝球] 已挂到会话列表页");
}

static void xh_new_ConvList_viewWillDisappear(id self, SEL _cmd, BOOL animated) {
    UIButton *btn = [HelloSendMgr shared].sendEntryBtn;
    if (btn && btn.superview == xh_view(self)) {
        [btn removeFromSuperview];
        XLog(@"[蓝球] 离开会话列表页, 已移除");
    }
    [HelloCountdownLabel hide];
}

static void installXihuanBalls(void) {
    @try {
        Class swipeCls = NSClassFromString(@"PUGSwipeViewControllerV1");
        if (swipeCls) {
            Method m = class_getInstanceMethod(swipeCls, @selector(viewWillAppear:));
            if (m) { orig_SwipeVC_viewWillAppear = method_getImplementation(m); method_setImplementation(m, (IMP)xh_new_SwipeVC_viewWillAppear); }
            m = class_getInstanceMethod(swipeCls, @selector(viewWillDisappear:));
            if (m) { orig_SwipeVC_viewWillDisappear = method_getImplementation(m); method_setImplementation(m, (IMP)xh_new_SwipeVC_viewWillDisappear); }
            class_addMethod(swipeCls, NSSelectorFromString(@"showXihuan"), (IMP)xh_showXihuan, "v@:");
            class_addMethod(swipeCls, NSSelectorFromString(@"showXihuanMainVc:"), (IMP)xh_showXihuanMainVc, "v@:@");
            XLog(@"[红球] 已 hook PUGSwipeViewControllerV1");
        } else {
            XLog(@"[红球] 未找到 PUGSwipeViewControllerV1 类");
        }

        Class convCls = NSClassFromString(@"PUGConversationListViewController");
        if (convCls) {
            Method m = class_getInstanceMethod(convCls, @selector(viewWillAppear:));
            if (m) { orig_ConvList_viewWillAppear = method_getImplementation(m); method_setImplementation(m, (IMP)xh_new_ConvList_viewWillAppear); }
            m = class_getInstanceMethod(convCls, @selector(viewWillDisappear:));
            if (m) method_setImplementation(m, (IMP)xh_new_ConvList_viewWillDisappear);
            class_addMethod(convCls, NSSelectorFromString(@"showSendEntry"), (IMP)xh_showSendEntry, "v@:");
            class_addMethod(convCls, NSSelectorFromString(@"showSendMainVc:"), (IMP)xh_showSendMainVc, "v@:@");
            XLog(@"[蓝球] 已 hook PUGConversationListViewController");
        } else {
            XLog(@"[蓝球] 未找到 PUGConversationListViewController 类");
        }
    } @catch (NSException *e) {
        XLog(@"[红球蓝球] hook 异常: %@", e);
    }
}
