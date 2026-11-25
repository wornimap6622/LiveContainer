//
//  HelloAuth.h
//  远程授权校验 (每次启动检测)
//  raw直链内容: 1=正常使用, 2=停止使用
//
#import <Foundation/Foundation.h>

// 全局函数: 是否已授权拦截(被【2】拦截)。供红球/蓝球/悬浮球挂载时判断, 拦截后不再挂载
BOOL XHAuthBlocked(void);

// 全局函数: 设置心跳间隔(秒, 5~3600)。供设置面板/输入框调用, 持久化到 NSUserDefaults
void XHSetHeartbeatInterval(double seconds);

@interface HelloAuth : NSObject

// 授权状态: YES=已放行, NO=已拦截
@property (nonatomic, readonly) BOOL passed;
// 是否已校验完成
@property (nonatomic, readonly) BOOL checked;

+ (instancetype)shared;

// 启动时调用: 异步请求授权直链, 完成后回调
- (void)startCheck;

// 云端停用控制 (HelloCloud 调用): blocked=YES 触发拦截, NO 恢复
// 复用与 Gitee 直链相同的拦截机制 (g_authBlocked + removeButtons), 二者任一拦截即生效
- (void)setCloudBlocked:(BOOL)blocked;

// 弹"请联系作者"提示框
- (void)showContactAlert;

@end
