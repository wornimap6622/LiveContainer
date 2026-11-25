//
//  HelloXihuanManager.h
//  自动点赞核心管理器 (点喜欢.deb 完整复刻)
//
#import <UIKit/UIKit.h>

@interface HelloXihuanManager : NSObject

// 运行状态
@property (nonatomic, assign) BOOL isStart;
// 定时器
@property (nonatomic, strong) NSTimer *timer;
// 任务数量 (匹配人数), 0=不限
@property (nonatomic, assign) NSInteger taskNumber;
// 速度(秒/次)
@property (nonatomic, assign) double taskSpeed;
// 速度区间上限(秒/次)。<= taskSpeed 时 = 固定速度 taskSpeed；> taskSpeed 时在区间内随机
@property (nonatomic, assign) double taskSpeedMax;
// 速度原始输入串(如 "1-3" / "1.5")，用于面板回显
@property (nonatomic, strong) NSString *taskSpeedText;
// 活跃时间(分钟), 0=不限
@property (nonatomic, assign) NSInteger activeTime;
// 已处理数
@property (nonatomic, assign) NSInteger alreadyTask;
// 当前划卡 VC
@property (nonatomic, strong) UIViewController *vc;
// 悬浮按钮
@property (nonatomic, weak) UIButton *outActionBtn;
// 任务类型: 0=喜欢 1=关注 2=评论 3=消息
@property (nonatomic, assign) NSInteger type;
// 消息文本
@property (nonatomic, strong) NSString *msgText;
// 用户列表(待处理)
@property (nonatomic, strong) NSMutableArray *userArray;
// 已点赞/关注/评论的用户 objectID 列表
@property (nonatomic, strong) NSMutableArray *parisedUserArray;
@property (nonatomic, strong) NSMutableArray *followUserArray;
@property (nonatomic, strong) NSMutableArray *commentUserArray;
// 连续无卡计数 (防卡死)
@property (nonatomic, assign) NSInteger noCardCount;

+ (instancetype)shared;

- (void)startWithVc:(UIViewController *)vc type:(NSInteger)type;
- (void)startTask;
- (void)stopTask;
- (void)timerTick;
// 任务运行中则重新显示倒计时 (页面切回时调用)
- (void)refreshCountdownIfRunning;
- (void)saveData;
// 解析速度输入，支持 "1-3" / "1.5-3" / "1.5" 等；成功返回 YES 并更新 taskSpeed/taskSpeedMax/taskSpeedText
- (BOOL)parseSpeed:(NSString *)s;

@end
