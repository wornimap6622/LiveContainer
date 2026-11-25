//
//  HelloSendMgr.h
//  顺发消息/顺发图片管理器 (借鉴视屏.deb 的 MsgPageSendTextMgr/MsgPageSendPicMgr)
//
//  核心链路:
//   1. 从会话列表 VC (PUGConversationListViewController) 拿会话数组
//   2. 遍历会话, 逐个 initWithConversation:shouldLoadMessages: 创建聊天页
//   3. 发送文本: sendText: (探探原生)
//   4. 发送图片: 从本地固定路径读图 -> processAndUploadImages:completion: 上传 -> 发送
//
#import <UIKit/UIKit.h>

@interface HelloSendMgr : NSObject

// 运行状态
@property (nonatomic, assign) BOOL isRunning;
// 定时器
@property (nonatomic, strong) NSTimer *timer;
// 活跃时间 (0=发送所有)
@property (nonatomic, assign) NSInteger activeTime;
// 速度(秒/次)
@property (nonatomic, assign) double sendDelay;
// 文字消息 (#分割连续发送 @分割随机发送)
@property (nonatomic, strong) NSString *msgText;
// 已选图片 (顺发图片用)
@property (nonatomic, strong) UIImage *selectedImage;
// 语音文件 URL 数组 (顺发语音用, Documents/audio/*.m4a)
@property (nonatomic, strong) NSMutableArray *audioFileURLs;
// 视频文件路径数组 (顺发视频用, Documents/video/*.mp4)
@property (nonatomic, strong) NSMutableArray *videoFilePaths;
// 类型: 0=顺发消息 1=顺发图片 2=顺发语音 3=顺发视频
@property (nonatomic, assign) NSInteger sendType;
// 图片发送方式: 0=旧版 PUGImageMessageParameterBuilder, 1=现在 PUGEXIFImage+sendImageConfirmed
@property (nonatomic, assign) NSInteger imageSendMode;
// 勾选: 先发“对方先开口”的聊天框, 再发其余会话(含匹配); 默认 YES
@property (nonatomic, assign) BOOL prioritizeIncoming;
// 已发送数
@property (nonatomic, assign) NSInteger alreadySent;
// 本次任务会话总数 (用于倒计时, 启动时快照, 不随 pop 减少)
@property (nonatomic, assign) NSInteger totalConversations;
// 会话列表 VC
@property (nonatomic, weak) UIViewController *listVC;
// 悬浮按钮
@property (nonatomic, weak) UIButton *sendEntryBtn;
// 待发送会话数组
@property (nonatomic, strong) NSMutableArray *conversationArray;
// 已发送的会话ID
@property (nonatomic, strong) NSMutableArray *sentArray;

+ (instancetype)shared;

- (void)startSendWithVc:(UIViewController *)listVC type:(NSInteger)type;
- (void)startTask;
- (void)stopTask;
- (void)sendNext;
// 任务运行中则重新显示倒计时 (页面切回时调用)
- (void)refreshCountdownIfRunning;
- (void)saveData;

@end
