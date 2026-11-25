//
//  HelloXihuanMainViewController.h
//  自动点赞设置面板
//
#import <UIKit/UIKit.h>

@interface HelloXihuanMainViewController : UIViewController

@property (nonatomic, strong) UIViewController *sourceVc;
@property (nonatomic, weak) UITextField *numberTextField;   // 匹配人数
@property (nonatomic, weak) UITextField *timeField;         // 活跃时间(分钟)
@property (nonatomic, weak) UITextField *speedField;        // 速度(秒)
@property (nonatomic, weak) UISegmentedControl *segmentedControl; // 类型
@property (nonatomic, assign) NSInteger type;

// 顺发模式字段
@property (nonatomic, assign) NSInteger entryType;          // 0=自动匹配 1=顺发
@property (nonatomic, weak) UITextField *activeTimeField;   // 活跃时间(0=发送所有)
@property (nonatomic, weak) UITextField *sendDelayField;    // 顺发速度(秒)
@property (nonatomic, weak) UITextField *msgTextField;      // 文字消息 (#连续 @随机)
@property (nonatomic, weak) UIImageView *imagePreviewView;  // 图片预览
@property (nonatomic, weak) UIButton *deleteImageBtn;       // 删除图片按钮
@property (nonatomic, weak) UIButton *oldImageModeBtn;          // 旧版发图勾选
@property (nonatomic, weak) UIButton *currentImageModeBtn;      // 现在发图勾选
@property (nonatomic, weak) UIButton *prioritizeIncomingBtn;        // 先发聊天框再发配对人勾选
@property (nonatomic, strong) UIImage *selectedImage;       // 已选图片
@property (nonatomic, weak) UIScrollView *scrollView;       // 顺发面板滚动容器
@property (nonatomic, strong) UISegmentedControl *sendTypeSeg; // 发送类型: 文本/图片/语音/视频
@property (nonatomic, weak) UILabel *audioHintLabel;        // 语音文件提示
@property (nonatomic, weak) UILabel *videoHintLabel;        // 视频文件提示

// 工具区
@property (nonatomic, weak) UITextField *versionField;      // 伪装版本号输入框
@property (nonatomic, weak) UIButton *deviceResetBtn;         // 一键新机按钮

@end
