//
//  HelloXihuanMainViewController.m
//  自动点赞设置面板 (点喜欢.deb 完整复刻)
//  中文用 UTF-8 hex 运行时构造, 绕过 clang 编译期中文丢失
//
#import "HelloXihuanMainViewController.h"
#import "HelloXihuanManager.h"
#import "HelloSendMgr.h"
#import "HelloHelper.h"

@interface HelloXihuanMainViewController () <UIImagePickerControllerDelegate, UINavigationControllerDelegate>
- (void)didSelectOldImageMode;
- (void)didSelectNewImageMode;
- (void)refreshImageModeButtons;
- (void)setupPrioritizeIncomingView:(CGFloat *)y superview:(UIView *)container;
- (void)didTogglePrioritizeIncoming;
- (void)refreshPrioritizeIncomingButton;
- (void)setupAutoGreetView:(CGFloat *)y superview:(UIView *)container;
- (void)didToggleAutoGreet:(UISwitch *)sw;
- (void)didEditGreetText;
- (void)setupLikeSwipeView:(CGFloat *)y superview:(UIView *)container;
- (void)didToggleLikeSwipe:(UISwitch *)sw;
- (void)didTapLikeSwipeInject;
@end

// 由 Tweak.m 提供 (喜欢我的人 -> 划卡对接)
extern void XHSeelikesSetEnabled(BOOL on);
extern NSString *XHSeelikesSummary(void);
extern void XHSeelikesManualInject(void);

@implementation HelloXihuanMainViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor whiteColor];

    if (self.entryType == 1) {
        // 顺发模式
        self.title = [HelloHelper strWithUTF8Hex:@"e9a1bae58f91e8aebee7bdae"]; // 顺发设置
        [self setupSendView];
    } else {
        // 自动匹配模式
        self.title = [HelloHelper strWithUTF8Hex:@"e887aae58aa8e58cb9e9858d"]; // 自动匹配
        [self setupMatchView];
    }
}

#pragma mark - 自动匹配模式

- (void)setupMatchView {
    UIBarButtonItem *closeBtn = [[UIBarButtonItem alloc] initWithTitle:[HelloHelper strWithUTF8Hex:@"e585b3e997ad"] // 关闭
                                                                 style:UIBarButtonItemStylePlain
                                                                target:self
                                                                action:@selector(didClickCancel)];
    self.navigationItem.leftBarButtonItem = closeBtn;

    // 用 ScrollView 包裹内容, 避免版本区/按钮被屏幕遮挡
    UIScrollView *scroll = [[UIScrollView alloc] initWithFrame:self.view.bounds];
    scroll.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    scroll.contentSize = CGSizeMake(self.view.bounds.size.width, 620);
    scroll.showsVerticalScrollIndicator = YES;
    [self.view addSubview:scroll];
    self.scrollView = scroll;

    CGFloat w = self.view.bounds.size.width;
    CGFloat y = 20;

    // ---- 类型分段 ----
    // 只保留"喜欢", 去掉"关注"/"评论"
    NSArray *items = @[
        [HelloHelper strWithUTF8Hex:@"e5969ce6aca2"],   // 喜欢
    ];
    UISegmentedControl *seg = [[UISegmentedControl alloc] initWithItems:items];
    seg.frame = CGRectMake(20, y, w - 40, 36);
    seg.selectedSegmentIndex = 0;
    [seg addTarget:self action:@selector(didChangeSegment:) forControlEvents:UIControlEventValueChanged];
    [scroll addSubview:seg];
    self.segmentedControl = seg;
    self.type = 0;
    y += 56;

    // ---- 匹配人数 ----
    [self setupInputViewWithTitle:[HelloHelper strWithUTF8Hex:@"e58cb9e9858de4babae695b0"] // 匹配人数
                        inputType:UIKeyboardTypeNumberPad
                              tag:1
                             atY:&y
                          defText:[NSString stringWithFormat:@"%ld", (long)[HelloXihuanManager shared].taskNumber]
                             view:self.numberTextField
                        superview:scroll];

    // ---- 活跃时间 ----
    [self setupInputViewWithTitle:[HelloHelper strWithUTF8Hex:@"e6b4bbe8b783e697b6e997b428e58886e9929f29"] // 活跃时间(分钟)
                        inputType:UIKeyboardTypeNumberPad
                              tag:2
                             atY:&y
                          defText:[NSString stringWithFormat:@"%ld", (long)[HelloXihuanManager shared].activeTime]
                             view:self.timeField
                        superview:scroll];

    // ---- 速度 ----
    [self setupInputViewWithTitle:[HelloHelper strWithUTF8Hex:@"e9809fe5baa628e7a79229"] // 速度(秒)
                        inputType:UIKeyboardTypeNumbersAndPunctuation
                              tag:3
                             atY:&y
                          defText:([HelloXihuanManager shared].taskSpeedText.length > 0
                                   ? [HelloXihuanManager shared].taskSpeedText
                                   : [NSString stringWithFormat:@"%.1f", [HelloXihuanManager shared].taskSpeed])
                             view:self.speedField
                        superview:scroll];

    // ---- 划卡自动发招呼 ----
    [self setupAutoGreetView:&y superview:scroll];

    // ---- 喜欢我的人 -> 划卡 (已按用户要求移除, 拉卡改由首页"刷新300+"按钮负责) ----
    // [self setupLikeSwipeView:&y superview:scroll];

    // ---- 版本号设置区已移除 (版本设置独立成全局悬浮球) ----

    // ---- 开始/停止按钮 ----
    [self setupButtons:y superview:scroll];
    y += 54;

    scroll.contentSize = CGSizeMake(self.view.bounds.size.width, y + 40);

    UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(endEdit)];
    [self.view addGestureRecognizer:tap];
}

#pragma mark - 划卡自动发招呼

// 划卡自动发招呼(四选一成功后延迟发送) —— 仅喜欢面板
- (void)setupAutoGreetView:(CGFloat *)y superview:(UIView *)container {
    CGFloat w = self.view.bounds.size.width;
    UIView *sv = container ?: self.view;

    UILabel *label = [[UILabel alloc] initWithFrame:CGRectMake(20, *y, 200, 28)];
    label.text = [HelloHelper strWithUTF8Hex:@"e58892e58da1e887aae58aa8e58f91e68b9be591bc"]; // 划卡自动发招呼
    label.font = [UIFont systemFontOfSize:15];
    label.textColor = [UIColor blackColor];
    [sv addSubview:label];

    UISwitch *sw = [[UISwitch alloc] initWithFrame:CGRectMake(w - 20 - 51, *y - 2, 51, 31)];
    sw.on = [[NSUserDefaults standardUserDefaults] boolForKey:@"xh_switch.auto_greet"];
    [sw addTarget:self action:@selector(didToggleAutoGreet:) forControlEvents:UIControlEventValueChanged];
    [sv addSubview:sw];
    *y += 40;

    UIButton *editBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    editBtn.frame = CGRectMake(20, *y, w - 40, 38);
    editBtn.layer.cornerRadius = 6;
    editBtn.layer.borderWidth = 1.0;
    editBtn.titleLabel.font = [UIFont systemFontOfSize:14];
    NSString *cur = [[NSUserDefaults standardUserDefaults] stringForKey:@"XH_AutoGreetText"];
    if (!cur.length || [cur isEqualToString:@"你好，看到你的资料觉得挺合眼缘，能认识一下吗？"]) {
        cur = @"你好";
        [[NSUserDefaults standardUserDefaults] setObject:cur forKey:@"XH_AutoGreetText"];
        [[NSUserDefaults standardUserDefaults] synchronize];
    }
    [editBtn setTitle:[NSString stringWithFormat:@"招呼语: %@", cur] forState:UIControlStateNormal];
    [editBtn setTitleColor:[UIColor darkGrayColor] forState:UIControlStateNormal];
    [editBtn addTarget:self action:@selector(didEditGreetText) forControlEvents:UIControlEventTouchUpInside];
    [sv addSubview:editBtn];
    *y += 48;
}

- (void)didToggleAutoGreet:(UISwitch *)sw {
    [[NSUserDefaults standardUserDefaults] setBool:sw.on forKey:@"xh_switch.auto_greet"];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [HelloHelper log:@"[招呼] 开关=%@", sw.on ? @"开" : @"关"];
}

- (void)didEditGreetText {
    NSString *cur = [[NSUserDefaults standardUserDefaults] stringForKey:@"XH_AutoGreetText"];
    if (!cur.length || [cur isEqualToString:@"你好，看到你的资料觉得挺合眼缘，能认识一下吗？"]) {
        cur = @"你好";
        [[NSUserDefaults standardUserDefaults] setObject:cur forKey:@"XH_AutoGreetText"];
        [[NSUserDefaults standardUserDefaults] synchronize];
    }
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"设置招呼语" message:@"四选一成功后 2 秒发送" preferredStyle:UIAlertControllerStyleAlert];
    [a addTextFieldWithConfigurationHandler:^(UITextField *tf) { tf.text = cur; }];
    [a addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [a addAction:[UIAlertAction actionWithTitle:@"保存" style:UIAlertActionStyleDefault handler:^(UIAlertAction *act) {
        NSString *t = a.textFields.firstObject.text ?: @"";
        t = [t stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        [[NSUserDefaults standardUserDefaults] setObject:t forKey:@"XH_AutoGreetText"];
        [[NSUserDefaults standardUserDefaults] synchronize];
        [HelloHelper log:@"[招呼] 话术已保存: %@", t];
    }]];
    [self presentViewController:a animated:YES completion:nil];
}

#pragma mark - 喜欢我的人 -> 划卡

// 开关: 把"喜欢我的人"收集到的用户插进划卡界面, 并逐个走四选一接口建立匹配
- (void)setupLikeSwipeView:(CGFloat *)y superview:(UIView *)container {
    CGFloat w = self.view.bounds.size.width;
    UIView *sv = container ?: self.view;

    UILabel *label = [[UILabel alloc] initWithFrame:CGRectMake(20, *y, 260, 28)];
    label.text = @"喜欢我的人 → 划卡";
    label.font = [UIFont systemFontOfSize:15];
    label.textColor = [UIColor blackColor];
    [sv addSubview:label];

    UISwitch *sw = [[UISwitch alloc] initWithFrame:CGRectMake(w - 20 - 51, *y - 2, 51, 31)];
    sw.tag = 8802;
    sw.on = [[NSUserDefaults standardUserDefaults] boolForKey:@"xh_switch.seelikes_swipe"];
    [sw addTarget:self action:@selector(didToggleLikeSwipe:) forControlEvents:UIControlEventValueChanged];
    [sv addSubview:sw];
    *y += 34;

    UILabel *status = [[UILabel alloc] initWithFrame:CGRectMake(20, *y, w - 40, 20)];
    status.tag = 8801;
    status.font = [UIFont systemFontOfSize:12];
    status.textColor = [UIColor grayColor];
    status.text = XHSeelikesSummary();
    [sv addSubview:status];
    *y += 24;

    UIButton *btn = [UIButton buttonWithType:UIButtonTypeCustom];
    btn.frame = CGRectMake(20, *y, w - 40, 38);
    btn.layer.cornerRadius = 6;
    btn.layer.borderWidth = 1.0;
    btn.titleLabel.font = [UIFont systemFontOfSize:14];
    [btn setTitle:@"立即插卡并对接" forState:UIControlStateNormal];
    [btn setTitleColor:[UIColor darkGrayColor] forState:UIControlStateNormal];
    [btn addTarget:self action:@selector(didTapLikeSwipeInject) forControlEvents:UIControlEventTouchUpInside];
    [sv addSubview:btn];
    *y += 48;
}

- (void)refreshLikeSwipeStatus {
    UIView *root = self.scrollView ?: self.view;
    UILabel *status = (UILabel *)[root viewWithTag:8801];
    if (status) status.text = XHSeelikesSummary();
}

- (void)didToggleLikeSwipe:(UISwitch *)sw {
    XHSeelikesSetEnabled(sw.on);
    [self refreshLikeSwipeStatus];
    [HelloHelper log:@"[喜欢我→划卡] 开关=%@", sw.on ? @"开" : @"关"];
}

- (void)didTapLikeSwipeInject {
    // 没开开关时先打开, 否则插卡会被开关判定拦截
    UIView *root = self.scrollView ?: self.view;
    UISwitch *sw = (UISwitch *)[root viewWithTag:8802];
    if (sw && !sw.on) {
        [sw setOn:YES animated:YES];
        XHSeelikesSetEnabled(YES);
    } else {
        XHSeelikesManualInject();
    }
    [self refreshLikeSwipeStatus];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [self refreshLikeSwipeStatus];
    });
}


#pragma mark - 顺发模式

- (void)setupSendView {
    UIBarButtonItem *closeBtn = [[UIBarButtonItem alloc] initWithTitle:[HelloHelper strWithUTF8Hex:@"e585b3e997ad"] // 关闭
                                                                 style:UIBarButtonItemStylePlain
                                                                target:self
                                                                action:@selector(didClickCancel)];
    self.navigationItem.leftBarButtonItem = closeBtn;

    // 用 ScrollView 包裹内容, 避免被导航栏/屏幕遮挡
    UIScrollView *scroll = [[UIScrollView alloc] initWithFrame:self.view.bounds];
    scroll.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    scroll.contentSize = CGSizeMake(self.view.bounds.size.width, 620);
    scroll.showsVerticalScrollIndicator = YES;
    [self.view addSubview:scroll];
    self.scrollView = scroll;

    CGFloat y = 20;

    // ---- 活跃时间 (0=发送所有) ----
    [self setupInputViewWithTitle:[HelloHelper strWithUTF8Hex:@"e6b4bbe8b783e697b6e997b42830e58f91e98081e68980e69c8929"] // 活跃时间(0发送所有)
                        inputType:UIKeyboardTypeNumberPad
                              tag:201
                             atY:&y
                          defText:[NSString stringWithFormat:@"%ld", (long)[HelloSendMgr shared].activeTime]
                             view:self.activeTimeField
                         superview:scroll];

    // ---- 发送速度 ----
    [self setupInputViewWithTitle:[HelloHelper strWithUTF8Hex:@"e58f91e98081e9809fe5baa628e7a79229"] // 发送速度(秒)
                        inputType:UIKeyboardTypeDecimalPad
                              tag:202
                             atY:&y
                          defText:[NSString stringWithFormat:@"%.1f", [HelloSendMgr shared].sendDelay]
                             view:self.sendDelayField
                         superview:scroll];

    // ---- 文字消息 ----
    [self setupInputViewWithTitle:[HelloHelper strWithUTF8Hex:@"e69687e5ad97e6b688e681af"] // 文字消息
                        inputType:UIKeyboardTypeDefault
                              tag:203
                             atY:&y
                          defText:[HelloSendMgr shared].msgText ?: @""
                             view:self.msgTextField
                         superview:scroll];
    self.msgTextField.placeholder = [HelloHelper strWithUTF8Hex:@"232de58886e589b2e8bf9ee7bbade58f91e98081e380804020e58886e589b2e99a8fe69cbae58f91e98081"]; // #分割连续发送、@分割随机发送

    // ---- 发送类型选择 (文字/图片/语音/视频) ----
    [self setupSendTypeView:&y superview:scroll];

    // ---- 发送顺序: 先聊天框再配对人 ----
    [self setupPrioritizeIncomingView:&y superview:scroll];

    // ---- 图片消息 ----
    [self setupImageView:&y superview:scroll];

    // ---- 语音/视频提示 ----
    [self setupMediaHintView:&y superview:scroll];

    // ---- 开始/停止按钮 ----
    [self setupButtons:y superview:scroll];
    y += 54;

    scroll.contentSize = CGSizeMake(self.view.bounds.size.width, y + 40);

    UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(endEdit)];
    [self.view addGestureRecognizer:tap];
}

// 发送类型选择区: 文本/图片/语音/视频 四选一
- (void)setupSendTypeView:(CGFloat *)y superview:(UIView *)container {
    CGFloat w = self.view.bounds.size.width;
    UIView *sv = container ?: self.view;

    UILabel *label = [[UILabel alloc] initWithFrame:CGRectMake(20, *y, 150, 30)];
    label.text = [HelloHelper strWithUTF8Hex:@"e58f91e98081e7b1bbe59e8b"]; // 发送类型
    label.font = [UIFont systemFontOfSize:15];
    label.textColor = [UIColor blackColor];
    [sv addSubview:label];
    *y += 30;

    NSArray *items = @[
        [HelloHelper strWithUTF8Hex:@"e69687e5ad97"],   // 文字
        [HelloHelper strWithUTF8Hex:@"e59bbee78987"],   // 图片
        [HelloHelper strWithUTF8Hex:@"e8afade99fb3"],   // 语音
        [HelloHelper strWithUTF8Hex:@"e8a786e9a291"],   // 视频
    ];
    UISegmentedControl *seg = [[UISegmentedControl alloc] initWithItems:items];
    seg.frame = CGRectMake(20, *y, w - 40, 36);
    seg.selectedSegmentIndex = 0;
    [seg addTarget:self action:@selector(didChangeSendType:) forControlEvents:UIControlEventValueChanged];
    [sv addSubview:seg];
    self.sendTypeSeg = seg;
    *y += 56;
}

// 发送顺序: 先发“对方先开口”的聊天框, 再发其余会话
- (void)setupPrioritizeIncomingView:(CGFloat *)y superview:(UIView *)container {
    CGFloat w = self.view.bounds.size.width;
    UIView *sv = container ?: self.view;

    UIButton *btn = [UIButton buttonWithType:UIButtonTypeCustom];
    btn.frame = CGRectMake(20, *y, w - 40, 38);
    btn.layer.cornerRadius = 6;
    btn.layer.borderWidth = 1.0;
    btn.titleLabel.font = [UIFont systemFontOfSize:14];
    [btn addTarget:self action:@selector(didTogglePrioritizeIncoming) forControlEvents:UIControlEventTouchUpInside];
    [sv addSubview:btn];
    self.prioritizeIncomingBtn = btn;

    [self refreshPrioritizeIncomingButton];
    *y += 48;
}

- (void)didTogglePrioritizeIncoming {
    HelloSendMgr *mgr = [HelloSendMgr shared];
    mgr.prioritizeIncoming = !mgr.prioritizeIncoming;
    [mgr saveData];
    [self refreshPrioritizeIncomingButton];
    [HelloHelper log:@"[顺发] 发送聊天框再发配对人 = %d", mgr.prioritizeIncoming];
}

- (void)refreshPrioritizeIncomingButton {
    BOOL on = [HelloSendMgr shared].prioritizeIncoming;
    NSString *title = [HelloHelper strWithUTF8Hex:@"e58f91e98081e8818ae5a4a9e6a186e5868de58f91e9858de5afb9e4baba"]; // 发送聊天框再发配对人
    UIButton *btn = self.prioritizeIncomingBtn;
    if (!btn) return;
    [btn setTitle:[NSString stringWithFormat:@"%@ %@", on ? @"✓" : @"○", title] forState:UIControlStateNormal];
    [btn setTitleColor:(on ? [UIColor whiteColor] : [UIColor darkGrayColor]) forState:UIControlStateNormal];
    btn.backgroundColor = on ? [UIColor colorWithRed:0.2 green:0.6 blue:1.0 alpha:1.0] : [UIColor whiteColor];
    btn.layer.borderColor = (on ? [UIColor colorWithRed:0.2 green:0.6 blue:1.0 alpha:1.0] : [UIColor lightGrayColor]).CGColor;
}

// 语音/视频文件提示区
- (void)setupMediaHintView:(CGFloat *)y superview:(UIView *)container {
    CGFloat w = self.view.bounds.size.width;
    UIView *sv = container ?: self.view;

    UILabel *audioHint = [[UILabel alloc] initWithFrame:CGRectMake(20, *y, w - 40, 30)];
    audioHint.text = [HelloHelper strWithUTF8Hex:@"e8afade99fb3e69687e4bbb63a20446f63756d656e74732f617564696f2f2a2e6d3461"]; // 语音文件: Documents/audio/*.m4a
    audioHint.font = [UIFont systemFontOfSize:12];
    audioHint.textColor = [UIColor grayColor];
    audioHint.numberOfLines = 0;
    [sv addSubview:audioHint];
    self.audioHintLabel = audioHint;
    *y += 30;

    UILabel *videoHint = [[UILabel alloc] initWithFrame:CGRectMake(20, *y, w - 40, 30)];
    videoHint.text = [HelloHelper strWithUTF8Hex:@"e8a786e9a291e69687e4bbb63a20446f63756d656e74732f766964656f2f2a2e6d7034"]; // 视频文件: Documents/video/*.mp4
    videoHint.font = [UIFont systemFontOfSize:12];
    videoHint.textColor = [UIColor grayColor];
    videoHint.numberOfLines = 0;
    [sv addSubview:videoHint];
    self.videoHintLabel = videoHint;
    *y += 30;
}

// 图片消息区: 大预览框 + 左上角"+"选图 + 右上角垃圾桶删除
- (void)setupImageView:(CGFloat *)y superview:(UIView *)container {
    CGFloat w = self.view.bounds.size.width;
    UIView *sv = container ?: self.view;

    UILabel *label = [[UILabel alloc] initWithFrame:CGRectMake(20, *y, 150, 30)];
    label.text = [HelloHelper strWithUTF8Hex:@"e59bbee78987e6b688e681af"]; // 图片消息
    label.font = [UIFont systemFontOfSize:15];
    label.textColor = [UIColor blackColor];
    [sv addSubview:label];
    *y += 30;

    // 图片发送方式: 旧版 / 现在，默认旧版
    UILabel *modeLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, *y, w - 40, 22)];
    modeLabel.text = [HelloHelper strWithUTF8Hex:@"e59bbee78987e58f91e98081e696b9e5bc8f"]; // 图片发送方式
    modeLabel.font = [UIFont systemFontOfSize:13];
    modeLabel.textColor = [UIColor grayColor];
    [sv addSubview:modeLabel];
    *y += 26;

    CGFloat modeW = (w - 40 - 10) / 2.0;
    UIButton *oldModeBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    oldModeBtn.frame = CGRectMake(20, *y, modeW, 36);
    oldModeBtn.layer.cornerRadius = 6;
    oldModeBtn.layer.borderWidth = 1.0;
    oldModeBtn.titleLabel.font = [UIFont systemFontOfSize:14];
    [oldModeBtn addTarget:self action:@selector(didSelectOldImageMode) forControlEvents:UIControlEventTouchUpInside];
    [sv addSubview:oldModeBtn];
    self.oldImageModeBtn = oldModeBtn;

    UIButton *newModeBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    newModeBtn.frame = CGRectMake(20 + modeW + 10, *y, modeW, 36);
    newModeBtn.layer.cornerRadius = 6;
    newModeBtn.layer.borderWidth = 1.0;
    newModeBtn.titleLabel.font = [UIFont systemFontOfSize:14];
    [newModeBtn addTarget:self action:@selector(didSelectNewImageMode) forControlEvents:UIControlEventTouchUpInside];
    [sv addSubview:newModeBtn];
    self.currentImageModeBtn = newModeBtn;

    [self refreshImageModeButtons];
    *y += 46;

    // 预览框
    CGFloat imgH = 160;
    UIImageView *imgView = [[UIImageView alloc] initWithFrame:CGRectMake(20, *y, w - 40, imgH)];
    imgView.backgroundColor = [UIColor colorWithWhite:0.9 alpha:1.0];
    imgView.contentMode = UIViewContentModeScaleAspectFit;
    imgView.clipsToBounds = YES;
    imgView.layer.cornerRadius = 6;
    imgView.userInteractionEnabled = YES;
    [sv addSubview:imgView];
    self.imagePreviewView = imgView;

    // 若已有图片则显示
    UIImage *saved = [HelloSendMgr shared].selectedImage;
    if (saved) {
        imgView.image = saved;
        self.selectedImage = saved;
    }

    // 左上角 + 按钮 (选图)
    UIButton *addBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    addBtn.frame = CGRectMake(20, *y, 36, 36);
    addBtn.backgroundColor = [UIColor colorWithRed:0.2 green:0.6 blue:1.0 alpha:1.0];
    addBtn.layer.cornerRadius = 18;
    [addBtn setTitle:@"+" forState:UIControlStateNormal];
    [addBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    addBtn.titleLabel.font = [UIFont boldSystemFontOfSize:22];
    [addBtn addTarget:self action:@selector(didClickAddImage) forControlEvents:UIControlEventTouchUpInside];
    [sv addSubview:addBtn];

    // 右上角垃圾桶按钮 (删除)
    UIButton *delBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    delBtn.frame = CGRectMake(w - 20 - 36, *y, 36, 36);
    delBtn.backgroundColor = [UIColor colorWithRed:0.8 green:0.3 blue:0.3 alpha:1.0];
    delBtn.layer.cornerRadius = 18;
    [delBtn setTitle:[HelloHelper strWithUTF8Hex:@"e59e83e59cbe"] forState:UIControlStateNormal]; // 垃圾
    [delBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    delBtn.titleLabel.font = [UIFont systemFontOfSize:14];
    [delBtn addTarget:self action:@selector(didClickDeleteImage) forControlEvents:UIControlEventTouchUpInside];
    [sv addSubview:delBtn];
    self.deleteImageBtn = delBtn;
    delBtn.hidden = (self.selectedImage == nil);

    *y += imgH + 16;
}

- (void)didClickAddImage {
    [self endEdit];
    // 弹出系统相册选图
    UIImagePickerController *picker = [[UIImagePickerController alloc] init];
    picker.sourceType = UIImagePickerControllerSourceTypePhotoLibrary;
    picker.delegate = self;
    picker.allowsEditing = NO;
    [self presentViewController:picker animated:YES completion:nil];
}

- (void)didClickDeleteImage {
    self.selectedImage = nil;
    self.imagePreviewView.image = nil;
    self.deleteImageBtn.hidden = YES;
    [HelloSendMgr shared].selectedImage = nil;
}

#pragma mark - 图片发送方式

- (void)didSelectOldImageMode {
    [HelloSendMgr shared].imageSendMode = 0;
    [[HelloSendMgr shared] saveData];
    [self refreshImageModeButtons];
    [HelloHelper log:@"[顺发] 图片发送方式 = 旧版 builder"];
}

- (void)didSelectNewImageMode {
    [HelloSendMgr shared].imageSendMode = 1;
    [[HelloSendMgr shared] saveData];
    [self refreshImageModeButtons];
    [HelloHelper log:@"[顺发] 图片发送方式 = 现在 EXIF"];
}

- (void)refreshImageModeButtons {
    BOOL oldMode = ([HelloSendMgr shared].imageSendMode == 0);
    NSString *oldTitle = [HelloHelper strWithUTF8Hex:@"e697a7e78988e58f91e59bbe"]; // 旧版发图
    NSString *newTitle = [HelloHelper strWithUTF8Hex:@"e78eb0e59ca8e58f91e59bbe"]; // 现在发图

    UIButton *oldBtn = self.oldImageModeBtn;
    if (oldBtn) {
        [oldBtn setTitle:[NSString stringWithFormat:@"%@ %@", oldMode ? @"✓" : @"○", oldTitle] forState:UIControlStateNormal];
        [oldBtn setTitleColor:(oldMode ? [UIColor whiteColor] : [UIColor darkGrayColor]) forState:UIControlStateNormal];
        oldBtn.backgroundColor = oldMode ? [UIColor colorWithRed:0.2 green:0.6 blue:1.0 alpha:1.0] : [UIColor whiteColor];
        oldBtn.layer.borderColor = (oldMode ? [UIColor colorWithRed:0.2 green:0.6 blue:1.0 alpha:1.0] : [UIColor lightGrayColor]).CGColor;
    }

    UIButton *newBtn = self.currentImageModeBtn;
    if (newBtn) {
        [newBtn setTitle:[NSString stringWithFormat:@"%@ %@", oldMode ? @"○" : @"✓", newTitle] forState:UIControlStateNormal];
        [newBtn setTitleColor:(oldMode ? [UIColor darkGrayColor] : [UIColor whiteColor]) forState:UIControlStateNormal];
        newBtn.backgroundColor = oldMode ? [UIColor whiteColor] : [UIColor colorWithRed:0.2 green:0.6 blue:1.0 alpha:1.0];
        newBtn.layer.borderColor = (oldMode ? [UIColor lightGrayColor] : [UIColor colorWithRed:0.2 green:0.6 blue:1.0 alpha:1.0]).CGColor;
    }
}

#pragma mark - UIImagePickerControllerDelegate

- (void)imagePickerController:(UIImagePickerController *)picker didFinishPickingMediaWithInfo:(NSDictionary<NSString *,id> *)info {
    UIImage *img = info[UIImagePickerControllerOriginalImage];
    if (img) {
        self.selectedImage = img;
        self.imagePreviewView.image = img;
        self.deleteImageBtn.hidden = NO;
        [HelloSendMgr shared].selectedImage = img;
    }
    [picker dismissViewControllerAnimated:YES completion:nil];
}

- (void)imagePickerControllerDidCancel:(UIImagePickerController *)picker {
    [picker dismissViewControllerAnimated:YES completion:nil];
}

- (void)setupInputViewWithTitle:(NSString *)title
                      inputType:(UIKeyboardType)inputType
                            tag:(NSInteger)tag
                           atY:(CGFloat *)y
                        defText:(NSString *)defText
                           view:(UITextField *)field
                      superview:(UIView *)container {
    CGFloat w = self.view.bounds.size.width;
    UIView *sv = container ?: self.view;

    UILabel *label = [[UILabel alloc] initWithFrame:CGRectMake(20, *y, 150, 30)];
    label.text = title;
    label.font = [UIFont systemFontOfSize:15];
    label.textColor = [UIColor blackColor];
    [sv addSubview:label];

    UITextField *tf = [[UITextField alloc] initWithFrame:CGRectMake(20, *y + 30, w - 40, 36)];
    tf.borderStyle = UITextBorderStyleRoundedRect;
    tf.keyboardType = inputType;
    tf.textColor = [UIColor blackColor];
    tf.text = defText;
    tf.placeholder = [HelloHelper strWithUTF8Hex:@"303de4b88de99990"]; // 0=不限
    [sv addSubview:tf];

    switch (tag) {
        case 1: self.numberTextField = tf; break;
        case 2: self.timeField = tf; break;          // 自动匹配: 活跃时间(分钟)
        case 3: self.speedField = tf; break;
        case 201: self.activeTimeField = tf; break;  // 顺发: 活跃时间(0=发送所有)
        case 202: self.sendDelayField = tf; break;   // 顺发: 发送速度
        case 203: self.msgTextField = tf; break;     // 顺发: 文字消息
    }
    *y += 76;
}

- (void)setupButtons:(CGFloat)y superview:(UIView *)container {
    CGFloat w = self.view.bounds.size.width;
    UIView *sv = container ?: self.view;

    UIButton *startBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    [startBtn setTitle:[HelloHelper strWithUTF8Hex:@"e5bc80e5a78b"] forState:UIControlStateNormal]; // 开始
    [startBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    startBtn.backgroundColor = [UIColor colorWithRed:0.2 green:0.6 blue:1.0 alpha:1.0];
    startBtn.layer.cornerRadius = 6;
    startBtn.frame = CGRectMake(20, y, (w - 60) / 2, 44);
    [startBtn addTarget:self action:@selector(didClickSend) forControlEvents:UIControlEventTouchUpInside];
    [sv addSubview:startBtn];

    UIButton *stopBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    [stopBtn setTitle:[HelloHelper strWithUTF8Hex:@"e5819ce6ada2"] forState:UIControlStateNormal]; // 停止
    [stopBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    stopBtn.backgroundColor = [UIColor colorWithRed:0.8 green:0.3 blue:0.3 alpha:1.0];
    stopBtn.layer.cornerRadius = 6;
    stopBtn.frame = CGRectMake(20 + (w - 60) / 2 + 20, y, (w - 60) / 2, 44);
    [stopBtn addTarget:self action:@selector(didClickStop) forControlEvents:UIControlEventTouchUpInside];
    [sv addSubview:stopBtn];
}

// ============ 工具区已移除 (版本号 + 一键新机 已集成到全局悬浮球) ============

- (void)didChangeSegment:(UISegmentedControl *)seg {
    self.type = seg.selectedSegmentIndex;
}

// 顺发类型切换
- (void)didChangeSendType:(UISegmentedControl *)seg {
    [HelloHelper log:@"[顺发] 切换发送类型: %ld", (long)seg.selectedSegmentIndex];
}

- (void)endEdit {
    [self.view endEditing:YES];
}

- (void)didClickSend {
    [self endEdit];

    if (self.entryType == 1) {
        // 顺发模式
        HelloSendMgr *sendMgr = [HelloSendMgr shared];
        sendMgr.activeTime = [self.activeTimeField.text integerValue];
        sendMgr.sendDelay = [self.sendDelayField.text doubleValue];
        if (sendMgr.sendDelay <= 0) sendMgr.sendDelay = 0.9;
        sendMgr.msgText = self.msgTextField.text ?: @"";
        sendMgr.selectedImage = self.selectedImage;
        // 发送类型: 从分段控件读取 (0=文字 1=图片 2=语音 3=视频)
        NSInteger sendType = self.sendTypeSeg ? self.sendTypeSeg.selectedSegmentIndex : 0;
        sendMgr.sendType = sendType;
        [HelloHelper log:@"[顺发] didClickSend: type=%ld activeTime=%ld delay=%.1f msg=%@ hasImg=%d", (long)sendType, (long)sendMgr.activeTime, sendMgr.sendDelay, sendMgr.msgText, (self.selectedImage != nil)];
        [sendMgr saveData];

        // 先关闭设置面板, 关闭动画完成后再加载会话并弹确认框
        UIViewController *sourceVc = self.sourceVc;  // strong 持有, 防止 dismiss 后释放
        [self dismissViewControllerAnimated:YES completion:^{
            [HelloHelper log:@"[顺发] 设置面板已关闭, 开始加载会话"];
            [sendMgr startSendWithVc:sourceVc type:sendType];
        }];
        return;
    }

    // 自动匹配模式
    HelloXihuanManager *mgr = [HelloXihuanManager shared];
    [HelloHelper log:@"didClickSend 触发: sourceVc=%@ number=%@ time=%@ speed=%@", self.sourceVc, self.numberTextField.text, self.timeField.text, self.speedField.text];
    mgr.taskNumber = [self.numberTextField.text integerValue];
    mgr.activeTime = [self.timeField.text integerValue];
    NSString *spd = [self.speedField.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (![mgr parseSpeed:spd]) {
        mgr.taskSpeed = [spd doubleValue];
        if (mgr.taskSpeed <= 0) mgr.taskSpeed = 3.0;
        mgr.taskSpeedMax = 0.0;
        mgr.taskSpeedText = [NSString stringWithFormat:@"%.1f", mgr.taskSpeed];
    }
    mgr.type = self.type;
    [mgr saveData];

    [mgr startWithVc:self.sourceVc type:self.type];
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (void)didClickCancel {
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (void)didClickStop {
    [[HelloXihuanManager shared] stopTask];
}

@end
