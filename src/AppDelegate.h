#import <UIKit/UIKit.h>

void run_jailbreak(void);
void log_printf(NSString *format, ...) NS_FORMAT_FUNCTION(1,2);

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@property (nonatomic, strong) UITextView *logView;      // important logs only
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, strong) UILabel *versionLabel;
@property (nonatomic, strong) UIButton *startButton;
- (void)startExploit;
@end
