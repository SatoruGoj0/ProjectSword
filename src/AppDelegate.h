#import <UIKit/UIKit.h>

void run_jailbreak(void);
void log_printf(NSString *format, ...) NS_FORMAT_FUNCTION(1,2);

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@property (strong, nonatomic) UITextView *logView;
- (void)startExploit;
@end