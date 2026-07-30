#import "AppDelegate.h"
#import <stdarg.h>

static AppDelegate *sharedDelegate = nil;

void log_printf(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *msg = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    NSLog(@"%@", msg);
    AppDelegate *delegate = sharedDelegate;
    if (delegate) {
        dispatch_async(dispatch_get_main_queue(), ^{
            UITextView *tv = delegate.logView;
            tv.text = [tv.text stringByAppendingString:msg];
            [tv scrollRangeToVisible:NSMakeRange(tv.text.length - 1, 1)];
        });
    }
}

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    sharedDelegate = self;

    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.backgroundColor = [UIColor blackColor];

    UITextView *tv = [[UITextView alloc] initWithFrame:self.window.bounds];
    tv.backgroundColor = [UIColor blackColor];
    tv.textColor = [UIColor greenColor];
    tv.font = [UIFont fontWithName:@"Menlo" size:11];
    tv.editable = NO;
    tv.selectable = NO;
    tv.text = @"";
    [self.window addSubview:tv];
    self.logView = tv;

    [self.window makeKeyAndVisible];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        run_jailbreak();
    });

    return YES;
}

@end