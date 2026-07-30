#import "AppDelegate.h"

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.backgroundColor = [UIColor blackColor];
    [self.window makeKeyAndVisible];

    UILabel *label = [[UILabel alloc] initWithFrame:self.window.bounds];
    label.text = @"ProjectSword";
    label.textColor = [UIColor greenColor];
    label.backgroundColor = [UIColor clearColor];
    label.font = [UIFont boldSystemFontOfSize:24];
    label.textAlignment = NSTextAlignmentCenter;
    [self.window addSubview:label];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        run_jailbreak();
    });

    return YES;
}

@end
