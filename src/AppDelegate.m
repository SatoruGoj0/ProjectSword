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

    CGFloat w = self.window.bounds.size.width;
    CGFloat h = self.window.bounds.size.height;

    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(0, 40, w, 40)];
    title.text = @"ProjectSword";
    title.textColor = [UIColor greenColor];
    title.backgroundColor = [UIColor clearColor];
    title.font = [UIFont boldSystemFontOfSize:20];
    title.textAlignment = NSTextAlignmentCenter;
    [self.window addSubview:title];

    UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
    btn.frame = CGRectMake(w/2 - 80, 90, 160, 44);
    [btn setTitle:@"START EXPLOIT" forState:UIControlStateNormal];
    [btn setTitleColor:[UIColor greenColor] forState:UIControlStateNormal];
    btn.titleLabel.font = [UIFont boldSystemFontOfSize:16];
    btn.layer.borderColor = [UIColor greenColor].CGColor;
    btn.layer.borderWidth = 1;
    btn.layer.cornerRadius = 8;
    [btn addTarget:self action:@selector(startExploit) forControlEvents:UIControlEventTouchUpInside];

    UIButton *clearBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    clearBtn.frame = CGRectMake(w - 70, 90, 60, 44);
    [clearBtn setTitle:@"CLEAR" forState:UIControlStateNormal];
    [clearBtn setTitleColor:[UIColor grayColor] forState:UIControlStateNormal];
    clearBtn.titleLabel.font = [UIFont systemFontOfSize:13];
    [clearBtn addTarget:self action:@selector(clearLog) forControlEvents:UIControlEventTouchUpInside];

    UITextView *tv = [[UITextView alloc] initWithFrame:CGRectMake(0, 140, w, h - 140)];
    tv.backgroundColor = [UIColor blackColor];
    tv.textColor = [UIColor greenColor];
    tv.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    tv.editable = NO;
    tv.selectable = NO;
    tv.text = @"";

    [self.window addSubview:tv];
    [self.window addSubview:btn];
    [self.window addSubview:clearBtn];
    [self.window makeKeyAndVisible];

    self.logView = tv;

    log_printf(@"ProjectSword loaded. Tap START EXPLOIT to begin.\n");

    return YES;
}

- (void)clearLog {
    self.logView.text = @"";
}

- (void)startExploit {
    log_printf(@"\n--- Starting exploit ---\n");
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        run_jailbreak();
    });
}

@end