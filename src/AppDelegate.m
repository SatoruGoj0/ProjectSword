#import "AppDelegate.h"
#import <stdarg.h>
#import <stdio.h>
#import <time.h>
#import <fcntl.h>
#import <unistd.h>

static AppDelegate *sharedDelegate = nil;

static dispatch_once_t gLogOnce;
static dispatch_queue_t gLogQueue;
static FILE *gLogFile;

void log_printf(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *msg = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    NSLog(@"%@", msg);

    dispatch_once(&gLogOnce, ^{
        gLogQueue = dispatch_queue_create("ps.log", NULL);
        NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        NSString *path = [dir stringByAppendingPathComponent:@"ps.log"];
        NSLog(@"ps.log -> %@", path);
        dispatch_sync(gLogQueue, ^{
            gLogFile = fopen(path.fileSystemRepresentation, "a");
            if (gLogFile) setvbuf(gLogFile, NULL, _IONBF, 0);
        });
    });

    dispatch_sync(gLogQueue, ^{
        if (gLogFile) {
            fprintf(gLogFile, "[%lld] %s\n", (long long)time(NULL), msg.UTF8String ?: "");
            fflush(gLogFile);
        }
    });

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

    UIViewController *vc = [[UIViewController alloc] init];
    vc.view.backgroundColor = [UIColor blackColor];
    self.window.rootViewController = vc;

    CGFloat w = self.window.bounds.size.width;
    CGFloat h = self.window.bounds.size.height;

    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(0, 40, w, 40)];
    title.text = @"ProjectSword";
    title.textColor = [UIColor greenColor];
    title.backgroundColor = [UIColor clearColor];
    title.font = [UIFont boldSystemFontOfSize:20];
    title.textAlignment = NSTextAlignmentCenter;
    [vc.view addSubview:title];

    UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
    btn.frame = CGRectMake(w/2 - 80, 90, 160, 44);
    [btn setTitle:@"START EXPLOIT" forState:UIControlStateNormal];
    [btn setTitleColor:[UIColor greenColor] forState:UIControlStateNormal];
    btn.titleLabel.font = [UIFont boldSystemFontOfSize:16];
    btn.layer.borderColor = [UIColor greenColor].CGColor;
    btn.layer.borderWidth = 1;
    btn.layer.cornerRadius = 8;
    [btn addTarget:self action:@selector(startExploit) forControlEvents:UIControlEventTouchUpInside];

    UIButton *copyBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    copyBtn.frame = CGRectMake(w - 140, 90, 60, 44);
    [copyBtn setTitle:@"COPY" forState:UIControlStateNormal];
    [copyBtn setTitleColor:[UIColor greenColor] forState:UIControlStateNormal];
    copyBtn.titleLabel.font = [UIFont systemFontOfSize:13];
    [copyBtn addTarget:self action:@selector(copyLog) forControlEvents:UIControlEventTouchUpInside];

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

    [vc.view addSubview:tv];
    [vc.view addSubview:btn];
    [vc.view addSubview:copyBtn];
    [vc.view addSubview:clearBtn];
    [self.window makeKeyAndVisible];

    self.logView = tv;

    log_printf(@"ProjectSword loaded. Tap START EXPLOIT to begin.\n");

    return YES;
}

- (void)clearLog {
    self.logView.text = @"";
}

- (void)copyLog {
    UIPasteboard *pb = [UIPasteboard generalPasteboard];
    pb.string = self.logView.text;
    log_printf(@"[COPY] %lu chars copied to clipboard\n", (unsigned long)pb.string.length);
}

- (void)startExploit {
    log_printf(@"\n--- Starting exploit ---\n");
    NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *path = [dir stringByAppendingPathComponent:@"ps.log"];
    int fd = open(path.fileSystemRepresentation, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd >= 0) {
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        close(fd);
        setvbuf(stdout, NULL, _IONBF, 0);
        setvbuf(stderr, NULL, _IONBF, 0);
        log_printf(@"[capture] stdout/stderr mirrored to ps.log (unbuffered)\n");
    }
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        run_jailbreak();
    });
}

@end