#import "AppDelegate.h"
#import <stdarg.h>
#import <stdio.h>
#import <time.h>
#import <fcntl.h>
#import <unistd.h>

// ---------------------------------------------------------------------------
// Design tokens (light, pastel green)
// ---------------------------------------------------------------------------
static inline UIColor *PSCol(uint32_t rgb) {
    return [UIColor colorWithRed:((rgb >> 16) & 0xFF) / 255.0
                           green:((rgb >> 8) & 0xFF) / 255.0
                            blue:(rgb & 0xFF) / 255.0
                           alpha:1.0];
}
#define PS_BG       PSCol(0xFEFFFE)   // near-white page background
#define PS_CARD     PSCol(0xE5FCF5)   // mint-tinted card background
#define PS_ACCENT   PSCol(0xB3DEC1)   // sage accent (buttons, highlights)
#define PS_INK      PSCol(0x210124)   // deep plum near-black (primary text)
#define PS_INK_DIM  [PSCol(0x210124) colorWithAlphaComponent:0.55]
#define PS_LINE     [PSCol(0x210124) colorWithAlphaComponent:0.10]

// ---------------------------------------------------------------------------
// Global logging
// ---------------------------------------------------------------------------
static AppDelegate *sharedDelegate = nil;

static dispatch_once_t gLogOnce;
static dispatch_queue_t gLogQueue;
static FILE *gLogFile;

static NSString *ps_doc_path(NSString *name) {
    NSString *dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    return [dir stringByAppendingPathComponent:name];
}

// "Important" = user-facing: stage banners, results, errors, final state.
// Everything else is verbose debug -> ps.log only.
static BOOL ps_is_important(NSString *s) {
    static NSArray<NSString *> *needles = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        needles = @[
            @"=== ", @"[Phase ", @"[+] ", @"[-] ", @"[!] ",
            @"uid:", @"Kernel base", @"Kernel slide", @"KASLR",
            @"Starting shell", @"Jailbreak Ready", @"FAILURE",
        ];
    });
    for (NSString *n in needles) if ([s containsString:n]) return YES;
    return NO;
}

void log_printf(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *msg = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    NSLog(@"%@", msg);

    dispatch_once(&gLogOnce, ^{
        gLogQueue = dispatch_queue_create("ps.log", NULL);
        NSString *path = ps_doc_path(@"ps.log");
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

    if (ps_is_important(msg)) {
        AppDelegate *delegate = sharedDelegate;
        if (delegate) {
            dispatch_async(dispatch_get_main_queue(), ^{
                UITextView *tv = delegate.logView;
                if (!tv) return;
                tv.text = [tv.text stringByAppendingString:msg];
                if (tv.text.length) [tv scrollRangeToVisible:NSMakeRange(tv.text.length - 1, 1)];
            });
        }
    }
}

// ---------------------------------------------------------------------------
// UI
// ---------------------------------------------------------------------------
@interface PSButton : UIButton
@end

@implementation PSButton
- (instancetype)initWithTitle:(NSString *)title {
    self = [UIButton buttonWithType:UIButtonTypeSystem];
    if (self) {
        [self setTitle:title forState:UIControlStateNormal];
        [self setTitleColor:PS_INK forState:UIControlStateNormal];
        self.titleLabel.font = [UIFont monospacedSystemFontOfSize:15 weight:UIFontWeightSemibold];
        self.backgroundColor = PS_ACCENT;
        self.layer.cornerRadius = 14;
        self.layer.borderWidth = 1;
        self.layer.borderColor = PS_LINE.CGColor;
        self.clipsToBounds = YES;
    }
    return self;
}
- (void)setHighlighted:(BOOL)h {
    [super setHighlighted:h];
    [UIView animateWithDuration:0.12 animations:^{
        self.alpha = h ? 0.65 : 1.0;
        self.transform = h ? CGAffineTransformMakeScale(0.97, 0.97) : CGAffineTransformIdentity;
    }];
}
@end

@implementation AppDelegate

- (NSString *)appVersionString {
    NSString *p = [[NSBundle mainBundle] pathForResource:@"version" ofType:@"txt"];
    NSString *v = nil;
    if (p) v = [[NSString stringWithContentsOfFile:p encoding:NSUTF8StringEncoding error:nil] stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (!v.length) v = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"dev";
    return v;
}

- (UIView *)makeCardIn:(UIView *)parent {
    UIView *c = [[UIView alloc] init];
    c.backgroundColor = PS_CARD;
    c.layer.cornerRadius = 20;
    c.layer.borderWidth = 1;
    c.layer.borderColor = PS_LINE.CGColor;
    c.layer.shadowColor = PS_INK.CGColor;
    c.layer.shadowOpacity = 0.06;
    c.layer.shadowRadius = 12;
    c.layer.shadowOffset = CGSizeMake(0, 4);
    [parent addSubview:c];
    return c;
}

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    sharedDelegate = self;

    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.backgroundColor = PS_BG;

    UIViewController *vc = [[UIViewController alloc] init];
    vc.view.backgroundColor = PS_BG;
    self.window.rootViewController = vc;

    CGFloat w = self.window.bounds.size.width;
    CGFloat h = self.window.bounds.size.height;
    CGFloat pad = 16;

    // Header
    UIView *header = [self makeCardIn:vc.view];
    header.frame = CGRectMake(pad, 52, w - pad * 2, 92);

    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(20, 14, w - 40, 28)];
    title.text = @"ProjectSword";
    title.textColor = PS_INK;
    title.font = [UIFont monospacedSystemFontOfSize:24 weight:UIFontWeightBold];
    [header addSubview:title];

    UILabel *sub = [[UILabel alloc] initWithFrame:CGRectMake(20, 44, w - 140, 20)];
    sub.text = @"DarkSword · iOS 18.2.1 · A14";
    sub.textColor = PS_INK_DIM;
    sub.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
    [header addSubview:sub];

    UILabel *ver = [[UILabel alloc] initWithFrame:CGRectMake(w - 110, 66, 74, 18)];
    ver.text = [@"v" stringByAppendingString:self.appVersionString];
    ver.textColor = PS_INK_DIM;
    ver.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightMedium];
    ver.textAlignment = NSTextAlignmentRight;
    [header addSubview:ver];
    self.versionLabel = ver;

    // Status
    UIView *statusCard = [self makeCardIn:vc.view];
    statusCard.frame = CGRectMake(pad, 156, w - pad * 2, 46);
    UILabel *status = [[UILabel alloc] initWithFrame:statusCard.bounds];
    status.text = @"Ready — tap JAILBREAK";
    status.textColor = PS_INK;
    status.textAlignment = NSTextAlignmentCenter;
    status.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightSemibold];
    [statusCard addSubview:status];
    self.statusLabel = status;

    // Primary action
    PSButton *btn = [[PSButton alloc] initWithTitle:@"JAILBREAK"];
    btn.frame = CGRectMake(pad, 214, w - pad * 2, 52);
    [btn addTarget:self action:@selector(startExploit) forControlEvents:UIControlEventTouchUpInside];
    [vc.view addSubview:btn];
    self.startButton = btn;

    // Log card (important messages only)
    UIView *logCard = [self makeCardIn:vc.view];
    CGFloat logY = 214 + 52 + 16;
    logCard.frame = CGRectMake(pad, logY, w - pad * 2, h - logY - pad - 44);

    UITextView *tv = [[UITextView alloc] initWithFrame:CGRectInset(logCard.bounds, 8, 8)];
    tv.backgroundColor = UIColor.clearColor;
    tv.textColor = PS_INK;
    tv.font = [UIFont monospacedSystemFontOfSize:11.5 weight:UIFontWeightRegular];
    tv.editable = NO;
    tv.selectable = YES;
    tv.text = @"";
    [logCard addSubview:tv];
    self.logView = tv;

    UILabel *foot = [[UILabel alloc] initWithFrame:CGRectMake(pad, h - 36, w - pad * 2, 18)];
    foot.text = @"Full log: Documents/ps.log";
    foot.textColor = PS_INK_DIM;
    foot.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    foot.textAlignment = NSTextAlignmentCenter;
    [vc.view addSubview:foot];

    [self.window makeKeyAndVisible];

    log_printf(@"ProjectSword v%@ loaded. Tap JAILBREAK to begin.\n", self.appVersionString);
    return YES;
}

- (void)startExploit {
    self.startButton.enabled = NO;
    dispatch_async(dispatch_get_main_queue(), ^{ self.statusLabel.text = @"Running exploit…"; });
    log_printf(@"\n=== Starting exploit ===\n");
    NSString *path = ps_doc_path(@"ps.log");
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
