#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>

static BOOL hasShownAlert = NO;

%hook UIViewController

- (void)viewDidLoad {
    %orig;

    if (!hasShownAlert) {
        hasShownAlert = YES;

        NSString *bundleID = NSBundle.mainBundle.bundleIdentifier;
        NSString *appName = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleDisplayName"]
                            ?: [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleName"];

        NSLog(@"[SimpleInject] Injected into %@ (%@)", appName, bundleID);

        NSString *message = [NSString stringWithFormat:@"Injected into %@\nBundle ID: %@", appName, bundleID];

        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"[SimpleInject]"
                                                                       message:message
                                                                preferredStyle:UIAlertControllerStyleAlert];

        UIAlertAction *ok = [UIAlertAction actionWithTitle:@"OK"
                                                     style:UIAlertActionStyleDefault
                                                   handler:nil];
        [alert addAction:ok];

        dispatch_async(dispatch_get_main_queue(), ^{
            [self presentViewController:alert animated:YES completion:nil];
        });
    }
}

%end
