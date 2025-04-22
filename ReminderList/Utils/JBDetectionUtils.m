#import <Foundation/Foundation.h>
#import "JBDetectionUtils.h"

// This Honeypot function acts as a decoy jailbreak check — it's intentionally visible and simple.
// Real detection logic should not calling this function directly.
BOOL isJailbroken(void) {
    
    NSArray *suspiciousPaths = @[@"/Applications/Cydia.app",
                                 @"/Library/MobileSubstrate/MobileSubstrate.dylib",
                                 @"/bin/bash",
                                 @"/usr/sbin/sshd",
                                 @"/etc/apt"];
    
    for (NSString *path in suspiciousPaths) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
            return YES;
        }
    }

    return NO;
}

// 🎣
BOOL isJailbreak(void) {
    return [JBDetector isJailbreakFlagCheck];
}

@implementation JBDetector

+ (BOOL)isJailbreakFlagCheck {
    // This is the internal decoy logic; return YES to bait bypassers.
    return YES;
}

@end
