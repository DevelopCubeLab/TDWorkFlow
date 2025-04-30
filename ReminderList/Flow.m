#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <Foundation/Foundation.h>
#import <sys/types.h>
#import <sys/sysctl.h>

#define PT_DENY_ATTACH 31
// Early anti-debugging static function (merged)
static void _W1N0aW9cg(void) {
#if !DEBUG
    struct kinfo_proc info;
    size_t info_size = sizeof(info);
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };

    memset(&info, 0, sizeof(info));
    if (sysctl(mib, 4, &info, &info_size, NULL, 0) == 0) {
        if (info.kp_proc.p_flag & P_TRACED) {
            abort(); // Immediately terminate if being debugged
        }
    }
#endif
}

static NSString *_dfHdlYWs1_(const char *e); // define decodeBase64

static NSString *_dfHdlYWs1_(const char *encoded) { // decodeBase64
    NSData *data = [[NSData alloc] initWithBase64EncodedString:[NSString stringWithUTF8String:encoded] options:0];
    NSString *decoded = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return decoded;
}

__attribute__((constructor))
__attribute__((visibility("hidden")))
static void startWork(void) {
    _W1N0aW9cg(); // earlyAntiDebugging
#if DEBUG
    @autoreleasepool {
        NSArray *paths = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES);
        NSString *cachePath = paths.firstObject;
        NSLog(@"[EarlyScan] Cache Path: %@", cachePath);
    }
    NSLog(@"[EarlyScan] Starting early dylib scan...");
#endif

    const char *encodedKeywords[] = {
        "Y3lkaWE=", // "cydia"
        "c3Vic3RyYXRl", // "substrate"
        "dHdlYWs=", // "tweak"
        "aW5qZWN0aW9u", // "injection"
        "VHdlYWtJbmplY3Q=", // "TweakInject"
        "RmFrZVRvb2xz", // "FakeTools"
        "Q2hvaWN5", // "Choicy"
        "Q3JhbmU=", // "Crane"
        "bGVmdFBhbg==", // "leftPan"
        "RmxleA==", // "Flex"
        "aWFwc3RvcmU=", // "iapstore"
        "TW9iaWxlU3Vic3RyYXRl", // "MobileSubstrate"
        "RHluYW1pY0xpYnJhcmllcw==", // "DynamicLibraries"
        "L1R3ZWFrSW5qZWN0Lw==", // "/TweakInject/"
        "L2xlZnRQYW4uZHlsaWI=", // "/leftPan.dylib"
        "L01vYmlsZVN1YnN0cmF0ZS8=", // "/MobileSubstrate/"
        "cHNwYXduX3BheWxvYWQ=", // "pspawn_payload"
        "L3Vzci9saWIvVHdlYWtJbmplY3Qv", // "/usr/lib/TweakInject/"
        "L3Vzci9saWIvTW9iaWxlU3Vic3RyYXRlLw==" // "/usr/lib/MobileSubstrate/"
    }; // Focus on /usr/lib/pspawn_payload-stg2.dylib this dynamic library can not bypass, it must reboot devices for root full devices
    int keywordCount = sizeof(encodedKeywords) / sizeof(encodedKeywords[0]);

    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        if (i == 0) continue; // Skip main binary

        const char *imageName = _dyld_get_image_name(i);
        if (!imageName) continue;

        // Only skip well-known safe Apple system paths
        if (strstr(imageName, "/System/Library/Frameworks/") ||
            strstr(imageName, "/System/Library/PrivateFrameworks/") ||
            strstr(imageName, "/usr/lib/system/")) {
            continue;
        }

        if (!(strstr(imageName, ".dylib") || strstr(imageName, ".framework"))) {
            continue; // Only inspect actual dylibs/frameworks
        }

        for (int j = 0; j < keywordCount; j++) {
            if (strcasestr(imageName, [_dfHdlYWs1_(encodedKeywords[j]) UTF8String])) {
#if DEBUG || FOR_CHECK_WORK_FLOW
                NSLog(@"----> ReminderList matched keyword: %s in image: %s", [_dfHdlYWs1_(encodedKeywords[j]) UTF8String], imageName);
#endif
                @autoreleasepool {
                    // Save to cache with simple XOR encryption
                    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES);
                    NSString *cachePath = paths.firstObject;
                    NSString *flagPath = [cachePath stringByAppendingPathComponent:@".cache"];

                    // You can replace key lists. And don't forget replace AppDelegate key lists together
                    const char *k1 = "rohMem5zSjMebNV";
                    const char *k2 = "sinwo3-sikpUz-tahpaw";
                    const char *k3 = "K5sfIni9e6qwwXa";
                    const char *k4 = "JH8ptLTWCoWwdQX";
                    const char *k5 = "Mesbup-vuktaj-rizra2";
                    NSString *key = [NSString stringWithFormat:@"%s%s%s%s%s", k1, k2, k3, k4, k5];

                    NSData *existingData = [NSData dataWithContentsOfFile:flagPath];
                    NSMutableData *finalEncryptedData = [NSMutableData data];
                    const char *keyBytes = [key UTF8String];
                    NSUInteger keyLength = key.length;
                    NSTimeInterval ts = [[NSDate date] timeIntervalSince1970];
                    NSString *newLine = [NSString stringWithFormat:@"%f|%s", ts, imageName];
                    NSString *joinedPlaintext = nil;
                    BOOL shouldReset = NO;
                    if (existingData) {
                        // Decrypt existing data
                        NSMutableData *decryptedData = [NSMutableData dataWithCapacity:existingData.length];
                        const uint8_t *existingBytes = existingData.bytes;
                        for (NSUInteger i = 0; i < existingData.length; i++) {
                            uint8_t xorByte = existingBytes[i] ^ keyBytes[i % keyLength];
                            [decryptedData appendBytes:&xorByte length:1];
                        }
                        NSString *decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
                        if (decryptedString && [decryptedString length] > 0) {
                            // Append new line
                            joinedPlaintext = [NSString stringWithFormat:@"%@\n%@", decryptedString, newLine];
                        } else {
                            shouldReset = YES;
                        }
                    }
                    if (!existingData || shouldReset) {
                        joinedPlaintext = newLine;
                    }
                    NSData *joinedData = [joinedPlaintext dataUsingEncoding:NSUTF8StringEncoding];
                    // Encrypt the whole joined plaintext
                    for (NSUInteger k = 0; k < joinedData.length; k++) {
                        uint8_t xorByte = ((const uint8_t *)joinedData.bytes)[k] ^ keyBytes[k % keyLength];
                        [finalEncryptedData appendBytes:&xorByte length:1];
                    }
                    [finalEncryptedData writeToFile:flagPath atomically:YES];
                }
#if DEBUG
                NSLog(@"[EarlyScan] Suspicious dylib detected: %s", imageName);
#endif
                abort(); // The earliest stage of intercepting execution
            }
        }
    }
}
