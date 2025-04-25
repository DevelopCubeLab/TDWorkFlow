#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <Foundation/Foundation.h>

__attribute__((constructor))
__attribute__((visibility("hidden")))
static void startWork(void) {
#if DEBUG
    @autoreleasepool {
        NSArray *paths = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES);
        NSString *cachePath = paths.firstObject;
        NSLog(@"[EarlyScan] Cache Path: %@", cachePath);
    }
    NSLog(@"[EarlyScan] Starting early dylib scan...");
#endif

    const char *keywords[] = {
        "cydia", "substrate", "tweak", "injection", "TweakInject", "FakeTools",
        "Choicy", "Crane", "leftPan", "Flex", "iapstore"
    };
    int keywordCount = sizeof(keywords) / sizeof(keywords[0]);

    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        if (i == 0) continue; // Skip main binary

        const char *imageName = _dyld_get_image_name(i);
        if (!imageName) continue;

        // Ignore the system path
        if (strstr(imageName, "/System/") || strstr(imageName, "/usr/lib/")) {
            continue;
        }

        if (!(strstr(imageName, ".dylib") || strstr(imageName, ".framework"))) {
            continue; // Only inspect actual dylibs/frameworks
        }

        for (int j = 0; j < keywordCount; j++) {
            if (strcasestr(imageName, keywords[j])) {
                @autoreleasepool {
                    // Save to cache with simple XOR encryption
                    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES);
                    NSString *cachePath = paths.firstObject;
                    NSString *flagPath = [cachePath stringByAppendingPathComponent:@".cache"];
                    NSString *raw = [NSString stringWithFormat:@"__attribute__((constructor))%s", imageName];

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
                    NSString *newLine = [NSString stringWithFormat:@"__attribute__((constructor))%s", imageName];
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
