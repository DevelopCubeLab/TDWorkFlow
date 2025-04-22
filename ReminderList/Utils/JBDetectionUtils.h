#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Public function declaration for Swift bridging
BOOL isJailbroken(void);
BOOL isJailbreak(void);

@interface JBDetector : NSObject
+ (BOOL)isJailbreakFlagCheck;
@end

NS_ASSUME_NONNULL_END
