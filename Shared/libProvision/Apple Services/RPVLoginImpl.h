//
//  RPVLoginImpl.hpp
//  iOS
//
//  Created by Matt Clarke on 24/11/2019.
//  Copyright © 2019 Matt Clarke. All rights reserved.
//

#import <Foundation/Foundation.h>

// Error definitions
#define RPVInternalLoginError 5000
#define RPVInternalLogin2FARequiredTrustedDeviceError 4010
#define RPVInternalLogin2FARequiredSecondaryAuthError 4011
#define RPVInternalLoginIncorrect2FACodeError 4012
#define RPVInternalLoginInvalid2FAFormatError 4013
#define RPVInternalLoginPostTwoFactorError 4014

// Block definitions
typedef void (^RPVLoginResultBlock)(NSError *error, NSString *userIdentity, NSString *gsToken, NSString *idmsToken);
typedef void (^RPVTwoFactorResultBlock)(NSError *error);

@interface RPVLoginImpl : NSObject

@property (nonatomic, strong) NSString *clientInfoOverride;

- (void)loginWithUsername:(NSString*)username password:(NSString*)password completion:(RPVLoginResultBlock)completionHandler;

- (void)requestTwoFactorCodeWithUserIdentity:(NSString*)userIdentity idmsToken:(NSString*)token mode:(int)mode andCompletion:(void (^)(NSError *error))completionHandler;

/// Sends the code to a trusted phone number, choosing sms or voice.
- (void)requestTwoFactorCodeWithUserIdentity:(NSString*)userIdentity idmsToken:(NSString*)token mode:(int)mode deliveryMode:(NSString *)deliveryMode andCompletion:(void (^)(NSError *error))completionHandler;

- (void)submitTwoFactorCode:(NSString*)code withUserIdentity:(NSString*)userIdentity idmsToken:(NSString*)token andCompletion:(RPVTwoFactorResultBlock)completionHandler;

/// Exchanges the SRP session that requested 2FA for an app token. Only valid
/// once the verification code has been accepted.
- (void)fetchAppTokenForPendingTwoFactorSessionWithCompletion:(void (^)(NSError *error, NSString *userIdentity, NSString *gsToken))completion;

@end
