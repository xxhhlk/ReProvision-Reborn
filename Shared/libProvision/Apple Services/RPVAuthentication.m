//
//  RPVAuthentication.m
//  iOS
//
//  Created by Matt Clarke on 11/11/2019.
//  Copyright © 2019 Matt Clarke. All rights reserved.
//

#import "RPVAuthentication.h"
#import "AuthKit.h"
#include "RPVLoginImpl.h"
#include "RPVLoginFallbackImpl.h"

@interface RPVAuthentication ()

@property (nonatomic, strong) AKAppleIDSession* appleIDSession;
@property (nonatomic, strong) RPVLoginImpl *loginImpl;
@property (nonatomic, strong) RPVLoginFallbackImpl *fallbackImpl;

@property (nonatomic, strong) NSString *cachedIdmsTokenFor2FA;
@property (nonatomic, strong) NSString *cachedUserIdentityFor2FA;
@property (nonatomic, strong) NSString *cachedUserPasswordFor2FA;
@property (nonatomic, readwrite) int requested2FAMode;

@end

@implementation RPVAuthentication

- (void)_clearTwoFactorSession {
    self.cachedUserIdentityFor2FA = nil;
    self.cachedIdmsTokenFor2FA = nil;
    self.cachedUserPasswordFor2FA = nil;
    self.requested2FAMode = 0;
}

// Performs a login without disturbing an in-progress 2FA context when
// allowIdentityRecovery is NO. Reusing an already-consumed IDMS session is a
// documented cause of "Your session has expired".
- (void)_authenticateWithUsername:(NSString *)username
                         password:(NSString *)password
            allowIdentityRecovery:(BOOL)allowIdentityRecovery
                   withCompletion:(void(^)(NSError *error, NSString *userIdentity, NSString *gsToken))completion {

    // Use fallback impl on iOS 9 only, due to missing corecrypto functionality.
    NSOperatingSystemVersion version;
    version.majorVersion = 10;
    version.minorVersion = 0;
    version.patchVersion = 0;
    if (![[NSProcessInfo processInfo] isOperatingSystemAtLeastVersion:version]) {
        [self.fallbackImpl loginWithUsername:username password:password completion:completion];
        return;
    }

    if (allowIdentityRecovery) {
        [self _clearTwoFactorSession];
    }

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        // Ensure username is lowercase!
        [self.loginImpl loginWithUsername:[username lowercaseString]
                                 password:password
                               completion:^(NSError *error, NSString *userIdentity, NSString *gsToken, NSString *idmsToken) {
            if (allowIdentityRecovery &&
                (error.code == RPVInternalLogin2FARequiredSecondaryAuthError ||
                 error.code == RPVInternalLogin2FARequiredTrustedDeviceError)) {
                self.cachedIdmsTokenFor2FA = idmsToken;
                self.cachedUserIdentityFor2FA = userIdentity;
                self.cachedUserPasswordFor2FA = password;
                self.requested2FAMode = (int)error.code;
            }
            completion(error, userIdentity, gsToken);
        }];
    });
}

- (instancetype)init {
    self = [super init];

    if (self) {
        self.loginImpl = [[RPVLoginImpl alloc] init];
        self.fallbackImpl = [[RPVLoginFallbackImpl alloc] initWithClientInfoOverride:self.loginImpl.clientInfoOverride];
    }

    return self;
}

- (void)authenticateWithUsername:(NSString*)username password:(NSString*)password withCompletion:(void(^)(NSError *error, NSString *userIdentity, NSString *gsToken))completion {
    [self _authenticateWithUsername:username
                           password:password
              allowIdentityRecovery:YES
                     withCompletion:completion];
}

// On iOS 13 anisette is produced synchronously by the device's own AuthKit, so
// there is nothing to fetch before a Developer Services request.
- (void)prepareAnisetteWithCompletion:(void(^)(NSError *error))completion {
    if (completion) {
        completion(nil);
    }
}

- (void)requestLoginCodeWithCompletion:(void(^)(NSError*))completionHandler {
    [self requestLoginCodeWithDeliveryMode:nil completion:completionHandler];
}

- (void)requestLoginCodeWithDeliveryMode:(NSString *)deliveryMode completion:(void(^)(NSError*))completionHandler {
    [self.loginImpl requestTwoFactorCodeWithUserIdentity:self.cachedUserIdentityFor2FA
                                               idmsToken:self.cachedIdmsTokenFor2FA
                                                    mode:self.requested2FAMode
                                            deliveryMode:deliveryMode
                                           andCompletion:completionHandler];
}

- (BOOL)hasActiveTwoFactorSession {
    return self.cachedUserIdentityFor2FA.length > 0 &&
           self.cachedIdmsTokenFor2FA.length > 0 &&
           self.cachedUserPasswordFor2FA.length > 0 &&
           (self.requested2FAMode == RPVInternalLogin2FARequiredSecondaryAuthError ||
            self.requested2FAMode == RPVInternalLogin2FARequiredTrustedDeviceError);
}

// Apple can lag behind an accepted verification code while it finishes creating
// the trusted session. Retry the follow-up login a bounded number of times
// instead of surfacing "Your session has expired".
- (void)_finishTwoFactorLoginWithUsername:(NSString *)username
                                  password:(NSString *)password
                          remainingRetries:(NSUInteger)remainingRetries
                                completion:(void(^)(NSError *error, NSString *userIdentity, NSString *gsToken))completion {
    [self _authenticateWithUsername:username
                           password:password
              allowIdentityRecovery:NO
                     withCompletion:^(NSError *error, NSString *userIdentity, NSString *gsToken) {
        BOOL hasCompleteCredentials = error == nil && userIdentity.length > 0 && gsToken.length > 0;
        if (hasCompleteCredentials) {
            [self _clearTwoFactorSession];
            completion(nil, userIdentity, gsToken);
            return;
        }

        if (remainingRetries > 0) {
            NSTimeInterval delay = remainingRetries == 2 ? 0.75 : 1.5;
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC)),
                           dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                [self _finishTwoFactorLoginWithUsername:username
                                               password:password
                                       remainingRetries:remainingRetries - 1
                                             completion:completion];
            });
            return;
        }

        // The accepted IDMS context cannot be reused.
        [self _clearTwoFactorSession];
        NSMutableDictionary *userInfo = [@{
            NSLocalizedDescriptionKey: @"Apple accepted the verification code, but did not finish creating the trusted login session. Please go back and sign in again."
        } mutableCopy];
        if (error) {
            userInfo[NSUnderlyingErrorKey] = error;
        }
        NSError *finalError = [NSError errorWithDomain:NSCocoaErrorDomain
                                                   code:RPVInternalLoginPostTwoFactorError
                                               userInfo:userInfo];
        completion(finalError, nil, nil);
    }];
}

- (void)validateLoginCode:(NSString*)code withCompletion:(void(^)(NSError *error, NSString *userIdentity, NSString *gsToken))completion {
    if (![self hasActiveTwoFactorSession]) {
        NSError *error = [NSError errorWithDomain:NSCocoaErrorDomain
                                             code:RPVInternalLoginError
                                         userInfo:@{NSLocalizedDescriptionKey: @"The Apple authentication session is incomplete. Please go back and sign in again."}];
        completion(error, nil, nil);
        return;
    }

    // Validate the one-time code against the cached IDMS context.
    [self.loginImpl submitTwoFactorCode:code
                       withUserIdentity:self.cachedUserIdentityFor2FA
                              idmsToken:self.cachedIdmsTokenFor2FA
                          andCompletion:^(NSError *error) {
        if (error) {
            completion(error, nil, nil);
            return;
        }

        // The session that requested 2FA is the one Apple just verified, so ask
        // it for the token directly. A fresh login would trigger a new prompt.
        [self.loginImpl fetchAppTokenForPendingTwoFactorSessionWithCompletion:^(NSError *tokenError, NSString *userIdentity, NSString *gsToken) {
            if (tokenError == nil && gsToken.length > 0) {
                [self _clearTwoFactorSession];
                completion(nil, userIdentity, gsToken);
                return;
            }

            NSString *username = [self.cachedUserIdentityFor2FA componentsSeparatedByString:@"|"].lastObject;
            NSString *password = [self.cachedUserPasswordFor2FA copy];
            [self _finishTwoFactorLoginWithUsername:username
                                           password:password
                                   remainingRetries:2
                                         completion:completion];
        }];
    }];
}

- (void)fallback2FACodeRequest:(void(^)(NSError *error, NSString *userIdentity, NSString *gsToken))completionHandler {

    NSString *username = [self.cachedUserIdentityFor2FA componentsSeparatedByString:@"|"].lastObject;
    NSString *password = [self.cachedUserPasswordFor2FA copy];
    NSLog(@"[DIAG] fallback2FA enter identity=%@ pwdLen=%lu hasSession=%d",
          self.cachedUserIdentityFor2FA, (unsigned long)password.length, [self hasActiveTwoFactorSession]);

    // Without the cached credentials there is nothing to re-authenticate with;
    // report it instead of running a login with an empty username.
    if (username.length == 0 || password.length == 0) {
        NSError *missing = [NSError errorWithDomain:NSCocoaErrorDomain
                                              code:RPVInternalLoginError
                                          userInfo:@{NSLocalizedDescriptionKey: @"The Apple authentication session is incomplete. Please go back and sign in again."}];
        completionHandler(missing, nil, nil);
        return;
    }

    // AuthKit only completes the on-device 2FA step; the token it returns is
    // scoped to com.apple.gs.appleid.auth, which Developer Services rejects.
    // Once 2FA is dealt with, run the real SRP login again to obtain a
    // com.apple.gs.xcode.auth token. authenticateWithUsername: clears the
    // cached 2FA session, so the become-active guard will not re-trigger.
    [self.fallbackImpl loginWithUsername:username password:password completion:^(NSError *error, NSString *userIdentity, NSString *gsToken) {
        NSLog(@"[DIAG] fallback2FA authkit done err=%@", error.localizedDescription ?: @"none");
        if (!error) {
            [self authenticateWithUsername:username password:password withCompletion:completionHandler];
        } else {
            completionHandler(error, nil, nil);
        }
    }];
}

- (NSDictionary*)appleIDHeadersForRequest:(NSURLRequest*)request {
    if (!self.appleIDSession){
        self.appleIDSession = [[AKAppleIDSession alloc] initWithIdentifier:@"com.apple.gs.xcode.auth"];
    }

    NSMutableDictionary *result = [[self.appleIDSession appleIDHeadersForRequest:request] mutableCopy];
    if (!result) {
        result = [NSMutableDictionary dictionary];
    }

    // Override some auth parameters
    [result setObject:@"com.apple.gs.xcode.auth" forKey:@"X-Apple-App-Info"];
    [result setObject:self.loginImpl.clientInfoOverride forKey:@"X-MMe-Client-Info"];

    return result;
}

@end
