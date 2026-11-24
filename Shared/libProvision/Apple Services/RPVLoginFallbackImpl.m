//
//  RPVLoginFallbackImpl.m
//  iOS
//
//  Created by Matt Clarke on 14/12/2019.
//  Copyright © 2019 Matt Clarke. All rights reserved.
//

#import "RPVLoginFallbackImpl.h"
#import "AuthKit.h"

@interface RPVLoginFallbackImpl ()
@property (nonatomic, strong) AKAppleIDAuthenticationController* authenticationController;
@property (nonatomic, strong) NSString *clientInfoOverride;
@property (nonatomic, strong) AKAppleIDAuthenticationContext *currentContext;
@end

@implementation RPVLoginFallbackImpl

- (instancetype)initWithClientInfoOverride:(NSString*)clientInfoOverride {
    self = [super init];
    
    if (self) {
        self.clientInfoOverride = clientInfoOverride;
    }
    
    return self;
}

- (void)_ensureAuthenticationController {
    if (!self.authenticationController) {
        // Setup AKDevice override
        [[AKDevice currentDevice] setServerFriendlyDescription:self.clientInfoOverride];
        
        AKAppleIDAuthenticationController *controller = [AKAppleIDAuthenticationController alloc];
        
        if ([controller respondsToSelector:@selector(initWithIdentifier:daemonXPCEndpoint:)])
            controller = [controller initWithIdentifier:nil daemonXPCEndpoint:nil];
        else
            controller = [controller initWithIdentifier:nil];
        
        self.authenticationController = controller;
    }
}

- (void)loginWithUsername:(NSString*)username password:(NSString*)password completion:(RPVLoginFallbackResultBlock)completionHandler {
    
    // Configure authentication context
    self.currentContext = [[AKAppleIDAuthenticationContext alloc] init];
    [self.currentContext setUsername:username];
    [self.currentContext _setPassword:password];
    
    if ([self.currentContext respondsToSelector:@selector(setAuthenticationType:)])
        [self.currentContext setAuthenticationType:2];
    
    [self.currentContext setServiceIdentifier:@"com.apple.gs.xcode.auth"];
    [self.currentContext setServiceIdentifiers:[NSArray arrayWithObject:@"com.apple.gs.xcode.auth"]];
    
    // Directly call into AuthKit for this context
    [self _ensureAuthenticationController];
    
    // 2FA is handled internally by this implementation
    [self.authenticationController authenticateWithContext:self.currentContext completion:^(id result, id error) {
        if (error) {
            NSLog(@"AuthKit authentication failed: %@", [error localizedDescription]);
            completionHandler(error, nil, nil);
            return;
        }

        id AKUsernameObj = [result objectForKey:@"AKUsername"];
        NSString* AKUsername = [AKUsernameObj isKindOfClass:[NSString class]] ? AKUsernameObj : nil;
        if (AKUsername.length == 0) {
            id dsid = [result objectForKey:@"AKDSID"];
            AKUsername = dsid ? [dsid description] : nil;
        }
        if (AKUsername.length == 0) AKUsername = @"unknown";

        NSString* AKAltDSID = [result objectForKey:@"AKAltDSID"];
        NSDictionary* IDMSToken = [result objectForKey:@"AKIDMSToken"];

        // The token from AuthKit only signals that the on-device 2FA step
        // completed; the real com.apple.gs.xcode.auth token is obtained by
        // re-running the SRP login afterwards. Do not fail here when the
        // scope is appleid.auth only - that is expected on older iOS.
        NSString* GSToken = [IDMSToken objectForKey:@"com.apple.gs.xcode.auth"];
        NSString* username = [[NSString alloc] initWithFormat:@"%@|%@", AKAltDSID ?: @"", AKUsername];

        completionHandler(nil, username, GSToken);
    }];
}

@end
