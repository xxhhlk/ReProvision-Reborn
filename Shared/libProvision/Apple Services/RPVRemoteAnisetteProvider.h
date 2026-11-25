//
//  RPVRemoteAnisetteProvider.h
//  ReProvision
//
//  Persistent macOS ADI identity over the SideStore anisette v3 protocol.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

extern NSString *const RPVAnisetteDefaultServer;

/// Provides a persistent macOS ADI identity through the anisette v3 protocol.
/// Only ADI provisioning material and a random local UUID are exchanged with
/// the server; Apple ID credentials and service tokens never leave the device.
@interface RPVRemoteAnisetteProvider : NSObject

/// Stops automatic ADI reprovisioning while an Apple session or GS token is
/// using the current machine identity.
@property (nonatomic, assign, getter=isIdentityPinned) BOOL identityPinned;

/// User-Agent that pairs with the server's client info. GrandSlam rejects the
/// login (-80045) when these disagree with the identity being emulated.
@property (nonatomic, copy, readonly, nullable) NSString *userAgent;

/// Server selected in settings, as an https URL without a trailing slash.
+ (NSString *)currentServerURL;

/// Discards the ADI identity stored for the current server so the next sign-in
/// provisions a new one. Existing Apple ID sessions stop working afterwards.
+ (void)resetStoredStateForCurrentServer;

- (void)fetchAnisetteDataWithCompletion:(void (^)(NSDictionary<NSString *, NSString *> * _Nullable headers,
                                                   NSError * _Nullable error))completion;

@end

NS_ASSUME_NONNULL_END
