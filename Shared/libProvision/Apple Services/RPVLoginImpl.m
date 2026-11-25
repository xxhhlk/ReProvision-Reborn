//
//  RPVLoginImpl.cpp
//  iOS
//
//  Created by Kabir Oberai on 11/11/19.
//  Adapted by Matt Clarke on 24/11/19.
//

#import "RPVLoginImpl.h"
#import "RPVRemoteAnisetteProvider.h"

#import <corecrypto/ccsrp.h>
#import <corecrypto/ccdrbg.h>
#import <corecrypto/ccsrp_gp.h>
#import <corecrypto/ccdigest.h>
#import <corecrypto/ccsha2.h>
#import <corecrypto/ccpbkdf2.h>
#import <corecrypto/cchmac.h>
#import <corecrypto/ccaes.h>
#import <corecrypto/ccpad.h>
#import <corecrypto/ccrng_system.h>

#import <dlfcn.h>

#define DEBUG 1

// GrandSlam's developer sign-in only accepts a Mac client. Claiming an iPhone
// makes the apptokens step answer -80046 ("This action cannot be completed at
// this time"), which is a platform check rather than a credential problem.
// The anisette still comes from the device; only the claimed client changes.
static NSString * const RPVGrandSlamClientInfo = @"<MacBookPro11,5> <Mac OS X;10.14.6;18G103> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";
static NSString * const RPVGrandSlamUserAgent = @"AuthKit/1 (Macintosh; OS X 26.5.2) (com.apple.dt.Xcode/26.0)";
static NSString * const RPVGrandSlamXcodeVersion = @"14.2 (14C18)";

// Anisette shared by every request in the current run. A server with a stable
// identity returns the same X-Mme-Device-Id every time and rotates only the
// one-shot X-Apple-I-MD, so Developer Services can be handed a fresh copy on a
// later launch and still accept the persisted token.
static NSDictionary *RPVAnisetteHeaders = nil;
static NSDate *RPVAnisetteFetchedAt = nil;

// Device identity that minted the current token. Kept only to verify that the
// anisette server still reports the same machine; the headers themselves are
// never reused because the attestation is a one-shot value.
static NSString *RPVTokenMintingDeviceId = nil;

struct ccrng_state *ccDRBGGetRngState(void);

// On this device syslog is not running and there is no `log` tool, so NSLog
// never reaches a file. Mirror the 2FA diagnostics into a file the operator can
// read over SSH. Kept small and best-effort; never throws.
void RPV2FAWriteLog(NSString *message) {
    if (message.length == 0) {
        return;
    }
    @try {
        NSString *path = @"/var/mobile/Documents/ReProvision-2FA.log";
        NSString *line = [NSString stringWithFormat:@"%@ %@\n", [NSDate date], message];
        NSData *data = [line dataUsingEncoding:NSUTF8StringEncoding];
        NSFileManager *fm = [NSFileManager defaultManager];
        [fm createDirectoryAtPath:[path stringByDeletingLastPathComponent]
      withIntermediateDirectories:YES attributes:nil error:nil];
        if ([fm fileExistsAtPath:path]) {
            NSDictionary *attrs = [fm attributesOfItemAtPath:path error:nil];
            if ([[attrs objectForKey:NSFileSize] unsignedLongLongValue] > 512 * 1024) {
                [fm removeItemAtPath:path error:nil];
            }
        }
        if ([fm fileExistsAtPath:path]) {
            NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
            [fh seekToEndOfFile];
            [fh writeData:data];
            [fh closeFile];
        } else {
            [data writeToFile:path atomically:YES];
        }
    } @catch (__unused NSException *exception) {
    }
}

@interface AKAppleIDSession : NSObject
- (AKAppleIDSession *)initWithIdentifier:(NSString *)identifier;
- (NSDictionary *)appleIDHeadersForRequest:(NSURLRequest *)request;
@end

@interface AKDevice : NSObject
+ (AKDevice *)currentDevice;
- (NSString *)uniqueDeviceIdentifier;
- (NSString *)MLBSerialNumber;
- (NSString *)ROMAddress;
- (NSString *)serialNumber;
@end

static void writeToLogFile(const char *string) {
#if DEBUG
    NSString *txtFileName = @"/var/mobile/Documents/ReProvisionDebug.txt";
    NSString *final = [NSString stringWithFormat:@"(%@) %s\n", [NSDate date], string];
     
    NSFileHandle *fileHandle = [NSFileHandle fileHandleForWritingAtPath:txtFileName];
    if (fileHandle) {
        [fileHandle seekToEndOfFile];
        [fileHandle writeData:[final dataUsingEncoding:NSUTF8StringEncoding]];
        [fileHandle closeFile];
    } else {
        [final writeToFile:txtFileName
                atomically:NO
                  encoding:NSStringEncodingConversionAllowLossy
                     error:nil];
    }
#endif
}

OS_FORMAT_PRINTF(1, 2)
static void log_error(const char *format, ...) {
    va_list args;
    va_start(args, format);
    char *str = NULL;
    vasprintf(&str, format, args);
    va_end(args);

    NSLog(@"[ERROR] %s", str);
    writeToLogFile(str);

    free(str);
}

OS_FORMAT_PRINTF(1, 2)
static void log_debug(const char *format, ...) {
#if DEBUG
    va_list args;
    va_start(args, format);
    char *str = NULL;
    vasprintf(&str, format, args);
    va_end(args);

    NSLog(@"[DEBUG] %s", str);
    writeToLogFile(str);

    free(str);
#endif
}

static const char hexchars[] = "0123456789abcdef";

// AppleIDAuthSupport`AppleIDAuthSupportPBKDF2SRP
static NSData *PBKDF2SRP(const struct ccdigest_info *di_info, BOOL notS2K, NSString *password, NSData *salt, NSNumber *iterations) {
    const struct ccdigest_info *password_di_info = ccsha256_di();
    char digest_raw[password_di_info->output_size];
    const char *passwordUTF8 = password.UTF8String;
    ccdigest(password_di_info, strlen(passwordUTF8), passwordUTF8, digest_raw);

    size_t final_digest_len = password_di_info->output_size * (notS2K ? 2 : 1);
    char digest[final_digest_len];

    if (notS2K) {
        // s2k_fo passes a hex string version of the bytes instead
        for (size_t i = 0; i < password_di_info->output_size; i++) {
            char byte = digest_raw[i];
            digest[i * 2 + 0] = hexchars[(byte >> 4) & 0x0F];
            digest[i * 2 + 1] = hexchars[(byte >> 0) & 0x0F];
        }
    } else {
        memcpy(digest, digest_raw, final_digest_len);
    }

    NSMutableData *data = [NSMutableData dataWithLength:di_info->output_size];
    int result = ccpbkdf2_hmac(di_info,
                               final_digest_len, digest,
                               salt.length, salt.bytes,
                               iterations.integerValue,
                               di_info->output_size, data.mutableBytes);
    if (result != 0) return nil;
    return data;
}

// AppleIDAuthSupport`addStringToNegProt
static void addStringToNegProt(const struct ccdigest_info *di_info, struct ccdigest_ctx *di_ctx, const char *str) {
    ccdigest_update(di_info, di_ctx, strlen(str), str);
}

// AppleIDAuthSupport`addDataToNegProt
static void addDataToNegProt(const struct ccdigest_info *di_info, struct ccdigest_ctx *di_ctx, NSData *data) {
    uint32_t data_len = (uint32_t)data.length; // 4 bytes for length
    ccdigest_update(di_info, di_ctx, sizeof(data_len), &data_len);
    ccdigest_update(di_info, di_ctx, data_len, data.bytes);
}

// AppleIDAuthSupport`SRPCreateSessionKey
static NSData *createSessionKey(ccsrp_ctx_t srp_ctx, const char *key_name) {
    size_t key_len;
    const void *session_key = ccsrp_get_session_key(srp_ctx, &key_len);
    const struct ccdigest_info *di_info = ccsha256_di();
    size_t hmac_len = di_info->output_size;
    unsigned char hmac_bytes[hmac_len];
    cchmac(di_info, key_len, session_key, strlen(key_name), key_name, hmac_bytes);
    return [NSData dataWithBytes:hmac_bytes length:hmac_len];
}

// AppleIDAuthSupport`CreateDecryptedData
static NSData *decryptCBC(ccsrp_ctx_t srp_ctx, NSData *spd) {
    NSData *extraDataKey = createSessionKey(srp_ctx, "extra data key:");
    NSData *extraDataIV = createSessionKey(srp_ctx, "extra data iv:");

    NSMutableData *decrypted = [NSMutableData dataWithLength:spd.length];

    const struct ccmode_cbc *decrypt_mode = ccaes_cbc_decrypt_mode();
    cccbc_iv iv[decrypt_mode->block_size];
    if (extraDataIV.bytes) {
        memcpy(iv, extraDataIV.bytes, decrypt_mode->block_size);
    } else {
        bzero(iv, decrypt_mode->block_size);
    }

    cccbc_ctx ctx_buf[decrypt_mode->size];
    decrypt_mode->init(decrypt_mode, ctx_buf, extraDataKey.length, extraDataKey.bytes);

    size_t len = ccpad_pkcs7_decrypt(decrypt_mode, ctx_buf, iv, spd.length, spd.bytes, decrypted.mutableBytes);
    if (len > spd.length) {
        log_error("decrypted len > spd len");
        return nil;
    }

    return decrypted;
}

// AppleIDAuthSupport`_AppleIDAuthSupportCreateDecryptedData
static NSData *decryptGCM(NSData *sk, NSData *encrypted) {
    const struct ccmode_gcm *decrypt_mode = ccaes_gcm_decrypt_mode();
    ccgcm_ctx gcm_ctx[decrypt_mode->size];
    decrypt_mode->init(decrypt_mode, gcm_ctx, sk.length, sk.bytes);
    if (encrypted.length < 35) {
        log_error("Encrypted token too short!");
        return nil;
    }
    if (cc_cmp_safe(3, encrypted.bytes, "XYZ")) {
        log_error("Encrypted token wrong version!");
        return nil;
    }
    decrypt_mode->set_iv(gcm_ctx, 16, (unsigned char*)encrypted.bytes + 3);
    decrypt_mode->gmac(gcm_ctx, 3, encrypted.bytes);

    size_t decrypted_len = encrypted.length - 35;
    NSMutableData *decrypted = [NSMutableData dataWithLength:decrypted_len];
    decrypt_mode->gcm(gcm_ctx, decrypted_len, (unsigned char*)encrypted.bytes + 16 + 3, decrypted.mutableBytes);

    char tag[16];
    decrypt_mode->finalize(gcm_ctx, 16, tag);
    if (cc_cmp_safe(16, (unsigned char*)encrypted.bytes + decrypted_len + 19, tag)) {
        log_error("Invalid tag version");
        return nil;
    }

    return decrypted;
}

// AppleIDAuthSupport`cfHMAC
static void update_hmac(const struct ccdigest_info *di_info, struct cchmac_ctx *hmac_ctx, id value) {
    if ([value isKindOfClass:NSArray.class]) {
        NSArray<NSString *> *apps = value;
        for (NSString *app in apps) {
            update_hmac(di_info, hmac_ctx, app);
        }
    } else if ([value isKindOfClass:NSString.class]) {
        NSString *app = value;
        const char *appUTF8 = app.UTF8String;
        cchmac_update(di_info, hmac_ctx, strlen(appUTF8), appUTF8);
    } else if ([value isKindOfClass:NSData.class]) {
        NSData *appData = value;
        cchmac_update(di_info, hmac_ctx, appData.length, appData.bytes);
    } else {
        log_error("Invalid hmac value passed: %s", [value description].UTF8String);
    }
}

// AppleIDAuthSupport`CreateAppTokensChecksum
static NSData *createAppTokensChecksum(NSData *sk, NSString *adsid, NSArray<NSString *> *apps) {
    const struct ccdigest_info *di_info = ccsha256_di();
    size_t hmac_size = cchmac_di_size(di_info);
    struct cchmac_ctx hmac_ctx[hmac_size];
    cchmac_init(di_info, hmac_ctx, sk.length, sk.bytes);

    const char *key = "apptokens";
    cchmac_update(di_info, hmac_ctx, strlen(key), key);

    const char *adsidUTF8 = adsid.UTF8String;
    cchmac_update(di_info, hmac_ctx, strlen(adsidUTF8), adsidUTF8);

    update_hmac(di_info, hmac_ctx, apps);

    NSMutableData *data = [NSMutableData dataWithLength:di_info->output_size];
    cchmac_final(di_info, hmac_ctx, (unsigned char*)data.mutableBytes);

    return data;
}

static NSInteger RPVDecimalDigitValue(unichar character) {
    // Convert localized keypad and AutoFill digits to the ASCII form Apple expects.
    static const unichar digitBlockStarts[] = {
        0x0030, 0x0660, 0x06F0, 0x07C0, 0x0966, 0x09E6, 0x0A66,
        0x0AE6, 0x0B66, 0x0BE6, 0x0C66, 0x0CE6, 0x0D66, 0x0DE6,
        0x0E50, 0x0ED0, 0x0F20, 0x1040, 0x1090, 0x17E0, 0x1810,
        0x1946, 0x19D0, 0x1A80, 0x1A90, 0x1B50, 0x1BB0, 0x1C40,
        0x1C50, 0xA620, 0xA8D0, 0xA900, 0xA9D0, 0xA9F0, 0xAA50,
        0xABF0, 0xFF10
    };

    for (NSUInteger index = 0;
         index < sizeof(digitBlockStarts) / sizeof(digitBlockStarts[0]);
         index++) {
        unichar start = digitBlockStarts[index];
        if (character >= start && character <= start + 9) {
            return character - start;
        }
    }
    return NSNotFound;
}

static NSString *RPVNormalizedVerificationCode(NSString *code) {
    NSMutableString *result = [NSMutableString stringWithCapacity:6];
    for (NSUInteger index = 0; index < code.length; index++) {
        NSInteger digit = RPVDecimalDigitValue([code characterAtIndex:index]);
        if (digit != NSNotFound) {
            [result appendFormat:@"%ld", (long)digit];
        }
    }
    return result;
}

@interface RPVLoginImpl ()

@property (nonatomic, strong) NSDictionary *lookupURLs;

// Keeps one adi_pb-backed identity for the whole app session.
@property (nonatomic, strong) RPVRemoteAnisetteProvider *anisetteProvider;

// Trusted phone number the current 2FA code was sent to, and how.
@property (nonatomic, strong) NSString *twoFactorPhoneNumberID;
@property (nonatomic, strong) NSString *twoFactorPhoneDeliveryMode;

// SRP session that asked for 2FA. Apple keeps it alive after the code is
// accepted, so it is the only session that can be exchanged for an app token
// without triggering a second 2FA prompt.
@property (nonatomic, strong) NSData *pendingTwoFactorSessionKey;
@property (nonatomic, strong) NSData *pendingTwoFactorSessionC;
@property (nonatomic, strong) NSString *pendingTwoFactorIdmsToken;
@property (nonatomic, strong) NSString *pendingTwoFactorADSID;
@property (nonatomic, strong) NSString *pendingTwoFactorIdentity;
@property (nonatomic, strong) NSDictionary *pendingTwoFactorClientData;

#if TARGET_OS_IOS
@property (nonatomic, readwrite) struct ccrng_state *rngState;
#endif

- (BOOL)_isRetryableGSAStatus:(long)httpCode;
- (BOOL)_isRetryableNSURLError:(NSError *)error;
- (NSURLSession *)_gsaEphemeralSession;
- (NSURLSession *)_twoFactorSession;
- (void)_performGSADataRequest:(NSMutableURLRequest *)request attempt:(NSUInteger)attempt completion:(void (^)(NSError *error, NSData *data, long httpCode))completionHandler;
- (void)_performGSADataRequest:(NSMutableURLRequest *)request attempt:(NSUInteger)attempt session:(NSURLSession *)providedSession completion:(void (^)(NSError *error, NSData *data, long httpCode))completionHandler;
- (void)_makeRequestWithParameters:(NSDictionary*)params attempt:(NSUInteger)attempt completion:(void (^)(NSError *err, NSDictionary *response))completionHandler;
- (void)_retryGSAParameters:(NSDictionary*)params attempt:(NSUInteger)attempt completion:(void (^)(NSError *err, NSDictionary *response))completionHandler;
- (NSDictionary *)_phoneDescriptorFromAuthResponse:(id)response;
- (void)_collectPhoneCandidates:(id)node into:(NSMutableArray *)out;
- (BOOL)_scanErrorNode:(id)node code:(NSInteger *)code message:(NSString **)message;
- (NSMutableURLRequest *)_twoFactorRequestWithURL:(NSURL *)URL userIdentity:(NSString *)userIdentity idmsToken:(NSString *)token;
- (NSMutableURLRequest *)_twoFactorJSONRequestWithURL:(NSURL *)URL userIdentity:(NSString *)userIdentity idmsToken:(NSString *)token;
- (void)_performTwoFactorCodeRequest:(NSMutableURLRequest *)request completion:(void (^)(NSError *error))completionHandler;
- (void)_submitPhoneVerificationCode:(NSString *)code userIdentity:(NSString *)userIdentity idmsToken:(NSString *)token completion:(RPVTwoFactorResultBlock)completionHandler;
- (void)_requestAppTokensWithSessionKey:(NSData *)sessionKey
                               sessionC:(NSData *)sessionC
                              idmsToken:(NSString *)idmsToken
                                   adsid:(NSString *)adsid
                                    apps:(NSArray<NSString *> *)apps
                              clientData:(NSDictionary *)clientData
                              completion:(void (^)(NSError *error, NSString *token))completionHandler;

@end

@implementation RPVLoginImpl

- (instancetype)init {
    self = [super init];
    
    if (self) {
        self.clientInfoOverride = RPVGrandSlamClientInfo;
        
#if TARGET_OS_IOS
        // Create rng pointer
        
        NSOperatingSystemVersion version;
        version.majorVersion = 10;
        version.minorVersion = 0;
        version.patchVersion = 0;
        
        if ([[NSProcessInfo processInfo] isOperatingSystemAtLeastVersion:version]) {
            self.rngState = ccrng(NULL);
        } else {
            self.rngState = (struct ccrng_state*)malloc(sizeof(struct ccrng_system_state));
            ccrng_system_init((struct ccrng_system_state*)self.rngState);
        }
#endif
        
    }
    
    return self;
}

- (void)dealloc {
#if TARGET_OS_IOS

    // Free rng pointer if needed
    NSOperatingSystemVersion version;
    version.majorVersion = 10;
    version.minorVersion = 0;
    version.patchVersion = 0;
    
    if (![[NSProcessInfo processInfo] isOperatingSystemAtLeastVersion:version]) {
        ccrng_system_done((struct ccrng_system_state*)self.rngState);
    }
    
#endif
}

-(NSError*)createError:(NSString *)string :(int)code {
    NSDictionary *userInfo = @{
                               NSLocalizedDescriptionKey: NSLocalizedString(string, nil),
                               NSLocalizedFailureReasonErrorKey: NSLocalizedString(string, nil),
                               NSLocalizedRecoverySuggestionErrorKey: NSLocalizedString(@"", nil)
                               };
    
    NSError *error = [NSError errorWithDomain:NSCocoaErrorDomain
                                         code:code
                                     userInfo:userInfo];
    
    return error;
}

- (void)_ensureAuthKitAvailable {
    dlopen("/System/Library/PrivateFrameworks/AuthKit.framework/AuthKit", RTLD_NOW);
}

- (NSDictionary *)_remoteAnisetteHeaders {
    // The device's own AuthKit anisette is unusable here: AKD cannot reach its
    // ADI keys on this jailbreak, so every request comes back with the same
    // X-Apple-I-MD-M value. Apple rejects that as an invalid attestation
    // (-22410 / -80046).
    //
    // A plain `GET /` anisette endpoint is not enough either: it hands out a
    // throwaway emulated Mac, so the identity changes on every fetch and the
    // saved GS token stops matching (resultCode 1100 on the next launch), while
    // the older endpoints report ADI routing info Apple now rejects with
    // -36607. The v3 provider provisions an adi_pb once and reuses it, which
    // keeps the identity fixed while the one-shot OTP stays fresh.
    @synchronized (self) {
        // Cache briefly so /auth, the code send and the code verification all
        // use the same attestation. A fresh anisette mid-flow makes Apple
        // reject the verification with HTTP 401.
        if (RPVAnisetteHeaders && RPVAnisetteFetchedAt && -[RPVAnisetteFetchedAt timeIntervalSinceNow] < 60.0) {
            return RPVAnisetteHeaders;
        }
    }

    if (!self.anisetteProvider) {
        self.anisetteProvider = [[RPVRemoteAnisetteProvider alloc] init];
    }

    __block NSDictionary *headers = nil;
    __block NSError *providerError = nil;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    [self.anisetteProvider fetchAnisetteDataWithCompletion:^(NSDictionary<NSString *,NSString *> *result, NSError *error) {
        headers = result;
        providerError = error;
        dispatch_semaphore_signal(sem);
    }];
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 45 * NSEC_PER_SEC));

    if (headers.count == 0) {
        NSLog(@"[DIAG] remote anisette failed: %@, fallback to local", providerError.localizedDescription ?: @"timeout");
        RPV2FAWriteLog([NSString stringWithFormat:@"anisette v3 failed: %@", providerError.localizedDescription ?: @"timeout"]);
        return nil;
    }

    NSString *clientInfo = headers[@"X-MMe-Client-Info"];
    if ([clientInfo isKindOfClass:[NSString class]] && clientInfo.length > 0) {
        self.clientInfoOverride = clientInfo;
    }
    RPV2FAWriteLog([NSString stringWithFormat:@"anisette v3 ok device=%@ rinfo=%@ mdlu=%@",
                    headers[@"X-Mme-Device-Id"] ?: @"-",
                    headers[@"X-Apple-I-MD-RINFO"] ?: @"-",
                    headers[@"X-Apple-I-MD-LU"] ?: @"-"]);
    @synchronized (self) { RPVAnisetteHeaders = headers; RPVAnisetteFetchedAt = [NSDate date]; }
    return headers;
}

// Anisette for Developer Services. Always fetched fresh so the attestation is
// current, and checked against the identity that minted the token: a server
// that hands out a new device id on every call would make Apple answer 1100.
- (NSDictionary *)currentAnisetteHeaders {
    NSDictionary *headers = [self _anisetteData];
    NSString *deviceId = headers[@"X-Mme-Device-Id"];
    NSString *mintedBy = nil;
    @synchronized (self) { mintedBy = RPVTokenMintingDeviceId; }
    if (mintedBy.length == 0) {
        mintedBy = [[NSUserDefaults standardUserDefaults] objectForKey:@"RPVTokenMintingDeviceId"];
        @synchronized (self) { RPVTokenMintingDeviceId = mintedBy; }
    }

    if (mintedBy.length > 0 && deviceId.length > 0 && ![deviceId isEqualToString:mintedBy]) {
        RPV2FAWriteLog([NSString stringWithFormat:@"anisette identity changed %@ -> %@, token is stale",
                        mintedBy, deviceId]);
    }
    return headers;
}

- (NSDictionary *)_anisetteData {
    NSDictionary *remoteHeaders = [self _remoteAnisetteHeaders];
    if (remoteHeaders.count > 0) {
        return remoteHeaders;
    }
    NSDateFormatter *formatter = [NSDateFormatter new];
    formatter.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    formatter.calendar = [NSCalendar calendarWithIdentifier:NSCalendarIdentifierGregorian];
    formatter.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"UTC"];
    formatter.dateFormat = @"yyyy-MM-dd'T'HH:mm:ss'Z'";
    NSString *dateString = [formatter stringFromDate:[NSDate date]];

    [self _ensureAuthKitAvailable];

    Class AKAppleIDSession = NSClassFromString(@"AKAppleIDSession");
    NSDictionary *headers = [[[AKAppleIDSession alloc] initWithIdentifier:@"com.apple.gs.xcode.auth"] appleIDHeadersForRequest:nil];
    
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    
    [result setObject:dateString forKey:@"X-Apple-I-Client-Time"];
    [result setObject:NSLocale.currentLocale.localeIdentifier forKey:@"X-Apple-Locale"];
    [result setObject:NSTimeZone.localTimeZone.abbreviation forKey:@"X-Apple-I-TimeZone"];
    
    [headers enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSString *value, BOOL *stop) {
        [result setObject:value forKey:key];
    }];
    
    [result setObject:self.clientInfoOverride forKey:@"X-MMe-Client-Info"];

    return result;
}

- (NSDictionary *)_deviceData {
    if ([self _remoteAnisetteHeaders].count > 0) {
        // Remote anisette already carries its own device id / serial; do not override.
        return [NSDictionary dictionary];
    }
    // Note: X-Apple-I-PRK is also sent, however it's a password reset key which (I think) may not always
    // be present even in genuine requests. It requires another account on device. So let's not include
    // it for now.
    //
    // In fact, the only X-whatever key required here is the device X-Mme-Device-Id
    // (which I believe must match that of a provisioned device)

    [self _ensureAuthKitAvailable];
    
    AKDevice *device = [NSClassFromString(@"AKDevice") currentDevice];
    
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    
    if (device.uniqueDeviceIdentifier)
        [result setObject:device.uniqueDeviceIdentifier forKey:@"X-Mme-Device-Id"];
    
    if ([device respondsToSelector:@selector(MLBSerialNumber)] && device.MLBSerialNumber)
        [result setObject:device.MLBSerialNumber forKey:@"X-Apple-I-MLB"];
    
    if ([device respondsToSelector:@selector(ROMAddress)] && device.ROMAddress)
        [result setObject:device.ROMAddress forKey:@"X-Apple-I-ROM"];
    
    if (device.serialNumber)
        [result setObject:device.serialNumber forKey:@"X-Apple-I-SRL-NO"];
    
    return result;
}

- (NSDictionary*)defaultRequestHeaders {
    return @{
        @"X-MMe-Client-Info": self.clientInfoOverride,
        @"Content-Type": @"text/x-xml-plist",
        @"User-Agent": RPVGrandSlamUserAgent,
        @"Accept": @"*/*"
    };
}

// GSA answers 502/503/504 while a session is being created, and 408/429 when
// it throttles. Those are transient upstream failures, so retry them with a
// short backoff instead of surfacing "Apple server returned HTTP 503".
- (BOOL)_isRetryableGSAStatus:(long)httpCode {
    switch (httpCode) {
        case 408:
        case 429:
        case 500:
        case 502:
        case 503:
        case 504:
            return YES;
        default:
            return NO;
    }
}

- (BOOL)_isRetryableNSURLError:(NSError *)error {
    switch (error.code) {
        case NSURLErrorTimedOut:
        case NSURLErrorCannotConnectToHost:
        case NSURLErrorNetworkConnectionLost:
        case NSURLErrorNotConnectedToInternet:
            return YES;
        default:
            return NO;
    }
}

// Apple's GrandSlam edge drops a keep-alive connection after two requests, but
// a sign-in issues three (lookup, complete, apptokens). Reusing a pooled
// connection makes the third one come back as an HTML 503. Hand every GSA
// request a throwaway session so it always opens a fresh connection.
- (NSURLSession *)_gsaEphemeralSession {
    NSURLSessionConfiguration *config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    config.URLCache = nil;
    // Keep cookies across throwaway sessions: the trusted-phone flow sends a
    // code on one request and verifies it on the next, and Apple ties the two
    // together with a session cookie. Dropping it makes a correct code look
    // wrong. The socket is still fresh per session, so the 503 reuse problem is
    // unaffected.
    config.HTTPCookieStorage = [NSHTTPCookieStorage sharedHTTPCookieStorage];
    config.HTTPCookieAcceptPolicy = NSHTTPCookieAcceptPolicyAlways;
    config.HTTPShouldUsePipelining = NO;
    config.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
    config.timeoutIntervalForRequest = 30.0;
    config.timeoutIntervalForResource = 60.0;
    return [NSURLSession sessionWithConfiguration:config];
}

// One long-lived session for the trusted-phone exchange (/auth, send, verify).
// Apple ties the code request and the code verification together with a session
// cookie; issuing them on separate throwaway sessions makes a correct code come
// back as HTTP 401. 5xx/edge drops are still handled by the retry in
// _performGSADataRequest.
- (NSURLSession *)_twoFactorSession {
    static NSURLSession *session = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSURLSessionConfiguration *config = [NSURLSessionConfiguration defaultSessionConfiguration];
        config.URLCache = nil;
        config.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
        config.timeoutIntervalForRequest = 30.0;
        config.timeoutIntervalForResource = 60.0;
        config.HTTPShouldUsePipelining = NO;
        session = [NSURLSession sessionWithConfiguration:config];
    });
    return session;
}

// Runs a single GSA request on a throwaway socket and retries transient
// failures (network errors and 5xx). The edge drops a keep-alive connection
// after a couple of uses and answers the next request with an HTML 503, so
// every attempt has to start on a fresh connection.
- (void)_performGSADataRequest:(NSMutableURLRequest *)request
                       attempt:(NSUInteger)attempt
                    completion:(void (^)(NSError *error, NSData *data, long httpCode))completionHandler {
    [self _performGSADataRequest:request attempt:attempt session:nil completion:completionHandler];
}

// Same, but on a caller-provided session. A shared session keeps cookies and
// cookies are what tie the 2FA "send code" and "verify code" requests together;
// such a session is owned by the caller and is not invalidated here.
- (void)_performGSADataRequest:(NSMutableURLRequest *)request
                       attempt:(NSUInteger)attempt
                       session:(NSURLSession *)providedSession
                    completion:(void (^)(NSError *error, NSData *data, long httpCode))completionHandler {
    if (!request || !request.URL) {
        completionHandler([self createError:@"The Apple request could not be created" :RPVInternalLoginError], nil, -1);
        return;
    }

    NSString *diagPath = request.URL.path ?: @"?";
    BOOL ownsSession = (providedSession == nil);
    NSURLSession *session = providedSession ?: [self _gsaEphemeralSession];
    NSURLSessionDataTask *task = [session dataTaskWithRequest:request
        completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        if (ownsSession) {
            [session finishTasksAndInvalidate];
        }

        NSHTTPURLResponse *httpResp = [response isKindOfClass:[NSHTTPURLResponse class]] ? (NSHTTPURLResponse *)response : nil;
        long httpCode = httpResp ? (long)httpResp.statusCode : -1;

        void (^retry)(void) = ^{
            NSTimeInterval delay = attempt == 0 ? 1.5 : (attempt == 1 ? 3.0 : 6.0);
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC)),
                           dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                [self _performGSADataRequest:request attempt:attempt + 1 session:providedSession completion:completionHandler];
            });
        };

        if (error) {
            if (attempt < 3 && [self _isRetryableNSURLError:error]) {
                NSLog(@"[DIAG] GSA %@ network error %ld, retry %lu", diagPath, (long)error.code, (unsigned long)(attempt + 1));
                retry();
                return;
            }
            completionHandler(error, nil, httpCode);
            return;
        }

        if (attempt < 3 && [self _isRetryableGSAStatus:httpCode]) {
            NSLog(@"[DIAG] GSA %@ HTTP=%ld retryable, retry %lu", diagPath, httpCode, (unsigned long)(attempt + 1));
            retry();
            return;
        }

        completionHandler(nil, data, httpCode);
    }];
    [task resume];
}


- (void)makeRequestWithParameters:(NSDictionary*)params completion:(void (^)(NSError *err, NSDictionary *response))completionHandler {
    [self _makeRequestWithParameters:params attempt:0 completion:completionHandler];
}

- (void)_retryGSAParameters:(NSDictionary*)params attempt:(NSUInteger)attempt completion:(void (^)(NSError *err, NSDictionary *response))completionHandler {
    NSTimeInterval delay = attempt == 0 ? 1.5 : (attempt == 1 ? 3.0 : 6.0);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC)),
                   dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [self _makeRequestWithParameters:params attempt:attempt + 1 completion:completionHandler];
    });
}

- (void)_makeRequestWithParameters:(NSDictionary*)params attempt:(NSUInteger)attempt completion:(void (^)(NSError *err, NSDictionary *response))completionHandler {
    NSString *internalEndpoint = @"https://gsa.apple.com/grandslam/GsService2";
    
    NSDictionary *defaultHeaders = [self defaultRequestHeaders];

    NSDictionary *requestBody = @{
        @"Header": @{
            @"Version": @"1.0.1"
        },
        @"Request": params
    };

    log_debug("Request Body: %s", requestBody.description.UTF8String);

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:internalEndpoint]];
    request.HTTPMethod = @"POST";
    request.HTTPBody = [NSPropertyListSerialization dataWithPropertyList:requestBody
                                                                  format:NSPropertyListXMLFormat_v1_0
                                                                 options:0
                                                                   error:nil];
    
    [defaultHeaders enumerateKeysAndObjectsUsingBlock:^(id  _Nonnull key, id  _Nonnull obj, BOOL * _Nonnull stop) {
        [request setValue:obj forHTTPHeaderField:key];
    }];
    
    NSURLSession *session = [self _gsaEphemeralSession];
    NSURLSessionTask *task = [session dataTaskWithRequest:request completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        // Retire this connection once the response is in; the next attempt must
        // not inherit a connection the edge already considers spent.
        [session finishTasksAndInvalidate];
        NSHTTPURLResponse *httpResp = [response isKindOfClass:[NSHTTPURLResponse class]] ? (NSHTTPURLResponse *)response : nil;
        long httpCode = httpResp ? (long)httpResp.statusCode : -1;
        NSString *diagAction = request.URL.lastPathComponent ?: @"?";
        
        if (error) {
            if (attempt < 3 && [self _isRetryableNSURLError:error]) {
                NSLog(@"[DIAG] GSA %@ network error %ld, retry %lu", diagAction, (long)error.code, (unsigned long)(attempt + 1));
                [self _retryGSAParameters:params attempt:attempt completion:completionHandler];
                return;
            }
            completionHandler(error, nil);
        } else if (!data) {
            completionHandler(nil, nil);
        } else {
            NSDictionary *response = [NSPropertyListSerialization propertyListWithData:data
                                                                               options:0
                                                                                format:nil
                                                                                 error:nil];
            NSDictionary *packedResponse = [response objectForKey:@"Response"];
            NSLog(@"[DIAG] GSA %@ HTTP=%ld bytes=%lu parsed=%@", diagAction, httpCode, (unsigned long)data.length, packedResponse ? @"YES" : @"NO");
            {
                NSDictionary *statusDict = [packedResponse isKindOfClass:[NSDictionary class]]
                    ? [packedResponse objectForKey:@"Status"] : nil;
                BOOL hasStatus = [statusDict isKindOfClass:[NSDictionary class]];
                RPV2FAWriteLog([NSString stringWithFormat:@"gsa %@ HTTP=%ld bytes=%lu ec=%@ em=%@ au=%@ keys=%@",
                                [params objectForKey:@"o"] ?: @"?",
                                httpCode,
                                (unsigned long)data.length,
                                hasStatus ? ([statusDict objectForKey:@"ec"] ?: @"-") : @"-",
                                hasStatus ? ([statusDict objectForKey:@"em"] ?: @"-") : @"-",
                                hasStatus ? ([statusDict objectForKey:@"au"] ?: @"-") : @"-",
                                [packedResponse isKindOfClass:[NSDictionary class]]
                                    ? [[[packedResponse allKeys] sortedArrayUsingSelector:@selector(compare:)] componentsJoinedByString:@","]
                                    : @"-"]);
            }
            if ([packedResponse isKindOfClass:[NSDictionary class]]) {
                NSDictionary *st = [packedResponse objectForKey:@"Status"];
                if ([st isKindOfClass:[NSDictionary class]]) {
                    NSLog(@"[DIAG]   Status ec=%@ em=%@ au=%@ hsc=%@", [st objectForKey:@"ec"], [st objectForKey:@"em"], [st objectForKey:@"au"], [st objectForKey:@"hsc"]);
                }
                NSLog(@"[DIAG]   keys=%@", [[[packedResponse allKeys] sortedArrayUsingSelector:@selector(compare:)] componentsJoinedByString:@","]);
            } else if (data.length > 0) {
                NSString *rawBody = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                if (!rawBody) rawBody = [[NSString alloc] initWithData:data encoding:NSISOLatin1StringEncoding];
                if (rawBody.length > 800) rawBody = [rawBody substringToIndex:800];
                NSLog(@"[DIAG]   raw=%@", rawBody);
            }
            
            log_debug("Response: %s", packedResponse.description.UTF8String);
            
            if (!packedResponse && (httpCode < 200 || httpCode >= 300)) {
                if (attempt < 3 && [self _isRetryableGSAStatus:httpCode]) {
                    NSLog(@"[DIAG] GSA %@ HTTP=%ld retryable, retry %lu", diagAction, httpCode, (unsigned long)(attempt + 1));
                    [self _retryGSAParameters:params attempt:attempt completion:completionHandler];
                    return;
                }
                NSString *msg = [NSString stringWithFormat:@"Apple server returned HTTP %ld for %@", httpCode, diagAction];
                completionHandler([self createError:msg :(int)httpCode], nil);
                return;
            }
            completionHandler(nil, packedResponse);
        }
        
    }];
    [task resume];
}

- (void)initialiseLookup:(void (^)(NSError*))completion {
    if (self.lookupURLs) {
        dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            completion(nil);
        });
        return;
    }
    
    NSURL *URL = [NSURL URLWithString:@"https://gsa.apple.com/grandslam/GsService2/lookup"];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:URL];
    
    log_debug("Doing lookup");
    
    // Sort out headers
    NSMutableDictionary<NSString *, NSString *> *httpHeaders = [@{
        @"Content-Type": @"text/x-xml-plist",
        @"User-Agent": RPVGrandSlamUserAgent,
        @"Accept": @"text/x-xml-plist",
        @"Accept-Language": @"en-us",
        @"X-Apple-App-Info": @"com.apple.gs.xcode.auth",
        @"X-Xcode-Version": RPVGrandSlamXcodeVersion,
    } mutableCopy];
    
    [httpHeaders addEntriesFromDictionary:[self _anisetteData]];
    [httpHeaders addEntriesFromDictionary:[self _deviceData]];
    
    [httpHeaders enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSString *value, BOOL *stop) {
        [request setValue:value forHTTPHeaderField:key];
    }];
    
    log_debug("Request Headers: %s", httpHeaders.description.UTF8String);
    
    // Do the request on a throwaway connection: the edge retires a keep-alive
    // connection after two requests, and complete/apptokens must not inherit
    // the one this lookup used.
    NSURLSession *session = [self _gsaEphemeralSession];
    NSURLSessionDataTask *task = [session dataTaskWithRequest:request
        completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        [session finishTasksAndInvalidate];
        
        log_debug("Response code: %ld", (long)[(NSHTTPURLResponse*)response statusCode]);
        
        if (!data || error) {
            completion(error);
        } else {
            // Parse the response
            NSError *parseError;
            NSDictionary *responseDictionary = [NSPropertyListSerialization propertyListWithData:data options:0 format:nil error:&parseError];
            
            if (responseDictionary) {
                log_debug("Reponse: %s", responseDictionary.description.UTF8String);
                
                self.lookupURLs = [responseDictionary objectForKey:@"urls"];
            }
            
            dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                completion(nil);
            });
        }
    }];
    [task resume];
}

#pragma mark API

- (void)loginWithUsername:(NSString*)username password:(NSString*)password completion:(RPVLoginResultBlock)completionHandler {
    if (username.length == 0 || password.length == 0) {
        NSLog(@"[DIAG] loginWithUsername: missing credentials userLen=%lu pwdLen=%lu", (unsigned long)username.length, (unsigned long)password.length);
        completionHandler([self createError:@"Missing username or password" :RPVInternalLoginError], nil, nil, nil);
        return;
    }

    // A fresh manual sign-in may legitimately provision a new ADI identity, but
    // once GrandSlam starts the identity has to stay put or a valid session
    // looks expired. Unpin here, re-pin as soon as the login begins.
    if (!self.anisetteProvider) {
        self.anisetteProvider = [[RPVRemoteAnisetteProvider alloc] init];
    }
    self.anisetteProvider.identityPinned = NO;
    @synchronized (self) { RPVAnisetteHeaders = nil; RPVAnisetteFetchedAt = nil; }
    
    // Ensure lookup URLs are populated first
    [self initialiseLookup:^(NSError *error) {
        if (error) {
            completionHandler(error, nil, nil, nil);
        } else {
            self.anisetteProvider.identityPinned = YES;
    
            NSMutableDictionary *clientData = @{
                @"bootstrap": @YES,
                @"icscrec": @YES,
                @"loc": NSLocale.currentLocale.localeIdentifier,
                @"pbe": @NO,
                @"prkgen": @YES,
                @"svct": @"iCloud",
            }.mutableCopy;
            [clientData addEntriesFromDictionary:[self _anisetteData]];
            [clientData addEntriesFromDictionary:[self _deviceData]];

            ccsrp_const_gp_t gp = ccsrp_gp_rfc5054_2048();
            
            const struct ccdigest_info *di_info = ccsha256_di();
            struct ccdigest_ctx *di_ctx = (struct ccdigest_ctx *)malloc(ccdigest_di_size(di_info));
            ccdigest_init(di_info, di_ctx);
            
            // MARK: AppleIDAuthSupport`stateClientNeg1
            
            const struct ccdigest_info *srp_di = ccsha256_di();
            struct ccsrp_ctx *srp_ctx = (struct ccsrp_ctx *)malloc(ccsrp_sizeof_srp(di_info, gp));
            ccsrp_ctx_init(srp_ctx, srp_di, gp);
            ccsrp_client_set_noUsernameInX(srp_ctx, true);
            SRP_RNG(srp_ctx) = ccrng(NULL);

            NSArray<NSString *> *ps = @[@"s2k", @"s2k_fo"];
            for (int i = 0; i < ps.count; i++) {
                addStringToNegProt(di_info, di_ctx, ps[i].UTF8String);
                if (i != ps.count - 1) addStringToNegProt(di_info, di_ctx, ",");
            }

            size_t A_size = ccsrp_exchange_size(srp_ctx);
            char A_bytes[A_size];
            ccsrp_client_start_authentication(srp_ctx, ccDRBGGetRngState(), A_bytes);

            NSData *AData = [NSData dataWithBytes:A_bytes length:A_size];

            addStringToNegProt(di_info, di_ctx, "|");
            
            // Initial request to GSA
            
            dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
            __block NSDictionary *initResponse = nil;
            [self makeRequestWithParameters:@{
                @"A2k": AData,
                @"ps": ps,
                @"cpd": clientData,
                @"u": username,
                @"o": @"init"
            } completion:^(NSError *err, NSDictionary *response) {
                if (response) {
                    initResponse = response;
                } else {
                    completionHandler(err, nil, nil, nil);
                }
                
                dispatch_semaphore_signal(semaphore);
            }];
            dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
            
            // Handle response
            if (!initResponse) {
                return;
            }
            
            NSDictionary *initialResponseStatus = [initResponse objectForKey:@"Status"];
            if ([initialResponseStatus objectForKey:@"ec"] &&
                [[initialResponseStatus objectForKey:@"ec"] intValue] != 0) {
                // Error during request
                NSError *responseError = [self createError:[initialResponseStatus objectForKey:@"em"]
                                                          :[[initialResponseStatus objectForKey:@"ec"] intValue]];
                completionHandler(responseError, nil, nil, nil);
                return;
            }

            // MARK: AppleIDAuthSupport`stateClientNeg2
            // Generate the password key with the salt and interations requested by GSA

            size_t M_len = ccsrp_get_session_key_length(srp_ctx);
            char M_buf[M_len];

            NSString *respSP = initResponse[@"sp"];
            BOOL isS2K = [respSP isEqualToString:@"s2k"];
            addStringToNegProt(di_info, di_ctx, "|");
            if (respSP) addStringToNegProt(di_info, di_ctx, respSP.UTF8String);

            NSString *respC = initResponse[@"c"];
            NSData *respSalt = initResponse[@"s"];
            NSNumber *respIterations = initResponse[@"i"];
            NSData *bData = initResponse[@"B"];

            NSData *passKey = PBKDF2SRP(di_info, !isS2K, password, respSalt, respIterations);
            if (!passKey) {
                log_error("Could not generate password key!");
                NSError *error = [self createError:@"Could not generate password key" :RPVInternalLoginError];
                completionHandler(error, nil, nil, nil);
                return;
            }

            int result = ccsrp_client_process_challenge(srp_ctx,
                                                        username.UTF8String,
                                                        passKey.length, passKey.bytes,
                                                        respSalt.length, respSalt.bytes,
                                                        bData.bytes,
                                                        M_buf);
            if (result != 0) {
                log_error("Could not process challenge!");
                NSError *error = [self createError:@"Could not process challenge" :RPVInternalLoginError];
                completionHandler(error, nil, nil, nil);
                return;
            }

            NSData *MData = [NSData dataWithBytes:M_buf length:M_len];
            
            
            // 'Complete' response to GSA
            semaphore = dispatch_semaphore_create(0);
            __block NSDictionary *completeResponse = nil;
            [self makeRequestWithParameters:@{
                @"c": respC,
                @"M1": MData,
                @"cpd": clientData,
                @"u": username,
                @"o": @"complete"
            } completion:^(NSError *err, NSDictionary *response) {
                if (response) {
                    completeResponse = response;
                } else {
                    completionHandler(err, nil, nil, nil);
                }
                
                dispatch_semaphore_signal(semaphore);
            }];
            dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
            
            // Handle 'complete' response
            if (!completeResponse) {
                return;
            }
            
            NSDictionary *completeResponseStatus = [completeResponse objectForKey:@"Status"];
            NSInteger completeStatusCode = [[completeResponseStatus objectForKey:@"ec"] integerValue];
            NSString *outerAuthenticationMode = [completeResponseStatus objectForKey:@"au"];
            RPV2FAWriteLog([NSString stringWithFormat:@"login complete ec=%ld em=%@ au=%@", (long)completeStatusCode, [completeResponseStatus objectForKey:@"em"] ?: @"-", outerAuthenticationMode ?: @"-"]);
            BOOL outerResponseRequiresTwoFactor = outerAuthenticationMode.length > 0 || completeStatusCode == 409;
            if ([completeResponseStatus objectForKey:@"ec"] &&
                completeStatusCode != 0) {
                // Don't error out just yet if 2FA has been requested
                // We need the idms token for that to be handled correctly

                if (outerResponseRequiresTwoFactor) {
                    // Ignore the error for now, because authentication is still required
                } else {
                    NSString *message = [completeResponseStatus objectForKey:@"em"] ?: @"Apple rejected the authentication request";
                    NSError *responseError = [self createError:message :(int)completeStatusCode];
                    completionHandler(responseError, nil, nil, nil);
                    return;
                }
            }

            // MARK: AppleIDAuthSupport`stateClientNeg3

            NSData *M2Data = completeResponse[@"M2"];
            if (!M2Data) {
                log_error("Missing M2 data!");
                NSError *error = [self createError:@"Missing M2 data" :RPVInternalLoginError];
                completionHandler(error, nil, nil, nil);
                return;
            }
            size_t data_len = M2Data.length;
            if (data_len != ccsrp_get_session_key_length(srp_ctx)) {
                log_error("Invalid M2 len!");
                NSError *error = [self createError:@"Invalid M2 len" :RPVInternalLoginError];
                completionHandler(error, nil, nil, nil);
                return;
            }

            if (!ccsrp_client_verify_session(srp_ctx, M2Data.bytes)) {
                log_error("Could not verify session!");
                NSError *error = [self createError:@"Could not verify session" :RPVInternalLoginError];
                completionHandler(error, nil, nil, nil);
                return;
            }

            addStringToNegProt(di_info, di_ctx, "|");

            NSData *spd = completeResponse[@"spd"];
            if (spd) {
                addDataToNegProt(di_info, di_ctx, spd);
            }
            addStringToNegProt(di_info, di_ctx, "|");

            NSData *sc = completeResponse[@"sc"];
            if (sc) {
                addDataToNegProt(di_info, di_ctx, sc);
            }
            addStringToNegProt(di_info, di_ctx, "|");

            NSData *negProto = completeResponse[@"np"];
            if (!negProto) {
                log_error("Neg proto missing!");
                NSError *error = [self createError:@"Neg proto missing" :RPVInternalLoginError];
                completionHandler(error, nil, nil, nil);
                return;
            }

            size_t digest_len = di_info->output_size;

            if (negProto.length != digest_len) {
                log_error("Neg proto hash too short");
                NSError *error = [self createError:@"Neg proto hash too short" :RPVInternalLoginError];
                completionHandler(error, nil, nil, nil);
                return;
            }

            unsigned char digest[digest_len];
            di_info->final(di_info, di_ctx, digest);

            unsigned char hmac_out[digest_len];
            NSData *hmacKey = createSessionKey(srp_ctx, "HMAC key:");
            cchmac(di_info,
                   hmacKey.length, hmacKey.bytes,
                   digest_len, digest,
                   hmac_out);

            if (cc_cmp_safe(digest_len, hmac_out, negProto.bytes)) {
                log_error("Invalid neg prot hmac!");
                NSError *error = [self createError:@"Invalid neg prot hmac" :RPVInternalLoginError];
                completionHandler(error, nil, nil, nil);
                return;
            }

            NSData *decrypted = decryptCBC(srp_ctx, spd);
            if (!decrypted) {
                log_error("Could not decrypt login response!");
                NSError *error = [self createError:@"Could not decrypt login response" :RPVInternalLoginError];
                completionHandler(error, nil, nil, nil);
                return;
            }
            NSDictionary *decryptedDict = [NSPropertyListSerialization propertyListWithData:decrypted options:0 format:nil error:nil];
            if (!decryptedDict) {
                log_error("Could not parse decrypted login response plist!");
                NSError *error = [self createError:@"Could not parse decrypted login response plist" :RPVInternalLoginError];
                completionHandler(error, nil, nil, nil);
                return;
            }

            // MARK: AppleIDAuthSupport`AppleIDAuthSupportCopyAppTokensOptions

            NSString *adsid = decryptedDict[@"adsid"];
            NSString *acname = decryptedDict[@"acname"];
            NSString *idmsToken = decryptedDict[@"GsIdmsToken"];

            if (adsid.length == 0 || idmsToken.length == 0) {
                NSError *error = [self createError:@"Apple returned an incomplete authentication session"
                                                   :RPVInternalLoginError];
                completionHandler(error, nil, nil, nil);
                return;
            }

            // Some responses omit acname; use the SRP username as the fallback.
            NSString *accountName = acname.length > 0 ? acname : username;
            NSString *altDSID = [NSString stringWithFormat:@"%@|%@", adsid, accountName];

            log_debug("IDMS Token: %s", idmsToken.UTF8String);

            // Apple may describe 2FA in either the outer or decrypted response.
            NSInteger decryptedStatusCode = [decryptedDict[@"status-code"] integerValue];
            NSString *decryptedAuthenticationMode = [decryptedDict[@"url"] isKindOfClass:[NSString class]]
                ? decryptedDict[@"url"]
                : nil;
            BOOL requiresTwoFactor = outerResponseRequiresTwoFactor || decryptedStatusCode == 409;

            // At this point, check if 2FA is required. If so, return with the idms token and adsid
            if (requiresTwoFactor) {
                NSString *authenticationMode = outerAuthenticationMode.length > 0
                    ? outerAuthenticationMode
                    : decryptedAuthenticationMode;

                int mode = [authenticationMode isEqualToString:@"trustedDeviceSecondaryAuth"] || authenticationMode.length == 0 ?
                    RPVInternalLogin2FARequiredTrustedDeviceError :
                    RPVInternalLogin2FARequiredSecondaryAuthError;

                // Keep the session that asked for 2FA. Once the code is accepted
                // Apple lets this session through, so it is the only context that
                // can be exchanged for a token without another 2FA prompt.
                self.pendingTwoFactorSessionKey = decryptedDict[@"sk"];
                self.pendingTwoFactorSessionC = decryptedDict[@"c"];
                self.pendingTwoFactorIdmsToken = idmsToken;
                self.pendingTwoFactorADSID = adsid;
                self.pendingTwoFactorIdentity = altDSID;
                self.pendingTwoFactorClientData = clientData;

                NSString *message = [completeResponseStatus objectForKey:@"em"] ?: @"Two-factor authentication is required";
                NSError *responseError = [self createError:message :mode];
                RPV2FAWriteLog([NSString stringWithFormat:@"login 2FA required mode=%d sk=%lu c=%lu", mode,
                                (unsigned long)self.pendingTwoFactorSessionKey.length,
                                (unsigned long)self.pendingTwoFactorSessionC.length]);

                completionHandler(responseError, altDSID, nil, idmsToken);
            } else {
                // A session that did not ask for 2FA has no pending context.
                self.pendingTwoFactorSessionKey = nil;
                self.pendingTwoFactorSessionC = nil;
                self.pendingTwoFactorIdmsToken = nil;
                self.pendingTwoFactorADSID = nil;
                self.pendingTwoFactorIdentity = nil;
                self.pendingTwoFactorClientData = nil;

                [self _requestAppTokensWithSessionKey:decryptedDict[@"sk"]
                                            sessionC:decryptedDict[@"c"]
                                           idmsToken:idmsToken
                                                adsid:adsid
                                                 apps:@[@"com.apple.gs.xcode.auth"]
                                           clientData:clientData
                                           completion:^(NSError *tokenError, NSString *token) {
                    if (tokenError) {
                        RPV2FAWriteLog([NSString stringWithFormat:@"login apptokens failed em=%@", tokenError.localizedDescription ?: @"-"]);
                    } else {
                        RPV2FAWriteLog(@"login apptokens ok");
                    }
                    completionHandler(tokenError, altDSID, token, nil);
                }];
            }
        }
    }];
}

// Exchanges a completed SRP session for an Xcode services token. Split out of
// loginWithUsername so the two-factor flow can reuse the session Apple already
// verified instead of starting a fresh login, which would ask for 2FA again.
- (void)_requestAppTokensWithSessionKey:(NSData *)sessionKey
                               sessionC:(NSData *)sessionC
                              idmsToken:(NSString *)idmsToken
                                   adsid:(NSString *)adsid
                                    apps:(NSArray<NSString *> *)apps
                              clientData:(NSDictionary *)clientData
                              completion:(void (^)(NSError *error, NSString *token))completionHandler {
    if (sessionKey.length == 0 || sessionC.length == 0 || idmsToken.length == 0 || adsid.length == 0) {
        completionHandler([self createError:@"The Apple authentication session is incomplete" :RPVInternalLoginError], nil);
        return;
    }

    NSString *app = apps.firstObject;
    NSData *checksum = createAppTokensChecksum(sessionKey, adsid, apps);

    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    __block NSDictionary *tokensResponse = nil;
    [self makeRequestWithParameters:@{
        @"u": adsid,
        @"app": apps,
        @"c": sessionC,
        @"t": idmsToken,
        @"checksum": checksum,
        @"cpd": clientData ?: @{},
        @"o": @"apptokens"
    } completion:^(NSError *err, NSDictionary *response) {
        if (response) {
            tokensResponse = response;
        } else {
            completionHandler(err, nil);
        }
        dispatch_semaphore_signal(semaphore);
    }];
    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);

    if (!tokensResponse) {
        return;
    }

    NSDictionary *status = [tokensResponse objectForKey:@"Status"];
    if ([status objectForKey:@"ec"] && [[status objectForKey:@"ec"] intValue] != 0) {
        NSString *message = [status objectForKey:@"em"] ?: @"Apple rejected the token request";
        RPV2FAWriteLog([NSString stringWithFormat:@"apptokens ec=%@ em=%@", [status objectForKey:@"ec"], message]);
        completionHandler([self createError:message :[[status objectForKey:@"ec"] intValue]], nil);
        return;
    }

    NSData *decryptedToken = decryptGCM(sessionKey, tokensResponse[@"et"]);
    NSDictionary *decryptedTokDict = decryptedToken
        ? [NSPropertyListSerialization propertyListWithData:decryptedToken options:0 format:nil error:nil]
        : nil;
    if (![decryptedTokDict isKindOfClass:[NSDictionary class]]) {
        completionHandler([self createError:@"Could not read the app token Apple returned" :RPVInternalLoginError], nil);
        return;
    }

    NSString *token = decryptedTokDict[@"t"][app][@"token"];
    RPV2FAWriteLog([NSString stringWithFormat:@"apptokens ok tokenLen=%lu", (unsigned long)token.length]);
    if (token.length > 0) {
        // Remember which machine minted this token so a later launch can tell
        // whether the anisette server still reports the same identity.
        NSString *deviceId = RPVAnisetteHeaders[@"X-Mme-Device-Id"];
        if (deviceId.length > 0) {
            @synchronized (self) { RPVTokenMintingDeviceId = deviceId; }
            [[NSUserDefaults standardUserDefaults] setObject:deviceId
                                                      forKey:@"RPVTokenMintingDeviceId"];
            RPV2FAWriteLog([NSString stringWithFormat:@"token minted by device=%@", deviceId]);
        }
    }
    completionHandler(nil, token);
}

// After the verification code is accepted, mint a token from the session that
// requested 2FA. Callers fall back to a fresh login if this returns an error.
- (void)fetchAppTokenForPendingTwoFactorSessionWithCompletion:(void (^)(NSError *error, NSString *userIdentity, NSString *gsToken))completion {
    NSData *sessionKey = self.pendingTwoFactorSessionKey;
    NSData *sessionC = self.pendingTwoFactorSessionC;
    NSString *idmsToken = self.pendingTwoFactorIdmsToken;
    NSString *adsid = self.pendingTwoFactorADSID;
    NSString *identity = self.pendingTwoFactorIdentity;
    NSDictionary *clientData = self.pendingTwoFactorClientData;

    if (sessionKey.length == 0 || sessionC.length == 0 || idmsToken.length == 0 || adsid.length == 0) {
        completion([self createError:@"The Apple authentication session is incomplete" :RPVInternalLoginError], nil, nil);
        return;
    }

    RPV2FAWriteLog([NSString stringWithFormat:@"apptokens pending sk=%lu c=%lu adsid=%.6s",
                    (unsigned long)sessionKey.length, (unsigned long)sessionC.length, adsid.UTF8String ?: ""]);

    [self _requestAppTokensWithSessionKey:sessionKey
                                sessionC:sessionC
                               idmsToken:idmsToken
                                    adsid:adsid
                                     apps:@[@"com.apple.gs.xcode.auth"]
                               clientData:clientData
                               completion:^(NSError *error, NSString *token) {
        if (error || token.length == 0) {
            completion(error ?: [self createError:@"Apple did not return an app token" :RPVInternalLoginError], nil, nil);
            return;
        }
        completion(nil, identity, token);
    }];
}

// Apple lists the trusted phone numbers for the account at /auth. Read the
// first one together with its delivery mode so a code can be sent to it.
- (void)_checkAuthEndpointWithUserIdentity:(NSString*)userIdentity idmsToken:(NSString*)token andCompletion:(void (^)(NSError *error, NSDictionary *phoneDescriptor))completionHandler {

    NSString *secondaryAuthURL = self.lookupURLs[@"secondaryAuth"];
    NSURL *URL = secondaryAuthURL.length > 0 ? [NSURL URLWithString:secondaryAuthURL]
                                             : [NSURL URLWithString:@"https://gsa.apple.com/auth"];

    // The trusted-phone endpoints negotiate JSON, not plist. Asking for
    // text/x-xml-plist makes Apple answer 200 with a body that is not a plist,
    // which then reads as an "unreadable" number list.
    NSMutableURLRequest *request = [self _twoFactorJSONRequestWithURL:URL
                                                         userIdentity:userIdentity
                                                            idmsToken:token];
    if (!request) {
        completionHandler([self createError:@"The Apple authentication session is incomplete" :RPVInternalLoginError], nil);
        return;
    }

    log_debug("Request to: %s", URL.description.UTF8String);

    [self _performGSADataRequest:request attempt:0 session:[self _twoFactorSession] completion:^(NSError *error, NSData *data, long httpCode) {
        NSLog(@"[DIAG] /auth HTTP=%ld bytes=%lu", httpCode, (unsigned long)data.length);
        RPV2FAWriteLog([NSString stringWithFormat:@"/auth HTTP=%ld bytes=%lu err=%@", httpCode, (unsigned long)data.length, error.localizedDescription ?: @"none"]);
        {
            NSString *md = request.allHTTPHeaderFields[@"X-Apple-I-MD"] ?: @"";
            NSString *mdm = request.allHTTPHeaderFields[@"X-Apple-I-MD-M"] ?: @"";
            NSString *tok = request.allHTTPHeaderFields[@"X-Apple-Identity-Token"] ?: @"";
            RPV2FAWriteLog([NSString stringWithFormat:@"/auth anisette MD=%.6s MDM=%.6s tokLen=%lu", md.UTF8String ?: "", mdm.UTF8String ?: "", (unsigned long)tok.length]);
        }

        if (error) {
            completionHandler(error, nil);
            return;
        }

        if (data.length == 0) {
            completionHandler([self createError:[NSString stringWithFormat:@"Apple returned an empty trusted number list (HTTP %ld)", httpCode] :RPVInternalLoginError], nil);
            return;
        }

        // The endpoint answers with a plist on older iOS and JSON on newer. The
        // root may be a dictionary or, depending on the account, a top-level
        // array of number objects, so accept both.
        id object = [NSPropertyListSerialization propertyListWithData:data options:0 format:nil error:nil];
        if (![object isKindOfClass:[NSDictionary class]] && ![object isKindOfClass:[NSArray class]]) {
            object = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        }
        if (![object isKindOfClass:[NSDictionary class]] && ![object isKindOfClass:[NSArray class]]) {
            // Apple answered with something else (typically an HTML page). Surface
            // a slice of it so the cause is visible in the log.
            NSString *raw = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (!raw) raw = [[NSString alloc] initWithData:data encoding:NSISOLatin1StringEncoding];
            NSString *rawFull = raw.length > 2000 ? [raw substringToIndex:2000] : raw;
            RPV2FAWriteLog([NSString stringWithFormat:@"/auth unparseable HTTP=%ld raw=%@", httpCode, rawFull ?: @"(non-text)"]);
            if (raw.length > 500) raw = [raw substringToIndex:500];
            NSLog(@"[DIAG] /auth unparseable HTTP=%ld raw=%@", httpCode, raw ?: @"(non-text)");
            completionHandler([self createError:[NSString stringWithFormat:@"Apple returned an unreadable list of trusted numbers (HTTP %ld). %@", httpCode, raw ?: @""] :RPVInternalLoginError], nil);
            return;
        }
        NSLog(@"[DIAG] /auth parsed root=%@", [object isKindOfClass:[NSArray class]] ? @"array" : @"dict");

        log_debug("Reponse: %s", ((NSObject *)object).description.UTF8String);

        // Even with HTTP 200 Apple may answer with an error payload (ec/code or
        // Status.ec). Surface its message instead of pretending the list is empty.
        if ([object isKindOfClass:[NSDictionary class]]) {
            NSDictionary *dict = (NSDictionary *)object;
            NSDictionary *status = [dict[@"Status"] isKindOfClass:[NSDictionary class]] ? dict[@"Status"] : nil;
            id rawCode = dict[@"ec"] ?: dict[@"code"] ?: status[@"ec"];
            NSInteger code = [rawCode respondsToSelector:@selector(integerValue)] ? [rawCode integerValue] : 0;
            if (code != 0) {
                NSString *message = dict[@"em"] ?: dict[@"message"];
                if (![message isKindOfClass:[NSString class]] || message.length == 0) {
                    message = [NSString stringWithFormat:@"Apple rejected the request (code %ld)", (long)code];
                }
                NSLog(@"[DIAG] /auth error code=%ld message=%@", (long)code, message);
                RPV2FAWriteLog([NSString stringWithFormat:@"/auth error code=%ld message=%@", (long)code, message]);
                completionHandler([self createError:message :(int)code], nil);
                return;
            }
        }

        NSDictionary *descriptor = [self _phoneDescriptorFromAuthResponse:object];
        if (descriptor.count == 0) {
            // No number found: dump the top-level keys (or first elements) so the
            // actual structure is visible when a real number list is expected.
            if ([object isKindOfClass:[NSDictionary class]]) {
                NSArray *keys = [[object allKeys] sortedArrayUsingSelector:@selector(compare:)];
                NSLog(@"[DIAG] /auth no number, keys=%@", keys);
                RPV2FAWriteLog([NSString stringWithFormat:@"/auth no number, keys=%@", keys]);
            } else if ([object isKindOfClass:[NSArray class]] && ((NSArray *)object).count > 0) {
                NSLog(@"[DIAG] /auth no number, first=%@", [object[0] description]);
                RPV2FAWriteLog([NSString stringWithFormat:@"/auth no number, first=%@", [object[0] description]]);
            }
            completionHandler([self createError:@"This Apple ID has no trusted phone number that can receive a code." :RPVInternalLoginError], nil);
            return;
        }
        RPV2FAWriteLog([NSString stringWithFormat:@"/auth ok id=%@ mode=%@", descriptor[@"id"], descriptor[@"mode"]]);
        completionHandler(nil, descriptor);
    }];
}

// Collects every dictionary that looks like a trusted phone number (has a usable
// id) from anywhere in the parsed /auth response, then returns the first one
// together with its delivery mode. Handles a dictionary root, a top-level array
// root, and arbitrary nesting under Response / serverInfo / trustedPhoneNumbers.
- (NSDictionary *)_phoneDescriptorFromAuthResponse:(id)response {
    NSMutableArray<NSDictionary *> *candidates = [NSMutableArray array];
    [self _collectPhoneCandidates:response into:candidates];

    // Prefer a candidate that also carries a number; fall back to the first one
    // that only has an id. This avoids mistaking a random id-bearing object for
    // a phone number when the response nests other entities.
    NSDictionary *pick = nil;
    for (NSDictionary *candidate in candidates) {
        NSString *number = candidate[@"numberWithDialCode"] ?: candidate[@"obfuscatedNumber"] ?: candidate[@"number"];
        if ([number isKindOfClass:[NSString class]] && number.length > 0) {
            pick = candidate;
            break;
        }
    }
    if (!pick && candidates.count > 0) {
        pick = candidates[0];
    }

    if (!pick) {
        return @{};
    }

    id rawIdentifier = pick[@"id"] ?: pick[@"phoneNumber.id"];
    NSString *identifier = [rawIdentifier respondsToSelector:@selector(stringValue)]
        ? [rawIdentifier stringValue]
        : ([rawIdentifier isKindOfClass:[NSString class]] ? rawIdentifier : nil);
    if (identifier.length == 0) {
        return @{};
    }

    NSString *rawMode = pick[@"pushMode"] ?: pick[@"mode"];
    NSString *mode = [rawMode.lowercaseString isEqualToString:@"voice"] ? @"voice" : @"sms";

    NSString *number = pick[@"numberWithDialCode"] ?: pick[@"obfuscatedNumber"] ?: pick[@"number"];
    NSLog(@"[DIAG] trusted number id=%@ mode=%@ number=%@", identifier, mode, [number isKindOfClass:[NSString class]] ? number : @"-");

    return @{
        @"id": identifier,
        @"mode": mode,
        @"number": [number isKindOfClass:[NSString class]] ? number : @"",
    };
}

// Walks dictionaries and arrays; any dictionary carrying a non-empty id is a
// phone-number candidate. Nesting is traversed fully so no number is missed.
- (void)_collectPhoneCandidates:(id)node into:(NSMutableArray *)out {
    if ([node isKindOfClass:[NSDictionary class]]) {
        NSDictionary *dict = (NSDictionary *)node;
        id rawId = dict[@"id"] ?: dict[@"phoneNumber.id"];
        NSString *identifier = [rawId respondsToSelector:@selector(stringValue)]
            ? [rawId stringValue]
            : ([rawId isKindOfClass:[NSString class]] ? rawId : nil);
        if (identifier.length > 0) {
            [out addObject:dict];
        }
        for (id value in [dict allValues]) {
            [self _collectPhoneCandidates:value into:out];
        }
    } else if ([node isKindOfClass:[NSArray class]]) {
        for (id item in (NSArray *)node) {
            [self _collectPhoneCandidates:item into:out];
        }
    }
}

// Finds Apple's error code/message anywhere in a response body. Prefers
// service_errors entries, then ec/code with em/message.
- (BOOL)_scanErrorNode:(id)node code:(NSInteger *)code message:(NSString **)message {
    if ([node isKindOfClass:[NSArray class]]) {
        for (id item in (NSArray *)node) {
            if ([self _scanErrorNode:item code:code message:message]) {
                return YES;
            }
        }
        return NO;
    }
    if (![node isKindOfClass:[NSDictionary class]]) {
        return NO;
    }

    NSDictionary *dict = (NSDictionary *)node;
    id serviceErrors = dict[@"service_errors"] ?: dict[@"serviceErrors"];
    if ([serviceErrors isKindOfClass:[NSArray class]]) {
        for (id item in (NSArray *)serviceErrors) {
            if ([self _scanErrorNode:item code:code message:message]) {
                return YES;
            }
        }
    }

    id rawCode = dict[@"ec"] ?: dict[@"code"];
    if ([rawCode respondsToSelector:@selector(integerValue)] && [rawCode integerValue] != 0) {
        *code = [rawCode integerValue];
        id rawMessage = dict[@"em"] ?: dict[@"message"] ?: dict[@"userString"] ?: dict[@"title"];
        if ([rawMessage isKindOfClass:[NSString class]] && [rawMessage length] > 0) {
            *message = rawMessage;
        }
        return YES;
    }

    for (id value in [dict allValues]) {
        if ([value isKindOfClass:[NSDictionary class]] || [value isKindOfClass:[NSArray class]]) {
            if ([self _scanErrorNode:value code:code message:message]) {
                return YES;
            }
        }
    }
    return NO;
}

// Sends the verification code. For a trusted-device prompt Apple pushes to the
// device; for a phone number the caller picks sms or voice. The number has to
// be listed first, because the request body must carry its id.
- (void)requestTwoFactorCodeWithUserIdentity:(NSString*)userIdentity idmsToken:(NSString*)token mode:(int)mode andCompletion:(void (^)(NSError *error))completionHandler {
    [self requestTwoFactorCodeWithUserIdentity:userIdentity
                                     idmsToken:token
                                          mode:mode
                                 deliveryMode:nil
                                andCompletion:completionHandler];
}

- (void)requestTwoFactorCodeWithUserIdentity:(NSString*)userIdentity idmsToken:(NSString*)token mode:(int)mode deliveryMode:(NSString *)requestedDeliveryMode andCompletion:(void (^)(NSError *error))completionHandler {

    // Apple reports "trustedDeviceSecondaryAuth" for accounts that can approve a
    // prompt on another device. That prompt never reaches the user here, so when
    // a delivery mode is chosen send the code to the trusted phone number
    // instead, whatever mode Apple reported.
    BOOL useTrustedPhone = requestedDeliveryMode.length > 0 ||
        mode == RPVInternalLogin2FARequiredSecondaryAuthError;

    if (!useTrustedPhone) {
        if (mode != RPVInternalLogin2FARequiredTrustedDeviceError) {
            completionHandler([self createError:@"Apple returned an unsupported two-factor authentication mode" :RPVInternalLoginError]);
            return;
        }

        self.twoFactorPhoneNumberID = nil;
        self.twoFactorPhoneDeliveryMode = nil;
        NSString *trustedDeviceURL = self.lookupURLs[@"trustedDeviceSecondaryAuth"];
        NSURL *URL = trustedDeviceURL.length > 0 ? [NSURL URLWithString:trustedDeviceURL]
                                                : [NSURL URLWithString:@"https://gsa.apple.com/auth/verify/trusteddevice"];

        NSMutableURLRequest *request = [self _twoFactorRequestWithURL:URL
                                                         userIdentity:userIdentity
                                                            idmsToken:token];
        [self _performTwoFactorCodeRequest:request completion:completionHandler];
        return;
    }

    [self _checkAuthEndpointWithUserIdentity:userIdentity idmsToken:token andCompletion:^(NSError *error, NSDictionary *phoneDescriptor) {
        if (error) {
            completionHandler(error);
            return;
        }

        NSString *phoneNumberID = phoneDescriptor[@"id"];
        NSString *deliveryMode = requestedDeliveryMode.length > 0 ? requestedDeliveryMode : phoneDescriptor[@"mode"];
        deliveryMode = [deliveryMode.lowercaseString isEqualToString:@"voice"] ? @"voice" : @"sms";
        self.twoFactorPhoneNumberID = phoneNumberID;
        self.twoFactorPhoneDeliveryMode = deliveryMode;

        NSURL *URL = [NSURL URLWithString:@"https://gsa.apple.com/auth/verify/phone"];
        NSMutableURLRequest *request = [self _twoFactorJSONRequestWithURL:URL
                                                             userIdentity:userIdentity
                                                                idmsToken:token];
        request.HTTPMethod = @"PUT";
        request.HTTPBody = [NSJSONSerialization dataWithJSONObject:@{
            @"phoneNumber": @{ @"id": @([phoneNumberID integerValue]) },
            @"mode": deliveryMode
        } options:0 error:nil];

        NSLog(@"[DIAG] 2FA code request id=%@ mode=%@", phoneNumberID, deliveryMode);
        [self _performTwoFactorCodeRequest:request completion:completionHandler];
    }];
}

- (NSMutableURLRequest *)_twoFactorRequestWithURL:(NSURL *)URL
                                     userIdentity:(NSString *)userIdentity
                                        idmsToken:(NSString *)token {
    NSString *dsid = [userIdentity componentsSeparatedByString:@"|"].firstObject;
    if (dsid.length == 0 || token.length == 0) {
        return nil;
    }

    NSString *identityToken = [NSString stringWithFormat:@"%@:%@", dsid, token];
    NSString *encodedIdentityToken = [[identityToken dataUsingEncoding:NSUTF8StringEncoding]
        base64EncodedStringWithOptions:0];

    NSMutableDictionary<NSString *, NSString *> *headers = [@{
        @"Content-Type": @"text/x-xml-plist",
        @"User-Agent": RPVGrandSlamUserAgent,
        @"Accept": @"text/x-xml-plist",
        @"Accept-Language": @"en-us",
        @"X-Apple-App-Info": @"com.apple.gs.xcode.auth",
        @"X-Apple-Client-App-Name": @"Xcode",
        @"X-Xcode-Version": RPVGrandSlamXcodeVersion,
        @"X-Apple-Identity-Token": encodedIdentityToken,
    } mutableCopy];

    [headers addEntriesFromDictionary:[self _anisetteData]];
    [headers addEntriesFromDictionary:[self _deviceData]];

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:URL];
    [headers enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSString *value, BOOL *stop) {
        [request setValue:value forHTTPHeaderField:key];
    }];
    [request setValue:self.clientInfoOverride forHTTPHeaderField:@"X-MMe-Client-Info"];
    return request;
}

- (NSMutableURLRequest *)_twoFactorJSONRequestWithURL:(NSURL *)URL
                                         userIdentity:(NSString *)userIdentity
                                            idmsToken:(NSString *)token {
    NSMutableURLRequest *request = [self _twoFactorRequestWithURL:URL userIdentity:userIdentity idmsToken:token];
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    [request setValue:@"application/json" forHTTPHeaderField:@"Accept"];
    return request;
}

- (void)_performTwoFactorCodeRequest:(NSMutableURLRequest *)request completion:(void (^)(NSError *error))completionHandler {
    if (!request) {
        completionHandler([self createError:@"The Apple authentication request could not be created" :RPVInternalLoginError]);
        return;
    }

    log_debug("Request to: %s", request.URL.description.UTF8String);

    [self _performGSADataRequest:request attempt:0 session:[self _twoFactorSession] completion:^(NSError *error, NSData *data, long httpCode) {
        NSLog(@"[DIAG] 2FA code request %@ HTTP=%ld bytes=%lu", request.URL.path, httpCode, (unsigned long)data.length);
        RPV2FAWriteLog([NSString stringWithFormat:@"2FA send %@ HTTP=%ld bytes=%lu", request.URL.path, httpCode, (unsigned long)data.length]);
        {
            NSString *md = request.allHTTPHeaderFields[@"X-Apple-I-MD"] ?: @"";
            NSString *mdm = request.allHTTPHeaderFields[@"X-Apple-I-MD-M"] ?: @"";
            NSString *tok = request.allHTTPHeaderFields[@"X-Apple-Identity-Token"] ?: @"";
            RPV2FAWriteLog([NSString stringWithFormat:@"2FA send anisette MD=%.6s MDM=%.6s tokLen=%lu", md.UTF8String ?: "", mdm.UTF8String ?: "", (unsigned long)tok.length]);
        }
        if (data.length > 0) {
            NSString *sendBody = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (!sendBody) sendBody = [[NSString alloc] initWithData:data encoding:NSISOLatin1StringEncoding];
            if (sendBody.length > 1200) sendBody = [sendBody substringToIndex:1200];
            RPV2FAWriteLog([NSString stringWithFormat:@"2FA send body=%@", sendBody ?: @"(non-text)"]);
        }

        if (error) {
            completionHandler(error);
            return;
        }

        if (httpCode >= 200 && httpCode < 300) {
            completionHandler(nil);
            return;
        }

        // Surface what Apple said instead of a bare status code.
        NSString *raw = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        if (raw.length > 300) {
            raw = [raw substringToIndex:300];
        }
        NSLog(@"[DIAG] 2FA code request failed raw=%@", raw);
        completionHandler([self createError:[NSString stringWithFormat:@"Apple did not send a code (HTTP %ld). %@", httpCode, raw ?: @""]
                                           :RPVInternalLoginError]);
    }];
}

- (void)submitTwoFactorCode:(NSString*)code withUserIdentity:(NSString*)userIdentity idmsToken:(NSString*)token andCompletion:(RPVTwoFactorResultBlock)completionHandler {

    // Localized/AutoFill digits must be normalized to ASCII before submission.
    NSString *normalizedCode = RPVNormalizedVerificationCode(code ?: @"");
    if (normalizedCode.length != 6) {
        completionHandler([self createError:@"The verification code must contain exactly six digits"
                                           :RPVInternalLoginInvalid2FAFormatError]);
        return;
    }

    // A code delivered to a phone number is validated against that number;
    // only the on-device prompt uses the GrandSlam validate endpoint.
    if (self.twoFactorPhoneNumberID.length > 0 && self.twoFactorPhoneDeliveryMode.length > 0) {
        [self _submitPhoneVerificationCode:normalizedCode
                              userIdentity:userIdentity
                                 idmsToken:token
                                completion:completionHandler];
        return;
    }

    // Parse the real dsid out of the identity
    NSString *dsid = [userIdentity componentsSeparatedByString:@"|"].firstObject;
    
    NSString *validateCodeURL = self.lookupURLs[@"validateCode"];
    NSURL *URL = validateCodeURL.length > 0 ? [NSURL URLWithString:validateCodeURL]
                                            : [NSURL URLWithString:@"https://gsa.apple.com/grandslam/GsService2/validate"];

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:URL];
    
    log_debug("Request to: %s", URL.description.UTF8String);
    
    NSString *identityToken = [NSString stringWithFormat:@"%@:%@", dsid, token];
    
    NSData *identityTokenData = [identityToken dataUsingEncoding:NSUTF8StringEncoding];
    NSString *encodedIdentityToken = [identityTokenData base64EncodedStringWithOptions:0];
    
    // Sort out headers
    NSMutableDictionary<NSString *, NSString *> *httpHeaders = [@{
        @"security-code": normalizedCode,
        @"Content-Type": @"text/x-xml-plist",
        @"User-Agent": RPVGrandSlamUserAgent,
        @"Accept": @"text/x-xml-plist",
        @"Accept-Language": @"en-us",
        @"X-Apple-App-Info": @"com.apple.gs.xcode.auth",
        @"X-Apple-Client-App-Name": @"Xcode",
        @"X-Xcode-Version": RPVGrandSlamXcodeVersion,
        @"X-Apple-Identity-Token": encodedIdentityToken,
    } mutableCopy];
    
    [httpHeaders addEntriesFromDictionary:[self _anisetteData]];
    [httpHeaders addEntriesFromDictionary:[self _deviceData]];
    
    [httpHeaders enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSString *value, BOOL *stop) {
        [request setValue:value forHTTPHeaderField:key];
    }];
    
    [request setValue:self.clientInfoOverride forHTTPHeaderField:@"X-MMe-Client-Info"];
    
    log_debug("Request Headers: %s", httpHeaders.description.UTF8String);
    
    [self _performGSADataRequest:request attempt:0 completion:^(NSError *error, NSData *data, long httpCode) {
        NSLog(@"[DIAG] validate HTTP=%ld bytes=%lu", httpCode, (unsigned long)data.length);

        if (!data || error) {
            completionHandler(error);
            return;
        }

        // Parse the response
        NSError *parseError;
        NSDictionary *responseDictionary = [NSPropertyListSerialization propertyListWithData:data options:0 format:nil error:&parseError];

        // Handle parse issues
        if (!responseDictionary) {
            NSError *error = [self createError:parseError.localizedDescription :RPVInternalLoginError];
            completionHandler(error);
            return;
        }

        log_debug("Request Reponse: %s", responseDictionary.description.UTF8String);

        NSInteger errorCode = [responseDictionary[@"ec"] integerValue]; // Same for NSString or NSNumber.
        if (errorCode == 0) {
            // Success! However, still need to re-login again
            completionHandler(nil);
        } else if (errorCode == -21669) {
            NSError *error = [self createError:@"Incorrect 2FA code" :RPVInternalLoginIncorrect2FACodeError];
            completionHandler(error);
        } else {
            NSError *responseError = [self createError:[responseDictionary objectForKey:@"em"]
                                                      :[[responseDictionary objectForKey:@"ec"] intValue]];

            completionHandler(responseError);
        }
    }];
}

// Validates a code that Apple delivered to the trusted phone number.
- (void)_submitPhoneVerificationCode:(NSString *)code userIdentity:(NSString *)userIdentity idmsToken:(NSString *)token completion:(RPVTwoFactorResultBlock)completionHandler {
    NSURL *URL = [NSURL URLWithString:@"https://gsa.apple.com/auth/verify/phone/securitycode"];
    NSMutableURLRequest *request = [self _twoFactorJSONRequestWithURL:URL
                                                         userIdentity:userIdentity
                                                            idmsToken:token];
    if (!request) {
        completionHandler([self createError:@"The Apple authentication request could not be created" :RPVInternalLoginError]);
        return;
    }

    request.HTTPMethod = @"POST";
    request.HTTPBody = [NSJSONSerialization dataWithJSONObject:@{
        @"securityCode": @{ @"code": code },
        @"phoneNumber": @{ @"id": @([self.twoFactorPhoneNumberID integerValue]) },
        @"mode": self.twoFactorPhoneDeliveryMode
    } options:0 error:nil];

    NSLog(@"[DIAG] 2FA submit id=%@ mode=%@", self.twoFactorPhoneNumberID, self.twoFactorPhoneDeliveryMode);
    RPV2FAWriteLog([NSString stringWithFormat:@"2FA submit id=%@ mode=%@", self.twoFactorPhoneNumberID, self.twoFactorPhoneDeliveryMode]);

    [self _performGSADataRequest:request attempt:0 session:[self _twoFactorSession] completion:^(NSError *error, NSData *data, long httpCode) {
        NSLog(@"[DIAG] 2FA submit HTTP=%ld bytes=%lu", httpCode, (unsigned long)data.length);
        RPV2FAWriteLog([NSString stringWithFormat:@"2FA submit HTTP=%ld bytes=%lu", httpCode, (unsigned long)data.length]);
        {
            NSString *md = request.allHTTPHeaderFields[@"X-Apple-I-MD"] ?: @"";
            NSString *mdm = request.allHTTPHeaderFields[@"X-Apple-I-MD-M"] ?: @"";
            NSString *tok = request.allHTTPHeaderFields[@"X-Apple-Identity-Token"] ?: @"";
            RPV2FAWriteLog([NSString stringWithFormat:@"2FA submit anisette MD=%.6s MDM=%.6s tokLen=%lu", md.UTF8String ?: "", mdm.UTF8String ?: "", (unsigned long)tok.length]);
        }

        if (error) {
            RPV2FAWriteLog([NSString stringWithFormat:@"2FA submit transport error=%@", error.localizedDescription ?: @"?"]);
            completionHandler(error);
            return;
        }

        // Parse whatever Apple sent so the real reason is reported, not a blanket
        // "incorrect code". Only -21669 actually means the code was wrong.
        id body = [NSPropertyListSerialization propertyListWithData:data options:0 format:nil error:nil];
        if (![body isKindOfClass:[NSDictionary class]] && ![body isKindOfClass:[NSArray class]]) {
            body = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        }
        NSInteger appleCode = 0;
        NSString *appleMessage = nil;
        [self _scanErrorNode:body code:&appleCode message:&appleMessage];

        NSString *raw = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        if (!raw) raw = [[NSString alloc] initWithData:data encoding:NSISOLatin1StringEncoding];
        if (raw.length > 800) raw = [raw substringToIndex:800];
        RPV2FAWriteLog([NSString stringWithFormat:@"2FA submit appleCode=%ld msg=%@ raw=%@", (long)appleCode, appleMessage ?: @"-", raw ?: @"(non-text)"]);
        NSLog(@"[DIAG] 2FA submit appleCode=%ld msg=%@", (long)appleCode, appleMessage ?: @"-");

        if (httpCode >= 200 && httpCode < 300 && appleCode == 0) {
            // Keep the same attestation for the follow-up login. Refreshing it
            // here makes Apple treat the next SRP login as an unknown device and
            // ask for 2FA all over again.
            RPV2FAWriteLog(@"2FA submit accepted, keeping anisette for follow-up login");
            completionHandler(nil);
            return;
        }

        if (appleCode == -21669) {
            completionHandler([self createError:@"Incorrect 2FA code" :RPVInternalLoginIncorrect2FACodeError]);
            return;
        }

        NSString *message = appleMessage.length > 0 ? appleMessage
            : [NSString stringWithFormat:@"Apple could not verify that code (HTTP %ld%@).", httpCode,
               appleCode != 0 ? [NSString stringWithFormat:@" / %ld", (long)appleCode] : @""];
        completionHandler([self createError:message :(int)(appleCode ?: httpCode)]);
    }];
}

@end
