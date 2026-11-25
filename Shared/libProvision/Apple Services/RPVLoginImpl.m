//
//  RPVLoginImpl.cpp
//  iOS
//
//  Created by Kabir Oberai on 11/11/19.
//  Adapted by Matt Clarke on 24/11/19.
//

#import "RPVLoginImpl.h"

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

struct ccrng_state *ccDRBGGetRngState(void);

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

// Trusted phone number the current 2FA code was sent to, and how.
@property (nonatomic, strong) NSString *twoFactorPhoneNumberID;
@property (nonatomic, strong) NSString *twoFactorPhoneDeliveryMode;

#if TARGET_OS_IOS
@property (nonatomic, readwrite) struct ccrng_state *rngState;
#endif

- (BOOL)_isRetryableGSAStatus:(long)httpCode;
- (BOOL)_isRetryableNSURLError:(NSError *)error;
- (NSURLSession *)_gsaEphemeralSession;
- (void)_performGSADataRequest:(NSMutableURLRequest *)request attempt:(NSUInteger)attempt completion:(void (^)(NSError *error, NSData *data, long httpCode))completionHandler;
- (void)_makeRequestWithParameters:(NSDictionary*)params attempt:(NSUInteger)attempt completion:(void (^)(NSError *err, NSDictionary *response))completionHandler;
- (void)_retryGSAParameters:(NSDictionary*)params attempt:(NSUInteger)attempt completion:(void (^)(NSError *err, NSDictionary *response))completionHandler;
- (NSDictionary *)_phoneDescriptorFromAuthResponse:(NSDictionary *)response;
- (NSMutableURLRequest *)_twoFactorRequestWithURL:(NSURL *)URL userIdentity:(NSString *)userIdentity idmsToken:(NSString *)token;
- (NSMutableURLRequest *)_twoFactorJSONRequestWithURL:(NSURL *)URL userIdentity:(NSString *)userIdentity idmsToken:(NSString *)token;
- (void)_performTwoFactorCodeRequest:(NSMutableURLRequest *)request completion:(void (^)(NSError *error))completionHandler;
- (void)_submitPhoneVerificationCode:(NSString *)code userIdentity:(NSString *)userIdentity idmsToken:(NSString *)token completion:(RPVTwoFactorResultBlock)completionHandler;

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
    // (-22410 / -80046), so prefer a remote Mac anisette and only fall back to
    // the device when the server is unreachable.
    static NSDictionary *cachedHeaders = nil;
    static NSDate *cachedAt = nil;
    @synchronized (self) {
        if (cachedHeaders && cachedAt && -[cachedAt timeIntervalSinceNow] < 5.0) {
            return cachedHeaders;
        }
    }
    NSString *storedURL = [[NSUserDefaults standardUserDefaults] objectForKey:@"anisetteServerURL"];
    NSString *urlString = (storedURL && storedURL.length > 0) ? storedURL : @"https://ani.jkcoxson.com";
    NSURL *url = [NSURL URLWithString:urlString];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.timeoutInterval = 8.0;
    __block NSData *respData = nil;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
        if (d && !e) { respData = d; }
        dispatch_semaphore_signal(sem);
    }] resume];
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 9 * NSEC_PER_SEC));
    if (!respData) {
        NSLog(@"[DIAG] remote anisette: no response, fallback to local");
        return nil;
    }
    id json = [NSJSONSerialization JSONObjectWithData:respData options:0 error:nil];
    if (![json isKindOfClass:[NSDictionary class]] || [json objectForKey:@"X-Apple-I-MD"] == nil) {
        NSLog(@"[DIAG] remote anisette: invalid payload, fallback to local");
        return nil;
    }
    NSString *remoteClientInfo = [json objectForKey:@"X-MMe-Client-Info"];
    if ([remoteClientInfo isKindOfClass:[NSString class]] && remoteClientInfo.length > 0) {
        self.clientInfoOverride = remoteClientInfo;
    }
    NSLog(@"[DIAG] remote anisette OK rininfo=%@ mdlu=%@ client=%@", [json objectForKey:@"X-Apple-I-MD-RINFO"], [json objectForKey:@"X-Apple-I-MD-LU"] ? @"yes" : @"no", remoteClientInfo);
    @synchronized (self) { cachedHeaders = json; cachedAt = [NSDate date]; }
    return json;
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
    config.HTTPCookieStorage = nil;
    config.HTTPCookieAcceptPolicy = NSHTTPCookieAcceptPolicyNever;
    config.HTTPShouldUsePipelining = NO;
    config.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
    config.timeoutIntervalForRequest = 30.0;
    config.timeoutIntervalForResource = 60.0;
    return [NSURLSession sessionWithConfiguration:config];
}

// Runs a single GSA request on a throwaway socket and retries transient
// failures (network errors and 5xx). The edge drops a keep-alive connection
// after a couple of uses and answers the next request with an HTML 503, so
// every attempt has to start on a fresh connection.
- (void)_performGSADataRequest:(NSMutableURLRequest *)request
                       attempt:(NSUInteger)attempt
                    completion:(void (^)(NSError *error, NSData *data, long httpCode))completionHandler {
    if (!request || !request.URL) {
        completionHandler([self createError:@"The Apple request could not be created" :RPVInternalLoginError], nil, -1);
        return;
    }

    NSString *diagPath = request.URL.path ?: @"?";
    NSURLSession *session = [self _gsaEphemeralSession];
    NSURLSessionDataTask *task = [session dataTaskWithRequest:request
        completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        [session finishTasksAndInvalidate];

        NSHTTPURLResponse *httpResp = [response isKindOfClass:[NSHTTPURLResponse class]] ? (NSHTTPURLResponse *)response : nil;
        long httpCode = httpResp ? (long)httpResp.statusCode : -1;

        void (^retry)(void) = ^{
            NSTimeInterval delay = attempt == 0 ? 1.5 : (attempt == 1 ? 3.0 : 6.0);
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC)),
                           dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                [self _performGSADataRequest:request attempt:attempt + 1 completion:completionHandler];
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
    
    // Ensure lookup URLs are populated first
    [self initialiseLookup:^(NSError *error) {
        if (error) {
            completionHandler(error, nil, nil, nil);
        } else {
    
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

                NSString *message = [completeResponseStatus objectForKey:@"em"] ?: @"Two-factor authentication is required";
                NSError *responseError = [self createError:message :mode];

                completionHandler(responseError, altDSID, nil, idmsToken);
            } else {
            
                NSData *completeSK = decryptedDict[@"sk"];
                NSData *completeC = decryptedDict[@"c"];
                
                NSString *app = @"com.apple.gs.xcode.auth";
                NSArray<NSString *> *apps = @[app];

                NSData *checksum = createAppTokensChecksum(completeSK, adsid, apps);
                
                // 'Tokens' response to GSA
                semaphore = dispatch_semaphore_create(0);
                __block NSDictionary *tokensResponse = nil;
                [self makeRequestWithParameters:@{
                    @"u": adsid,
                    @"app": apps,
                    @"c": completeC,
                    @"t": idmsToken,
                    @"checksum": checksum,
                    @"cpd": clientData,
                    @"o": @"apptokens"
                } completion:^(NSError *err, NSDictionary *response) {
                    if (response) {
                        tokensResponse = response;
                    } else {
                        completionHandler(err, nil, nil, nil);
                    }
                    
                    dispatch_semaphore_signal(semaphore);
                }];
                dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
                
                // Handle 'complete' response
                if (!tokensResponse) {
                    return;
                }
                
                NSDictionary *tokensResponseStatus = [tokensResponse objectForKey:@"Status"];
                if ([tokensResponseStatus objectForKey:@"ec"] &&
                    [[tokensResponseStatus objectForKey:@"ec"] intValue] != 0) {
                    // Error during request
                    NSError *responseError = [self createError:[tokensResponseStatus objectForKey:@"em"]
                                                              :[[tokensResponseStatus objectForKey:@"ec"] intValue]];
                    
                    completionHandler(responseError, nil, nil, nil);
                    return;
                }

                NSData *encryptedToken = tokensResponse[@"et"];
                NSData *decryptedToken = decryptGCM(completeSK, encryptedToken);
                if (!decryptedToken) {
                    log_error("Could not decrypt apptoken!");
                    NSError *error = [self createError:@"Could not decrypt apptoken" :RPVInternalLoginError];
                    completionHandler(error, nil, nil, nil);
                    return;
                }
                NSDictionary *decryptedTokDict = [NSPropertyListSerialization propertyListWithData:decryptedToken options:0 format:nil error:nil];
                if (!decryptedTokDict) {
                    log_error("Could not parse decrypted apptoken plist!");
                    NSError *error = [self createError:@"Could not parse decrypted apptoken plist" : RPVInternalLoginError];
                    completionHandler(error, nil, nil, nil);
                    return;
                }
                log_debug("Decrypted token dict: %s", decryptedTokDict.description.UTF8String);

                NSDictionary *tokenDict = decryptedTokDict[@"t"][app];
                NSString *token = tokenDict[@"token"];
                
                completionHandler(nil, altDSID, token, nil);
            }
        }
    }];
}

// Apple lists the trusted phone numbers for the account at /auth. Read the
// first one together with its delivery mode so a code can be sent to it.
- (void)_checkAuthEndpointWithUserIdentity:(NSString*)userIdentity idmsToken:(NSString*)token andCompletion:(void (^)(NSError *error, NSDictionary *phoneDescriptor))completionHandler {
    
    NSString *dsid = [userIdentity componentsSeparatedByString:@"|"].firstObject;

    NSString *secondaryAuthURL = self.lookupURLs[@"secondaryAuth"];
    NSURL *URL = secondaryAuthURL.length > 0 ? [NSURL URLWithString:secondaryAuthURL]
                                             : [NSURL URLWithString:@"https://gsa.apple.com/auth"];

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:URL];
    
    log_debug("Request to: %s", URL.description.UTF8String);
    
    NSString *identityToken = [NSString stringWithFormat:@"%@:%@", dsid, token];
    
    NSData *identityTokenData = [identityToken dataUsingEncoding:NSUTF8StringEncoding];
    NSString *encodedIdentityToken = [identityTokenData base64EncodedStringWithOptions:0];
    
    // Sort out headers
    NSMutableDictionary<NSString *, NSString *> *httpHeaders = [@{
        @"Content-Type": @"text/x-xml-plist",
        @"User-Agent": RPVGrandSlamUserAgent,
        @"Accept": @"text/x-xml-plist",
        @"Accept-Language": @"en-us",
        @"X-Apple-Client-App-Name": @"Xcode",
        @"X-Apple-App-Info": @"com.apple.gs.xcode.auth",
        @"X-Xcode-Version": RPVGrandSlamXcodeVersion,
        @"X-Apple-Identity-Token": encodedIdentityToken,
    } mutableCopy];
    
    [httpHeaders addEntriesFromDictionary:[self _anisetteData]];
    [httpHeaders addEntriesFromDictionary:[self _deviceData]];
    
    [httpHeaders enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSString *value, BOOL *stop) {
        [request setValue:value forHTTPHeaderField:key];
    }];
    
    [request setValue:self.clientInfoOverride forHTTPHeaderField:@"X-MMe-Client-Info"];

    [self _performGSADataRequest:request attempt:0 completion:^(NSError *error, NSData *data, long httpCode) {
        NSLog(@"[DIAG] /auth HTTP=%ld bytes=%lu", httpCode, (unsigned long)data.length);

        if (error) {
            completionHandler(error, nil);
            return;
        }

        if (data.length == 0) {
            completionHandler([self createError:[NSString stringWithFormat:@"Apple returned an empty trusted number list (HTTP %ld)", httpCode] :RPVInternalLoginError], nil);
            return;
        }

        // The endpoint answers with a plist on older iOS and JSON on newer.
        id object = [NSPropertyListSerialization propertyListWithData:data options:0 format:nil error:nil];
        if (![object isKindOfClass:[NSDictionary class]]) {
            object = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        }
        if (![object isKindOfClass:[NSDictionary class]]) {
            // Apple answered with something else (typically an HTML 503 from the
            // edge). Surface a slice of it so the cause is visible in the log.
            NSString *raw = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if (!raw) raw = [[NSString alloc] initWithData:data encoding:NSISOLatin1StringEncoding];
            if (raw.length > 500) raw = [raw substringToIndex:500];
            NSLog(@"[DIAG] /auth unparseable HTTP=%ld raw=%@", httpCode, raw ?: @"(non-text)");
            completionHandler([self createError:[NSString stringWithFormat:@"Apple returned an unreadable list of trusted numbers (HTTP %ld). %@", httpCode, raw ?: @""] :RPVInternalLoginError], nil);
            return;
        }

        log_debug("Reponse: %s", ((NSDictionary *)object).description.UTF8String);

        NSDictionary *descriptor = [self _phoneDescriptorFromAuthResponse:object];
        if (descriptor.count == 0) {
            completionHandler([self createError:@"This Apple ID has no trusted phone number that can receive a code." :RPVInternalLoginError], nil);
            return;
        }
        completionHandler(nil, descriptor);
    }];
}

// Walk the containers Apple may nest the numbers in, then take the first entry
// that carries an id. Delivery mode defaults to sms.
- (NSDictionary *)_phoneDescriptorFromAuthResponse:(NSDictionary *)response {
    NSMutableArray<NSDictionary *> *containers = [NSMutableArray arrayWithObject:response];
    for (NSString *key in @[@"Response", @"response", @"serverInfo", @"ServerInfo"]) {
        NSDictionary *container = response[key];
        if ([container isKindOfClass:[NSDictionary class]]) {
            [containers addObject:container];
            NSDictionary *serverInfo = container[@"serverInfo"] ?: container[@"ServerInfo"];
            if ([serverInfo isKindOfClass:[NSDictionary class]]) {
                [containers addObject:serverInfo];
            }
        }
    }

    for (NSDictionary *container in containers) {
        NSMutableArray<NSDictionary *> *candidates = [NSMutableArray array];
        for (NSString *key in @[@"trustedPhoneNumber", @"phoneNumber"]) {
            NSDictionary *candidate = container[key];
            if ([candidate isKindOfClass:[NSDictionary class]]) {
                [candidates addObject:candidate];
            }
        }
        NSArray *trusted = container[@"trustedPhoneNumbers"];
        if ([trusted isKindOfClass:[NSArray class]]) {
            for (id candidate in trusted) {
                if ([candidate isKindOfClass:[NSDictionary class]]) {
                    [candidates addObject:candidate];
                }
            }
        }

        for (NSDictionary *candidate in candidates) {
            id rawIdentifier = candidate[@"id"] ?: candidate[@"phoneNumber.id"];
            NSString *identifier = [rawIdentifier respondsToSelector:@selector(stringValue)]
                ? [rawIdentifier stringValue]
                : ([rawIdentifier isKindOfClass:[NSString class]] ? rawIdentifier : nil);
            if (identifier.length == 0) {
                continue;
            }

            NSString *rawMode = candidate[@"pushMode"] ?: candidate[@"mode"] ?: container[@"mode"];
            NSString *mode = [rawMode.lowercaseString isEqualToString:@"voice"] ? @"voice" : @"sms";

            NSString *number = candidate[@"numberWithDialCode"] ?: candidate[@"obfuscatedNumber"] ?: candidate[@"number"];
            NSLog(@"[DIAG] trusted number id=%@ mode=%@ number=%@", identifier, mode, [number isKindOfClass:[NSString class]] ? number : @"-");

            return @{
                @"id": identifier,
                @"mode": mode,
                @"number": [number isKindOfClass:[NSString class]] ? number : @"",
            };
        }
    }

    return @{};
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

    [self _performGSADataRequest:request attempt:0 completion:^(NSError *error, NSData *data, long httpCode) {
        NSLog(@"[DIAG] 2FA code request %@ HTTP=%ld bytes=%lu", request.URL.path, httpCode, (unsigned long)data.length);

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

    [self _performGSADataRequest:request attempt:0 completion:^(NSError *error, NSData *data, long httpCode) {
        NSLog(@"[DIAG] 2FA submit HTTP=%ld bytes=%lu", httpCode, (unsigned long)data.length);

        if (error) {
            completionHandler(error);
            return;
        }

        if (httpCode >= 200 && httpCode < 300) {
            completionHandler(nil);
            return;
        }

        NSString *raw = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        if (raw.length > 300) {
            raw = [raw substringToIndex:300];
        }
        NSLog(@"[DIAG] 2FA submit failed raw=%@", raw);

        if (httpCode == 400 || httpCode == 401 || httpCode == 403) {
            completionHandler([self createError:@"Apple did not accept that verification code. Request a new code and try again."
                                               :RPVInternalLoginIncorrect2FACodeError]);
            return;
        }
        completionHandler([self createError:[NSString stringWithFormat:@"Apple could not verify that code (HTTP %ld).", httpCode]
                                           :RPVInternalLoginError]);
    }];
}

@end
