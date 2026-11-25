//
//  RPVRemoteAnisetteProvider.m
//  ReProvision
//
//  Persistent macOS ADI identity over the SideStore anisette v3 protocol.
//
//  Why this exists: the plain `GET /` anisette endpoint hands out a throwaway
//  emulated Mac, so the machine identity changes between launches. Developer
//  Services binds a GS token to the identity that minted it, which made every
//  cold start look like an expired session (resultCode 1100). The v3 protocol
//  provisions an `adi_pb` blob once, stores it locally, and asks the server to
//  generate fresh OTP headers from that same blob afterwards. Identity stays
//  fixed, the one-shot X-Apple-I-MD stays fresh, and the saved token keeps
//  working across launches.
//

#import "RPVRemoteAnisetteProvider.h"

#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha2.h>

NSString *const RPVAnisetteDefaultServer = @"mac-ani.jkcoxson.com";

static NSString *const RPVAnisetteErrorDomain = @"jp.soh.reprovision.anisette";
static NSString *const RPVAnisetteServerDefaultsKey = @"anisetteServerURL";
static NSString *const RPVAnisetteLocalUserUUIDKey = @"RPVAnisetteLocalUserUUID";
static NSString *const RPVAnisetteProvisioningKeyPrefix = @"RPVAnisetteProvisioningInfo";
static NSString *const RPVAnisetteRoutingInfoKeyPrefix = @"RPVAnisetteRoutingInfo";
static NSString *const RPVAnisetteClientInfoKeyPrefix = @"RPVAnisetteClientInfo";
static NSString *const RPVAnisetteUserAgentKeyPrefix = @"RPVAnisetteUserAgent";

// The server no longer accepts the stored ADI blob (Apple rotated the machine
// it emulates). Recoverable by provisioning again.
static const NSInteger RPVAnisetteIdentityRejectedError = 20;

static NSError *RPVAnisetteError(NSInteger code, NSString *description) {
    return [NSError errorWithDomain:RPVAnisetteErrorDomain
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey: description ?: @"Anisette request failed"}];
}

// Accepts "host", "host:port/path" or a full URL; returns nil when invalid.
static NSString *RPVNormalizedServerURL(id value) {
    if (![value isKindOfClass:[NSString class]]) {
        return nil;
    }
    NSString *string = [value stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (string.length == 0) {
        return nil;
    }
    if ([string rangeOfString:@"://"].location == NSNotFound) {
        string = [@"https://" stringByAppendingString:string];
    }
    NSURLComponents *components = [NSURLComponents componentsWithString:string];
    if (components.host.length == 0 ||
        !([components.scheme isEqualToString:@"https"] || [components.scheme isEqualToString:@"http"])) {
        return nil;
    }
    components.query = nil;
    components.fragment = nil;
    while ([components.path hasSuffix:@"/"]) {
        components.path = [components.path substringToIndex:components.path.length - 1];
    }
    return components.string;
}

// Identifies a server in storage keys, e.g. "mac-ani.jkcoxson.com".
static NSString *RPVServerStorageName(NSString *serverURL) {
    NSURLComponents *components = [NSURLComponents componentsWithString:serverURL];
    NSString *name = components.host ?: serverURL;
    if (components.port) {
        name = [name stringByAppendingFormat:@":%@", components.port];
    }
    if (components.path.length > 0) {
        name = [name stringByAppendingString:components.path];
    }
    return name;
}

static NSString *RPVScopedKey(NSString *prefix, NSString *serverURL) {
    return [NSString stringWithFormat:@"%@.%@", prefix, RPVServerStorageName(serverURL)];
}

@interface RPVRemoteAnisetteProvider () <NSURLSessionWebSocketDelegate>

@property (nonatomic, copy) NSString *serverURL;
@property (nonatomic, strong) NSURLSession *session;

@property (nonatomic, copy) NSString *clientInfo;
@property (nonatomic, copy) NSString *userAgent;
@property (nonatomic, copy) NSString *localUserID;

@property (nonatomic, strong) NSData *cachedProvisioningInfo;
@property (nonatomic, copy) NSString *cachedRoutingInfo;

@property (nonatomic, strong) NSURLSessionWebSocketTask *openingWebSocketTask;
@property (nonatomic, copy) void (^webSocketOpenCompletion)(NSURLSessionWebSocketTask *task, NSError *error);

@end

@implementation RPVRemoteAnisetteProvider

+ (NSString *)currentServerURL {
    NSString *stored = [[NSUserDefaults standardUserDefaults] objectForKey:RPVAnisetteServerDefaultsKey];
    NSString *normalized = RPVNormalizedServerURL(stored);
    if (normalized.length > 0) {
        return normalized;
    }
    return [@"https://" stringByAppendingString:RPVAnisetteDefaultServer];
}

+ (void)resetStoredStateForCurrentServer {
    NSString *serverURL = [self currentServerURL];
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    [defaults removeObjectForKey:RPVScopedKey(RPVAnisetteProvisioningKeyPrefix, serverURL)];
    [defaults removeObjectForKey:RPVScopedKey(RPVAnisetteRoutingInfoKeyPrefix, serverURL)];
    [defaults synchronize];
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _serverURL = [[self class] currentServerURL];

        NSURLSessionConfiguration *config = [NSURLSessionConfiguration defaultSessionConfiguration];
        config.timeoutIntervalForRequest = 20.0;
        config.timeoutIntervalForResource = 40.0;
        config.URLCache = nil;
        _session = [NSURLSession sessionWithConfiguration:config delegate:self delegateQueue:nil];
    }
    return self;
}

- (void)dealloc {
    [_session invalidateAndCancel];
}

#pragma mark - Identity

// A random per-install UUID. It is the X-Mme-Device-Id Apple sees, so it must
// never change once an ADI blob has been provisioned for it.
- (NSUUID *)localUserUUID {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *stored = [defaults stringForKey:RPVAnisetteLocalUserUUIDKey];
    NSUUID *uuid = stored.length > 0 ? [[NSUUID alloc] initWithUUIDString:stored] : nil;
    if (!uuid) {
        uuid = [NSUUID UUID];
        [defaults setObject:uuid.UUIDString forKey:RPVAnisetteLocalUserUUIDKey];
        [defaults synchronize];
    }
    return uuid;
}

- (NSData *)localUserUUIDData {
    uuid_t bytes;
    [[self localUserUUID] getUUIDBytes:bytes];
    return [NSData dataWithBytes:bytes length:sizeof(bytes)];
}

// Base64 of the UUID bytes; this is the X-Apple-I-MD-LU value Apple expects.
- (NSString *)localUserID {
    if (!_localUserID) {
        _localUserID = [[self localUserUUIDData] base64EncodedStringWithOptions:0];
    }
    return _localUserID;
}

- (NSString *)clientInfo {
    if (_clientInfo.length > 0) {
        return _clientInfo;
    }
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *stored = [defaults stringForKey:RPVScopedKey(RPVAnisetteClientInfoKeyPrefix, self.serverURL)];
    if (stored.length > 0) {
        _clientInfo = stored;
    }
    return _clientInfo;
}

- (NSString *)userAgent {
    if (_userAgent.length > 0) {
        return _userAgent;
    }
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *stored = [defaults stringForKey:RPVScopedKey(RPVAnisetteUserAgentKeyPrefix, self.serverURL)];
    if (stored.length > 0) {
        _userAgent = stored;
    }
    return _userAgent;
}

#pragma mark - Client info

- (void)fetchClientInfoWithCompletion:(void (^)(NSError *error))completion {
    if (self.clientInfo.length > 0 && self.userAgent.length > 0) {
        completion(nil);
        return;
    }

    NSURL *URL = [NSURL URLWithString:[self.serverURL stringByAppendingString:@"/v3/client_info"]];
    [[self.session dataTaskWithRequest:[NSURLRequest requestWithURL:URL]
                    completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (error || !data || [(NSHTTPURLResponse *)response statusCode] != 200) {
            completion(error ?: RPVAnisetteError(1, @"The anisette server did not return its client info"));
            return;
        }
        NSDictionary *JSON = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        NSString *clientInfo = JSON[@"client_info"];
        NSString *userAgent = JSON[@"user_agent"];
        if (![clientInfo isKindOfClass:[NSString class]] || clientInfo.length == 0) {
            completion(RPVAnisetteError(2, @"The anisette server returned an unusable client info"));
            return;
        }
        self.clientInfo = clientInfo;
        self.userAgent = [userAgent isKindOfClass:[NSString class]] && userAgent.length > 0
            ? userAgent : @"akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0";

        NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
        [defaults setObject:clientInfo forKey:RPVScopedKey(RPVAnisetteClientInfoKeyPrefix, self.serverURL)];
        [defaults setObject:self.userAgent forKey:RPVScopedKey(RPVAnisetteUserAgentKeyPrefix, self.serverURL)];
        [defaults synchronize];
        completion(nil);
    }] resume];
}

#pragma mark - Apple provisioning

- (void)sendAppleProvisioningRequestToURL:(NSString *)URLString
                                   values:(NSDictionary *)values
                               completion:(void (^)(NSDictionary *response, NSError *error))completion {
    NSDictionary *body = @{ @"Header": @{}, @"Request": values ?: @{} };
    NSData *bodyData = [NSPropertyListSerialization dataWithPropertyList:body
                                                                  format:NSPropertyListXMLFormat_v1_0
                                                                 options:0
                                                                   error:nil];
    if (!bodyData) {
        completion(nil, RPVAnisetteError(3, @"Could not build the provisioning request"));
        return;
    }

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:URLString]];
    request.HTTPMethod = @"POST";
    request.HTTPBody = bodyData;
    [request setValue:@"text/x-xml-plist" forHTTPHeaderField:@"Content-Type"];
    [request setValue:@"en_US" forHTTPHeaderField:@"Accept-Language"];
    [request setValue:self.userAgent ?: @"akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0" forHTTPHeaderField:@"User-Agent"];
    [request setValue:self.localUserID forHTTPHeaderField:@"X-Apple-I-MD-LU"];
    [request setValue:self.clientInfo forHTTPHeaderField:@"X-MMe-Client-Info"];
    [request setValue:[self localUserUUID].UUIDString forHTTPHeaderField:@"X-Mme-Device-Id"];
    NSString *country = NSLocale.currentLocale.countryCode;
    if (country.length > 0) {
        [request setValue:country forHTTPHeaderField:@"X-MMe-Country"];
    }

    [[self.session dataTaskWithRequest:request
                    completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (error || !data || [(NSHTTPURLResponse *)response statusCode] != 200) {
            completion(nil, error ?: RPVAnisetteError(4, @"Apple anisette provisioning was unavailable"));
            return;
        }
        NSDictionary *root = [NSPropertyListSerialization propertyListWithData:data options:0 format:nil error:nil];
        NSDictionary *operationResponse = root[@"Response"];
        NSInteger resultCode = [operationResponse[@"Status"][@"ec"] integerValue];
        if (![operationResponse isKindOfClass:[NSDictionary class]] || resultCode != 0) {
            completion(nil, RPVAnisetteError(resultCode ?: 5, @"Apple rejected anisette provisioning"));
            return;
        }
        completion(operationResponse, nil);
    }] resume];
}

#pragma mark - WebSocket

- (void)finishOpeningWebSocketTask:(NSURLSessionWebSocketTask *)task error:(NSError *)error {
    void (^completion)(NSURLSessionWebSocketTask *, NSError *) = nil;
    @synchronized (self) {
        if (task == self.openingWebSocketTask && self.webSocketOpenCompletion) {
            completion = self.webSocketOpenCompletion;
            self.openingWebSocketTask = nil;
            self.webSocketOpenCompletion = nil;
        }
    }
    if (completion) {
        completion(task, error);
    }
}

- (void)URLSession:(NSURLSession *)session
      webSocketTask:(NSURLSessionWebSocketTask *)webSocketTask
    didOpenWithProtocol:(NSString *)protocol {
    [self finishOpeningWebSocketTask:webSocketTask error:nil];
}

- (void)URLSession:(NSURLSession *)session
      webSocketTask:(NSURLSessionWebSocketTask *)webSocketTask
    didCloseWithCode:(NSURLSessionWebSocketCloseCode)closeCode
              reason:(NSData *)reason {
    [self finishOpeningWebSocketTask:webSocketTask
                               error:RPVAnisetteError(6, @"The anisette provisioning socket closed before it was ready")];
}

- (void)URLSession:(NSURLSession *)session
                    task:(NSURLSessionTask *)task
    didCompleteWithError:(NSError *)error {
    if (error && [task isKindOfClass:[NSURLSessionWebSocketTask class]]) {
        [self finishOpeningWebSocketTask:(NSURLSessionWebSocketTask *)task error:error];
    }
}

- (void)openProvisioningWebSocketWithCompletion:(void (^)(NSURLSessionWebSocketTask *task, NSError *error))completion {
    NSURL *URL = [NSURL URLWithString:[self.serverURL stringByAppendingString:@"/v3/provisioning_session"]];
    NSURLComponents *components = [NSURLComponents componentsWithURL:URL resolvingAgainstBaseURL:NO];
    components.scheme = [components.scheme isEqualToString:@"http"] ? @"ws" : @"wss";
    NSURLSessionWebSocketTask *task = [self.session webSocketTaskWithURL:components.URL];

    @synchronized (self) {
        self.openingWebSocketTask = task;
        self.webSocketOpenCompletion = completion;
    }
    [task resume];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(15 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        BOOL stillOpening = NO;
        @synchronized (self) {
            stillOpening = (task == self.openingWebSocketTask && self.webSocketOpenCompletion != nil);
        }
        if (stillOpening) {
            [self finishOpeningWebSocketTask:task error:RPVAnisetteError(7, @"The anisette provisioning socket timed out")];
            [task cancelWithCloseCode:NSURLSessionWebSocketCloseCodeGoingAway reason:nil];
        }
    });
}

- (void)receiveJSONFromWebSocket:(NSURLSessionWebSocketTask *)task
                      completion:(void (^)(NSDictionary *message, NSError *error))completion {
    [task receiveMessageWithCompletionHandler:^(NSURLSessionWebSocketMessage *message, NSError *error) {
        if (error || message.type != NSURLSessionWebSocketMessageTypeString) {
            completion(nil, error ?: RPVAnisetteError(8, @"The anisette provisioning session ended early"));
            return;
        }
        NSDictionary *JSON = [NSJSONSerialization JSONObjectWithData:[message.string dataUsingEncoding:NSUTF8StringEncoding]
                                                             options:0
                                                               error:nil];
        if (![JSON isKindOfClass:[NSDictionary class]]) {
            completion(nil, RPVAnisetteError(9, @"The anisette server sent an unreadable message"));
            return;
        }
        completion(JSON, nil);
    }];
}

- (void)sendJSON:(NSDictionary *)JSON
     toWebSocket:(NSURLSessionWebSocketTask *)task
      completion:(void (^)(NSError *error))completion {
    NSData *data = [NSJSONSerialization dataWithJSONObject:JSON options:0 error:nil];
    NSString *string = data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : nil;
    if (!string) {
        completion(RPVAnisetteError(10, @"Could not build an anisette message"));
        return;
    }
    [task sendMessage:[[NSURLSessionWebSocketMessage alloc] initWithString:string]
    completionHandler:^(NSError *error) {
        completion(error);
    }];
}

- (BOOL)message:(NSDictionary *)message hasResult:(NSString *)result {
    return [message[@"result"] isEqualToString:result];
}

- (void)performRemoteProvisioningWithSPIM:(NSData *)SPIM
                               completion:(void (^)(NSData *provisioningInfo, NSString *routingInfo, NSError *error))completion {
    [self openProvisioningWebSocketWithCompletion:^(NSURLSessionWebSocketTask *task, NSError *openError) {
        if (openError || !task) {
            completion(nil, nil, openError ?: RPVAnisetteError(11, @"The anisette provisioning socket did not open"));
            return;
        }
        [self receiveJSONFromWebSocket:task completion:^(NSDictionary *first, NSError *error) {
            if (error || ![self message:first hasResult:@"GiveIdentifier"]) {
                completion(nil, nil, error ?: RPVAnisetteError(12, @"Unexpected anisette provisioning handshake"));
                return;
            }
            NSString *identifier = [[self localUserUUIDData] base64EncodedStringWithOptions:0];
            [self sendJSON:@{ @"identifier": identifier } toWebSocket:task completion:^(NSError *error) {
                if (error) { completion(nil, nil, error); return; }
                [self receiveJSONFromWebSocket:task completion:^(NSDictionary *second, NSError *error) {
                    if (error || ![self message:second hasResult:@"GiveStartProvisioningData"]) {
                        completion(nil, nil, error ?: RPVAnisetteError(13, @"Unexpected anisette start request"));
                        return;
                    }
                    [self sendJSON:@{ @"spim": [SPIM base64EncodedStringWithOptions:0] }
                       toWebSocket:task completion:^(NSError *error) {
                        if (error) { completion(nil, nil, error); return; }
                        [self receiveJSONFromWebSocket:task completion:^(NSDictionary *third, NSError *error) {
                            NSString *CPIMString = third[@"cpim"];
                            NSData *CPIM = [CPIMString isKindOfClass:[NSString class]]
                                ? [[NSData alloc] initWithBase64EncodedString:CPIMString options:0] : nil;
                            if (error || ![self message:third hasResult:@"GiveEndProvisioningData"] || !CPIM) {
                                completion(nil, nil, error ?: RPVAnisetteError(14, @"The anisette provider did not produce CPIM data"));
                                return;
                            }

                            [self sendAppleProvisioningRequestToURL:@"https://gsa.apple.com/grandslam/MidService/finishMachineProvisioning"
                                                            values:@{ @"cpim": [CPIM base64EncodedStringWithOptions:0] }
                                                        completion:^(NSDictionary *response, NSError *error) {
                                NSString *PTMString = response[@"ptm"];
                                NSString *TKString = response[@"tk"];
                                NSString *routingInfo = [response[@"X-Apple-I-MD-RINFO"] description];
                                NSData *PTM = [PTMString isKindOfClass:[NSString class]]
                                    ? [[NSData alloc] initWithBase64EncodedString:PTMString options:0] : nil;
                                NSData *TK = [TKString isKindOfClass:[NSString class]]
                                    ? [[NSData alloc] initWithBase64EncodedString:TKString options:0] : nil;
                                if (error || !PTM || !TK || routingInfo.length == 0) {
                                    completion(nil, nil, error ?: RPVAnisetteError(15, @"Apple returned incomplete provisioning data"));
                                    return;
                                }

                                [self sendJSON:@{
                                    @"ptm": [PTM base64EncodedStringWithOptions:0],
                                    @"tk": [TK base64EncodedStringWithOptions:0]
                                } toWebSocket:task completion:^(NSError *error) {
                                    if (error) { completion(nil, nil, error); return; }
                                    [self receiveJSONFromWebSocket:task completion:^(NSDictionary *final, NSError *error) {
                                        NSString *provisioningString = final[@"adi_pb"] ?: final[@"adiPb"];
                                        NSData *provisioningInfo = [provisioningString isKindOfClass:[NSString class]]
                                            ? [[NSData alloc] initWithBase64EncodedString:provisioningString options:0] : nil;
                                        [task cancelWithCloseCode:NSURLSessionWebSocketCloseCodeNormalClosure reason:nil];
                                        if (error || ![self message:final hasResult:@"ProvisioningSuccess"] || !provisioningInfo) {
                                            completion(nil, nil, error ?: RPVAnisetteError(16, @"Anisette provisioning did not complete"));
                                            return;
                                        }
                                        completion(provisioningInfo, routingInfo, nil);
                                    }];
                                }];
                            }];
                        }];
                    }];
                }];
            }];
        }];
    }];
}

- (void)provisionWithCompletion:(void (^)(NSData *provisioningInfo, NSString *routingInfo, NSError *error))completion {
    [self sendAppleProvisioningRequestToURL:@"https://gsa.apple.com/grandslam/MidService/startMachineProvisioning"
                                    values:@{}
                                completion:^(NSDictionary *response, NSError *error) {
        NSString *SPIMString = response[@"spim"];
        NSData *SPIM = [SPIMString isKindOfClass:[NSString class]]
            ? [[NSData alloc] initWithBase64EncodedString:SPIMString options:0] : nil;
        if (error || !SPIM) {
            completion(nil, nil, error ?: RPVAnisetteError(17, @"Apple returned incomplete start-provisioning data"));
            return;
        }
        [self performRemoteProvisioningWithSPIM:SPIM completion:completion];
    }];
}

#pragma mark - Headers

- (NSDictionary *)headersFromJSON:(NSDictionary *)JSON routingInfo:(NSString *)storedRoutingInfo error:(NSError **)error {
    NSString *machineID = JSON[@"X-Apple-I-MD-M"];
    NSString *OTP = JSON[@"X-Apple-I-MD"];
    NSString *routingInfo = [JSON[@"X-Apple-I-MD-RINFO"] description] ?: storedRoutingInfo;
    if (machineID.length == 0 || OTP.length == 0 || routingInfo.length == 0 || self.clientInfo.length == 0) {
        if (error) {
            *error = RPVAnisetteError(18, @"The anisette provider returned incomplete headers");
        }
        return nil;
    }

    NSDateFormatter *formatter = [NSDateFormatter new];
    formatter.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    formatter.calendar = [NSCalendar calendarWithIdentifier:NSCalendarIdentifierGregorian];
    formatter.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"UTC"];
    formatter.dateFormat = @"yyyy-MM-dd'T'HH:mm:ss'Z'";
    NSString *locale = NSLocale.currentLocale.localeIdentifier ?: @"en_US";
    NSString *timeZone = NSTimeZone.localTimeZone.abbreviation ?: @"UTC";

    return @{
        @"X-Apple-I-MD-M": machineID,
        @"X-Apple-I-MD": OTP,
        @"X-Apple-I-MD-LU": self.localUserID,
        @"X-Apple-I-MD-RINFO": routingInfo,
        @"X-Mme-Device-Id": [self localUserUUID].UUIDString,
        @"X-MMe-Client-Info": self.clientInfo,
        @"X-Apple-I-Client-Time": [formatter stringFromDate:[NSDate date]],
        @"X-Apple-Locale": locale,
        @"X-Apple-I-Locale": locale,
        @"X-Apple-I-TimeZone": timeZone,
        @"X-Apple-I-SRL-NO": @"0",
    };
}

- (void)requestHeadersWithProvisioningInfo:(NSData *)provisioningInfo
                               routingInfo:(NSString *)routingInfo
                                completion:(void (^)(NSDictionary *headers, NSError *error))completion {
    NSDictionary *body = @{
        @"identifier": [[self localUserUUIDData] base64EncodedStringWithOptions:0],
        @"adi_pb": [provisioningInfo base64EncodedStringWithOptions:0],
    };
    NSData *bodyData = [NSJSONSerialization dataWithJSONObject:body options:0 error:nil];
    if (!bodyData) {
        completion(nil, RPVAnisetteError(19, @"Could not build the anisette header request"));
        return;
    }

    NSURL *URL = [NSURL URLWithString:[self.serverURL stringByAppendingString:@"/v3/get_headers"]];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:URL];
    request.HTTPMethod = @"POST";
    request.HTTPBody = bodyData;
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];

    [[self.session dataTaskWithRequest:request
                    completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (error || !data || [(NSHTTPURLResponse *)response statusCode] != 200) {
            completion(nil, error ?: RPVAnisetteError(20, @"Could not generate anisette headers"));
            return;
        }
        NSDictionary *JSON = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        if (![JSON isKindOfClass:[NSDictionary class]]) {
            completion(nil, RPVAnisetteError(21, @"The anisette server sent unreadable headers"));
            return;
        }
        if ([self message:JSON hasResult:@"GetHeadersError"]) {
            NSString *message = [JSON[@"message"] isKindOfClass:[NSString class]] ? JSON[@"message"] : @"unknown error";
            // The server no longer accepts this identity, typically because the
            // machine it emulates changed.
            if ([message containsString:@"-45061"]) {
                completion(nil, RPVAnisetteError(RPVAnisetteIdentityRejectedError,
                                                 @"The anisette server no longer recognizes this device identity"));
                return;
            }
            completion(nil, RPVAnisetteError(22, [@"The anisette server could not generate headers: "
                                                  stringByAppendingString:message]));
            return;
        }
        NSError *headerError = nil;
        NSDictionary *headers = [self headersFromJSON:JSON routingInfo:routingInfo error:&headerError];
        completion(headers, headerError);
    }] resume];
}

- (void)provisionAndFetchWithCompletion:(void (^)(NSDictionary *headers, NSError *error))completion {
    [self provisionWithCompletion:^(NSData *provisioningInfo, NSString *routingInfo, NSError *error) {
        if (error || provisioningInfo.length == 0) {
            completion(nil, error ?: RPVAnisetteError(23, @"Anisette provisioning failed"));
            return;
        }
        // Retain before writing to preferences: the device can lock right after
        // the user taps Sign, and the in-flight pass must keep the identity its
        // GS token is bound to.
        self.cachedProvisioningInfo = provisioningInfo;
        self.cachedRoutingInfo = routingInfo;
        NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
        [defaults setObject:provisioningInfo forKey:RPVScopedKey(RPVAnisetteProvisioningKeyPrefix, self.serverURL)];
        [defaults setObject:routingInfo forKey:RPVScopedKey(RPVAnisetteRoutingInfoKeyPrefix, self.serverURL)];
        [defaults synchronize];
        [self requestHeadersWithProvisioningInfo:provisioningInfo routingInfo:routingInfo completion:completion];
    }];
}

#pragma mark - Public

- (void)fetchAnisetteDataWithCompletion:(void (^)(NSDictionary<NSString *, NSString *> * _Nullable headers,
                                                   NSError * _Nullable error))completion {
    [self fetchClientInfoWithCompletion:^(NSError *error) {
        if (error) {
            completion(nil, error);
            return;
        }

        NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
        NSData *provisioningInfo = self.cachedProvisioningInfo;
        NSString *routingInfo = self.cachedRoutingInfo;
        if (provisioningInfo.length == 0 || routingInfo.length == 0) {
            provisioningInfo = [defaults dataForKey:RPVScopedKey(RPVAnisetteProvisioningKeyPrefix, self.serverURL)];
            routingInfo = [defaults stringForKey:RPVScopedKey(RPVAnisetteRoutingInfoKeyPrefix, self.serverURL)];
            self.cachedProvisioningInfo = provisioningInfo;
            self.cachedRoutingInfo = routingInfo;
        }
        if (provisioningInfo.length == 0 || routingInfo.length == 0) {
            [self provisionAndFetchWithCompletion:completion];
            return;
        }

        [self requestHeadersWithProvisioningInfo:provisioningInfo routingInfo:routingInfo completion:^(NSDictionary *headers, NSError *error) {
            if (!error && headers) {
                completion(headers, nil);
                return;
            }
            // A GrandSlam identity and its GS token are bound to the ADI blob
            // that created them, so reprovisioning mid-flow would make a valid
            // session look expired.
            if (self.identityPinned) {
                completion(nil, error ?: RPVAnisetteError(24, @"Could not refresh the pinned anisette identity"));
                return;
            }
            // Apple can invalidate provisioning. Keep the stable UUID, drop only
            // the ADI blob, and recover once.
            self.cachedProvisioningInfo = nil;
            self.cachedRoutingInfo = nil;
            [defaults removeObjectForKey:RPVScopedKey(RPVAnisetteProvisioningKeyPrefix, self.serverURL)];
            [defaults removeObjectForKey:RPVScopedKey(RPVAnisetteRoutingInfoKeyPrefix, self.serverURL)];
            [self provisionAndFetchWithCompletion:completion];
        }];
    }];
}

@end
