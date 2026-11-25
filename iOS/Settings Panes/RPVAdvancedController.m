//
//  EEAdvancedController.m
//  Extender Installer
//
//  Created by Matt Clarke on 05/05/2017.
//
//

#import "RPVAdvancedController.h"
#import "AppDelegate.h"
#import "RPVResources.h"
#import "RPVRemoteAnisetteProvider.h"

#include <notify.h>

@interface RPVAdvancedController ()
@property (nonatomic, readwrite) int daemonNotificationToken;
@property (nonatomic, strong) NSArray *anisetteServerURLs;
- (NSDictionary *)anisetteServerTitles;
@end

@implementation RPVAdvancedController

- (void)viewDidLoad {
    [super viewDidLoad];

    if (@available(iOS 11.0, *)) {
        self.navigationItem.largeTitleDisplayMode = UINavigationItemLargeTitleDisplayModeNever;
    }

    [[self navigationItem] setTitle:@"Advanced"];

    // Register token for daemon notifications.
    int status = notify_register_check("jp.soh.reprovision.ios/debugStartBackgroundSign", &_daemonNotificationToken);
    if (status != NOTIFY_STATUS_OK) {
        fprintf(stderr, "registration failed (%u)\n", status);
        return;
    }
}

- (id)specifiers {
    if (_specifiers == nil) {
        NSMutableArray *testingSpecs = [NSMutableArray array];

        // Create specifiers!
        [testingSpecs addObjectsFromArray:[self _signingSpecifiers]];
        [testingSpecs addObjectsFromArray:[self _errorHandlingSpecifiers]];

        _specifiers = testingSpecs;
    }

    return _specifiers;
}

- (NSArray *)_signingSpecifiers {
    NSMutableArray *array = [NSMutableArray array];

    PSSpecifier *group = [PSSpecifier groupSpecifierWithName:@"Re-signing"];
    [group setProperty:@"Set how often checks are made for if any applications are in need of re-signing." forKey:@"footerText"];
    [array addObject:group];

    NSDate *nextFireDate = [RPVResources preferenceValueForKey:@"nextFireDate"];
    NSMutableString *nextFireDateStr = [NSMutableString stringWithString:@"Next Fire Date: "];
    if (nextFireDate) {
        NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
        dateFormatter.dateStyle = NSDateFormatterMediumStyle;
        dateFormatter.timeStyle = NSDateFormatterMediumStyle;
        [nextFireDateStr appendString:[dateFormatter stringFromDate:nextFireDate]];
    } else {
        [nextFireDateStr appendString:@"-"];
    }
    PSSpecifier *nextFire = [PSSpecifier preferenceSpecifierNamed:nextFireDateStr target:self set:nil get:nil detail:nil cell:PSStaticTextCell edit:nil];
    [array addObject:nextFire];

    PSSpecifier *resign = [PSSpecifier preferenceSpecifierNamed:@"Re-sign in Low Power Mode" target:self set:@selector(setPreferenceValue:specifier:) get:@selector(readPreferenceValue:) detail:nil cell:PSSwitchCell edit:nil];
    [resign setProperty:@"resignInLowPowerMode" forKey:@"key"];
    [resign setProperty:@0 forKey:@"default"];

    [array addObject:resign];

    PSSpecifier *forceResign = [PSSpecifier preferenceSpecifierNamed:@"Force Re-sign" target:self set:@selector(setPreferenceValue:specifier:) get:@selector(readPreferenceValue:) detail:nil cell:PSSwitchCell edit:nil];
    [forceResign setProperty:@"forceResign" forKey:@"key"];
    [forceResign setProperty:@1 forKey:@"default"];

    [array addObject:forceResign];

    PSSpecifier *trueBgResign = [PSSpecifier preferenceSpecifierNamed:@"True Background Re-sign (Beta)" target:self set:@selector(setPreferenceValue:specifier:) get:@selector(readPreferenceValue:) detail:nil cell:PSSwitchCell edit:nil];
    [trueBgResign setProperty:@"trueBgResign" forKey:@"key"];
    [trueBgResign setProperty:@0 forKey:@"default"];

    [array addObject:trueBgResign];

    PSSpecifier *threshold = [PSSpecifier preferenceSpecifierNamed:@"Check Expiry Times:" target:self set:@selector(setPreferenceValue:specifier:) get:@selector(readPreferenceValue:) detail:NSClassFromString(@"PSListItemsController") cell:PSLinkListCell edit:nil];
    [threshold setProperty:@YES forKey:@"enabled"];
    [threshold setProperty:@2 forKey:@"default"];
    threshold.values = [NSArray arrayWithObjects:@1, @2, @6, @12, @24, @48, nil];
    threshold.titleDictionary = [NSDictionary dictionaryWithObjects:[NSArray arrayWithObjects:@"Every 1 Hour", @"Every 2 Hours", @"Every 6 Hours", @"Every 12 Hours", @"Every 24 Hours", @"Every Other Day", nil] forKeys:threshold.values];
    threshold.shortTitleDictionary = threshold.titleDictionary;
    [threshold setProperty:@"heartbeatTimerInterval" forKey:@"key"];
    [threshold setProperty:@"A longer time between checks uses less battery, but has more risk that applications won't be re-signed before a reboot." forKey:@"staticTextMessage"];

    [array addObject:threshold];

    PSSpecifier *anisetteGroup = [PSSpecifier groupSpecifierWithName:@"Anisette Server"];
    [anisetteGroup setProperty:@"Remote anisette server used for Apple ID sign-in. The device keeps its own ADI identity, so the server only computes attestations; switching servers makes the current Apple ID session stale and asks for the password again." forKey:@"footerText"];
    [array addObject:anisetteGroup];

    NSArray *serverURLs = [self anisetteServerURLs];
    NSMutableArray *serverNames = [NSMutableArray array];
    for (NSString *URLString in serverURLs) {
        [serverNames addObject:[[self anisetteServerTitles] objectForKey:URLString]];
    }

    PSSpecifier *anisetteServer = [PSSpecifier preferenceSpecifierNamed:@"Anisette Server" target:self set:@selector(setPreferenceValue:specifier:) get:@selector(readPreferenceValue:) detail:NSClassFromString(@"PSListItemsController") cell:PSLinkListCell edit:nil];
    [anisetteServer setProperty:@"anisetteServerURL" forKey:@"key"];
    [anisetteServer setProperty:@YES forKey:@"enabled"];
    [anisetteServer setProperty:[@"https://" stringByAppendingString:RPVAnisetteDefaultServer] forKey:@"default"];
    anisetteServer.values = serverURLs;
    anisetteServer.titleDictionary = [NSDictionary dictionaryWithObjects:serverNames forKeys:serverURLs];
    anisetteServer.shortTitleDictionary = anisetteServer.titleDictionary;
    [array addObject:anisetteServer];

    return array;
}

// Every listed server speaks the anisette v3 protocol, which is all that
// matters: the ADI identity lives in the adi_pb provisioned on this device, so
// the server never decides who Apple thinks we are. The old ADI version labels
// were misleading - mac-ani.jkcoxson.com reports a lower routing info than the
// servers it was being compared against and still signs in fine.
- (NSArray *)anisetteServerURLs {
    if (_anisetteServerURLs == nil) {
        _anisetteServerURLs = @[
            @"https://mac-ani.jkcoxson.com",
            @"https://new.ani.sidestore.io",
            @"https://ani.jkcoxson.com",
            @"https://ani3.stikstore.app",
        ];
    }
    return _anisetteServerURLs;
}

- (NSDictionary *)anisetteServerTitles {
    return @{
        @"https://mac-ani.jkcoxson.com":  @"Jkcoxson Mac",
        @"https://new.ani.sidestore.io":  @"SideStore",
        @"https://ani.jkcoxson.com":      @"Jkcoxson",
        @"https://ani3.stikstore.app":    @"Stikstore",
    };
}

- (NSArray *)_errorHandlingSpecifiers {
    NSMutableArray *array = [NSMutableArray array];

    /*PSSpecifier *group = [PSSpecifier groupSpecifierWithName:@"Error Handling"];
    [group setProperty:@"Some errors may be resolved automatically by revoking any existing certificates. This is only a temporary workaround.\n\nIt is strongly NOT recommended to use this feature if you use Extender: Reloaded on multiple devices." forKey:@"footerText"];
    [array addObject:group];
    
    PSSpecifier *resign = [PSSpecifier preferenceSpecifierNamed:@"Auto-Revoke Certificates" target:self set:@selector(setPreferenceValue:specifier:) get:@selector(readPreferenceValue:) detail:nil cell:PSSwitchCell edit:nil];
    [resign setProperty:@"shouldAutoRevokeIfNeeded" forKey:@"key"];
    //[resign setProperty:@YES forKey:@"enabled"];
    [resign setProperty:@NO forKey:@"enabled"];
    [resign setProperty:@0 forKey:@"default"];
    
    [array addObject:resign];*/

    PSSpecifier *group = [PSSpecifier groupSpecifierWithName:@"Debugging Tools"];
    [group setProperty:@"Danger! Here be dragons..." forKey:@"footerText"];
    [array addObject:group];

    PSSpecifier *startBackgroundSign = [PSSpecifier preferenceSpecifierNamed:@"Initiate Background Signing" target:self set:nil get:nil detail:nil cell:PSButtonCell edit:nil];
    startBackgroundSign->action = @selector(startBackgroundSign:);

    [array addObject:startBackgroundSign];

    return array;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [super tableView:tableView cellForRowAtIndexPath:indexPath];

    // Find the type of cell this is.
    int section = (int)indexPath.section;
    int row = (int)indexPath.row;

    PSSpecifier *represented;
    NSArray *specifiers = [self specifiers];
    int currentSection = -1;
    int currentRow = 0;
    for (int i = 0; i < specifiers.count; i++) {
        PSSpecifier *spec = [specifiers objectAtIndex:i];

        // Update current sections
        if (spec.cellType == PSGroupCell) {
            currentSection++;
            currentRow = 0;
            continue;
        }

        // Check if this is the right specifier.
        if (currentRow == row && currentSection == section) {
            represented = spec;
            break;
        } else {
            currentRow++;
        }
    }

    // Tint the cell if needed!
    if (represented.cellType == PSButtonCell)
        cell.textLabel.textColor = [UIApplication sharedApplication].delegate.window.tintColor;

    return cell;
}

- (id)readPreferenceValue:(PSSpecifier *)value {
    NSString *key = [value propertyForKey:@"key"];

    // The anisette picker must always resolve to one of its listed URLs,
    // otherwise a stale or empty stored value leaves the row blank.
    if ([key isEqualToString:@"anisetteServerURL"]) {
        NSString *stored = [RPVResources preferenceValueForKey:key];
        NSArray *urls = [self anisetteServerURLs];
        if ([urls containsObject:stored]) {
            return stored;
        }
        NSString *fallback = [@"https://" stringByAppendingString:RPVAnisetteDefaultServer];
        return [urls containsObject:fallback] ? fallback : [urls firstObject];
    }

    id val = [RPVResources preferenceValueForKey:key];

    if (!val) {
        // Defaults.

        NSString *key = [value propertyForKey:@"key"];

        if ([key isEqualToString:@"resignInLowPowerMode"]) {
            return [NSNumber numberWithBool:NO];
        } else if ([key isEqualToString:@"forceResign"]) {
            return [NSNumber numberWithBool:YES];
        } else if ([key isEqualToString:@"trueBgResign"]) {
            return [NSNumber numberWithBool:NO];
        } else if ([key isEqualToString:@"heartbeatTimerInterval"]) {
            return [NSNumber numberWithInt:2];
        } else if ([key isEqualToString:@"shouldAutoRevokeIfNeeded"]) {
            return [NSNumber numberWithBool:NO];
        }

        return nil;
    } else {
        return val;
    }
}

- (void)setPreferenceValue:(id)value specifier:(PSSpecifier *)specifier {
    NSString *key = [specifier propertyForKey:@"key"];
    NSString *notification = specifier.properties[@"PostNotification"];

    [RPVResources setPreferenceValue:value forKey:key withNotification:notification];
}

/////////////////////////////////////////////////////////////////////////////////////
// Button actions
/////////////////////////////////////////////////////////////////////////////////////

- (void)startBackgroundSign:(id)sender {
    [(AppDelegate *)[UIApplication sharedApplication].delegate requestDebuggingBackgroundSigning];
}

@end
