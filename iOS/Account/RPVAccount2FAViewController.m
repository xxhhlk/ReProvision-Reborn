//
//  RPVAccount2FAViewController.m
//  iOS
//
//  Created by Matt Clarke on 07/03/2018.
//  Copyright © 2018 Matt Clarke. All rights reserved.
//

#import "RPVAccount2FAViewController.h"
#import "RPVAccountTeamIDViewController.h"
#import "RPVAccountFinalController.h"
#import "RPVAccountChecker.h"

@interface RPVAccount2FAViewController ()

@property (nonatomic, strong) NSString *emailAddress;
@property (nonatomic, strong) NSArray *_interimTeamIDArray;
@property (nonatomic, strong) NSURLCredential *credentials;
@property (nonatomic) BOOL requestedCode;
@property (nonatomic) BOOL authenticationInProgress;
@property (nonatomic, strong) UIButton *requestCodeButton;
@property (nonatomic, strong) UISegmentedControl *deliveryControl;

@end

@implementation RPVAccount2FAViewController

- (void)viewDidLoad {
    [super viewDidLoad];

    // The storyboard has no code field, so add one under the subtitle.
    if (!self.passwordTextField) {
        UITextField *codeField = [[UITextField alloc] initWithFrame:CGRectZero];
        codeField.translatesAutoresizingMaskIntoConstraints = NO;
        codeField.borderStyle = UITextBorderStyleRoundedRect;
        codeField.placeholder = @"6-digit verification code";
        codeField.keyboardType = UIKeyboardTypeNumberPad;
        codeField.textAlignment = NSTextAlignmentCenter;
        codeField.font = [UIFont monospacedDigitSystemFontOfSize:24.0 weight:UIFontWeightRegular];
        codeField.accessibilityLabel = @"Apple verification code";

        [self.view addSubview:codeField];
        [NSLayoutConstraint activateConstraints:@[
            [codeField.topAnchor constraintEqualToAnchor:self.subtitleLabel.bottomAnchor constant:28.0],
            [codeField.leadingAnchor constraintEqualToAnchor:self.view.layoutMarginsGuide.leadingAnchor],
            [codeField.trailingAnchor constraintEqualToAnchor:self.view.layoutMarginsGuide.trailingAnchor],
            [codeField.heightAnchor constraintEqualToConstant:52.0],
        ]];
        self.passwordTextField = codeField;
    }

    // Choose how Apple delivers the code: a text message or a phone call.
    UISegmentedControl *delivery = [[UISegmentedControl alloc] initWithItems:@[@"Text Message", @"Phone Call"]];
    delivery.translatesAutoresizingMaskIntoConstraints = NO;
    delivery.selectedSegmentIndex = 0;
    [self.view addSubview:delivery];
    [NSLayoutConstraint activateConstraints:@[
        [delivery.topAnchor constraintEqualToAnchor:self.passwordTextField.bottomAnchor constant:16.0],
        [delivery.leadingAnchor constraintEqualToAnchor:self.passwordTextField.leadingAnchor],
        [delivery.trailingAnchor constraintEqualToAnchor:self.passwordTextField.trailingAnchor],
    ]];
    self.deliveryControl = delivery;

    // Repurpose the Settings redirect button into a resend action.
    for (UIView *subview in self.view.subviews) {
        if (![subview isKindOfClass:[UIButton class]]) {
            continue;
        }
        UIButton *button = (UIButton *)subview;
        if ([[button titleForState:UIControlStateNormal] isEqualToString:@"Continue Authentication"]) {
            self.requestCodeButton = button;
            [button setTitle:@"Send Code" forState:UIControlStateNormal];
            break;
        }
    }

    [self.passwordTextField addTarget:self
                               action:@selector(textFieldDidChange:)
                     forControlEvents:UIControlEventEditingChanged];

    // Tapping anywhere outside the field dismisses the number pad.
    UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc] initWithTarget:self
                                                                         action:@selector(dismissKeyboard)];
    tap.cancelsTouchesInView = NO;
    [self.view addGestureRecognizer:tap];

    self.titleLabel.text = @"2-Factor Authentication";
    self.subtitleLabel.text = @"Choose how Apple should send the code, then tap Send Code.";
    self.confirmBarButtonItem.enabled = NO;

    if (@available(iOS 13.0, *)) {
        self.view.backgroundColor = [UIColor systemBackgroundColor];
        self.titleLabel.textColor = [UIColor labelColor];
        self.subtitleLabel.textColor = [UIColor labelColor];
    } else {
        self.view.backgroundColor = [UIColor whiteColor];
        self.titleLabel.textColor = [UIColor blackColor];
        self.subtitleLabel.textColor = [UIColor blackColor];
    }
}

- (void)dismissKeyboard {
    [self.view endEditing:YES];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];

    [self.navigationController.navigationBar setBackgroundImage:[UIImage new] forBarMetrics:UIBarMetricsDefault];
    [self.navigationController.navigationBar setShadowImage:[UIImage new]];

    // Request one code for this screen. The code is validated against the same
    // SRP session that asked for it; sending the user to Settings would let
    // AuthKit authenticate a different anisette identity and Apple would ask
    // for 2FA again on the follow-up login.
    if (!self.requestedCode && !self.authenticationInProgress) {
        [self requestVerificationCode];
    }
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
}

- (void)presentTeamIDViewControllerIfNecessaryWithTeamIDs:(NSArray*)teamids credentials:(NSURLCredential*)credential {
    self._interimTeamIDArray = teamids;
    self.credentials = credential;
    if ([teamids count] == 1) {
        [self presentFinalController];
    } else {
        [self performSegueWithIdentifier:@"presentTeamIDController" sender:nil];
    }
}

- (void)presentFinalController {
    [self performSegueWithIdentifier:@"presentFinalController" sender:nil];
}

- (void)showNavigationSpinner {
    UIActivityIndicatorView *spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleGray];
    spinner.hidesWhenStopped = YES;
    if (@available(iOS 13.0, *)) {
        spinner.color = [UIColor labelColor];
    }
    [spinner startAnimating];
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithCustomView:spinner];
}

- (void)restoreNavigationButton {
    self.navigationItem.rightBarButtonItem = self.confirmBarButtonItem;
    [self textFieldDidChange:self.passwordTextField];
}

- (NSString *)selectedDeliveryMode {
    return self.deliveryControl.selectedSegmentIndex == 1 ? @"voice" : @"sms";
}

- (void)requestVerificationCode {
    if (self.authenticationInProgress) {
        return;
    }

    if (![[RPVAccountChecker sharedInstance] hasActiveTwoFactorSession]) {
        self.requestCodeButton.enabled = NO;
        [self changeUIToIncorrectStatus:@"This verification session has finished. Go back and sign in again."];
        return;
    }

    [self dismissKeyboard];

    self.authenticationInProgress = YES;
    self.passwordTextField.text = @"";
    self.requestCodeButton.enabled = NO;
    self.confirmBarButtonItem.enabled = NO;
    self.deliveryControl.enabled = NO;
    [self showNavigationSpinner];

    NSString *deliveryMode = [self selectedDeliveryMode];
    NSString *channel = [deliveryMode isEqualToString:@"voice"] ? @"call" : @"text message";

    [[RPVAccountChecker sharedInstance] requestLoginCodeWithDeliveryMode:deliveryMode completionHandler:^(NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            self.authenticationInProgress = NO;
            self.requestCodeButton.enabled = YES;
            self.deliveryControl.enabled = YES;
            [self restoreNavigationButton];

            if (error) {
                self.requestedCode = NO;
                NSString *message = error.localizedDescription.length > 0
                    ? error.localizedDescription
                    : @"Could not request a verification code. Please try again.";
                [self changeUIToIncorrectStatus:message];
                return;
            }

            self.requestedCode = YES;
            self.subtitleLabel.text = [NSString stringWithFormat:
                @"Enter the six-digit code Apple sent by %@. Requesting another code invalidates older ones.", channel];
            [self.passwordTextField becomeFirstResponder];
        });
    }];
}

- (IBAction)didTapFallbackButton:(id)sender {
    [self requestVerificationCode];
}

- (IBAction)didTapConfirmButton:(id)sender {
    if (self.authenticationInProgress || self.passwordTextField.text.length != 6) {
        return;
    }

    [self dismissKeyboard];

    NSString *code = [self.passwordTextField.text copy];
    self.authenticationInProgress = YES;
    self.passwordTextField.enabled = NO;
    self.requestCodeButton.enabled = NO;
    self.confirmBarButtonItem.enabled = NO;
    self.deliveryControl.enabled = NO;
    [self showNavigationSpinner];

    [[RPVAccountChecker sharedInstance] validateLoginCode:code withCompletionHandler:^(NSString *failureReason, NSString *resultCode, NSArray *teamIDArray, NSURLCredential *credential) {
        dispatch_async(dispatch_get_main_queue(), ^{
            BOOL hasActiveSession = [[RPVAccountChecker sharedInstance] hasActiveTwoFactorSession];
            self.authenticationInProgress = NO;
            self.passwordTextField.enabled = YES;
            self.requestCodeButton.enabled = hasActiveSession;
            self.deliveryControl.enabled = YES;
            [self restoreNavigationButton];

            if (teamIDArray.count > 0 && credential) {
                [self presentTeamIDViewControllerIfNecessaryWithTeamIDs:teamIDArray credentials:credential];
                return;
            }

            NSString *message = failureReason.length > 0
                ? failureReason
                : @"Apple did not accept that verification code. Request a new code and try again.";
            [self changeUIToIncorrectStatus:message];
        });
    }];
}

- (void)changeUIToIncorrectStatus:(NSString*)statusString {
    self.subtitleLabel.text = statusString.length > 0
        ? statusString
        : @"Authentication could not be completed. Please try again.";

    self.passwordTextField.text = @"";
    self.confirmBarButtonItem.enabled = NO;
}

- (void)setupWithEmailAddress:(NSString*)emailAddress {
    self.emailAddress = emailAddress;
}

////////////////////////////////////////////////////////
// UITextFieldDelegate
////////////////////////////////////////////////////////

- (void)textFieldDidChange:(id)sender {
    NSString *text = self.passwordTextField.text ?: @"";
    NSCharacterSet *nonDigits = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
    NSString *digits = [[text componentsSeparatedByCharactersInSet:nonDigits] componentsJoinedByString:@""];
    if (digits.length > 6) {
        digits = [digits substringToIndex:6];
    }
    if (![digits isEqualToString:text]) {
        self.passwordTextField.text = digits;
    }

    self.confirmBarButtonItem.enabled = digits.length == 6 &&
        !self.authenticationInProgress &&
        [[RPVAccountChecker sharedInstance] hasActiveTwoFactorSession];
}

#pragma mark - Navigation

- (void)prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender {
    if ([[[segue destinationViewController] class] isEqual:[RPVAccountTeamIDViewController class]]) {
        RPVAccountTeamIDViewController *teamidController = (RPVAccountTeamIDViewController*)[segue destinationViewController];
        [teamidController setupWithDataSource:self._interimTeamIDArray
                                     username:self.credentials.user
                                  andPassword:self.credentials.password];
    } else if ([[[segue destinationViewController] class] isEqual:[RPVAccountFinalController class]]) {
        NSString *teamID = [[self._interimTeamIDArray firstObject] objectForKey:@"teamId"];
        RPVAccountFinalController *finalController = (RPVAccountFinalController*)[segue destinationViewController];
        [finalController setupWithUsername:self.credentials.user
                                  password:self.credentials.password
                                andTeamID:teamID];
    }
}

@end
