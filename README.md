## ReProvision Reborn
Re-sign applications on your device.

This project aims at making it easier to (re-)sign iOS and Apple Watch applications on a **jailbroken** iOS device, allowing users to avoid the 7-day limit of free certificates associated with their normal Apple account.

### Maintenance status
As of 2026, this fork is maintained with a conservative scope. The current focus is iOS support on jailbroken devices, issue triage, security-sensitive review, and compatibility fixes that can be verified by maintainers or contributors. Compatibility should be verified before assuming support for a specific iOS version, device, or jailbreak environment.

tvOS and macOS are not a current maintenance focus for this fork. Changes in those areas may be accepted if they are well-tested, but users should not assume active support for those platforms.

See [MAINTENANCE.md](MAINTENANCE.md) for the current maintenance scope and triage policy.

### Features
- Automatic re-signing of locally provisioned applications
- Basic settings to configure alerts shown when applications are (re-)signed
- Ability to install any ``.ipa`` file downloaded through Safari from the device
- Support for (re-)signing Apple Watch applications
- 3D Touch menu for starting a new re-signing routine directly from the Homescreen
- URL scheme to install ipa file from URL

Battery optimisations are also in place through the usage of a background daemon to handle automatic signing.

### What this fork changes

This fork carries a set of Apple ID sign-in fixes that upstream does not have. Sign-in is the part that broke once Apple started refusing older anisette attestations, so most of the work went there.

- **2FA happens inside the app.** The code is typed into a field in ReProvision instead of being collected in Settings and handed back through a URL, and the field is marked as a one-time code so the keyboard offers the SMS code.
- **SMS or voice, to a phone number you pick.** Trusted numbers are listed as Apple returns them, with the delivery mode chosen per number.
- **Remote Mac anisette on every iOS version.** Upstream only uses it on iOS 17+ and leaves older jailbreaks on the device's own AKD. AKD cannot reach its ADI keys on these jailbreaks, so every request carries the same `X-Apple-I-MD-M` and Apple answers -22410 / -80046.
- **One ADI identity that survives a relaunch.** The anisette server provisions an `adi_pb` once and the device keeps it, so the identity Apple sees stays fixed while the one-shot attestation stays fresh. Relaunching no longer invalidates the saved token (the portal's resultCode 1100) and no longer asks for the password and a 2FA code again. The older endpoints that hand out a throwaway Mac per request are what made this unavoidable before, and the ones reporting old ADI routing info were rejected with -36607.
- **The 2FA exchange holds together.** `/auth`, `verify/phone` and `verify/phone/securitycode` use JSON content negotiation, the whole exchange shares one session so the cookies tie the steps together, and a code is only reported as wrong when Apple returns -21669 instead of treating any 400 that way.
- **The token is presented by the identity that earned it.** Developer Services requests use the same anisette identity that minted the GS token; a mismatch is what made the portal answer 1100 and drop the session.
- **Sign-in diagnostics go to a file.** `/var/mobile/Documents/ReProvision-2FA.log` records the GSA steps, attestation fingerprints and portal result codes. iOS 13 here has no syslogd and no `log` tool, so there was nowhere else to look.
- **The anisette server is a picker, not a text field.** Four known v3 servers are listed under Settings → Advanced. They all speak the same protocol, and the device keeps its own ADI identity, so switching one only costs you a fresh sign-in.
- **Firebase is gone**, and the deb now packages on macOS 10.15.

Sign-in and re-signing were verified end to end on iOS 13.4.1.

## URL scheme
ReProvision Reborn supports URL scheme.

```
reprovision://install?url=<IPA URL>
```

## Notes
[The original project, ReProvision](https://github.com/Matchstic/ReProvision), has been EOL after Apple changed the process of application provisioning on their servers. This fork of ReProvision attempts to maintain the project and get it up-to-date with support for iOS 13 and above, which also explains the rename of the project.

Although this is an attempt at resurrecting the project, I ask that you **do not bother** the original developer about specific updates made to **this** fork, since they're no longer behind the project.

### Support
Attempting to maintain this fork comes at the cost of "dropping" tvOS and macOS support, since other viable options, such as [AltStore](https://github.com/rileytestut/AltStore) and AltDeploy are available for their respective platforms; the main focus of this fork is iOS.

Furthermore, while re-distribution of this software is allowed, support for modified versions of this software will not be provided.  

### Account Handling
Like most provisioning software, ReProvision supports free and paid development Apple accounts. While credentials are stored in the device's Keychain for subsequent re-use, they're only sent to Apple's iTunes Connect API for authentication.

### Security-sensitive areas
This project handles several security-sensitive workflows, including Apple account authentication, Keychain-stored credentials, provisioning API calls, code signing, URL scheme IPA installation, and the background signing daemon.

Changes touching these areas should be reviewed carefully and tested against the relevant signing and installation flows. The project does not claim compatibility with untested Apple service changes or platform updates.

### AltStore vs ReProvision
This fork of ReProvision uses the same techniques that AltStore uses to tackle provisioning, and by no means should be considered as a competitor.

### Contributing
Pull requests that add a focused feature, fix a reproducible bug, improve compatibility, or harden security-sensitive behavior are welcome. Check out the [contributing guidelines](CONTRIBUTING.md) for further information.

## Building
As long as you have standard libraries for Xcode projects, the only dependencies you need are [CocoaPods](https://github.com/CocoaPods/CocoaPods), [Git](https://git-scm.com/downloads), and [iOSOpenDev](https://github.com/Matchstic/iOSOpenDev.git). You can build the project with 3 simple steps
1. ``git clone https://github.com/sohsatoh/ReProvision-Reborn.git``
2. ``pod install`` in the project's root directory
3. Open ``ReProvision.xcworkspace``, and roll from there

## License and Third-Party Libraries
Licensed under the AGPLv3 license. This project occupies specific third-party libraries, which have all been listed (and given credit to) in this [notice](https://raw.githubusercontent.com/sohsatoh/ReProvision-Reborn/master/iOS/HTML/openSourceLicenses.html).

The software, ReProvision Reborn (and by extension, ``libReprovision`` as found in ``/Shared/``), and all consecutive copies of the software, are provided without warranty and AS-IS. **This project is NOT intended for piracy.**

Special thanks to [Matchstic](https://github.com/Matchstic) for originally developing ReProvision, and [rileytestut](https://github.com/rileytestut) for his amazing work on AltStore.
