# Changelog

## v0.8.12 - 2026-11-26

Apple ID sign-in rewrite. Signing itself was fine; the parts that touch Apple's authentication servers were not, and this release replaces them.

- **2FA inside the app.** The verification code is entered in ReProvision instead of being collected in Settings and passed back through a URL. The field is marked as a one-time code so the keyboard offers the code from Messages.
- **SMS or voice, to the number you choose.** Trusted phone numbers are listed as Apple returns them, and the delivery mode is picked per number.
- **Remote Mac anisette on every iOS version.** It was previously limited to iOS 17 and newer, which left older jailbreaks on the device's own AKD. AKD cannot reach its ADI keys there, so every request carried the same `X-Apple-I-MD-M` and Apple rejected the sign-in with -22410 / -80046.
- **A device identity that survives a relaunch.** The anisette server provisions an `adi_pb` once and the device keeps it, so the identity Apple sees stays fixed while the one-shot attestation stays fresh. Cold starts no longer invalidate the saved token (portal resultCode 1100) and no longer ask for the password and a 2FA code again.
- **Fixed the 2FA exchange.** `/auth`, `verify/phone` and `verify/phone/securitycode` now use JSON content negotiation, all three share one session so cookies tie them together, and a code is only reported as wrong when Apple returns -21669 rather than on any HTTP 400.
- **Fixed "session expired" after 2FA.** Developer Services requests present the same anisette identity that minted the GS token; the mismatch was what made the portal answer 1100 and drop the session.
- **Sign-in diagnostics in a file.** `/var/mobile/Documents/ReProvision-2FA.log` records the GSA steps, attestation fingerprints and portal result codes. iOS 13 has no syslogd and no `log` tool, so there was nowhere to look before.
- **The anisette server is a picker.** Four v3 servers are listed under Settings → Advanced instead of a free-text URL. They all speak the same protocol and the identity lives on the device, so switching one only costs a fresh sign-in.
- Removed tracked pre-edit backups from the repository and ignored the pattern.

Verified end to end on iOS 13.4.1: sign in once with 2FA, force-quit, relaunch, and re-sign without signing in again.

## v0.8.4 - 2026-06-05

Repository maintenance release. No application binary is attached to this release.

- Documented the current conservative maintenance scope.
- Added security reporting guidance for sensitive workflows.
- Added structured issue templates for reproducible bug reports and non-sensitive security hardening suggestions.
- Added a best-effort DevSkim security scanning baseline.
