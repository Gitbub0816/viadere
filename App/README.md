# Viadere for iOS

SwiftUI app (iOS 17+, Swift 6) plus its extensions. **Security is the first requirement; the UI follows the brand
exactly** (charcoal / ivory / champagne, the `via` ribbon, hairlines, generous whitespace, custom components from
`Shared/DesignSystem` instead of stock chrome).

```
App/
  project.yml                 XcodeGen spec (single source of truth for the Xcode project)
  Configs/                    xcconfig: team id, API URL, APNs environment, Debug-only ATS switch
  Resources/                  Asset catalog (icon, brand art, semantic colors) + Outfit fonts
  Shared/DesignSystem/        ViadereMark, ViadereDesignSystem (moved from Design/swift) + ViadereComponents
  Shared/Runtime/             Configuration bootstrap, notification-category builders (app, NSE, clip)
  Shared/LiveActivity/        ActivityKit attributes (app + widgets)
  Shared/UI/                  Pieces shared by the app and the App Clip (connect review, key window)
  Shared/Privacy/             PrivacyInfo.xcprivacy (app, clip, watch)
  Viadere/                    The app (Onboarding, Home, Approval, Connect, Business, Messages, Settings, Security, Push)
  ViadereNotificationService/ UNNotificationServiceExtension: opaque push -> rich, actionable notification
  ViadereNotificationContent/ Custom compact approval card for sign-in / approval notifications
  ViadereWidgets/             Live Activities + Dynamic Island (order, delivery, flight, appointment)
  ViadereClip/                App Clip com.viadere.app.Clip: quick connect for /c/{code}
  ViadereWatch/               watchOS companion: compact approvals list
Packages/ViadereKit           All non-UI logic (API client, keys, approvals, notification mapping, view models). Tested on Linux.
Packages/ViadereCore          Shared contract (models, routes, signers). Not modified by the app.
```

## Generate and run

```sh
brew install xcodegen
cd App
cp Configs/Local.xcconfig.example Configs/Local.xcconfig   # then set DEVELOPMENT_TEAM
xcodegen
open Viadere.xcodeproj
```

Requires Xcode 16+ (Swift 6.0 language mode). Run the `Viadere` scheme on a device for Secure Enclave keys; on the
simulator Debug builds fall back to clearly marked **software keys** (`SoftwareDeviceKeyStore`, compiled out of
Release, reported to the server as `hardwareBacked: false`).

Previews: every screen has `#Preview`s backed by `MockViadereAPI` (in-memory server that verifies enrollment proofs and
signed decisions with ViadereCore's real verifiers).

### Local server

Debug uses `http://localhost:8080` (`Configs/Debug.xcconfig`). Plain HTTP is allowed **only** there:

- `Configs/Debug.xcconfig` defines `VIADERE_PLIST_DEFS = VIADERE_LOCAL_DEV=1`. The hand-written, preprocessed
  `Info.plist` of the networking targets (app, notification service, clip) adds `NSAllowsLocalNetworking` and a
  `localhost` exception inside `#ifdef VIADERE_LOCAL_DEV`. Release defines nothing: **ATS has no exceptions**.
- `ViadereConfiguration.resolve` additionally refuses `http` unless built with `DEBUG` *and* the host is loopback/`.local`.

Override the server with `VIADERE_API_BASE_URL` in `Configs/Local.xcconfig`.

## Configuration checklist

| What | Where |
|---|---|
| Team id | `Configs/Local.xcconfig` (`DEVELOPMENT_TEAM`) |
| Server URL | `VIADERE_API_BASE_URL` in `Configs/*.xcconfig` (read from Info.plist key `ViadereAPIBaseURL`) |
| **Certificate pins** | `ViadereConfiguration.productionPinning` in `Packages/ViadereKit/.../ViadereConfiguration.swift`. **TODO before release:** replace the two `REPLACE_ME_*` placeholders with the SPKI SHA-256 of the current key and a backup key (command in `PinningConfiguration`). Until then Release builds fail closed. |
| Bundle ids | `com.viadere.app`, `.NotificationService`, `.NotificationContent`, `.Widgets`, `.Clip`, `.watchkitapp` |
| App group | `group.com.viadere.shared` (app + notification service) |
| Keychain group | `$(AppIdentifierPrefix)com.viadere.shared` (app + notification service); the clip keeps its own private keychain |
| Entitlements | associated domains (`applinks`, `webcredentials`, `appclips:viadere.com`), push, time-sensitive notifications, app groups, keychain sharing, parent-application-identifiers (clip) |
| Developer portal | Enable Push, Associated Domains, App Groups, Time Sensitive Notifications, App Clip; register the App Clip experience in App Store Connect |
| Server (viadere.com) | Serve `/.well-known/apple-app-site-association` with `applinks` (`/c/*`, `/l/*`, `/h/*`), `webcredentials` (this app) and `appclips` (the clip) |

Export compliance: `ITSAppUsesNonExemptEncryption = false`. The app uses TLS and CryptoKit/Secure Enclave
**signatures only** (authentication, no data-confidentiality encryption of its own). **Flag for legal review** before the
first submission.

## Security architecture

**Keys.** One Secure Enclave P-256 key per `DeviceKeyPurpose`, non-exportable (`SecureEnclaveKeyStore`):

| Key | Access control | Used for |
|---|---|---|
| `request` | `privateKeyUsage` | silently signs every API request (`VIADERE-SIG-V1`) |
| `approvalUserPresence` | `privateKeyUsage + userPresence` | standard approvals (Face ID/Touch ID **or** passcode) |
| `approvalBiometric` | `privateKeyUsage + biometryCurrentSet` | high/critical approvals; **invalidated when biometrics change** |

Approval keys are `WhenUnlockedThisDeviceOnly`. The request key and the session tokens are
`AfterFirstUnlockThisDeviceOnly` so the notification service extension can fetch interaction details while the phone is
locked (it can read details but can never approve: it has no user-presence key). If a key is invalidated,
`EnrollmentHealth` reports `needsReenrollment` and the app shows the re-enrollment screen; the old device is revoked
best-effort and approvals are paused. Enrollment proves possession of every key (`VIADERE-ENROLL-V1`).

**Requests.** `APIClient` signs every `deviceSigned*` request with `RequestSigner` (fresh timestamp and nonce on each
attempt) and sends bearer tokens only to bearer routes. `401` triggers one **single-flight** refresh
(`SessionManager`), serialized across the app and extensions with a file lock because refresh tokens are single-use and
rotated. Two consecutive `signature_invalid` responses mean the device was revoked: everything local is wiped.

**Approvals.** `ApprovalService` builds a `DecisionPayload`, picks the key from `AssurancePolicy` (never weaker),
signs with an `LAContext` whose reason names the business and amount ("Approve $285.28 at Northfield Market"), and
submits. Sensitive kinds (`authenticate`, `authorize`, unknown) are **never approved from a notification action**:
the action opens the secure sheet (`.foreground` + authentication required). Only refusals (deny/report) can run from
the lock screen, and only `choose`/`confirm`/`acknowledge`/`reply` at low assurance run inline. Slide-to-approve is used
for money and high-risk sign-ins. Expired or already-handled requests show a clear state. While the screen is being
recorded or mirrored the sheet shows a notice and approving is paused (denying never is).

**Storage and privacy.** Tokens, device record and keys live in the Keychain (`ThisDeviceOnly`), never in defaults or
logs. Sign-out, account deletion and device revocation wipe tokens, keys, device record, preferences and the keychain
service. `os.Logger` is wrapped (`ViadereLog`) so every dynamic value is `.private`. The app switcher shows a plain
cover (`PrivacyShield`). Optional Face ID app lock with a short grace period. Copied codes use
`UIPasteboard` with `localOnly` and a 60-second expiry; sensitive text is not selectable; approval details are
`privacySensitive`.

**Network.** Ephemeral `URLSession`, no URL cache, no cookies, TLS 1.2+ (server should negotiate 1.3), SPKI SHA-256
pinning with a backup pin in `PinningSessionDelegate` after normal trust evaluation. Strict ATS.

**Passkeys.** `ASAuthorizationPlatformPublicKeyCredentialProvider` for register and sign-in, RP `viadere.com`.

## Push contract (for the server)

Pushes carry **no sensitive data**, only an opaque interaction id:

```json
{ "aps": { "alert": { "title": "Viadere", "body": "Open Viadere to review a request." }, "mutable-content": 1,
           "category": "viadere.unknown", "thread-id": "business.<businessId>", "interruption-level": "time-sensitive" },
  "v": 1, "iid": "<interaction uuid>" }
```

The notification service extension fetches `GET /v1/interactions/{iid}` (device-signed), renders it with
`ChannelRenderer.notification`, registers the per-interaction `viadere.choose.<id>` category and attaches a compact card
(`userInfo["viadere.card"]`) for the content extension. Silent status pushes (`content-available`, same `iid`) start or
update Live Activities; `pushType: .token` update tokens and the iOS 17.2 push-to-start token are registered through
`/v1/live-activities/tokens`; the APNs token through `/v1/push/apns-token`.

## Screens (P2 scope, structured for P3–P5)

Onboarding (animated mark, passkey, device enrollment, notification priming, optional phone link with OTP) ·
Home · Connect (`@handle`, auto-formatted codes with I→1/O→0, name search, QR scanner, universal links, verified card,
purpose-scoped consent) · Business detail · **Approval sheet** · Messages (threads, structured `choose` chips,
composer) · Settings/Security (devices, app lock, linked phones, consent history, sessions, sign out, delete).

## Not verified by compilation

This repository was authored on Linux, where there is no Xcode or iOS SDK. **Everything under `Packages/ViadereKit`
that is platform-neutral compiles and is covered by `swift test` (124 tests).** The following were written carefully
against the iOS 17/18 SDK but never compiled; build them first in Xcode and expect a few mechanical fixes:

1. SwiftUI/UIKit code in `Viadere/`, `Shared/`, the extensions, widgets, clip and watch (only syntax-parsed).
2. `Keys/SecureEnclaveKeyStore.swift`, `Platform/KeychainSecretStore.swift`, `Platform/PinningSessionDelegate.swift`,
   `Platform/ApplePasskeyService.swift`, `Platform/SystemServices.swift`, `ViadereServices.live` (Apple-only, guarded).
3. Swift 6 strict-concurrency diagnostics around UIKit/UserNotifications/WatchConnectivity delegates (`@preconcurrency`
   conformances are used; if needed set `SWIFT_VERSION` to 5 for the UI targets).
4. The preprocessed Info.plist approach for the Debug-only ATS exception (`INFOPLIST_PREPROCESS`, `-traditional`).
5. `@Observable` view models (compile on Linux as plain classes because Observation does not link there).
6. Passkeys inside an App Clip, Live Activity push-to-start, the Dynamic Island layout, and the content-extension card.
7. XcodeGen spec details (extension embedding, on-demand-install-capable type, watch embedding).
