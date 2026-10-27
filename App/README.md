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
  Viadere/                    The app (Onboarding, Home, Activity, Rewards, Wallet, Approval, Connect, Business, Messages,
                              Household, Consent, Settings, Security, Push)
  ViadereNotificationService/ UNNotificationServiceExtension: opaque push -> rich, actionable notification
  ViadereNotificationContent/ Custom compact approval card for sign-in / approval notifications
  ViadereWidgets/             Live Activities + Dynamic Island (order, delivery, flight, appointment), branded compact/expanded/lock layouts
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
| **Certificate pins** (build-checked) | `ViadereConfiguration.productionPinning` in `Packages/ViadereKit/.../ViadereConfiguration.swift`. **TODO before release:** replace the two `REPLACE_ME_*` placeholders with the SPKI SHA-256 of the current key and a backup key (command in `PinningConfiguration`). Until then Release builds fail closed, and `Scripts/check-release-pins.sh` (a pre-build phase of the app and the clip) **fails a Release archive** while the placeholders are present. |
| Bundle ids | `com.viadere.app`, `.NotificationService`, `.NotificationContent`, `.Widgets`, `.Clip`, `.watchkitapp` |
| App group | `group.com.viadere.shared` (app + notification service) |
| Keychain groups | `$(AppIdentifierPrefix)com.viadere.shared` (app + notification service: request key and access token only) and `$(AppIdentifierPrefix)com.viadere.app.approval` (**app only**: the approval keys). The clip keeps its own private keychain and holds a request key only. |
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

Approval keys are `WhenUnlockedThisDeviceOnly` and live in an **app-only keychain access group**: the notification
extensions and the App Clip are not entitled to it and cannot even see those keys. The request key and the access token
are `AfterFirstUnlockThisDeviceOnly` (shared group) so the notification service extension can fetch interaction details
while the phone is locked; the **refresh token** is `WhenUnlockedThisDeviceOnly`, so a locked phone's extension cannot
rotate the session and shows a generic banner instead. If a key is invalidated (`errSecItemNotFound` for a key the device
enrolled), `EnrollmentHealth` reports `needsReenrollment` and the app shows the re-enrollment screen ("Set up again");
approvals are paused until it completes. The old device is **not** revoked beforehand (the server cascades a device revoke
to the caller's session): the enrollment carries `replacesDeviceId` and the server revokes it atomically. A locked or unavailable keychain (`errSecInteractionNotAllowed`, -25308, and
other transient statuses) is **not** invalidation: it reports `unavailable`, the app stays usable and re-checks later.
**Passkey-bound enrollment.** Enrollment proves possession of every key (`VIADERE-ENROLL-V1`) **and of the account's
passkey**: `POST /v1/devices/enroll/begin` returns `{challenge, expiresAt, assertion, assertionOptional}`; unless
`assertionOptional` is true (only right after sign-up or sign-in), `AccountService` performs a user-verified passkey assertion
over `assertion` (checking it carries the same challenge and `userVerification: required`) and sends it in
`POST /v1/devices`. "Set up again" (`EnrollmentPurpose.setUpAgain`) **always** asserts, whatever the server says. Before
the system sheet, `Shared/UI/PasskeyExplanationView` explains why (`PasskeyExplanationGate` bridges it to the account
flow; declining changes nothing). The App Clip uses Core's `clientKind: .appClip` (request key only; the server refuses
approvals from it and expires it); the full app revokes the person's clip devices (read from Core's `Device.clipDevice`
and `revokedAt`) after enrolling. `passkey_assertion_required` is reported as such (never as an expired session).

**Requests.** `APIClient` signs every `deviceSigned*` request with `RequestSigner` (fresh timestamp and nonce on each
attempt) and sends bearer tokens only to bearer routes. `401` triggers one **single-flight** refresh
(`SessionManager`), serialized across the app and extensions because refresh tokens are single-use and rotated. The
`flock` guards only short read-compare-write sections (never network I/O, which risks a `0xdead10cc` kill); the
network call is covered by a short-lived lease file, and it **fails closed**: if the lock file can't be opened or the
lock isn't acquired in time, no refresh runs and a retryable error surfaces. A generation counter stops a refresh that was
in flight at sign-out from resurrecting the session. Two consecutive `signature_invalid` responses mean the device was revoked: everything local is wiped.

**Approvals.** `ApprovalService` builds a **v2** `DecisionPayload` whose `contextDigest` is
`interaction.displayContextDigest()` of the exact interaction the sheet displayed. Before signing it re-fetches, compares
digests and, if the request changed, signs nothing: the sheet re-renders the current details with a notice and clears any
selection (`ApprovalError.contextChanged`). A server `context_mismatch` does the same (refresh, show, never auto-retry).
An interaction with a `schemaVersion` newer than the app supports shows "Update Viadere to respond to this request": it can
be denied (v1, no digest) but never approved. It picks the key from `AssurancePolicy` (never weaker),
signs with an `LAContext` whose reason names the business and amount ("Approve $285.28 at Northfield Market"), and
submits. Sensitive kinds (`authenticate`, `authorize`, unknown) are **never approved from a notification action**:
the action opens the secure sheet (`.foreground` + authentication required). Only refusals (deny/report) can run from
the lock screen, and only `choose`/`confirm`/`acknowledge`/`reply` at low assurance run inline. Slide-to-approve is used
for money and high-risk sign-ins. Expired or already-handled requests show a clear state. While the screen is being
recorded or mirrored the sheet shows a notice and approving is paused (denying never is).

**New-device cool-down.** A device enrolled while another trusted device exists has `approvalsLockedUntil` (24 h). Home and
the approval sheet say so calmly ("For your security, this iPhone can approve high-risk requests after {time}, or confirm
it from your other device."); high and critical approvals are paused before any Face ID prompt (`CoolDownPolicy`), while
deny, decline and report always work. `device_cool_down` from the server is handled the same way. In Settings → Trusted
devices a trusted device (not itself cooling down, with a Face ID key) can **Confirm this device**:
`ConfirmationService` signs `ConfirmationProof` (subject `device`) with the biometric approval key and posts it to
`POST /v1/devices/{id}/confirm`; likewise `POST /v1/phone-links/{id}/confirm` (subject `phoneLink`) for a phone linked from
an SMS token, whose `usableFrom` is shown in Linked phones.

**Storage and privacy.** Tokens, device record and keys live in the Keychain (`ThisDeviceOnly`), never in defaults or
logs. Sign-out first revokes this device on the server (best effort, bounded), then removes delivered notifications, ends Live
Activities, clears the watch context and the dynamic notification categories (`LocalResidueCleaner`), then wipes tokens,
keys, device record, preferences and the keychain service; account deletion and device revocation wipe the same way. `os.Logger` is wrapped (`ViadereLog`) so every dynamic value is `.private`. The app switcher shows a plain
cover (`PrivacyShield`). Optional Face ID app lock with a short grace period: the lock is shown in its **own window above everything** (sheets,
alerts), locking tears down presented screens (`AppModel.lock()` + content keyed on `lockEpoch`), and deep links and
notification opens that arrive while locked are queued and replayed after the unlock. Copied codes use
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

The notification service extension fetches `GET /v1/interactions/{iid}` (device-signed), renders it, registers the
per-interaction `viadere.choose.<id>` category and, **only when the user turned on "Details on the lock screen"**
(`richNotificationPreviews`, off by default), shows the facts and attaches a compact card (`userInfo["viadere.card"]`)
for the content extension. By default an approval or sign-in shows only "Approval requested by {business}".

**Business-supplied text.** Every string a business controls (names, merchants, services, locations, notes, labels) goes
through one sanitizer, `UntrustedText` (ViadereKit): bidi controls (including U+061C), U+180E, zero-width and control
characters are removed, line breaks become spaces, stacked combining marks and length are capped, and a name that imitates
"Viadere" is shown quoted and attributed (`Business "Viadere Security"`). It is applied in the Face ID prompt, approval
sheet, notification, card, watch list, Live Activity and Activity/Home/Messages surfaces; the amount always comes first so
truncation can never hide it. The card's verification badge uses the real `isVerified` flag.

**SMS account links.** Only the https universal link `https://viadere.com/l/{token}` is accepted (no `viadere://l/`). The
confirmation sheet first previews what the token would link (Core's `SMSLinkPreview`: masked number, expiry), warns, and
links only after an explicit "This is my phone"; redeem sends `{token, confirmPhoneLast4, confirmMaskedPhone}` (both from the
preview) and the result shows when the number starts working (`usableFrom`). Silent status pushes (`content-available`, same `iid`) start or
update Live Activities; `pushType: .token` update tokens and the iOS 17.2 push-to-start token are registered through
`/v1/live-activities/tokens`; the APNs token through `/v1/push/apns-token`.

## Screens (P2 scope, structured for P3–P5)

Onboarding (animated mark, passkey, device enrollment, notification priming, optional phone link with OTP) ·
Home · Connect (`@handle`, auto-formatted codes with I→1/O→0, name search, QR scanner, universal links, verified card,
purpose-scoped consent) · Business detail · **Approval sheet** · Messages (threads, structured `choose` chips,
composer) · Settings/Security (devices, app lock, linked phones, consent history, sessions, sign out, delete).

## P3 utility features

Five tabs: Home, **Activity**, Connect, Messages, Settings. Rewards hang off Home and Business detail; Household and
Acknowledgments live under Settings → Trust and records. Every new screen is built from `Shared/DesignSystem`
(`ViadereRowGroup`, `ViadereRow`, `ViadereBadge`, `ViadereChip`, `ViadereProgressBar`, …); the only stock Apple UI is
Wallet's `PKAddPassButton` / `PKAddPassesViewController`, which Apple requires for adding passes. Logic lives in
ViadereKit (view models, eligibility display, countdowns, Live Activity eligibility, delegation validation) and is
tested on Linux; the SwiftUI files only lay it out. All of it is driven by `MockViadereAPI.p3Demo()` in `#Preview`s.

| Area | Files | Rules |
|---|---|---|
| **Rewards and loyalty** | `Features/Rewards/*`, Kit `Rewards/*` | Eligibility is **server-computed** (`RewardEligibility`); the client shows it and offers the single `nextAction` the server names. It never reads `RewardRecurrence`, the device clock or the points balance to decide. A verdict older than 5 minutes (device clock to device clock) is refetched before an action is offered. Claim and redeem are device-signed (`deviceSignedBearer`) and re-checked by the server (`409` refreshes the list). Redemption shows a server-issued, single-use code and QR with a countdown; the code lives only in memory, is wiped at expiry, on disappear, on backgrounding and while the screen is recorded or mirrored, and a screenshot raises a notice. Never cached (POST, ephemeral session) and copied only through `SecurePasteboard`. Loyalty enrollment and account linking start from Business detail. |
| **Apple Wallet** | `Features/Wallet/*`, Kit `Wallet/*`, `Platform/PassKitWalletLibrary.swift` | The server signs passes. The app downloads the `.pkpass` (`GET /v1/wallet/passes/{id}`), checks its size, validates it with `PKPass(data:)`, confirms it is the pass the metadata promised (type id and serial), then presents `PKAddPassesViewController`. "In Wallet" is read from `PKPassLibrary.pass(withPassTypeIdentifier:serialNumber:)` and refreshed when the sheet closes and when the app becomes active. Loyalty cards, coupons, event tickets, boarding passes and reservations. |
| **Activity** | `Features/Activity/*`, Kit `Activity/*` | Built from `status`, `ticket` and `confirm` interactions, merged by `correlationId`, grouped by business, filtered by category. Appointment actions (confirm, cancel, reschedule, check in) are the pending interactions the business sent, labeled by its `requestedActions`; a missing reschedule offer falls back to a message. Travel shows delays and cancellations and rebooking prompts; anything that can change money or identity, anything at sensitivity `standard` or above, and every travel prompt opens the secure approval sheet instead of answering inline (`ActivityActionRouter`). Events show tickets, schedule changes and venue notes. Live Activities start and update only for `LiveActivityPolicy`-eligible, ongoing, unexpired statuses (`ActivityLiveEligibility`), never marketing or rewards. |
| **Live Activity / Dynamic Island** | `ViadereWidgets/ViadereLiveActivityWidget.swift` | Compact leading is the via mark; trailing is a live countdown when the ETA is within 99 minutes, otherwise a status word. Expanded shows business, headline, detail, a champagne progress line ending in the via dot, and the next step. Wording comes from `LiveActivityPresentation` (tested). |
| **Household (delegation)** | `Features/Household/*`, Kit `Delegation/*` | Grants given and received, invite by single-use code (no account-id lookup), scoped role, per-purpose and per-business scope, expiry (max one year; sensitive scopes max 30 days), revocation and an audit trail. Nothing is preselected and sensitive access is never inherited. Granting `security` or `accountService` shows a clear warning and requires a **Face ID signature from the `approvalBiometric` key** over the exact scope (`DelegationStepUpProof`, verified by the server), so the step-up cannot be replayed on a wider grant. Delegates can never approve sign-ins or payments (SECURITY.md). Delegated requests carry "On behalf of" in the sheet, the Face ID reason and the audit trail. |
| **Acknowledgments** | `Features/Consent/*`, Kit `Consent/*` | The `acknowledge` interaction shows the document summary, version, source and an https-only link, then a receipt with the **server's** timestamp, document version and a reference. Copy says it records a reading and is not a legal signature. Settings → Acknowledgments lists the server's records. |

### Wallet entitlement

Adding passes with `PKAddPassesViewController` needs **no entitlement**. The `com.apple.developer.pass-type-identifiers`
entitlement (for example `$(TeamIdentifierPrefix)pass.com.viadere.*`) is only needed to read or update passes beyond what
this app added, so it is **not requested**. The pass type id and its signing certificate belong to the server. If testing
shows "In Wallet" going stale for passes added outside the app, add the entitlement to `Viadere/Viadere.entitlements`
via `project.yml` and the pass type ids in the Developer portal.

### Server contract

All `deviceSignedBearer`. Every route below lives in ViadereCore's `APIRoutes` (shared with the server); a `404` still means "the business has no such feature" and hides it.

| Route | Returns |
|---|---|
| `GET /v1/rewards/overview` | `RewardsOverview` (accounts + `RewardEntry` with server `eligibility`) |
| `GET /v1/loyalty/{businessId}` / `POST .../enroll` | `LoyaltyProgramOverview` / `LoyaltyAccount` (enroll body carries the accepted `termsVersion`) |
| `POST /v1/rewards/{id}/claim` | `RewardEntry` (`409` if no longer claimable) |
| `POST /v1/rewards/{id}/redeem` (**Core**) | `RewardRedemption` (single-use code, about 2 minutes; `409` if not eligible) |
| `GET /v1/wallet/passes`, `POST /v1/wallet/passes` | `[WalletPassMetadata]`, issue a pass |
| `GET /v1/wallet/passes/{id}` (**Core**) | signed `.pkpass` bytes |
| `GET /v1/interactions` (**Core**) | Activity feed source (`status`, `ticket`, `confirm`, correlated by `correlationId`) |
| `POST /v1/live-activities/tokens` (**Core**) | Live Activity push-to-start and update tokens |
| `GET /v1/household`, `GET /v1/household/audit` | `HouseholdOverview`, `[HouseholdAuditEntry]` |
| `POST /v1/household/invitations` (+ `/preview`, `/accept`) | `DelegationInvitation` / `DelegationInvitationPreview` / `HouseholdGrant` |
| `DELETE /v1/delegations/{id}` (**Core**) | revoke |
| `GET /v1/acknowledgments` | `[AcknowledgmentRecord]` (acknowledgments themselves are signed `acknowledge` decisions via **Core** `interactions/{id}/decide`) |

## Not verified by compilation

This repository was authored on Linux, where there is no Xcode or iOS SDK. **Everything under `Packages/ViadereKit`
that is platform-neutral compiles and is covered by `swift test` (260 tests).** The following were written carefully
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
8. P3 UI: everything under `Features/Rewards`, `Activity`, `Wallet`, `Household`, `Consent`, the reworked widget, and the
   PassKit calls (`PKAddPassButton`, `PKAddPassesViewController`, `PKPass(data:)`, `PKPassLibrary`). `Text(timerInterval:)`
   in the Dynamic Island, `NavigationLink` destinations inside the typed Home stack, and Swift 6 isolation around
   `PKAddPassesViewControllerDelegate` (`WalletPresenter`) are the likeliest to need a mechanical fix.
