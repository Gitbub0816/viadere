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
  Viadere/                    The app: four tabs (Messages, Alerts, Benefits, Businesses) under one business selector
                              (Organization), plus Onboarding, Activity (Alerts > History), Rewards, Wallet, Approval,
                              Connect (Add business), Business, Household, Consent, Settings (from the context bar),
                              Security, Push
  ViadereNotificationService/ UNNotificationServiceExtension: opaque push -> rich, actionable notification
  ViadereNotificationContent/ Custom compact approval card for sign-in / approval notifications
  ViadereCredentialProvider/  Authenticator credential-provider extension (passkeys iOS 17, one-time codes iOS 18; no network)
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

Requires the latest stable Xcode (27.1; Swift 6 language mode, `SWIFT_VERSION` 6.0). Run the `Viadere` scheme on a device for Secure Enclave keys; on the
simulator Debug builds fall back to clearly marked **software keys** (`SoftwareDeviceKeyStore`, compiled out of
Release, reported to the server as `hardwareBacked: false`).

Previews: every screen has `#Preview`s backed by `MockViadereAPI` (in-memory server that verifies enrollment proofs and
signed decisions with ViadereCore's real verifiers).

### Staging build

The `Staging` configuration (`Configs/Staging.xcconfig`, scheme **Staging**) is Release-grade (no DEBUG, strict ATS) and points at `https://api-staging.viadere.com` with the passkey domain `staging.viadere.com`, the same bundle IDs, APNs sandbox and App Attest `development`. Fill `VIADERE_PIN_PRIMARY` / `VIADERE_PIN_BACKUP` first (`python3 -I Scripts/compute-spki-pins.py api-staging.viadere.com`); `Scripts/check-release-pins.sh` fails a Staging archive while they are placeholders. Full guide, including TestFlight: [`docs/ops/STAGING-SETUP.md`](../docs/ops/STAGING-SETUP.md).

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
| Server URL | `VIADERE_API_BASE_URL` in `Configs/*.xcconfig` (read from Info.plist key `ViadereAPIBaseURL`). Staging also sets `VIADERE_RP_DOMAIN`, `VIADERE_WEB_DOMAIN` (associated domains), `VIADERE_API_PINS` (Info.plist `ViadereAPIPins`) and `VIADERE_APNS_ENVIRONMENT` (`ViadereAPNsEnvironment`), honoured only for a non-production host |
| **Certificate pins** (build-checked) | `ViadereConfiguration.productionPinning` in `Packages/ViadereKit/.../ViadereConfiguration.swift`. **TODO before release:** replace the two `REPLACE_ME_*` placeholders with the SPKI SHA-256 of the current key and a backup key (command in `PinningConfiguration`). Until then Release builds fail closed, and `Scripts/check-release-pins.sh` (a pre-build phase of the app and the clip) **fails a Release archive** while the placeholders are present. |
| Bundle ids | `com.viadere.app`, `.NotificationService`, `.NotificationContent`, `.CredentialProvider`, `.Widgets`, `.Clip`, `.watchkitapp` |
| App group | `group.com.viadere.shared` (app + notification service) |
| Keychain groups | `$(AppIdentifierPrefix)com.viadere.shared` (app + notification service: request key and access token only) and `$(AppIdentifierPrefix)com.viadere.app.approval` (**app only**: the approval keys). The clip keeps its own private keychain and holds a request key only. |
| Entitlements | associated domains (`applinks`, `webcredentials`, `appclips:viadere.com`), push, time-sensitive notifications, app groups, keychain sharing, parent-application-identifiers (clip), **App Attest** (`com.apple.developer.devicecheck.appattest-environment` on the app and the clip, `$(APP_ATTEST_ENVIRONMENT)`: `development` in `Debug.xcconfig`, `production` in `Release.xcconfig`; the server's `APP_ATTEST_ENVIRONMENT` must match) |
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

**Identity hardening (server round 4, `docs/SECURITY.md` §2.5, §2.8, §2.26).**

- **App Attest at enrollment.** `AccountService.enrollThisDevice` generates a **new App Attest key per enrollment** and calls
  `attestKey(keyId, clientDataHash: AppAttestBinding.clientDataHash(consumerId:challenge:keys:))` over **exactly the keys it
  sends** (the app's three keys; the Clip's request key only), then sends `appAttest {keyId, attestation}` (app and Clip).
  `DCAppAttestService` sits behind `AppAttestProviding` (`DeviceCheckAppAttest`, guarded by `#if canImport(DeviceCheck)`;
  `MockAppAttest` for tests, whose "attestation" the mock server checks against the request's own key list). Where App Attest
  is unsupported (the Simulator) **DEBUG builds enroll without it; Release reports `AppAttestError.unsupported`**.
  `403 attestation_required` reads "This iPhone couldn't be verified. Make sure you're using the App Store version of Viadere."
- **Signed refresh.** `POST /v1/auth/refresh` is declared `.none` in Core, so `APITokenRefresher` asks the executor to sign it
  explicitly (`RequestExecutor.run(..., signsWhenEnrolled: true)`): when a device is enrolled it carries the `Viadere-*` headers
  signed with the request key and **no bearer**; with no enrolled device it goes unsigned (a session that has not bound one).
  A `clock_skew` or `replay_detected` answer is retried once, re-signed. A `signature_invalid` answer is reported without
  discarding the session (it says something about this device, not the refresh token). The notification service extension
  gets the same behavior because it builds the same executor over the shared request key and device record.
- **Recovery codes** (`Recovery/*` in Kit, `Shared/UI/RecoveryCodesView`, `Features/Recovery/*`). `AuthSession.recoveryCodes`
  arrives once at registration and is shown on the brand-styled **Save your recovery codes** screen (recovery ID and ten
  codes) with **Copy** (`SecurePasteboard`: local only, expiring), **Save to Files** (the stock share sheet, text only, its own
  Copy excluded) and a required **I saved these**; screenshots raise a notice and the codes hide while the screen is
  recorded or mirrored. The codes live only in `RecoveryCodesViewModel` memory: never in the Keychain, defaults, a file, a
  link, a notification or a log (a test scans everything the stores ever wrote). They are released on confirmation; if the app
  locks while they show they are gone and Settings → Security → **Recovery codes** generates a new set (needs a trusted
  device and a fresh passkey assertion: `recoveryCodesBegin` → assertion → `recoveryCodesRegenerate`; the App Clip shows the
  codes after it creates an account, too). **Lost your devices?** on the welcome and account screens runs
  `AccountRecoveryViewModel`: recovery ID and one code → `recoveryBegin` → new passkey → `recoveryFinish` (a `statusToken`) →
  a hold screen (72 hours, other devices can cancel) → `recoveryComplete` polled when the screen opens and when the app returns
  to the foreground (throttled to once a minute, never a loop) → the replacement codes shown once → sign in with the new
  passkey → enroll this iPhone like any lapsed account's. The `statusToken` (and recovery id) are the only things kept during
  the hold, in the Keychain-backed secret store (`RecoveryHoldStore`), so a relaunch resumes the hold. Every refusal of
  `recoveryBegin` reads the same, so the screen cannot be used to find accounts.
- **Pending device replacement.** "Set up again" stores `Device.replacementSession` as the new session when the server returns
  one (a live old device keeps working; the caller's old session stays bound to it). Settings → Trusted devices shows
  **Replacing this iPhone** / **Being replaced** / **Pending replacement** from `pendingReplacementBy` and
  `pendingReplacementAt`, with a "Not you? Cancel" button (`deviceReplacementCancel`, acts on the new device, needs a trusted
  device that is not the new one).
- **Security notices.** The banner copy is chosen by `SecurityNotice.topic` (`devicePendingReplacement`, `recoveryStarted`,
  `recoveryCancelled`, `recoveryAttemptsLocked`, plus the existing ones) with a generic fallback for unknown topics. A notice
  with `action == .cancelRecovery` shows "Account recovery was started. Not you? Cancel recovery" (`recoveryCancel`);
  `.cancelDeviceReplacement` shows "A new iPhone is replacing this one. Not you? Cancel" (`deviceReplacementCancel`).
  `device_cool_down` is explained, not shown as a failure. The push category **`viadere.security.cancel`** (action "Review",
  foreground, authentication required) is registered at launch; the push has no subject id, so opening the app fetches the
  notices (`AppModel.apply(.open(nil))`, launch and foreground).

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

Adding passes with `PKAddPassesViewController` needs **no entitlement**, but reading them does: `PKPassLibrary`'s
`pass(withPassTypeIdentifier:serialNumber:)` returns `nil` unless the app holds `com.apple.developer.pass-type-identifiers`
for that Pass Type ID (Apple documentation, checked 2026-10-31). The app therefore requests
`$(TeamIdentifierPrefix)$(VIADERE_PASS_TYPE_IDENTIFIER)` (`Configs/Shared.xcconfig`, default `pass.com.viadere.wallet`, the
server's `PASS_TYPE_IDENTIFIER`). **Owner:** in the Developer portal enable the Wallet capability on the `com.viadere.app` App ID
and select that Pass Type ID, then regenerate the profiles; signing fails until then. The pass signing certificate belongs to
the server only (docs/WALLET.md). Wallet screens show a "Beta" label while `VIADERE_WALLET_BETA_LABEL = YES` (an open owner decision).

### Verify with Wallet entitlement and the Didit SDK (WP3)

Verify offers two ways to prove an age threshold or an identity attribute (`App/Viadere/Features/Verify`):

1. **An ID in Apple Wallet** (`PKIdentityAuthorizationController`, iOS 16+). Requires the `com.apple.developer.in-app-identity-presentment`
   entitlement, which **Apple grants per bundle ID** after a request by the Account Holder
   (<https://developer.apple.com/wallet/get-started-with-verify-with-wallet/>). Prepare for the request:
   * app name, bundle ID, TestFlight/App Store URL; a description of the good or service that needs age or identity verification;
   * **screenshots of the verification flow for people who do not use an ID in Wallet** (the Didit screens and the "no way to verify" and
     "decline" paths: Verify always shows the alternative and never makes Wallet the only route, VER-008);
   * screenshots of the Wallet flow (the request screen with the exact disclosure), the privacy policy URL of Viadere **and of Didit**;
   * request only `Age Over N Flag` (and `Issuing Authority`) first; `Given Name`, `Family Name` and `Address` only for tiers that need identity
     attributes. Apple entitles the app to a fixed element set: the app can never ask for more.
   Then create the **merchant identifier** and the **identity encryption certificate** in the developer portal (its private key goes to the
   server's KMS, `WALLET_ENCRYPTION_KEY_WRAPPED`) and add the capability in Xcode (Signing & Capabilities → Verify with Wallet). The entitlement
   is deliberately **not** in `project.yml` until Apple has issued it (an unapproved entitlement fails signing); until then Wallet is simply not
   offered. `NSIdentityUsageDescription` is in `Info.plist`. The simulator returns a mock mDL without issuer or device signatures: the server
   refuses it (test the server path with Apple's sample and the synthetic issuers in the server tests).
2. **Scan an ID document** with Didit's native SDK (`DiditSDKCore` 4.9.1, Swift Package, iOS 13+, no NFC, no OpenSSL). The SDK renders its
   own screens, themed to Viadere in the Didit console (White Label); camera, microphone and photo-library usage strings are in `Info.plist`.
   Images and biometrics go from the phone to Didit; Viadere never receives them. If passport chip reading is added later, switch to
   `DiditSDKNFC` (iOS 15+) and add the NFC capability and ISO7816 identifiers.

The Didit console must have the identity workflow (document + liveness + face match), a `status.updated` webhook destination pointing at
`/v1/providers/didit/webhook`, the shortest data retention, and biometric-template retention **off**.

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

## Authenticator (WP5): passkeys, one-time codes, optional end-to-end encrypted sync

A third-party credential provider (`ViadereCredentialProvider`, an `ASCredentialProviderViewController`) plus an Authenticator section in the app
(Home → Authenticator, Settings → Security → Authenticator). Protocol, wire formats and residual risks: `docs/SECURITY.md` §2.40. Logic lives in
`ViadereCore/Vault` (WebAuthn authenticator engine, TOTP, vault crypto) and `ViadereKit/Vault` (engine, storage, sync client, view model);
the app and the extension only host it.

| What | Where |
|---|---|
| Passkeys | iOS 17: `prepareInterface(forPasskeyRegistration:)`, `prepareInterfaceToProvideCredential(for:)`, `prepareCredentialList(for:requestParameters:)`; `provideCredentialWithoutUserInteraction` always answers `userInteractionRequired` (the vault opens only with Face ID / Touch ID / passcode, and that verification is what sets the UV flag) |
| One-time codes | iOS 18 (`#available`): `prepareOneTimeCodeCredentialList(for:)`, `ASOneTimeCodeCredential`. Codes are computed after unlock; the identity store gets a label only |
| Identity store | `IdentityStoreSync` replaces `ASPasskeyCredentialIdentity`s (site, account name, credential id, user handle: **metadata only**). "Suggest in AutoFill" in Authenticator turns even that off |
| Local vault | `FileVaultLocalStore` in the App Group container (`group.com.viadere.shared/Vault`): ciphertext, signed manifests, sync bookkeeping; excluded from backup; app and extension write it under `flock` with compare-and-swap on the manifest hash |
| Keys | `AppleVaultKeyProvider`: Secure Enclave signing key (`.privateKeyUsage + .userPresence`) and a Keychain agreement key (`.biometryCurrentSet` or the device passcode, `WhenUnlockedThisDeviceOnly`) in the **vault-only** keychain group `$(AppIdentifierPrefix)com.viadere.vault` (app + extension; no other target). A new `LAContext` (no reuse) per unlock **and per membership or recovery operation** (`freshIdentity(reason:)`: approve or remove a device, replace the recovery key, turn sync on, restore). The agreement key's bytes are read from the Keychain per HPKE operation and overwritten, not held for the session. `SecureEnclaveVaultAgreementKey` is a refusing stub for an enclave-held DHKEM key (TODO `vault-se-dhkem`; validate on a device before wiring) |
| Extension prompts | one engine, so one Face ID, per time the extension is on screen (choosing a row reuses the unlock that opened the picker); a verification older than 60 s is repeated before signing. iOS 18 `excludedCredentials` is passed to the registration; one-time-code suggestions are filtered by the requesting site's domain (`OneTimeCodeDomainMatcher`) |
| Extension isolation | built with no sync API (`VaultRuntime.makeEngine(… api: nil …)`): it can't reach the network. Changes it makes upload the next time the app opens |
| Add a device | scan or type the pairing code (QR payload `viadere-vault://pair?c=…`), biometric approval on the existing device. The waiting device shows its own fingerprint; the approving device shows the same one: compare them before approving |
| Recovery key | shown once at "Turn on sync", must be typed back, verifiable later, replaceable (optionally rotating the vault key); restores through "Already use Authenticator on another device?": **ask** (a 72-hour wait; the other devices are told and can cancel from the notice), **check** (when the vault last changed, its devices, item counts; nothing is committed), then confirm the new recovery key |
| QR scanning | `AuthenticatorQRScanner` (AVFoundation); payloads are validated by `OTPAuthURI` and never opened |
| Clipboard | codes copy through `SecurePasteboard` (local only, expires in 60 s); hidden while the screen is recorded |
| Credential Exchange | `CredentialExchange` (ViadereKit) parses CXF JSON (ES256 passkeys and TOTP; everything else reported). The iOS 26 `ASCredentialImportManager` glue is a **TODO** (`CredentialExchangeImport.swift`): the button is `#available(iOS 26.0, *)`-gated and currently imports a CXF `.json` file. Export is not implemented |

Entitlements: `com.apple.developer.authentication-services.autofill-credential-provider` on the app **and** the extension; both get the
`group.com.viadere.shared` app group; app and extension share keychain group `$(AppIdentifierPrefix)com.viadere.vault`. The extension's Info.plist
declares `ProvidesPasskeys`, `ProvidesOneTimeCodes` (iOS 18) and `SupportsConfiguration`, and `NSFaceIDUsageDescription`.

**Export compliance (legal review required before release).** The app's `ITSAppUsesNonExemptEncryption = false` rests on "TLS and signatures
only". Vault sync adds data-confidentiality encryption (AES-256-GCM, HPKE), which that basis does not cover: classify before submitting.

**Needs a real device / Xcode** (nothing in `Platform/AppleVaultKeyProvider.swift`, the extension or the Authenticator screens was compiled here; also verify on a device: `.biometryCurrentSet`/passcode access control behaviour after a biometric change, the `ASPasskeyCredentialRequest.excludedCredentials` accessor's optionality, one prompt per picker interaction, and the file-based Credential Exchange stand-in being absent from a release build):
Secure Enclave and Keychain key creation and `.userPresence` prompts (the keychain item needs a device passcode); the extension in the system
sheets (registration, assertion, picker, one-time codes) against real relying parties and Apple's passkey test pages; `ASCredentialIdentityStore`
state and `replaceCredentialIdentities`; the `ASExtensionError` codes and `ASPasskeyCredentialRequest` property names; the camera scanner;
two-device pairing; the iOS 26 Credential Exchange types; whether `SecureEnclave.P256` HPKE conformance could replace the Keychain agreement key.

## Approve v2 (WP1): pairwise keys, E2EE requests, key directory

`ViadereKit/ApproveV2` and `App/Viadere/Features/Approve`. Wire formats: `docs/SECURITY.md` 2.50 to 2.58. The feature is closed (and says so) unless the build pins the transparency-log public key: set `VIADERE_KEY_DIRECTORY_LOG_KEYS` in `Configs/*.xcconfig` (Info.plist key `ViadereKeyDirectoryLogKeys`, comma separated, public keys only; `ViadereServer key-directory-log-key` prints it).

* **Keys.** One Secure Enclave approval key per business relationship (`.biometryCurrentSet` for high and critical capabilities, `.userPresence` otherwise; app-only access group `ViadereApprovalKeychainAccessGroup`, `ThisDeviceOnly`) and one HPKE key in the Keychain (`WhenUnlockedThisDeviceOnly`, never synced). Nothing derives from the device or account keys, so businesses cannot correlate them. `AppleApprovalKeyVault` wraps `SecureEnclaveKeyStore` with a per-enrollment tag prefix.
* **Enrollment** (`ApproveEnrollmentSheet`, from a `https://viadere.com/a/{CODE}?rk=` link, QR or typed code): shows the verified business, the protection and the business root fingerprint, then signs the enrollment statement with the new key (Face ID) and waits for the business's confirmation. The key becomes active only after the phone verifies that confirmation against the transparency log and finds its own statement digest in it; otherwise the keys are deleted and revoked and the person is told.
* **Requests** (`ApproveRequestSheet`): decrypted and verified on the phone (published business signing key, business, customer, key, request id, expiry) before anything is shown; anything that fails is hidden and listed under "Waiting for you" as a failed check. The sheet says whether the request was checked end to end or was passed on by Viadere in the clear (`server_visible`). Deny is as prominent as Approve; Face ID reads "Approve $X to Y". Prompt fatigue: warning from the third request in an hour (the relay's count or the phone's own), Approve disabled until "I started this myself" is tapped, and "Report suspicious request" signs a report.
* **Directory pinning** (`BusinessDirectoryClient`): first contact pins the business root (out of band when the link carried `rk`); a valid root succession blocks that business and shows both fingerprints (Settings, Approvals) until the person confirms; a contradicted history blocks it until the person forgets the business; a log that shrinks, forks or goes stale is refused.
* **Freeze:** Settings, Approvals (account) and the business page (one business). Freezing needs no Face ID; turning it off needs Face ID on a trusted device.
* **Tests:** `Packages/ViadereKit/Tests/ViadereKitTests/ApproveV2Tests.swift` runs the real flows against an in-memory relay and log, including relay key substitution, a forged confirmation, a root change, a forked log, a rolled-back head, a request signed by an unpublished key and result verification by the business.

## Not verified by compilation

This repository was authored on Linux, where there is no Xcode or iOS SDK. **Everything under `Packages/ViadereKit`
that is platform-neutral compiles and is covered by `swift test` (335 tests).** The following were written carefully
against the iOS 17/18 SDK but never compiled; build them first in Xcode and expect a few mechanical fixes:

1. SwiftUI/UIKit code in `Viadere/`, `Shared/`, the extensions, widgets, clip and watch (only syntax-parsed).
2. `Keys/SecureEnclaveKeyStore.swift`, `Platform/KeychainSecretStore.swift`, `Platform/PinningSessionDelegate.swift`,
   `Platform/ApplePasskeyService.swift`, `Platform/SystemServices.swift`, `ViadereServices.live` (Apple-only, guarded).
3. Swift 6 strict-concurrency diagnostics around UIKit/UserNotifications/WatchConnectivity delegates (`@preconcurrency`
   conformances are used; if needed set `SWIFT_VERSION` to 5 for the UI targets).
4. The preprocessed Info.plist approach for the Debug-only ATS exception (`INFOPLIST_PREPROCESS`, `-traditional`).
5. `@Observable` view models (compile on Linux as plain classes because Observation does not link there).
6. Verify (WP3): `Features/Verify/*`, `PassKitWalletIdentity` (`PKIdentityAuthorizationController`, `PKIdentityError` codes) and the DiditSDK launcher
   (`DiditSdk.shared.startVerification(token:)`, `.diditVerification`); the DiditSDK package requirement and the entitlement are untested here.
7. Approve v2 (WP1): `Features/Approve/*` (syntax-parsed only), `ApproveV2/AppleApprovalKeyVault.swift` (per-enrollment Secure Enclave tags through `SecureEnclaveKeyStore`, Keychain HPKE key) and `ApproveEnvironment.live`; the `VIADERE_KEY_DIRECTORY_LOG_KEYS` xcconfig-to-Info.plist substitution.
7. Passkeys inside an App Clip, Live Activity push-to-start, the Dynamic Island layout, and the content-extension card.
7. XcodeGen spec details (extension embedding, on-demand-install-capable type, watch embedding).
8. P3 UI: everything under `Features/Rewards`, `Activity`, `Wallet`, `Household`, `Consent`, the reworked widget, and the
   PassKit calls (`PKAddPassButton`, `PKAddPassesViewController`, `PKPass(data:)`, `PKPassLibrary`). `Text(timerInterval:)`
   in the Dynamic Island, `NavigationLink` destinations inside the typed Home stack, and Swift 6 isolation around
   `PKAddPassesViewControllerDelegate` (`WalletPresenter`) are the likeliest to need a mechanical fix.
9. Round-4 identity UI and platform code: `DeviceCheckAppAttest` (`DCAppAttestService`; needs a device, the Simulator
   reports unsupported), the App Attest entitlement and `APP_ATTEST_ENVIRONMENT` xcconfig wiring, `RecoveryCodesView` (the
   `UIActivityViewController` share sheet), `Features/Recovery/*`, the recovery and replacement rows in Settings, the banner's
   action button, the Clip sources that now include `SecurePasteboard` and `ScreenCaptureObserver`.
10. WP5 Authenticator: `ViadereCredentialProvider/*`, `Features/Authenticator/*`, `Platform/AppleVaultKeyProvider.swift` (see the Authenticator section above).
