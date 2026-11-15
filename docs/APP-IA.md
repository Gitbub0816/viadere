# Viadere iOS app — information architecture

**Status:** implemented (November 2026). Supersedes the "variant A" bar of plan 4.8 (Messages, Alerts, Benefits, Businesses with Settings as
a sheet behind the context bar). Spec C1 allows Settings to become a tab after usability feedback; the owner's feedback was that the app is
unintuitive, Settings is hard to find and badly organized, business pages are disorganized, gestures do not work as expected, and settings
are walls of switches. This document is the proposal and the record of what was built.

## 1. Audit (before)

| Area | Problem |
|---|---|
| Tabs | Messages, Alerts, Benefits, Businesses, but the app **opened on Alerts, the second tab**. Settings was a sheet behind a small person icon in the context bar: owners did not find it, and a sheet is the wrong container for a deep hierarchy. |
| Settings | One long sheet. "Security" held fourteen unrelated rows (profile, sharing history, data export, verification history, sessions…); "Trust and records" and "Notifications" were fragments; the device card, app lock and lock-screen details were mixed in. No search. |
| Authenticator | Reachable from Settings **and** from an "Also in Viadere" row at the bottom of Businesses. |
| Business page | The profile, then modules, then one "Settings for X" row at the very bottom. Message was a full-width button module; favorite only in the directory list; rewards disappeared when the business's layout left them out. |
| Business settings | A full second hero (handle, code, date), a favorite switch, a mute filter bar, a column of six permission switches, a freeze switch, a Loop switch, then rewards, profile access, history, disconnect, block. Mute durations existed in the view model but were never offered. |
| Ended connections | Shown as inert rows; the block copy said "unblock it in Businesses" but there was no way to unblock or reconnect. |
| Gestures | Every pushed screen hides the system navigation bar and draws `ViadereBackButton`; UIKit disables the interactive pop gesture whenever the bar is hidden, so **edge-swipe back did nothing anywhere**. The QR scanner (a full-screen cover) could not be pulled down. A security sheet with a typed reply could be pulled away and lose it. |
| Toggles | 18 switches across Settings, business settings, permissions (connect and business), household access, profile sharing, Loop consent and approvals — including consequential ones (freeze approvals, "This is my phone") that a stray tap flips. |

## 2. Tabs

```
Alerts · Messages · Benefits · Businesses · You
```

* **Alerts** (first, and where the app opens): *Needs you* / *History* (History is the old Activity). Badge = actionable count.
* **Messages**: conversations, grouped by business in All. Badge = unread.
* **Benefits**: coupons, rewards, loyalty, Wallet passes; filters Available / Saved / Ready now / Used / Expired.
* **Businesses**: Discover (Loops, reserved), then the directory (favorites, everyone else, no longer connected), Add business.
* **You**: the account. Badge dot when an account notice (new device, recovery in progress) waits.

The business selector (All by default) sits at the top of Alerts, Messages, Benefits and Businesses and filters the first three, exactly as
before (C1–C3, C9.7). You is global and has no selector. The context bar keeps Add business (+); its account button is gone (You is a tab).
`AppTab.destination` maps You to `OrganizationDestination.settings`; Core is unchanged.

## 3. Hierarchy

### Businesses
```
Businesses
├── Discover                      (only while Loops are offered)
│   ├── Loop directory            → LoopDirectorySlot   [reserved: Loops work]
│   └── Your Loops                → YourLoopsSlot       [reserved: Loops work]
├── Favorites / Everyone else     → Business page
└── No longer connected           Unblock (confirmed) · Reconnect (opens the connect review from the code)

Business page
├── Identity (brand band, name, verified badge, handle)
├── Quick actions: Message · Favorite · Settings
├── Modules in the business's order (waiting for you, verification requests, offers, rewards, recent activity, Loops)
├── Rewards and Requests (Loops) always have a place, even when the layout omits them
└── Your connection: Notifications (current level) · Settings for X  → Business settings

Business settings
├── Header (avatar, name, verified, favorite star)
├── Notifications: level picker (Everything / Balanced / Only what matters) + "For" stepper (1 hour … Until I change it)
├── X can contact you about: chips (security and account notices locked on) + one-line summary
├── Approvals: state card (Pause / Resume)            (only when this phone holds a key for X)
├── Requests: state card (Allow… / Stop)              (only while Loops are on)
├── Privacy: What X can see · History (expands in place)
├── About this connection: handle, code (copy), category, connected
└── End the connection: Disconnect · Block (both confirmed inline)
```

### You
```
You
├── Search settings (on device; titles, details and synonyms: "face id", "freeze", "dark mode"…)
├── Security summary card (weakest fact wins: "Well protected · Face ID approvals · App lock on · 2 trusted devices")
├── Account notice banner, cool-down notice
├── Account: Profile · Household · Linked phones · Signed-in sessions
├── Security: App lock (switch) · Approvals · Trusted devices · Authenticator · Recovery codes
├── Notifications: Notifications → lock-screen details (choice cards), business by business (level per business,
│                  opened in place, "More for X" → Business settings), Requests built by businesses, iOS sounds and Focus
│                  · Requests built by businesses
├── Privacy and sharing: Sharing history · Consent history · Verification history
├── Records: Acknowledgments · Download my data
├── Appearance: Appearance → AppearanceSettingsSlot   [reserved: themes work]
└── Sign out or leave: Sign out · Delete account (confirmed inline)
```

Every row shows its **state** where it is known ("2 active", "Frozen: no business can ask", "Name only on the lock screen · 2 quieted",
"8 unused codes"). Rows for features the server does not offer (404) are hidden. The structure is data (`SettingsCatalog` in ViadereKit),
so rows and search can never disagree; it is unit-tested.

Deep links are unchanged in meaning: `/settings`, account-link and Approve-enrollment links, handoff "account help" and "Review" on a security
notice now select the You tab (and push Approvals or Trusted devices) instead of presenting a sheet. `AppModel.settingsPresented` remains as
a compatibility accessor that selects You.

## 4. Primary flows

| Flow | Path |
|---|---|
| Answer a request | Notification → sheet; or Alerts → Needs you → sheet (unchanged) |
| Message a business | Business page → Message, or Messages |
| Quiet a business | Business page → Your connection → Notifications; or You → Notifications → Business by business (one tap opens the level) |
| Quiet everything at night | You → Notifications → Quiet hours (From / Until; only security interrupts inside the window) |
| One level for every business | You → Notifications → For all businesses (Everything / Balanced / Only what matters); a business with its own level keeps it, "Follow my default level" returns it |
| Alerts from a Loop I added without connecting | Install sheet → "Alerts from this Loop"; later Your Loops → the Alerts chip, or the Loop's page (this Loop's requests only) |
| Stop offers from a business | Business settings → tap the Offers chip |
| Freeze everything | You → Security summary / Approvals → Freeze approvals |
| Something looks wrong | You badge → banner → Review → Trusted devices |
| Unblock / reconnect | Businesses → No longer connected → Unblock / Reconnect |
| Find any setting | You → Search |

## 5. Controls (`App/Shared/DesignSystem/ViadereControls.swift`)

Built from the existing tokens only (no new colors), so the appearance themes drop in.

| Control | Use | Replaced |
|---|---|---|
| `ViadereChoiceCards` | One of a few options, each with a sentence | Lock-screen details switch |
| `ViadereLevelPicker` (+ `ViadereLevelMeter`) | Preset levels with a meter, caption and optional "Customize" | Business mute filter bar; per-business levels in Notifications |
| `ViadereChipSet` / `ViadereToggleChip` | Several independent yes/no items, locked items shown | Permission switches (business settings, connect review), household access purposes and businesses, profile sharing fields, profile requests, verified facts, Loop per-business switches |
| `ViadereInlineStepper` | Short ordered range with − / + | (new) mute duration, never exposed before |
| `ViadereStateCard` | Consequential state + named action | Freeze approvals (account and per business), Loops on/off, a business's Loop authorization |
| `ViadereSummaryCard` | Smart summary of a group | (new) security summary |
| `ViadereCheckbox` | Explicit affirmation | "This is my phone", "I saved these codes", Loop consent agreement |
| `ViadereFavoriteButton`, `ViadereQuickAction`, `ViadereSheetHandle` | Small shared pieces | Favorite switch; Message module button; sheet grabber |

Switches remain only where one binary is clearest: **App lock**, **Suggest in AutoFill** (Authenticator), **rotate keys** in Authenticator
sync, and a Loop's own yes/no field (`PresentationView`, the business's form).

## 6. Gestures (`App/Shared/DesignSystem/ViadereNavigationGestures.swift`)

* **Edge-swipe back everywhere.** `ViadereBackButton` installs `ViadereSwipeBack` as the delegate of its navigation controller's interactive
  pop gesture: it allows the swipe whenever there is a screen to go back to and no transition is running, regardless of the hidden bar.
  Every pushed screen has a back button, so this covers the whole app; `.viadereEdgeSwipeBack()` exists for a pushed screen without one.
* **Pull down closes sheets** (SwiftUI's default, kept). The QR scanners (full-screen covers) get the same pull with
  `.viaderePullDownToDismiss()`, plus the VoiceOver escape gesture.
* **Security sheets are not pulled away by accident.** Approval and Approve sheets keep refusing dismissal while a decision is being signed
  (unchanged). In addition, once an answer is in progress (a typed reply or chosen options; or the fatigue warning worked through) the pull is
  held and `ViadereSheetHandle` shows **Close**, which asks "Leave without sending?" first. Without a draft a pull closes the sheet and the
  request stays in Alerts until it expires, which loses nothing. Recovery codes stay a full-screen cover that cannot be swiped away.

## 7. Missing functionality

Added with existing APIs:

* You tab with search and live summaries; security summary card.
* Timed quiet ("For 1 hour / 1 day / 1 week / Until I change it"): the API and view model supported it, the UI never offered it.
* Business-by-business notification levels in one screen (`BusinessesViewModel.setMute`, optimistic with rollback).
* Unblock and reconnect for ended connections (`BusinessesViewModel.unblock`, `AppModel.reconnect`; the server already allowed preference
  changes on ended connections, the mock now matches it).
* Business page quick actions (Message, Favorite, Settings) and "Your connection" summary; rewards entry always reachable.
* Permission summary line ("Orders, support and offers").
* Messages → Archived: archived threads used to vanish for good (the list loaded without them); Messages now loads them through the
  Organization API (`archived=1`), hides them from the list and offers Restore.

Needs server or partner work:

* ~~A **global** notification preference.~~ Done: an account-wide default level (inherited by businesses without their own level) and optional
  quiet hours, stored and enforced on the server (SECURITY.md §2.96 "Notification level and quiet hours"; `NotificationSettingsViewModel`).
* Server-side list of **ended** connections in the mock/test fixtures (the live server returns them; the mock drops them on reload).
* Activity export / richer history per business (only the last 10 interactions are fetched client-side).
* Appearance and the Loop directory / Your Loops: reserved destinations, wired by their own work (§8).

## 8. Reserved places (integration slots)

`App/Viadere/Features/Settings/IntegrationSlots.swift`:

* `AppearanceSettingsSlot` — You → Appearance (call site `SettingsView.screen(_:)`, `.appearance`).
* `LoopDirectorySlot` — Businesses → Discover → Loop directory (call site `BusinessesView`, route `.loopDirectory`).
* `YourLoopsSlot` — Businesses → Discover → Your Loops (route `.yourLoops`).

The business page keeps `BusinessLoopsSection`, owned and loaded by the page (`LoopCatalogViewModel`, `BusinessRewardsViewModel`), because
SwiftUI never runs `.task` on a view with no content.

## 9. Scanner and feedback (2026-11-14)

* **Scan a code** is a round `viewfinder` button in the Alerts and Businesses headers, and "Scan a code" in Add business. All three open the
  same full-screen scanner (`Features/Scan/CodeScannerScreen.swift`): it reads the Viadere code on "Sign in with Viadere" (a CKey) and
  Viadere QR codes, has a light button when the phone has a torch, closes with the close button or a downward pull, and says in one
  sentence why a code was refused. What a scan may open is decided only by `ScannedCodePolicy` (`docs/SECURITY.md` §2.104).
* **Outcomes** (`ViadereOutcome`): the end of a sign-in or link request is a drawn ring and mark with one haptic (success, neutral for the
  person's own refusal, caution for anything that stopped), in the flow's approved copy. **Loading** in sheets is the breathing mark with a
  caption (`ViadereLoadingState`), never a stock spinner.
* **Motion**: tabs cross-fade (0.16 s); alert cards rise in, staggered for the first screenful only (`viadereEntrance`); history rows settle
  under a press (`.viaderePressable`). All of it is off with Reduce Motion.

### 9.1 Screen states, feedback and motion rules (refinement pass, 2026-11-14)

New design-system pieces (`App/Shared/DesignSystem/ViadereStates.swift`, all in `ViadereDesignSystemGallery`):

* `ViadereSkeleton(.rows(n) | .cards(n), label:)`: placeholder rows or cards for a list's first load. It breathes gently, is still with
  Reduce Motion, and is one "Loading …" element for VoiceOver.
* `ViadereErrorState(title, message:, retry:)`: a first load that failed, with "Try again". Only when there is nothing to show.
* `ViadereNoResults(text, clear:)`: an on-device search that found nothing, with "Clear search".
* `.viadereToast($text)`: a toast owned by a pushed screen or sheet (the tabs keep using `AppModel.toast`).
* `withViadereAnimation(_:reduceMotion:_:)` and `.viadereAnimation(_:value:)`: the only way a screen animates explicitly. Screens do not
  call `withAnimation` or `.animation(_:value:)` directly (not yet migrated: the approval sheet's "not me" toggle, the scanner, and
  the Loop presentation button style; the sign-in sheet and the tab bar gate theirs inline).

Rules the screens follow:

* **One decision for list screens** (`ScreenLoadState.resolve`, ViadereKit, tested): content always wins; a first load shows the skeleton;
  a first load that failed shows `ViadereErrorState`; only a successful empty answer shows `ViadereEmptyState`. A refresh that fails keeps
  the content and says so in a `ViadereNotice`. Used by Alerts, Messages, Businesses and Benefits.
* **Confirmations** are a toast with the copy in `FeedbackCopy` (ViadereKit, tested), shown only when the server kept the change
  (`setMuted`, `setArchived` and `setFavorite` return whether it did): mute and archive a conversation, restore it, favorite a business, save the public name.
* **Rows that open something** use `.buttonStyle(.viaderePressable)`; rows that select or toggle stay `.plain`.
* **Context menus** repeat actions the screen already offers: conversation (Mute, Archive), business (Open, favorite), authenticator code
  (Copy code, Delete). There are no swipe actions: lists are `ViadereRowGroup` in a `ScrollView`, not `List`, so the stock swipe is not
  available and no custom one was added.
* **Haptics** mark a result, never a tap: a message sent or refused, a claim, a code arriving, the vault unlocking, a destructive
  confirmation appearing, an onboarding step. `ViadereOutcome` carries its own.
* **Flow endings** use `ViadereOutcome` with the flow's existing copy: Connect, redemption (expired, refused, failed), the verification
  result and failure, phone linking, data export.
* **Numbers that change** (points balance, authenticator code) use `contentTransition(.numericText())` through `.viadereAnimation`.

## 10. Auth deliveries, Lock Screen details and the Home Screen widget (2026-11-15)

* **Deliveries in Alerts.** Sign-in links, one-time codes and security notices are not in the Alerts read model, so "Needs you" shows
  them from their own inbox (`AuthDeliveryInboxViewModel`, `GET /v1/auth-deliveries`) at the top: pending only, newest first, expired
  rows gone by the device clock, disabled while offline. A row, like a push, opens the delivery sheet, which reads the display object
  only and shows the link screen (still fail-closed: nothing is opened), the code sheet, or the N-06 line for a notice.
* **Code sheet** (C-OTP-01/02/04, C-TOTP-01): who and "Expires at …" first; "Show code" is the one-time `open`; the code is large,
  monospaced and read digit by digit, hidden while the screen is recorded, cleared on expiry, close and backgrounding, and "Copy code"
  is local-only with an expiry never later than the code's. Footer: This wasn't me · Copy code, equal. No live countdown (UX_COPY §0
  rule 10); the expiry is checked every second and the sheet turns to C-OTP-02.
* **Live Activity details** (You → Notifications, searchable): two choice cards, "Only that a decision is needed" by default; the
  detailed choice needs Face ID or the passcode.
* **Home Screen widget** (small, medium): the count of waiting requests and, medium only, benefits available; neutral when signed out
  or a day stale. A tap opens the app. The app writes only numbers (`HomeWidgetWriter`, `WidgetSnapshot`).

## 11. Link service, business names on the Lock Screen and the pairing QR (2026-11-15)

* **Link-service deliveries** (`link_mode: "viadere"`): the delivery sheet now routes them to `LinkServiceScreen` (UX_COPY LS-01 to LS-08)
  instead of "not supported". Same states and motion as the OIDC sheet (§9.1): `ViadereLoadingState` while the statement is checked, the
  question, then one `ViadereOutcome` (success only for an accepted approval, neutral for Deny and This wasn't me, caution otherwise) and one
  warning haptic for a wrong number. Footer: This wasn't me · Deny · Approve, one component of equal `.secondary` buttons, side by side until
  they would truncate, then stacked; the number field only when the challenge asks for one. Nothing on it opens a URL.
* **Show business names on the Lock Screen** (You → Notifications, beside "Live Activity details", searchable): two choice cards, "Just
  Viadere" by default; "The business name" needs Face ID or the passcode. Off, every notification is titled "Viadere" and has no logo.
* **Pairing QR**: Settings → Trusted devices → Add another device shows the code and, under it, the same code as a QR (`QRCodeView`, the
  white plate of §9). The new device's pairing entry has "Scan the code" (the shared `CodeScannerScreen`, refusals in its fixed sentence);
  a scan or an opened `/p/` link only fills the field, and Continue stays the person's tap. Any other scanner, or an enrolled device,
  refuses it with the S-PAIR-10 line.
