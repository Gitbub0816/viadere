import Foundation

/// The approved customer copy for authentication delivery (`docs/product/UX_COPY.md`, revision 3), keyed by the file's stable ids.
///
/// Rules this type enforces (UX_COPY §0, §10): every variable is wrapped in Unicode bidi isolates, so a business name or host renders
/// correctly next to right-to-left text; no sentence is assembled by a caller; no string carries a code, number, amount or URL. The App
/// moves these into a String Catalog with the ids as keys; until then this is the single source and the tests pin the wording.
public enum AuthDeliveryCopy {
    /// Wraps a variable in first-strong isolate ... pop-directional-isolate.
    public static func iso(_ value: String) -> String { "\u{2068}\(value)\u{2069}" }

    // MARK: Notifications (§1)

    public static let n01Title = "Viadere"
    public static let n01Body = "You have a new security item."
    public static let n08Body = "You have a new security item. Open Viadere to review it."
    public static let n09Title = "Viadere"
    public static let n09Body = "Deny not sent yet. Open Viadere."
    public static let hiddenPreviewsPlaceholder = "You have a security item."

    // MARK: Safe-action vocabulary (§0.1)

    public static let deny = "Deny"
    public static let approve = "Approve"
    public static let notMe = "This wasn't me"
    public static let review = "Review"
    public static let open = "Open"
    public static let continueTitle = "Continue"
    public static let denyLine = "Deny says no. This wasn't me also reports it."

    // MARK: Sign-in link (§2)

    public static func linkTitle(business: String) -> String { "\(iso(business)) sign-in link" }
    public static func linkBody(business: String, host: String) -> String { "Continue to sign in to \(iso(business)). This opens \(iso(host))." }
    public static let unusualHost = "This address uses unusual characters."
    public static func expiresAt(_ time: String) -> String { "Expires at \(time)" }
    public static func linkFootnote(business: String) -> String { "Continue only if you asked \(iso(business)) for a sign-in link on this device." }
    public static func linkOpened(host: String) -> String { "Opened \(iso(host)). Finish signing in there." }
    public static func linkReported(business: String) -> String {
        "Thanks. We told \(iso(business)) you didn't ask for this. You can ignore it. If you keep getting these, report it."
    }
    public static func linkExpired(business: String) -> String { "This sign-in link has expired. Ask \(iso(business)) for a new link." }
    public static func linkUsed(business: String) -> String {
        "This sign-in link was already used. Ask \(iso(business)) for a new link if you still need to sign in."
    }
    public static func linkWrongDestination(business: String) -> String {
        "We didn't open this link because it doesn't go to a website \(iso(business)) has verified."
    }
    public static func linkSignatureFailed(business: String) -> String {
        "We couldn't confirm this link came from \(iso(business)). We didn't open it."
    }
    public static let linkRetired = "This link is no longer used. Open Viadere to see your requests."
    public static let linkCannotCheck = "We couldn't check this sign-in link right now, so we didn't open it. Try again in a moment."
    public static let linkClock = "We couldn't check this sign-in link. Check your phone's date and time, then try again."
    public static let tryAgain = "Try again"

    // MARK: Legacy `/h/` hand-off confirm (ADR-0021 §4 item 4; wording proposed by A6, A9 to review before the Stage 4 merge)

    public static let handoffTitle = "Open this link in Viadere?"
    public static let handoffBody = "This link came from a text message. Opening it uses it up. Open it only if you asked a business to send it."
    public static let handoffNotMeDone = "Thanks. Nothing was opened. You can ignore the text."
    public static let handoffExpired = "That link has expired. Open Viadere to see your requests."

    // MARK: Push approval and payment (§3)

    public static func signInTitle(business: String) -> String { "Approve sign-in to \(iso(business))?" }
    public static let signInSubtitle = "Only approve if you started this."
    public static func paymentTitle(payee: String) -> String { "Confirm a payment to \(iso(payee))?" }
    public static let paymentSubtitle = "Only approve if you started this payment."
    public static func numberFieldLabel(business: String) -> String { "Number on \(iso(business))" }
    public static func numberHelper(business: String, digits: Int, payment: Bool) -> String {
        if payment {
            return "Enter the \(digits)-digit number on the \(iso(business)) checkout screen. No number there, or someone gave it to you? Tap Deny."
        }
        return "Enter the \(digits)-digit number on the \(iso(business)) screen where you're signing in. No number there, or someone gave it to you? Tap Deny."
    }
    /// INB-01: the line under a request that was delivered silently (over the hourly budget, no alert push), so a person who is signing in finds it (ADR-0022 §5.1).
    public static func silentPendingSignIn(business: String) -> String { "You have a pending sign-in from \(iso(business))." }
    /// The helper line for a group whose codes have different lengths (some 2, some 3 digits): no digit count, so the person types the number they see.
    public static func numberHelperAnyLength(business: String) -> String {
        "Enter the number on the \(iso(business)) screen where you're signing in. No number there, or someone gave it to you? Tap Deny."
    }
    public static func requestedAt(_ time: String) -> String { "Requested at \(time)" }
    public static let wrongNumber = "That number doesn't match. Check the screen where you're signing in. Don't type a number someone gave you."
    public static func wrongNumberAutoDeny(business: String) -> String {
        "The number didn't match, so we denied this request. If you're signing in, start again on \(iso(business))."
    }
    public static func faceIDReason(business: String) -> String { "Confirm it's you to approve this \(iso(business)) request." }
    public static func approved(business: String) -> String { "Approved. Your answer was sent to \(iso(business))." }
    public static func approvedPayment(business: String) -> String {
        "Approved. Your answer was sent to \(iso(business)). Check \(iso(business)) to see whether the payment went through."
    }
    public static func denied(business: String) -> String {
        "Request denied. We told \(iso(business)). If that was a mistake, start again on \(iso(business))."
    }
    public static func deniedPayment(business: String) -> String { "Payment denied. We told \(iso(business)) you didn't approve it." }
    public static func reported(business: String) -> String {
        "Thanks. We denied this request and told \(iso(business)) it wasn't you. Someone may have your \(iso(business)) sign-in details. You can change your password there. If you keep getting requests you didn't start, you can pause them."
    }
    public static func pauseAction(business: String) -> String { "Pause requests from \(iso(business)) for 1 hour" }
    public static func fatigue(count: Int, business: String) -> String {
        "There have been \(count) sign-in requests for \(iso(business)) in the last hour. If you didn't start them, tap This wasn't me."
    }
    public static let startedMyself = "I started this myself"
    public static func sameDeviceHint(business: String) -> String {
        "Switch to \(iso(business)), read the number, then come back. Don't use a number from a message or call."
    }
    public static func answerNotSent(business: String) -> String {
        "Your answer wasn't sent. Check your connection and try again. \(iso(business)) hasn't received anything yet."
    }
    public static let answerExpired = "This request expired before your answer could be sent. If you still need to sign in, start again on the business's page."
    public static func openRequests(count: Int, business: String) -> String {
        "\(count) open sign-in requests from \(iso(business)). Enter the number shown where you're signing in. Only that request is approved."
    }
    public static let numberMatchesSeveral = "This number matches more than one request. Nothing was approved. Start again on the business's page to get a new number."
    public static let paymentDeviceNotTrusted = "This iPhone can't approve payments yet. To allow it, approve it with Face ID on a device you already trust. You can still deny."
    public static func paymentNoTrustedDevice(business: String) -> String {
        "This iPhone can't approve payments yet. \(iso(business)) can set it up again. You can still deny."
    }
    public static let unverifiedRelayLine = "Viadere passed this on and could read it. It is not signed by the business. Only approve if you started this yourself."

    // MARK: Device add (§5)

    public static func newDeviceCodeTitle(code: String) -> String { "Enter this number on your other device: \(code)" }
    public static let newDeviceCodeDetail = "Only enter it on a device you own and are holding. Viadere never asks for this number by phone, text or email."
    public static let existingDeviceTitle = "Add a new device to your account?"
    public static func existingDeviceName(_ name: String) -> String { "Name chosen on the new device: \(iso(name))" }
    public static let deviceNumberLabel = "Number on the new device"
    public static let deviceNumberHelper = "Type the 6-digit number shown on the new device. No new device in front of you, or someone gave you a number? Tap This wasn't me."
    public static let addDevice = "Add device"
    public static let deviceWrongNumber = "That number doesn't match the new device. Check it and try again."
    public static let deviceWrongNumberFinal = "Nothing was added. Start again on the new device."
    public static let deviceChallengeMismatch = "We couldn't confirm this request belongs to this device, so nothing was added. Start again."

    // MARK: Errors (§6) and watchOS (§7)

    public static let offline = "You're offline. Connect to the internet to review this request."
    public static let noLongerActive = "This request is no longer active."
    public static let unlockToContinue = "Unlock your iPhone to continue."
    public static let delegateDevice = "Only the account holder can respond to security requests."
    public static func watchApprovalItem(business: String) -> String { "\(iso(business)) sign-in request" }
    public static let watchInstruction = "Approve on your iPhone."
    public static func watchLinkItem(business: String) -> String { "\(iso(business)) sign-in link is ready. Open it on your iPhone." }
    public static let watchPhoneUnreachable = "Couldn't reach your iPhone. Open Viadere on your iPhone to deny."

    // MARK: Live Activity and Lock Screen (F-09; neutral wording owned by A6, A9 to review)

    public static let liveActivityHeadline = "Decision needed"
    public static let liveActivityDetail = "Open Viadere to see it."
}
