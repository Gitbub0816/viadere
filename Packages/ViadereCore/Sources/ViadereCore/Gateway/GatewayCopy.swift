import Foundation

/// All gateway-authored SMS copy. Kept GSM-7 and short. Viadere's own messages start with
/// `Viadere:`; business messages are attributed as `[Business Name]: …`.
public enum GatewayCopy {
    public static let brand = "Viadere"

    public static func attribution(_ business: BusinessSummary) -> String {
        "[" + safeName(business) + "]: "
    }

    static func safeName(_ business: BusinessSummary) -> String {
        SMSEncoding.field(business.displayName, maxLength: 40).replacingOccurrences(of: "[", with: "(").replacingOccurrences(of: "]", with: ")")
    }

    static func label(_ business: BusinessSummary) -> String {
        var s = safeName(business)
        if let handle = business.handle { s += " (\(handle.display))" }
        return s
    }

    public static let help = "Viadere: Text a business name, @handle, or code to connect. Reply MENU for options, STOP to opt out. Msg & data rates may apply. viadere.com/help"
    public static let optOutConfirmation = "Viadere: You're unsubscribed and won't get more messages. Reply START to resubscribe."
    public static let resubscribed = "Viadere: You're resubscribed."
    public static let welcome = "Viadere: A trusted way to connect with verified businesses."
    public static let searchPrompt = "Viadere: Reply with a business name, @handle, or 6-character code (like AF-2345)."
    public static let noRecent = "Viadere: No recent businesses yet."
    public static let linked = "Viadere: Your number is now linked to your Viadere account."
    public static let notConnected = "Viadere: You're not connected to a business. Text a name, @handle, or code."
    public static let directoryUnavailable = "Viadere: Sorry, we couldn't look that up right now. Please try again shortly."
    public static let howItWorks = "Viadere: Pick a verified business, then text normally. Each business sees only its own conversation. Reply MENU anytime."
    public static let privacy = "Viadere: Businesses see only their own conversation with you. Reply STOP anytime to opt out. viadere.com/privacy"
    public static let staleReply = "Viadere: That reply was for an earlier menu."
    public static let expiredMenu = "Viadere: That menu expired."
    public static let invalidChoice = "Viadere: Please reply with one of these numbers."

    public static func noMatch(_ query: String) -> String {
        "Viadere: No verified business matches \"\(SMSEncoding.field(query, maxLength: 30))\". Try another name, @handle, or code, or reply MENU."
    }

    public static func confirm(_ business: BusinessSummary, hasPendingMessage: Bool) -> String {
        var s = "Viadere: Connect to \(label(business)), code \(business.code.display)?"
        if hasPendingMessage { s += " Your message will be sent after you confirm." }
        return s
    }

    public static func connected(_ business: BusinessSummary) -> String {
        "Viadere: Connected to \(safeName(business)). Send your message normally. Reply MENU to switch."
    }

    public static func continued(_ business: BusinessSummary) -> String {
        "Viadere: Back with \(safeName(business)). Send your message normally."
    }

    public static func ended(_ business: BusinessSummary) -> String {
        "Viadere: Conversation with \(safeName(business)) ended."
    }

    public static func sessionHeader(_ business: BusinessSummary) -> String {
        "Viadere: You're chatting with \(safeName(business))."
    }

    public static func expiredSession(_ business: BusinessSummary, messageHeld: Bool) -> String {
        "Viadere: Your conversation with \(safeName(business)) timed out." + (messageHeld ? " Your message was not sent yet." : "")
    }

    /// A number that is not linked cannot route to a business. Linking happens in the app (ADR-0027); nothing is texted but this pointer.
    public static func linkRequired(_ business: BusinessSummary, url: String) -> String {
        "Viadere: To message \(safeName(business)), link this number in the Viadere app first. Get the app: \(url)"
    }

    public static func businessUnavailable(_ business: BusinessSummary) -> String {
        "Viadere: \(safeName(business)) isn't available on Viadere right now."
    }

    public static func backWhileConnected(_ business: BusinessSummary) -> String {
        "Viadere: You're connected to \(safeName(business)). Reply MENU for options, or \\BACK to send the word BACK."
    }

    /// Content-free notice sent instead of a business's text while the shared SMS thread is connected to a *different* business, so
    /// the person's natural reply cannot be forwarded to the wrong tenant (and the other business's words never appear as if
    /// replies would reach it).
    public static func newMessageNotice(from sender: BusinessSummary, whileConnectedTo active: BusinessSummary) -> String {
        "Viadere: You have a new message from \(safeName(sender)) in the Viadere app. Don't reply here: replies in this chat go to \(safeName(active)). Reply MENU to switch."
    }

    /// UX_COPY SMS-01: the on-ramp pointer. A static page, never a token (decision 9).
    public static func getViadere(url: String) -> String { "Get the Viadere app to connect with businesses: \(url)" }

    /// ADR-0027 §4: what the gateway says instead of minting a hand-off link. No link, no code.
    public static let openAppToRespond = "Viadere: Open the Viadere app to respond."
    public static let openAppForAccount = "Viadere: Open the Viadere app for account help and settings."

    /// UX_COPY SMS-02: sent to a number after every valid customer-originated link text, before any waiting period ends.
    public static let phoneLinkedNotice = "Viadere: Someone linked this number to a Viadere app using a text sent from this phone. If that wasn't you, reply UNLINK. Reply STOP to stop messages."
    /// UX_COPY SMS-03.
    public static let unlinkDone = "Viadere: Done. Viadere will not use this number for messages or approvals. The Viadere account that holds it can remove it in the app."
    /// UX_COPY SMS-04: the only thing a number linked by text ever receives about an interaction.
    public static func secureRequestNotice(business: BusinessSummary) -> String {
        "Viadere: \(safeName(business)) sent you something that needs the Viadere app. Open Viadere to respond."
    }

    /// Menu body with numbered options.
    public static func menu(header: String, options: [MenuOption]) -> String {
        ([header] + options.map { "\($0.number). \($0.label)" }).joined(separator: "\n")
    }
}
