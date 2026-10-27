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
    public static let linkSent = "Viadere: We're texting you a secure link to link your account."
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

    public static func linkRequired(_ business: BusinessSummary) -> String {
        "Viadere: To message \(safeName(business)), link your account first. We're texting you a secure link."
    }

    public static func businessUnavailable(_ business: BusinessSummary) -> String {
        "Viadere: \(safeName(business)) isn't available on Viadere right now."
    }

    public static func backWhileConnected(_ business: BusinessSummary) -> String {
        "Viadere: You're connected to \(safeName(business)). Reply MENU for options, or \\BACK to send the word BACK."
    }

    /// Sent by the server for `.sendAccountLink`.
    public static func accountLink(url: URL, ttlMinutes: Int) -> String {
        "Viadere: Link your account: \(url.absoluteString) Expires in \(ttlMinutes) min. Don't share this link."
    }

    /// Sent by the server for `.sendSecureHandoff`.
    public static func secureHandoff(url: URL, ttlMinutes: Int) -> String {
        "Viadere: For your security, continue here: \(url.absoluteString) Expires in \(ttlMinutes) min."
    }

    /// Menu body with numbered options.
    public static func menu(header: String, options: [MenuOption]) -> String {
        ([header] + options.map { "\($0.number). \($0.label)" }).joined(separator: "\n")
    }
}
