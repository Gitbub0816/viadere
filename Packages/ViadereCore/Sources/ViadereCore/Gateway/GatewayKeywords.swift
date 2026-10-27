import Foundation

/// Reserved SMS keywords.
///
/// Matching: the **whole message** after trimming whitespace, removing trailing `.`/`!`, and
/// uppercasing (so `" stop. "` matches, `"stop sending"` does not).
///
/// | Keyword set                                           | Effect                              | Escapable |
/// |-------------------------------------------------------|-------------------------------------|-----------|
/// | STOP, STOPALL, UNSUBSCRIBE, CANCEL, END, QUIT, OPTOUT, REVOKE | Opt out (every state)       | No        |
/// | HELP, INFO                                            | Help text (every state but OPTED_OUT)| No        |
/// | START, UNSTOP, YES                                    | Re-opt-in, only from OPTED_OUT      | n/a       |
/// | MENU                                                  | Gateway controls                    | Yes       |
/// | BACK                                                  | Previous menu                       | Yes       |
///
/// Escape: a leading backslash sends the remainder literally to the connected business
/// (`\MENU` → "MENU"). Carrier-mandated opt-out and help keywords cannot be escaped.
public enum GatewayKeyword: String, Sendable, CaseIterable {
    case optOut, help, optIn, menu, back

    public static let escapePrefix: Character = "\\"
    public static let optOutWords: Set<String> = ["STOP", "STOPALL", "UNSUBSCRIBE", "CANCEL", "END", "QUIT", "OPTOUT", "REVOKE"]
    public static let helpWords: Set<String> = ["HELP", "INFO"]
    public static let optInWords: Set<String> = ["START", "UNSTOP", "YES"]

    /// Normalized keyword form of a message.
    public static func normalize(_ text: String) -> String {
        var s = Substring(text.trimmingCharacters(in: .whitespacesAndNewlines))
        while let last = s.last, last == "." || last == "!" { s = s.dropLast() }
        return s.trimmingCharacters(in: .whitespaces).uppercased()
    }

    /// Classifies a whole message.
    public static func classify(_ text: String) -> GatewayKeyword? {
        let word = normalize(text)
        if optOutWords.contains(word) { return .optOut }
        if helpWords.contains(word) { return .help }
        if optInWords.contains(word) { return .optIn }
        if word == "MENU" { return .menu }
        if word == "BACK" { return .back }
        return nil
    }
}
