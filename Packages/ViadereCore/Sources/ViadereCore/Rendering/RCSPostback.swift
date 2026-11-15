import Foundation

/// What an RCS suggested reply means, decoded from the *renderer's* postback string.
///
/// `ChannelRenderer.rcs` emits `viadere:{interactionId}:{target}` placeholders. Servers must **not**
/// put that string on the wire (it exposes raw ids and is trivially forgeable); they translate each
/// suggestion into an opaque, signed, single-use token and keep this target server-side.
public enum RCSPostbackTarget: Sendable, Hashable {
    case decision(Decision)
    case option(String)
    /// Index into `ReplyPayload.suggestedReplies`.
    case suggestedReply(Int)

    /// Parses the target part of a renderer postback for `interactionId`. Returns `nil` for anything
    /// that does not belong to that interaction or is not a known target.
    public static func parse(postback: String, interactionId: InteractionID) -> RCSPostbackTarget? {
        let prefix = "viadere:\(interactionId):"
        guard postback.hasPrefix(prefix) else { return nil }
        let target = String(postback.dropFirst(prefix.count))
        if target.hasPrefix("decision.") {
            return Decision(rawValue: String(target.dropFirst("decision.".count))).map(RCSPostbackTarget.decision)
        }
        if target.hasPrefix("option.") {
            let id = String(target.dropFirst("option.".count))
            return id.isEmpty ? nil : .option(id)
        }
        if target.hasPrefix("suggested.") {
            guard let index = Int(target.dropFirst("suggested.".count)), index >= 0 else { return nil }
            return .suggestedReply(index)
        }
        return nil
    }

    /// Stable server-side string form (stored next to the opaque token).
    public var storageValue: String {
        switch self {
        case .decision(let d): "decision.\(d.rawValue)"
        case .option(let id): "option.\(id)"
        case .suggestedReply(let i): "suggested.\(i)"
        }
    }

    public init?(storageValue: String) {
        if storageValue.hasPrefix("decision."), let d = Decision(rawValue: String(storageValue.dropFirst(9))) {
            self = .decision(d)
        } else if storageValue.hasPrefix("option."), storageValue.count > 7 {
            self = .option(String(storageValue.dropFirst(7)))
        } else if storageValue.hasPrefix("suggested."), let i = Int(storageValue.dropFirst(10)), i >= 0 {
            self = .suggestedReply(i)
        } else {
            return nil
        }
    }
}

extension RCSSuggestion {
    /// The decoded target of a reply suggestion for `interactionId` (`nil` for URL actions).
    public func target(forInteraction interactionId: InteractionID) -> RCSPostbackTarget? {
        guard kind == .reply, let postbackData else { return nil }
        return RCSPostbackTarget.parse(postback: postbackData, interactionId: interactionId)
    }
}
