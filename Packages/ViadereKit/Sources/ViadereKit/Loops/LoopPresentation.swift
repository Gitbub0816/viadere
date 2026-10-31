import Foundation
import ViadereCore

/// Renderer-side rules for `PresentationTree` (WP-3.6; plan section 4.4; SECURITY.md §2.92). The SwiftUI `PresentationView` lays out
/// exactly what these return; they are here so the rules are tested on Linux.
public enum PresentationRendering {
    /// A tree the renderer may draw, or the fallback: a business tree must open with the protected attribution bar, a fallback or paused
    /// tree may contain only protected nodes, and the version must be known. (The builder already guarantees this; the renderer does not
    /// trust it blindly.)
    public static func validated(_ tree: PresentationTree) -> PresentationTree {
        guard tree.v == PresentationTree.version, case .screen(let screen) = tree.root else {
            return PresentationBuilder.fallback(.manifestInvalid)
        }
        switch tree.origin {
        case .business:
            guard case .attributionBar(let bar)? = screen.children.first, bar.protected, bar.verified,
                  screen.children.dropFirst().allSatisfy({ if case .attributionBar = $0 { return false } else { return true } }) else {
                return PresentationBuilder.fallback(.manifestInvalid)
            }
        case .viadere:
            guard !tree.nodes.contains(where: { if case .attributionBar = $0 { return true } else { return false } }) else {
                return PresentationBuilder.fallback(.publisherMismatch)
            }
        case .unavailable:
            guard screen.children.allSatisfy(\.isProtected), tree.style.source == .neutral else { return PresentationBuilder.fallback(.manifestInvalid) }
        }
        return tree
    }

    /// Decodes a serialized tree; anything unknown (an unknown node kind, version or member type) gives the fallback (never a guess).
    public static func decodeOrFallback(_ data: Data) -> PresentationTree {
        guard let tree = try? JSONDecoder().decode(PresentationTree.self, from: data) else { return PresentationBuilder.fallback(.manifestInvalid) }
        return validated(tree)
    }

    /// The palette a node is drawn with: `ProtectedPalette` (neutral) for protected nodes whatever the kit, else the tree's clamped style.
    public static func palette(for node: PresentationNode, in tree: PresentationTree, appearance: BrandAppearance) -> ResolvedPalette {
        node.isProtected ? ProtectedPalette.palette(appearance) : tree.style.palette.palette(appearance)
    }

    /// Whether a frame may be drawn behind this node (`z: protected` nodes are never covered by a frame).
    public static func allowsFrame(behind node: PresentationNode, in tree: PresentationTree) -> Bool {
        tree.style.frameId != nil && !node.isProtected
    }

    /// The spoken label of a node (A6a.T5: the attribution bar is read first, with its explicit label).
    public static func accessibilityLabel(_ node: PresentationNode) -> String? {
        switch node {
        case .screen(let n): return n.title
        case .header(let n): return n.text
        case .attributionBar(let n): return n.accessibilityLabel
        case .text(let n): return n.text
        case .fieldGroup: return nil
        case .choice(let n): return n.required ? "\(n.label), required" : n.label
        case .input(let n): return n.required ? "\(n.label), required" : n.label
        case .actionBar: return nil
        case .confirmationPanel(let n): return n.accessibilityLabel
        case .outcomeStatus(let n): return "Status: \(n.text)"
        case .moduleSlot: return nil
        case .notice(let n): return [n.title, n.text].compactMap { $0 }.joined(separator: ". ")
        }
    }
}

/// How each of the five outcome states is shown (plan section 4.5): distinct and non-promissory. The words come from the tree
/// (`OutcomeStatusNode.text`, Viadere's catalog); this adds the tone and symbol.
public enum LoopOutcomeTone: String, Sendable, Hashable, CaseIterable {
    case confirmed, declined, waiting, overdue, uncertain

    public init(_ outcome: LoopActionOutcome) {
        switch outcome {
        case .accepted: self = .confirmed
        case .rejected: self = .declined
        case .pending: self = .waiting
        case .timedOut: self = .overdue
        case .unknown: self = .uncertain
        }
    }

    /// SF Symbol name (no shield imagery).
    public var symbol: String {
        switch self {
        case .confirmed: "checkmark.circle"
        case .declined: "xmark.circle"
        case .waiting: "clock"
        case .overdue: "hourglass"
        case .uncertain: "questionmark.circle"
        }
    }

    /// Whether the state is final (the business decided).
    public var isFinal: Bool { self == .confirmed || self == .declined }
}

/// A value the customer entered for one field, before it becomes a request input (`LoopInputValidator` on both sides).
public enum LoopFieldValue: Sendable, Hashable {
    case option(String)
    case options([String])
    case text(String)
    /// `YYYY-MM-DD`.
    case date(String)
    case flag(Bool)

    public var jsonValue: JSONValue {
        switch self {
        case .option(let id): .string(id)
        case .options(let ids): .array(ids.map { .string($0) })
        case .text(let s): .string(s.trimmingCharacters(in: .whitespacesAndNewlines))
        case .date(let s): .string(s)
        case .flag(let b): .bool(b)
        }
    }

    /// `YYYY-MM-DD` of `date` in `timeZone` (Gregorian), as the server expects.
    public static func dateString(_ date: Date, timeZone: TimeZone = .current) -> String {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = timeZone
        let c = calendar.dateComponents([.year, .month, .day], from: date)
        return String(format: "%04d-%02d-%02d", c.year ?? 1970, c.month ?? 1, c.day ?? 1)
    }
}

/// Where a `viadere.loop` notification leads (SECURITY.md §2.98: the push is opaque, title "Viadere", no business name or content).
public enum LoopNotificationRoute: Sendable, Hashable {
    public static let category = "viadere.loop"
    /// Keys a future push may carry with the instance id (the current server sends none; see App/README.md).
    static let instanceKeys = ["loopInstanceId", "lid"]

    case instance(LoopInstanceID)
    /// No instance id in the payload: open Alerts, where the `loop_task` item leads to the instance.
    case alerts

    public static func route(categoryIdentifier: String, userInfo: [String: String]) -> LoopNotificationRoute? {
        guard categoryIdentifier == category else { return nil }
        for key in instanceKeys {
            if let raw = userInfo[key], let id = LoopInstanceID(raw) { return .instance(id) }
        }
        return .alerts
    }
}
