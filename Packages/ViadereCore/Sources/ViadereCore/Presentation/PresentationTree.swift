import Foundation

/// Semantic style roles (never colors or fonts: renderers map roles to the resolved palette, or to `ProtectedPalette` for protected nodes).
public enum PresentationRole: String, Sendable, Codable, CaseIterable, Hashable {
    case primary, secondary, danger, surface
}

/// Who a tree speaks for.
public enum PresentationOrigin: String, Sendable, Codable, CaseIterable, Hashable {
    /// A business-authored Loop: always carries the attribution bar.
    case business
    /// A Viadere first-party surface: never carries a "Built by" label.
    case viadere
    /// The safe fallback: publisher metadata was missing or invalid; no business content is shown.
    case unavailable
}

public struct ScreenNode: Sendable, Hashable, Codable {
    public var id: String
    /// Screen title for accessibility (the navigation title).
    public var title: String
    public var children: [PresentationNode]
}

public struct HeaderNode: Sendable, Hashable, Codable {
    public var text: String
    public var role: PresentationRole
}

/// "Built by {verified business}" (spec A6a). Inserted by the builder from the signed manifest and the verified business record; first
/// child of every business Loop screen; protected (no Brand Kit styling, no frame drawn over it).
public struct AttributionNode: Sendable, Hashable, Codable {
    public var text: String
    /// Read first by screen readers: "Built by {name}, a business on Viadere" (A6a.T5).
    public var accessibilityLabel: String
    public var businessId: BusinessID
    public var businessName: String
    /// The separate verified-business indicator (never merged into the attribution text).
    public var verified: Bool
    public var verifiedLabel: String
    public var role: PresentationRole
    public var protected: Bool

    enum CodingKeys: String, CodingKey {
        case text, verified, role, protected
        case accessibilityLabel = "accessibility_label"
        case businessId = "business_id"
        case businessName = "business_name"
        case verifiedLabel = "verified_label"
    }
}

public struct TextNode: Sendable, Hashable, Codable {
    public var text: String
    public var role: PresentationRole
}

public struct ChoiceOptionNode: Sendable, Hashable, Codable {
    public var id: String
    public var label: String
}

public struct ChoiceNode: Sendable, Hashable, Codable {
    public var fieldId: String
    public var label: String
    public var multiple: Bool
    /// `list` or `time_slot`.
    public var control: String
    public var required: Bool
    public var options: [ChoiceOptionNode]

    enum CodingKeys: String, CodingKey {
        case label, multiple, control, required, options
        case fieldId = "field_id"
    }
}

public struct InputNode: Sendable, Hashable, Codable {
    public var fieldId: String
    public var label: String
    /// `short_text`, `date`, `yes_no` or `acknowledgement`.
    public var input: String
    public var required: Bool
    public var maxLength: Int?

    enum CodingKeys: String, CodingKey {
        case label, input, required
        case fieldId = "field_id"
        case maxLength = "max_length"
    }
}

public struct FieldGroupNode: Sendable, Hashable, Codable {
    public var id: String
    /// `choice` and `input` nodes only.
    public var children: [PresentationNode]
}

public struct ActionNode: Sendable, Hashable, Codable {
    public var id: String
    /// A registered action type, or a Viadere system action (`viadere.close`, `viadere.report`, `viadere.cancel`).
    public var actionType: String
    public var label: String
    public var role: PresentationRole
    public var requiresConfirmation: Bool
    public var system: Bool

    enum CodingKeys: String, CodingKey {
        case id, label, role, system
        case actionType = "action_type"
        case requiresConfirmation = "requires_confirmation"
    }
}

public struct ActionBarNode: Sendable, Hashable, Codable {
    public var actions: [ActionNode]
    /// True for confirmation and fallback bars: rendered with the protected palette.
    public var protected: Bool
}

/// The confirmation of a consequential action, generated from the action registry: names the responsible business, the exact effect and
/// any amount (spec A6a.2, plan section 4.4 point 3). Protected.
public struct ConfirmationPanelNode: Sendable, Hashable, Codable {
    public var actionId: String
    public var title: String
    public var statement: String
    public var effect: String
    public var amount: String?
    public var responsibleBusinessId: BusinessID
    public var responsibleBusinessName: String
    public var accessibilityLabel: String
    public var protected: Bool

    enum CodingKeys: String, CodingKey {
        case title, statement, effect, amount, protected
        case actionId = "action_id"
        case responsibleBusinessId = "responsible_business_id"
        case responsibleBusinessName = "responsible_business_name"
        case accessibilityLabel = "accessibility_label"
    }
}

public struct OutcomeStatusNode: Sendable, Hashable, Codable {
    public var outcome: LoopActionOutcome
    public var text: String
    public var protected: Bool
}

public struct ModuleSlotNode: Sendable, Hashable, Codable {
    public var module: String
    public var size: ModuleSize
}

public struct NoticeNode: Sendable, Hashable, Codable {
    public enum Kind: String, Sendable, Codable, Hashable {
        case unavailable
        case paused
        /// "Don't share health details here." on any step with a free-text field (FX-4 layer 3).
        case healthPrivacy = "health_privacy"
        case preview
    }

    public var kind: Kind
    public var title: String?
    public var text: String
    public var protected: Bool

    /// `notice_kind` on the wire: `kind` is the node discriminator.
    enum CodingKeys: String, CodingKey {
        case title, text, protected
        case kind = "notice_kind"
    }
}

/// The closed node set of the platform-neutral presentation model (plan section 4.4; FX-1). Order of `children` is reading order.
public indirect enum PresentationNode: Sendable, Hashable, Codable {
    case screen(ScreenNode)
    case header(HeaderNode)
    case attributionBar(AttributionNode)
    case text(TextNode)
    case fieldGroup(FieldGroupNode)
    case choice(ChoiceNode)
    case input(InputNode)
    case actionBar(ActionBarNode)
    case confirmationPanel(ConfirmationPanelNode)
    case outcomeStatus(OutcomeStatusNode)
    case moduleSlot(ModuleSlotNode)
    case notice(NoticeNode)

    public var kind: String {
        switch self {
        case .screen: "screen"
        case .header: "header"
        case .attributionBar: "attribution_bar"
        case .text: "text"
        case .fieldGroup: "field_group"
        case .choice: "choice"
        case .input: "input"
        case .actionBar: "action_bar"
        case .confirmationPanel: "confirmation_panel"
        case .outcomeStatus: "outcome_status"
        case .moduleSlot: "module_slot"
        case .notice: "notice"
        }
    }

    /// Whether the node is drawn with `ProtectedPalette` and above any frame (`z: protected`).
    public var isProtected: Bool {
        switch self {
        case .attributionBar(let n): n.protected
        case .confirmationPanel(let n): n.protected
        case .outcomeStatus(let n): n.protected
        case .notice(let n): n.protected
        case .actionBar(let n): n.protected
        default: false
        }
    }

    public var children: [PresentationNode] {
        switch self {
        case .screen(let n): n.children
        case .fieldGroup(let n): n.children
        default: []
        }
    }

    /// Depth-first, reading order.
    public var flattened: [PresentationNode] { [self] + children.flatMap(\.flattened) }

    private enum KindKey: String, CodingKey { case kind }

    public init(from decoder: any Decoder) throws {
        let kind = try decoder.container(keyedBy: KindKey.self).decode(String.self, forKey: .kind)
        switch kind {
        case "screen": self = .screen(try ScreenNode(from: decoder))
        case "header": self = .header(try HeaderNode(from: decoder))
        case "attribution_bar": self = .attributionBar(try AttributionNode(from: decoder))
        case "text": self = .text(try TextNode(from: decoder))
        case "field_group": self = .fieldGroup(try FieldGroupNode(from: decoder))
        case "choice": self = .choice(try ChoiceNode(from: decoder))
        case "input": self = .input(try InputNode(from: decoder))
        case "action_bar": self = .actionBar(try ActionBarNode(from: decoder))
        case "confirmation_panel": self = .confirmationPanel(try ConfirmationPanelNode(from: decoder))
        case "outcome_status": self = .outcomeStatus(try OutcomeStatusNode(from: decoder))
        case "module_slot": self = .moduleSlot(try ModuleSlotNode(from: decoder))
        case "notice": self = .notice(try NoticeNode(from: decoder))
        default:
            // A renderer never guesses: an unknown node kind fails the whole tree (the caller shows the fallback).
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Unknown presentation node \(kind)"))
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: KindKey.self)
        try container.encode(kind, forKey: .kind)
        switch self {
        case .screen(let n): try n.encode(to: encoder)
        case .header(let n): try n.encode(to: encoder)
        case .attributionBar(let n): try n.encode(to: encoder)
        case .text(let n): try n.encode(to: encoder)
        case .fieldGroup(let n): try n.encode(to: encoder)
        case .choice(let n): try n.encode(to: encoder)
        case .input(let n): try n.encode(to: encoder)
        case .actionBar(let n): try n.encode(to: encoder)
        case .confirmationPanel(let n): try n.encode(to: encoder)
        case .outcomeStatus(let n): try n.encode(to: encoder)
        case .moduleSlot(let n): try n.encode(to: encoder)
        case .notice(let n): try n.encode(to: encoder)
        }
    }
}

/// Styling applied by renderers after layout validation. Brand values are already clamped (`ContrastPolicy.resolve`); protected nodes
/// ignore all of it and use `ProtectedPalette`.
public struct PresentationStyle: Sendable, Hashable, Codable {
    public enum Source: String, Sendable, Codable, Hashable { case neutral, brandKit = "brand_kit" }

    public var source: Source
    public var kitId: String?
    public var palette: BrandStyleResolution
    public var frameId: String?
    public var radius: BrandRadius
    public var border: BrandBorder
    public var typeScale: BrandTypeScale

    enum CodingKeys: String, CodingKey {
        case source, palette, radius, border
        case kitId = "kit_id"
        case frameId = "frame_id"
        case typeScale = "type_scale"
    }

    public static let neutral = PresentationStyle(source: .neutral, kitId: nil, palette: .neutral, frameId: nil, radius: .medium, border: .hairline,
                                                  typeScale: .standard)
}

/// The platform-neutral presentation model (FX-1; `SECURITY.md` §2.92; schema `docs/protocol/schemas/presentation-tree-v1.schema.json`).
/// Produced only by `PresentationBuilder`; consumed by the SwiftUI renderer (iOS, production) and the server-side web renderer (Studio
/// preview only). Equatable and canonically encodable, so tree equality is tested on Linux and the vectors double as the Android
/// conformance spec (FX-2).
public struct PresentationTree: Sendable, Hashable, Codable {
    public static let version = 1

    public var v: Int
    public var origin: PresentationOrigin
    public var root: PresentationNode
    public var style: PresentationStyle
    /// Machine reason for a fallback tree (telemetry, never shown).
    public var fallbackReason: String?
    /// Concise business-origin indicator for compact surfaces (A6a.T6); `nil` for first-party and fallback trees.
    public var compactOrigin: String?

    enum CodingKeys: String, CodingKey {
        case v, origin, root, style
        case fallbackReason = "fallback_reason"
        case compactOrigin = "compact_origin"
    }

    /// Every node in reading order.
    public var nodes: [PresentationNode] { root.flattened }

    /// Canonical JSON bytes (`SECURITY.md` §2.2).
    public func canonicalJSON() throws -> Data { try CanonicalJSON.serialize(try JSONValue.encoding(self)) }
}
