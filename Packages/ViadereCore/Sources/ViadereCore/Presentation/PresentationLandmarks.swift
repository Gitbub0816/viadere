import Foundation

/// The layout landmarks every renderer of a `PresentationTree` must reproduce (plan section 5.3, WP-3.8): node order, visible text in reading
/// order, whether the attribution bar is present (and first), the number of actions, and which nodes are protected. The tree-level parity
/// harness stores them next to each golden tree; the web renderer's tests (and, on a macOS runner, the SwiftUI renderer's) extract the same
/// values from their output and compare.
public struct PresentationLandmarks: Sendable, Hashable, Codable {
    /// `PresentationNode.kind` of every node, depth-first in reading order (the root `screen` first).
    public var nodeKinds: [String]
    /// Every visible string in reading order (screen title, then node texts; choice options after their label; action labels in bar order).
    public var texts: [String]
    public var attributionBar: Bool
    /// True when the attribution bar is the first child of the screen (spec A6a: read first).
    public var attributionFirst: Bool
    /// Total actions across all action bars (system actions included).
    public var actionCount: Int
    /// Kinds of the protected nodes in reading order (drawn with `ProtectedPalette`, never brand-styled).
    public var protectedKinds: [String]

    enum CodingKeys: String, CodingKey {
        case texts
        case nodeKinds = "node_kinds"
        case attributionBar = "attribution_bar"
        case attributionFirst = "attribution_first"
        case actionCount = "action_count"
        case protectedKinds = "protected_kinds"
    }

    public init(_ tree: PresentationTree) {
        let nodes = tree.nodes
        nodeKinds = nodes.map(\.kind)
        texts = nodes.flatMap(Self.texts(of:))
        attributionBar = nodes.contains { if case .attributionBar = $0 { true } else { false } }
        if case .attributionBar? = tree.root.children.first { attributionFirst = true } else { attributionFirst = false }
        actionCount = nodes.reduce(0) { count, node in if case .actionBar(let bar) = node { count + bar.actions.count } else { count } }
        protectedKinds = nodes.filter(\.isProtected).map(\.kind)
    }

    /// The visible strings of one node (not its children), in the order a renderer shows them.
    public static func texts(of node: PresentationNode) -> [String] {
        switch node {
        case .screen(let n): [n.title]
        case .header(let n): [n.text]
        case .attributionBar(let n): [n.text, n.verifiedLabel]
        case .text(let n): [n.text]
        case .fieldGroup: []
        case .choice(let n): [n.label] + n.options.map(\.label)
        case .input(let n): [n.label]
        case .actionBar(let n): n.actions.map(\.label)
        // The amount is part of the statement; the responsible business is named in the title and statement.
        case .confirmationPanel(let n): [n.title, n.statement, n.effect]
        case .outcomeStatus(let n): [n.text]
        case .moduleSlot: []
        case .notice(let n): (n.title.map { [$0] } ?? []) + [n.text]
        }
    }
}
