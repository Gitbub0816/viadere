import Foundation

public enum BrandRadius: String, Sendable, Codable, CaseIterable, Hashable { case none, small, medium, large }
public enum BrandBorder: String, Sendable, Codable, CaseIterable, Hashable { case none, hairline, regular }
public enum BrandTypeScale: String, Sendable, Codable, CaseIterable, Hashable { case compact, standard, large }

/// The enumerated style tokens of a Brand Kit (spec B2.1, plan section 4.6). Colors are `#RRGGBB`; everything else is an enumerated id.
/// There is **no** member for text, links, labels, layout, fonts, button meaning or any protected element; foregrounds are computed
/// (`on_primary` accepts only `"auto"`). Unknown members are refused.
public struct BrandTokens: Sendable, Hashable {
    public var primary: BrandColor
    public var secondary: BrandColor?
    public var accent: BrandColor?
    public var surface: BrandColor?
    public var radius: BrandRadius?
    public var border: BrandBorder?
    public var typeScale: BrandTypeScale?

    public init(primary: BrandColor, secondary: BrandColor? = nil, accent: BrandColor? = nil, surface: BrandColor? = nil,
                radius: BrandRadius? = nil, border: BrandBorder? = nil, typeScale: BrandTypeScale? = nil) {
        self.primary = primary
        self.secondary = secondary
        self.accent = accent
        self.surface = surface
        self.radius = radius
        self.border = border
        self.typeScale = typeScale
    }

    static let members: Set<String> = ["primary", "secondary", "accent", "surface", "on_primary", "radius", "border", "type_scale"]

    public var jsonValue: JSONValue {
        var o: [String: JSONValue] = ["primary": .string(primary.hex), "on_primary": .string("auto")]
        if let secondary { o["secondary"] = .string(secondary.hex) }
        if let accent { o["accent"] = .string(accent.hex) }
        if let surface { o["surface"] = .string(surface.hex) }
        if let radius { o["radius"] = .string(radius.rawValue) }
        if let border { o["border"] = .string(border.rawValue) }
        if let typeScale { o["type_scale"] = .string(typeScale.rawValue) }
        return .object(o)
    }

    /// A color token: exactly `#` and six hex digits. Anything else (`red`, `#fff`, `rgba(...)`, `url(...)`, CSS with `;`) is refused.
    static func color(_ value: String?) -> BrandColor? {
        guard let value, value.utf8.count == 7, value.hasPrefix("#") else { return nil }
        return BrandColor(value)
    }

    /// Strict parse of a tokens object.
    public static func parse(_ value: JSONValue) -> (tokens: BrandTokens?, issues: [ContractIssue]) {
        let sink = ContractIssueSink()
        let tokens = parse(value, path: "tokens", sink: sink)
        return (sink.issues.isEmpty ? tokens : nil, sink.issues)
    }

    static func parse(_ value: JSONValue?, path: String, sink: ContractIssueSink) -> BrandTokens? {
        guard let o = StrictObject(value, path: path, allowed: members, required: ["primary"], sink: sink) else { return nil }
        func colorMember(_ key: String) -> BrandColor? {
            guard o.has(key) else { return nil }
            guard let c = color(o.string(key)) else { sink.add("invalid_color", o.child(key)); return nil }
            return c
        }
        func enumMember<E: RawRepresentable>(_ key: String, _ type: E.Type) -> E? where E.RawValue == String {
            guard o.has(key) else { return nil }
            guard let raw = o.string(key), let e = E(rawValue: raw) else { sink.add(ContractIssue.invalidValue, o.child(key)); return nil }
            return e
        }
        if o.has("on_primary"), o.string("on_primary") != "auto" { sink.add(ContractIssue.invalidValue, o.child("on_primary")) }
        guard let primary = colorMember("primary") else { return nil }
        return BrandTokens(primary: primary, secondary: colorMember("secondary"), accent: colorMember("accent"), surface: colorMember("surface"),
                           radius: enumMember("radius", BrandRadius.self), border: enumMember("border", BrandBorder.self),
                           typeScale: enumMember("type_scale", BrandTypeScale.self))
    }
}

/// Viadere-authored decorative frames (spec B3.3). The manifest names only an id the registry knows and currently allows; anything else
/// means no frame. Frames never draw over protected nodes (`PresentationNode` with `protected`).
public struct FrameDefinition: Sendable, Hashable {
    public var id: String
    /// Unix seconds; `nil` = no bound.
    public var availableFrom: Int64?
    public var availableUntil: Int64?

    public init(id: String, availableFrom: Int64? = nil, availableUntil: Int64? = nil) {
        self.id = id
        self.availableFrom = availableFrom
        self.availableUntil = availableUntil
    }

    public func isAvailable(at now: Date) -> Bool {
        let t = Int64(now.timeIntervalSince1970.rounded(.down))
        if let from = availableFrom, t < from { return false }
        if let until = availableUntil, t >= until { return false }
        return true
    }
}

public struct FrameRegistry: Sendable {
    public let frames: [FrameDefinition]

    public init(frames: [FrameDefinition]) { self.frames = frames }

    public func definition(_ id: String) -> FrameDefinition? { frames.first { $0.id == id } }

    /// The frame to draw: `id` only if registered and available at `now`, else `nil` (no frame).
    public func resolve(_ id: String?, at now: Date) -> String? {
        guard let id, let frame = definition(id), frame.isAvailable(at: now) else { return nil }
        return frame.id
    }

    /// Version 1: an always-available hairline frame and the 2026/27 winter frame (2026-12-01 to 2027-03-01 UTC).
    public static let v1 = FrameRegistry(frames: [
        FrameDefinition(id: "viadere.frame.hairline.v1"),
        FrameDefinition(id: "viadere.frame.snow.v1", availableFrom: 1_796_083_200, availableUntil: 1_803_859_200),
    ])
}
