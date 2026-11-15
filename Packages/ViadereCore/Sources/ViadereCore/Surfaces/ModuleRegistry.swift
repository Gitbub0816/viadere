import Foundation

/// Display sizes a module supports.
public enum ModuleSize: String, Sendable, Codable, CaseIterable, Hashable {
    case compact, regular, expanded
}

/// What the customer may do inside a module (spec B6.1 "interaction permissions").
public enum ModulePermission: String, Sendable, Codable, CaseIterable, Hashable {
    case view
    case reply
    /// Opens a first-party decision flow (approval sheet, verification sheet). The module never decides itself.
    case openDecision = "open_decision"
    case redeem
    /// Opens a Loop (only where the customer enabled Loops and authorized the business).
    case openLoop = "open_loop"
    /// Leaves Viadere for a merchant's hosted checkout after a fixed interstitial (FX-5; reserved).
    case externalHandoff = "external_handoff"
}

/// Per-platform support (FX-2: Android is specified, not built).
public enum ModulePlatformSupport: String, Sendable, Codable, Hashable {
    case supported
    case specOnly = "spec_only"
    case previewOnly = "preview_only"
    case unsupported
}

/// The accessibility contract of a module (checked by snapshot tests on the renderer): its role, the label it announces first, and the
/// minimum touch target.
public struct ModuleAccessibilityContract: Sendable, Codable, Hashable {
    public var role: String
    public var headingLabel: String
    public var minimumTouchTargetPoints: Int
    /// The module announces its business owner when it shows business content.
    public var announcesBusiness: Bool
}

public enum ModuleAvailability: String, Sendable, Codable, Hashable {
    case active
    /// Present in the registry and in layouts only once the feature is enabled (Loops: Phase 3 plus customer consent).
    case gated
    /// Data only; refused in every layout until the feature ships (`shop`, FX-5, WP-4.6).
    case reserved
}

/// One module of the registry (spec B6.1; plan section 4.7).
public struct ModuleDescriptor: Sendable, Codable, Hashable {
    public var id: String
    /// Input schema: the names of the module's configuration inputs. Version 1 modules take none (their content comes from first-party
    /// data); the field exists so a later version can add enumerated inputs without a contract change.
    public var inputs: [String]
    public var sizes: [ModuleSize]
    public var permissions: [ModulePermission]
    public var accessibility: ModuleAccessibilityContract
    public var riskClass: LoopRiskClass
    public var platforms: [String: ModulePlatformSupport]
    public var availability: ModuleAvailability
    /// For `external_handoff` modules: the handoff kind.
    public var handoff: LoopHandoffKind?
}

/// The closed module registry. Businesses choose modules and order from page templates; they never control navigation, security UX or
/// module behavior.
public struct ModuleRegistry: Sendable {
    public let modules: [ModuleDescriptor]

    public init(modules: [ModuleDescriptor]) { self.modules = modules }

    public func module(_ id: String) -> ModuleDescriptor? { modules.first { $0.id == id } }

    private static func module(_ id: String, _ heading: String, sizes: [ModuleSize] = [.compact, .regular, .expanded], permissions: [ModulePermission],
                               risk: LoopRiskClass = .low, availability: ModuleAvailability = .active, announcesBusiness: Bool = true,
                               android: ModulePlatformSupport = .specOnly, handoff: LoopHandoffKind? = nil) -> ModuleDescriptor {
        ModuleDescriptor(id: id, inputs: [], sizes: sizes, permissions: permissions,
                         accessibility: ModuleAccessibilityContract(role: "region", headingLabel: heading, minimumTouchTargetPoints: 44,
                                                                    announcesBusiness: announcesBusiness),
                         riskClass: risk, platforms: ["ios": .supported, "android": android, "web_preview": .previewOnly],
                         availability: availability, handoff: handoff)
    }

    /// Version 1 (plan section 4.7): `profile`, `message`, `offers`, `rewards`, `recent_activity`, `approvals`, `verification_requests`,
    /// `loops` (gated until Phase 3), `shop` (reserved, Shopify handoff only, physical goods and out-of-app services, FX-5).
    public static let v1 = ModuleRegistry(modules: [
        module("profile", "Business profile", sizes: [.regular, .expanded], permissions: [.view]),
        module("message", "Messages", permissions: [.view, .reply]),
        module("offers", "Offers", permissions: [.view, .redeem]),
        module("rewards", "Rewards", permissions: [.view, .redeem]),
        module("recent_activity", "Recent activity", permissions: [.view]),
        module("approvals", "Approvals", permissions: [.view, .openDecision], risk: .high),
        module("verification_requests", "Verification requests", permissions: [.view, .openDecision], risk: .high),
        module("loops", "Requests from this business", permissions: [.view, .openLoop], risk: .medium, availability: .gated),
        module("shop", "Shop", sizes: [.regular, .expanded], permissions: [.view, .externalHandoff], risk: .medium, availability: .reserved,
               handoff: .shop),
    ])
}

/// A page or widget template: which slots exist (spec B6.2: pages arrange modules; widgets use constrained slots).
public struct PageTemplate: Sendable, Hashable {
    public var id: String
    public var maxModules: Int
    public var allowedSizes: [ModuleSize]
    /// The module that must come first (the verified profile on a business home), if any.
    public var requiredFirst: String?
    /// Modules a widget template may hold (`nil` = any active module).
    public var allowedModules: Set<String>?

    public static let businessHome = PageTemplate(id: "business_home", maxModules: 8, allowedSizes: [.compact, .regular, .expanded], requiredFirst: "profile")
    public static let widgetSmall = PageTemplate(id: "widget_small", maxModules: 1, allowedSizes: [.compact], requiredFirst: nil,
                                                 allowedModules: ["offers", "rewards", "recent_activity"])
    public static let widgetMedium = PageTemplate(id: "widget_medium", maxModules: 2, allowedSizes: [.compact], requiredFirst: nil,
                                                  allowedModules: ["offers", "rewards", "recent_activity", "message"])
    public static let all: [PageTemplate] = [.businessHome, .widgetSmall, .widgetMedium]
}

public struct ModulePlacement: Sendable, Hashable {
    public var module: String
    public var size: ModuleSize

    public init(module: String, size: ModuleSize) {
        self.module = module
        self.size = size
    }
}

/// A business's module layout (`business_surfaces.layout_json`; schema `docs/protocol/schemas/module-layout-v1.schema.json`).
public struct SurfaceLayout: Sendable, Hashable {
    public static let version: Int64 = 1
    public var template: String
    public var modules: [ModulePlacement]

    public init(template: String, modules: [ModulePlacement]) {
        self.template = template
        self.modules = modules
    }

    public var jsonValue: JSONValue {
        .object(["v": .integer(Self.version), "template": .string(template),
                 "modules": .array(modules.map { .object(["module": .string($0.module), "size": .string($0.size.rawValue)]) })])
    }

    /// Strict parse plus every layout rule. Returns the layout only when it is valid.
    public static func validate(_ value: JSONValue, registry: ModuleRegistry = .v1, loopsEnabled: Bool = false) -> (layout: SurfaceLayout?, issues: [ContractIssue]) {
        let sink = ContractIssueSink()
        guard let root = StrictObject(value, path: "", allowed: ["v", "template", "modules"], required: ["v", "template", "modules"], sink: sink) else {
            return (nil, sink.issues)
        }
        if let v = root.int("v"), v != version { sink.add("unsupported_version", "v") }
        let templateId = root.string("template") ?? ""
        let template = PageTemplate.all.first { $0.id == templateId }
        if template == nil, root.has("template") { sink.add("unknown_template", "template") }
        var placements: [ModulePlacement] = []
        var seen = Set<String>()
        let items = root.array("modules") ?? []
        if items.isEmpty, root.has("modules") { sink.add("empty_layout", "modules") }
        for (i, item) in items.enumerated() {
            let path = "modules[\(i)]"
            guard let m = StrictObject(item, path: path, allowed: ["module", "size"], required: ["module", "size"], sink: sink),
                  let id = m.string("module"), let rawSize = m.string("size") else { continue }
            guard let size = ModuleSize(rawValue: rawSize) else { sink.add(ContractIssue.invalidValue, "\(path).size"); continue }
            guard let descriptor = registry.module(id) else { sink.add("unknown_module", "\(path).module"); continue }
            if !seen.insert(id).inserted { sink.add("duplicate_module", "\(path).module") }
            switch descriptor.availability {
            case .active: break
            case .gated: if !loopsEnabled { sink.add("module_not_enabled", "\(path).module") }
            case .reserved: sink.add("module_reserved", "\(path).module")
            }
            if !descriptor.sizes.contains(size) { sink.add("size_not_supported", "\(path).size") }
            if let template {
                if !template.allowedSizes.contains(size) { sink.add("size_not_allowed_in_template", "\(path).size") }
                if let allowed = template.allowedModules, !allowed.contains(id) { sink.add("module_not_allowed_in_template", "\(path).module") }
            }
            placements.append(ModulePlacement(module: id, size: size))
        }
        if let template {
            if items.count > template.maxModules { sink.add("too_many_modules", "modules") }
            if let first = template.requiredFirst {
                if !placements.contains(where: { $0.module == first }) { sink.add("missing_required_module", "modules") } else if placements.first?.module != first {
                    sink.add("required_module_not_first", "modules")
                }
            }
        }
        let issues = sink.issues
        return (issues.isEmpty ? SurfaceLayout(template: templateId, modules: placements) : nil, issues)
    }
}
