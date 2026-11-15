import Fluent
import Foundation
import Vapor
import ViadereCore

/// The code style a business chose for its own connect and install codes (docs/SECURITY.md §2.105): one row per business, canonical JSON
/// of Core's `BusinessCodeStyle`. No row, a row that no longer validates, a banned category or a branding stop all mean the default.
final class BusinessCodeStyleRecord: Model, @unchecked Sendable {
    static let schema = "business_code_styles"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "style_json") var styleJSON: String
    @OptionalField(key: "updated_by") var updatedBy: String?
    @Field(key: "updated_at") var updatedAt: Date
    init() {}
}

/// Tenant-scoped reads and writes of the stored style. Every function takes the business from the caller's session or the row being
/// rendered; there is no lookup by style id.
struct BusinessCodeStyleService {
    let db: any Database
    let ctx: ServerContext

    /// The style exactly as stored, if a valid one is stored (for the editor).
    func stored(businessId: UUID) async throws -> BusinessCodeStyle? {
        guard let row = try await BusinessCodeStyleRecord.query(on: db).filter(\.$businessId == businessId).first() else { return nil }
        // Decoding validates: a row written under older rules that no longer passes is ignored, never drawn.
        return try? JSONDecoder().decode(BusinessCodeStyle.self, from: Data(row.styleJSON.utf8))
    }

    /// The style to draw the business's codes with. Viadere's default when nothing valid is stored, when the business may not use branding
    /// (banned category) or while Viadere has stopped its branding.
    func effective(businessId: UUID) async throws -> BusinessCodeStyle {
        guard let business = try await BusinessRecord.find(businessId, on: db), !BrandKitService.isBanned(business) else { return .standard }
        if await PlatformFlags(db: db, ctx: ctx).brandKitsStopped(businessId: businessId) { return .standard }
        return try await stored(businessId: businessId) ?? .standard
    }

    /// Stores `style` (already validated by construction) and records who changed it.
    func save(businessId: UUID, style: BusinessCodeStyle, actor: AuditActor) async throws {
        _ = try await BrandKitService(db: db, ctx: ctx).editableBusiness(businessId)
        let json = String(decoding: try CanonicalJSON.serialize(try JSONDecoder().decode(JSONValue.self, from: JSONEncoder().encode(style))), as: UTF8.self)
        let now = ctx.now
        if let row = try await BusinessCodeStyleRecord.query(on: db).filter(\.$businessId == businessId).first() {
            row.styleJSON = json
            row.updatedBy = actor.id
            row.updatedAt = now
            try await row.update(on: db)
        } else {
            let row = BusinessCodeStyleRecord()
            row.id = UUID()
            row.businessId = businessId
            row.styleJSON = json
            row.updatedBy = actor.id
            row.updatedAt = now
            try await row.create(on: db)
        }
        _ = try await AuditService(db: db, ctx: ctx).record("brandkit.code_style_saved", actor: actor, businessId: BusinessID(businessId), subjectType: "code_style",
                                                             metadata: ["symbology": style.symbology.rawValue, "look": Self.look(style)])
    }

    static func look(_ style: BusinessCodeStyle) -> String {
        switch style.choice {
        case .ckeyPreset(let preset): preset.rawValue
        case .ckeyCustom, .qr: "custom"
        }
    }

    /// The tokens of the business's newest **approved** Brand Kit, for form suggestions only.
    func approvedTokens(businessId: UUID) async throws -> BrandTokens? {
        let kits = try await BrandKitRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$approvedJSON != nil).sort(\.$updatedAt, .descending).all()
        return kits.lazy.compactMap { BrandKitService.approvedKit($0)?.tokens }.first
    }

    // MARK: Form parsing (only known fields are read; Core validates)

    /// Builds a style from the editor's form. A refusal carries Core's reason as the message.
    static func style(from form: [String: String]) throws -> BusinessCodeStyle {
        func color(_ key: String) throws -> BrandColor {
            guard let raw = form[key]?.trimmingCharacters(in: .whitespaces), raw.utf8.count == 7, raw.hasPrefix("#"), let color = BrandColor(raw) else {
                throw APIError.validation("Enter every colour as #RRGGBB.", details: [key: "invalid_color"])
            }
            return color
        }
        func amount(_ key: String) throws -> Int {
            guard let raw = form[key], !raw.isEmpty else { return 0 }
            guard let value = Int(raw), (0...100).contains(value) else { throw APIError.validation("Bevel, shadow, texture and the accent share go from 0 to 100.", details: [key: "invalid"]) }
            return value
        }
        func pick<E: RawRepresentable>(_ key: String, _ fallback: E) throws -> E where E.RawValue == String {
            guard let raw = form[key], !raw.isEmpty else { return fallback }
            guard let value = E(rawValue: raw) else { throw APIError.validation("Choose one of the listed options.", details: [key: "invalid"]) }
            return value
        }
        do {
            switch form["look"] ?? "" {
            case "concept": return BusinessCodeStyle(preset: .concept)
            case "plain": return BusinessCodeStyle(preset: .plain)
            case "custom":
                var accents: [BrandColor] = []
                for i in 1...CKeyStyleSpec.maxAccents where form["use_accent\(i)"] == "1" { accents.append(try color("accent\(i)")) }
                let background = try color("background")
                let ink = try color("ink")
                let spec = CKeyStyleSpec(background: background, backgroundEdge: form["use_edge"] == "1" ? try color("background_edge") : background, ink: ink,
                                         inkShade: form["use_shade"] == "1" ? try color("ink_shade") : ink, accents: accents,
                                         accentPercent: accents.isEmpty ? 0 : try amount("accent_percent"), modules: try pick("modules", .rounded),
                                         rings: try pick("rings", .joined), rays: try pick("rays", .round), bevel: try amount("bevel"), shadow: try amount("shadow"),
                                         texture: try amount("texture"))
                return try BusinessCodeStyle(custom: spec)
            case "qr":
                return try BusinessCodeStyle(qrDark: try color("qr_dark"), light: try color("qr_light"))
            default:
                throw APIError.validation("Choose a code style.", details: ["look": "invalid"])
            }
        } catch let refusal as BusinessCodeStyle.Refusal {
            throw APIError.validation(refusal.message, details: ["style": "refused"])
        }
    }
}
