import Crypto
import Foundation
@testable import ViadereCore

/// Shared fixtures for the feature expansion v4 tests (Loops, Brand Kits, surfaces, organization). Non-health examples only (FX-4).
enum FX {
    static let business = BusinessID(UUID(uuidString: "0b0e5a4c-7d1f-4e2a-9c3b-5f6a7b8c9d01")!)
    static let otherBusiness = BusinessID(UUID(uuidString: "0b0e5a4c-7d1f-4e2a-9c3b-5f6a7b8c9d02")!)
    static let consumer = ConsumerID(UUID(uuidString: "6f1c2a4e-9b3d-4c5e-8f70-1122334455aa")!)
    static let publication = LoopPublicationID(UUID(uuidString: "3c9d2e1f-4a5b-4c6d-8e7f-90a1b2c3d4e5")!)
    /// 2026-11-15T12:00:00Z
    static let now = Date(timeIntervalSince1970: 1_794_744_000)
    static let kid = "loop-publication-v1"
    static let brandKid = "brand-manifest-v1"

    static func key(_ label: String) -> SoftwareP256SigningKey {
        try! SoftwareP256SigningKey(rawRepresentation: Data(SHA256.hash(data: Data("viadere-vector-\(label)".utf8))))
    }

    static var publicationKey: SoftwareP256SigningKey { key("loop-publication") }
    static var brandKey: SoftwareP256SigningKey { key("brand-manifest") }
    static var pinned: [PinnedManifestKey] { [PinnedManifestKey(kid: kid, publicKey: publicationKey.publicKey)] }
    static var brandPinned: [PinnedManifestKey] { [PinnedManifestKey(kid: brandKid, publicKey: brandKey.publicKey)] }

    static let salon = VerifiedBusinessRecord(id: business, displayName: "Juniper Salon", verificationStatus: .verified, category: .retail)

    static func context(phase: LoopPlatformPhase = .hosted, publisher: LoopPublisherIdentity? = .business(FX.business), kits: Set<String>? = nil) -> LoopValidationContext {
        LoopValidationContext(submittingBusinessId: business, publisher: publisher, phase: phase, brandKitKeys: kits)
    }

    /// The plan's pickup-scheduling example (section 4.3), as JSON.
    static let pickupJSON = """
    {
      "schema_version": 1,
      "key": "pickup-scheduling",
      "title": "Schedule your pickup",
      "entry_points": ["business_page", "message", "alert"],
      "appearance": {"mode": "standard"},
      "steps": [
        {"id": "s1", "type": "form",
         "fields": [{"id": "slot", "type": "single_choice", "label": "Pickup time", "required": true,
                     "options": [{"id": "am", "label": "Morning"}, {"id": "pm", "label": "Afternoon"}]}],
         "actions": [{"id": "confirm", "action": "select_option", "label": "continue", "next": "s2"}]},
        {"id": "s2", "type": "summary",
         "actions": [{"id": "submit", "action": "acknowledge", "label": "send_request", "routing": {"mode": "hosted", "queue": "pickups"}, "next": "done"}]},
        {"id": "done", "type": "result", "show_outcome": true}
      ],
      "limits": {"expires_in_seconds": 86400}
    }
    """

    static var pickupValue: JSONValue { try! JSONDecoder().decode(JSONValue.self, from: Data(pickupJSON.utf8)) }
    static var pickup: LoopDefinition { LoopDefinition.parse(pickupValue).definition! }

    /// A repair-shop estimate review (high risk, read-only in Phase 3).
    static var estimate: LoopDefinition {
        LoopDefinition(key: "estimate-review", title: "Your repair estimate", entryPoints: [.message, .alert], appearance: .brandKit("spring"),
                       steps: [
                        LoopStep(id: "review", type: .summary, title: "Brake repair estimate", body: "Parts and labor for the front brakes.",
                                 actions: [LoopActionBinding(id: "ack", action: "review_estimate", label: "send_acknowledgement", next: "done",
                                                             routing: LoopRouting(mode: .hosted, queue: "estimates"),
                                                             params: ["amount": .object(["value": .string("285.28"), "currency": .string("USD")]),
                                                                      "terms": .string("Valid for 14 days. Work starts after you approve in person."),
                                                                      "reference": .string("EST-1042")])]),
                        LoopStep(id: "done", type: .result, showOutcome: true),
                       ], limits: LoopLimits(expiresInSeconds: 3 * 86400))
    }

    /// Replaces one member of a JSON object at a path of keys/indices.
    static func modify(_ value: JSONValue, _ path: [Any], _ newValue: JSONValue?) -> JSONValue {
        guard let head = path.first else { return newValue ?? .null }
        let rest = Array(path.dropFirst())
        switch (value, head) {
        case (.object(var o), let key as String):
            if rest.isEmpty, newValue == nil { o.removeValue(forKey: key) } else { o[key] = modify(o[key] ?? .null, rest, newValue) }
            return .object(o)
        case (.array(var a), let index as Int):
            a[index] = modify(a[index], rest, newValue)
            return .array(a)
        default:
            return value
        }
    }

    static func manifest(for definition: LoopDefinition, publisher: LoopPublisherType = .business, business: BusinessID? = FX.business,
                         policy: Int64 = 1, validFrom: Date = FX.now.addingTimeInterval(-3600), lifetime: Int64 = 30 * 86400,
                         key: SoftwareP256SigningKey = FX.publicationKey, kid: String = FX.kid) async throws -> String {
        let from = Int64(validFrom.timeIntervalSince1970)
        return try await LoopPublicationManifest(publisherType: publisher, publisherBusinessId: business, publishedDefinitionId: publication, revision: 3,
                                                 attributionPolicyVersion: policy, definitionHash: try definition.definitionHash(),
                                                 validFrom: from, notAfter: from + lifetime, kid: kid).sign(with: key)
    }

    static func presentation(_ definition: LoopDefinition, manifest: String?, publisher: VerifiedBusinessRecord? = FX.salon,
                             brand: BrandKitPresentation? = nil, status: LoopPublicationStatus = .active) -> LoopPresentationContext {
        LoopPresentationContext(manifest: manifest, pinnedKeys: pinned, definition: definition, instanceBusinessId: business, publisher: publisher,
                                publicationStatus: status, brand: brand, now: now)
    }

    static let springTokens = BrandTokens(primary: BrandColor("#2F5D50")!, secondary: BrandColor("#4A4A48")!, accent: BrandColor("#B5683A")!,
                                          surface: BrandColor("#FFFDF7")!, radius: .large, border: .hairline, typeScale: .standard)

    static func brandManifest(windows: [BrandScheduleWindow] = [], pool: [BrandPoolEntry] = [], defaultKit: String? = "everyday",
                              timezone: String = "America/New_York") -> BrandManifest {
        let issued = Int64(now.timeIntervalSince1970) - 3600
        return BrandManifest(businessId: business, manifestVersion: 14, kits: [
            BrandKit(kitId: "everyday", name: "Everyday", tokens: BrandTokens(primary: BrandColor("#8C2F39")!)),
            BrandKit(kitId: "spring", name: "Spring", tokens: springTokens, frameId: "viadere.frame.hairline.v1",
                     assets: [.logo: BrandAssetRef(sha256: String(repeating: "ab", count: 32), width: 512, height: 512, bytes: 18432)]),
            BrandKit(kitId: "winter", name: "Winter", tokens: BrandTokens(primary: BrandColor("#1D3557")!), frameId: "viadere.frame.snow.v1"),
        ], schedule: BrandSchedule(timezone: timezone, defaultKit: defaultKit, windows: windows, randomPool: pool),
           issuedAt: issued, notAfter: issued + 30 * 86400, kid: brandKid)
    }
}
