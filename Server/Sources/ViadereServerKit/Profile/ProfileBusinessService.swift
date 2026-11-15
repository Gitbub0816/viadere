@preconcurrency import Crypto
import Fluent
import Foundation
import ViadereCore

/// The business side of customer profiles (docs/PROFILES.md §Business API; SECURITY.md §2.97).
///
/// Order of checks for a request: body shape and catalog → **category entitlement** (`403 not_entitled`, before any customer is looked up, so
/// a business without the category learns nothing about the subject) → purpose display text → idempotency → the customer (a foreign, unknown
/// or other-environment `subjectRef` is a plain `404`) → open-request bound. A read re-checks scope, entitlement, grant and environment on
/// every call and is audited with field keys only.
struct ProfileBusinessService {
    let db: any Database
    let ctx: ServerContext

    static let maxOpenPerSubject = 3
    static let requestRate = RateRule(capacity: 60, perMinute: 60)
    static let readRate = RateRule(capacity: 120, perMinute: 120)
    static let readPerSubjectRate = RateRule(capacity: 20, perMinute: 10)

    static var notEntitledMessage: String {
        "Your organization is not allowed to ask for these profile fields. Ask Viadere to allow their categories in the console (Organization > Customer profile access)."
    }

    // MARK: Request

    func create(principal: BusinessPrincipal, body: CreateProfileRequest, idempotencyKey: String) async throws -> (ProfileRequestResource, Bool) {
        try await ctx.limiter.enforce("profile-request", key: principal.businessId.description, rule: Self.requestRate)
        let keys = body.fieldKeys
        guard !keys.isEmpty, keys.count <= CreateProfileRequest.maxFields, Set(keys).count == keys.count else {
            throw APIError.validation("Ask for 1 to \(CreateProfileRequest.maxFields) distinct fields.", details: ["fieldKeys": "invalid"])
        }
        let unknown = keys.filter { ProfileCatalog.definition(for: $0) == nil }
        guard unknown.isEmpty else {
            throw APIError.validation("Unknown profile fields.", details: Dictionary(uniqueKeysWithValues: unknown.prefix(20).map { ($0, ProfileValueIssue.unknownField.rawValue) }))
        }
        let service = ProfileService(db: db, ctx: ctx)
        let allowed = try await service.allowedCategories(businessId: principal.businessId.uuid)
        let refused = ProfileAccessPolicy.disallowed(keys, allowed: allowed)
        guard refused.isEmpty else {
            _ = try? await AuditService(db: db, ctx: ctx).record("profile.request_denied", outcome: .denied, actor: AuditActor(kind: .business, id: principal.keyId.uuidString.lowercased()),
                businessId: principal.businessId, subjectType: "profile_request", metadata: ["reason": "not_entitled", "fields": refused.joined(separator: " ")])
            throw APIError(.forbidden, .notEntitled, Self.notEntitledMessage, details: Dictionary(uniqueKeysWithValues: refused.map { ($0, "not_entitled") }))
        }
        if DisplayTextSanitizer.containsDisallowedScalars(body.purpose) {
            throw APIError.validation("The purpose contains characters that can't be shown.", details: ["purpose": DisplayTextSanitizer.Violation.disallowedCharacters.rawValue])
        }
        let purpose = PublicName.clean(body.purpose)
        guard !purpose.isEmpty else { throw APIError.validation("State the purpose.", details: ["purpose": "required"]) }
        if let violation = DisplayTextSanitizer.violation(of: purpose, maxCharacters: CreateProfileRequest.maxPurposeCharacters) {
            throw APIError.validation("The purpose can't be shown as written.", details: ["purpose": violation.rawValue])
        }
        let lifetime = body.expiresInSeconds ?? Int(CreateProfileRequest.defaultLifetime)
        guard CreateProfileRequest.lifetimeRange.contains(lifetime) else {
            throw APIError.validation("expiresInSeconds must be between 1 hour and 30 days.", details: ["expiresInSeconds": "out_of_range"])
        }
        // Idempotency (same key + same body = the original; another body = 409).
        let idempotencyHash = SecureToken.sha256Hex(Data("profile-request\n\(idempotencyKey)".utf8))
        let canonical = "\(body.subjectRef.rawValue)\n\(keys.joined(separator: " "))\n\(purpose)\n\(lifetime)"
        let requestHash = SecureToken.sha256Hex(Data(canonical.utf8))
        if let existing = try await ProfileRequestRecord.query(on: db).filter(\.$businessId == principal.businessId.uuid)
            .filter(\.$idempotencyHash == idempotencyHash).first() {
            guard existing.requestHash == requestHash else { throw APIError(.conflict, .idempotencyConflict, "This Idempotency-Key was used with a different request.") }
            return (try resource(existing), false)
        }
        let relationship = try await subjectRelationship(principal: principal, subjectRef: body.subjectRef)
        let now = ctx.now
        let open = try await ProfileRequestRecord.query(on: db).filter(\.$relationshipId == relationship.id!)
            .filter(\.$status == ProfileRequestStatus.pending.rawValue).filter(\.$expiresAt > now).count()
        guard open < Self.maxOpenPerSubject else { throw APIError.conflict("This customer already has \(Self.maxOpenPerSubject) open requests from you.") }
        let record = ProfileRequestRecord()
        record.id = UUID()
        record.businessId = principal.businessId.uuid
        record.keyId = principal.keyId
        record.livemode = principal.livemode
        record.relationshipId = relationship.id!
        record.consumerId = relationship.consumerId
        record.subjectRef = body.subjectRef.rawValue
        record.fieldKeys = keys.joined(separator: " ")
        record.purpose = purpose
        record.status = ProfileRequestStatus.pending.rawValue
        record.idempotencyHash = idempotencyHash
        record.requestHash = requestHash
        record.createdAt = now
        record.expiresAt = now.addingTimeInterval(TimeInterval(lifetime))
        do {
            try await record.create(on: db)
        } catch {
            if error.isConstraintViolation { throw APIError(.conflict, .idempotencyConflict, "This Idempotency-Key is being used by a concurrent request.") }
            throw error
        }
        _ = try await AuditService(db: db, ctx: ctx).record("profile.requested", actor: AuditActor(kind: .business, id: principal.keyId.uuidString.lowercased()),
            consumerId: ConsumerID(relationship.consumerId), businessId: principal.businessId, subjectType: "profile_request",
            subjectId: record.id?.uuidString.lowercased(), metadata: ["fields": record.fieldKeys, "livemode": principal.livemode ? "true" : "false"])
        if !principal.livemode { try await completeSandbox(record, relationship: relationship) }
        let stored = try await ProfileRequestRecord.find(record.id, on: db) ?? record
        return (try resource(stored), true)
    }

    func get(principal: BusinessPrincipal, id: UUID) async throws -> ProfileRequestResource {
        guard let row = try await ProfileRequestRecord.query(on: db).filter(\.$id == id).filter(\.$businessId == principal.businessId.uuid)
            .filter(\.$livemode == principal.livemode).first() else { throw APIError.notFound }
        return try resource(row)
    }

    func resource(_ row: ProfileRequestRecord) throws -> ProfileRequestResource {
        guard let subject = SubjectRef(row.subjectRef) else { throw APIError.internalError }
        var status = row.statusValue
        if status == .pending, row.expiresAt <= ctx.now { status = .expired }
        return ProfileRequestResource(id: ProfileRequestID(row.id!), subjectRef: subject, fieldKeys: row.keys, purpose: row.purpose, status: status,
                                      approvedKeys: row.approved, livemode: row.livemode, createdAt: row.createdAt, expiresAt: row.expiresAt, answeredAt: row.answeredAt)
    }

    /// The calling business's **own, active** relationship for `subjectRef`, in the key's environment; anything else is a plain 404.
    func subjectRelationship(principal: BusinessPrincipal, subjectRef: SubjectRef) async throws -> RelationshipRecord {
        let relationship = try await SubjectResolver(db: db, ctx: ctx).relationship(businessId: principal.businessId, subjectRef: subjectRef)
        guard relationship.isActive, try await Sandbox(db: db).matches(consumerId: relationship.consumerId, livemode: principal.livemode) else { throw APIError.notFound }
        return relationship
    }

    // MARK: Read

    func read(principal: BusinessPrincipal, subjectRef: SubjectRef) async throws -> BusinessProfileView {
        try await ctx.limiter.enforce("profile-read", key: principal.businessId.description, rule: Self.readRate)
        try await ctx.limiter.enforce("profile-read-subject", key: "\(principal.businessId)|\(subjectRef.rawValue)", rule: Self.readPerSubjectRate)
        let relationship = try await subjectRelationship(principal: principal, subjectRef: subjectRef)
        let service = ProfileService(db: db, ctx: ctx)
        let consumer = relationship.consumerId
        // Both gates, evaluated now: the customer's grants ∩ the categories Viadere allows this business today.
        let allowed = try await service.allowedCategories(businessId: principal.businessId.uuid)
        let granted = Set(try await service.activeGrants(relationshipId: relationship.id!).map(\.fieldKey))
        let readable = ProfileAccessPolicy.readable(granted, allowed: allowed)
        let entries = readable.isEmpty ? [] : try await service.values(consumer: consumer)
        let facts = readable.isEmpty ? [] : try await service.facts(consumer: consumer)
        var fields: [BusinessProfileField] = []
        var missing: [String] = []
        let now = ctx.now
        for key in readable.sorted() {
            if let kind = ProfileVerifiedFactKind.allCases.first(where: { $0.fieldKey == key }) {
                if let fact = facts.first(where: { $0.fact == kind }) { fields.append(BusinessProfileField(key: key, entry: nil, value: .boolean(true), verification: fact)) }
                else { missing.append(key) }
                continue
            }
            if ProfileCatalog.definition(for: key)?.isDerived == true {
                var birth: String?
                if case .text(let date)? = entries.first(where: { $0.key == "birthdate.date" })?.value { birth = date }
                if let value = ProfileAccessPolicy.ageCheck(key: key, birthDate: birth, now: now) { fields.append(BusinessProfileField(key: key, entry: nil, value: .boolean(value))) }
                else { missing.append(key) }
                continue
            }
            let matching = entries.filter { $0.key == key }
            if matching.isEmpty { missing.append(key) }
            for entry in matching { fields.append(BusinessProfileField(key: key, entry: entry.entry, value: entry.value)) }
        }
        let publicName = try await service.publicName(consumer: consumer)
        // Every read is audited: which keys left, never their values.
        _ = try await AuditService(db: db, ctx: ctx).record("profile.read", actor: AuditActor(kind: .business, id: principal.keyId.uuidString.lowercased()),
            consumerId: ConsumerID(consumer), businessId: principal.businessId, subjectType: "relationship", subjectId: relationship.id?.uuidString.lowercased(),
            metadata: ["fields": Set(fields.map(\.key)).sorted().joined(separator: " "), "livemode": principal.livemode ? "true" : "false"])
        return BusinessProfileView(subjectRef: subjectRef, publicName: publicName, fields: fields, grantedWithoutValue: missing, livemode: principal.livemode)
    }

    // MARK: Sandbox

    /// Simulated values a test-mode request is answered with at once (never a real person's data; `sandbox` facts are never evidence).
    static let sandboxValues: [String: ProfileValue] = [
        "contact.email": .text("sandbox.customer@example.com"), "contact.phone": .text("+15555550100"),
        "contact.mailing_address": .address(ProfileAddress(line1: "1 Test Street", locality: "Testville", region: "CA", postalCode: "94000", country: "US")),
        "personal.given_name": .text("Test"), "personal.family_name": .text("Person"), "personal.preferred_name": .text("Tess"),
        "personal.preferred_language": .text("en-US"), "personal.pronouns": .text("they/them"), "birthdate.date": .text("1990-01-01"),
        "travel.known_traveler_number": .text("TT1234567"), "travel.seat_preference": .text("aisle"), "travel.meal_preference": .text("vegetarian"),
        "vehicle.make": .text("Testmobile"), "vehicle.model": .text("Model T"), "vehicle.year": .text("2024"), "vehicle.plate": .text("TEST01"),
        "home.property_type": .text("house"), "home.access_notes": .text("Ring the bell at the side gate."),
        "work.employer": .text("Example Corp"), "work.title": .text("Tester"),
    ]
    static let sandboxEntries: [String: (String, ProfileValue)] = [
        "contact.service_address": ("home", .address(ProfileAddress(line1: "1 Test Street", locality: "Testville", region: "CA", postalCode: "94000", country: "US"))),
        "travel.frequent_flyer": ("TT", .text("TT123456")), "memberships.loyalty_number": ("Test Rewards", .text("TR-0001")),
    ]

    private func completeSandbox(_ record: ProfileRequestRecord, relationship: RelationshipRecord) async throws {
        guard let consumer = try await ConsumerRecord.find(relationship.consumerId, on: db), consumer.isSandbox else { return }
        let now = ctx.now
        let service = ProfileService(db: db, ctx: ctx)
        for key in record.keys {
            for source in ProfileAccessPolicy.sourceKeys(for: key) {
                let (entry, value): (String, ProfileValue?) = Self.sandboxEntries[source].map { ($0.0, $0.1) } ?? ("", Self.sandboxValues[source])
                guard let value, try await ProfileValueRecord.query(on: db).filter(\.$consumerId == consumer.id!).filter(\.$fieldKey == source).count() == 0 else { continue }
                let row = ProfileValueRecord(consumerId: consumer.id!, fieldKey: source, entryKey: entry, now: now)
                try service.seal(value, into: row)
                try await row.create(on: db)
            }
            if let kind = ProfileVerifiedFactKind.allCases.first(where: { $0.fieldKey == key }),
               try await ProfileVerifiedFactRecord.query(on: db).filter(\.$consumerId == consumer.id!).filter(\.$fact == kind.rawValue).count() == 0 {
                let fact = ProfileVerifiedFactRecord()
                fact.id = UUID()
                fact.consumerId = consumer.id!
                fact.fact = kind.rawValue
                fact.method = VerificationMethod.sandbox.rawValue
                fact.assurance = "sandbox_simulated"
                fact.policyVersion = VerifyPolicy.version
                fact.verifiedAt = now
                try await fact.create(on: db)
            }
        }
        guard try await DB.swap(db, table: ProfileRequestRecord.schema, id: record.id!, column: "status", expected: ProfileRequestStatus.pending.rawValue,
                                newValue: ProfileRequestStatus.answered.rawValue, extra: [("approved_keys", record.fieldKeys), ("answered_at", now)]) else { return }
        let current = Set(try await service.activeGrants(relationshipId: relationship.id!).map(\.fieldKey))
        try await service.applyGrants(principal: nil, relationship: relationship, add: Set(record.keys).subtracting(current), revoke: [], requestId: record.id,
                                      purpose: record.purpose, reason: "sandbox")
    }
}
