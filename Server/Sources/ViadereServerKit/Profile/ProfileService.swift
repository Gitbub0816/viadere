import Fluent
import Foundation
import ViadereCore

/// Customer profiles with selective sharing (docs/PROFILES.md, SECURITY.md §2.97): the customer side and the storage shared with the business
/// side.
///
/// What it guarantees (each has a test in `ProfileTests`):
/// - **Closed catalog.** Every value passes `ProfileCatalog.validate` before it is stored; unknown keys are refused.
/// - **Encrypted at rest.** Values (and the custom public name) are sealed with the row-bound field cipher; operators have no reader.
/// - **Nothing beyond the public name without a grant.** Grants are per business and per field, can only cover categories Viadere allowed that
///   business, are recorded with timestamps and a disclosure receipt, and revocation is effective on the business's next read.
/// - **Erased with the account.** `wipe` deletes values, facts, attempts and requests and ends every grant.
struct ProfileService {
    let db: any Database
    let ctx: ServerContext

    static let maxValuesPerAccount = 120
    static let maxReceiptsListed = 200

    // MARK: Values

    func valueRows(consumer: UUID) async throws -> [ProfileValueRecord] {
        try await ProfileValueRecord.query(on: db).filter(\.$consumerId == consumer).sort(\.$fieldKey).sort(\.$entryKey).all()
    }

    func open(_ row: ProfileValueRecord) throws -> ProfileValue {
        let data = try ctx.cipher.open(row.value, context: ProfileValueRecord.valueContext, rowId: row.id!)
        return try ViadereJSON.decode(ProfileValue.self, from: data)
    }

    func seal(_ value: ProfileValue, into row: ProfileValueRecord) throws {
        row.value = try ctx.cipher.seal(try ViadereJSON.encode(value), context: ProfileValueRecord.valueContext, rowId: row.id!)
    }

    /// The decrypted values of an account keyed by field key (multi-entry fields keep every entry).
    func values(consumer: UUID) async throws -> [ProfileFieldEntry] {
        try await valueRows(consumer: consumer).compactMap { row in
            guard let value = try? open(row) else { return nil }
            return ProfileFieldEntry(key: row.fieldKey, entry: row.entry, value: value, updatedAt: row.updatedAt)
        }
    }

    func facts(consumer: UUID) async throws -> [ProfileVerifiedFact] {
        try await ProfileVerifiedFactRecord.query(on: db).filter(\.$consumerId == consumer).all().compactMap(\.dto)
            .sorted { $0.fact.rawValue < $1.fact.rawValue }
    }

    // MARK: Public name

    func customPublicName(consumer: UUID) async throws -> String? {
        guard let row = try await ConsumerProfileRecord.find(consumer, on: db), let sealed = row.publicName else { return nil }
        return try? ctx.cipher.openString(sealed, context: ConsumerProfileRecord.publicNameContext, rowId: consumer)
    }

    /// `(effective, custom, derived)`.
    func publicNames(consumer: UUID, entries: [ProfileFieldEntry]? = nil) async throws -> (String?, String?, String?) {
        let values: [ProfileFieldEntry]
        if let entries { values = entries } else { values = try await self.values(consumer: consumer) }
        func text(_ key: String) -> String? {
            if case .text(let value)? = values.first(where: { $0.key == key })?.value { return value }
            return nil
        }
        let accountName = try await ConsumerRecord.find(consumer, on: db)?.displayName
        let derived = PublicName.derive(givenName: text("personal.given_name"), familyName: text("personal.family_name")) ?? PublicName.derive(fullName: accountName)
        let custom = try await customPublicName(consumer: consumer)
        return (custom ?? derived, custom, derived)
    }

    /// What every connected business receives with the relationship.
    func publicName(consumer: UUID) async throws -> String? { try await publicNames(consumer: consumer).0 }

    // MARK: Customer: profile

    func profile(consumer: UUID) async throws -> CustomerProfile {
        let entries = try await values(consumer: consumer)
        let names = try await publicNames(consumer: consumer, entries: entries)
        return CustomerProfile(publicName: names.0, customPublicName: names.1, derivedPublicName: names.2, fields: entries,
                               verified: try await facts(consumer: consumer))
    }

    /// Applies an update atomically. Every value is validated first; one bad value refuses everything (`422`, `details` names the field).
    func update(principal: ConsumerPrincipal, _ request: ProfileUpdateRequest) async throws -> CustomerProfile {
        let consumer = principal.consumerId.uuid
        try await ctx.limiter.enforce("profile-write", key: consumer.uuidString, rule: RateRule(capacity: 30, perMinute: 10))
        guard request.set.count + request.remove.count <= ProfileUpdateRequest.maxChanges else {
            throw APIError.validation("Too many changes at once.", details: ["set": "too_many"])
        }
        guard !(request.customPublicName != nil && request.useDerivedPublicName == true) else {
            throw APIError.validation("Choose a custom public name or the default, not both.", details: ["publicName": "conflict"])
        }
        var customNameDraft: String?
        if let raw = request.customPublicName {
            if let issue = PublicName.validate(raw) { throw APIError.validation("That public name can't be used.", details: ["publicName": issue.rawValue]) }
            customNameDraft = PublicName.clean(raw)
        }
        // Validate and normalize everything before touching the database.
        var setsDraft: [(key: String, entry: String, value: ProfileValue)] = []
        for (index, item) in request.set.enumerated() {
            do {
                let value = try ProfileCatalog.validate(key: item.key, entry: item.entry, value: item.value)
                let entry = try ProfileCatalog.validateEntry(item.entry, for: ProfileCatalog.definition(for: item.key)!) ?? ""
                setsDraft.append((item.key, entry, value))
            } catch let issue as ProfileValueIssue {
                throw APIError.validation("A profile value is not valid.", details: ["set[\(index)].\(item.key)": issue.rawValue])
            }
        }
        var removesDraft: [(key: String, entry: String)] = []
        for item in request.remove {
            guard let definition = ProfileCatalog.definition(for: item.key), !definition.isDerived else {
                throw APIError.validation("Unknown profile field.", details: ["remove.\(item.key)": ProfileValueIssue.unknownField.rawValue])
            }
            removesDraft.append((item.key, definition.isMultiEntry ? PublicName.clean(item.entry ?? "") : ""))
        }
        let now = ctx.now
        let changedKeys = Set(setsDraft.map(\.key) + removesDraft.map(\.key))
        let (sets, removes, customName) = (setsDraft, removesDraft, customNameDraft)
        try await db.transaction { tx in
            for remove in removes {
                var query = ProfileValueRecord.query(on: tx).filter(\.$consumerId == consumer).filter(\.$fieldKey == remove.key)
                if let definition = ProfileCatalog.definition(for: remove.key), definition.isMultiEntry {
                    // Entry labels compare after normalization (airline codes are upper case).
                    let normalized = ((try? ProfileCatalog.validateEntry(remove.entry, for: definition)) ?? nil) ?? remove.entry
                    query = query.filter(\.$entryKey == normalized)
                }
                try await query.delete()
            }
            for item in sets {
                let existing = try await ProfileValueRecord.query(on: tx).filter(\.$consumerId == consumer).filter(\.$fieldKey == item.key)
                    .filter(\.$entryKey == item.entry).first()
                let row = existing ?? ProfileValueRecord(consumerId: consumer, fieldKey: item.key, entryKey: item.entry, now: now)
                if existing == nil, let definition = ProfileCatalog.definition(for: item.key), definition.isMultiEntry {
                    let count = try await ProfileValueRecord.query(on: tx).filter(\.$consumerId == consumer).filter(\.$fieldKey == item.key).count()
                    guard count < definition.maxEntries else {
                        throw APIError.validation("Too many entries for this field.", details: [item.key: ProfileValueIssue.tooManyEntries.rawValue])
                    }
                }
                try ProfileService(db: tx, ctx: ctx).seal(item.value, into: row)
                row.updatedAt = now
                row.catalogVersion = ProfileCatalog.version
                if existing == nil { try await row.create(on: tx) } else { try await row.update(on: tx) }
            }
            let total = try await ProfileValueRecord.query(on: tx).filter(\.$consumerId == consumer).count()
            guard total <= Self.maxValuesPerAccount else { throw APIError.validation("Your profile is full.", details: ["set": "too_many"]) }
            // A verified legal-name match is about the name that was verified: editing the name forgets it.
            if changedKeys.contains("personal.given_name") || changedKeys.contains("personal.family_name") {
                try await ProfileVerifiedFactRecord.query(on: tx).filter(\.$consumerId == consumer)
                    .filter(\.$fact == ProfileVerifiedFactKind.legalName.rawValue).delete()
            }
            if customName != nil || request.useDerivedPublicName == true {
                let row = try await ConsumerProfileRecord.find(consumer, on: tx)
                let profile = row ?? ConsumerProfileRecord(consumerId: consumer, now: now)
                profile.publicName = try customName.map { try ctx.cipher.seal($0, context: ConsumerProfileRecord.publicNameContext, rowId: consumer) }
                profile.updatedAt = now
                if row == nil { try await profile.create(on: tx) } else { try await profile.update(on: tx) }
            }
            // Field keys only, never values.
            _ = try await AuditService(db: tx, ctx: ctx).record("profile.updated", principal: principal, subjectType: "profile", subjectId: nil,
                metadata: ["fields": changedKeys.sorted().joined(separator: " "),
                           "public_name": customName != nil ? "custom" : (request.useDerivedPublicName == true ? "derived" : "unchanged")])
        }
        return try await profile(consumer: consumer)
    }

    // MARK: Grants

    /// The consumer's **active** relationship with `businessId`, or 404 (a business the caller is not connected to is not an oracle).
    func relationship(consumer: UUID, businessId: UUID) async throws -> RelationshipRecord {
        guard let row = try await RelationshipRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$businessId == businessId).first(),
              row.isActive else { throw APIError.notFound }
        return row
    }

    func activeGrants(relationshipId: UUID) async throws -> [ProfileGrantRecord] {
        try await ProfileGrantRecord.query(on: db).filter(\.$relationshipId == relationshipId).filter(\.$revokedAt == nil).all()
    }

    /// The categories a business may ask for / read right now: its operator-granted profile-category entitlements, and only while it is verified.
    func allowedCategories(businessId: UUID) async throws -> Set<ProfileCategory> {
        guard let business = try await BusinessRecord.find(businessId, on: db), business.isVerified else { return [] }
        return try await EntitlementService(db: db, ctx: ctx).snapshot(businessId: businessId).profileCategories
    }

    /// Whether the account has something to share for `key` (derived fields: whether they can be computed).
    static func hasValue(_ key: String, entries: [ProfileFieldEntry], facts: [ProfileVerifiedFact]) -> Bool {
        if key.hasPrefix("verified.") { return facts.contains { $0.fact.fieldKey == key } }
        let sources = ProfileAccessPolicy.sourceKeys(for: key)
        return entries.contains { sources.contains($0.key) }
    }

    func accessView(consumer: UUID, businessId: UUID) async throws -> ProfileAccessView {
        let relationship = try await relationship(consumer: consumer, businessId: businessId)
        guard let business = try await BusinessRecord.find(businessId, on: db) else { throw APIError.notFound }
        let allowed = try await allowedCategories(businessId: businessId)
        let grants = try await activeGrants(relationshipId: relationship.id!)
        let entries = try await values(consumer: consumer)
        let facts = try await facts(consumer: consumer)
        let byKey = Dictionary(grants.map { ($0.fieldKey, $0) }, uniquingKeysWith: { a, _ in a })
        // Fields of allowed categories, plus anything still granted from a category since withdrawn (so the customer can see and revoke it).
        let keys = ProfileCatalog.fields.map(\.key).filter { key in
            (ProfileCatalog.category(of: key).map(allowed.contains) ?? false) || byKey[key] != nil
        }
        let fields = keys.map { key in
            ProfileAccessField(key: key, granted: byKey[key] != nil, grantedAt: byKey[key]?.grantedAt,
                               hasValue: Self.hasValue(key, entries: entries, facts: facts))
        }
        return ProfileAccessView(businessId: BusinessID(businessId), businessName: business.displayName,
                                 publicName: try await publicName(consumer: consumer), allowedCategories: allowed.sorted(), fields: fields)
    }

    /// Replaces the granted set for one business (`[]` revokes everything).
    func setAccess(principal: ConsumerPrincipal, businessId: UUID, update: ProfileAccessUpdate) async throws -> ProfileAccessView {
        let consumer = principal.consumerId.uuid
        try await ctx.limiter.enforce("profile-write", key: consumer.uuidString, rule: RateRule(capacity: 30, perMinute: 10))
        let relationship = try await relationship(consumer: consumer, businessId: businessId)
        let wanted = Set(update.grantedKeys)
        guard wanted.count == update.grantedKeys.count, wanted.count <= ProfileCatalog.fields.count else {
            throw APIError.validation("Each field may appear once.", details: ["grantedKeys": "duplicate"])
        }
        let current = Set(try await activeGrants(relationshipId: relationship.id!).map(\.fieldKey))
        let added = wanted.subtracting(current)
        // A customer can only add fields of categories Viadere allowed this business; removing is always possible.
        let allowed = try await allowedCategories(businessId: businessId)
        let refused = ProfileAccessPolicy.disallowed(Array(added), allowed: allowed)
        guard refused.isEmpty else {
            throw APIError.validation("This business can't receive some of these fields.", details: Dictionary(uniqueKeysWithValues: refused.map { ($0, "not_allowed") }))
        }
        try await applyGrants(principal: principal, relationship: relationship, add: added, revoke: current.subtracting(wanted), requestId: nil, purpose: nil,
                              reason: "customer")
        return try await accessView(consumer: consumer, businessId: businessId)
    }

    /// The one place grants change: rows, the disclosure receipt, the audit event (keys only) and the business's webhook (keys only). The
    /// revocation is committed before the webhook is queued, so a business told "revoked" can already no longer read.
    func applyGrants(principal: ConsumerPrincipal?, relationship: RelationshipRecord, add: Set<String>, revoke: Set<String>, requestId: UUID?, purpose: String?,
                     reason: String) async throws {
        guard !add.isEmpty || !revoke.isEmpty else { return }
        let now = ctx.now
        let business = try await BusinessRecord.find(relationship.businessId, on: db)
        let subject = SubjectResolver(db: db, ctx: ctx).ref(for: relationship)
        let consumer = relationship.consumerId
        try await db.transaction { tx in
            if !revoke.isEmpty {
                for row in try await ProfileGrantRecord.query(on: tx).filter(\.$relationshipId == relationship.id!).filter(\.$revokedAt == nil)
                    .filter(\.$fieldKey ~~ Array(revoke)).all() {
                    row.revokedAt = now
                    row.revokeReason = reason
                    try await row.update(on: tx)
                }
                try await ProfileReceiptRecord(consumerId: consumer, businessId: relationship.businessId, recipientName: business?.displayName ?? "",
                                               action: .revoked, fieldKeys: revoke.sorted(), purpose: nil, requestId: requestId, now: now).create(on: tx)
                try await WebhookService(db: tx, ctx: ctx).enqueue(.profileAccessRevoked, businessId: BusinessID(relationship.businessId),
                    payload: ProfileAccessEvent(subjectRef: subject, fieldKeys: revoke.sorted(), requestId: requestId.map(ProfileRequestID.init), occurredAt: now))
            }
            if !add.isEmpty {
                for key in add.sorted() {
                    try await ProfileGrantRecord(consumerId: consumer, businessId: relationship.businessId, relationshipId: relationship.id!, fieldKey: key,
                                                 requestId: requestId, now: now).create(on: tx)
                }
                try await ProfileReceiptRecord(consumerId: consumer, businessId: relationship.businessId, recipientName: business?.displayName ?? "",
                                               action: .granted, fieldKeys: add.sorted(), purpose: purpose, requestId: requestId, now: now).create(on: tx)
                try await WebhookService(db: tx, ctx: ctx).enqueue(.profileAccessGranted, businessId: BusinessID(relationship.businessId),
                    payload: ProfileAccessEvent(subjectRef: subject, fieldKeys: add.sorted(), requestId: requestId.map(ProfileRequestID.init), occurredAt: now))
            }
            let actor = principal.map { AuditActor(kind: .device, id: $0.deviceId?.description) } ?? AuditActor(kind: .system, id: "profile:\(reason)")
            _ = try await AuditService(db: tx, ctx: ctx).record("profile.grants_changed", actor: actor, consumerId: ConsumerID(consumer),
                businessId: BusinessID(relationship.businessId), subjectType: "relationship", subjectId: relationship.id?.uuidString.lowercased(),
                metadata: ["granted": add.sorted().joined(separator: " "), "revoked": revoke.sorted().joined(separator: " "), "reason": reason,
                           "request_id": requestId?.uuidString.lowercased() ?? ""])
        }
    }

    /// Ends every grant of a relationship (disconnect, block). Must run inside the disconnect transaction.
    func revokeAll(relationship: RelationshipRecord, reason: String) async throws {
        let current = Set(try await activeGrants(relationshipId: relationship.id!).map(\.fieldKey))
        try await applyGrants(principal: nil, relationship: relationship, add: [], revoke: current, requestId: nil, purpose: nil, reason: reason)
        // Open requests of that business end with the connection.
        try await ProfileRequestRecord.query(on: db).filter(\.$relationshipId == relationship.id!).filter(\.$status == ProfileRequestStatus.pending.rawValue)
            .set(\.$status, to: ProfileRequestStatus.cancelled.rawValue).set(\.$answeredAt, to: ctx.now).update()
    }

    // MARK: Customer: requests

    func prompt(_ record: ProfileRequestRecord, entries: [ProfileFieldEntry], facts: [ProfileVerifiedFact], granted: Set<String>) async throws -> ProfileRequestPrompt? {
        guard let business = try await BusinessRecord.find(record.businessId, on: db), let summary = try await DirectoryService(db: db).summary(for: business) else {
            return nil
        }
        var status = record.statusValue
        if status == .pending, record.expiresAt <= ctx.now { status = .expired }
        let fields = record.keys.map { ProfileRequestedField(key: $0, hasValue: Self.hasValue($0, entries: entries, facts: facts), alreadyGranted: granted.contains($0)) }
        // The purpose was validated on the way in; it is sanitized again here as a second line of defence (an older row, a future rule).
        return ProfileRequestPrompt(id: ProfileRequestID(record.id!), business: summary,
                                    purpose: DisplayTextSanitizer.sanitize(record.purpose, maxCharacters: CreateProfileRequest.maxPurposeCharacters),
                                    fields: fields, status: status, approvedKeys: record.approved, createdAt: record.createdAt, expiresAt: record.expiresAt)
    }

    func requests(consumer: UUID, pendingOnly: Bool) async throws -> [ProfileRequestPrompt] {
        var query = ProfileRequestRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$livemode == true)
        if pendingOnly { query = query.filter(\.$status == ProfileRequestStatus.pending.rawValue).filter(\.$expiresAt > ctx.now) }
        let rows = try await query.sort(\.$createdAt, .descending).limit(50).all()
        let entries = try await values(consumer: consumer)
        let facts = try await facts(consumer: consumer)
        var out: [ProfileRequestPrompt] = []
        for row in rows {
            let granted = Set(try await activeGrants(relationshipId: row.relationshipId).map(\.fieldKey))
            if let prompt = try await prompt(row, entries: entries, facts: facts, granted: granted) { out.append(prompt) }
        }
        return out
    }

    func ownRequest(consumer: UUID, id: UUID) async throws -> ProfileRequestRecord {
        guard let row = try await ProfileRequestRecord.query(on: db).filter(\.$id == id).filter(\.$consumerId == consumer).filter(\.$livemode == true).first() else {
            throw APIError.notFound
        }
        return row
    }

    func request(consumer: UUID, id: UUID) async throws -> ProfileRequestPrompt {
        let row = try await ownRequest(consumer: consumer, id: id)
        let granted = Set(try await activeGrants(relationshipId: row.relationshipId).map(\.fieldKey))
        guard let prompt = try await prompt(row, entries: try await values(consumer: consumer), facts: try await facts(consumer: consumer), granted: granted) else {
            throw APIError.notFound
        }
        return prompt
    }

    /// Field-by-field approval: `approvedKeys` must be a subset of the request; the rest is not granted. Empty declines. Single use.
    func answer(principal: ConsumerPrincipal, id: UUID, answer: ProfileRequestAnswer) async throws -> ProfileRequestPrompt {
        let consumer = principal.consumerId.uuid
        let row = try await ownRequest(consumer: consumer, id: id)
        let approved = Set(answer.approvedKeys)
        guard approved.count == answer.approvedKeys.count, approved.isSubset(of: Set(row.keys)) else {
            throw APIError.validation("Only fields the business asked for can be approved.", details: ["approvedKeys": "not_requested"])
        }
        guard row.statusValue == .pending, row.expiresAt > ctx.now else { throw APIError.conflict("This request is no longer open.") }
        let relationship = try await relationship(consumer: consumer, businessId: row.businessId)
        guard relationship.id == row.relationshipId else { throw APIError.notFound }
        // The entitlement is checked again now: a category withdrawn since the request was made cannot be granted.
        let allowed = try await allowedCategories(businessId: row.businessId)
        let grantable = approved.filter { ProfileCatalog.category(of: $0).map(allowed.contains) ?? false }
        let status: ProfileRequestStatus = approved.isEmpty ? .declined : .answered
        guard try await DB.swap(db, table: ProfileRequestRecord.schema, id: row.id!, column: "status", expected: ProfileRequestStatus.pending.rawValue,
                                newValue: status.rawValue, extra: [("approved_keys", grantable.sorted().joined(separator: " ")), ("answered_at", ctx.now)]) else {
            throw APIError.conflict("This request is no longer open.")
        }
        let current = Set(try await activeGrants(relationshipId: relationship.id!).map(\.fieldKey))
        try await applyGrants(principal: principal, relationship: relationship, add: grantable.subtracting(current), revoke: [], requestId: row.id, purpose: row.purpose,
                              reason: "request")
        _ = try await AuditService(db: db, ctx: ctx).record("profile.request_answered", principal: principal, businessId: BusinessID(row.businessId),
            subjectType: "profile_request", subjectId: row.id?.uuidString.lowercased(),
            metadata: ["outcome": status.rawValue, "approved": grantable.sorted().joined(separator: " "), "requested": row.fieldKeys])
        return try await request(consumer: consumer, id: id)
    }

    func receipts(consumer: UUID) async throws -> [ProfileDisclosureReceipt] {
        try await ProfileReceiptRecord.query(on: db).filter(\.$consumerId == consumer).sort(\.$createdAt, .descending).limit(Self.maxReceiptsListed).all().map(\.dto)
    }

    // MARK: Maintenance, export, deletion

    /// Ends pending requests past their expiry and tells the business (keys only).
    @discardableResult
    func expireRequests(limit: Int = 100) async throws -> Int {
        let now = ctx.now
        let rows = try await ProfileRequestRecord.query(on: db).filter(\.$status == ProfileRequestStatus.pending.rawValue).filter(\.$expiresAt <= now).limit(limit).all()
        var changed = 0
        for row in rows {
            guard try await DB.swap(db, table: ProfileRequestRecord.schema, id: row.id!, column: "status", expected: ProfileRequestStatus.pending.rawValue,
                                    newValue: ProfileRequestStatus.expired.rawValue) else { continue }
            if let subject = SubjectRef(row.subjectRef) {
                try await WebhookService(db: db, ctx: ctx).enqueue(.profileRequestExpired, businessId: BusinessID(row.businessId),
                    payload: ProfileAccessEvent(subjectRef: subject, fieldKeys: row.keys, requestId: ProfileRequestID(row.id!), occurredAt: now))
            }
            changed += 1
        }
        return changed
    }

    /// The profile section of the customer's data export (`ConsumerExports.document`): values, public name, grants, receipts, verified facts and
    /// requests, exactly as the person would want to see them.
    func exportSection(consumer: UUID) async throws -> [String: Any] {
        let iso = { (date: Date?) -> Any in date.map { ViadereDate.format($0) } ?? NSNull() }
        let names = try await publicNames(consumer: consumer)
        var out: [String: Any] = ["catalogVersion": ProfileCatalog.version, "publicName": names.0 as Any? ?? NSNull(), "customPublicName": names.1 as Any? ?? NSNull()]
        out["fields"] = try await values(consumer: consumer).map { entry -> [String: Any] in
            let value: Any = (try? JSONSerialization.jsonObject(with: ViadereJSON.encode(entry.value), options: [.fragmentsAllowed])) ?? entry.value.displayText
            return ["key": entry.key, "entry": entry.entry as Any? ?? NSNull(), "value": value, "updatedAt": iso(entry.updatedAt)]
        }
        out["verified"] = try await facts(consumer: consumer).map { ["fact": $0.fact.rawValue, "method": $0.method.rawValue, "assurance": $0.assurance, "verifiedAt": iso($0.verifiedAt)] }
        let grants = try await ProfileGrantRecord.query(on: db).filter(\.$consumerId == consumer).sort(\.$grantedAt, .descending).limit(5000).all()
        let businesses = try await BusinessRecord.query(on: db).filter(\.$id ~~ Array(Set(grants.map(\.businessId)))).all()
        let businessNames = Dictionary(businesses.compactMap { b in b.id.map { ($0, b.displayName) } }, uniquingKeysWith: { a, _ in a })
        out["grants"] = grants.map { ["business": businessNames[$0.businessId] ?? "", "businessId": $0.businessId.uuidString.lowercased(), "field": $0.fieldKey,
                                      "grantedAt": iso($0.grantedAt), "revokedAt": iso($0.revokedAt)] }
        out["receipts"] = try await receipts(consumer: consumer).map { ["business": $0.businessName, "action": $0.action.rawValue, "fields": $0.fieldKeys,
                                                                        "purpose": $0.purpose as Any? ?? NSNull(), "at": iso($0.createdAt)] }
        let requests = try await ProfileRequestRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$livemode == true).sort(\.$createdAt, .descending).limit(1000).all()
        out["requests"] = requests.map { ["businessId": $0.businessId.uuidString.lowercased(), "fields": $0.keys, "purpose": $0.purpose, "status": $0.status,
                                          "createdAt": iso($0.createdAt), "answeredAt": iso($0.answeredAt)] }
        return out
    }

    /// Account deletion (SECURITY.md §2.20): values, the custom public name, verified facts, verification attempts and requests are deleted, and
    /// every remaining grant is ended (rows kept without values as the record of what was shared, as consent history is). Runs inside the
    /// deletion transaction, after the relationships were disconnected (which already revoked grants and told each business).
    static func wipe(consumer: UUID, on db: any Database, ctx: ServerContext) async throws {
        let now = ctx.now
        try await ProfileGrantRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$revokedAt == nil)
            .set(\.$revokedAt, to: now).set(\.$revokeReason, to: "account_deleted").update()
        try await ProfileValueRecord.query(on: db).filter(\.$consumerId == consumer).delete()
        try await ConsumerProfileRecord.query(on: db).filter(\.$id == consumer).delete()
        try await ProfileVerifiedFactRecord.query(on: db).filter(\.$consumerId == consumer).delete()
        try await ProfileRequestRecord.query(on: db).filter(\.$consumerId == consumer).delete()
        // Attempts with a provider session still to purge stay (without a nonce) until the purge succeeded; the rest go now.
        try await ProfileVerificationAttemptRecord.query(on: db).filter(\.$consumerId == consumer).set(\.$nonce, to: nil).update()
        try await ProfileVerificationAttemptRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$providerSessionId == nil).delete()
        try await ProfileVerificationAttemptRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$purgeStatus == "done").delete()
    }
}
