import Fluent
import Foundation
import ViadereCore

/// Installable Loops (SECURITY.md §2.98 "Installed Loops"): the directory, installs, uninstalls and the operator's directory listing.
///
/// * **What an install grants.** Only that this customer may start and use *this* Loop under every other existing control (business
///   verified, category allowed, both consents at the current text version, platform and business switches, publication status, rollout,
///   expiry). It creates no relationship (unless the customer chose `install_and_connect`, which runs the normal Connect), so the business
///   gets no `subjectRef`, no webhook, no messaging and no profile access: it sees only the answers the reviewed definition sends, in the
///   hosted inbox, without customer identity.
/// * **What the customer sees.** Only active, reviewed publications the customer is inside the rollout for, of verified businesses in an
///   allowed category, not switched off and not blocked by the customer. Anything else is `404` (never an existence oracle).
/// * **Directory metadata is reviewed data.** Name and description from the published definition; category, listing and featured from a
///   `loop_reviewer` operator; the icon from the business's signed brand manifest on the device.
struct LoopInstallService {
    let db: any Database
    let ctx: ServerContext

    static let maxQueryLength = 60

    // MARK: Candidates

    /// An active publication the caller may see, with what the views need.
    struct Candidate {
        var publication: LoopPublicationRecord
        var definition: LoopDefinition
        var business: BusinessRecord
        var summary: BusinessSummary
        var listing: LoopDirectoryListingRecord?

        var definitionId: UUID { publication.definitionId }
    }

    /// Visible active publications, one per Loop (the newest revision), optionally limited to some businesses or Loops.
    func candidates(consumer: UUID, businesses: [UUID]? = nil, definitions: [UUID]? = nil) async throws -> [Candidate] {
        if await PlatformFlags(db: db, ctx: ctx).isStopped(.loops) { return [] }
        if let businesses, businesses.isEmpty { return [] }
        if let definitions, definitions.isEmpty { return [] }
        var query = LoopPublicationRecord.query(on: db).filter(\.$status == LoopPublicationStatus.active.rawValue)
        if let businesses { query = query.filter(\.$businessId ~~ businesses) }
        if let definitions { query = query.filter(\.$definitionId ~~ definitions) }
        let publications = try await query.sort(\.$revision, .descending).all()
        guard !publications.isEmpty else { return [] }
        let businessIds = Array(Set(publications.map(\.businessId)))
        let allowed = Set(try await LoopRolloutAllowRecord.query(on: db).filter(\.$consumerId == consumer).all().map(\.publicationId))
        let blocked = Set(try await BusinessPreferenceRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$businessId ~~ businessIds)
            .filter(\.$blockedAt != nil).all().map(\.businessId))
        let switchedOff = Set(try await LoopSwitchRecord.query(on: db).filter(\.$businessId ~~ businessIds).filter(\.$clearedAt == nil).all().map(\.businessId))
        let records = try await BusinessRecord.query(on: db).filter(\.$id ~~ businessIds).all()
        let recordById = Dictionary(records.compactMap { r in r.id.map { ($0, r) } }, uniquingKeysWith: { a, _ in a })
        let summaryById = Dictionary(try await DirectoryService(db: db).summaries(for: records).map { ($0.id.uuid, $0) }, uniquingKeysWith: { a, _ in a })
        let revisionIds = publications.map(\.revisionId)
        let revisions = Dictionary(try await LoopRevisionRecord.query(on: db).filter(\.$id ~~ revisionIds).all().compactMap { r in r.id.map { ($0, r) } },
                                   uniquingKeysWith: { a, _ in a })
        let listings = Dictionary(try await LoopDirectoryListingRecord.query(on: db).filter(\.$definitionId ~~ publications.map(\.definitionId)).all()
            .map { ($0.definitionId, $0) }, uniquingKeysWith: { a, _ in a })
        var seen = Set<UUID>()
        var out: [Candidate] = []
        for publication in publications {
            guard let id = publication.id, !seen.contains(publication.definitionId),
                  LoopRollout.isEligible(consumerId: consumer, publicationId: id, percent: publication.rolloutPercent, allowListed: allowed.contains(id)),
                  !blocked.contains(publication.businessId), !switchedOff.contains(publication.businessId),
                  let business = recordById[publication.businessId], business.status == .verified,
                  case .eligible = LoopCategoryPolicy.loops(BusinessCategory(rawValue: business.category)),
                  let summary = summaryById[publication.businessId],
                  let revision = revisions[publication.revisionId], revision.businessId == publication.businessId,
                  let definition = LoopDefinition.parse(Data(revision.definitionJSON.utf8)).definition else { continue }
            seen.insert(publication.definitionId)
            out.append(Candidate(publication: publication, definition: definition, business: business, summary: summary,
                                 listing: listings[publication.definitionId].flatMap { $0.businessId == publication.businessId ? $0 : nil }))
        }
        return out
    }

    func entry(_ c: Candidate, installed: Set<UUID>, connected: Set<UUID>) -> LoopDirectoryEntry {
        let summary = c.definition.description.map { DisplayTextSanitizer.sanitize($0, maxCharacters: LoopLimits.descriptionLength) }.flatMap { $0.isEmpty ? nil : $0 }
        let kit: String? = if case .brandKit(let key) = c.definition.appearance { key } else { nil }
        return LoopDirectoryEntry(loopId: LoopDefinitionID(c.definitionId), publicationId: LoopPublicationID(c.publication.id!), revision: Int64(c.publication.revision),
                                  business: c.summary, businessCategory: BusinessCategory(rawValue: c.business.category),
                                  title: DisplayTextSanitizer.sanitize(c.definition.title, maxCharacters: LoopLimits.titleLength), summary: summary,
                                  category: c.listing.map { LoopDirectoryCategory(rawValue: $0.category) },
                                  featured: c.listing?.featured == true && c.listing?.listed == true, entryPoints: c.definition.entryPoints,
                                  installed: installed.contains(c.definitionId), connected: connected.contains(c.business.id!), brandKitId: kit)
    }

    func activeInstalls(consumer: UUID) async throws -> [LoopInstallRecord] {
        try await LoopInstallRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$uninstalledAt == nil).all()
    }

    func connectedBusinesses(consumer: UUID) async throws -> Set<UUID> {
        Set(try await RelationshipRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$status == "active").all().map(\.businessId))
    }

    /// The active install of this Loop by this customer, if the customer has not blocked the business (a block always wins).
    func activeInstall(consumer: UUID, definition: UUID) async throws -> LoopInstallRecord? {
        guard let row = try await LoopInstallRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$definitionId == definition)
            .filter(\.$uninstalledAt == nil).first() else { return nil }
        if try await PreferenceService(db: db, ctx: ctx).isBlocked(consumer: consumer, business: row.businessId) { return nil }
        return row
    }

    /// Whether the customer has any active install of a Loop of this business (the basis for its Loop authorization without a connection).
    func hasInstall(consumer: UUID, business: UUID) async throws -> Bool {
        guard try await LoopInstallRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$businessId == business).filter(\.$uninstalledAt == nil).first() != nil
        else { return false }
        return try await !PreferenceService(db: db, ctx: ctx).isBlocked(consumer: consumer, business: business)
    }

    // MARK: Directory

    func directory(principal: ConsumerPrincipal, query rawQuery: String?, category: LoopDirectoryCategory?, business: BusinessID?) async throws -> LoopDirectoryPage {
        let consumer = principal.consumerId.uuid
        try await ctx.limiter.enforce("loop-directory", key: consumer.uuidString.lowercased(), rule: ctx.config.loops.directoryRate)
        let query = (rawQuery ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard query.count <= Self.maxQueryLength else { throw APIError.validation("Use a shorter search.", details: ["q": "too_long"]) }
        if let category, !category.isKnown { throw APIError.validation("Choose a category.", details: ["category": "unknown"]) }
        let all = try await candidates(consumer: consumer, businesses: business.map { [$0.uuid] })
        let installed = Set(try await activeInstalls(consumer: consumer).map(\.definitionId))
        let connected = try await connectedBusinesses(consumer: consumer)
        // A business page shows every visible Loop of that business; the browsable directory only operator-listed ones.
        let pool = business == nil ? all.filter { $0.listing?.listed == true } : all
        let categories = LoopDirectoryCategory.known.filter { known in pool.contains { $0.listing?.listed == true && $0.listing?.category == known.rawValue } }
        let entries = pool.filter { c in
            if let category, c.listing?.category != category.rawValue { return false }
            guard !query.isEmpty else { return true }
            let haystack = [c.definition.title, c.definition.description ?? "", c.summary.displayName, c.summary.handle?.value ?? ""].joined(separator: " ").lowercased()
            return haystack.contains(query)
        }.map { entry($0, installed: installed, connected: connected) }.sorted { ($0.title, $0.loopId.description) < ($1.title, $1.loopId.description) }
        let featured = (query.isEmpty && category == nil && business == nil) ? entries.filter(\.featured) : []
        return LoopDirectoryPage(featured: featured, entries: entries, categories: categories)
    }

    func detail(principal: ConsumerPrincipal, loopId: LoopDefinitionID) async throws -> LoopDirectoryDetail {
        let consumer = principal.consumerId.uuid
        try await ctx.limiter.enforce("loop-directory", key: consumer.uuidString.lowercased(), rule: ctx.config.loops.directoryRate)
        guard let candidate = try await candidates(consumer: consumer, definitions: [loopId.uuid]).first,
              let revision = try await LoopRevisionRecord.find(candidate.publication.revisionId, on: db),
              let definition = LoopIDs.json(Data(revision.definitionJSON.utf8)) else { throw APIError.notFound }
        let installed = Set(try await activeInstalls(consumer: consumer).map(\.definitionId))
        let connected = try await connectedBusinesses(consumer: consumer)
        let manifest = try await LoopPublicationService(db: db, ctx: ctx).currentManifest(candidate.publication)
        return LoopDirectoryDetail(entry: entry(candidate, installed: installed, connected: connected), manifest: manifest, definition: definition)
    }

    // MARK: Install / uninstall

    func install(principal: ConsumerPrincipal, loopId: LoopDefinitionID, request: LoopInstallRequest) async throws -> LoopInstallResult {
        let consumer = principal.consumerId.uuid
        try await ctx.limiter.enforce("loop-install", key: consumer.uuidString.lowercased(), rule: ctx.config.loops.installRate)
        guard let candidate = try await candidates(consumer: consumer, definitions: [loopId.uuid]).first else { throw APIError.notFound }
        let current = LoopConsentCatalog.current
        guard request.agree else { throw APIError.validation("Agree to add this Loop.", details: ["agree": "required"]) }
        guard request.textVersion == current.version, request.textDigest == current.digest else {
            throw APIError.validation("The text changed. Read the current version first.", details: ["textVersion": "stale"])
        }
        let global = try await LoopConsentRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$businessId == nil).filter(\.$revokedAt == nil).first()
        guard let global, global.textVersion >= current.version else { throw APIError.conflict("Turn on requests built by businesses first.") }
        let existing = try await LoopInstallRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$definitionId == loopId.uuid).first()
        if existing?.isActive != true {
            let count = try await LoopInstallRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$uninstalledAt == nil).count()
            guard count < ctx.config.loops.maxInstalledPerAccount else {
                throw APIError.conflict("You've added the most Loops you can. Remove one to add another.")
            }
        }
        let businessId = candidate.publication.businessId
        // "Install and connect" is exactly Connect (blocks, consents, webhook, audit), run first so a refusal installs nothing.
        if request.mode == .installAndConnect {
            _ = try await RelationshipService(db: db, ctx: ctx).connect(consumer: principal.consumerId,
                request: ConnectRequest(businessId: BusinessID(businessId), source: request.source.connectSource), source: request.source.connectSource)
        }
        let now = ctx.now
        let ctx = self.ctx
        do { try await db.transaction { tx in
            if let existing {
                let wasActive = existing.isActive
                existing.mode = request.mode.rawValue
                existing.source = wasActive ? existing.source : request.source.rawValue
                if !wasActive { existing.installedAt = now }
                // Alerts are off unless the customer chooses them: a fresh install starts off, a repeated one keeps its choice unless it carries one.
                existing.alertsEnabled = request.alertsEnabled ?? (wasActive ? existing.alertsEnabled : false)
                existing.uninstalledAt = nil
                existing.updatedAt = now
                try await existing.update(on: tx)
            } else {
                let row = LoopInstallRecord()
                row.consumerId = consumer
                row.businessId = businessId
                row.definitionId = loopId.uuid
                row.mode = request.mode.rawValue
                row.source = request.source.rawValue
                row.installedAt = now
                row.updatedAt = now
                row.alertsEnabled = request.alertsEnabled ?? false
                try await row.create(on: tx)
            }
            // The install sheet carries the per-business authorization sentence: record it (a new grant revokes the previous one of the
            // same scope, as `PUT /v1/loops/consent/businesses/{id}` does).
            let grants = try await LoopConsentRecord.query(on: tx).filter(\.$consumerId == consumer).filter(\.$businessId == businessId).filter(\.$revokedAt == nil).all()
            if !grants.contains(where: { $0.textVersion >= current.version }) {
                try await LoopConsentRecord.query(on: tx).filter(\.$consumerId == consumer).filter(\.$businessId == businessId).filter(\.$revokedAt == nil)
                    .set(\.$revokedAt, to: now).update()
                let grant = LoopConsentRecord()
                grant.consumerId = consumer
                grant.businessId = businessId
                grant.textVersion = current.version
                grant.textDigest = current.digest
                grant.grantedAt = now
                try await grant.create(on: tx)
                _ = try await AuditService(db: tx, ctx: ctx).record("loop.consent_granted", principal: principal, businessId: BusinessID(businessId),
                                                                   metadata: ["scope": "business", "version": String(current.version), "via": "install"])
            }
            _ = try await AuditService(db: tx, ctx: ctx).record("loop.installed", principal: principal, businessId: BusinessID(businessId),
                subjectType: "loop_definition", subjectId: loopId.description,
                metadata: ["mode": request.mode.rawValue, "source": request.source.rawValue, "alerts": request.alertsEnabled == true ? "on" : "off"])
        } } catch let error where error.isConstraintViolation {
            // A concurrent install of the same Loop by the same account won the unique (consumer, Loop) row; its result stands.
        }
        ctx.metrics.count(.loopInstalled)
        guard let view = try await installed(consumer: consumer).first(where: { $0.loopId == loopId }) else { throw APIError.internalError }
        return LoopInstallResult(installed: view, consent: try await LoopRuntimeService(db: db, ctx: ctx).consentStatus(consumer: consumer))
    }

    /// Allows or stops this installed Loop's own alerts in Alerts (owner decision F-4). Only the Loop's alerts: it subscribes the customer to
    /// nothing else from the business. `404` when the Loop is not installed (or the business is blocked).
    func setAlerts(principal: ConsumerPrincipal, loopId: LoopDefinitionID, enabled: Bool) async throws -> InstalledLoop {
        let consumer = principal.consumerId.uuid
        try await ctx.limiter.enforce("loop-install", key: consumer.uuidString.lowercased(), rule: ctx.config.loops.installRate)
        guard let row = try await activeInstall(consumer: consumer, definition: loopId.uuid) else { throw APIError.notFound }
        if row.alertsEnabled != enabled {
            row.alertsEnabled = enabled
            row.updatedAt = ctx.now
            try await row.update(on: db)
            _ = try await AuditService(db: db, ctx: ctx).record("loop.alerts_changed", principal: principal, businessId: BusinessID(row.businessId),
                subjectType: "loop_definition", subjectId: loopId.description, metadata: ["alerts": enabled ? "on" : "off"])
        }
        guard let view = try await installed(consumer: consumer).first(where: { $0.loopId == loopId }) else { throw APIError.notFound }
        return view
    }

    func uninstall(principal: ConsumerPrincipal, loopId: LoopDefinitionID) async throws -> [InstalledLoop] {
        let consumer = principal.consumerId.uuid
        try await ctx.limiter.enforce("loop-install", key: consumer.uuidString.lowercased(), rule: ctx.config.loops.installRate)
        guard let row = try await LoopInstallRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$definitionId == loopId.uuid)
            .filter(\.$uninstalledAt == nil).first() else { throw APIError.notFound }
        let ctx = self.ctx
        try await db.transaction { tx in
            let revoked = try await LoopInstallService(db: tx, ctx: ctx).end(row, reason: "uninstalled")
            _ = try await AuditService(db: tx, ctx: ctx).record("loop.uninstalled", principal: principal, businessId: BusinessID(row.businessId),
                subjectType: "loop_definition", subjectId: loopId.description, metadata: ["authorization_revoked": revoked ? "true" : "false"])
        }
        ctx.metrics.count(.loopUninstalled)
        return try await installed(consumer: consumer)
    }

    /// Ends an install: marks it uninstalled, cancels the customer's open instances of that Loop (every publication of it), and revokes the
    /// business's Loop authorization when nothing else supports it (no connection, no other installed Loop of that business). Returns whether
    /// the authorization was revoked. Runs inside the caller's transaction.
    @discardableResult
    func end(_ row: LoopInstallRecord, reason: String) async throws -> Bool {
        let now = ctx.now
        row.uninstalledAt = now
        row.alertsEnabled = false
        row.updatedAt = now
        try await row.update(on: db)
        let publications = try await LoopPublicationRecord.query(on: db).filter(\.$definitionId == row.definitionId).all().compactMap(\.id)
        if !publications.isEmpty {
            try await LoopInstanceRecord.query(on: db).filter(\.$consumerId == row.consumerId).filter(\.$publicationId ~~ publications)
                .filter(\.$state ~~ [LoopInstanceState.active.rawValue, LoopInstanceState.submitted.rawValue])
                .set(\.$state, to: LoopInstanceState.cancelled.rawValue).set(\.$updatedAt, to: now).update()
        }
        let connected = try await RelationshipRecord.query(on: db).filter(\.$consumerId == row.consumerId).filter(\.$businessId == row.businessId)
            .filter(\.$status == "active").first() != nil
        let others = try await LoopInstallRecord.query(on: db).filter(\.$consumerId == row.consumerId).filter(\.$businessId == row.businessId)
            .filter(\.$uninstalledAt == nil).count()
        guard !connected, others == 0 else { return false }
        try await LoopConsentRecord.query(on: db).filter(\.$consumerId == row.consumerId).filter(\.$businessId == row.businessId).filter(\.$revokedAt == nil)
            .set(\.$revokedAt, to: now).update()
        return true
    }

    /// Blocking a business uninstalls its Loops (a block is never weaker than an uninstall).
    func uninstallAll(principal: ConsumerPrincipal, business: UUID, reason: String) async throws {
        let consumer = principal.consumerId.uuid
        let rows = try await LoopInstallRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$businessId == business).filter(\.$uninstalledAt == nil).all()
        guard !rows.isEmpty else { return }
        let ctx = self.ctx
        try await db.transaction { tx in
            for row in rows {
                try await LoopInstallService(db: tx, ctx: ctx).end(row, reason: reason)
                _ = try await AuditService(db: tx, ctx: ctx).record("loop.uninstalled", principal: principal, businessId: BusinessID(business),
                    subjectType: "loop_definition", subjectId: row.definitionId.uuidString.lowercased(), metadata: ["reason": reason])
            }
        }
    }

    /// Account deletion: installs go with the account; open instances are cancelled.
    static func wipe(consumer: UUID, on db: any Database, now: Date) async throws {
        try await LoopInstanceRecord.query(on: db).filter(\.$consumerId == consumer)
            .filter(\.$state ~~ [LoopInstanceState.active.rawValue, LoopInstanceState.submitted.rawValue])
            .set(\.$state, to: LoopInstanceState.cancelled.rawValue).set(\.$updatedAt, to: now).update()
        try await LoopInstallRecord.query(on: db).filter(\.$consumerId == consumer).delete()
    }

    // MARK: Installed list

    func installed(consumer: UUID) async throws -> [InstalledLoop] {
        let rows = try await activeInstalls(consumer: consumer)
        guard !rows.isEmpty else { return [] }
        let definitionIds = rows.map(\.definitionId)
        let visible = Dictionary(try await candidates(consumer: consumer, definitions: definitionIds).map { ($0.definitionId, $0) }, uniquingKeysWith: { a, _ in a })
        let businesses = try await BusinessRecord.query(on: db).filter(\.$id ~~ Array(Set(rows.map(\.businessId)))).all()
        let summaryById = Dictionary(try await DirectoryService(db: db).summaries(for: businesses).map { ($0.id.uuid, $0) }, uniquingKeysWith: { a, _ in a })
        let categoryById = Dictionary(businesses.compactMap { b in b.id.map { ($0, b.category) } }, uniquingKeysWith: { a, _ in a })
        let connected = try await connectedBusinesses(consumer: consumer)
        let publications = try await LoopPublicationRecord.query(on: db).filter(\.$definitionId ~~ definitionIds).sort(\.$revision, .descending).all()
        let instances = try await LoopInstanceRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$publicationId ~~ publications.compactMap(\.id))
            .filter(\.$state ~~ [LoopInstanceState.active.rawValue, LoopInstanceState.submitted.rawValue]).sort(\.$createdAt, .descending).all()
        var out: [InstalledLoop] = []
        for row in rows {
            guard let summary = summaryById[row.businessId] else { continue }
            let own = publications.filter { $0.definitionId == row.definitionId }
            let ownIds = Set(own.compactMap(\.id))
            let candidate = visible[row.definitionId]
            var title = candidate.map { $0.definition.title }
            if title == nil, let last = own.first, let revision = try await LoopRevisionRecord.find(last.revisionId, on: db) {
                title = LoopDefinition.parse(Data(revision.definitionJSON.utf8)).definition?.title
            }
            let kit: String? = if case .brandKit(let key)? = candidate?.definition.appearance { key } else { nil }
            out.append(InstalledLoop(loopId: LoopDefinitionID(row.definitionId), business: summary,
                                     businessCategory: BusinessCategory(rawValue: categoryById[row.businessId] ?? "other"),
                                     title: DisplayTextSanitizer.sanitize(title ?? "Loop", maxCharacters: LoopLimits.titleLength),
                                     mode: LoopInstallMode(rawValue: row.mode) ?? .installOnly, source: LoopInstallSource(rawValue: row.source) ?? .directory,
                                     installedAt: row.installedAt, connected: connected.contains(row.businessId),
                                     publicationId: candidate.map { LoopPublicationID($0.publication.id!) }, entryPoints: candidate?.definition.entryPoints ?? [],
                                     openInstances: instances.filter { ownIds.contains($0.publicationId) }.prefix(5).compactMap { $0.id.map(LoopInstanceID.init) },
                                     brandKitId: kit, alertsEnabled: row.alertsEnabled))
        }
        return out.sorted { ($0.title, $0.loopId.description) < ($1.title, $1.loopId.description) }
    }

    // MARK: Public landing

    /// The title and business name for the `/lp/{loopId}` web page: only for a fully launched publication (active, rollout 100%, verified
    /// business in an allowed category, no switch, platform on). Anything else gives `nil` (a generic page; nothing about the Loop).
    func publicLanding(definitionId: UUID) async throws -> (title: String, business: String)? {
        if await PlatformFlags(db: db, ctx: ctx).isStopped(.loops) { return nil }
        guard let publication = try await LoopPublicationRecord.query(on: db).filter(\.$definitionId == definitionId)
                .filter(\.$status == LoopPublicationStatus.active.rawValue).sort(\.$revision, .descending).first(),
              publication.rolloutPercent >= 100,
              try await !LoopPublicationService.businessSwitchedOff(publication.businessId, on: db),
              let business = try await DirectoryService(db: db).verified(id: publication.businessId),
              case .eligible = LoopCategoryPolicy.loops(BusinessCategory(rawValue: business.category)),
              let revision = try await LoopRevisionRecord.find(publication.revisionId, on: db),
              let definition = LoopDefinition.parse(Data(revision.definitionJSON.utf8)).definition else { return nil }
        return (DisplayTextSanitizer.sanitize(definition.title, maxCharacters: LoopLimits.titleLength),
                DisplayTextSanitizer.sanitize(business.displayName, maxCharacters: 60))
    }

    // MARK: Brand manifest visibility

    /// Whether the caller may read a business's signed brand manifest without a connection: it has an installed Loop of that business, or the
    /// business has a Loop the caller can see in the directory (the icon). Brand manifests hold business branding only.
    func brandVisible(consumer: UUID, business: UUID) async throws -> Bool {
        if try await hasInstall(consumer: consumer, business: business) { return true }
        return try await candidates(consumer: consumer, businesses: [business]).contains { $0.listing?.listed == true }
    }

    // MARK: Operator listing

    func setListing(publicationId: UUID, category: LoopDirectoryCategory, listed: Bool, featured: Bool, operatorId: UUID, reason rawReason: String?) async throws {
        guard try await OperatorPermission.holds(.loopReviewer, userId: operatorId, on: db) else {
            throw APIError(.forbidden, .forbidden, "You need the loop_reviewer permission.")
        }
        let reason = try LoopPublicationService.reason(rawReason)
        guard category.isKnown else { throw APIError.validation("Choose a category.") }
        guard let publication = try await LoopPublicationRecord.find(publicationId, on: db) else { throw APIError.notFound }
        let now = ctx.now
        let row = try await LoopDirectoryListingRecord.query(on: db).filter(\.$definitionId == publication.definitionId).first() ?? {
            let row = LoopDirectoryListingRecord()
            row.definitionId = publication.definitionId
            row.businessId = publication.businessId
            return row
        }()
        row.category = category.rawValue
        row.listed = listed
        row.featured = listed && featured
        row.setBy = operatorId
        row.setAt = now
        try await row.save(on: db)
        _ = try await AuditService(db: db, ctx: ctx).record("loop.directory_listing_changed", actor: LoopPublicationService.operatorActor(operatorId),
            businessId: BusinessID(publication.businessId), subjectType: "loop_definition", subjectId: publication.definitionId.uuidString.lowercased(),
            metadata: ["category": category.rawValue, "listed": listed ? "true" : "false", "featured": row.featured ? "true" : "false", "reason": reason])
    }

    /// The staging demo's listing (staging only; `StagingDemo` refuses every other environment). Audited with the system actor.
    func seedListing(definitionId: UUID, businessId: UUID, category: LoopDirectoryCategory, featured: Bool, actor: AuditActor) async throws {
        guard try await LoopDirectoryListingRecord.query(on: db).filter(\.$definitionId == definitionId).first() == nil else { return }
        let row = LoopDirectoryListingRecord()
        row.definitionId = definitionId
        row.businessId = businessId
        row.category = category.rawValue
        row.listed = true
        row.featured = featured
        row.setBy = UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        row.setAt = ctx.now
        try await row.create(on: db)
        _ = try await AuditService(db: db, ctx: ctx).record("loop.directory_listing_changed", actor: actor, businessId: BusinessID(businessId),
            subjectType: "loop_definition", subjectId: definitionId.uuidString.lowercased(),
            metadata: ["category": category.rawValue, "listed": "true", "featured": featured ? "true" : "false", "reason": "staging demo seed"])
    }
}
