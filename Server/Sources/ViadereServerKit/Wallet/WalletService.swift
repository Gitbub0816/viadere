@preconcurrency import Crypto
import Fluent
import Foundation
import ViadereCore

/// Wallet pass issuance, signing, the PassKit web service, update pushes, the business pass API and pass scanning.
///
/// * Each pass has an `authenticationToken`, derived as `HMAC(pepper, id ‖ salt)` so it can be re-embedded in every download,
///   while the database stores only its keyed hash, compared in constant time.
/// * The pass's QR carries a signed presentation code (`WalletScanCode`): `HMAC(pepper, "wallet-scan-v1" ‖ id ‖ generation)`, checked
///   in constant time. It identifies the pass to its own business only; redemption and check-in are single use on the server.
/// * Updates are announced through a durable outbox; a worker sends the empty PassKit push to every registered device.
/// * The server signs; the app never builds or signs a pass. A test-mode key never produces one.
struct WalletService {
    let db: any Database
    let ctx: ServerContext

    static let serialPrefix = "VP-"
    static let maxLogMessages = 20
    static let maxLogLength = 500
    static let maxPushAttempts = 5
    static let maxTextLength = 80

    // MARK: Identity and tokens

    /// Metadata without the presentation code (embedded in rewards and loyalty responses).
    static func metadata(_ record: WalletPassRecord) -> WalletPassMetadata? {
        guard let id = record.id else { return nil }
        return WalletPassMetadata(id: WalletPassID(id), businessId: BusinessID(record.businessId), kind: record.kindValue,
                                  passTypeIdentifier: record.passTypeIdentifier, serialNumber: record.serialNumber,
                                  updatedAt: record.updatedAt, voided: record.voided, usedAt: record.usedAt)
    }

    /// The holder's own view: adds the presentation code while the pass is valid, so the app can show the same QR as Wallet.
    func holderMetadata(_ record: WalletPassRecord) -> WalletPassMetadata? {
        guard var metadata = Self.metadata(record) else { return nil }
        if !record.voided { metadata.scanCode = scanCode(for: record) }
        return metadata
    }

    /// The per-pass secret Wallet echoes back as `Authorization: ApplePass <token>`.
    func authenticationToken(id: UUID, salt: String) -> String {
        let key = SymmetricKey(data: ctx.config.pepper)
        let mac = HMAC<SHA256>.authenticationCode(for: Data("wallet-auth-v1\n\(id.uuidString.lowercased())\n\(salt)".utf8), using: key)
        return Base64URL.encode(Data(mac))
    }

    func tokenHash(_ token: String) -> String { ctx.hasher.hmacHex("wallet-auth-hash", token) }

    /// Constant-time check of a presented token against the stored hash.
    func verify(token: String, for pass: WalletPassRecord) -> Bool {
        guard token.count >= 16, token.count <= 128 else { return false }
        return ConstantTime.equals(tokenHash(token), pass.authTokenHash)
    }

    private func requireSigner() throws -> any PassSigner {
        guard let signer = ctx.passSigner else { throw APIError.unavailable("Wallet passes are not available yet.") }
        return signer
    }

    // MARK: Presentation code (QR)

    static func scanPayload(id: UUID, generation: Int) -> Data {
        var data = withUnsafeBytes(of: id.uuid) { Data($0) }
        let value = UInt32(truncatingIfNeeded: generation).bigEndian
        withUnsafeBytes(of: value) { data.append(contentsOf: $0) }
        return data
    }

    private func scanTag(_ payload: Data) -> Data {
        let key = SymmetricKey(data: ctx.config.pepper)
        let mac = HMAC<SHA256>.authenticationCode(for: Data("wallet-scan-v1\n".utf8) + payload, using: key)
        return Data(Data(mac).prefix(WalletScanCode.tagByteCount))
    }

    func scanCode(for pass: WalletPassRecord) -> String {
        let payload = Self.scanPayload(id: pass.id!, generation: pass.scanGeneration)
        return WalletScanCode.prefix + Base64URL.encode(payload + scanTag(payload))
    }

    /// The pass id and generation of a genuine code, or nil for anything else (malformed, forged, altered). The tag is compared in
    /// constant time; the caller still checks the generation, the tenant and the pass's state.
    func verifyScanCode(_ raw: String) -> (id: UUID, generation: Int)? {
        let code = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard WalletScanCode.isWellFormed(code), let bytes = Base64URL.decode(String(code.dropFirst(WalletScanCode.prefix.count))),
              bytes.count == WalletScanCode.payloadByteCount + WalletScanCode.tagByteCount else { return nil }
        let payload = Data(bytes.prefix(WalletScanCode.payloadByteCount))
        guard ConstantTime.equals(Data(bytes.suffix(WalletScanCode.tagByteCount)), scanTag(payload)) else { return nil }
        let id = payload.prefix(16).withUnsafeBytes { UUID(uuid: $0.loadUnaligned(as: uuid_t.self)) }
        let generation = payload.suffix(4).reduce(0) { ($0 << 8) | Int($1) }
        return (id, generation)
    }

    // MARK: Issue

    func list(consumer: ConsumerID) async throws -> [WalletPassMetadata] {
        try await WalletPassRecord.query(on: db).filter(\.$consumerId == consumer.uuid).sort(\.$updatedAt, .descending).limit(200).all()
            .compactMap(holderMetadata)
    }

    func issue(consumer: ConsumerID, request: WalletPassIssueRequest) async throws -> WalletPassMetadata {
        let record = try await issueRecord(consumer: consumer, request: request, issuer: nil).record
        guard let metadata = holderMetadata(record) else { throw APIError.internalError }
        return metadata
    }

    /// Issues (or returns the existing) pass. `issuer` is nil for the customer, or the business principal for the business API.
    func issueRecord(consumer: ConsumerID, request: WalletPassIssueRequest, issuer: BusinessPrincipal?) async throws -> (record: WalletPassRecord, created: Bool) {
        let signer = try requireSigner()
        guard let business = try await DirectoryService(db: db).verified(id: request.businessId.uuid),
              try await RelationshipRecord.query(on: db).filter(\.$consumerId == consumer.uuid).filter(\.$businessId == business.id!)
                .filter(\.$status == "active").count() > 0 else { throw APIError.notFound }
        let businessId = business.id!
        var subjectKey: String
        var rewardId: UUID?
        var interactionId: UUID?
        switch request.kind {
        case .storeCard:
            guard try await LoyaltyAccountRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$consumerId == consumer.uuid).count() > 0 else {
                throw APIError.conflict("Join the loyalty program before adding its card to Wallet.")
            }
            subjectKey = "storeCard:\(request.businessId)"
        case .coupon:
            guard let id = request.rewardId, let reward = try await RewardRecord.find(id.uuid, on: db), reward.businessId == businessId,
                  reward.consumerId == nil || reward.consumerId == consumer.uuid else { throw APIError.notFound }
            guard !reward.isRevoked else { throw APIError.gone("This reward is no longer available.") }
            rewardId = id.uuid
            subjectKey = "coupon:\(id)"
        case .eventTicket, .boardingPass, .generic:
            guard let id = request.interactionId, let record = try await InteractionRecord.query(on: db).filter(\.$id == id.uuid)
                .filter(\.$consumerId == consumer.uuid).filter(\.$businessId == businessId).filter(\.$livemode == true).first() else { throw APIError.notFound }
            // Tickets and rewards carry what a pass shows; other interaction kinds have no pass.
            guard record.kind == InteractionKind.ticket.rawValue || (request.kind == .generic && record.kind == InteractionKind.reward.rawValue) else {
                throw APIError.conflict("This request can't be added to Wallet.")
            }
            guard record.statusValue != .cancelled else { throw APIError.gone("This ticket was cancelled.") }
            interactionId = id.uuid
            subjectKey = "ticket:\(id)"
        }
        if let existing = try await WalletPassRecord.query(on: db).filter(\.$consumerId == consumer.uuid).filter(\.$subjectKey == subjectKey).first() {
            return (existing, false)
        }
        let now = ctx.now
        let record = WalletPassRecord()
        record.id = UUID()
        record.businessId = businessId
        record.consumerId = consumer.uuid
        record.kind = request.kind.rawValue
        record.subjectKey = subjectKey
        record.passTypeIdentifier = signer.passTypeIdentifier
        record.serialNumber = Self.serialPrefix + SecureToken.generate(byteCount: 16)
        record.authSalt = SecureToken.generate(byteCount: 16)
        record.authTokenHash = tokenHash(authenticationToken(id: record.id!, salt: record.authSalt))
        record.rewardId = rewardId
        record.interactionId = interactionId
        record.voided = false
        record.scanGeneration = 0
        record.issuedBy = issuer == nil ? nil : BusinessWalletPass.Issuer.business.rawValue
        record.createdAt = now
        record.updatedAt = now
        let actor = issuer.map { AuditActor(kind: .businessAPIKey, id: $0.keyId.uuidString.lowercased()) } ?? AuditActor(kind: .consumer, id: consumer.description)
        do {
            try await db.transaction { tx in
                try await record.create(on: tx)
                _ = try await AuditService(db: tx, ctx: ctx).record("wallet.pass_issued", actor: actor,
                    consumerId: consumer, businessId: BusinessID(businessId), subjectType: "wallet_pass", subjectId: record.id?.uuidString.lowercased(),
                    metadata: ["kind": request.kind.rawValue, "issuer": issuer == nil ? "customer" : "business"])
            }
        } catch {
            if error.isConstraintViolation, let existing = try await WalletPassRecord.query(on: db).filter(\.$consumerId == consumer.uuid)
                .filter(\.$subjectKey == subjectKey).first() { return (existing, false) }
            throw error
        }
        return (record, true)
    }

    // MARK: Build

    private func descriptor(for pass: WalletPassRecord, signer: any PassSigner) async throws -> PassDescriptor {
        guard let business = try await BusinessRecord.find(pass.businessId, on: db) else { throw APIError.notFound }
        let name = String(business.displayName.prefix(64))
        var d = PassDescriptor(
            kind: pass.kindValue, passTypeIdentifier: pass.passTypeIdentifier, teamIdentifier: signer.teamIdentifier,
            serialNumber: pass.serialNumber, authenticationToken: authenticationToken(id: pass.id!, salt: pass.authSalt),
            webServiceURL: ctx.config.publicBaseURL + "/wallet", organizationName: name, description: "\(name) pass", logoText: name,
            barcodeMessage: pass.voided ? nil : scanCode(for: pass), voided: pass.voided)
        d.back = [PassDescriptor.Field(key: "issuer", label: PassStrings.issuedBy, value: .text(name)),
                  PassDescriptor.Field(key: "platform", label: PassStrings.deliveredBy, value: .text("Viadere"))]
        switch pass.kindValue {
        case .storeCard:
            let account = try await LoyaltyAccountRecord.query(on: db).filter(\.$businessId == pass.businessId).filter(\.$consumerId == pass.consumerId).first()
            let program = try await LoyaltyProgramRecord.query(on: db).filter(\.$businessId == pass.businessId).first()
            d.description = "\(name) loyalty card"
            d.primary = [.init(key: "points", label: PassStrings.points, value: .number(account?.pointsBalance ?? 0))]
            if let program, let account, let tier = program.tiers.last(where: { $0.minimumPoints <= account.pointsBalance }) {
                d.secondary = [.init(key: "status", label: PassStrings.status, value: .text(tier.name))]
            }
            if let program { d.back.append(.init(key: "program", label: PassStrings.program, value: .text(program.programName))) }
        case .coupon:
            if let id = pass.rewardId, let reward = try await RewardRecord.find(id, on: db) {
                d.description = "\(name) offer"
                d.primary = [.init(key: "offer", label: PassStrings.offer, value: .text(reward.title))]
                if let details = reward.details { d.secondary = [.init(key: "details", label: PassStrings.details, value: .text(details))] }
                d.expirationDate = reward.validUntil
            }
        case .eventTicket, .boardingPass, .generic:
            if let id = pass.interactionId, let record = try await InteractionRecord.find(id, on: db), let interaction = try? record.interaction() {
                switch interaction.payload {
                case .ticket(let ticket):
                    let label = pass.kindValue == .boardingPass ? PassStrings.flight : (pass.kindValue == .generic ? PassStrings.reservation : PassStrings.event)
                    d.description = "\(name) \(ticket.title)"
                    d.primary = [.init(key: "title", label: label, value: .text(ticket.title))]
                    if let venue = pass.ticketVenue ?? ticket.venue {
                        d.secondary.append(.init(key: "venue", label: PassStrings.venue, value: .text(venue), changeMessage: PassStrings.venueChanged))
                    }
                    if let seat = pass.ticketSeat ?? ticket.seat {
                        d.secondary.append(.init(key: "seat", label: PassStrings.seat, value: .text(seat), changeMessage: PassStrings.seatChanged))
                    }
                    let starts = pass.ticketStartsAt ?? ticket.startsAt
                    if let starts {
                        d.auxiliary.append(.init(key: "starts", label: PassStrings.starts, value: .date(starts), changeMessage: PassStrings.startChanged))
                    }
                    if pass.usedAt != nil { d.auxiliary.append(.init(key: "entry", label: PassStrings.entry, value: .text(PassStrings.checkedIn))) }
                    if let relevant = starts ?? ticket.validFrom {
                        d.relevantDate = relevant
                        d.relevantInterval = (relevant, ticket.validUntil.flatMap { $0 > relevant ? $0 : nil } ?? relevant.addingTimeInterval(4 * 3600))
                    }
                    d.expirationDate = ticket.validUntil
                case .reward(let reward):
                    d.primary = [.init(key: "title", label: PassStrings.reward, value: .text(reward.title))]
                    d.expirationDate = reward.redeemBy
                default:
                    break
                }
            }
        }
        if ctx.config.walletBetaLabel { d.back.append(.init(key: "beta", label: PassStrings.about, value: .text(PassStrings.beta))) }
        return d
    }

    /// The signed `.pkpass` bytes for a pass, built fresh from current data.
    func pkpass(for pass: WalletPassRecord) async throws -> Data {
        let signer = try requireSigner()
        let json = try await descriptor(for: pass, signer: signer).json()
        do {
            return try PKPassBuilder.build(passJSON: json, signer: signer, at: ctx.now)
        } catch {
            throw APIError.internalError
        }
    }

    /// Consumer download: `410` once voided.
    func download(consumer: ConsumerID, id: WalletPassID) async throws -> (data: Data, pass: WalletPassRecord) {
        guard let pass = try await WalletPassRecord.query(on: db).filter(\.$id == id.uuid).filter(\.$consumerId == consumer.uuid).first() else {
            throw APIError.notFound
        }
        guard !pass.voided else { throw APIError.gone("This pass is no longer valid.") }
        return (try await pkpass(for: pass), pass)
    }

    // MARK: Changes and pushes

    /// Marks a pass changed and queues the push that tells registered devices to refresh it.
    func touch(_ pass: WalletPassRecord) async throws {
        let now = ctx.now
        pass.updatedAt = now
        try await WalletPassRecord.query(on: db).filter(\.$id == pass.id!).set(\.$updatedAt, to: now).update()
        let row = WalletPushOutboxRecord()
        row.id = UUID()
        row.passId = pass.id!
        row.status = "queued"
        row.attempts = 0
        row.nextAttemptAt = now
        row.createdAt = now
        try await db.transaction { [ctx] tx in
            try await row.create(on: tx)
            try await Outbox.enqueue(QueueHandlers.walletPush, ref: row.id!, on: tx, ctx: ctx)
        }
    }

    func touch(consumer: UUID, businessId: UUID, kind: WalletPassKind) async throws {
        for pass in try await WalletPassRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$businessId == businessId)
            .filter(\.$kind == kind.rawValue).filter(\.$voided == false).all() { try await touch(pass) }
    }

    func void(_ pass: WalletPassRecord) async throws {
        guard !pass.voided else { return }
        pass.voided = true
        try await WalletPassRecord.query(on: db).filter(\.$id == pass.id!).set(\.$voided, to: true).update()
        try await touch(pass)
    }

    /// Voids every live pass matching the filter (a disconnected relationship, a cancelled ticket).
    func voidAll(consumer: UUID, businessId: UUID) async throws {
        for pass in try await WalletPassRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$businessId == businessId)
            .filter(\.$voided == false).all() { try await void(pass) }
    }

    func voidAll(interactionId: UUID) async throws {
        for pass in try await WalletPassRecord.query(on: db).filter(\.$interactionId == interactionId).filter(\.$voided == false).all() {
            try await void(pass)
        }
    }

    /// Sends queued pass-update pushes. Claims each row with a compare-and-swap, so concurrent workers never double-send.
    @discardableResult
    func deliverDue(limit: Int = 50) async throws -> Int {
        let now = ctx.now
        let due = try await WalletPushOutboxRecord.query(on: db).filter(\.$status == "queued").filter(\.$nextAttemptAt <= now)
            .sort(\.$createdAt, .ascending).limit(limit).all()
        var sent = 0
        for row in due {
            guard try await DB.swap(db, table: WalletPushOutboxRecord.schema, id: row.id!, column: "status", expected: "queued", newValue: "sending") else { continue }
            if try await pushClaimed(row, now: now) { sent += 1 }
        }
        return sent
    }

    /// Sends one claimed (`sending`) outbox row: the shared body of `deliverDue` and the `wallet.push` queue handler. Returns whether it finished.
    @discardableResult
    func pushClaimed(_ row: WalletPushOutboxRecord, now: Date) async throws -> Bool {
        let registrations = try await WalletRegistrationRecord.query(on: db).filter(\.$passId == row.passId).all()
        guard let pass = try await WalletPassRecord.find(row.passId, on: db) else {
            try await WalletPushOutboxRecord.query(on: db).filter(\.$id == row.id!).delete()
            return false
        }
        var failed = false
        for registration in registrations {
            switch await ctx.passPush.notify(pushToken: registration.pushToken, passTypeIdentifier: pass.passTypeIdentifier) {
            case .delivered: break
            // Wallet told us the device forgot the pass: stop pushing to it.
            case .tokenInvalid: try await WalletRegistrationRecord.query(on: db).filter(\.$id == registration.id!).delete()
            case .failed: failed = true
            }
        }
        let attempts = row.attempts + 1
        if failed, attempts < Self.maxPushAttempts {
            try await WalletPushOutboxRecord.query(on: db).filter(\.$id == row.id!).set(\.$status, to: "queued").set(\.$attempts, to: attempts)
                .set(\.$nextAttemptAt, to: now.addingTimeInterval(TimeInterval(60 * attempts * attempts))).update()
            return false
        }
        try await WalletPushOutboxRecord.query(on: db).filter(\.$id == row.id!).set(\.$status, to: "sent").set(\.$attempts, to: attempts).update()
        return true
    }

    /// Maintenance: drop finished outbox rows and old device logs.
    func purge() async throws {
        let cutoff = ctx.now.addingTimeInterval(-7 * 86_400)
        try await WalletPushOutboxRecord.query(on: db).filter(\.$status == "sent").filter(\.$createdAt < cutoff).delete()
        try await WalletLogRecord.query(on: db).filter(\.$createdAt < cutoff).delete()
    }

    // MARK: Business API

    private func businessDTO(_ pass: WalletPassRecord) async throws -> BusinessWalletPass {
        let relationship = try await RelationshipRecord.query(on: db).filter(\.$consumerId == pass.consumerId).filter(\.$businessId == pass.businessId)
            .sort(\.$connectedAt, .descending).first()
        return BusinessWalletPass(
            id: WalletPassID(pass.id!), kind: pass.kindValue, relationshipId: relationship.flatMap { $0.id.map { RelationshipID($0) } },
            subjectRef: ctx.subjects.subjectRef(businessId: BusinessID(pass.businessId), consumerId: ConsumerID(pass.consumerId)),
            rewardId: pass.rewardId.map { RewardID($0) }, interactionId: pass.interactionId.map { InteractionID($0) },
            issuedBy: pass.issuedBy == BusinessWalletPass.Issuer.business.rawValue ? .business : .customer, voided: pass.voided,
            usedAt: pass.usedAt, createdAt: pass.createdAt, updatedAt: pass.updatedAt)
    }

    /// The business's own live pass, or `404` (another business's pass, or any pass for a test-mode key, is indistinguishable from none).
    private func ownedPass(principal: BusinessPrincipal, id: WalletPassID) async throws -> WalletPassRecord {
        try Sandbox.requireLive(principal, "manage Wallet passes")
        guard let pass = try await WalletPassRecord.query(on: db).filter(\.$id == id.uuid).filter(\.$businessId == principal.businessId.uuid).first() else {
            throw APIError.notFound
        }
        return pass
    }

    func businessIssue(principal: BusinessPrincipal, request: BusinessIssueWalletPassRequest) async throws -> (pass: BusinessWalletPass, created: Bool) {
        // A pass reaches a real person's Wallet: a test-mode key never produces one.
        try Sandbox.requireLive(principal, "issue Wallet passes")
        guard let relationshipId = request.relationshipId, let relationship = try await RelationshipRecord.query(on: db)
            .filter(\.$id == relationshipId.uuid).filter(\.$businessId == principal.businessId.uuid).first() else { throw APIError.notFound }
        guard relationship.isActive else { throw APIError.conflict("The customer is not connected to your business.") }
        try await Sandbox(db: db).requireMatching(relationship: relationship, livemode: principal.livemode)
        let result = try await issueRecord(consumer: ConsumerID(relationship.consumerId), request: WalletPassIssueRequest(
            kind: request.kind, businessId: principal.businessId, rewardId: request.rewardId, interactionId: request.interactionId), issuer: principal)
        return (try await businessDTO(result.record), result.created)
    }

    func businessList(principal: BusinessPrincipal, limit: Int) async throws -> [BusinessWalletPass] {
        guard principal.livemode else { return [] }
        var out: [BusinessWalletPass] = []
        for pass in try await WalletPassRecord.query(on: db).filter(\.$businessId == principal.businessId.uuid).sort(\.$createdAt, .descending)
            .limit(limit).all() { out.append(try await businessDTO(pass)) }
        return out
    }

    func businessVoid(principal: BusinessPrincipal, id: WalletPassID) async throws -> BusinessWalletPass {
        let pass = try await ownedPass(principal: principal, id: id)
        if !pass.voided {
            try await db.transaction { tx in
                try await WalletService(db: tx, ctx: ctx).void(pass)
                _ = try await AuditService(db: tx, ctx: ctx).record("wallet.pass_voided", actor: AuditActor(kind: .businessAPIKey, id: principal.keyId.uuidString.lowercased()),
                    consumerId: ConsumerID(pass.consumerId), businessId: principal.businessId, subjectType: "wallet_pass", subjectId: id.description)
            }
        }
        return try await businessDTO(pass)
    }

    private func validatedText(_ value: String?, field: String) throws -> String?? {
        guard let value else { return .none }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return .some(nil) }
        guard trimmed.count <= Self.maxTextLength, !trimmed.contains(where: { $0.isNewline }),
              !trimmed.unicodeScalars.contains(where: { $0.properties.generalCategory == .control || $0.properties.generalCategory == .format }) else {
            throw APIError.validation("\(field) is not valid.", details: [field: "invalid"])
        }
        return .some(trimmed)
    }

    func businessUpdate(principal: BusinessPrincipal, id: WalletPassID, request: UpdateWalletPassRequest) async throws -> BusinessWalletPass {
        let pass = try await ownedPass(principal: principal, id: id)
        guard !pass.voided else { throw APIError.gone("This pass was voided.") }
        let venue = try validatedText(request.venue, field: "venue")
        let seat = try validatedText(request.seat, field: "seat")
        let ticketChange = venue != nil || seat != nil || request.startsAt != nil
        let rotate = request.rotateScanCode == true
        guard ticketChange || rotate else { throw APIError.validation("Nothing to update.", details: ["body": "empty"]) }
        if ticketChange {
            guard [.eventTicket, .generic, .boardingPass].contains(pass.kindValue) else {
                throw APIError.conflict("Only ticket and reservation passes have a venue, seat or start time.")
            }
            if let starts = request.startsAt, starts < ctx.now.addingTimeInterval(-86_400) {
                throw APIError.validation("startsAt is in the past.", details: ["startsAt": "invalid"])
            }
        }
        // Updates are operational: a pass takes a few a day, so they cannot become a notification channel.
        try await ctx.limiter.enforce("wallet-update", key: id.description, rule: ctx.config.rateLimits.walletUpdatePerPass)
        var fields: [String] = []
        if let venue { pass.ticketVenue = venue; fields.append("venue") }
        if let seat { pass.ticketSeat = seat; fields.append("seat") }
        if let starts = request.startsAt { pass.ticketStartsAt = starts; fields.append("startsAt") }
        if rotate { pass.scanGeneration += 1; fields.append("scanCode") }
        let changed = fields
        try await db.transaction { tx in
            try await WalletPassRecord.query(on: tx).filter(\.$id == pass.id!).set(\.$ticketVenue, to: pass.ticketVenue).set(\.$ticketSeat, to: pass.ticketSeat)
                .set(\.$ticketStartsAt, to: pass.ticketStartsAt).set(\.$scanGeneration, to: pass.scanGeneration).update()
            try await WalletService(db: tx, ctx: ctx).touch(pass)
            _ = try await AuditService(db: tx, ctx: ctx).record("wallet.pass_updated", actor: AuditActor(kind: .businessAPIKey, id: principal.keyId.uuidString.lowercased()),
                consumerId: ConsumerID(pass.consumerId), businessId: principal.businessId, subjectType: "wallet_pass", subjectId: id.description,
                metadata: ["fields": changed.joined(separator: ",")])
        }
        return try await businessDTO(pass)
    }

    // MARK: Scan

    func scan(principal: BusinessPrincipal, request: WalletScanRequest) async throws -> WalletScanResult {
        // Every attempt costs budget, so neither forging tags nor replaying old codes can be done at volume.
        try await ctx.limiter.enforce("wallet-scan", key: principal.businessId.description, rule: ctx.config.rateLimits.walletScan)
        let location = try RewardsService.validatedLocation(request.locationCode)
        // Forged, altered, malformed, rotated-out, another business's, a sandbox key's or a disconnected customer's: the same 404.
        guard principal.livemode, let parsed = verifyScanCode(request.code),
              let pass = try await WalletPassRecord.query(on: db).filter(\.$id == parsed.id).filter(\.$businessId == principal.businessId.uuid).first(),
              parsed.generation == pass.scanGeneration,
              try await Sandbox(db: db).matches(consumerId: pass.consumerId, livemode: true),
              let relationship = try await RelationshipRecord.query(on: db).filter(\.$consumerId == pass.consumerId)
                .filter(\.$businessId == principal.businessId.uuid).filter(\.$status == "active").first(), let relationshipId = relationship.id else {
            throw APIError(.notFound, .notFound, "This pass isn't valid here.")
        }
        guard !pass.voided else { throw APIError.gone("This pass is no longer valid.") }
        let now = ctx.now
        let consumer = ConsumerID(pass.consumerId)
        let subjectRef = ctx.subjects.subjectRef(businessId: principal.businessId, consumerId: consumer)
        let actor = AuditActor(kind: .businessAPIKey, id: principal.keyId.uuidString.lowercased())
        func result(_ outcome: WalletScanResult.Outcome, title: String? = nil, points: Int? = nil, redemption: RedemptionReceipt? = nil) -> WalletScanResult {
            WalletScanResult(outcome: outcome, passId: WalletPassID(pass.id!), kind: pass.kindValue, relationshipId: RelationshipID(relationshipId),
                             subjectRef: subjectRef, title: title, pointsBalance: points, redemption: redemption, scannedAt: now)
        }
        switch pass.kindValue {
        case .storeCard:
            let account = try await LoyaltyAccountRecord.query(on: db).filter(\.$businessId == pass.businessId).filter(\.$consumerId == pass.consumerId).first()
            _ = try await AuditService(db: db, ctx: ctx).record("wallet.pass_scanned", actor: actor, consumerId: consumer, businessId: principal.businessId,
                subjectType: "wallet_pass", subjectId: pass.id!.uuidString.lowercased(), metadata: ["outcome": "member"])
            return result(.member, points: account?.pointsBalance ?? 0)
        case .coupon:
            guard let rewardId = pass.rewardId, let reward = try await RewardRecord.find(rewardId, on: db), !reward.isRevoked else {
                throw APIError.gone("This pass is no longer valid.")
            }
            if let until = reward.validUntil, now >= until { throw APIError.gone("This offer has expired.") }
            let receipt = try await RewardsService(db: db, ctx: ctx).redeemPresentedPass(principal: principal, consumerId: pass.consumerId,
                                                                                        rewardId: rewardId, location: location)
            return result(.redeemed, title: receipt.rewardTitle, redemption: receipt)
        case .eventTicket, .boardingPass, .generic:
            guard let interactionId = pass.interactionId, let record = try await InteractionRecord.find(interactionId, on: db),
                  record.statusValue != .cancelled, let interaction = try? record.interaction() else {
                throw APIError.gone("This pass is no longer valid.")
            }
            var title: String?
            if case .ticket(let ticket) = interaction.payload {
                title = ticket.title
                if let from = ticket.validFrom, now < from {
                    throw APIError(.conflict, .conflict, "This ticket isn't valid yet.", details: ["state": "notYetValid", "validFrom": ViadereDate.format(from)])
                }
                if let until = ticket.validUntil, now >= until { throw APIError.gone("This ticket has expired.") }
            } else if case .reward(let reward) = interaction.payload {
                title = reward.title
                if let until = reward.redeemBy, now >= until { throw APIError.gone("This pass has expired.") }
            }
            // Single entry: exactly one scan flips used_at from NULL; every later one learns when it was used.
            let checkedIn = try await db.transaction { tx -> Bool in
                guard try await DB.swapFromNull(tx, table: WalletPassRecord.schema, id: pass.id!, column: "used_at", newValue: now) else { return false }
                pass.usedAt = now
                try await WalletService(db: tx, ctx: ctx).touch(pass)
                _ = try await AuditService(db: tx, ctx: ctx).record("wallet.pass_checked_in", actor: actor, consumerId: consumer, businessId: principal.businessId,
                    subjectType: "wallet_pass", subjectId: pass.id!.uuidString.lowercased(), metadata: location.map { ["location": $0] } ?? [:])
                return true
            }
            guard checkedIn else {
                let used = try await WalletPassRecord.find(pass.id!, on: db)?.usedAt
                throw APIError(.conflict, .conflict, "This pass was already used.", details: used.map { ["usedAt": ViadereDate.format($0)] })
            }
            return result(.checkedIn, title: title)
        }
    }

    // MARK: PassKit web service

    /// Looks up the pass named in the URL and checks the `ApplePass` token. A wrong token, a wrong pass type and an unknown
    /// serial are all the same `401`.
    func authenticated(passTypeIdentifier: String, serialNumber: String, authorization: String?, clientKey: String) async throws -> WalletPassRecord {
        func fail() async throws -> Never {
            try await ctx.limiter.enforce("wallet-auth-fail", key: clientKey, rule: ctx.config.rateLimits.walletAuthFailurePerPass)
            throw APIError.unauthorized
        }
        guard let authorization, authorization.hasPrefix("ApplePass "), serialNumber.count <= 64, passTypeIdentifier.count <= 128 else { try await fail() }
        let token = String(authorization.dropFirst("ApplePass ".count)).trimmingCharacters(in: .whitespaces)
        guard let pass = try await WalletPassRecord.query(on: db).filter(\.$serialNumber == serialNumber).first(),
              pass.passTypeIdentifier == passTypeIdentifier, verify(token: token, for: pass) else { try await fail() }
        return pass
    }

    static func validDeviceLibraryIdentifier(_ value: String) -> Bool {
        (1...64).contains(value.count) && value.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }
    }

    static func validPushToken(_ value: String) -> Bool {
        (32...200).contains(value.count) && value.allSatisfy { $0.isASCII && $0.isHexDigit }
    }

    /// Registers (or re-registers) a device for updates. `true` when newly created.
    func register(pass: WalletPassRecord, deviceLibraryIdentifier: String, pushToken: String) async throws -> Bool {
        guard Self.validDeviceLibraryIdentifier(deviceLibraryIdentifier), Self.validPushToken(pushToken) else {
            throw APIError.badRequest("The registration is not valid.")
        }
        let token = pushToken.lowercased()
        if let existing = try await WalletRegistrationRecord.query(on: db).filter(\.$passId == pass.id!)
            .filter(\.$deviceLibraryIdentifier == deviceLibraryIdentifier).first() {
            if existing.pushToken != token {
                existing.pushToken = token
                try await existing.update(on: db)
            }
            return false
        }
        // A device registers a bounded number of passes, so a leaked token cannot be used to fill the table.
        guard try await WalletRegistrationRecord.query(on: db).filter(\.$passId == pass.id!).count() < 20 else {
            throw APIError.rateLimited(retryAfter: 3600)
        }
        let row = WalletRegistrationRecord()
        row.id = UUID()
        row.passId = pass.id!
        row.deviceLibraryIdentifier = deviceLibraryIdentifier
        row.pushToken = token
        row.createdAt = ctx.now
        do { try await row.create(on: db) } catch { if !error.isConstraintViolation { throw error } }
        return true
    }

    func unregister(pass: WalletPassRecord, deviceLibraryIdentifier: String) async throws {
        try await WalletRegistrationRecord.query(on: db).filter(\.$passId == pass.id!).filter(\.$deviceLibraryIdentifier == deviceLibraryIdentifier).delete()
    }

    /// Serial numbers of the device's passes changed after `since`, and the new tag. `nil` when nothing changed.
    func updatedSerials(deviceLibraryIdentifier: String, passTypeIdentifier: String, since: String?) async throws -> (serials: [String], tag: String)? {
        guard Self.validDeviceLibraryIdentifier(deviceLibraryIdentifier) else { return nil }
        let passIds = try await WalletRegistrationRecord.query(on: db).filter(\.$deviceLibraryIdentifier == deviceLibraryIdentifier).all().map(\.passId)
        guard !passIds.isEmpty else { return nil }
        var passes = try await WalletPassRecord.query(on: db).filter(\.$id ~~ passIds).filter(\.$passTypeIdentifier == passTypeIdentifier).all()
        if let since, let millis = Int64(since) {
            let date = Date(timeIntervalSince1970: TimeInterval(millis) / 1000)
            passes = passes.filter { $0.updatedAt > date }
        }
        guard !passes.isEmpty else { return nil }
        let newest = passes.map(\.updatedAt).max() ?? ctx.now
        return (passes.map(\.serialNumber).sorted(), String(Int64((newest.timeIntervalSince1970 * 1000).rounded())))
    }

    func record(logs: [String]) async throws {
        for message in logs.prefix(Self.maxLogMessages) {
            let row = WalletLogRecord()
            row.id = UUID()
            row.message = LogRedactor.redact(String(message.prefix(Self.maxLogLength)))
            row.createdAt = ctx.now
            try await row.create(on: db)
        }
    }
}
