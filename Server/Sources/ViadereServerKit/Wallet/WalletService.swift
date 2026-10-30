@preconcurrency import Crypto
import Fluent
import Foundation
import ViadereCore

/// Wallet pass issuance, signing, the PassKit web service and update pushes.
///
/// * Each pass has an `authenticationToken`, derived as `HMAC(pepper, id ‖ salt)` so it can be re-embedded in every download,
///   while the database stores only its keyed hash, compared in constant time.
/// * Updates are announced through a durable outbox; a worker sends the empty PassKit push to every registered device.
/// * The server signs; the app never builds or signs a pass.
struct WalletService {
    let db: any Database
    let ctx: ServerContext

    static let serialPrefix = "VP-"
    static let maxLogMessages = 20
    static let maxLogLength = 500
    static let maxPushAttempts = 5

    // MARK: Identity and tokens

    static func metadata(_ record: WalletPassRecord) -> WalletPassMetadata? {
        guard let id = record.id else { return nil }
        return WalletPassMetadata(id: WalletPassID(id), businessId: BusinessID(record.businessId), kind: record.kindValue,
                                  passTypeIdentifier: record.passTypeIdentifier, serialNumber: record.serialNumber,
                                  updatedAt: record.updatedAt, voided: record.voided)
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

    // MARK: Issue

    func list(consumer: ConsumerID) async throws -> [WalletPassMetadata] {
        try await WalletPassRecord.query(on: db).filter(\.$consumerId == consumer.uuid).sort(\.$updatedAt, .descending).limit(200).all()
            .compactMap(Self.metadata)
    }

    func issue(consumer: ConsumerID, request: WalletPassIssueRequest) async throws -> WalletPassMetadata {
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
                .filter(\.$consumerId == consumer.uuid).filter(\.$businessId == businessId).first() else { throw APIError.notFound }
            // Tickets and rewards carry what a pass shows; other interaction kinds have no pass.
            guard record.kind == InteractionKind.ticket.rawValue || (request.kind == .generic && record.kind == InteractionKind.reward.rawValue) else {
                throw APIError.conflict("This request can't be added to Wallet.")
            }
            interactionId = id.uuid
            subjectKey = "ticket:\(id)"
        }
        if let existing = try await WalletPassRecord.query(on: db).filter(\.$consumerId == consumer.uuid).filter(\.$subjectKey == subjectKey).first() {
            guard let metadata = Self.metadata(existing) else { throw APIError.internalError }
            return metadata
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
        record.createdAt = now
        record.updatedAt = now
        do {
            try await db.transaction { tx in
                try await record.create(on: tx)
                _ = try await AuditService(db: tx, ctx: ctx).record("wallet.pass_issued", actor: AuditActor(kind: .consumer, id: consumer.description),
                    consumerId: consumer, businessId: BusinessID(businessId), subjectType: "wallet_pass", subjectId: record.id?.uuidString.lowercased(),
                    metadata: ["kind": request.kind.rawValue])
            }
        } catch {
            if error.isConstraintViolation, let existing = try await WalletPassRecord.query(on: db).filter(\.$consumerId == consumer.uuid)
                .filter(\.$subjectKey == subjectKey).first(), let metadata = Self.metadata(existing) { return metadata }
            throw error
        }
        guard let metadata = Self.metadata(record) else { throw APIError.internalError }
        return metadata
    }

    // MARK: Build

    private func descriptor(for pass: WalletPassRecord, signer: any PassSigner) async throws -> PassDescriptor {
        guard let business = try await BusinessRecord.find(pass.businessId, on: db) else { throw APIError.notFound }
        let name = String(business.displayName.prefix(64))
        var d = PassDescriptor(
            kind: pass.kindValue, passTypeIdentifier: pass.passTypeIdentifier, teamIdentifier: signer.teamIdentifier,
            serialNumber: pass.serialNumber, authenticationToken: authenticationToken(id: pass.id!, salt: pass.authSalt),
            webServiceURL: ctx.config.publicBaseURL + "/wallet", organizationName: name, description: "\(name) pass", logoText: name,
            barcodeMessage: pass.serialNumber, voided: pass.voided)
        d.back = [PassDescriptor.Field(key: "issuer", label: "ISSUED BY", value: .text("\(name), through Viadere"))]
        switch pass.kindValue {
        case .storeCard:
            let account = try await LoyaltyAccountRecord.query(on: db).filter(\.$businessId == pass.businessId).filter(\.$consumerId == pass.consumerId).first()
            let program = try await LoyaltyProgramRecord.query(on: db).filter(\.$businessId == pass.businessId).first()
            d.description = "\(name) loyalty card"
            d.primary = [.init(key: "points", label: "POINTS", value: .number(account?.pointsBalance ?? 0))]
            if let program, let account, let tier = program.tiers.last(where: { $0.minimumPoints <= account.pointsBalance }) {
                d.secondary = [.init(key: "status", label: "STATUS", value: .text(tier.name))]
            }
            if let program { d.back.append(.init(key: "program", label: "PROGRAM", value: .text(program.programName))) }
        case .coupon:
            if let id = pass.rewardId, let reward = try await RewardRecord.find(id, on: db) {
                d.description = "\(name) offer"
                d.primary = [.init(key: "offer", label: "OFFER", value: .text(reward.title))]
                if let details = reward.details { d.secondary = [.init(key: "details", label: "DETAILS", value: .text(details))] }
                d.expirationDate = reward.validUntil
            }
        case .eventTicket, .boardingPass, .generic:
            if let id = pass.interactionId, let record = try await InteractionRecord.find(id, on: db), let interaction = try? record.interaction() {
                switch interaction.payload {
                case .ticket(let ticket):
                    d.description = "\(name) \(ticket.title)"
                    d.primary = [.init(key: "title", label: pass.kindValue == .boardingPass ? "FLIGHT" : "EVENT", value: .text(ticket.title))]
                    if let venue = ticket.venue { d.secondary.append(.init(key: "venue", label: "VENUE", value: .text(venue))) }
                    if let seat = ticket.seat { d.secondary.append(.init(key: "seat", label: "SEAT", value: .text(seat))) }
                    d.relevantDate = ticket.startsAt ?? ticket.validFrom
                    d.expirationDate = ticket.validUntil
                case .reward(let reward):
                    d.primary = [.init(key: "title", label: "REWARD", value: .text(reward.title))]
                    d.expirationDate = reward.redeemBy
                default:
                    break
                }
            }
        }
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
