import Fluent
import FluentSQL
import Foundation
import SQLKit
import ViadereCore

/// Phone-number ownership by a customer-originated text (ADR-0027, owner decisions 1 and 9).
///
/// Viadere sends no code and no link to a number. A trusted device asks for a challenge (`begin`); the person sends the nonce **from their phone**
/// to the Viadere number; the gateway hands that inbound message to `handleInbound`, which binds the number to the account only when the message
/// came from the claimed number, carries the live nonce, arrived within the TTL and passed the provider's sender check. The proof is control of the
/// number at that moment: the link carries the label `phone_control_mo`, satisfies no assurance level, is never an authenticator and never shortens
/// a waiting period. A number linked this way receives on-ramp texts and the "open Viadere" notice only (`ChannelRouter`).
struct PhoneLinkService {
    let db: any Database
    let ctx: ServerContext

    static let maxLinkedNumbersPerAccount = 1
    /// A new link is not used for routing or delivery for this long. The proving device is the requester's own, so a trusted-device confirmation
    /// does not shorten it for a number linked by text (ADR-0027 §2).
    static let newLinkCoolDown: TimeInterval = 24 * 3600
    /// The same, when the account has no *other* trusted device that could notice the link (nobody to ask, so the delay is the defence).
    static let soleDeviceLinkCoolDown: TimeInterval = 72 * 3600
    /// Verified links per number: at most 2 in 7 days and 1 in a day (UNLINK/re-link churn, ADR-0027 §1.5).
    static let maxLinksPerNumberPerWeek = 2
    static let maxLinksPerNumberPerDay = 1
    /// A challenge row never outlives its expiry by more than this (class P, ADR-0026: expiry + 2 minutes).
    static let challengeGrace: TimeInterval = 2 * 60

    static let sourceMO = "mo"
    static let statePendingTransfer = "pending_transfer"

    /// Recovery took effect: every verified number goes back into cool-down (usable from `until`, or sooner when a trusted device
    /// confirms it with Face ID), because whoever recovered the account is not yet known to be its owner. Returns how many links changed.
    @discardableResult
    static func coolDownAll(consumerId: UUID, until: Date, on db: any Database) async throws -> Int {
        let links = try await PhoneLinkRecord.query(on: db).filter(\.$consumerId == consumerId).filter(\.$state == "verified").all()
        for link in links {
            link.usableFrom = max(link.usableFrom ?? until, until)
            link.confirmedAt = nil
            try await link.update(on: db)
        }
        return links.count
    }

    /// `SELECT id FROM phone_links WHERE phone_hash = ? ORDER BY id FOR UPDATE`, first thing in every transaction that decides who holds a number
    /// (completing a transfer, Keep, removal, a new text). PostgreSQL runs at READ COMMITTED, so without it a Keep or removal that commits between
    /// a job's read and its write would be overwritten. Always all rows of the number, always in id order: one lock order, no deadlock. A statement
    /// that runs after the lock is granted sees the committed rows, so callers re-read **after** calling this. SQLite serializes writers.
    static func lockNumber(phoneHash: String, on db: any Database) async throws {
        guard let sql = db as? any SQLDatabase else { throw APIError.internalError }
        _ = try await sql.select().column("id").from(PhoneLinkRecord.schema).where("phone_hash", .equal, phoneHash).orderBy("id").for(.update).all()
    }

    private func nonceHash(linkId: UUID, nonce: String) -> String { ctx.hasher.hmacHex("phone-mo", "\(linkId.uuidString.lowercased())\n\(nonce)") }

    // MARK: Begin and status (device-signed, trusted device)

    func begin(principal: ConsumerPrincipal, request: PhoneLinkMOBeginRequest) async throws -> PhoneLinkMOBeginResponse {
        // A trusted device only (not one enrolled in the last day, not an App Clip): the nonce is a secret shown on its screen.
        try await DeviceTrust.require(principal, db: db, now: ctx.now)
        let limits = ctx.config.rateLimits
        guard PhoneRegions.isAllowed(request.phone, regions: ctx.config.phoneLinkAllowedCountries) else {
            _ = try? await AuditService(db: db, ctx: ctx).record("phone_link.destination_refused", outcome: .denied, principal: principal,
                                                                metadata: ["prefix": PhoneRegions.budgetPrefix(of: request.phone, digits: 2)])
            throw APIError.validation("We can't link numbers from that country yet.", details: ["phone": "countryNotSupported"])
        }
        guard let sendTo = ctx.config.phoneLinkNumber else { throw APIError.unavailable("Phone linking isn't available right now.") }
        if let deviceId = principal.deviceId, await ctx.integrity.assessSensitiveRequest(deviceId: deviceId, purpose: "phone_link") == .failed {
            throw APIError(.forbidden, .forbidden, "This device could not be verified.")
        }
        let phoneHash = ctx.hasher.phoneHash(request.phone)
        try await ctx.limiter.enforce("phonelink-consumer", key: principal.consumerId.description, rule: limits.phoneLinkStartPerConsumer)
        try await ctx.limiter.enforce("phonelink-phone", key: phoneHash, rule: limits.phoneLinkStartPerPhone)
        // One number per account. The answer never depends on what other accounts or the number's opt-out state are (no enumeration).
        let ownOther = try await PhoneLinkRecord.query(on: db).filter(\.$consumerId == principal.consumerId.uuid)
            .filter(\.$state ~~ ["verified", Self.statePendingTransfer]).filter(\.$phoneHash != phoneHash).count()
        guard ownOther < Self.maxLinkedNumbersPerAccount else { throw APIError.conflict("Remove your current number before linking another.") }
        let now = ctx.now
        let id = UUID()
        let nonce = PhoneLinkMO.generateNonce()
        let challenge = PhoneLinkMOChallengeRecord()
        challenge.id = id
        challenge.consumerId = principal.consumerId.uuid
        challenge.deviceId = principal.deviceId?.uuid
        challenge.nonceHash = nonceHash(linkId: id, nonce: nonce)
        challenge.phoneHash = phoneHash
        challenge.phoneCiphertext = try ctx.cipher.seal(request.phone.e164, context: "phone_link_mo_challenges.phone", rowId: id)
        challenge.phoneMasked = request.phone.masked
        challenge.phoneLast4 = String(request.phone.e164.suffix(4))
        challenge.createdAt = now
        challenge.expiresAt = now.addingTimeInterval(PhoneLinkMO.ttl)
        try await db.transaction { tx in
            // Only the newest begin per (account, number) is live.
            try await PhoneLinkMOChallengeRecord.query(on: tx).filter(\.$consumerId == principal.consumerId.uuid).filter(\.$phoneHash == phoneHash).delete()
            try await challenge.create(on: tx)
            _ = try await AuditService(db: tx, ctx: ctx).record("phone_link.mo_begun", principal: principal, subjectType: "phone_link",
                                                               subjectId: id.uuidString.lowercased(), metadata: ["phone": request.phone.masked])
        }
        return PhoneLinkMOBeginResponse(phoneLinkId: PhoneLinkID(id), nonce: nonce, sendTo: sendTo.e164, expiresAt: challenge.expiresAt)
    }

    func status(principal: ConsumerPrincipal, id: PhoneLinkID) async throws -> PhoneLinkMOStatus {
        try await ctx.limiter.enforce("phonelink-status", key: principal.consumerId.description, rule: ctx.config.rateLimits.phoneLinkStatus)
        let now = ctx.now
        if let link = try await PhoneLinkRecord.query(on: db).filter(\.$id == id.uuid).filter(\.$consumerId == principal.consumerId.uuid)
            .filter(\.$state ~~ ["verified", Self.statePendingTransfer]).first() {
            return PhoneLinkMOStatus(state: .verified, link: dto(link, now: now))
        }
        if let challenge = try await PhoneLinkMOChallengeRecord.query(on: db).filter(\.$id == id.uuid).filter(\.$consumerId == principal.consumerId.uuid).first(),
           challenge.expiresAt > now {
            return PhoneLinkMOStatus(state: .pending)
        }
        // Unknown, someone else's, used up and expired all read the same.
        return PhoneLinkMOStatus(state: .expired)
    }

    func dto(_ link: PhoneLinkRecord, now: Date) -> PhoneLink {
        PhoneLink(id: PhoneLinkID(link.id!), maskedPhone: link.phoneMasked, verifiedAt: link.verifiedAt ?? link.createdAt,
                  usableFrom: link.usableFrom.flatMap { $0 > now ? $0 : nil }, assurance: link.source == Self.sourceMO ? PhoneLinkMO.assuranceLabel : nil)
    }

    // MARK: Inbound (the gateway calls this inside its transaction, before the menu engine)

    /// Work that must run only after the gateway's transaction committed (pushes reach the network; a rolled-back text must not announce anything).
    final class AfterCommit: @unchecked Sendable {
        private let lock = NSLock()
        private var actions: [@Sendable () async -> Void] = []
        func add(_ action: @escaping @Sendable () async -> Void) { lock.lock(); actions.append(action); lock.unlock() }
        func run() async {
            let pending = take()
            for action in pending { await action() }
        }
        private func take() -> [@Sendable () async -> Void] {
            lock.lock(); defer { lock.unlock() }
            let pending = actions
            actions = []
            return pending
        }
    }

    enum InboundHandling: Equatable {
        /// An ordinary message: the menu engine handles it.
        case ordinary
        /// A link text or UNLINK: fully handled here. Nothing else may see the message (a nonce never reaches a business or a menu).
        case handled
    }

    /// True when `sms` is a link text (it carries a nonce), so the caller can rate-limit it before opening a transaction.
    static func isLinkMessage(_ sms: InboundSMS) -> Bool {
        GatewayKeyword.classify(sms.text) != .unlink && PhoneLinkMO.extractNonce(from: sms.text) != nil
    }

    /// True for `UNLINK`. It has its own, generous bucket: a flood of forged link texts must never block the real owner's safety valve (F-4).
    static func isUnlink(_ sms: InboundSMS) -> Bool { GatewayKeyword.classify(sms.text) == .unlink }

    func handleInbound(_ sms: InboundSMS, on tx: any Database, afterCommit: AfterCommit) async throws -> InboundHandling {
        if GatewayKeyword.classify(sms.text) == .unlink {
            try await unlink(number: sms.from, indicator: sms.senderIndicator, on: tx)
            return .handled
        }
        guard let nonce = PhoneLinkMO.extractNonce(from: sms.text) else { return .ordinary }
        let now = ctx.now
        let phoneHash = ctx.hasher.phoneHash(sms.from)
        // Only challenges for the number the text came from are candidates: a nonce sent from any other number matches nothing.
        let candidates = try await PhoneLinkMOChallengeRecord.query(on: tx).filter(\.$phoneHash == phoneHash).limit(8).all()
        let match = candidates.first { ConstantTime.equals(nonceHash(linkId: $0.id!, nonce: nonce), $0.nonceHash) }
        guard let challenge = match else {
            // No answer, no reply and no business ever sees the text: a wrong, reused, late or misdirected nonce looks like nothing (ST-PH-07).
            if !candidates.isEmpty { try await audit("phone_link.mo_refused", reason: "nonce", number: sms.from, on: tx) }
            return .handled
        }
        // Whatever happens next, the challenge is spent: one try per begin.
        try await challenge.delete(on: tx)
        guard challenge.expiresAt > now else {
            try await audit("phone_link.mo_refused", reason: "expired", number: sms.from, consumer: challenge.consumerId, on: tx)
            return .handled
        }
        guard senderAccepted(sms.senderIndicator) else {
            try await audit("phone_link.mo_refused", reason: "sender_indicator", number: sms.from, consumer: challenge.consumerId, on: tx)
            ctx.logger.warning("phone link text refused by the sender check", metadata: ["indicator": "\(sms.senderIndicator.rawValue)"])
            return .handled
        }
        if let context = try await SMSContextRecord.query(on: tx).filter(\.$phoneHash == phoneHash).first(), context.optedOut {
            try await audit("phone_link.mo_refused", reason: "opted_out", number: sms.from, consumer: challenge.consumerId, on: tx)
            return .handled
        }
        // The cap limits *new* links of a number. The current holder's own text (resume after an UNLINK, or "already linked") creates no row, so it
        // never meets the cap: rows induced by someone else (a waiting transfer, a forged UNLINK in between) must not lock the holder out (R-8).
        let holderTexted = try await PhoneLinkRecord.query(on: tx).filter(\.$verifiedPhoneHash == phoneHash).filter(\.$state == "verified")
            .filter(\.$consumerId == challenge.consumerId).first() != nil
        let withinCap = holderTexted ? true : try await churnAllows(phoneHash: phoneHash, on: tx)
        guard withinCap else {
            try await audit("phone_link.mo_refused", reason: "churn", number: sms.from, consumer: challenge.consumerId, on: tx)
            ctx.logger.warning("phone link churn limit reached", metadata: ["phone": "\(sms.from.masked)"])
            return .handled
        }
        guard let device = try await challenge.deviceId.asyncFlatMap({ try await DeviceRecord.find($0, on: tx) }), device.revokedAt == nil,
              device.consumerId == challenge.consumerId, device.isTrusted(at: now),
              let phone = PhoneNumber(try ctx.cipher.openString(challenge.phoneCiphertext, context: "phone_link_mo_challenges.phone", rowId: challenge.id!)),
              phone == sms.from
        else {
            try await audit("phone_link.mo_refused", reason: "device", number: sms.from, consumer: challenge.consumerId, on: tx)
            return .handled
        }
        try await bind(challenge: challenge, device: device, phone: phone, now: now, on: tx, afterCommit: afterCommit)
        // SMS-02, for every valid text, before any waiting period ends: states the effect and offers UNLINK and STOP. No code, no link.
        try await OutboundSMS(db: tx, ctx: ctx).enqueue(to: phone, body: GatewayCopy.phoneLinkedNotice)
        return .handled
    }

    private func senderAccepted(_ indicator: InboundSenderIndicator) -> Bool {
        switch indicator {
        case .verified: true
        case .suspectedSpoof, .notProvided: false
        case .unsupported: !ctx.config.phoneLinkRequireSenderIndicator
        }
    }

    private func churnAllows(phoneHash: String, on tx: any Database) async throws -> Bool {
        let now = ctx.now
        let week = try await PhoneLinkRecord.query(on: tx).filter(\.$phoneHash == phoneHash).filter(\.$source == Self.sourceMO)
            .filter(\.$createdAt > now.addingTimeInterval(-7 * 86_400)).count()
        let day = try await PhoneLinkRecord.query(on: tx).filter(\.$phoneHash == phoneHash).filter(\.$source == Self.sourceMO)
            .filter(\.$createdAt > now.addingTimeInterval(-86_400)).count()
        return week < Self.maxLinksPerNumberPerWeek && day < Self.maxLinksPerNumberPerDay
    }

    private func bind(challenge: PhoneLinkMOChallengeRecord, device: DeviceRecord, phone: PhoneNumber, now: Date, on tx: any Database,
                      afterCommit: AfterCommit) async throws {
        let consumerId = ConsumerID(challenge.consumerId)
        let hash = challenge.phoneHash
        try await Self.lockNumber(phoneHash: hash, on: tx)
        let devices = try await DeviceRecord.query(on: tx).filter(\.$consumerId == challenge.consumerId).filter(\.$revokedAt == nil).all()
        let otherTrusted = devices.contains { $0.id != device.id && $0.isTrusted(at: now) }
        var usableFrom = now.addingTimeInterval(otherTrusted ? Self.newLinkCoolDown : Self.soleDeviceLinkCoolDown)
        if let locked = device.approvalsLockedUntil { usableFrom = max(usableFrom, locked) }
        let existing = try await PhoneLinkRecord.query(on: tx).filter(\.$verifiedPhoneHash == hash).filter(\.$state == "verified").first()
        let auditService = AuditService(db: tx, ctx: ctx)
        if let existing, existing.consumerId == challenge.consumerId {
            if existing.suspendedAt != nil {
                // The holder's number was paused by an UNLINK text and the holder texted again from the phone: resume it with a fresh waiting period.
                existing.suspendedAt = nil
                existing.usableFrom = max(existing.usableFrom ?? usableFrom, usableFrom)
                existing.confirmedAt = nil
                existing.provedByDeviceId = device.id
                try await existing.update(on: tx)
                _ = try await auditService.record("phone_link.resumed_mo", actor: AuditActor(kind: .consumer, id: consumerId.description), consumerId: consumerId,
                    subjectType: "phone_link", subjectId: existing.id?.uuidString.lowercased(), metadata: ["phone": phone.masked, "cool_down": "true"])
                return
            }
            // Already this account's number: nothing changes.
            _ = try await auditService.record("phone_link.verified_mo", actor: AuditActor(kind: .consumer, id: consumerId.description), consumerId: consumerId,
                subjectType: "phone_link", subjectId: existing.id?.uuidString.lowercased(), metadata: ["phone": phone.masked, "result": "already_linked"])
            return
        }
        let record = try PhoneLinkRecord(consumerId: challenge.consumerId, phone: phone, hasher: ctx.hasher, cipher: ctx.cipher, now: now)
        record.id = challenge.id
        // The row id seeds the encryption context of the ciphertext, so seal again for the final id.
        record.phoneCiphertext = try ctx.cipher.seal(phone.e164, context: "phone_links.phone", rowId: challenge.id!)
        record.verifiedAt = now
        record.usableFrom = usableFrom
        record.source = Self.sourceMO
        record.provedByDeviceId = device.id
        if let existing {
            // No immediate displacement (S1-A2-7): the current owner keeps the number until this request's waiting period ends and they were
            // told in the app and did not keep it. A spoofed or victim-induced text therefore never takes a linked number over at once.
            record.state = Self.statePendingTransfer
            record.verifiedPhoneHash = nil
            try await record.create(on: tx)
            _ = try await auditService.record("phone_link.transfer_requested", actor: AuditActor(kind: .consumer, id: consumerId.description),
                consumerId: consumerId, subjectType: "phone_link", subjectId: record.id?.uuidString.lowercased(),
                metadata: ["phone": phone.masked, "assurance": PhoneLinkMO.assuranceLabel])
            try await SecurityNotices(db: tx, ctx: ctx).store(of: existing.consumerId, except: nil, notice: .phoneTransferRequested,
                                                              subjectId: existing.id?.uuidString.lowercased())
            let (db, ctx, owner) = (self.db, self.ctx, existing.consumerId)
            afterCommit.add { await SecurityNotices(db: db, ctx: ctx).push(to: owner, except: nil, notice: .phoneTransferRequested) }
        } else {
            record.state = "verified"
            record.verifiedPhoneHash = hash
            try await record.create(on: tx)
            _ = try await auditService.record("phone_link.verified_mo", actor: AuditActor(kind: .consumer, id: consumerId.description), consumerId: consumerId,
                subjectType: "phone_link", subjectId: record.id?.uuidString.lowercased(),
                metadata: ["phone": phone.masked, "assurance": PhoneLinkMO.assuranceLabel, "cool_down": "true"])
        }
        // The account's other devices are told; the proving device already knows.
        try await SecurityNotices(db: tx, ctx: ctx).store(of: challenge.consumerId, except: device.id, notice: .newPhone, subjectId: record.id?.uuidString.lowercased())
        let (db, ctx, consumer, deviceId) = (self.db, self.ctx, challenge.consumerId, device.id)
        afterCommit.add { await SecurityNotices(db: db, ctx: ctx).push(to: consumer, except: deviceId, notice: .newPhone) }
    }

    // MARK: UNLINK

    /// `UNLINK` from a number (ADR-0027 section 1.5, rev 4). It **pauses** every link of the number and tells each account in the app, and replies
    /// SMS-03. It never releases the number: the link stays bound to its holder until the holder removes it in the app (a trusted device) or a
    /// transfer completes (section 1.3). So a forged UNLINK, which can be sent without being the number's owner, can only stop routing (fail-safe).
    /// It cannot open a dormant owner's number for a victim-induced text to bind fresh, which is how it used to get around section 1.3 (F-4).
    /// A positive spoof indicator is refused without an answer; `unsupported` and `notProvided` still work, because the real owner's safety valve
    /// must keep working with the shipped adapters. Waiting claims on the number (`pending_transfer` rows) are **left alone** (R-8): a forged UNLINK
    /// could otherwise cancel a genuine requester's claim again and again, and every retry costs that person a slot of the per-number link cap. The
    /// holder already has Keep, and a claim still completes only after the holder's trusted device showed the notice.
    func unlink(number: PhoneNumber, indicator: InboundSenderIndicator = .unsupported, on tx: any Database) async throws {
        let hash = ctx.hasher.phoneHash(number)
        guard indicator != .suspectedSpoof else {
            try await audit("phone_link.unlink_refused", reason: "sender_indicator", number: number, on: tx)
            return
        }
        try await Self.lockNumber(phoneHash: hash, on: tx)
        let now = ctx.now
        let links = try await PhoneLinkRecord.query(on: tx).filter(\.$phoneHash == hash).filter(\.$state == "verified").all()
        var paused = 0
        for link in links {
            guard link.suspendedAt == nil else { continue }
            link.suspendedAt = now
            try await link.update(on: tx)
            paused += 1
            try await SecurityNotices(db: tx, ctx: ctx).store(of: link.consumerId, except: nil, notice: .phoneUnlinked, subjectId: link.id?.uuidString.lowercased())
            _ = try await AuditService(db: tx, ctx: ctx).record("phone_link.suspended_by_text", actor: AuditActor(kind: .gateway, id: number.masked),
                consumerId: ConsumerID(link.consumerId), subjectType: "phone_link", subjectId: link.id?.uuidString.lowercased(), metadata: ["phone": number.masked])
        }
        try await PhoneLinkMOChallengeRecord.query(on: tx).filter(\.$phoneHash == hash).delete()
        try await SMSContextRecord.query(on: tx).filter(\.$phoneHash == hash).set(\.$consumerId, to: nil).update()
        if links.isEmpty { _ = try await AuditService(db: tx, ctx: ctx).record("phone_link.unlink_no_link", actor: AuditActor(kind: .gateway, id: number.masked), metadata: ["phone": number.masked]) }
        try await OutboundSMS(db: tx, ctx: ctx).enqueue(to: number, body: GatewayCopy.unlinkDone)
        for _ in 0..<paused { ctx.logger.warning("phone number paused by an UNLINK text", metadata: ["phone": "\(number.masked)"]) }
    }

    private func audit(_ action: String, reason: String, number: PhoneNumber, consumer: UUID? = nil, on tx: any Database) async throws {
        _ = try await AuditService(db: tx, ctx: ctx).record(action, outcome: .denied, actor: AuditActor(kind: .gateway, id: number.masked),
            consumerId: consumer.map { ConsumerID($0) }, subjectType: "phone_link", metadata: ["reason": reason, "phone": number.masked])
    }

    // MARK: Pending transfers

    /// The current owner refuses a pending transfer of their number ("Keep my number"). Any live app device of the holder may do it, a new phone
    /// in cool-down included: it only preserves the status quo (R-1). The number's rows are locked first and re-read, so a transfer that is
    /// completing at the same moment either finishes before this call (then the link is gone: 404) or sees the Keep (R-2).
    func keep(principal: ConsumerPrincipal, id: PhoneLinkID) async throws {
        try await DeviceTrust.requireActiveApp(principal, db: db, now: ctx.now)
        guard let probe = try await PhoneLinkRecord.query(on: db).filter(\.$id == id.uuid).filter(\.$consumerId == principal.consumerId.uuid)
            .filter(\.$state == "verified").first() else { throw APIError.notFound }
        try await db.transaction { tx in
            try await Self.lockNumber(phoneHash: probe.phoneHash, on: tx)
            guard let link = try await PhoneLinkRecord.query(on: tx).filter(\.$id == id.uuid).filter(\.$consumerId == principal.consumerId.uuid)
                .filter(\.$state == "verified").first() else { throw APIError.notFound }
            let pending = try await PhoneLinkRecord.query(on: tx).filter(\.$phoneHash == link.phoneHash).filter(\.$state == Self.statePendingTransfer).all()
            for other in pending {
                other.state = "revoked"
                try await other.update(on: tx)
            }
            _ = try await AuditService(db: tx, ctx: ctx).record("phone_link.transfer_refused", principal: principal, subjectType: "phone_link",
                                                               subjectId: id.description, metadata: ["pending": String(pending.count)])
        }
    }

    /// Moves a number to the account that asked for it. Run by the `minute` job. ADR-0027 section 1.3 (rev 3): the transfer completes only when
    /// all of these hold, otherwise it stays `pending_transfer` and the current holder keeps routing:
    /// 1. the request's waiting period ended;
    /// 2. the **current holder's** app **showed** the in-app `phoneTransferRequested` notice written for that holder's link (`security_notices
    ///    .fetched_at`, set by `POST /v1/security-notices/{id}/seen`, never by listing; a dormant owner never loses a number);
    /// 3. the holder did not choose "Keep my number" (that revokes the pending row, see `keep`);
    /// 4. the holder is still the account that was notified. If the holder changed, the new holder gets a fresh notice and a fresh waiting period.
    ///    The same when the only notice is older than the app's list window, because the app can no longer show it (R-4);
    /// 5. the requester's **account** is active and the **device that proved the link** is still an active app device (R-3).
    /// The losing account is told in the app when the number moves. Everything for one number runs under that number's row locks and re-reads the
    /// rows after taking them, so it cannot overwrite a concurrent Keep, removal or UNLINK (R-2).
    @discardableResult
    func completeTransfers() async throws -> Int {
        let now = ctx.now
        let due = try await PhoneLinkRecord.query(on: db).filter(\.$state == Self.statePendingTransfer).filter(\.$usableFrom <= now).all()
        var moved = 0
        for candidate in due {
            let afterCommit = AfterCommit()
            let completed: Bool = try await db.transaction { tx in
                try await Self.lockNumber(phoneHash: candidate.phoneHash, on: tx)
                // The row may have been kept, revoked, extended or completed since it was read.
                guard let pending = try await PhoneLinkRecord.query(on: tx).filter(\.$id == candidate.id!).filter(\.$state == Self.statePendingTransfer).first(),
                      (pending.usableFrom ?? now) <= now else { return false }
                let audits = AuditService(db: tx, ctx: ctx)
                guard try await requesterCanReceive(pending, on: tx) else {
                    pending.state = "revoked"
                    try await pending.update(on: tx)
                    _ = try await audits.record("phone_link.transfer_dropped", actor: AuditActor(kind: .system), consumerId: ConsumerID(pending.consumerId),
                        subjectType: "phone_link", subjectId: pending.id?.uuidString.lowercased(), metadata: ["reason": "requester_inactive"])
                    return false
                }
                let holders = try await PhoneLinkRecord.query(on: tx).filter(\.$verifiedPhoneHash == pending.phoneHash).filter(\.$state == "verified").all()
                for holder in holders where holder.consumerId != pending.consumerId {
                    let subject = holder.id?.uuidString.lowercased()
                    let notices = try await SecurityNoticeRecord.query(on: tx).filter(\.$consumerId == holder.consumerId)
                        .filter(\.$kind == SecurityNotices.Notice.phoneTransferRequested.kind.rawValue).filter(\.$subjectId == subject)
                        .filter(\.$createdAt >= pending.createdAt).all()
                    let noneSeen = !notices.contains { $0.fetchedAt != nil }
                    let newest = notices.map(\.createdAt).max()
                    let outOfWindow = noneSeen && (newest.map { $0 < now.addingTimeInterval(-SecurityNotices.listWindow) } ?? false)
                    if notices.isEmpty || outOfWindow {
                        // The account that was notified is not the holder any more, the notice is gone, or it is too old for the app to show:
                        // restart with a fresh notice and wait.
                        try await SecurityNotices(db: tx, ctx: ctx).store(of: holder.consumerId, except: nil, notice: .phoneTransferRequested, subjectId: subject)
                        pending.usableFrom = max(pending.usableFrom ?? now, now.addingTimeInterval(Self.newLinkCoolDown))
                        try await pending.update(on: tx)
                        _ = try await audits.record("phone_link.transfer_renotified", actor: AuditActor(kind: .system), consumerId: ConsumerID(holder.consumerId),
                            subjectType: "phone_link", subjectId: pending.id?.uuidString.lowercased(),
                            metadata: ["reason": notices.isEmpty ? "holder_changed" : "notice_expired"])
                        let (db, ctx, owner) = (self.db, self.ctx, holder.consumerId)
                        afterCommit.add { await SecurityNotices(db: db, ctx: ctx).push(to: owner, except: nil, notice: .phoneTransferRequested) }
                        return false
                    }
                    guard !noneSeen else { return false }
                }
                for old in holders where old.consumerId != pending.consumerId {
                    old.state = "revoked"
                    old.verifiedPhoneHash = nil
                    try await old.update(on: tx)
                    _ = try await audits.record("phone_link.revoked", actor: AuditActor(kind: .system), consumerId: ConsumerID(old.consumerId),
                        subjectType: "phone_link", subjectId: old.id?.uuidString.lowercased(), metadata: ["reason": "transferred_after_waiting_period"])
                    try await SecurityNotices(db: tx, ctx: ctx).store(of: old.consumerId, except: nil, notice: .phoneTransferred, subjectId: old.id?.uuidString.lowercased())
                    let (db, ctx, loser) = (self.db, self.ctx, old.consumerId)
                    afterCommit.add { await SecurityNotices(db: db, ctx: ctx).push(to: loser, except: nil, notice: .phoneTransferred) }
                }
                pending.state = "verified"
                pending.verifiedPhoneHash = pending.phoneHash
                pending.usableFrom = nil
                try await pending.update(on: tx)
                try await SMSContextRecord.query(on: tx).filter(\.$phoneHash == pending.phoneHash).set(\.$consumerId, to: nil).update()
                return true
            }
            await afterCommit.run()
            if completed { moved += 1 }
        }
        return moved
    }

    /// R-3: the requester's account is active and the device that proved the link is still a live app device. A row made before the proving
    /// device was recorded falls back to "any live app device of the account".
    private func requesterCanReceive(_ pending: PhoneLinkRecord, on tx: any Database) async throws -> Bool {
        let now = ctx.now
        guard let account = try await ConsumerRecord.find(pending.consumerId, on: tx), account.status == "active" else { return false }
        if let proving = pending.provedByDeviceId {
            guard let device = try await DeviceRecord.find(proving, on: tx) else { return false }
            return device.consumerId == pending.consumerId && device.kind == .app && device.revokedAt == nil && !device.isExpired(at: now)
        }
        let devices = try await DeviceRecord.query(on: tx).filter(\.$consumerId == pending.consumerId).filter(\.$revokedAt == nil).all()
        return devices.contains { $0.kind == .app && !$0.isExpired(at: now) }
    }

    // MARK: Sweep (class P: the challenge row never outlives expiry + 2 minutes)

    @discardableResult
    static func purgeChallenges(on db: any Database, now: Date) async throws -> Int {
        let cutoff = now.addingTimeInterval(-challengeGrace)
        let count = try await PhoneLinkMOChallengeRecord.query(on: db).filter(\.$expiresAt < cutoff).count()
        if count > 0 { try await PhoneLinkMOChallengeRecord.query(on: db).filter(\.$expiresAt < cutoff).delete() }
        return count
    }

    // MARK: Waiting period

    /// Makes a linked phone usable now. Only for a link made by an older build (an SMS-code link): a number linked by text waits out its period,
    /// because the device that would confirm it is the requester's own and adds no protection for the number's real owner (ADR-0027 §2).
    func confirmLink(principal: ConsumerPrincipal, id: PhoneLinkID, proof: ConfirmationProof) async throws -> PhoneLink {
        try await ctx.limiter.enforce("phone-confirm", key: principal.consumerId.description, rule: .perHour(30, burst: 10))
        let now = ctx.now
        guard let deviceId = principal.deviceId, proof.deviceId == deviceId,
              let device = try await DeviceRecord.find(deviceId.uuid, on: db), device.consumerId == principal.consumerId.uuid, device.isTrusted(at: now),
              let link = try await PhoneLinkRecord.query(on: db).filter(\.$id == id.uuid).filter(\.$consumerId == principal.consumerId.uuid)
                  .filter(\.$state == "verified").first() else { throw APIError.notFound }
        if link.source == Self.sourceMO {
            throw APIError(.forbidden, .forbidden, "A number linked by text becomes usable after its waiting period.")
        }
        if link.usableFrom != nil {
            guard let purpose = proof.requiredKeyPurpose,
                  let keyRecord = try await DeviceKeyRecord.query(on: db).filter(\.$deviceId == deviceId.uuid).filter(\.$purpose == purpose.rawValue).first(),
                  let publicKey = try? DevicePublicKey(base64URL: keyRecord.publicKey) else {
                throw APIError(.forbidden, .insufficientAssurance, "Confirm with Face ID.")
            }
            do {
                try await proof.verify(subject: .phoneLink, subjectId: id.description, publicKey: publicKey, now: now, replayGuard: DatabaseReplayGuard(db: db))
            } catch ConfirmationProof.Failure.replayed {
                throw APIError(.unauthorized, .replayDetected, "This confirmation was already used.")
            } catch ConfirmationProof.Failure.assuranceTooLow {
                throw APIError(.forbidden, .insufficientAssurance, "Confirm with Face ID.")
            } catch {
                throw APIError.signatureInvalid
            }
            link.usableFrom = nil
            link.confirmedAt = now
            try await db.transaction { tx in
                try await link.update(on: tx)
                _ = try await AuditService(db: tx, ctx: ctx).record("phone_link.confirmed", principal: principal, subjectType: "phone_link",
                                                                   subjectId: id.description, metadata: ["assurance": proof.assurance.rawValue])
            }
            // The thread was left unlinked while the link cooled down: attach it now.
            if let phone = PhoneNumber(try ctx.cipher.openString(link.phoneCiphertext, context: "phone_links.phone", rowId: link.id!)) {
                try await GatewayService(db: db, ctx: ctx).accountLinked(consumerId: principal.consumerId, phone: phone)
            }
        }
        return dto(link, now: now)
    }
}

private extension Optional {
    func asyncFlatMap<T>(_ transform: (Wrapped) async throws -> T?) async rethrows -> T? {
        switch self {
        case .some(let value): try await transform(value)
        case .none: nil
        }
    }
}
