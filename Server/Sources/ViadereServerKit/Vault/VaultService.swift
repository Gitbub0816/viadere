import Crypto
import Fluent
import Foundation
import ViadereCore

/// Credential-vault sync. The server is a **dumb, verifying store**: it keeps ciphertext, signed public manifests, public keys and HPKE
/// envelopes, and it never learns (and never logs) item contents, device names or any key that opens them.
///
/// What it does check, so that an attacker who has the account (a stolen session or a freshly enrolled device) but no vault key still
/// cannot change a vault:
/// - every write is a **compare-and-swap** on the vault version carrying a signed manifest, verified with the same `VaultChainVerifier`
///   the clients use (hash chain, signer is a member of the previous manifest, rotation and revision rules);
/// - the calling **account device must be bound** to the vault member that signed (binding happens only at creation, through a join an
///   existing vault device approved, or a recovery-key restore: never because the account says so);
/// - blobs and envelopes must hash to what the signed manifest commits to.
struct VaultService {
    let db: any Database
    let ctx: ServerContext

    private var settings: VaultSyncSettings { ctx.config.vaultSync }

    /// The release gate: every vault route answers `404` while `VAULT_SYNC_ENABLED` is off.
    static func requireEnabled(_ ctx: ServerContext) throws {
        guard ctx.config.vaultSync.enabled else { throw APIError.notFound }
    }

    // MARK: Lookup

    private func vault(of consumer: UUID, on database: (any Database)? = nil) async throws -> VaultRecord? {
        try await VaultRecord.query(on: database ?? db).filter(\.$consumerId == consumer).first()
    }

    private func boundMember(_ principal: ConsumerPrincipal, in vault: VaultRecord, on database: (any Database)? = nil) async throws -> VaultMemberRecord? {
        guard let device = principal.deviceId, let vaultId = vault.id else { return nil }
        return try await VaultMemberRecord.query(on: database ?? db).filter(\.$vaultId == vaultId).filter(\.$accountDeviceId == device.uuid)
            .filter(\.$removedAt == nil).first()
    }

    private func requireBound(_ principal: ConsumerPrincipal) async throws -> (VaultRecord, VaultMemberRecord) {
        guard let vault = try await vault(of: principal.consumerId.uuid) else { throw APIError.notFound }
        guard let member = try await boundMember(principal, in: vault) else {
            throw APIError(.forbidden, .forbidden, "This device is not part of the synced vault. Approve it from a device that is, or restore with the recovery key.")
        }
        return (vault, member)
    }

    private func throttle(_ name: String, _ principal: ConsumerPrincipal, rule: RateRule) async throws {
        try await ctx.limiter.enforce(name, key: principal.consumerId.description, rule: rule)
    }

    static func hex(_ data: Data) -> String { Hex.encode(data) }

    private func reject(_ error: VaultError) -> APIError {
        // The reason is a short, fixed identifier; it never echoes request content.
        let reason: String
        switch error {
        case .rollback: reason = "rollback"
        case .fork: reason = "fork"
        case .badSignature: reason = "bad_signature"
        case .unknownSigner: reason = "unknown_signer"
        case .invalidChain: reason = "invalid_chain"
        case .invalidManifest: reason = "invalid_manifest"
        case .limitExceeded: reason = "limit_exceeded"
        case .unsupportedVersion: reason = "unsupported_version"
        default: reason = "rejected"
        }
        return APIError.validation("The vault update was rejected.", details: ["reason": reason])
    }

    private func conflict(currentVersion: Int) -> APIError {
        APIError(.conflict, .conflict, "The vault changed. Fetch the latest version and try again.", details: ["currentVersion": String(currentVersion)])
    }

    // MARK: Status

    func status(_ principal: ConsumerPrincipal) async throws -> VaultStatus {
        try await throttle("vault-read", principal, rule: settings.readRate)
        guard let vault = try await vault(of: principal.consumerId.uuid), let vaultId = vault.id else { return VaultStatus(exists: false) }
        let members = try await VaultMemberRecord.query(on: db).filter(\.$vaultId == vaultId).filter(\.$removedAt == nil).all()
        let bound = try await boundMember(principal, in: vault)
        return VaultStatus(exists: true, vaultId: vaultId, version: UInt64(vault.version), epoch: UInt64(vault.epoch), bound: bound != nil,
                           memberId: bound?.memberId, deviceCount: members.filter { $0.role == "device" }.count,
                           recoveryConfigured: members.contains { $0.role == "recovery" })
    }

    // MARK: Write

    func put(_ principal: ConsumerPrincipal, _ request: VaultPutRequest) async throws -> VaultStatus {
        let consumer = principal.consumerId.uuid
        try await throttle("vault-write", principal, rule: settings.writeRate)
        guard let signed = request.manifest.signed, signed.manifestBytes.count <= VaultFormat.maxManifestBytes, signed.signature.count == 64 else {
            throw APIError.validation("The manifest is malformed.")
        }
        var newBlobs: [UUID: Data] = [:]
        for entry in request.blobs {
            guard newBlobs[entry.itemId] == nil, let blob = Base64URL.decode(entry.blob), !blob.isEmpty, blob.count <= VaultFormat.maxItemBlobBytes else {
                throw APIError.validation("A blob is malformed.")
            }
            newBlobs[entry.itemId] = blob
        }
        var newEnvelopes: [String: Data] = [:]
        for entry in request.envelopes {
            guard newEnvelopes[entry.memberId] == nil, let envelope = Base64URL.decode(entry.envelope), envelope.count == VaultFormat.envelopeLength else {
                throw APIError.validation("An envelope is malformed.")
            }
            newEnvelopes[entry.memberId] = envelope
        }
        guard request.blobs.count <= settings.maxItems, request.envelopes.count <= settings.maxDevices + 1 else { throw APIError.validation("Too many items.") }

        let existing = try await vault(of: consumer)
        let verified: VerifiedManifest
        var previous: VerifiedManifest?
        let genesis = request.expectedVersion == 0
        var recoveryRestore = false
        if genesis {
            guard existing == nil else { throw conflict(currentVersion: existing?.version ?? 0) }
            // Creating a vault takes a trusted device: a device enrolled minutes ago with a stolen passkey cannot claim the account's vault.
            try await DeviceTrust.require(principal, db: db, now: ctx.now)
            do { verified = try VaultChainVerifier.verifyGenesis(signed) } catch let error as VaultError { throw reject(error) }
            guard request.bindMemberId == verified.manifest.signerId, request.joinId == nil else { throw APIError.validation("The creating device must bind to itself.") }
        } else {
            guard let existing, existing.id != nil else { throw APIError.notFound }
            guard existing.version == Int(clamping: request.expectedVersion) else { throw conflict(currentVersion: existing.version) }
            guard let latest = try await VaultManifestRecord.query(on: db).filter(\.$vaultId == existing.id!).filter(\.$version == existing.version).first(),
                  let stored = VaultManifestDTO(manifest: latest.manifest, signature: latest.signature, recoveryAuthorization: latest.authorization).signed,
                  let restored = try? VaultChainVerifier.restore(stored) else { throw APIError.internalError }
            previous = restored
            do { verified = try VaultChainVerifier.verify(signed, after: restored) } catch let error as VaultError { throw reject(error) }
            recoveryRestore = signed.recoveryAuthorization != nil
            if recoveryRestore {
                // Restoring with the recovery key: a trusted device that is not yet a member signs with its own new key (authorized by the
                // recovery member, which `verify` checked) and binds itself.
                try await DeviceTrust.require(principal, db: db, now: ctx.now)
                try await ctx.limiter.enforce("vault-recovery-put", key: consumer.uuidString, rule: settings.recoveryRate)
                guard request.bindMemberId == verified.manifest.signerId, request.joinId == nil else { throw APIError.validation("The restoring device must bind to itself.") }
            } else {
                guard let bound = try await boundMember(principal, in: existing), bound.memberId == verified.manifest.signerId else {
                    throw APIError(.forbidden, .forbidden, "This device did not sign that update.")
                }
            }
        }

        let m = verified.manifest
        let vaultId = m.vaultId
        if !genesis { guard existing?.id == vaultId else { throw APIError.validation("The manifest belongs to another vault.") } }
        guard m.items.count <= settings.maxItems, m.devices.count <= settings.maxDevices else { throw APIError.validation("The vault is too large.") }

        // Blobs: every listed item is either uploaded now or already stored, byte-for-byte what the manifest commits to.
        let storedBlobs = genesis ? [] : try await VaultBlobRecord.query(on: db).filter(\.$vaultId == vaultId).all()
        let storedById = Dictionary(uniqueKeysWithValues: storedBlobs.map { ($0.itemId, $0) })
        let listed = Set(m.items.map(\.itemId))
        guard Set(newBlobs.keys).isSubset(of: listed) else { throw APIError.validation("A blob is not listed in the manifest.") }
        for ref in m.items {
            if let blob = newBlobs[ref.itemId] {
                guard Data(SHA256.hash(data: blob)) == ref.blobHash else { throw APIError.validation("A blob does not match the manifest.") }
            } else {
                guard let stored = storedById[ref.itemId], stored.revision == Int(clamping: ref.revision), stored.blobHash == Self.hex(ref.blobHash) else {
                    throw APIError.validation("A blob listed in the manifest is missing.")
                }
            }
        }

        // Envelopes: required exactly for members that are new or whose envelope changed.
        for member in m.members {
            let prior = previous?.manifest.member(member.id)
            if prior == nil || prior?.envelopeHash != member.envelopeHash {
                guard let envelope = newEnvelopes[member.id], VaultEnvelope.hash(envelope) == member.envelopeHash else {
                    throw APIError.validation("An envelope is missing or does not match the manifest.")
                }
            } else {
                guard newEnvelopes[member.id] == nil else { throw APIError.validation("An envelope was not expected.") }
            }
        }
        guard Set(newEnvelopes.keys).isSubset(of: Set(m.members.map(\.id))) else { throw APIError.validation("An envelope names no member.") }

        let totalBytes = m.items.reduce(0) { $0 + (newBlobs[$1.itemId]?.count ?? storedById[$1.itemId]?.blob.count ?? 0) } + signed.manifestBytes.count
        guard totalBytes <= settings.maxVaultBytes else { throw APIError.validation("The vault is too large.") }

        // Membership changes.
        let priorIds = Set(previous?.manifest.members.map(\.id) ?? [])
        let added = m.members.filter { !priorIds.contains($0.id) }
        let removed = (previous?.manifest.members ?? []).filter { member in !m.members.contains { $0.id == member.id } }
        let addedDevices = added.filter { $0.role == .device }
        var join: VaultJoinRecord?
        if let joinId = request.joinId {
            guard !genesis, !recoveryRestore, let approvalText = request.joinApproval, let approval = Base64URL.decode(approvalText), !approval.isEmpty, approval.count <= 2048,
                  let memberId = request.joinMemberId, addedDevices.map(\.id) == [memberId],
                  let record = try await VaultJoinRecord.query(on: db).filter(\.$joinId == joinId).filter(\.$consumerId == consumer).first(),
                  record.vaultId == vaultId, record.expiresAt > ctx.now, record.request != nil, record.approval == nil, record.requesterDeviceId != nil else {
                throw APIError.validation("The join is not valid.")
            }
            // The requesting device must not already act as another member: one account device, one vault member.
            if let requester = record.requesterDeviceId, try await VaultMemberRecord.query(on: db).filter(\.$vaultId == vaultId)
                .filter(\.$accountDeviceId == requester).filter(\.$removedAt == nil).count() > 0 {
                throw APIError.validation("That device is already part of the vault.")
            }
            join = record
        } else if !genesis, !recoveryRestore, !addedDevices.isEmpty {
            throw APIError.validation("A device can only be added through a join.")
        }
        if genesis || recoveryRestore {
            guard addedDevices.map(\.id) == [m.signerId] else { throw APIError.validation("Only the signing device can be added here.") }
        }

        let now = ctx.now
        let hash = Self.hex(verified.hash)
        let blobUploads = newBlobs, envelopeUploads = newEnvelopes, isRestore = recoveryRestore, joinRecord = join
        do {
            try await db.transaction { tx in
                if genesis {
                    do {
                        try await VaultRecord(id: vaultId, consumerId: consumer, version: Int(m.version), epoch: Int(m.epoch), manifestHash: hash, now: now).create(on: tx)
                    } catch where error.isConstraintViolation {
                        throw ConcurrencyConflict()
                    }
                } else {
                    guard try await DB.swap(tx, table: VaultRecord.schema, id: vaultId, column: "version", expected: Int(clamping: request.expectedVersion),
                                            newValue: Int(m.version)) else { throw ConcurrencyConflict() }
                    try await VaultRecord.query(on: tx).filter(\.$id == vaultId).set(\.$epoch, to: Int(m.epoch)).set(\.$manifestHash, to: hash).set(\.$updatedAt, to: now).update()
                }
                do {
                    try await VaultManifestRecord(vaultId: vaultId, version: Int(m.version), manifest: request.manifest.manifest, signature: request.manifest.signature,
                                                  authorization: request.manifest.recoveryAuthorization, hash: hash, now: now).create(on: tx)
                } catch where error.isConstraintViolation {
                    throw ConcurrencyConflict()
                }
                // Blobs.
                for (itemId, blob) in blobUploads {
                    guard let ref = m.items.first(where: { $0.itemId == itemId }) else { continue }
                    if let stored = storedById[itemId] {
                        try await VaultBlobRecord.query(on: tx).filter(\.$id == stored.id!).set(\.$revision, to: Int(clamping: ref.revision))
                            .set(\.$blobHash, to: Self.hex(ref.blobHash)).set(\.$blob, to: blob).set(\.$updatedAt, to: now).update()
                    } else {
                        try await VaultBlobRecord(vaultId: vaultId, itemId: itemId, revision: Int(clamping: ref.revision), blobHash: Self.hex(ref.blobHash), blob: blob, now: now).create(on: tx)
                    }
                }
                for stored in storedBlobs where !listed.contains(stored.itemId) { try await stored.delete(on: tx) }
                // Members.
                let storedMembers = genesis ? [] : try await VaultMemberRecord.query(on: tx).filter(\.$vaultId == vaultId).all()
                for member in m.members {
                    let envelopeHash = Self.hex(member.envelopeHash)
                    if let record = storedMembers.first(where: { $0.memberId == member.id }) {
                        if let envelope = envelopeUploads[member.id] {
                            try await VaultMemberRecord.query(on: tx).filter(\.$id == record.id!).set(\.$envelope, to: envelope).set(\.$envelopeHash, to: envelopeHash).update()
                        }
                    } else {
                        let device = (genesis || isRestore) && member.id == m.signerId ? principal.deviceId?.uuid : joinRecord.flatMap { $0.approvedMemberId == nil && request.joinMemberId == member.id ? $0.requesterDeviceId : nil }
                        try await VaultMemberRecord(vaultId: vaultId, memberId: member.id, role: member.role == .device ? "device" : "recovery",
                                                    signingKey: Base64URL.encode(member.signingKey), envelopeHash: envelopeHash, envelope: envelopeUploads[member.id],
                                                    accountDeviceId: device, addedAt: Date(timeIntervalSince1970: TimeInterval(member.addedAt))).create(on: tx)
                    }
                }
                for gone in removed {
                    try await VaultMemberRecord.query(on: tx).filter(\.$vaultId == vaultId).filter(\.$memberId == gone.id)
                        .set(\.$removedAt, to: now).set(\.$envelope, to: nil).set(\.$accountDeviceId, to: nil).update()
                }
                if let joinRecord, let approval = request.joinApproval.flatMap(Base64URL.decode) {
                    try await VaultJoinRecord.query(on: tx).filter(\.$id == joinRecord.id!).set(\.$approval, to: approval).set(\.$approvedMemberId, to: request.joinMemberId)
                        .set(\.$approvedVersion, to: Int(m.version)).update()
                }
                _ = try await AuditService(db: tx, ctx: ctx).record(genesis ? "vault.created" : "vault.updated", principal: principal, subjectType: "vault",
                                                                     subjectId: vaultId.uuidString.lowercased(),
                                                                     metadata: ["version": String(m.version), "items": String(m.items.count), "devices": String(m.devices.count),
                                                                                "added": String(addedDevices.count), "removed": String(removed.filter { $0.role == .device }.count),
                                                                                "restore": isRestore ? "true" : "false"])
            }
        } catch is ConcurrencyConflict {
            let current = try await vault(of: consumer)?.version ?? 0
            throw conflict(currentVersion: current)
        }

        let notices = SecurityNotices(db: db, ctx: ctx)
        if !addedDevices.isEmpty && !genesis {
            await notices.notifyOtherDevices(of: consumer, except: principal.deviceId?.uuid, notice: .vaultDeviceAdded, subjectId: addedDevices.first?.id)
        }
        if let gone = removed.first(where: { $0.role == .device }) {
            await notices.notifyOtherDevices(of: consumer, except: principal.deviceId?.uuid, notice: .vaultDeviceRemoved, subjectId: gone.id)
        }
        return try await status(principal)
    }

    // MARK: Reads

    func manifests(_ principal: ConsumerPrincipal, after: UInt64, limit: Int) async throws -> VaultManifestsResponse {
        guard let vault = try await vault(of: principal.consumerId.uuid), let vaultId = vault.id else { throw APIError.notFound }
        if try await boundMember(principal, in: vault) != nil {
            try await throttle("vault-read", principal, rule: settings.readRate)
        } else {
            // A trusted device that is not a member (restoring with the recovery key) may read the signed history, which holds only public
            // keys, hashes and sealed labels; it is not enough to read an item or open the vault.
            try await DeviceTrust.require(principal, db: db, now: ctx.now)
            try await ctx.limiter.enforce("vault-history", key: principal.consumerId.description, rule: .perHour(60, burst: 20))
        }
        let rows = try await VaultManifestRecord.query(on: db).filter(\.$vaultId == vaultId).filter(\.$version > Int(clamping: after))
            .sort(\.$version, .ascending).limit(min(max(limit, 1), 100)).all()
        return VaultManifestsResponse(manifests: rows.map { VaultManifestDTO(manifest: $0.manifest, signature: $0.signature, recoveryAuthorization: $0.authorization) },
                                      latestVersion: UInt64(vault.version))
    }

    func blobs(_ principal: ConsumerPrincipal, ids: [UUID]) async throws -> VaultBlobsResponse {
        guard ids.count <= 100 else { throw APIError.validation("Too many items requested.") }
        guard let vault = try await vault(of: principal.consumerId.uuid) else { throw APIError.notFound }
        if try await boundMember(principal, in: vault) != nil {
            try await throttle("vault-read", principal, rule: settings.readRate)
        } else {
            // A trusted device restoring with the recovery key reads the ciphertext it must re-encrypt; ciphertext alone opens nothing.
            try await DeviceTrust.require(principal, db: db, now: ctx.now)
            try await ctx.limiter.enforce("vault-history", key: principal.consumerId.description, rule: .perHour(60, burst: 20))
        }
        let rows = ids.isEmpty ? [] : try await VaultBlobRecord.query(on: db).filter(\.$vaultId == vault.id!).filter(\.$itemId ~~ ids).all()
        return VaultBlobsResponse(blobs: rows.map { VaultBlobDTO(itemId: $0.itemId, blob: Base64URL.encode($0.blob)) })
    }

    func envelope(_ principal: ConsumerPrincipal) async throws -> VaultEnvelopeResponse {
        try await throttle("vault-read", principal, rule: settings.readRate)
        let (_, member) = try await requireBound(principal)
        guard let envelope = member.envelope else { throw APIError.notFound }
        return VaultEnvelopeResponse(memberId: member.memberId, envelope: Base64URL.encode(envelope))
    }

    /// The recovery member's envelope: ciphertext only the recovery key opens. Needs a trusted device and is rate-limited hard; every fetch is audited.
    func recoveryEnvelope(_ principal: ConsumerPrincipal) async throws -> VaultEnvelopeResponse {
        try await DeviceTrust.require(principal, db: db, now: ctx.now)
        try await ctx.limiter.enforce("vault-recovery", key: principal.consumerId.description, rule: settings.recoveryRate)
        guard let vault = try await vault(of: principal.consumerId.uuid), let vaultId = vault.id,
              let member = try await VaultMemberRecord.query(on: db).filter(\.$vaultId == vaultId).filter(\.$role == "recovery").filter(\.$removedAt == nil).first(),
              let envelope = member.envelope else { throw APIError.notFound }
        _ = try await AuditService(db: db, ctx: ctx).record("vault.recovery_envelope_fetched", principal: principal, subjectType: "vault", subjectId: vaultId.uuidString.lowercased())
        return VaultEnvelopeResponse(memberId: member.memberId, envelope: Base64URL.encode(envelope))
    }

    func devices(_ principal: ConsumerPrincipal) async throws -> [VaultDeviceInfo] {
        try await throttle("vault-read", principal, rule: settings.readRate)
        guard let vault = try await vault(of: principal.consumerId.uuid), let vaultId = vault.id else { throw APIError.notFound }
        if try await boundMember(principal, in: vault) == nil { try await DeviceTrust.require(principal, db: db, now: ctx.now) }
        let rows = try await VaultMemberRecord.query(on: db).filter(\.$vaultId == vaultId).filter(\.$removedAt == nil).sort(\.$addedAt, .ascending).all()
        let deviceIds = rows.compactMap(\.accountDeviceId)
        let active = deviceIds.isEmpty ? [] : try await DeviceRecord.query(on: db).filter(\.$id ~~ deviceIds).filter(\.$revokedAt == nil).all().compactMap(\.id)
        return rows.map { VaultDeviceInfo(memberId: $0.memberId, role: $0.role, addedAt: $0.addedAt, accountDeviceId: $0.accountDeviceId,
                                          accountDeviceActive: $0.accountDeviceId.map { active.contains($0) } ?? false, removed: false) }
    }

    // MARK: Removal and deletion

    /// Ends a vault device's server access at once (the manifest still lists it until a device publishes the rotation that removes it).
    func removeDevice(_ principal: ConsumerPrincipal, memberId: String) async throws {
        try await DeviceTrust.require(principal, db: db, now: ctx.now)
        try await throttle("vault-write", principal, rule: settings.writeRate)
        let (vault, own) = try await requireBound(principal)
        guard memberId != own.memberId, let target = try await VaultMemberRecord.query(on: db).filter(\.$vaultId == vault.id!).filter(\.$memberId == memberId)
            .filter(\.$removedAt == nil).first(), target.role == "device" else { throw APIError.notFound }
        let now = ctx.now
        try await db.transaction { tx in
            try await VaultMemberRecord.query(on: tx).filter(\.$id == target.id!).set(\.$removedAt, to: now).set(\.$envelope, to: nil).set(\.$accountDeviceId, to: nil).update()
            _ = try await AuditService(db: tx, ctx: ctx).record("vault.device_removed", principal: principal, subjectType: "vault", subjectId: vault.id!.uuidString.lowercased(),
                                                                 metadata: ["member": memberId])
        }
        await SecurityNotices(db: db, ctx: ctx).notifyOtherDevices(of: principal.consumerId.uuid, except: principal.deviceId?.uuid, notice: .vaultDeviceRemoved, subjectId: memberId)
    }

    /// Turns sync off: erases the vault from the server. Devices keep their local encrypted copies.
    func delete(_ principal: ConsumerPrincipal) async throws {
        try await DeviceTrust.require(principal, db: db, now: ctx.now)
        try await throttle("vault-write", principal, rule: settings.writeRate)
        let (vault, _) = try await requireBound(principal)
        try await db.transaction { tx in
            try await Self.wipe(consumer: principal.consumerId.uuid, on: tx)
            _ = try await AuditService(db: tx, ctx: ctx).record("vault.deleted", principal: principal, subjectType: "vault", subjectId: vault.id!.uuidString.lowercased())
        }
        await SecurityNotices(db: db, ctx: ctx).notifyOtherDevices(of: principal.consumerId.uuid, except: principal.deviceId?.uuid, notice: .vaultDeleted)
    }

    /// Erases every vault row of `consumer` (blobs, manifests, members, joins, the vault). Used by `delete` and by account deletion, which
    /// runs it whether or not sync is enabled.
    static func wipe(consumer: UUID, on database: any Database) async throws {
        guard let vault = try await VaultRecord.query(on: database).filter(\.$consumerId == consumer).first(), let id = vault.id else { return }
        try await VaultJoinRecord.query(on: database).filter(\.$vaultId == id).delete()
        try await VaultMemberRecord.query(on: database).filter(\.$vaultId == id).delete()
        try await VaultBlobRecord.query(on: database).filter(\.$vaultId == id).delete()
        try await VaultManifestRecord.query(on: database).filter(\.$vaultId == id).delete()
        try await VaultRecord.query(on: database).filter(\.$id == id).delete()
    }

    // MARK: Joins

    private static func isValidJoinId(_ id: String) -> Bool {
        Base64URL.isValid(id, minLength: 22, maxLength: 22) && Base64URL.decode(id)?.count == 16
    }

    private func liveJoin(_ joinId: String, consumer: UUID) async throws -> VaultJoinRecord {
        guard Self.isValidJoinId(joinId),
              let record = try await VaultJoinRecord.query(on: db).filter(\.$joinId == joinId).filter(\.$consumerId == consumer).first() else { throw APIError.notFound }
        guard record.expiresAt > ctx.now else { throw APIError.gone("This pairing code has expired.") }
        return record
    }

    private func state(_ record: VaultJoinRecord) -> VaultJoinState {
        VaultJoinState(joinId: record.joinId, expiresAt: record.expiresAt, request: record.request.map { Base64URL.encode($0) },
                       approval: record.approval.map { Base64URL.encode($0) }, approvedMemberId: record.approvedMemberId,
                       approvedVersion: record.approvedVersion.map { UInt64($0) })
    }

    /// An existing vault device opens a join (it generated the pairing secret and shows it to the person).
    func createJoin(_ principal: ConsumerPrincipal, joinId: String) async throws -> VaultJoinState {
        try await throttle("vault-join", principal, rule: settings.joinRate)
        guard Self.isValidJoinId(joinId) else { throw APIError.validation("The pairing identifier is malformed.") }
        let (vault, _) = try await requireBound(principal)
        let consumer = principal.consumerId.uuid
        let now = ctx.now
        try await VaultJoinRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$expiresAt <= now).delete()
        if let existing = try await VaultJoinRecord.query(on: db).filter(\.$joinId == joinId).first() {
            guard existing.consumerId == consumer else { throw APIError.conflict("That pairing identifier is in use.") }
            return state(existing)
        }
        guard try await VaultJoinRecord.query(on: db).filter(\.$consumerId == consumer).count() < settings.maxOpenJoins else {
            throw APIError.conflict("Too many devices are waiting to be added. Finish or cancel one first.")
        }
        let record = VaultJoinRecord(joinId: joinId, consumerId: consumer, vaultId: vault.id!, now: now, expiresAt: now.addingTimeInterval(settings.joinLifetime))
        do { try await record.create(on: db) } catch where error.isConstraintViolation { throw APIError.conflict("That pairing identifier is in use.") }
        return state(record)
    }

    /// The new device posts its sealed request. One request per join: a wrong guess cannot be retried against the same code.
    func submitJoinRequest(_ principal: ConsumerPrincipal, joinId: String, body: VaultJoinRequestBody) async throws -> VaultJoinState {
        try await throttle("vault-join", principal, rule: settings.joinRate)
        guard let sealed = Base64URL.decode(body.request), sealed.count >= VaultFormat.sealedBoxOverhead, sealed.count <= 2048, let device = principal.deviceId else {
            throw APIError.validation("The request is malformed.")
        }
        let record = try await liveJoin(joinId, consumer: principal.consumerId.uuid)
        guard record.request == nil, try await DB.swapFromNull(db, table: VaultJoinRecord.schema, id: record.id!, column: "requester_device_id", newValue: device.uuid) else {
            throw APIError.conflict("A device already asked to join with this pairing code.")
        }
        try await VaultJoinRecord.query(on: db).filter(\.$id == record.id!).set(\.$request, to: sealed).update()
        return state(try await liveJoin(joinId, consumer: principal.consumerId.uuid))
    }

    func join(_ principal: ConsumerPrincipal, joinId: String) async throws -> VaultJoinState {
        try await throttle("vault-join", principal, rule: settings.joinRate)
        let record = try await liveJoin(joinId, consumer: principal.consumerId.uuid)
        return state(record)
    }

    func cancelJoin(_ principal: ConsumerPrincipal, joinId: String) async throws {
        try await throttle("vault-join", principal, rule: settings.joinRate)
        guard Self.isValidJoinId(joinId), let record = try await VaultJoinRecord.query(on: db).filter(\.$joinId == joinId).filter(\.$consumerId == principal.consumerId.uuid).first()
        else { throw APIError.notFound }
        let isRequester = record.requesterDeviceId != nil && record.requesterDeviceId == principal.deviceId?.uuid
        if !isRequester, let vault = try await vault(of: principal.consumerId.uuid), try await boundMember(principal, in: vault) == nil { throw APIError.forbidden }
        try await record.delete(on: db)
    }
}
