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

    /// Rate-limit buckets are keyed by account **and device**, so one account device cannot use up what the others need (gate review L5).
    private func bucketKey(_ principal: ConsumerPrincipal) -> String {
        "\(principal.consumerId.description)/\(principal.deviceId.map { $0.uuid.uuidString.lowercased() } ?? "-")"
    }

    private func throttle(_ name: String, _ principal: ConsumerPrincipal, rule: RateRule) async throws {
        try await ctx.limiter.enforce(name, key: bucketKey(principal), rule: rule)
    }

    /// Reads draw on the bound-device bucket only when the caller is bound; every other caller has its own, smaller bucket.
    private func throttleRead(_ principal: ConsumerPrincipal, bound: Bool) async throws {
        if bound {
            try await throttle("vault-read", principal, rule: settings.readRate)
        } else {
            try await throttle("vault-unbound", principal, rule: settings.unboundReadRate)
        }
    }

    // MARK: Recovery-envelope release (gate review M2)

    private func releaseState(_ record: VaultRecoveryReleaseRecord) -> VaultRecoveryRelease.State {
        switch record.state {
        case "cancelled": return .cancelled
        case "consumed": return .consumed
        default: return ctx.now < record.releaseAt ? .holding : (ctx.now < record.expiresAt ? .released : .expired)
        }
    }

    private func releaseDTO(_ record: VaultRecoveryReleaseRecord, _ principal: ConsumerPrincipal) -> VaultRecoveryRelease {
        VaultRecoveryRelease(releaseId: record.id ?? UUID(), state: releaseState(record), requestedAt: record.requestedAt, releaseAt: record.releaseAt,
                             expiresAt: record.expiresAt, requestedByThisDevice: record.requesterDeviceId == principal.deviceId?.uuid)
    }

    /// Releases that can still matter: not cancelled or consumed, and not past their window.
    private func openReleases(_ vaultId: UUID) async throws -> [VaultRecoveryReleaseRecord] {
        let now = ctx.now
        return try await VaultRecoveryReleaseRecord.query(on: db).filter(\.$vaultId == vaultId).filter(\.$state == "pending").filter(\.$expiresAt > now)
            .sort(\.$requestedAt, .descending).all()
    }

    /// The first time anyone sees a window open, the account is told (nothing runs at the 72 h mark by itself).
    private func announceOpening(_ record: VaultRecoveryReleaseRecord) async {
        guard let id = record.id, record.releaseAt <= ctx.now, record.openedNotifiedAt == nil,
              (try? await DB.swapFromNull(db, table: VaultRecoveryReleaseRecord.schema, id: id, column: "opened_notified_at", newValue: ctx.now)) == true else { return }
        await SecurityNotices(db: db, ctx: ctx).notifyOtherDevices(of: record.consumerId, except: record.requesterDeviceId, notice: .vaultRecoveryReleased, subjectId: id.uuidString.lowercased())
    }

    /// The release that is open **for this device** right now: its hold has passed, its 24 h window has not, and it was this device that asked.
    private func activeWindow(_ principal: ConsumerPrincipal, vault: VaultRecord) async throws -> VaultRecoveryReleaseRecord? {
        guard let device = principal.deviceId, let vaultId = vault.id else { return nil }
        guard let window = try await openReleases(vaultId).first(where: { $0.requesterDeviceId == device.uuid && $0.releaseAt <= ctx.now }) else { return nil }
        await announceOpening(window)
        return window
    }

    private func requireWindow(_ principal: ConsumerPrincipal, vault: VaultRecord) async throws -> VaultRecoveryReleaseRecord {
        guard let window = try await activeWindow(principal, vault: vault) else {
            throw APIError(.forbidden, .forbidden, "This device is not part of the synced vault. To restore with the recovery key, ask for a release in Viadere: it takes effect after a 72-hour wait that your other devices can cancel.")
        }
        return window
    }

    /// An account device that once acted for a vault member that was since removed never gets back in (gate review L4).
    private func requireNotFormerMember(_ principal: ConsumerPrincipal, vault: VaultRecord) async throws {
        guard let device = principal.deviceId, let vaultId = vault.id else { return }
        if try await VaultMemberRecord.query(on: db).filter(\.$vaultId == vaultId).filter(\.$formerDeviceId == device.uuid).count() > 0 {
            throw APIError(.forbidden, .forbidden, "This device was removed from the synced vault. Set it up again as a new device.")
        }
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
        guard let vault = try await vault(of: principal.consumerId.uuid), let vaultId = vault.id else {
            try await throttleRead(principal, bound: false)
            return VaultStatus(exists: false)
        }
        let members = try await VaultMemberRecord.query(on: db).filter(\.$vaultId == vaultId).filter(\.$removedAt == nil).all()
        let bound = try await boundMember(principal, in: vault)
        try await throttleRead(principal, bound: bound != nil)
        let open = try await openReleases(vaultId).first
        if let open { await announceOpening(open) }
        return VaultStatus(exists: true, vaultId: vaultId, version: UInt64(vault.version), epoch: UInt64(vault.epoch), bound: bound != nil,
                           memberId: bound?.memberId, deviceCount: members.filter { $0.role == "device" }.count,
                           recoveryConfigured: members.contains { $0.role == "recovery" }, recoveryRelease: open.map { releaseDTO($0, principal) })
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
        var restoreWindow: VaultRecoveryReleaseRecord?
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
                try await requireNotFormerMember(principal, vault: existing)
                // Only the device whose release window is open may restore (M2); the window is spent by the restore.
                restoreWindow = try await requireWindow(principal, vault: existing)
                try await throttle("vault-recovery-put", principal, rule: settings.recoveryRate)
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

        // Item ciphertext only: re-encryption keeps blob sizes, so a vault inside this cap can always upload a full rotation (gate review M3).
        let totalBytes = m.items.reduce(0) { $0 + (newBlobs[$1.itemId]?.count ?? storedById[$1.itemId]?.blob.count ?? 0) }
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
            if let requester = record.requesterDeviceId, try await VaultMemberRecord.query(on: db).filter(\.$vaultId == vaultId).filter(\.$formerDeviceId == requester).count() > 0 {
                throw APIError.validation("That device was removed from the vault before.")
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
        let blobUploads = newBlobs, envelopeUploads = newEnvelopes, isRestore = recoveryRestore, joinRecord = join, window = restoreWindow
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
                    let former = storedMembers.first { $0.memberId == gone.id }.flatMap { $0.accountDeviceId ?? $0.formerDeviceId }
                    try await VaultMemberRecord.query(on: tx).filter(\.$vaultId == vaultId).filter(\.$memberId == gone.id)
                        .set(\.$removedAt, to: now).set(\.$envelope, to: nil).set(\.$accountDeviceId, to: nil).set(\.$formerDeviceId, to: former).update()
                }
                if let window {
                    guard try await DB.swap(tx, table: VaultRecoveryReleaseRecord.schema, id: window.id!, column: "state", expected: "pending", newValue: "consumed",
                                            extra: [("closed_at", now)]) else { throw ConcurrencyConflict() }
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
        if recoveryRestore {
            await notices.notifyOtherDevices(of: consumer, except: principal.deviceId?.uuid, notice: .vaultRestored, subjectId: vaultId.uuidString.lowercased())
        }
        return try await status(principal)
    }

    // MARK: Reads

    func manifests(_ principal: ConsumerPrincipal, after: UInt64, limit: Int) async throws -> VaultManifestsResponse {
        guard let vault = try await vault(of: principal.consumerId.uuid), let vaultId = vault.id else { throw APIError.notFound }
        if try await boundMember(principal, in: vault) != nil {
            try await throttleRead(principal, bound: true)
        } else {
            // A device that is not a member may read the signed history only inside its own released-envelope window (restoring with the
            // recovery key); account access alone reads nothing (gate review M2/L4).
            try await DeviceTrust.require(principal, db: db, now: ctx.now)
            try await requireNotFormerMember(principal, vault: vault)
            try await throttleRead(principal, bound: false)
            _ = try await requireWindow(principal, vault: vault)
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
            try await throttleRead(principal, bound: true)
        } else {
            // The device restoring with the recovery key reads the ciphertext it must re-encrypt, only inside its own window.
            try await DeviceTrust.require(principal, db: db, now: ctx.now)
            try await requireNotFormerMember(principal, vault: vault)
            try await throttleRead(principal, bound: false)
            _ = try await requireWindow(principal, vault: vault)
        }
        let rows = ids.isEmpty ? [] : try await VaultBlobRecord.query(on: db).filter(\.$vaultId == vault.id!).filter(\.$itemId ~~ ids).all()
        return VaultBlobsResponse(blobs: rows.map { VaultBlobDTO(itemId: $0.itemId, blob: Base64URL.encode($0.blob)) })
    }

    func envelope(_ principal: ConsumerPrincipal) async throws -> VaultEnvelopeResponse {
        let (_, member) = try await requireBound(principal)
        try await throttleRead(principal, bound: true)
        guard let envelope = member.envelope else { throw APIError.notFound }
        return VaultEnvelopeResponse(memberId: member.memberId, envelope: Base64URL.encode(envelope))
    }

    /// The recovery member's envelope: ciphertext only the recovery key opens. Released only to the device that asked for it, after the 72 h hold
    /// and for 24 h; rate-limited per device, audited, and announced to every other device on each fetch.
    func recoveryEnvelope(_ principal: ConsumerPrincipal) async throws -> VaultEnvelopeResponse {
        try await DeviceTrust.require(principal, db: db, now: ctx.now)
        guard let vault = try await vault(of: principal.consumerId.uuid), let vaultId = vault.id else { throw APIError.notFound }
        try await requireNotFormerMember(principal, vault: vault)
        _ = try await requireWindow(principal, vault: vault)
        try await throttle("vault-recovery", principal, rule: settings.recoveryRate)
        guard let member = try await VaultMemberRecord.query(on: db).filter(\.$vaultId == vaultId).filter(\.$role == "recovery").filter(\.$removedAt == nil).first(),
              let envelope = member.envelope else { throw APIError.notFound }
        _ = try await AuditService(db: db, ctx: ctx).record("vault.recovery_envelope_fetched", principal: principal, subjectType: "vault", subjectId: vaultId.uuidString.lowercased())
        await SecurityNotices(db: db, ctx: ctx).notifyOtherDevices(of: principal.consumerId.uuid, except: principal.deviceId?.uuid, notice: .vaultRecoveryFetched, subjectId: vaultId.uuidString.lowercased())
        return VaultEnvelopeResponse(memberId: member.memberId, envelope: Base64URL.encode(envelope))
    }

    /// Asks for the recovery envelope. Nothing is released for `recoveryHold` (72 h): every other device is told at once, with a "Not you? Cancel"
    /// action, and a vault device or any trusted account device can cancel. The notice is stored in the same transaction as the hold, so a
    /// hold nobody could be told about never starts.
    func requestRecoveryRelease(_ principal: ConsumerPrincipal) async throws -> VaultRecoveryRelease {
        let caller = try await DeviceTrust.require(principal, db: db, now: ctx.now)
        guard let device = caller.id else { throw APIError.signatureInvalid }
        try await throttle("vault-recovery-request", principal, rule: settings.recoveryRate)
        guard let vault = try await vault(of: principal.consumerId.uuid), let vaultId = vault.id,
              try await VaultMemberRecord.query(on: db).filter(\.$vaultId == vaultId).filter(\.$role == "recovery").filter(\.$removedAt == nil).count() > 0
        else { throw APIError.notFound }
        try await requireNotFormerMember(principal, vault: vault)
        if try await boundMember(principal, in: vault) != nil { throw APIError.conflict("This device already belongs to the vault.") }
        let open = try await openReleases(vaultId)
        if let mine = open.first(where: { $0.requesterDeviceId == device }) { return releaseDTO(mine, principal) }
        guard open.isEmpty else { throw APIError.conflict("A recovery key release is already pending for this vault. Cancel it first if it wasn't you.") }
        let now = ctx.now
        let record = VaultRecoveryReleaseRecord(vaultId: vaultId, consumerId: principal.consumerId.uuid, requesterDeviceId: device, now: now,
                                                releaseAt: now.addingTimeInterval(settings.recoveryHold), expiresAt: now.addingTimeInterval(settings.recoveryHold + settings.recoveryWindow))
        let consumer = principal.consumerId.uuid
        try await db.transaction { tx in
            try await record.create(on: tx)
            try await SecurityNotices(db: tx, ctx: ctx).store(of: consumer, except: device, notice: .vaultRecoveryRequested, subjectId: record.id!.uuidString.lowercased())
            _ = try await AuditService(db: tx, ctx: ctx).record("vault.recovery_release_requested", principal: principal, subjectType: "vault", subjectId: vaultId.uuidString.lowercased(),
                                                                 metadata: ["releases_at": ViadereDate.format(record.releaseAt)])
        }
        await SecurityNotices(db: db, ctx: ctx).push(to: consumer, except: device, notice: .vaultRecoveryRequested)
        return releaseDTO(record, principal)
    }

    /// "Not you? Cancel": a vault device, or any trusted account device. Closes every open release of the vault.
    func cancelRecoveryRelease(_ principal: ConsumerPrincipal, releaseId: UUID) async throws -> VaultRecoveryRelease {
        try await ctx.limiter.enforce("vault-recovery-cancel", key: bucketKey(principal), rule: .perHour(30, burst: 10))
        guard let record = try await VaultRecoveryReleaseRecord.find(releaseId, on: db), record.consumerId == principal.consumerId.uuid,
              let vault = try await VaultRecord.find(record.vaultId, on: db), let vaultId = vault.id else { throw APIError.notFound }
        if try await boundMember(principal, in: vault) == nil { try await DeviceTrust.require(principal, db: db, now: ctx.now) }
        switch record.state {
        case "cancelled": return releaseDTO(record, principal)
        case "pending": break
        default: throw APIError.conflict("This release can no longer be cancelled.")
        }
        let now = ctx.now
        let cancelled: Bool = try await db.transaction { tx in
            guard try await DB.swap(tx, table: VaultRecoveryReleaseRecord.schema, id: releaseId, column: "state", expected: "pending", newValue: "cancelled",
                                    extra: [("closed_at", now)]) else { return false }
            try await VaultRecoveryReleaseRecord.query(on: tx).filter(\.$vaultId == vaultId).filter(\.$state == "pending").set(\.$state, to: "cancelled").set(\.$closedAt, to: now).update()
            _ = try await AuditService(db: tx, ctx: ctx).record("vault.recovery_release_cancelled", principal: principal, subjectType: "vault", subjectId: vaultId.uuidString.lowercased())
            return true
        }
        guard cancelled else { throw APIError.conflict("This release can no longer be cancelled.") }
        await SecurityNotices(db: db, ctx: ctx).notifyOtherDevices(of: principal.consumerId.uuid, except: principal.deviceId?.uuid, notice: .vaultRecoveryCancelled, subjectId: releaseId.uuidString.lowercased())
        guard let fresh = try await VaultRecoveryReleaseRecord.find(releaseId, on: db) else { throw APIError.notFound }
        return releaseDTO(fresh, principal)
    }

    func devices(_ principal: ConsumerPrincipal) async throws -> [VaultDeviceInfo] {
        guard let vault = try await vault(of: principal.consumerId.uuid), let vaultId = vault.id else { throw APIError.notFound }
        if try await boundMember(principal, in: vault) == nil {
            try await DeviceTrust.require(principal, db: db, now: ctx.now)
            try await requireNotFormerMember(principal, vault: vault)
            try await throttleRead(principal, bound: false)
            _ = try await requireWindow(principal, vault: vault)
        } else {
            try await throttleRead(principal, bound: true)
        }
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
            try await VaultMemberRecord.query(on: tx).filter(\.$id == target.id!).set(\.$removedAt, to: now).set(\.$envelope, to: nil).set(\.$accountDeviceId, to: nil)
                .set(\.$formerDeviceId, to: target.accountDeviceId ?? target.formerDeviceId).update()
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
        try await VaultRecoveryReleaseRecord.query(on: database).filter(\.$vaultId == id).delete()
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
        if let vault = try await VaultRecord.find(record.vaultId, on: db) { try await requireNotFormerMember(principal, vault: vault) }
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
