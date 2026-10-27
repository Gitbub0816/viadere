import Crypto
import Foundation
import Testing
@testable import ViadereCore

private let t0 = Date(timeIntervalSince1970: 1_800_000_000)

private func totpItem(_ name: String = "alice") -> VaultItemPayload {
    VaultItemPayload(body: .totp(TOTPParameters(secret: Data("12345678901234567890".utf8), issuer: "Example", accountName: name)), createdAt: t0)
}

private func passkeyItem(rp: String = "example.com") throws -> VaultItemPayload {
    let made = try WebAuthnAuthenticator.makeCredential(rpId: rp, userHandle: Data([7, 7]), userName: "alice", clientDataHash: Data(repeating: 3, count: 32),
                                                        requireUserVerification: true, userVerified: true, backedUp: true, now: t0)
    return VaultItemPayload(body: .passkey(made.credential), createdAt: t0)
}

@Suite("Vault crypto primitives")
struct VaultCryptoTests {
    @Test func sealOpenAndContextBinding() throws {
        let key = SymmetricKey(size: .bits256)
        let aad = VaultAAD.make("t", [Data([1])])
        let sealed = try VaultSeal.seal(Data("secret".utf8), key: key, aad: aad)
        #expect(sealed.count == 2 + 12 + 6 + 16)
        #expect(try VaultSeal.open(sealed, key: key, aad: aad) == Data("secret".utf8))
        #expect(throws: VaultError.authenticationFailed) { try VaultSeal.open(sealed, key: SymmetricKey(size: .bits256), aad: aad) }
        #expect(throws: VaultError.authenticationFailed) { try VaultSeal.open(sealed, key: key, aad: VaultAAD.make("t", [Data([2])])) }
        #expect(throws: VaultError.authenticationFailed) { try VaultSeal.open(sealed, key: key, aad: VaultAAD.make("u", [Data([1])])) }
        for index in 0..<sealed.count {
            var bad = sealed
            bad[index] ^= 0x01
            #expect(throws: VaultError.self) { try VaultSeal.open(bad, key: key, aad: aad) }
        }
        var future = sealed
        future[0] = 2
        #expect(throws: VaultError.unsupportedVersion(2)) { try VaultSeal.open(future, key: key, aad: aad) }
        #expect(throws: VaultError.self) { try VaultSeal.open(Data([1, 1, 0]), key: key, aad: aad) }
    }

    @Test func aadFieldsAreUnambiguous() {
        // ("ab","c") and ("a","bc") must not collide.
        #expect(VaultAAD.make("p", [Data("ab".utf8), Data("c".utf8)]) != VaultAAD.make("p", [Data("a".utf8), Data("bc".utf8)]))
    }

    @Test func noncesAreFreshForEverySeal() throws {
        let key = SymmetricKey(size: .bits256)
        var nonces = Set<Data>()
        for _ in 0..<20_000 {
            let sealed = try VaultSeal.seal(Data(), key: key, aad: Data())
            #expect(nonces.insert(try #require(VaultSeal.nonce(of: sealed))).inserted, "a 96-bit nonce repeated")
        }
    }

    @Test func paddingHidesSizeAndRejectsGarbage() throws {
        for count in [0, 1, 100, 251, 252, 253, 1000] {
            let data = SecureToken.randomBytes(count)
            let padded = VaultPadding.pad(data)
            #expect(padded.count % 256 == 0)
            #expect(try VaultPadding.unpad(padded) == data)
        }
        var bad = VaultPadding.pad(Data([1, 2, 3]))
        bad[bad.count - 1] = 1
        #expect(throws: VaultError.self) { try VaultPadding.unpad(bad) }
        #expect(throws: VaultError.self) { try VaultPadding.unpad(Data([0, 0, 1, 0]) + Data(repeating: 0, count: 252)) }
    }

    @Test func itemBlobsBindVaultItemEpochAndRevision() throws {
        let key = VaultKey.generate()
        let vault = UUID()
        let item = try passkeyItem()
        let blob = try VaultItemBlob.seal(item, vaultId: vault, epoch: 1, revision: 3, vaultKey: key)
        #expect(try VaultItemBlob.open(blob, itemId: item.id, vaultId: vault, epoch: 1, revision: 3, vaultKey: key) == item)
        #expect(throws: VaultError.authenticationFailed) { try VaultItemBlob.open(blob, itemId: UUID(), vaultId: vault, epoch: 1, revision: 3, vaultKey: key) }
        #expect(throws: VaultError.authenticationFailed) { try VaultItemBlob.open(blob, itemId: item.id, vaultId: UUID(), epoch: 1, revision: 3, vaultKey: key) }
        #expect(throws: VaultError.authenticationFailed) { try VaultItemBlob.open(blob, itemId: item.id, vaultId: vault, epoch: 2, revision: 3, vaultKey: key) }
        #expect(throws: VaultError.authenticationFailed) { try VaultItemBlob.open(blob, itemId: item.id, vaultId: vault, epoch: 1, revision: 2, vaultKey: key) }
        #expect(throws: VaultError.authenticationFailed) { try VaultItemBlob.open(blob, itemId: item.id, vaultId: vault, epoch: 1, revision: 3, vaultKey: .generate()) }
        // Same plaintext, different item key and nonce each time; the passkey's private key never appears in the blob.
        let again = try VaultItemBlob.seal(item, vaultId: vault, epoch: 1, revision: 3, vaultKey: key)
        #expect(again != blob)
        guard case .passkey(let credential) = item.body else { Issue.record("not a passkey"); return }
        #expect(blob.range(of: credential.privateKey) == nil)
        #expect(blob.count < VaultFormat.maxItemBlobBytes)
    }

    @Test func totpAndPasskeysSealToTheSamePaddedBucket() throws {
        let key = VaultKey.generate()
        let a = try VaultItemBlob.seal(totpItem(), vaultId: UUID(), epoch: 1, revision: 1, vaultKey: key)
        let b = try VaultItemBlob.seal(try passkeyItem(), vaultId: UUID(), epoch: 1, revision: 1, vaultKey: key)
        #expect(a.count == b.count)
    }

    @Test func envelopesBindVaultEpochAndMember() throws {
        let device = VaultDeviceIdentity.software()
        let vk = VaultKey.generate()
        let vault = UUID()
        let envelope = try VaultEnvelope.seal(vk, to: device.agreementPublicKey, vaultId: vault, epoch: 1, memberId: device.memberId)
        #expect(envelope.count == VaultFormat.envelopeLength)
        let opened = try VaultEnvelope.open(envelope, with: device.agreementKey, vaultId: vault, epoch: 1, memberId: device.memberId)
        #expect(opened.bytes == vk.bytes)
        #expect(throws: VaultError.self) { try VaultEnvelope.open(envelope, with: device.agreementKey, vaultId: UUID(), epoch: 1, memberId: device.memberId) }
        #expect(throws: VaultError.self) { try VaultEnvelope.open(envelope, with: device.agreementKey, vaultId: vault, epoch: 2, memberId: device.memberId) }
        #expect(throws: VaultError.self) { try VaultEnvelope.open(envelope, with: device.agreementKey, vaultId: vault, epoch: 1, memberId: "someone-else") }
        #expect(throws: VaultError.self) { try VaultEnvelope.open(envelope, with: SoftwareVaultAgreementKey(), vaultId: vault, epoch: 1, memberId: device.memberId) }
        for index in [0, 1, 2, 40, 66, 67, 100, envelope.count - 1] {
            var bad = envelope
            bad[index] ^= 0x80
            #expect(throws: VaultError.self) { try VaultEnvelope.open(bad, with: device.agreementKey, vaultId: vault, epoch: 1, memberId: device.memberId) }
        }
        #expect(throws: VaultError.self) { try VaultEnvelope.open(envelope.dropLast(), with: device.agreementKey, vaultId: vault, epoch: 1, memberId: device.memberId) }
        // Two seals of the same key to the same recipient differ (fresh ephemeral key).
        #expect(try VaultEnvelope.seal(vk, to: device.agreementPublicKey, vaultId: vault, epoch: 1, memberId: device.memberId) != envelope)
    }

    @Test func recoveryKeyAndPairingCodeFormats() throws {
        let key = RecoveryKey.generate()
        let text = key.displayString
        #expect(text.hasPrefix("VRK1-") && text.split(separator: "-").count == 12)
        #expect(try RecoveryKey(parsing: text) == key)
        #expect(try RecoveryKey(parsing: text.lowercased().replacingOccurrences(of: "-", with: " ")) == key)
        // One wrong character is caught by the checksum.
        var chars = Array(text)
        let index = chars.lastIndex { $0 != "-" }!
        chars[index] = chars[index] == "0" ? "1" : "0"
        #expect(throws: VaultError.invalidRecoveryKey) { try RecoveryKey(parsing: String(chars)) }
        #expect(throws: VaultError.invalidRecoveryKey) { try RecoveryKey(parsing: "VRK1-0000") }
        #expect(throws: VaultError.invalidRecoveryKey) { try RecoveryKey(parsing: "") }
        let vault = UUID()
        let a = try key.identity(vaultId: vault)
        #expect(a.memberId == (try key.identity(vaultId: vault)).memberId, "deterministic")
        #expect(a.memberId != (try key.identity(vaultId: UUID())).memberId, "bound to the vault")
        #expect(a.signingPublicKey != a.agreementPublicKey)
        let pairing = PairingSecret.generate()
        #expect(pairing.displayString.split(separator: "-").count == 7)
        #expect(try PairingSecret(parsing: pairing.displayString) == pairing)
        #expect(try PairingSecret(parsing: pairing.displayString.lowercased()).joinId == pairing.joinId)
        #expect(throws: VaultError.invalidPairingCode) { try PairingSecret(parsing: "AAAA-AAAA") }
        #expect(PairingSecret.generate().joinId != pairing.joinId)
    }
}

@Suite("Vault protocol")
struct VaultProtocolTests {
    @Test func createUnlockAndEditItems() async throws {
        let device = VaultDeviceIdentity.software()
        let totp = totpItem()
        let created = try await UnlockedVault.create(identity: device, label: "Anna's iPhone", items: [totp], now: t0)
        #expect(created.vault.manifest.version == 1 && created.vault.manifest.epoch == 1)
        #expect(try created.vault.items() == [totp])
        #expect(created.vault.label(of: device.memberId) == "Anna's iPhone")

        // Reopen from nothing but the snapshot (what is on disk) and the device keys.
        let reopened = try UnlockedVault.open(created.vault.snapshot, identity: device)
        #expect(try reopened.items() == [totp])

        let passkey = try passkeyItem()
        let second = try await reopened.applying(upserts: [passkey], now: t0.addingTimeInterval(10))
        #expect(second.vault.manifest.version == 2)
        #expect(second.delta.blobs.keys.sorted { $0.uuidString < $1.uuidString } == [passkey.id])
        #expect(Set(try second.vault.items().map(\.id)) == [totp.id, passkey.id])

        var edited = totp
        edited.body = .totp(TOTPParameters(secret: Data("12345678901234567890".utf8), issuer: "Example", accountName: "renamed"))
        let third = try await second.vault.applying(upserts: [edited], deletes: [passkey.id], now: t0.addingTimeInterval(20))
        #expect(third.vault.manifest.items.count == 1 && third.vault.manifest.items[0].revision == 2)
        #expect(third.delta.removedItems == [passkey.id])
        #expect(third.vault.snapshot.blobs[passkey.id] == nil)
        #expect(try third.vault.items().first?.body == edited.body)
    }

    @Test func snapshotContentsMustMatchTheSignedManifest() async throws {
        let device = VaultDeviceIdentity.software()
        let made = try await UnlockedVault.create(identity: device, label: "d", items: [totpItem()], now: t0)
        var tampered = made.vault.snapshot
        let id = tampered.blobs.keys.first!
        tampered.blobs[id]![40] ^= 1
        #expect(throws: VaultError.blobMismatch) { try tampered.validateContents() }
        #expect(throws: VaultError.blobMismatch) { try UnlockedVault.open(tampered, identity: device) }
        var swapped = made.vault.snapshot
        swapped.envelopes[device.memberId]![80] ^= 1
        #expect(throws: VaultError.blobMismatch) { try swapped.validateContents() }
    }

    @Test func approvingANewDeviceReSealsTheVaultKeyThroughThePairingChannel() async throws {
        let a = VaultDeviceIdentity.software()
        let b = VaultDeviceIdentity.software()
        let item = totpItem()
        let vault = try await UnlockedVault.create(identity: a, label: "Phone", items: [item], now: t0).vault

        // A shows a pairing code; B types it and sends its sealed keys through the server.
        let secret = PairingSecret.generate()
        let request = try JoinRequest.make(for: b, label: "iPad").sealed(with: secret)
        // A decrypts the request (only possible with the secret), and approves it.
        let opened = try JoinRequest.open(request, with: secret)
        #expect(opened.label == "iPad" && opened.signingKey == b.signingPublicKey)
        let approval = try await vault.approvingJoin(opened, secret: secret, now: t0.addingTimeInterval(60))
        #expect(approval.vault.manifest.devices.count == 2)
        let newManifest = approval.delta.manifest
        let envelope = try #require(approval.delta.envelopes[b.memberId])

        // B accepts: needs only the approval, the manifest and its envelope from the server.
        let joined = try UnlockedVault.acceptingJoin(approval: try #require(approval.approval), secret: secret, manifest: newManifest, envelope: envelope, identity: b)
        #expect(joined.vaultKey.bytes == vault.vaultKey.bytes)
        #expect(joined.label(of: b.memberId) == "iPad")
        // It then fetches the blobs the manifest lists and reads them.
        var withBlobs = joined.snapshot
        withBlobs.blobs = approval.vault.snapshot.blobs
        #expect(try UnlockedVault.open(withBlobs, identity: b).items() == [item])
        // B can sign the next version.
        let next = try await UnlockedVault.open(withBlobs, identity: b).applying(upserts: [totpItem("b")], now: t0.addingTimeInterval(120))
        _ = try VaultChainVerifier.verify(next.delta.manifest, after: approval.vault.snapshot.verified)
    }

    @Test func aWrongOrMissingPairingSecretCannotJoinOrForge() async throws {
        let a = VaultDeviceIdentity.software()
        let b = VaultDeviceIdentity.software()
        let attacker = VaultDeviceIdentity.software()
        let vault = try await UnlockedVault.create(identity: a, label: "Phone", now: t0).vault
        let secret = PairingSecret.generate()
        let sealed = try JoinRequest.make(for: b, label: "iPad").sealed(with: secret)
        // The server (or anyone without the pairing code) cannot read the request or substitute its own.
        #expect(throws: VaultError.authenticationFailed) { try JoinRequest.open(sealed, with: PairingSecret.generate()) }
        let forged = try JoinRequest.make(for: attacker, label: "Totally the iPad").sealed(with: PairingSecret.generate())
        #expect(throws: VaultError.authenticationFailed) { try JoinRequest.open(forged, with: secret) }
        // A request sealed for another join cannot be replayed into this one.
        let other = PairingSecret.generate()
        let otherSealed = try JoinRequest.make(for: attacker, label: "x").sealed(with: other)
        #expect(throws: VaultError.authenticationFailed) { try JoinRequest.open(otherSealed, with: secret) }

        // The server cannot hand B a manifest or an envelope of its own making: the approval pins the approver's key and the manifest hash.
        let approval = try await vault.approvingJoin(try JoinRequest.open(sealed, with: secret), secret: secret, now: t0.addingTimeInterval(1))
        let evil = try await UnlockedVault.create(identity: attacker, label: "evil", now: t0)
        let evilEnvelope = try VaultEnvelope.seal(evil.vault.vaultKey, to: b.agreementPublicKey, vaultId: evil.vault.vaultId, epoch: 1, memberId: b.memberId)
        #expect(throws: VaultError.self) {
            try UnlockedVault.acceptingJoin(approval: try #require(approval.approval), secret: secret, manifest: evil.delta.manifest, envelope: evilEnvelope, identity: b)
        }
        // And a stolen approval is useless without the secret.
        #expect(throws: VaultError.authenticationFailed) {
            try UnlockedVault.acceptingJoin(approval: try #require(approval.approval), secret: PairingSecret.generate(), manifest: approval.delta.manifest,
                                            envelope: try #require(approval.delta.envelopes[b.memberId]), identity: b)
        }
    }

    @Test func aServerHoldingEverythingCannotOpenOrExtendTheVault() async throws {
        // What the server stores: manifests, blobs, every envelope. None of it opens without a device key or the recovery key.
        let a = VaultDeviceIdentity.software()
        let recovery = RecoveryKey.generate()
        let made = try await UnlockedVault.create(identity: a, label: "Phone", recoveryKey: recovery, items: [totpItem()], now: t0)
        let serverCopy = made.vault.snapshot
        let attacker = VaultDeviceIdentity.software()
        #expect(throws: VaultError.notAMember) { try UnlockedVault.open(serverCopy, identity: attacker) }
        // Even claiming a member's envelope, the attacker's key does not open it.
        var stolen = serverCopy
        stolen.envelopes[attacker.memberId] = serverCopy.envelopes[a.memberId]
        #expect(throws: VaultError.notAMember) { try UnlockedVault.open(stolen, identity: attacker) }
        // A new account device after account recovery has no vault key, no pairing code and no recovery key: it cannot sign a valid manifest either.
        let forged = VaultManifest(vaultId: made.vault.vaultId, version: 2, previousHash: serverCopy.verified.hash, epoch: 1, keyCheck: serverCopy.manifest.keyCheck,
                                   members: serverCopy.manifest.members + [VaultMember(role: .device, signingKey: attacker.signingPublicKey, agreementKey: attacker.agreementPublicKey,
                                                                                         envelopeHash: Data(repeating: 1, count: 32), addedAt: 1, sealedLabel: Data(repeating: 2, count: 40))],
                                   items: serverCopy.manifest.items, signerId: attacker.memberId, createdAt: 2)
        let signed = try await SignedVaultManifest.sign(forged, with: attacker.signingKey)
        #expect(throws: VaultError.unknownSigner) { try VaultChainVerifier.verify(signed, after: serverCopy.verified) }
    }

    @Test func removingADeviceRotatesTheKeyAndLocksItOut() async throws {
        let a = VaultDeviceIdentity.software()
        let b = VaultDeviceIdentity.software()
        let item = totpItem()
        let first = try await UnlockedVault.create(identity: a, label: "Phone", items: [item], now: t0).vault
        let secret = PairingSecret.generate()
        let joined = try await first.approvingJoin(try JoinRequest.open(try JoinRequest.make(for: b, label: "iPad").sealed(with: secret), with: secret), secret: secret, now: t0.addingTimeInterval(1))
        let bBefore = try UnlockedVault.open(joined.vault.snapshot, identity: b)

        let removed = try await joined.vault.removingDevice(b.memberId, now: t0.addingTimeInterval(5))
        #expect(removed.vault.manifest.epoch == 2 && removed.vault.manifest.devices.count == 1)
        #expect(removed.vault.vaultKey.bytes != joined.vault.vaultKey.bytes)
        #expect(try removed.vault.items() == [item])
        #expect(removed.vault.manifest.items[0].revision == 2, "re-encrypted under a fresh key")
        _ = try VaultChainVerifier.verify(removed.delta.manifest, after: joined.vault.snapshot.verified)
        // B has no envelope at the new epoch, and its old one does not open under the new manifest.
        #expect(throws: VaultError.notAMember) { try UnlockedVault.open(removed.vault.snapshot, identity: b) }
        var stale = removed.vault.snapshot
        stale.envelopes[b.memberId] = bBefore.snapshot.envelopes[b.memberId]
        #expect(throws: VaultError.notAMember) { try UnlockedVault.open(stale, identity: b) }
        // B (removed) cannot sign a successor either.
        var forgedNext = removed.vault.manifest
        forgedNext.version += 1
        forgedNext.previousHash = removed.vault.snapshot.verified.hash
        forgedNext.signerId = b.memberId
        let attempt = try await SignedVaultManifest.sign(forgedNext, with: b.signingKey)
        #expect(throws: VaultError.unknownSigner) { try VaultChainVerifier.verify(attempt, after: removed.vault.snapshot.verified) }
        // A device cannot remove itself or the recovery member through this call.
        await #expect(throws: VaultError.self) { try await removed.vault.removingDevice(a.memberId, now: t0) }
    }

    @Test func recoveryKeyRestoresTheVaultOnANewDeviceAndRetiresItself() async throws {
        let a = VaultDeviceIdentity.software()
        let recovery = RecoveryKey.generate()
        let item = try passkeyItem()
        let v1 = try await UnlockedVault.create(identity: a, label: "Phone", recoveryKey: recovery, items: [item], now: t0)
        let v2 = try await v1.vault.applying(upserts: [totpItem()], now: t0.addingTimeInterval(1))
        let chain = [v1.delta.manifest, v2.delta.manifest]

        // The phone is lost. A new device holds only the recovery key and what the server returns.
        let fresh = VaultDeviceIdentity.software()
        let parsed = try RecoveryKey(parsing: recovery.displayString)
        let authenticated = try UnlockedVault.authenticateChain(chain, recoveryKey: parsed)
        #expect(authenticated.manifest.version == 2)
        let snapshot = VaultSnapshot(verified: authenticated, blobs: v2.vault.snapshot.blobs,
                                     envelopes: [authenticated.manifest.recoveryMember!.id: v2.vault.snapshot.envelopes[authenticated.manifest.recoveryMember!.id]!])
        try snapshot.validateContents()
        let newRecovery = RecoveryKey.generate()
        let restored = try await UnlockedVault.recovering(snapshot, recoveryKey: parsed, newRecoveryKey: newRecovery, newDevice: fresh, label: "New phone", now: t0.addingTimeInterval(100))
        #expect(restored.vault.manifest.epoch == 2 && restored.vault.manifest.devices.map(\.id) == [fresh.memberId])
        #expect(Set(try restored.vault.items().map(\.id)).count == 2)
        // The lost phone is out, the used recovery key is retired, the new one works.
        #expect(restored.vault.manifest.recoveryMember?.id != authenticated.manifest.recoveryMember?.id)
        _ = try VaultChainVerifier.verify(restored.delta.manifest, after: authenticated)
        #expect(throws: VaultError.notAMember) { try UnlockedVault.open(restored.vault.snapshot, identity: a) }
        let chain2 = chain + [restored.delta.manifest]
        #expect(try UnlockedVault.authenticateChain(chain2, recoveryKey: newRecovery).manifest.version == 3)
        #expect(throws: VaultError.invalidRecoveryKey) { try UnlockedVault.authenticateChain(chain2, recoveryKey: recovery) }
        // Wrong key from the start.
        #expect(throws: VaultError.invalidRecoveryKey) { try UnlockedVault.authenticateChain(chain, recoveryKey: RecoveryKey.generate()) }
    }

    @Test func aMaliciousServerCannotSubstituteAForgedVaultDuringRecovery() async throws {
        let a = VaultDeviceIdentity.software()
        let recovery = RecoveryKey.generate()
        let real = try await UnlockedVault.create(identity: a, label: "Phone", recoveryKey: recovery, now: t0)
        // The server knows the recovery member's PUBLIC keys. It builds its own vault listing them, with its own vault key sealed to them.
        let attacker = VaultDeviceIdentity.software()
        let realRecovery = try #require(real.vault.manifest.recoveryMember)
        let evilKey = VaultKey.generate()
        let evilEnvelope = try VaultEnvelope.seal(evilKey, to: realRecovery.agreementKey, vaultId: real.vault.vaultId, epoch: 1, memberId: realRecovery.id)
        let evilDevice = try VaultEnvelope.seal(evilKey, to: attacker.agreementPublicKey, vaultId: real.vault.vaultId, epoch: 1, memberId: attacker.memberId)
        let members = [VaultMember(role: .device, signingKey: attacker.signingPublicKey, agreementKey: attacker.agreementPublicKey, envelopeHash: VaultEnvelope.hash(evilDevice), addedAt: 1,
                                   sealedLabel: Data(repeating: 1, count: 40)),
                       VaultMember(role: .recovery, signingKey: realRecovery.signingKey, agreementKey: realRecovery.agreementKey, envelopeHash: VaultEnvelope.hash(evilEnvelope), addedAt: 1,
                                   sealedLabel: nil, binding: realRecovery.binding)]
        let manifest = VaultManifest(vaultId: real.vault.vaultId, version: 1, previousHash: VaultManifest.genesisPreviousHash, epoch: 1, keyCheck: evilKey.keyCheck(epoch: 1),
                                     members: members, items: [], signerId: attacker.memberId, createdAt: 1)
        let forged = try await SignedVaultManifest.sign(manifest, with: attacker.signingKey)
        // Everything checks out except the binding, which only a holder of the recovery key can produce.
        #expect(throws: VaultError.invalidRecoveryKey) { try UnlockedVault.authenticateChain([forged], recoveryKey: recovery) }
    }

    @Test func recoveryMustAuthorizeTheNewDeviceAndRotate() async throws {
        let a = VaultDeviceIdentity.software()
        let recovery = RecoveryKey.generate()
        let v1 = try await UnlockedVault.create(identity: a, label: "Phone", recoveryKey: recovery, now: t0)
        let fresh = VaultDeviceIdentity.software()
        let good = try await UnlockedVault.recovering(v1.vault.snapshot, recoveryKey: recovery, newRecoveryKey: .generate(), newDevice: fresh, label: "n", now: t0)
        // Strip the authorization: the unknown signer is rejected.
        var stripped = good.delta.manifest
        stripped.recoveryAuthorization = nil
        #expect(throws: VaultError.unknownSigner) { try VaultChainVerifier.verify(stripped, after: v1.vault.snapshot.verified) }
        // An authorization issued by another recovery key is rejected.
        var wrong = good.delta.manifest
        wrong.recoveryAuthorization = try await SoftwareP256SigningKey().signature(for: Data("x".utf8)).rawRepresentation
        #expect(throws: VaultError.badSignature) { try VaultChainVerifier.verify(wrong, after: v1.vault.snapshot.verified) }
        // An authorization for the next-but-one manifest (different previous hash) does not transfer.
        let v2 = try await v1.vault.applying(upserts: [totpItem()], now: t0.addingTimeInterval(1))
        #expect(throws: VaultError.self) { try VaultChainVerifier.verify(good.delta.manifest, after: v2.vault.snapshot.verified) }
    }

    @Test func settingARecoveryKeyLaterAndRotatingIt() async throws {
        let a = VaultDeviceIdentity.software()
        let v1 = try await UnlockedVault.create(identity: a, label: "Phone", items: [totpItem()], now: t0).vault
        #expect(v1.manifest.recoveryMember == nil)
        let rk1 = RecoveryKey.generate()
        let v2 = try await v1.settingRecoveryKey(rk1, rotateKey: false, now: t0.addingTimeInterval(1))
        #expect(v2.vault.manifest.epoch == 1 && v2.vault.manifest.recoveryMember != nil)
        _ = try VaultChainVerifier.verify(v2.delta.manifest, after: v1.snapshot.verified)
        // Replace it with a new one, rotating the vault key: the old key's envelope no longer opens anything current.
        let rk2 = RecoveryKey.generate()
        let v3 = try await v2.vault.settingRecoveryKey(rk2, rotateKey: true, now: t0.addingTimeInterval(2))
        #expect(v3.vault.manifest.epoch == 2 && v3.vault.manifest.recoveryMember?.id != v2.vault.manifest.recoveryMember?.id)
        _ = try VaultChainVerifier.verify(v3.delta.manifest, after: v2.vault.snapshot.verified)
        #expect(try v3.vault.items().count == 1)
    }

    @Test func labelsAreSealedAndSanitized() async throws {
        let a = VaultDeviceIdentity.software()
        let made = try await UnlockedVault.create(identity: a, label: "  Evil\u{202E}name\n" + String(repeating: "x", count: 200), now: t0).vault
        let label = try #require(made.label(of: a.memberId))
        #expect(label.utf8.count <= VaultFormat.maxLabelBytes && !DisplayTextSanitizer.containsDisallowedScalars(label))
        // The manifest carries only ciphertext for it.
        #expect(made.manifest.encoded().range(of: Data("Evil".utf8)) == nil)
    }
}

@Suite("Vault manifest chain and anti-rollback")
struct VaultChainTests {
    /// A vault with devices a (and b) and a few versions.
    func history() async throws -> (a: VaultDeviceIdentity, b: VaultDeviceIdentity, vaults: [UnlockedVault], chain: [SignedVaultManifest]) {
        let a = VaultDeviceIdentity.software()
        let b = VaultDeviceIdentity.software()
        let v1 = try await UnlockedVault.create(identity: a, label: "A", items: [totpItem("one")], now: t0)
        let v2 = try await v1.vault.applying(upserts: [totpItem("two")], now: t0.addingTimeInterval(1))
        let secret = PairingSecret.generate()
        let v3 = try await v2.vault.approvingJoin(JoinRequest.make(for: b, label: "B"), secret: secret, now: t0.addingTimeInterval(2))
        let v4 = try await v3.vault.applying(upserts: [totpItem("three")], now: t0.addingTimeInterval(3))
        return (a, b, [v1.vault, v2.vault, v3.vault, v4.vault], [v1, v2, v3, v4].map(\.delta.manifest))
    }

    @Test func acceptsTheGenuineChainFromGenesisAndFromAnyAnchor() async throws {
        let h = try await history()
        #expect(try VaultChainVerifier.verifyChain(h.chain, trusted: nil).manifest.version == 4)
        for index in 0..<4 {
            let anchor = h.vaults[index].snapshot.verified
            let latest = try VaultChainVerifier.verifyChain(Array(h.chain[index...]), trusted: anchor)
            #expect(latest.manifest.version == 4)
            // The server may send the anchor again or the whole history.
            #expect(try VaultChainVerifier.verifyChain(h.chain, trusted: anchor).manifest.version == 4)
        }
        #expect(try VaultChainVerifier.verifyChain([h.chain[3]], trusted: h.vaults[3].snapshot.verified).hash == h.chain[3].hash)
    }

    @Test func rejectsRollbackToAnOlderVersion() async throws {
        let h = try await history()
        let trusted = h.vaults[3].snapshot.verified
        #expect(throws: VaultError.rollback) { try VaultChainVerifier.verifyChain([h.chain[1]], trusted: trusted) }
        #expect(throws: VaultError.rollback) { try VaultChainVerifier.verifyChain(Array(h.chain[0...2]), trusted: trusted) }
        #expect(throws: VaultError.rollback) { try VaultChainVerifier.verifyChain([h.chain[2]], trusted: trusted) }
        #expect(throws: VaultError.self) { try VaultChainVerifier.verify(h.chain[1], after: trusted) }
    }

    @Test func rejectsAForkedHistory() async throws {
        let h = try await history()
        // The same version 4 signed with different content (a fork the server presents to a device that trusts the other one).
        let forkBase = h.vaults[2]
        let fork = try await forkBase.applying(upserts: [totpItem("fork")], now: t0.addingTimeInterval(3))
        #expect(fork.delta.manifest.hash != h.chain[3].hash)
        #expect(throws: VaultError.fork) { try VaultChainVerifier.verifyChain([fork.delta.manifest], trusted: h.vaults[3].snapshot.verified) }
        #expect(throws: VaultError.fork) { try VaultChainVerifier.verifyChain(Array(h.chain[0...2]) + [fork.delta.manifest], trusted: h.vaults[3].snapshot.verified) }
        // A different next version whose previous hash is not the trusted one.
        let sibling = try await h.vaults[2].applying(upserts: [totpItem("sibling")], now: t0.addingTimeInterval(4))
        let next = try await UnlockedVault.open(sibling.vault.snapshot, identity: h.a).applying(upserts: [totpItem("n")], now: t0.addingTimeInterval(5))
        #expect(throws: VaultError.fork) { try VaultChainVerifier.verify(next.delta.manifest, after: h.vaults[3].snapshot.verified) }
    }

    @Test func rejectsGapsReorderingAndUnknownGenesis() async throws {
        let h = try await history()
        #expect(throws: VaultError.self) { try VaultChainVerifier.verifyChain([h.chain[0], h.chain[2]], trusted: nil) }
        #expect(throws: VaultError.self) { try VaultChainVerifier.verifyChain([h.chain[1], h.chain[0]], trusted: nil) }
        #expect(throws: VaultError.self) { try VaultChainVerifier.verifyChain(Array(h.chain[1...]), trusted: nil) }
        #expect(throws: VaultError.self) { try VaultChainVerifier.verifyChain([h.chain[3]], trusted: h.vaults[1].snapshot.verified) }
        #expect(throws: VaultError.self) { try VaultChainVerifier.verifyChain([], trusted: nil) }
    }

    @Test func rejectsBadSignaturesAndTamperedBytes() async throws {
        let h = try await history()
        var badSignature = h.chain[1]
        badSignature.signature[3] ^= 1
        #expect(throws: VaultError.badSignature) { try VaultChainVerifier.verify(badSignature, after: h.vaults[0].snapshot.verified) }
        var tampered = h.chain[1]
        tampered.manifestBytes[tampered.manifestBytes.count - 3] ^= 1
        #expect(throws: VaultError.self) { try VaultChainVerifier.verify(tampered, after: h.vaults[0].snapshot.verified) }
        // A high-S signature is a distinct encoding of the same signature: refused, so one manifest has one valid byte string.
        var highS = h.chain[1]
        highS.signature = try flipS(h.chain[1].signature)
        #expect(throws: VaultError.badSignature) { try VaultChainVerifier.verify(highS, after: h.vaults[0].snapshot.verified) }
        // A manifest signed by a key that is not a member.
        let outsider = VaultDeviceIdentity.software()
        let manifest = try VaultManifest.decode(h.chain[1].manifestBytes)
        var other = manifest
        other.signerId = outsider.memberId
        let outsiderSigned = try await SignedVaultManifest.sign(other, with: outsider.signingKey)
        #expect(throws: VaultError.unknownSigner) { try VaultChainVerifier.verify(outsiderSigned, after: h.vaults[0].snapshot.verified) }
    }

    /// `(r, n - s)`: valid ECDSA, wrong (high-S) form.
    private func flipS(_ raw: Data) throws -> Data {
        let n: [UInt8] = [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51]
        let s = [UInt8](raw[32..<64])
        var out = [UInt8](repeating: 0, count: 32)
        var borrow = 0
        for i in stride(from: 31, through: 0, by: -1) {
            var d = Int(n[i]) - Int(s[i]) - borrow
            if d < 0 { d += 256; borrow = 1 } else { borrow = 0 }
            out[i] = UInt8(d)
        }
        return raw.prefix(32) + Data(out)
    }

    @Test func enforcesStructuralRulesBetweenVersions() async throws {
        let h = try await history()
        // One item at revision 2, so a revision can be seen going backwards.
        let one = try h.vaults[3].items().first!
        let base = try await h.vaults[3].applying(upserts: [one], now: t0.addingTimeInterval(8)).vault
        let prev = base.snapshot.verified
        func resign(_ edit: (inout VaultManifest) -> Void) async throws -> SignedVaultManifest {
            var m = prev.manifest
            m.version += 1
            m.previousHash = prev.hash
            m.signerId = h.a.memberId
            edit(&m)
            return try await SignedVaultManifest.sign(m, with: h.a.signingKey)
        }
        func rejected(_ edit: (inout VaultManifest) -> Void, _ expected: VaultError? = nil) async throws {
            let signed = try await resign(edit)
            if let expected {
                #expect(throws: expected) { try VaultChainVerifier.verify(signed, after: prev) }
            } else {
                #expect(throws: VaultError.self) { try VaultChainVerifier.verify(signed, after: prev) }
            }
        }
        let bumped = prev.manifest.items.firstIndex { $0.revision == 2 }!
        // Item revision going backwards, or changing content without a new revision.
        try await rejected({ $0.items[bumped].revision = 1 }, .rollback)
        try await rejected { $0.items[0].blobHash = Data(repeating: 9, count: 32) }
        // Key check changing without a new epoch, or an epoch jump.
        try await rejected { $0.keyCheck = Data(repeating: 1, count: 32) }
        try await rejected { $0.epoch += 2; $0.keyCheck = Data(repeating: 1, count: 32) }
        // A member's envelope silently replaced, or two devices added at once.
        try await rejected { $0.members[0].envelopeHash = Data(repeating: 5, count: 32) }
        let c = VaultDeviceIdentity.software(), d = VaultDeviceIdentity.software()
        func newMember(_ id: VaultDeviceIdentity) -> VaultMember {
            VaultMember(role: .device, signingKey: id.signingPublicKey, agreementKey: id.agreementPublicKey, envelopeHash: Data(repeating: 4, count: 32), addedAt: 1, sealedLabel: Data(repeating: 1, count: 40))
        }
        try await rejected { $0.members += [newMember(c), newMember(d)] }
        // A device removing itself.
        try await rejected { $0.members.removeAll { $0.id == h.a.memberId } }
        // Removing a member without rotating the key keeps its envelope valid: refused only via rotation rules (envelope hash of others unchanged is fine,
        // but the removed member's access persists), so removal must come with a new epoch.
        let ok = try await resign { _ in }
        #expect(try VaultChainVerifier.verify(ok, after: prev).manifest.version == prev.manifest.version + 1)
    }

    @Test func manifestEncodingIsCanonicalAndStrict() async throws {
        let h = try await history()
        let m = try VaultManifest.decode(h.chain[3].manifestBytes)
        #expect(m.encoded() == h.chain[3].manifestBytes)
        // Reordered members/items, extra keys, a wrong version and trailing bytes are all refused.
        var shuffled = m
        shuffled.members.reverse()
        let value = try CBOR.decode(h.chain[3].manifestBytes)
        var entries = value.mapEntries!
        entries.append(.init(key: .text("zz"), value: .unsigned(1)))
        #expect(throws: VaultError.self) { try VaultManifest.decode(CBOR.encode(.map(entries), deterministic: true)) }
        #expect(throws: VaultError.self) { try VaultManifest.decode(h.chain[3].manifestBytes + Data([0])) }
        var futureEntries = value.mapEntries!
        futureEntries[futureEntries.firstIndex { $0.key == .text("v") }!].value = .unsigned(2)
        #expect(throws: VaultError.unsupportedVersion(2)) { try VaultManifest.decode(CBOR.encode(.map(futureEntries), deterministic: true)) }
        #expect(throws: VaultError.self) { try VaultManifest.decode(Data(repeating: 0, count: VaultFormat.maxManifestBytes + 1)) }
    }
}
