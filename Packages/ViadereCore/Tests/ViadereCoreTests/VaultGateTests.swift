import Crypto
import Foundation
import Testing
@testable import ViadereCore

/// Phase 4 gate review: exploit-reproducing tests (M3, L4). Each failed before its fix.
private let g0 = Date(timeIntervalSince1970: 1_800_000_000)

private func smallTotp(_ index: Int) -> VaultItemPayload {
    VaultItemPayload(body: .totp(TOTPParameters(secret: Data("12345678901234567890".utf8), issuer: "Example", accountName: "user\(index)@example.com")), createdAt: g0)
}

/// A passkey item whose user name fills the blob up to about `bytes` (what a hostile relying party could have made before names were cut).
private func bigPasskey(userNameBytes: Int) -> VaultItemPayload {
    let credential = PasskeyCredential(credentialId: SecureToken.randomBytes(32), rpId: "example.com", userHandle: Data([1]), userName: String(repeating: "a", count: userNameBytes),
                                       displayName: nil, privateKey: SecureToken.randomBytes(32), createdAt: g0)
    return VaultItemPayload(body: .passkey(credential), createdAt: g0)
}

private func requestBytes(_ mutation: VaultMutation) throws -> Int {
    let body = VaultPutRequest(expectedVersion: 1, manifest: VaultManifestDTO(mutation.delta.manifest),
                               blobs: mutation.delta.blobs.map { VaultBlobDTO(itemId: $0.key, blob: Base64URL.encode($0.value)) },
                               envelopes: mutation.delta.envelopes.map { VaultEnvelopeDTO(memberId: $0.key, envelope: Base64URL.encode($0.value)) })
    return try ViadereJSON.encode(body).count
}

@Suite("Vault gate review (Core)")
struct VaultGateCoreTests {
    // MARK: M3

    @Test func userAndDisplayNamesAreCutToSixtyFourBytesOnACharacterBoundary() throws {
        let hostile = String(repeating: "\u{1F600}", count: 8_000)  // 4 bytes each: 32,000 bytes
        let made = try WebAuthnAuthenticator.makeCredential(rpId: "example.com", userHandle: Data([1]), userName: hostile, displayName: hostile,
                                                            clientDataHash: Data(repeating: 1, count: 32), requireUserVerification: true, userVerified: true, backedUp: true, now: g0)
        #expect(made.credential.userName.utf8.count <= 64 && !made.credential.userName.isEmpty)
        #expect((made.credential.displayName ?? "").utf8.count <= 64)
        #expect(String(decoding: Data(made.credential.userName.utf8), as: UTF8.self) == made.credential.userName, "no split character")
        let blob = try VaultItemBlob.seal(VaultItemPayload(body: .passkey(made.credential), createdAt: g0), vaultId: UUID(), epoch: 1, revision: 1, vaultKey: .generate())
        #expect(blob.count <= 1024, "one hostile registration cannot make a 32 KiB item")
    }

    @Test func aRotationOfTwoThousandItemsFitsOneRequest() async throws {
        let a = VaultDeviceIdentity.software()
        let items = (0..<VaultFormat.maxItems).map(smallTotp)
        let created = try await UnlockedVault.create(identity: a, label: "Phone", recoveryKey: .generate(), items: items, now: g0)
        #expect(created.vault.manifest.items.count == 2000)
        let rotation = try await created.vault.settingRecoveryKey(.generate(), rotateKey: true, now: g0.addingTimeInterval(1))
        #expect(rotation.vault.manifest.epoch == 2 && rotation.delta.blobs.count == 2000)
        #expect(try requestBytes(rotation) <= VaultFormat.maxRotationRequestBytes)
        #expect(VaultFormat.maxRotationRequestBytes <= 4 * 1_048_576, "the server's body ceiling for vault routes is 4 MiB")
    }

    @Test func totalCiphertextIsCappedSoARotationAlwaysFits() async throws {
        let a = VaultDeviceIdentity.software()
        // Fill the vault with the largest items the format allows until the cap; the next one is refused with a clear error.
        let largest = (0..<(VaultFormat.maxTotalBlobBytes / VaultFormat.maxItemBlobBytes)).map { _ in bigPasskey(userNameBytes: 32_000) }
        var vault = try await UnlockedVault.create(identity: a, label: "Phone", recoveryKey: .generate(), items: Array(largest.prefix(1)), now: g0).vault
        let rest = Array(largest.dropFirst())
        vault = try await vault.applying(upserts: rest, now: g0.addingTimeInterval(1)).vault
        let total = vault.snapshot.blobs.values.reduce(0) { $0 + $1.count }
        #expect(total <= VaultFormat.maxTotalBlobBytes)
        await #expect(throws: VaultError.limitExceeded("vault size")) { try await vault.applying(upserts: [bigPasskey(userNameBytes: 32_000)], now: g0.addingTimeInterval(2)) }
        // Deleting makes room again.
        let id = try #require(vault.manifest.items.first?.itemId)
        let freed = try await vault.applying(upserts: [bigPasskey(userNameBytes: 1_000)], deletes: [id], now: g0.addingTimeInterval(3))
        #expect(freed.vault.manifest.items.count == vault.manifest.items.count)
        // The full vault still rotates inside the request ceiling.
        let rotation = try await vault.settingRecoveryKey(.generate(), rotateKey: true, now: g0.addingTimeInterval(4))
        #expect(try requestBytes(rotation) <= VaultFormat.maxRotationRequestBytes)
        // Creating over the cap is refused too.
        await #expect(throws: VaultError.limitExceeded("vault size")) {
            try await UnlockedVault.create(identity: a, label: "Phone", items: (0...(VaultFormat.maxTotalBlobBytes / VaultFormat.maxItemBlobBytes)).map { _ in bigPasskey(userNameBytes: 32_000) }, now: g0)
        }
    }

    // MARK: L4

    @Test func removingADeviceWithoutRotatingTheKeyIsRefused() async throws {
        let a = VaultDeviceIdentity.software(), b = VaultDeviceIdentity.software()
        let first = try await UnlockedVault.create(identity: a, label: "Phone", items: [smallTotp(1)], now: g0).vault
        let secret = PairingSecret.generate()
        let joined = try await first.approvingJoin(try JoinRequest.open(try JoinRequest.make(for: b, label: "iPad").sealed(with: secret), with: secret), secret: secret, now: g0.addingTimeInterval(1)).vault
        // The device simply disappears from the member list while the epoch and every envelope stay: its envelope still opens the key.
        var m = joined.manifest
        m.version += 1
        m.previousHash = joined.snapshot.verified.hash
        m.signerId = a.memberId
        m.members.removeAll { $0.id == b.memberId }
        let signed = try await SignedVaultManifest.sign(m, with: a.signingKey)
        #expect(throws: VaultError.invalidChain("a removed device requires a key rotation")) { try VaultChainVerifier.verify(signed, after: joined.snapshot.verified) }
        // The honest removal rotates and passes.
        let honest = try await joined.removingDevice(b.memberId, now: g0.addingTimeInterval(2))
        #expect(honest.vault.manifest.epoch == 2)
    }
}
