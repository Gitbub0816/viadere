@preconcurrency import Crypto
import Foundation
import Testing
@testable import ViadereCore

/// Key-log formats (ADR-0033 §2, §4.1, §5), the pinned-key mechanism (ADR-0033 §3.1, ADR-0034 §5.4, §10.4) and sealed recovery envelopes (ADR-0034).
@Suite("Authority key log formats")
struct AuthorityKeyLogCoreTests {
    static let now = Date(timeIntervalSince1970: 1_800_000_000)

    static func slot(_ key: P256.Signing.PublicKey) -> AuthorityPinnedKeys.Slot {
        let raw = key.rawRepresentation
        return .init(x: Base64URL.encode(raw.prefix(32)), y: Base64URL.encode(raw.suffix(32)))
    }

    // MARK: Pins

    @Test func unfilledPinsFailClosed() {
        // The shipped table holds owner placeholders: nothing resolves, so every statement and every seal is refused.
        for environment in AuthorityEnvironment.allCases {
            #expect(AuthorityPinnedKeys.deviceStatementKeys(environment).isEmpty)
            #expect(AuthorityPinnedKeys.deviceStatementKids(environment).isEmpty)
            #expect(AuthorityPinnedKeys.sealKeys(environment).isEmpty)
            #expect(!AuthorityPinnedKeys.isProvisioned(environment))
        }
        #expect(AuthorityPinnedKeys.resolve([.unfilled, .unfilled]) == nil)
    }

    @Test func pinsResolveAllOrNothing() {
        let a = P256.Signing.PrivateKey().publicKey, b = P256.Signing.PrivateKey().publicKey
        #expect(AuthorityPinnedKeys.resolve([Self.slot(a), Self.slot(b)])?.count == 2)
        // One placeholder, one malformed slot, a duplicate, or more than two slots empties the list.
        #expect(AuthorityPinnedKeys.resolve([Self.slot(a), .unfilled]) == nil)
        #expect(AuthorityPinnedKeys.resolve([Self.slot(a), .init(x: "AAAA", y: "BBBB")]) == nil)
        #expect(AuthorityPinnedKeys.resolve([Self.slot(a), Self.slot(a)]) == nil)
        #expect(AuthorityPinnedKeys.resolve([Self.slot(a), Self.slot(b), Self.slot(P256.Signing.PrivateKey().publicKey)]) == nil)
        // A point that is not on the curve.
        #expect(AuthorityPinnedKeys.resolve([.init(x: Base64URL.encode(Data(repeating: 1, count: 32)), y: Base64URL.encode(Data(repeating: 2, count: 32)))]) == nil)
    }

    /// ADR-0034 §10.4: a key pinned for staging can never be a production pin (and vice versa).
    @Test func aKeyPinnedInBothEnvironmentsIsRefusedInBoth() {
        let shared = P256.Signing.PrivateKey().publicKey, own = P256.Signing.PrivateKey().publicKey
        let table: [AuthorityEnvironment: [AuthorityPinnedKeys.Slot]] = [.staging: [Self.slot(shared)], .production: [Self.slot(own), Self.slot(shared)]]
        #expect(AuthorityPinnedKeys.resolved(table, .staging).isEmpty)
        #expect(AuthorityPinnedKeys.resolved(table, .production).isEmpty)
        let clean: [AuthorityEnvironment: [AuthorityPinnedKeys.Slot]] = [.staging: [Self.slot(shared)], .production: [Self.slot(own)]]
        #expect(AuthorityPinnedKeys.resolved(clean, .production).count == 1)
        // The shipped table never shares a key between environments.
        #expect(Set(AuthorityPinnedKeys.deviceStatementKids(.staging)).isDisjoint(with: AuthorityPinnedKeys.deviceStatementKids(.production)))
        #expect(Set(AuthorityPinnedKeys.sealKids(.staging)).isDisjoint(with: AuthorityPinnedKeys.sealKids(.production)))
    }

    // MARK: Static discovery (ADR-0024 §7, S6-10)

    /// `authority-publish.yml` fills the issuer into this template; it must stay byte-identical to Core's discovery document, so the published
    /// document is Core's and nothing else.
    @Test func publishedDiscoveryTemplateIsCoresDocument() throws {
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { root.deleteLastPathComponent() }
        let template = try String(contentsOf: root.appendingPathComponent("Infra/azure-authority/publish/openid-configuration.template.json"), encoding: .utf8)
        #expect(template == String(decoding: try CanonicalJSON.serialize(OIDCProfile.discoveryDocument(issuer: "{{ISSUER}}")), as: UTF8.self))
        let filled = template.replacingOccurrences(of: "{{ISSUER}}", with: "https://id.staging.example")
        #expect(filled == String(decoding: try CanonicalJSON.serialize(OIDCProfile.discoveryDocument(issuer: "https://id.staging.example")), as: UTF8.self))
    }

    // MARK: Chain, PoP, comparison code

    @Test func entryHashIsDomainSeparatedAndCoversPrevHash() throws {
        let entry: [String: JSONValue] = ["account_ref": .string("acct_" + String(repeating: "a", count: 32)), "seq": .integer(0), "type": .string("genesis"),
                                          "kid": .string("k"), "public_key": .string("p"), "key_purpose": .string("approvalBiometric"), "detail": .object([:]),
                                          "created_at": .integer(1), "prev_hash": .string(AuthorityKeyLogFormat.zeroHash)]
        let hash = try AuthorityKeyLogFormat.entryHash(entry)
        #expect(hash == SecureToken.sha256Hex(Data("VIADERE-KEYLOG-ENTRY-V1\n".utf8) + (try CanonicalJSON.serialize(.object(entry)))))
        var other = entry
        other["prev_hash"] = .string(String(repeating: "1", count: 64))
        #expect(try AuthorityKeyLogFormat.entryHash(other) != hash)
    }

    @Test func popIsBoundToEnvironmentTypeKidAndNonce() async throws {
        let key = SoftwareP256SigningKey()
        let kid = KeyIdentifier.make(try key.publicKey.signingKey())
        let message = AuthorityKeyLogFormat.popMessage(environment: .staging, type: "genesis", kid: kid, nonce: "n")
        #expect(String(decoding: message, as: UTF8.self) == "VIADERE-KEYLOG-V1\nstg\ngenesis\n\(kid)\nn")
        let pop = try await AuthorityKeyLogFormat.signPoP(key, message: message)
        #expect(AuthorityKeyLogFormat.verifyPoP(pop, key: try key.publicKey.signingKey(), message: message))
        for wrong in [AuthorityKeyLogFormat.popMessage(environment: .production, type: "genesis", kid: kid, nonce: "n"),
                      AuthorityKeyLogFormat.popMessage(environment: .staging, type: "device_added", kid: kid, nonce: "n"),
                      AuthorityKeyLogFormat.popMessage(environment: .staging, type: "genesis", kid: kid, nonce: "m")] {
            #expect(!AuthorityKeyLogFormat.verifyPoP(pop, key: try key.publicKey.signingKey(), message: wrong))
        }
    }

    /// ADR-0033 §4.1 item 4: decimal6 of the first 8 bytes, sorted kids (vector computed independently in Python).
    @Test func comparisonCodeVector() {
        let code = AuthorityDeviceAddCode.code(environment: .staging, nonce: "bm9uY2U", kids: ["b", "a"])
        #expect(code == "526042")
        #expect(code.count == 6)
        #expect(AuthorityDeviceAddCode.code(environment: .staging, nonce: "bm9uY2U", kids: ["a", "b"]) == code)
        #expect(AuthorityDeviceAddCode.code(environment: .production, nonce: "bm9uY2U", kids: ["a", "b"]) != code)
    }

    static func decimal6(_ input: String) -> UInt64 {
        Array(SHA256.hash(data: Data(input.utf8))).prefix(8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) } % 1_000_000
    }

    // MARK: Heads

    static func signedHead(_ head: AuthorityKeyLogHead, key: P256.Signing.PrivateKey, typ: String = AuthorityKeyLogHead.type) throws -> String {
        let input = try AuthorityJWS.signingInput(alg: "ES256", kid: JWKThumbprint.p256(key.publicKey), typ: typ, payload: head.payload)
        return input + "." + ViadereSignatureEncoding.encode(try key.signature(for: Data(input.utf8)))
    }

    static func head(seq: Int64 = 3, issuedAt: Int64 = Int64(now.timeIntervalSince1970), keys: [AuthorityKeyLogHead.Key]) -> AuthorityKeyLogHead {
        AuthorityKeyLogHead(environment: .staging, accountRef: "acct_" + String(repeating: "b", count: 32), seq: seq, headHash: String(repeating: "c", count: 64),
                            keys: keys, pendingRecoveries: [], recoverySet: "none", issuedAt: issuedAt)
    }

    @Test func headChecks() throws {
        let signer = P256.Signing.PrivateKey()
        let own = KeyIdentifier.make(P256.Signing.PrivateKey().publicKey), attacker = KeyIdentifier.make(P256.Signing.PrivateKey().publicKey)
        let k = { (kid: String, imported: Bool) in AuthorityKeyLogHead.Key(kid: kid, purpose: "approvalBiometric", usableFrom: 0, entryType: imported ? "imported" : "genesis",
                                                                           imported: imported, grantCapable: false) }
        let good = try Self.signedHead(Self.head(keys: [k(own, false)]), key: signer)
        let verified = try AuthorityStatementVerifier.verifyHead(good, pinnedKeys: [signer.publicKey], environment: .staging, ownKids: [own], minimumSeq: 3, now: Self.now)
        try AuthorityStatementVerifier.requireExactEntry(verified, ownKids: [own])
        // Rollback, staleness, another account, wrong typ, unpinned signer, revoked signer.
        #expect(throws: AuthorityStatementVerifier.HeadError.rollback) {
            try AuthorityStatementVerifier.verifyHead(good, pinnedKeys: [signer.publicKey], environment: .staging, ownKids: [own], minimumSeq: 4, now: Self.now)
        }
        #expect(throws: AuthorityStatementVerifier.HeadError.stale) {
            try AuthorityStatementVerifier.verifyHead(good, pinnedKeys: [signer.publicKey], environment: .staging, ownKids: [own], minimumSeq: 0, now: Self.now.addingTimeInterval(901))
        }
        #expect(throws: AuthorityStatementVerifier.HeadError.notMyAccount) {
            try AuthorityStatementVerifier.verifyHead(good, pinnedKeys: [signer.publicKey], environment: .staging, ownKids: [attacker], minimumSeq: 0, now: Self.now)
        }
        #expect(throws: AuthorityJOSEError.wrongType) {
            try AuthorityStatementVerifier.verifyHead(try Self.signedHead(Self.head(keys: [k(own, false)]), key: signer, typ: AuthorityChallengeStatement.type),
                                                      pinnedKeys: [signer.publicKey], environment: .staging, ownKids: [own], minimumSeq: 0, now: Self.now)
        }
        #expect(throws: AuthorityJOSEError.unknownKey) {
            try AuthorityStatementVerifier.verifyHead(good, pinnedKeys: [P256.Signing.PrivateKey().publicKey], environment: .staging, ownKids: [own], minimumSeq: 0, now: Self.now)
        }
        #expect(throws: AuthorityJOSEError.unknownKey) {
            try AuthorityStatementVerifier.verifyHead(good, pinnedKeys: [signer.publicKey], revokedKids: [JWKThumbprint.p256(signer.publicKey)], environment: .staging,
                                                      ownKids: [own], minimumSeq: 0, now: Self.now)
        }
        // An attacker key in the same unconfirmed entry: the device refuses to confirm (ADR-0032 §1.4).
        let mixed = try AuthorityStatementVerifier.verifyHead(try Self.signedHead(Self.head(keys: [k(own, false), k(attacker, false)]), key: signer),
                                                              pinnedKeys: [signer.publicKey], environment: .staging, ownKids: [own], minimumSeq: 0, now: Self.now)
        #expect(throws: AuthorityStatementVerifier.HeadError.entryMismatch) { try AuthorityStatementVerifier.requireExactEntry(mixed, ownKids: [own]) }
        // Imported accounts only need to contain the device's keys.
        let imported = try AuthorityStatementVerifier.verifyHead(try Self.signedHead(Self.head(keys: [k(own, true), k(attacker, true)]), key: signer),
                                                                 pinnedKeys: [signer.publicKey], environment: .staging, ownKids: [own], minimumSeq: 0, now: Self.now)
        try AuthorityStatementVerifier.requireExactEntry(imported, ownKids: [own])
    }

    @Test func keyLogMembersOnlyOnKeyLogStatements() throws {
        let signer = P256.Signing.PrivateKey()
        let kid = KeyIdentifier.make(P256.Signing.PrivateKey().publicKey)
        func sign(_ statement: AuthorityChallengeStatement) throws -> String {
            let input = try AuthorityJWS.signingInput(alg: "ES256", kid: JWKThumbprint.p256(signer.publicKey), typ: AuthorityChallengeStatement.type, payload: statement.payload)
            return input + "." + ViadereSignatureEncoding.encode(try signer.signature(for: Data(input.utf8)))
        }
        let t = Int64(Self.now.timeIntervalSince1970)
        let deviceAdd = AuthorityChallengeStatement(environment: .staging, challengeId: AuthorityChallengeID.generate(), nonce: AuthorityNonce.generate(),
                                                    purpose: .keylogDeviceAdded, display: AuthorityDisplay.deviceAdded(reportedName: "Tablet", kids: [kid]),
                                                    matchRequired: true, issuedAt: t, expiresAt: t + 120, accountRef: "acct_" + String(repeating: "d", count: 32), kids: [kid])
        let parsed = try AuthorityStatementVerifier.verifyChallenge(try sign(deviceAdd), pinnedKeys: [signer.publicKey], environment: .staging, now: Self.now)
        #expect(parsed.kids == [kid])
        // `kids` on a link statement is refused.
        var link = AuthorityChallengeStatement(environment: .staging, challengeId: AuthorityChallengeID.generate(), nonce: AuthorityNonce.generate(), purpose: .linkOpen,
                                               display: AuthorityDisplay.linkOpen(tenantName: "T", clientName: "C", returnURL: "https://a.example/r", matchDigits: nil),
                                               returnURL: "https://a.example/r", matchRequired: false, issuedAt: t, expiresAt: t + 120)
        link.kids = [kid]
        #expect(throws: AuthorityJOSEError.claims("kids")) {
            try AuthorityStatementVerifier.verifyChallenge(try sign(link), pinnedKeys: [signer.publicKey], environment: .staging, now: Self.now)
        }
    }

    // MARK: Sealed envelopes (ADR-0034 §1, §2, §7)

    @Test func sealedSetOpensOnlyForItsPurposeEnvironmentAndChallenge() throws {
        let seal = P256.KeyAgreement.PrivateKey()
        let ach = AuthorityChallengeID.generate(), nonce = AuthorityNonce.generate()
        let plaintext = RecoverySeal.setPlaintext(accountRef: "acct_" + String(repeating: "e", count: 32), setId: RecoverySeal.generateSetId(), nonce: nonce,
                                                  codes: RecoverySeal.generateCodes())
        let envelope = try RecoverySeal.seal(plaintext, to: seal.publicKey, purpose: .codesSet, environment: .staging, challengeId: ach, nonce: nonce)
        let opened = try RecoverySeal.open(envelope, with: seal, purpose: .codesSet, environment: .staging, challengeId: ach, nonce: nonce)
        #expect(try RecoverySeal.parseSet(opened).codes.count == 10)
        #expect(throws: RecoverySealError.openFailed) { try RecoverySeal.open(envelope, with: seal, purpose: .start, environment: .staging, challengeId: ach, nonce: nonce) }
        #expect(throws: RecoverySealError.openFailed) { try RecoverySeal.open(envelope, with: seal, purpose: .codesSet, environment: .production, challengeId: ach, nonce: nonce) }
        #expect(throws: RecoverySealError.openFailed) {
            try RecoverySeal.open(envelope, with: seal, purpose: .codesSet, environment: .staging, challengeId: AuthorityChallengeID.generate(), nonce: nonce)
        }
        var tampered = envelope
        tampered.ct[0] ^= 1
        #expect(throws: RecoverySealError.openFailed) { try RecoverySeal.open(tampered, with: seal, purpose: .codesSet, environment: .staging, challengeId: ach, nonce: nonce) }
        #expect(throws: RecoverySealError.wrongKey) {
            try RecoverySeal.open(envelope, with: P256.KeyAgreement.PrivateKey(), purpose: .codesSet, environment: .staging, challengeId: ach, nonce: nonce)
        }
        // The digest commits to enc ‖ ct; the wire form is exact.
        #expect(tampered.digest != envelope.digest)
        #expect(try RecoverySealEnvelope.parse(envelope.json) == envelope)
        var extra = envelope.json.objectValue!
        extra["aad"] = .string("x")
        #expect(throws: RecoverySealError.self) { try RecoverySealEnvelope.parse(.object(extra)) }
    }

    @Test func plaintextsAreStrict() throws {
        let nonce = AuthorityNonce.generate()
        var codes = RecoverySeal.generateCodes()
        #expect(throws: RecoverySealError.self) {
            try RecoverySeal.parseSet(RecoverySeal.setPlaintext(accountRef: "a", setId: RecoverySeal.generateSetId(), nonce: nonce, codes: Array(codes.prefix(9))).objectValue!)
        }
        codes[1] = codes[0]
        #expect(throws: RecoverySealError.self) {
            try RecoverySeal.parseSet(RecoverySeal.setPlaintext(accountRef: "a", setId: RecoverySeal.generateSetId(), nonce: nonce, codes: codes).objectValue!)
        }
        let kid = KeyIdentifier.make(P256.Signing.PrivateKey().publicKey)
        var start = RecoverySeal.startPlaintext(recoveryId: "ABCDEFGHJKMN", nonce: nonce, code: "ABCDE12345", newKids: [kid]).objectValue!
        #expect(try RecoverySeal.parseStart(start).newKids == [kid])
        start["code"] = .string("abcde-12345")
        #expect(throws: RecoverySealError.self) { try RecoverySeal.parseStart(start) }
    }
}
