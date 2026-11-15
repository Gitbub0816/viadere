@preconcurrency import Crypto
import Foundation
import Testing
@testable import ViadereCore

/// `passkey_added` members, the genesis App Attest binding and the JWE seal format (ADR-0023 §4, ADR-0032 §1.3, ADR-0034 §9). The RSA step is outside
/// Core (iOS `SecKey`, the authority's Key Vault); here a stand-in "encryption" pads the content key to 384 bytes so the format checks run alone.
@Suite("Authority passkey and JWE seal formats")
struct AuthorityPasskeyAndJWEFormatTests {
    static func fakeRSA(_ cek: Data) -> Data { cek + Data(repeating: 0xA5, count: RecoverySealJWE.encryptedKeyBytes - cek.count) }
    static func fakeRSAOpen(_ encrypted: Data) -> Data { encrypted.prefix(32) }

    @Test func strictBase64URLHasOneTextForm() {
        #expect(AuthorityKeyLogFormat.strictBytes("QQ") == Data([0x41]))
        for refused in ["QQ==", "QR", "Q", "Q+", "Q/", "", "QQ "] { #expect(AuthorityKeyLogFormat.strictBytes(refused) == nil, "\(refused)") }
        #expect(AuthorityKeyLogFormat.strictBytes("QUFB", minBytes: 4) == nil)
        #expect(AuthorityKeyLogFormat.strictBytes("QUFB", maxBytes: 2) == nil)
    }

    @Test func passkeyAddedParsesOnlyCanonicalES256AndStrictIds() throws {
        let key = P256.Signing.PrivateKey().publicKey
        let cose = WebAuthnAuthenticator.coseES256(key)
        let id = Base64URL.encode(SecureToken.randomBytes(32))
        let added = try #require(AuthorityPasskeyAdded.parse(credentialId: id, publicKey: Base64URL.encode(cose)))
        // The kid is the SPKI KeyIdentifier of the COSE key (ADR-0023 §2), the same as a device key's.
        #expect(added.kid == KeyIdentifier.make(key))
        #expect(AuthorityKeyLogFormat.passkeyKid(cose: cose) == added.kid)
        var eddsa = cose
        eddsa[4] = 0x27
        #expect(PasskeyCOSE.es256PublicKey(eddsa) == nil)
        #expect(AuthorityPasskeyAdded.parse(credentialId: id + "=", publicKey: Base64URL.encode(cose)) == nil)
        #expect(AuthorityPasskeyAdded.parse(credentialId: Base64URL.encode(Data(repeating: 1, count: 15)), publicKey: Base64URL.encode(cose)) == nil)
        #expect(AuthorityPasskeyAdded.parse(credentialId: Base64URL.encode(Data(repeating: 1, count: 1024)), publicKey: Base64URL.encode(cose)) == nil)
        #expect(AuthorityPasskeyAdded.parse(credentialId: id, publicKey: cose.base64EncodedString()) == nil) // 77 bytes: always padded
        #expect(AuthorityPasskeyAdded.parse(credentialId: id, publicKey: Base64URL.encode(eddsa)) == nil)
        // The display: the fixed label and exactly the new kid.
        let display = AuthorityDisplay.passkeyAdded(kid: added.kid)
        #expect(display.objectValue?["label"]?.stringValue == "New passkey on this phone")
        #expect(display.objectValue?["kids"] == .array([.string(added.kid)]))
    }

    @Test func genesisAttestationBindsEnvironmentNonceAndEveryKid() {
        let nonce = AuthorityNonce.generate()
        let kids = [KeyIdentifier.make(P256.Signing.PrivateKey().publicKey), KeyIdentifier.make(P256.Signing.PrivateKey().publicKey)]
        let hash = AuthorityKeyLogFormat.genesisAttestationClientDataHash(environment: .staging, nonce: nonce, kids: kids)
        #expect(hash == AuthorityKeyLogFormat.genesisAttestationClientDataHash(environment: .staging, nonce: nonce, kids: kids.reversed()))
        #expect(hash != AuthorityKeyLogFormat.genesisAttestationClientDataHash(environment: .production, nonce: nonce, kids: kids))
        #expect(hash != AuthorityKeyLogFormat.genesisAttestationClientDataHash(environment: .staging, nonce: AuthorityNonce.generate(), kids: kids))
        #expect(hash != AuthorityKeyLogFormat.genesisAttestationClientDataHash(environment: .staging, nonce: nonce, kids: [kids[0]]))
        let text = String(decoding: AuthorityKeyLogFormat.genesisAttestationClientData(environment: .staging, nonce: nonce, kids: kids), as: UTF8.self)
        #expect(text.hasPrefix("VIADERE-KEYLOG-ATTEST-V1\n" + AuthorityEnvironment.staging.rawValue + "\ngenesis\n" + nonce + "\n"))
    }

    @Test func jweRoundTripsAndEveryHeaderMemberIsAuthenticated() throws {
        let ach = AuthorityChallengeID.generate(), nonce = AuthorityNonce.generate()
        let kid = Base64URL.encode(SecureToken.randomBytes(32))
        let plaintext = RecoverySeal.startPlaintext(recoveryId: "ABCDEFGHJKMN", nonce: nonce, code: RecoverySeal.generateCodes()[0],
                                                    newKids: [KeyIdentifier.make(P256.Signing.PrivateKey().publicKey)])
        let envelope = try RecoverySealJWE.seal(plaintext, kid: kid, purpose: .start, environment: .staging, challengeId: ach, nonce: nonce, encryptKey: Self.fakeRSA)
        #expect(envelope.compact.split(separator: ".").count == 5)
        #expect(envelope.type == "viadere-recovery-start+jwe")
        #expect(envelope.purpose == .start)
        #expect(envelope.digest == Base64URL.encode(Data(SHA256.hash(data: Data(envelope.compact.utf8)))))
        try RecoverySealJWE.check(envelope, kid: kid, purpose: .start, environment: .staging, challengeId: ach, nonce: nonce)
        #expect(try RecoverySealJWE.open(envelope, contentKey: Self.fakeRSAOpen(envelope.encryptedKey)) == plaintext.objectValue!)
        // Header binding (checked before the HSM is asked): purpose, environment, challenge, nonce, key.
        #expect(throws: RecoverySealError.self) { try RecoverySealJWE.check(envelope, kid: kid, purpose: .codesSet, environment: .staging, challengeId: ach, nonce: nonce) }
        #expect(throws: RecoverySealError.self) { try RecoverySealJWE.check(envelope, kid: kid, purpose: .start, environment: .production, challengeId: ach, nonce: nonce) }
        #expect(throws: RecoverySealError.self) {
            try RecoverySealJWE.check(envelope, kid: kid, purpose: .start, environment: .staging, challengeId: AuthorityChallengeID.generate(), nonce: nonce)
        }
        #expect(throws: RecoverySealError.self) { try RecoverySealJWE.check(envelope, kid: kid, purpose: .start, environment: .staging, challengeId: ach, nonce: AuthorityNonce.generate()) }
        #expect(throws: RecoverySealError.wrongKey) { try RecoverySealJWE.check(envelope, kid: Base64URL.encode(SecureToken.randomBytes(32)), purpose: .start, environment: .staging, challengeId: ach, nonce: nonce) }
        // A header rewritten to name another challenge parses, but the AAD no longer matches: nothing opens.
        let parts = envelope.compact.split(separator: ".").map(String.init)
        let other = Base64URL.encode(try CanonicalJSON.serialize(RecoverySealJWE.header(kid: kid, purpose: .start, environment: .staging, challengeId: AuthorityChallengeID.generate(), nonce: nonce)))
        let swapped = try RecoverySealJWE.parse(([other] + parts.dropFirst()).joined(separator: "."))
        #expect(throws: RecoverySealError.openFailed) { try RecoverySealJWE.open(swapped, contentKey: Self.fakeRSAOpen(envelope.encryptedKey)) }
        // A wrong or short content key: the same answer.
        #expect(throws: RecoverySealError.openFailed) { try RecoverySealJWE.open(envelope, contentKey: Data(repeating: 0, count: 32)) }
        #expect(throws: RecoverySealError.openFailed) { try RecoverySealJWE.open(envelope, contentKey: Data(repeating: 0, count: 16)) }
    }

    @Test func jweParseIsStrict() throws {
        let ach = AuthorityChallengeID.generate(), nonce = AuthorityNonce.generate(), kid = Base64URL.encode(SecureToken.randomBytes(32))
        let envelope = try RecoverySealJWE.seal(.object(["v": .integer(1), "pad": .string("at least seventeen bytes")]), kid: kid, purpose: .codesSet, environment: .staging, challengeId: ach, nonce: nonce,
                                                encryptKey: Self.fakeRSA)
        let parts = envelope.compact.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        func header(_ mutate: (inout [String: JSONValue]) -> Void) throws -> String {
            var h = RecoverySealJWE.header(kid: kid, purpose: .codesSet, environment: .staging, challengeId: ach, nonce: nonce).objectValue!
            mutate(&h)
            return ([Base64URL.encode(try CanonicalJSON.serialize(.object(h)))] + parts.dropFirst()).joined(separator: ".")
        }
        let refused: [String] = [
            parts.dropLast().joined(separator: "."),                                         // four parts
            envelope.compact + ".",                                                           // six parts
            ([parts[0], Base64URL.encode(Data(repeating: 1, count: 256))] + parts.dropFirst(2)).joined(separator: "."), // RSA 2048 key
            ([parts[0], parts[1], Base64URL.encode(Data(repeating: 1, count: 16))] + parts.dropFirst(3)).joined(separator: "."), // IV not 12 bytes
            (parts.dropLast() + [Base64URL.encode(Data(repeating: 1, count: 12))]).joined(separator: "."), // tag not 16 bytes
            ([parts[0] + "="] + parts.dropFirst()).joined(separator: "."),                    // padding
            try header { $0["zip"] = .string("DEF") },
            try header { $0["jku"] = .string("https://evil.example/jwks") },
            try header { $0["alg"] = .string("RSA-OAEP") },
            try header { $0["alg"] = .string("dir") },
            try header { $0["enc"] = .string("A128GCM") },
            try header { $0["typ"] = .string("JWT") },
            try header { $0["env"] = .string("development") },
            try header { $0["ach"] = nil },
            String(repeating: "A", count: 4097),
        ]
        for compact in refused { #expect(throws: RecoverySealError.self, "\(compact.prefix(40))") { try RecoverySealJWE.parse(compact) } }
        // A header that is valid JSON but not canonical (spaces, another member order) is refused: one text form.
        let loose = Base64URL.encode(Data("{ \"alg\":\"RSA-OAEP-256\"}".utf8))
        #expect(throws: RecoverySealError.self) { try RecoverySealJWE.parse(([loose] + parts.dropFirst()).joined(separator: ".")) }
        #expect(try RecoverySealJWE.parse(envelope.compact) == envelope)
    }
}
