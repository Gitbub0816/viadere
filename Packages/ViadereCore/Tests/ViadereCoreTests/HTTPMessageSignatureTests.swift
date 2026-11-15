import Crypto
import Foundation
import Testing
@testable import ViadereCore

/// RFC 9421 request signatures, Viadere profile (SECURITY §2.112): the cross-language vectors (`docs/protocol/vectors/http-signatures-v1.json`,
/// generated independently in Python with deterministic RFC 6979 signatures) reproduced byte for byte, and every refusal of the profile.
@Suite("HTTP message signatures (RFC 9421 profile)")
struct HTTPMessageSignatureTests {
    struct Request: Decodable {
        var method: String
        var pathAndQuery: String
        var headers: [[String]]
        var body: String
        enum CodingKeys: String, CodingKey { case method, pathAndQuery = "path_and_query", headers, body }
    }
    struct Presenter: Decodable {
        var businessId: String, apiKeyId: String
        enum CodingKeys: String, CodingKey { case businessId = "business_id", apiKeyId = "api_key_id" }
    }
    struct Positive: Decodable {
        var name: String, request: Request, presenter: Presenter, signatureBase: String, signatureInput: String, signature: String
        var contentDigest: String?, signatureRaw: String, keyid: String, nonce: String, created: Int64
        enum CodingKeys: String, CodingKey {
            case name, request, presenter, signatureBase = "signature_base", signatureInput = "signature_input", signature, contentDigest = "content_digest"
            case signatureRaw = "signature_raw_b64url", keyid, nonce, created
        }
    }
    struct UsedNonce: Decodable { var scope: String, nonce: String }
    struct Negative: Decodable {
        var name: String, expectedError: String, request: Request, presenter: Presenter, usedNonces: [UsedNonce]?
        enum CodingKeys: String, CodingKey { case name, expectedError = "expected_error", request, presenter, usedNonces = "used_nonces" }
    }
    struct Key: Decodable {
        var keyid: String, publicKey: String, businessId: String, apiKeyId: String, revoked: Bool
        enum CodingKeys: String, CodingKey { case keyid, publicKey = "public_key", businessId = "business_id", apiKeyId = "api_key_id", revoked }
    }
    struct Vectors: Decodable {
        var now: Int64, acceptedAuthorities: [String], keys: [Key], signerPrivateKeyHex: String, positive: [Positive], negative: [Negative]
        enum CodingKeys: String, CodingKey {
            case now, acceptedAuthorities = "accepted_authorities", keys, signerPrivateKeyHex = "signer_private_key_hex", positive, negative
        }
    }

    static let vectors: Vectors = {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { url.deleteLastPathComponent() }
        return try! JSONDecoder().decode(Vectors.self, from: Data(contentsOf: url.appendingPathComponent("docs/protocol/vectors/http-signatures-v1.json")))
    }()

    static func request(_ r: Request) -> HTTPSignatureRequest {
        HTTPSignatureRequest(method: r.method, target: r.pathAndQuery, fields: r.headers.map { (name: $0[0], value: $0[1]) }, body: Data(r.body.utf8))
    }

    static func registered(_ keyId: String) throws -> HTTPSignatureVerifier.RegisteredKey? {
        guard let k = vectors.keys.first(where: { $0.keyid == keyId }) else { return nil }
        return .init(publicKey: try DevicePublicKey(base64URL: k.publicKey), businessId: k.businessId, apiKeyIds: [k.apiKeyId], revoked: k.revoked)
    }

    /// The whole profile: parse, key binding, signature, nonce.
    static func run(_ r: Request, presenter: Presenter, used: [UsedNonce] = [], now: Date? = nil) async throws {
        let guardStore = InMemoryReplayGuard()
        let clock = now ?? Date(timeIntervalSince1970: TimeInterval(vectors.now))
        for u in used { _ = try await guardStore.registerIfFresh(nonce: u.nonce, scope: u.scope, expiresAt: clock.addingTimeInterval(600), now: clock) }
        let parsed = try HTTPSignatureVerifier.parse(request(r), now: clock)
        _ = try await HTTPSignatureVerifier.verify(parsed, key: try registered(parsed.keyId), businessId: presenter.businessId, apiKeyId: presenter.apiKeyId,
                                                   authorities: vectors.acceptedAuthorities, replayGuard: guardStore, now: clock)
    }

    static var signer: SoftwareHTTPRequestSigningKey {
        try! SoftwareHTTPRequestSigningKey(keyId: "vsk_0123456789abcdef", rawRepresentation: Data(hexString: vectors.signerPrivateKeyHex)!)
    }

    @Test func thereAreVectorsForEveryRefusalCode() {
        #expect(Self.vectors.positive.count >= 5)
        let used = Set(Self.vectors.negative.map(\.expectedError))
        // Every code a request can trigger has a vector (`non_ascii` cannot be expressed in a JSON header string of the vectors).
        for code in HTTPSignatureError.allCases where code != .nonASCII { #expect(used.contains(code.rawValue), "no vector for \(code.rawValue)") }
    }

    @Test func positiveVectorsReproduceByteForByteAndVerify() async throws {
        for v in Self.vectors.positive {
            let parsed = try HTTPSignatureVerifier.parse(Self.request(v.request), now: Date(timeIntervalSince1970: TimeInterval(Self.vectors.now)))
            #expect(try parsed.signatureBase(authority: Self.vectors.acceptedAuthorities[0]) == v.signatureBase, "\(v.name)")
            try await Self.run(v.request, presenter: v.presenter)
        }
    }

    /// The signer writes exactly the vector's fields; with the vector's (deterministic) signature bytes it writes exactly its `Signature` too.
    @Test func signerWritesTheVectorFields() async throws {
        struct Fixed: HTTPRequestSigningKey {
            var keyId: String, publicKey: DevicePublicKey, raw: Data
            func sign(_ message: Data) async throws -> Data { raw }
        }
        for v in Self.vectors.positive where v.name != "parameters_reordered_with_alg" {
            let body = Data(v.request.body.utf8)
            let type = v.request.headers.first { $0[0] == "Content-Type" }?[1]
            let fixed = Fixed(keyId: v.keyid, publicKey: Self.signer.publicKey, raw: Base64URL.decode(v.signatureRaw)!)
            let fields = try await HTTPRequestSigner(key: fixed).sign(method: v.request.method, authority: "viadere.com", target: v.request.pathAndQuery,
                                                                     body: body.isEmpty ? nil : body, contentType: type,
                                                                     now: Date(timeIntervalSince1970: TimeInterval(v.created)), nonce: v.nonce)
            let byName = Dictionary(uniqueKeysWithValues: fields.map { ($0.name, $0.value) })
            #expect(byName["Signature-Input"] == v.signatureInput, "\(v.name)")
            #expect(byName["Signature"] == v.signature, "\(v.name)")
            #expect(byName["Content-Digest"] == v.contentDigest, "\(v.name)")
            // And a real (randomized) software signature verifies through the whole profile.
            let real = try await HTTPRequestSigner(key: Self.signer).sign(method: v.request.method, authority: "viadere.com", target: v.request.pathAndQuery,
                                                                         body: body.isEmpty ? nil : body, contentType: type,
                                                                         now: Date(timeIntervalSince1970: TimeInterval(Self.vectors.now)))
            var r = v.request
            r.headers = (type.map { [["Content-Type", $0]] } ?? []) + real.map { [$0.name, $0.value] }
            try await Self.run(r, presenter: v.presenter)
        }
    }

    @Test func everyNegativeVectorIsRefusedWithItsCode() async throws {
        for v in Self.vectors.negative {
            do {
                try await Self.run(v.request, presenter: v.presenter, used: v.usedNonces ?? [])
                Issue.record("\(v.name) was accepted")
            } catch let error as HTTPSignatureError {
                #expect(error.rawValue == v.expectedError, "\(v.name): \(error.rawValue)")
            }
        }
    }

    @Test func aNonceIsSingleUseAndScopedToTheKey() async throws {
        let v = Self.vectors.positive[0]
        let store = InMemoryReplayGuard()
        let now = Date(timeIntervalSince1970: TimeInterval(Self.vectors.now))
        let parsed = try HTTPSignatureVerifier.parse(Self.request(v.request), now: now)
        let key = try Self.registered(parsed.keyId)
        _ = try await HTTPSignatureVerifier.verify(parsed, key: key, businessId: v.presenter.businessId, apiKeyId: v.presenter.apiKeyId,
                                                   authorities: ["viadere.com"], replayGuard: store, now: now)
        await #expect(throws: HTTPSignatureError.replayed) {
            _ = try await HTTPSignatureVerifier.verify(parsed, key: key, businessId: v.presenter.businessId, apiKeyId: v.presenter.apiKeyId,
                                                       authorities: ["viadere.com"], replayGuard: store, now: now)
        }
    }

    @Test func aSignatureThatFailsDoesNotSpendTheNonce() async throws {
        let v = Self.vectors.positive[0]
        let store = InMemoryReplayGuard()
        let now = Date(timeIntervalSince1970: TimeInterval(Self.vectors.now))
        let parsed = try HTTPSignatureVerifier.parse(Self.request(v.request), now: now)
        await #expect(throws: HTTPSignatureError.badSignature) {
            _ = try await HTTPSignatureVerifier.verify(parsed, key: try Self.registered(parsed.keyId), businessId: v.presenter.businessId, apiKeyId: v.presenter.apiKeyId,
                                                       authorities: ["evil.example"], replayGuard: store, now: now)
        }
        #expect(await store.count == 0)
    }

    @Test func theSignerNormalizesHighSAndDERFromAKMS() async throws {
        struct KMS: HTTPRequestSigningKey {
            let inner: SoftwareHTTPRequestSigningKey
            var keyId: String { inner.keyId }
            var publicKey: DevicePublicKey { inner.publicKey }
            func sign(_ message: Data) async throws -> Data {
                // Return the high-S twin, DER-encoded, as some KMS APIs do.
                let raw = try await inner.sign(message)
                let low = ViadereSignatureEncoding.normalizedRaw(raw)
                var s = [UInt8](low[32...])
                let n: [UInt8] = [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                  0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51]
                var borrow = 0
                for i in stride(from: 31, through: 0, by: -1) {
                    var d = Int(n[i]) - Int(s[i]) - borrow
                    if d < 0 { d += 256; borrow = 1 } else { borrow = 0 }
                    s[i] = UInt8(d)
                }
                return try P256.Signing.ECDSASignature(rawRepresentation: Data(low[0..<32]) + Data(s)).derRepresentation
            }
        }
        let fields = try await HTTPRequestSigner(key: KMS(inner: Self.signer)).sign(method: "GET", authority: "viadere.com", target: "/v1/business/capabilities",
                                                                                   body: nil, contentType: nil, now: Date(timeIntervalSince1970: TimeInterval(Self.vectors.now)))
        let r = Request(method: "GET", pathAndQuery: "/v1/business/capabilities", headers: fields.map { [$0.name, $0.value] }, body: "")
        try await Self.run(r, presenter: Self.vectors.positive[0].presenter)
    }

    @Test func aSignerWhoseKeyDoesNotMatchIsRefusedBeforeSending() async throws {
        struct Wrong: HTTPRequestSigningKey {
            var keyId = "vsk_0123456789abcdef"
            var publicKey = DevicePublicKey(P256.Signing.PrivateKey().publicKey)
            func sign(_ message: Data) async throws -> Data { try P256.Signing.PrivateKey().signature(for: message).rawRepresentation }
        }
        await #expect(throws: HTTPSignatureSigningError.signatureDoesNotVerify) {
            _ = try await HTTPRequestSigner(key: Wrong()).sign(method: "GET", authority: "viadere.com", target: "/x", body: nil, contentType: nil)
        }
    }

    @Test func proofOfPossessionBindsTheChallengeAndTheKey() async throws {
        let proof = try await HTTPSigningKeyProof.prove(challenge: "c-1", key: Self.signer)
        #expect(HTTPSigningKeyProof.verify(proof: proof, challenge: "c-1", publicKey: Self.signer.publicKey))
        #expect(!HTTPSigningKeyProof.verify(proof: proof, challenge: "c-2", publicKey: Self.signer.publicKey))
        #expect(!HTTPSigningKeyProof.verify(proof: proof, challenge: "c-1", publicKey: DevicePublicKey(P256.Signing.PrivateKey().publicKey)))
    }

    @Test func authorityNormalization() {
        #expect(HTTPSignatureProfile.authority(of: URL(string: "https://Viadere.COM:443")!) == "viadere.com")
        #expect(HTTPSignatureProfile.authority(of: URL(string: "https://api.viadere.com:8443/")!) == "api.viadere.com:8443")
        #expect(HTTPSignatureProfile.authority(of: URL(string: "http://localhost:80")!) == "localhost")
        #expect(HTTPSignatureProfile.pathAndQuery("/a?b=c?d") == ("/a", "?b=c?d"))
        #expect(HTTPSignatureProfile.pathAndQuery("/a") == ("/a", "?"))
    }
}

private extension Data {
    init?(hexString: String) {
        var bytes: [UInt8] = []
        var index = hexString.startIndex
        while index < hexString.endIndex {
            let next = hexString.index(index, offsetBy: 2)
            guard let b = UInt8(hexString[index..<next], radix: 16) else { return nil }
            bytes.append(b)
            index = next
        }
        self.init(bytes)
    }
}
