@preconcurrency import Crypto
import Foundation
import XCTest
import ViadereCore
@testable import ViadereBusinessSDK

/// RFC 9421 request signing in the Swift business SDK (SECURITY §2.112): the cross-language vectors byte for byte, and the client signs every
/// attempt (fresh nonce per retry) so that the server-side profile verifies it.
final class RequestSigningSDKTests: XCTestCase {
    struct VRequest: Decodable {
        var method: String, pathAndQuery: String, headers: [[String]], body: String
        enum CodingKeys: String, CodingKey { case method, pathAndQuery = "path_and_query", headers, body }
    }
    struct Positive: Decodable {
        var name: String, request: VRequest, signatureInput: String, signature: String, contentDigest: String?, signatureRaw: String, keyid: String, nonce: String, created: Int64
        enum CodingKeys: String, CodingKey {
            case name, request, signatureInput = "signature_input", signature, contentDigest = "content_digest", signatureRaw = "signature_raw_b64url", keyid, nonce, created
        }
    }
    struct Vectors: Decodable {
        var now: Int64, signerPrivateKeyHex: String, positive: [Positive]
        enum CodingKeys: String, CodingKey { case now, signerPrivateKeyHex = "signer_private_key_hex", positive }
    }
    static let vectors: Vectors = {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { url.deleteLastPathComponent() }
        return try! JSONDecoder().decode(Vectors.self, from: Data(contentsOf: url.appendingPathComponent("docs/protocol/vectors/http-signatures-v1.json")))
    }()

    static var privateKey: P256.Signing.PrivateKey {
        var bytes: [UInt8] = []
        var i = vectors.signerPrivateKeyHex.startIndex
        while i < vectors.signerPrivateKeyHex.endIndex {
            let j = vectors.signerPrivateKeyHex.index(i, offsetBy: 2)
            bytes.append(UInt8(vectors.signerPrivateKeyHex[i..<j], radix: 16)!)
            i = j
        }
        return try! P256.Signing.PrivateKey(rawRepresentation: Data(bytes))
    }

    /// Returns the vector's deterministic signature bytes (what the Python RFC 6979 signer produced), so the header values must match exactly.
    struct FixedSigner: HTTPRequestSigningKey {
        var keyId: String, publicKey: DevicePublicKey, raw: Data
        func sign(_ message: Data) async throws -> Data { raw }
    }

    func testSigningReproducesTheVectorsByteForByte() async throws {
        for v in Self.vectors.positive where v.name != "parameters_reordered_with_alg" {
            let type = v.request.headers.first { $0[0] == "Content-Type" }?[1]
            let body = Data(v.request.body.utf8)
            let request = BusinessHTTPRequest(method: v.request.method, url: URL(string: "https://viadere.io" + v.request.pathAndQuery)!,
                                              headers: type.map { ["Content-Type": $0] } ?? [:], body: body.isEmpty ? nil : body)
            let signer = HTTPRequestSigner(key: FixedSigner(keyId: v.keyid, publicKey: DevicePublicKey(Self.privateKey.publicKey), raw: Base64URL.decode(v.signatureRaw)!))
            let signed = try await ViadereRequestSigning.sign(request, with: signer, now: Date(timeIntervalSince1970: TimeInterval(v.created)), nonce: v.nonce)
            XCTAssertEqual(signed.headers["Signature-Input"], v.signatureInput, v.name)
            XCTAssertEqual(signed.headers["Signature"], v.signature, v.name)
            XCTAssertEqual(signed.headers["Content-Digest"], v.contentDigest, v.name)
        }
    }

    func testAClientWithASignerSignsEveryAttemptAndTheProfileVerifiesIt() async throws {
        let transport = MockTransport()
        transport.enqueue(status: 503, raw: "{}")
        transport.enqueue(status: 503, raw: "{}")
        let key = SoftwareHTTPRequestSigningKey(keyId: "vsk_0123456789abcdef", privateKey: Self.privateKey)
        let now = Date(timeIntervalSince1970: TimeInterval(Self.vectors.now))
        let client = try ViadereBusinessClient(apiKey: Fixtures.key, baseURL: URL(string: "https://viadere.io")!, transport: transport,
                                               retry: RetryPolicy(maxAttempts: 3, baseDelay: 0, maxDelay: 0), sleep: { _ in }, requestSigner: key, now: { now })
        XCTAssertTrue(client.signsRequests)
        _ = try? await client.cancelAuthDelivery(id: AuthDeliveryID(), idempotencyKey: "cancel-1")
        _ = try? await client.capabilities()
        let sent = transport.requests
        XCTAssertGreaterThanOrEqual(sent.count, 3)
        var nonces = Set<String>()
        let store = InMemoryReplayGuard()
        for request in sent {
            let target = String(request.url.absoluteString.dropFirst("https://viadere.io".count))
            let parsed = try HTTPSignatureVerifier.parse(HTTPSignatureRequest(method: request.method, target: target, fields: request.headers.map { (name: $0.key, value: $0.value) },
                                                                              body: request.body ?? Data()), now: now)
            nonces.insert(parsed.nonce)
            _ = try await HTTPSignatureVerifier.verify(parsed, key: .init(publicKey: key.publicKey, businessId: "b", apiKeyIds: ["k"], revoked: false), businessId: "b",
                                                       apiKeyId: "k", authorities: ["viadere.io"], replayGuard: store, now: now)
        }
        XCTAssertEqual(nonces.count, sent.count, "a retry never reuses a nonce")
        // The API key still travels as the bearer credential.
        XCTAssertTrue(sent.allSatisfy { $0.headers["Authorization"] == "Bearer \(Fixtures.key)" })
    }

    func testAJSONBodyIsDigestedAndTyped() async throws {
        let transport = MockTransport()
        let key = SoftwareHTTPRequestSigningKey(keyId: "vsk_0123456789abcdef", privateKey: Self.privateKey)
        let client = try ViadereBusinessClient(apiKey: Fixtures.key, transport: transport, retry: .none, sleep: { _ in }, requestSigner: key)
        _ = try? await client.issueInteraction(Fixtures.confirm())
        let request = try XCTUnwrap(transport.requests.first)
        XCTAssertEqual(request.headers["Content-Digest"], HTTPSignatureProfile.contentDigest(request.body!))
        XCTAssertEqual(request.headers["Content-Type"], "application/json")
        XCTAssertTrue(request.headers["Signature-Input"]!.hasPrefix("sig1=(\"@method\" \"@authority\" \"@path\" \"@query\" \"content-digest\" \"content-type\");created="))
    }

    func testABaseURLWithAPortIsCoveredAsItsAuthority() async throws {
        let transport = MockTransport()
        let key = SoftwareHTTPRequestSigningKey(keyId: "vsk_0123456789abcdef", privateKey: Self.privateKey)
        let client = try ViadereBusinessClient(apiKey: Fixtures.key, baseURL: URL(string: "https://API.viadere.io:8443")!, transport: transport, retry: .none,
                                               sleep: { _ in }, requestSigner: key)
        _ = try? await client.capabilities()
        let request = try XCTUnwrap(transport.requests.first)
        let parsed = try HTTPSignatureVerifier.parse(HTTPSignatureRequest(method: "GET", target: "/v1/business/capabilities",
                                                                          fields: request.headers.map { (name: $0.key, value: $0.value) }, body: Data()), now: Date())
        XCTAssertNoThrow(try parsed.verify(publicKey: key.publicKey, authorities: ["api.viadere.io:8443"]))
        XCTAssertThrowsError(try parsed.verify(publicKey: key.publicKey, authorities: ["api.viadere.io"]))
    }

    func testAMalformedKeyIdIsRefusedAtConstruction() {
        let key = SoftwareHTTPRequestSigningKey(keyId: "my-key", privateKey: P256.Signing.PrivateKey())
        XCTAssertThrowsError(try ViadereBusinessClient(apiKey: Fixtures.key, requestSigner: key)) { XCTAssertEqual($0 as? ViadereSDKError, .invalidSigningKey) }
    }

    func testASignerThatFailsSendsNothingUnsigned() async throws {
        struct Broken: HTTPRequestSigningKey {
            var keyId = "vsk_0123456789abcdef"
            var publicKey = DevicePublicKey(P256.Signing.PrivateKey().publicKey)
            func sign(_ message: Data) async throws -> Data { Data(repeating: 1, count: 64) }
        }
        let transport = MockTransport()
        let client = try ViadereBusinessClient(apiKey: Fixtures.key, transport: transport, retry: .none, sleep: { _ in }, requestSigner: Broken())
        do { _ = try await client.capabilities(); XCTFail("sent") } catch { XCTAssertEqual(error as? ViadereSDKError, .signingFailed) }
        XCTAssertTrue(transport.requests.isEmpty)
    }

    func testTheProofOfPossessionHelperMatchesTheConsole() async throws {
        let key = SoftwareHTTPRequestSigningKey(keyId: "vsk_0123456789abcdef", privateKey: Self.privateKey)
        let proof = try await HTTPSigningKeyProof.prove(challenge: "1800000000.abc.def", key: key)
        XCTAssertTrue(HTTPSigningKeyProof.verify(proof: proof, challenge: "1800000000.abc.def", publicKey: key.publicKey))
    }
}
