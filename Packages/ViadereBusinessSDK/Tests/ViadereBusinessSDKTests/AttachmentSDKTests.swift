@preconcurrency import Crypto
import Foundation
import XCTest
import ViadereCore
@testable import ViadereBusinessSDK

/// Message attachments in the Swift business SDK (SECURITY.md §2.113): uploads are checked before they are sent and never retried, the raw body is
/// what the RFC 9421 signature digests, downloads are returned only when they match their reference, and message ids are checked locally.
final class AttachmentSDKTests: XCTestCase {
    static let session = SessionID(UUID(uuidString: "6f1e2d3c-4b5a-4968-8776-655443322110")!)
    static let png = Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) + Data("IHDR fake image body".utf8)
    static let jpeg = Data([0xFF, 0xD8, 0xFF, 0xE0]) + Data("fake jpeg".utf8)

    static func reference(for data: Data, mediaType: String = "image/png", session: SessionID = session, state: MessageAttachment.State = .pending) -> MessageAttachment {
        MessageAttachment(id: AttachmentID(), sessionId: session, mediaType: mediaType, byteSize: data.count, width: 4, height: 3,
                          sha256: Hex.encode(Data(SHA256.hash(data: data))), state: state, expiresAt: state == .pending ? Fixtures.now : nil)
    }

    // MARK: Upload

    func testUploadSendsTheRawImageWithItsTypeAndNoIdempotencyKey() async throws {
        let transport = MockTransport()
        let stored = Self.reference(for: Self.jpeg, mediaType: "image/jpeg")
        try transport.enqueue(status: 201, json: stored)
        let client = try Fixtures.client(transport)
        let attachment = try await client.uploadAttachment(sessionId: Self.session, data: Self.png, contentType: "image/png")
        XCTAssertEqual(attachment, stored)
        let request = try XCTUnwrap(transport.requests.first)
        XCTAssertEqual(request.method, "POST")
        XCTAssertEqual(request.url.absoluteString, "https://viadere.io/v1/business/conversations/\(Self.session.description)/attachments")
        XCTAssertEqual(request.body, Self.png, "the bytes travel as they are: no JSON, no base64")
        XCTAssertEqual(request.headers["Content-Type"], "image/png")
        XCTAssertEqual(request.headers["Authorization"], "Bearer \(Fixtures.key)")
        XCTAssertNil(request.headers[ViadereHeader.idempotencyKey])
    }

    func testAnUploadIsNeverRetried() async throws {
        // The route takes no idempotency key: a repeat after a lost answer would store a second pending copy.
        for step in [MockTransport.Step.response(BusinessHTTPResponse(status: 503, body: Data("{}".utf8))), .failure(NetworkDown())] {
            let transport = MockTransport()
            transport.enqueue(step)
            let sleeps = RecordedSleeps()
            let client = try Fixtures.client(transport, sleeps: sleeps)
            do {
                _ = try await client.uploadAttachment(sessionId: Self.session, data: Self.png, contentType: "image/png")
                XCTFail("expected a failure")
            } catch {}
            XCTAssertEqual(transport.requests.count, 1)
            XCTAssertEqual(sleeps.delays, [])
        }
    }

    func testAnUploadThatBreaksThePolicyIsRefusedBeforeAnythingIsSent() async throws {
        let cases: [(Data, String, MessageAttachmentPolicy.Rejection)] = [
            (Data(), "image/png", .empty),
            (Self.png + Data(count: MessageAttachmentPolicy.maxUploadBytes), "image/png", .tooLarge),
            (Self.jpeg, "image/png", .contentTypeMismatch),
            (Self.png, "image/jpeg", .contentTypeMismatch),
            (Data("GIF89a....".utf8), "image/png", .unsupportedFormat),
            (Data("<svg xmlns='http://www.w3.org/2000/svg'/>".utf8), "image/png", .svgRefused),
            (Data("<html><script>alert(1)</script>".utf8), "image/jpeg", .markupRefused),
            (Self.png, "image/gif", .unsupportedFormat),
            (Self.png, "application/json", .unsupportedFormat),
        ]
        for (data, type, expected) in cases {
            let transport = MockTransport()
            let client = try Fixtures.client(transport)
            do {
                _ = try await client.uploadAttachment(sessionId: Self.session, data: data, contentType: type)
                XCTFail("\(type) \(expected) was accepted")
            } catch {
                XCTAssertEqual(error as? ViadereSDKError, .attachmentRejected(expected), "\(type) \(expected)")
            }
            XCTAssertTrue(transport.requests.isEmpty, "\(expected): nothing is sent")
        }
        // Exactly the cap is accepted.
        let transport = MockTransport()
        try transport.enqueue(status: 201, json: Self.reference(for: Self.png))
        let atCap = Self.png + Data(count: MessageAttachmentPolicy.maxUploadBytes - Self.png.count)
        _ = try await Fixtures.client(transport).uploadAttachment(sessionId: Self.session, data: atCap, contentType: "image/png; charset=binary")
        XCTAssertEqual(transport.requests.first?.body?.count, MessageAttachmentPolicy.maxUploadBytes)
        XCTAssertEqual(transport.requests.first?.headers["Content-Type"], "image/png")
    }

    func testAnUploadAnswerForAnotherConversationIsRefused() async throws {
        let transport = MockTransport()
        try transport.enqueue(status: 201, json: Self.reference(for: Self.png, session: SessionID()))
        do {
            _ = try await Fixtures.client(transport).uploadAttachment(sessionId: Self.session, data: Self.png, contentType: "image/png")
            XCTFail("expected attachmentMismatch")
        } catch { XCTAssertEqual(error as? ViadereSDKError, .attachmentMismatch) }
    }

    func testASignedUploadDigestsTheRawBytesAndTheProfileVerifiesIt() async throws {
        // The key of the cross-language vectors (docs/protocol/vectors/http-signatures-v1.json).
        let key = SoftwareHTTPRequestSigningKey(keyId: "vsk_0123456789abcdef", privateKey: RequestSigningSDKTests.privateKey)
        let now = Date(timeIntervalSince1970: TimeInterval(RequestSigningSDKTests.vectors.now))
        let transport = MockTransport()
        try transport.enqueue(status: 201, json: Self.reference(for: Self.png))
        let client = try ViadereBusinessClient(apiKey: Fixtures.key, baseURL: URL(string: "https://viadere.io")!, transport: transport, retry: .none,
                                               sleep: { _ in }, requestSigner: key, now: { now })
        _ = try await client.uploadAttachment(sessionId: Self.session, data: Self.png, contentType: "image/png")
        let request = try XCTUnwrap(transport.requests.first)
        XCTAssertEqual(request.headers["Content-Digest"], HTTPSignatureProfile.contentDigest(Self.png))
        XCTAssertEqual(request.headers["Content-Type"], "image/png", "the signer keeps the image type (never application/json)")
        XCTAssertTrue(request.headers["Signature-Input"]!.contains("\"content-digest\" \"content-type\""))
        let target = String(request.url.absoluteString.dropFirst("https://viadere.io".count))
        func verify(body: Data, type: String) async throws {
            var fields = request.headers
            fields["Content-Type"] = type
            let parsed = try HTTPSignatureVerifier.parse(HTTPSignatureRequest(method: "POST", target: target, fields: fields.map { (name: $0.key, value: $0.value) }, body: body),
                                                         now: now)
            _ = try await HTTPSignatureVerifier.verify(parsed, key: .init(publicKey: key.publicKey, businessId: "b", apiKeyIds: ["k"], revoked: false), businessId: "b",
                                                       apiKeyId: "k", authorities: ["viadere.io"], replayGuard: InMemoryReplayGuard(), now: now)
        }
        try await verify(body: Self.png, type: "image/png")
        // A swapped image, or the same bytes relabelled, no longer verifies.
        var tampered = Self.png
        tampered[tampered.count - 1] ^= 0x01
        do { try await verify(body: tampered, type: "image/png"); XCTFail("a changed image verified") } catch {}
        do { try await verify(body: Self.png, type: "image/jpeg"); XCTFail("a relabelled image verified") } catch {}
    }

    // MARK: Download

    func testADownloadIsReturnedOnlyWhenItMatchesItsReference() async throws {
        let reference = Self.reference(for: Self.png, state: .attached)
        let transport = MockTransport()
        transport.enqueue(.response(BusinessHTTPResponse(status: 200, headers: ["Content-Type": "image/png"], body: Self.png)))
        let client = try Fixtures.client(transport)
        let data = try await client.downloadAttachment(reference)
        XCTAssertEqual(data, Self.png)
        let request = try XCTUnwrap(transport.requests.first)
        XCTAssertEqual(request.method, "GET")
        XCTAssertEqual(request.url.absoluteString, "https://viadere.io/v1/business/conversations/\(Self.session.description)/attachments/\(reference.id.description)")
        XCTAssertEqual(request.headers["Accept"], "image/png, image/jpeg")
        XCTAssertNil(request.body)
    }

    func testADownloadThatDoesNotMatchIsDiscarded() async throws {
        let reference = Self.reference(for: Self.png, state: .attached)
        var flipped = Self.png
        flipped[3] ^= 0x20
        let bad: [BusinessHTTPResponse] = [
            BusinessHTTPResponse(status: 200, headers: ["Content-Type": "image/png"], body: flipped), // same size, other digest
            BusinessHTTPResponse(status: 200, headers: ["Content-Type": "image/png"], body: Self.png + Data([0])), // longer
            BusinessHTTPResponse(status: 200, headers: ["Content-Type": "image/png"], body: Self.jpeg), // another image
            BusinessHTTPResponse(status: 200, headers: ["Content-Type": "text/html"], body: Self.png), // the right bytes, a dangerous type
        ]
        for response in bad {
            let transport = MockTransport()
            transport.enqueue(.response(response))
            do {
                _ = try await Fixtures.client(transport).downloadAttachment(reference)
                XCTFail("a mismatching download was returned")
            } catch { XCTAssertEqual(error as? ViadereSDKError, .attachmentMismatch) }
        }
    }

    func testADownloadIsRetriedLikeEveryGet() async throws {
        let reference = Self.reference(for: Self.jpeg, mediaType: "image/jpeg", state: .attached)
        let transport = MockTransport()
        transport.enqueue(status: 503, raw: "{}")
        transport.enqueue(.response(BusinessHTTPResponse(status: 200, headers: ["Content-Type": "image/jpeg"], body: Self.jpeg)))
        let data = try await Fixtures.client(transport).downloadAttachment(reference)
        XCTAssertEqual(data, Self.jpeg)
        XCTAssertEqual(transport.requests.count, 2)
    }

    // MARK: Sending

    func testAMessageCarriesItsAttachmentIds() async throws {
        let ids = [AttachmentID(), AttachmentID()]
        let transport = MockTransport()
        transport.enqueue(status: 201, raw: "{}")
        let client = try Fixtures.client(transport)
        _ = try? await client.sendMessage(BusinessSendMessageRequest(relationshipId: Fixtures.relationship, sessionId: Self.session, body: "",
                                                                     idempotencyKey: "msg-1", attachmentIds: ids))
        let body = try XCTUnwrap(transport.requests.first?.body)
        let sent = try ViadereJSON.decode(BusinessSendMessageRequest.self, from: body)
        XCTAssertEqual(sent.attachmentIds, ids)
        XCTAssertEqual(sent.sessionId, Self.session)
    }

    func testAttachmentIdsThatCannotBeSentAreRefusedLocally() async throws {
        let one = AttachmentID()
        let requests = [
            BusinessSendMessageRequest(relationshipId: Fixtures.relationship, body: "Here", idempotencyKey: "msg-1", attachmentIds: [one]), // no sessionId
            BusinessSendMessageRequest(relationshipId: Fixtures.relationship, sessionId: Self.session, body: "", idempotencyKey: "msg-2", attachmentIds: []),
            BusinessSendMessageRequest(relationshipId: Fixtures.relationship, sessionId: Self.session, body: "", idempotencyKey: "msg-3", attachmentIds: [one, one]),
            BusinessSendMessageRequest(relationshipId: Fixtures.relationship, sessionId: Self.session, body: "", idempotencyKey: "msg-4",
                                       attachmentIds: (0...MessageAttachmentPolicy.maxPerMessage).map { _ in AttachmentID() }),
        ]
        for request in requests {
            let transport = MockTransport()
            do {
                _ = try await Fixtures.client(transport).sendMessage(request)
                XCTFail("\(request.idempotencyKey) was sent")
            } catch { XCTAssertEqual(error as? ViadereSDKError, .invalidAttachmentIds, request.idempotencyKey) }
            XCTAssertTrue(transport.requests.isEmpty)
        }
    }

    // MARK: Contract

    func testTheUploadCapIsTheOneTheOpenAPIDocumentStates() throws {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { url.deleteLastPathComponent() }
        let yaml = try String(contentsOf: url.appendingPathComponent("docs/openapi.yaml"), encoding: .utf8)
        let upload = try XCTUnwrap(yaml.range(of: "  /v1/business/conversations/{sessionId}/attachments:\n"))
        let section = yaml[upload.upperBound...].prefix(4000)
        XCTAssertTrue(section.contains("image/png:\n            schema: { type: string, format: binary, maxLength: \(MessageAttachmentPolicy.maxUploadBytes) }"))
        XCTAssertTrue(section.contains("image/jpeg:\n            schema: { type: string, format: binary, maxLength: \(MessageAttachmentPolicy.maxUploadBytes) }"))
        XCTAssertEqual(MessageAttachmentPolicy.maxUploadBytes, 2 * 1024 * 1024)
    }
}
