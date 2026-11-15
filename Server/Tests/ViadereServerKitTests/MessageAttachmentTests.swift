import Crypto
import Fluent
import Foundation
import JPEG
import Vapor
import ViadereCore
import struct ViadereCore.Page
import typealias ViadereCore.SessionID
import XCTest
@testable import ViadereServerKit

/// Message attachments (docs/SECURITY.md §2.113). Exploit paths first: hostile files (polyglot, garbage, decompression bomb, SVG/HTML and
/// other types, oversized bodies refused before they are read), metadata that must not survive (EXIF/GPS), every cross-boundary id (another
/// tenant, another conversation, another customer, the other side's pending upload) on download and on attach, webhooks and SMS that must not
/// carry bytes or links, encryption at rest and tampering, and deletion and expiry that must remove the stored objects.
final class MessageAttachmentTests: XCTestCase {
    struct Thread {
        var business: TestBusiness
        var consumer: TestConsumer
        var relationship: Relationship
        var session: SessionID
    }

    /// A verified business, a connected customer (support messages allowed) and an open in-app conversation.
    static func thread(_ h: TestHarness, name: String = "Acme Roasters", handle: String = "acmeroasters", consumer: TestConsumer? = nil,
                       business: TestBusiness? = nil) async throws -> Thread {
        var business = business
        if business == nil { business = try await h.makeBusiness(name: name, handle: handle) }
        var customer = consumer
        if customer == nil { customer = try await h.readyConsumer() }
        let (b, c) = (business!, customer!)
        let relationship = try await h.connect(c, to: b, optIn: [.support])
        let started = try await h.signedPost(c, APIRoutes.conversationStart.template, StartConversationRequest(businessId: b.id))
        XCTAssertEqual(started.status, .ok, started.text)
        return Thread(business: b, consumer: c, relationship: relationship, session: try started.json(ConversationSummary.self).id)
    }

    static func withStore(_ body: (TestHarness, MemoryObjectStore) async throws -> Void) async throws {
        let store = MemoryObjectStore()
        try await withHarness(overrides: { $0.attachmentStore = store }) { h in try await body(h, store) }
    }

    // MARK: Requests

    func upload(_ h: TestHarness, _ consumer: TestConsumer, _ session: SessionID, _ data: Data, type: String? = "image/png",
                headers extra: [String: String] = [:]) async throws -> HTTPResult {
        let path = "/v1/conversations/\(session)/attachments"
        var headers = try await h.signedHeaders(consumer, .POST, path, body: data)
        for (k, v) in extra { headers[k] = v }
        return try await h.request(.POST, path, headers: headers, body: data, contentType: type)
    }

    func businessUpload(_ h: TestHarness, _ b: TestBusiness, _ session: SessionID, _ data: Data, type: String = "image/png") async throws -> HTTPResult {
        try await h.request(.POST, "/v1/business/conversations/\(session)/attachments", headers: ["Authorization": "Bearer \(b.key)"], body: data, contentType: type)
    }

    func download(_ h: TestHarness, _ consumer: TestConsumer, _ session: SessionID, _ id: AttachmentID) async throws -> HTTPResult {
        try await h.signed(consumer, .GET, "/v1/conversations/\(session)/attachments/\(id)")
    }

    func businessDownload(_ h: TestHarness, _ b: TestBusiness, _ session: SessionID, _ id: AttachmentID) async throws -> HTTPResult {
        try await h.business(b, .GET, "/v1/business/conversations/\(session)/attachments/\(id)")
    }

    func send(_ h: TestHarness, _ consumer: TestConsumer, _ session: SessionID, body: String = "", ids: [AttachmentID]) async throws -> HTTPResult {
        try await h.signedPost(consumer, "/v1/conversations/\(session)/messages", SendMessageRequest(body: body, clientMessageId: "c-\(UUID().uuidString)", attachmentIds: ids))
    }

    func businessSend(_ h: TestHarness, _ t: Thread, session: SessionID? = nil, body: String = "", ids: [AttachmentID]) async throws -> HTTPResult {
        try await h.businessPost(t.business, "/v1/business/messages", BusinessSendMessageRequest(relationshipId: t.relationship.id, sessionId: session ?? t.session, body: body,
                                                                                                 idempotencyKey: "k-\(UUID().uuidString)", attachmentIds: ids))
    }

    static var png: Data { Data(BrandAssetPipelineTests.png(width: 40, height: 30)) }
    static var opaquePNG: Data { Data(BrandAssetPipelineTests.png(width: 64, height: 48, opaque: true)) }

    static func assertSafeImageHeaders(_ r: HTTPResult, type: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(r.status, .ok, r.text, file: file, line: line)
        XCTAssertEqual(r.headers.first(name: .contentType), type, file: file, line: line)
        XCTAssertEqual(r.headers.first(name: "X-Content-Type-Options"), "nosniff", file: file, line: line)
        XCTAssertEqual(r.headers.first(name: "Content-Security-Policy"), "default-src 'none'; sandbox", file: file, line: line)
        XCTAssertEqual(r.headers.first(name: .cacheControl), "private, no-store", file: file, line: line)
        XCTAssertNil(r.headers.first(name: .location), file: file, line: line)
    }

    // MARK: Hostile files

    func testGarbageAndPolyglotFilesNamedPNGAreRefusedAndNothingIsStored() async throws {
        try await Self.withStore { h, store in
            let t = try await Self.thread(h)
            let garbage = Data((0..<4096).map { UInt8(truncatingIfNeeded: $0 &* 7919) })
            let polyglot = Self.png + Data("<html><script>alert(document.cookie)</script></html>".utf8)
            let zipTail = Self.png + Data([0x50, 0x4B, 0x03, 0x04]) + Data(repeating: 0x41, count: 64)
            let pngHeaderOnly = Data(PNGStructure.signature) + Data("<svg onload=alert(1)>".utf8)
            for (name, data, reason) in [("garbage", garbage, "unsupported_format"), ("polyglot html", polyglot, "trailing_data"),
                                         ("polyglot zip", zipTail, "trailing_data"), ("png signature then markup", pngHeaderOnly, "truncated")] {
                let r = try await upload(h, t.consumer, t.session, data)
                XCTAssertEqual(r.status, .unprocessableEntity, "\(name): \(r.text)")
                XCTAssertTrue(r.text.contains(reason), "\(name): \(r.text)")
                let b = try await businessUpload(h, t.business, t.session, data)
                XCTAssertEqual(b.status, .unprocessableEntity, "\(name) (business): \(b.text)")
            }
            XCTAssertTrue(store.names.isEmpty)
            try await eq(try await MessageAttachmentRecord.query(on: h.db).count(), 0)
            // Refusals are audited with their reason, never with file content.
            let audits = try await AuditEventRecord.query(on: h.db).filter(\.$action == "message.attachment_rejected").all()
            XCTAssertEqual(audits.count, 8)
            XCTAssertFalse(audits.contains { $0.metadataJSON.contains("script") })
        }
    }

    func testOversizedBodiesAreRefusedFromTheDeclaredLengthBeforeTheBodyIsRead() async throws {
        try await Self.withStore { h, store in
            let t = try await Self.thread(h)
            // A declared length over the cap is refused by the request guard on the header alone: the next responder (authentication, which
            // collects the body) is never reached. The in-memory test client rewrites Content-Length, so the guard is driven directly.
            for path in ["/v1/conversations/\(t.session)/attachments", "/v1/business/conversations/\(t.session)/attachments"] {
                for length in [MessageAttachmentPolicy.maxUploadBytes + 1, 50_000_000] {
                    let request = Request(application: h.app, method: .POST, url: URI(path: path),
                                          headers: ["Content-Length": String(length), "Content-Type": "image/png"], on: h.app.eventLoopGroup.next())
                    let reached = Box<Bool>()
                    let next = AsyncBasicResponder { _ in reached.value = true; return Response(status: .ok) }
                    do {
                        _ = try await RequestGuardMiddleware().respond(to: request, chainingTo: next)
                        XCTFail("\(path) \(length): accepted")
                    } catch let error as APIError {
                        XCTAssertEqual(error.status, .payloadTooLarge, "\(path) \(length)")
                    }
                    XCTAssertNil(reached.value, "\(path) \(length): the body would have been read")
                }
            }
            // A real body one byte over the cap is refused too, and the cap of the rest of the API does not grow with it.
            let big = Data(repeating: 0x00, count: MessageAttachmentPolicy.maxUploadBytes + 1)
            try await eq(try await upload(h, t.consumer, t.session, big).status, .payloadTooLarge)
            try await eq(try await businessUpload(h, t.business, t.session, big).status, .payloadTooLarge)
            XCTAssertEqual(h.ctx.config.maxBodyBytes(forPath: "/v1/conversations/\(t.session)/messages"), h.ctx.config.maxBodyBytes)
            XCTAssertEqual(h.ctx.config.maxBodyBytes(forPath: "/v1/conversations/\(t.session)/attachments/x"), h.ctx.config.maxBodyBytes)
            XCTAssertEqual(h.ctx.config.maxBodyBytes(forPath: "/v1/conversations/not-a-uuid/attachments"), h.ctx.config.maxBodyBytes)
            XCTAssertTrue(store.names.isEmpty)
            try await eq(try await MessageAttachmentRecord.query(on: h.db).count(), 0)
        }
    }

    func testDecompressionBombsAreRefusedFromTheHeaderBeforeAnyPixelBufferExists() async throws {
        try await Self.withStore { h, store in
            let t = try await Self.thread(h)
            // Valid chunk structure, absurd declared sizes, a few bytes of data: refused from IHDR / SOF.
            let parts = BrandAssetPipelineTests.chunks(BrandAssetPipelineTests.png())
            let tail = parts.dropFirst().flatMap(\.1)
            for (w, h2) in [(100_000, 100_000), (8193, 10), (6000, 6000), (Int(UInt32.max >> 1), 1)] {
                let bomb = Data(PNGStructure.signature + BrandAssetPipelineTests.ihdr(width: UInt32(w), height: UInt32(h2)) + tail)
                let r = try await upload(h, t.consumer, t.session, bomb)
                XCTAssertEqual(r.status, .unprocessableEntity, "\(w)x\(h2): \(r.text)")
                XCTAssertTrue(r.text.contains("dimensions_too_large"), "\(w)x\(h2): \(r.text)")
            }
            var jpeg = BrandAssetPipelineTests.jpeg()
            // Patch the SOF0 height and width to 65535 x 65535.
            if let sof = (0..<(jpeg.count - 1)).first(where: { jpeg[$0] == 0xFF && jpeg[$0 + 1] == 0xC0 }) {
                for offset in [sof + 5, sof + 6, sof + 7, sof + 8] { jpeg[offset] = 0xFF }
            }
            let r = try await upload(h, t.consumer, t.session, Data(jpeg), type: "image/jpeg")
            XCTAssertEqual(r.status, .unprocessableEntity, r.text)
            XCTAssertTrue(r.text.contains("dimensions_too_large"), r.text)
            XCTAssertTrue(store.names.isEmpty)
        }
    }

    func testSVGHTMLAndEveryOtherTypeIsRefused() async throws {
        try await Self.withStore { h, store in
            let t = try await Self.thread(h)
            let svg = Data(#"<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><script>alert(2)</script></svg>"#.utf8)
            let html = Data("<!doctype html><html><body><script>alert(1)</script></body></html>".utf8)
            // Declared as what it is: the request guard refuses every non-image type outright.
            for (type, data) in [("image/svg+xml", svg), ("text/html", html), ("application/json", Data("{}".utf8)), ("image/gif", Data("GIF89a....".utf8)),
                                 ("image/webp", Data("RIFF....WEBP".utf8)), ("application/pdf", Data("%PDF-1.7".utf8)), ("multipart/form-data; boundary=x", html)] {
                let r = try await upload(h, t.consumer, t.session, data, type: type)
                XCTAssertEqual(r.status, .unsupportedMediaType, "\(type): \(r.text)")
                try await eq(try await businessUpload(h, t.business, t.session, data, type: type).status, .unsupportedMediaType, type)
            }
            // Declared as an image: the bytes decide.
            for (data, reason) in [(svg, "svg_refused"), (html, "markup_refused"), (Data("GIF89a\u{1}\u{0}\u{1}\u{0}".utf8), "unsupported_format")] {
                let r = try await upload(h, t.consumer, t.session, data, type: "image/png")
                XCTAssertEqual(r.status, .unprocessableEntity, r.text)
                XCTAssertTrue(r.text.contains(reason), r.text)
            }
            // A real JPEG declared as PNG (and the reverse) is a mismatch.
            let mismatch = try await upload(h, t.consumer, t.session, Data(BrandAssetPipelineTests.jpeg()), type: "image/png")
            XCTAssertTrue(mismatch.text.contains("content_type_mismatch"), mismatch.text)
            XCTAssertTrue(store.names.isEmpty)
        }
    }

    func testEXIFGPSAndOtherMetadataAreGoneFromTheStoredBytes() async throws {
        try await Self.withStore { h, _ in
            let t = try await Self.thread(h)
            let exif = Array("Exif\0\0MM\0*GPSLatitude 47.3769N GPSLongitude 8.5417E iPhone 17 Pro".utf8)
            let jpeg = BrandAssetPipelineTests.jpegWith([BrandAssetPipelineTests.segment(0xE1, exif),
                                                         BrandAssetPipelineTests.segment(0xE1, Array("http://ns.adobe.com/xap/1.0/\0<x:xmpmeta>home</x:xmpmeta>".utf8)),
                                                         BrandAssetPipelineTests.segment(0xFE, Array("<script>alert(1)</script>".utf8))],
                                                        base: BrandAssetPipelineTests.jpeg(width: 64, height: 48))
            let up = try await upload(h, t.consumer, t.session, Data(jpeg), type: "image/jpeg")
            XCTAssertEqual(up.status, .created, up.text)
            let photo = try up.json(MessageAttachment.self)
            XCTAssertEqual(photo.mediaType, "image/jpeg")
            XCTAssertEqual(photo.state, .pending)
            XCTAssertEqual([photo.width, photo.height], [64, 48])
            let fetched = try await download(h, t.consumer, t.session, photo.id)
            Self.assertSafeImageHeaders(fetched, type: "image/jpeg")
            XCTAssertTrue(photo.matches(fetched.body))
            for needle in ["GPS", "Exif", "xmpmeta", "<script>", "iPhone", "JFIF"] {
                XCTAssertNil(fetched.body.range(of: Data(needle.utf8)), "stored JPEG still contains \(needle)")
            }
            // The stored JPEG has no APPn or COM segment at all: rebuilding it through the front end drops nothing.
            let parsed = try JPEGStructure.parse([UInt8](fetched.body)).get()
            XCTAssertEqual(parsed.pixelStream, [UInt8](fetched.body))
            // A PNG with transparency and metadata chunks stays a PNG with only pixel chunks.
            let png = BrandAssetPipelineTests.pngWith([BrandAssetPipelineTests.chunk("eXIf", exif),
                                                       BrandAssetPipelineTests.chunk("tEXt", Array("Comment\0GPSLatitude 1.0".utf8))])
            let upPNG = try await upload(h, t.consumer, t.session, Data(png))
            XCTAssertEqual(upPNG.status, .created, upPNG.text)
            let pngRef = try upPNG.json(MessageAttachment.self)
            XCTAssertEqual(pngRef.mediaType, "image/png")
            let pngBytes = try await download(h, t.consumer, t.session, pngRef.id)
            Self.assertSafeImageHeaders(pngBytes, type: "image/png")
            XCTAssertEqual(Set(BrandAssetPipelineTests.chunks([UInt8](pngBytes.body)).map(\.0)), ["IHDR", "IDAT", "IEND"])
            XCTAssertNil(pngBytes.body.range(of: Data("GPS".utf8)))
            // An opaque PNG is stored as JPEG; a large image is scaled to the stored ceiling.
            let opaque = try await upload(h, t.consumer, t.session, Self.opaquePNG)
            XCTAssertEqual(try opaque.json(MessageAttachment.self).mediaType, "image/jpeg")
        }
    }

    // MARK: Boundaries

    func testAnotherTenantsAttachmentIsNotFoundOnDownloadAndOnAttach() async throws {
        try await Self.withStore { h, _ in
            let a = try await Self.thread(h)
            let b = try await Self.thread(h, name: "Other Shop", handle: "othershop")
            // B's customer sends B an image.
            let bImage = try await upload(h, b.consumer, b.session, Self.png).json(MessageAttachment.self)
            try await eq(try await send(h, b.consumer, b.session, ids: [bImage.id]).status, .created)
            let bOwn = try await businessUpload(h, b.business, b.session, Self.png).json(MessageAttachment.self)
            try await eq(try await businessDownload(h, b.business, b.session, bImage.id).status, .ok)
            // A's key: B's conversation, and B's image under A's own conversation, are both plain 404s.
            for (session, id) in [(b.session, bImage.id), (a.session, bImage.id), (b.session, bOwn.id), (a.session, bOwn.id), (a.session, AttachmentID())] {
                let r = try await businessDownload(h, a.business, session, id)
                XCTAssertEqual(r.status, .notFound, r.text)
                XCTAssertFalse(r.body.starts(with: PNGStructure.signature))
            }
            // A cannot upload into B's conversation, nor attach B's images to its own message.
            try await eq(try await businessUpload(h, a.business, b.session, Self.png).status, .notFound)
            let attach = try await businessSend(h, a, body: "Look", ids: [bOwn.id])
            XCTAssertEqual(attach.status, .notFound, attach.text)
            let attachReceived = try await businessSend(h, a, body: "Look", ids: [bImage.id])
            XCTAssertEqual(attachReceived.status, .notFound, attachReceived.text)
            // Nothing was written to A's thread and B's pending upload is untouched.
            try await eq(try await ConversationMessageRecord.query(on: h.db).filter(\.$sessionId == a.session.uuid).filter(\.$direction == MessageDirection.businessToConsumer.rawValue).count(), 0)
            try await eq(try await MessageAttachmentRecord.find(bOwn.id.uuid, on: h.db)?.state, "pending")
            // The console of A: the same 404 for B's thread and B's image.
        }
    }

    func testACustomerCannotFetchAnotherConversationsImageOrTheBusinessesUnsentOne() async throws {
        try await Self.withStore { h, _ in
            let t = try await Self.thread(h)
            let other = try await Self.thread(h, business: t.business)
            let mine = try await upload(h, t.consumer, t.session, Self.png).json(MessageAttachment.self)
            try await eq(try await send(h, t.consumer, t.session, body: "Receipt", ids: [mine.id]).status, .created)
            try await eq(try await download(h, t.consumer, t.session, mine.id).status, .ok)
            // Another customer of the same business: their own session with my id, and my session, are 404.
            try await eq(try await download(h, other.consumer, other.session, mine.id).status, .notFound)
            try await eq(try await download(h, other.consumer, t.session, mine.id).status, .notFound)
            // A business upload that was not sent yet is not the customer's to see; once sent, it is.
            let draft = try await businessUpload(h, t.business, t.session, Self.png).json(MessageAttachment.self)
            try await eq(try await download(h, t.consumer, t.session, draft.id).status, .notFound)
            // ...and the business cannot read the customer's unsent upload either.
            let unsent = try await upload(h, t.consumer, t.session, Self.png).json(MessageAttachment.self)
            try await eq(try await businessDownload(h, t.business, t.session, unsent.id).status, .notFound)
            try await eq(try await businessSend(h, t, body: "Here you go", ids: [draft.id]).status, .created)
            let fetched = try await download(h, t.consumer, t.session, draft.id)
            Self.assertSafeImageHeaders(fetched, type: draft.mediaType)
            XCTAssertTrue(fetched.headers.first(name: "Content-Disposition")?.hasPrefix("attachment;") == true)
            // The customer's thread shows both images in their messages.
            let page = try await h.signed(t.consumer, .GET, "/v1/conversations/\(t.session)/messages").json(Page<ConversationMessage>.self)
            XCTAssertEqual(Set(page.items.flatMap { $0.attachments ?? [] }.map(\.id)), [mine.id, draft.id])
            XCTAssertTrue(page.items.flatMap { $0.attachments ?? [] }.allSatisfy { $0.state == .attached && $0.expiresAt == nil })
        }
    }

    func testAnImageUploadedToOneConversationCannotBeSentInAnother() async throws {
        try await Self.withStore { h, _ in
            let a = try await Self.thread(h)
            let b = try await Self.thread(h, name: "Harbor Hotel", handle: "harborhotel", consumer: a.consumer)
            let image = try await upload(h, a.consumer, a.session, Self.png).json(MessageAttachment.self)
            XCTAssertEqual(image.sessionId, a.session)
            let crossed = try await send(h, a.consumer, b.session, body: "Wrong thread", ids: [image.id])
            XCTAssertEqual(crossed.status, .notFound, crossed.text)
            try await eq(try await ConversationMessageRecord.query(on: h.db).filter(\.$sessionId == b.session.uuid).count(), 0)
            try await eq(try await download(h, a.consumer, b.session, image.id).status, .notFound)
            // The business side: an upload to one customer's session cannot be sent to another customer's session.
            let other = try await Self.thread(h, business: a.business)
            let draft = try await businessUpload(h, a.business, a.session, Self.png).json(MessageAttachment.self)
            let wrong = try await businessSend(h, other, ids: [draft.id])
            XCTAssertEqual(wrong.status, .notFound, wrong.text)
            // attachmentIds needs the session the images belong to.
            let noSession = try await h.businessPost(a.business, "/v1/business/messages", BusinessSendMessageRequest(relationshipId: a.relationship.id, body: "", idempotencyKey: "ns", attachmentIds: [draft.id]))
            XCTAssertEqual(noSession.status, .unprocessableEntity, noSession.text)
            // An image is sent once: the second message naming it is refused, and duplicates or more than four are refused.
            try await eq(try await send(h, a.consumer, a.session, ids: [image.id]).status, .created)
            try await eq(try await send(h, a.consumer, a.session, body: "Again", ids: [image.id]).status, .notFound)
            let fresh = try await upload(h, a.consumer, a.session, Self.png).json(MessageAttachment.self)
            try await eq(try await send(h, a.consumer, a.session, ids: [fresh.id, fresh.id]).status, .unprocessableEntity)
            try await eq(try await send(h, a.consumer, a.session, ids: (0..<5).map { _ in fresh.id }).status, .unprocessableEntity)
            // An empty message without images is still refused.
            try await eq(try await send(h, a.consumer, a.session, ids: []).status, .unprocessableEntity)
        }
    }

    // MARK: Channels

    func testTheWebhookCarriesIdsAndMetadataButNeverTheBytes() async throws {
        try await Self.withStore { h, _ in
            let t = try await Self.thread(h)
            let hook = try await h.businessPost(t.business, "/v1/business/webhooks", CreateWebhookRequest(url: URL(string: "https://hooks.example.com/messages")!, events: [.messageReceived]))
            XCTAssertEqual(hook.status, .created, hook.text)
            let image = try await upload(h, t.consumer, t.session, Self.opaquePNG).json(MessageAttachment.self)
            let bytes = try await download(h, t.consumer, t.session, image.id).body
            try await eq(try await send(h, t.consumer, t.session, ids: [image.id]).status, .created)
            try await h.runJobs()
            let delivered = try XCTUnwrap(h.webhooks.received.last)
            let text = String(decoding: delivered.body, as: UTF8.self)
            let payload = try ViadereJSON.decode(WebhookEvent.self, from: delivered.body).decodeData(MessageReceivedPayload.self)
            XCTAssertEqual(payload.attachments?.map(\.id), [image.id])
            XCTAssertEqual(payload.attachments?.first?.sha256, image.sha256)
            XCTAssertEqual(payload.text, "")
            // No image bytes in any encoding, no URL, no storage name.
            for needle in [Base64URL.encode(bytes), bytes.base64EncodedString(), "attachments/", "blob.core", "http://", "/v1/conversations"] {
                XCTAssertFalse(text.contains(needle), "webhook body contains \(needle.prefix(24))")
            }
            XCTAssertLessThan(delivered.body.count, 4096)
            // The business fetches the bytes by id with its key.
            let fetched = try await businessDownload(h, t.business, payload.sessionId, image.id)
            Self.assertSafeImageHeaders(fetched, type: "image/jpeg")
            XCTAssertEqual(fetched.body, bytes)
        }
    }

    // MARK: At rest

    func testStoredObjectsAreEncryptedBoundToTheirRowAndCheckedOnRead() async throws {
        try await Self.withStore { h, store in
            let t = try await Self.thread(h)
            let first = try await upload(h, t.consumer, t.session, Self.png).json(MessageAttachment.self)
            let second = try await upload(h, t.consumer, t.session, Self.opaquePNG).json(MessageAttachment.self)
            let plain = try await download(h, t.consumer, t.session, first.id).body
            let rows = try await MessageAttachmentRecord.query(on: h.db).all()
            XCTAssertEqual(Set(store.names), Set(rows.map(\.objectName)))
            for row in rows {
                XCTAssertTrue(row.objectName.hasPrefix("attachments/\(t.business.id)/\(t.session)/"))
                let stored = try await store.read(name: row.objectName)
                let sealed = try XCTUnwrap(stored)
                XCTAssertTrue(String(decoding: sealed, as: UTF8.self).hasPrefix("v2."), "sealed with the field cipher")
                XCTAssertNil(sealed.range(of: Data(PNGStructure.signature)))
                XCTAssertNil(sealed.range(of: plain.prefix(32)))
            }
            // Swapping two stored objects (storage-level tampering) serves neither: each is bound to its row.
            let a = try XCTUnwrap(rows.first { $0.id == first.id.uuid }), b = try XCTUnwrap(rows.first { $0.id == second.id.uuid })
            let aBytes = try await store.read(name: a.objectName)!, bBytes = try await store.read(name: b.objectName)!
            try await store.delete(name: a.objectName)
            try await store.delete(name: b.objectName)
            try await store.create(name: a.objectName, data: bBytes, contentType: "application/octet-stream")
            try await store.create(name: b.objectName, data: aBytes, contentType: "application/octet-stream")
            try await eq(try await download(h, t.consumer, t.session, first.id).status, .notFound)
            try await eq(try await download(h, t.consumer, t.session, second.id).status, .notFound)
        }
    }

    // MARK: Storage

    func testTheStoreIsItsOwnPrivateContainerAndDeletesForReal() async throws {
        // Configuration: never the audit-head (write-once) or the brand-asset container; no development directory in production.
        var config = ServerConfig.testing()
        config.azure.clientId = "00000000-0000-0000-0000-000000000001"
        config.azure.auditBlobEndpoint = AzureStub.blob
        config.azure.auditBlobContainer = "audit-heads"
        config.brandKits.blobEndpoint = AzureStub.blob
        config.brandKits.blobContainer = "brand-assets"
        let identity = ["IDENTITY_ENDPOINT": "http://169.254.169.254/x", "IDENTITY_HEADER": "h", "AZURE_ATTACHMENT_BLOB_ENDPOINT": AzureStub.blob]
        for container in ["audit-heads", "brand-assets", "Bad_Name", ""] {
            XCTAssertThrowsError(try config.applyAttachmentEnvironment(identity.merging(["AZURE_ATTACHMENT_BLOB_CONTAINER": container]) { $1 }, production: true), container)
        }
        XCTAssertThrowsError(try config.applyAttachmentEnvironment(["ATTACHMENT_DIRECTORY": "/tmp/x"], production: true))
        XCTAssertThrowsError(try config.applyAttachmentEnvironment(["AZURE_ATTACHMENT_BLOB_ENDPOINT": "https://evil.example.com", "AZURE_ATTACHMENT_BLOB_CONTAINER": "attachments"], production: true))
        try config.applyAttachmentEnvironment(identity.merging(["AZURE_ATTACHMENT_BLOB_CONTAINER": "message-attachments"]) { $1 }, production: true)
        XCTAssertEqual(config.attachments.blobContainer, "message-attachments")
        // Strict environments without a store have none (uploads answer 503); the in-memory store is for development and tests only.
        var strict = ServerConfig.testing()
        strict.environment = .production
        XCTAssertNil(try AttachmentRuntime.store(config: strict, override: nil, tokens: nil, http: AzureStub(), now: { Date() }))
        // The Azure store deletes with its snapshots; an immutable (audit) container refuses, which surfaces as a failure to retry.
        let stub = AzureStub()
        let store = try AzureBlobObjectStore(endpoint: AzureStub.blob, container: "message-attachments", tokens: FakeAccessTokens(), http: stub)
        try await store.create(name: "attachments/a/b/c.bin", data: Data("x".utf8), contentType: "application/octet-stream")
        do {
            try await store.delete(name: "attachments/a/b/c.bin")
            XCTFail("the stub container is immutable")
        } catch ObjectStoreError.unavailable(let status) { XCTAssertEqual(status, 405) }
        let call = try XCTUnwrap(stub.calls.last)
        XCTAssertEqual(call.method, .DELETE)
        XCTAssertEqual(call.headers["x-ms-delete-snapshots"], "include")
        XCTAssertTrue(call.url.hasSuffix("/message-attachments/attachments/a/b/c.bin"), call.url)
        do { try await store.delete(name: "../escape"); XCTFail("invalid name") } catch ObjectStoreError.invalidName {}
        // The directory store deletes, and deleting what is gone succeeds.
        let dir = DirectoryObjectStore(directory: NSTemporaryDirectory() + "viadere-att-\(UUID().uuidString)")
        try await dir.create(name: "attachments/x.bin", data: Data("y".utf8), contentType: "application/octet-stream")
        try await dir.delete(name: "attachments/x.bin")
        try await dir.delete(name: "attachments/x.bin")
        let gone = try await dir.read(name: "attachments/x.bin")
        XCTAssertNil(gone)
    }

    // MARK: Lifetime

    func testUnsentUploadsExpireAndTheirObjectsAreRemoved() async throws {
        try await Self.withStore { h, store in
            let t = try await Self.thread(h)
            let image = try await upload(h, t.consumer, t.session, Self.png).json(MessageAttachment.self)
            XCTAssertEqual(image.expiresAt, h.clock.now().addingTimeInterval(MessageAttachmentPolicy.pendingLifetime))
            let draft = try await businessUpload(h, t.business, t.session, Self.png).json(MessageAttachment.self)
            XCTAssertEqual(store.names.count, 2)
            h.clock.advance(by: MessageAttachmentPolicy.pendingLifetime + 1)
            // A fresh sign-in (the access token outlived itself too), then: expired, no longer readable, no longer sendable.
            let consumer = try await h.login(t.consumer)
            try await eq(try await download(h, consumer, t.session, image.id).status, .notFound)
            try await eq(try await send(h, consumer, t.session, ids: [image.id]).status, .notFound)
            try await eq(try await businessSend(h, t, ids: [draft.id]).status, .notFound)
            try await h.runJobs()
            XCTAssertTrue(store.names.isEmpty)
            try await eq(try await MessageAttachmentRecord.query(on: h.db).count(), 0)
            // The pending cap per conversation.
            for _ in 0..<MessageAttachmentPolicy.maxPendingPerSession { try await eq(try await upload(h, consumer, t.session, Self.png).status, .created) }
            try await eq(try await upload(h, consumer, t.session, Self.png).status, .conflict)
        }
    }

    func testAccountDeletionTenantDeletionAndRetentionRemoveTheStoredObjects() async throws {
        try await Self.withStore { h, store in
            // Account deletion: both sides' images in the person's conversations.
            let t = try await Self.thread(h)
            let mine = try await upload(h, t.consumer, t.session, Self.png).json(MessageAttachment.self)
            try await eq(try await send(h, t.consumer, t.session, ids: [mine.id]).status, .created)
            let theirs = try await businessUpload(h, t.business, t.session, Self.png).json(MessageAttachment.self)
            try await eq(try await businessSend(h, t, body: "Thanks", ids: [theirs.id]).status, .created)
            // A bystander's image of the same business stays.
            let bystander = try await Self.thread(h, business: t.business)
            let kept = try await upload(h, bystander.consumer, bystander.session, Self.png).json(MessageAttachment.self)
            try await eq(try await send(h, bystander.consumer, bystander.session, ids: [kept.id]).status, .created)
            XCTAssertEqual(store.names.count, 3)
            try await eq(try await h.signed(t.consumer, .DELETE, "/v1/account").status, .ok)
            try await h.runJobs()
            XCTAssertEqual(store.names.count, 1)
            try await eq(try await MessageAttachmentRecord.query(on: h.db).filter(\.$consumerId == t.consumer.id.uuid).count(), 0)
            try await eq(try await businessDownload(h, t.business, bystander.session, kept.id).status, .ok)

            // Tenant deletion: every image of the organization.
            let other = try await Self.thread(h, name: "Doomed Co", handle: "doomedco")
            let doomed = try await upload(h, other.consumer, other.session, Self.png).json(MessageAttachment.self)
            try await eq(try await send(h, other.consumer, other.session, ids: [doomed.id]).status, .created)
            let request = DataRequestRecord()
            request.id = UUID()
            request.businessId = other.business.record.id!
            request.kind = "delete"
            request.status = "requested"
            request.requestedBy = UUID()
            request.createdAt = h.clock.now()
            try await request.create(on: h.db)
            try await TenantDataRequests(db: h.db, ctx: h.ctx).complete(id: request.id!, operatorId: UUID())
            try await h.runJobs()
            try await eq(try await MessageAttachmentRecord.query(on: h.db).filter(\.$businessId == other.business.record.id!).count(), 0)
            XCTAssertEqual(store.names.count, 1)

            // Retention: an image follows its message's conversation-content period.
            h.clock.advance(by: Double(RetentionClass.conversationContent.definition.defaultDays + 1) * 86_400)
            try await RetentionService(db: h.db, ctx: h.ctx).purge()
            try await h.runJobs()
            XCTAssertTrue(store.names.isEmpty)
            try await eq(try await MessageAttachmentRecord.query(on: h.db).count(), 0)
        }
    }

    // MARK: Business API happy path

    func testABusinessSendsAnImageThatTheCustomerSeesAndTheReplayIsIdempotent() async throws {
        try await Self.withStore { h, _ in
            let t = try await Self.thread(h)
            let up = try await businessUpload(h, t.business, t.session, Self.opaquePNG, type: "image/png")
            XCTAssertEqual(up.status, .created, up.text)
            let image = try up.json(MessageAttachment.self)
            let request = BusinessSendMessageRequest(relationshipId: t.relationship.id, sessionId: t.session, body: "", idempotencyKey: "img-1", attachmentIds: [image.id])
            let first = try await h.businessPost(t.business, "/v1/business/messages", request)
            XCTAssertEqual(first.status, .created, first.text)
            XCTAssertEqual(try first.json(ConversationMessage.self).attachments?.map(\.id), [image.id])
            let replay = try await h.businessPost(t.business, "/v1/business/messages", request)
            XCTAssertEqual(replay.status, .ok, replay.text)
            XCTAssertEqual(try replay.json(ConversationMessage.self).attachments?.map(\.id), [image.id])
            // The thread list shows "Image" for an image-only message.
            let list = try await h.signed(t.consumer, .GET, "/v1/conversations").json([ConversationSummary].self)
            XCTAssertEqual(list.first { $0.id == t.session }?.lastMessagePreview, "Image")
            // The audit chain records the upload without content.
            let audit = try await XCTUnwrapAsync(await AuditEventRecord.query(on: h.db).filter(\.$action == "message.attachment_uploaded").first())
            XCTAssertTrue(audit.metadataJSON.contains("image/jpeg"), audit.metadataJSON)
            XCTAssertFalse(audit.metadataJSON.contains(image.sha256))
        }
    }

    func testWithoutAStoreUploadsAreUnavailableAndTextStillWorks() async throws {
        try await Self.withStore { h, _ in
            let t = try await Self.thread(h)
            h.app.attachments.store = nil
            let r = try await upload(h, t.consumer, t.session, Self.png)
            XCTAssertEqual(r.status, .serviceUnavailable, r.text)
            try await eq(try await MessageAttachmentRecord.query(on: h.db).count(), 0)
            try await eq(try await send(h, t.consumer, t.session, body: "Text still works", ids: []).status, .created)
        }
    }

    func testTheConsoleShowsEscapedThumbnailsThroughItsOwnTenantCheckedRoute() async throws {
        try await withHarness(overrides: { $0.attachmentStore = MemoryObjectStore() }) { h in
            let t = try await ConsoleConversationsTests.tenant(h)
            let session = SessionID(t.session)
            let image = try await upload(h, t.consumer, session, Self.png).json(MessageAttachment.self)
            try await eq(try await send(h, t.consumer, session, body: "<img src=x onerror=alert(1)> photo", ids: [image.id]).status, .created)
            let thread = "/dashboard/conversations/\(t.session.uuidString.lowercased())"
            let page = try await h.page(thread, t.owner)
            XCTAssertEqual(page.status, .ok, page.text)
            let src = "\(thread)/attachments/\(image.id)"
            XCTAssertTrue(page.text.contains("<img src=\"\(src)\" alt=\"Image from the customer\" width=\"40\" height=\"30\""), page.text)
            XCTAssertFalse(page.text.contains("<img src=x"))
            XCTAssertTrue(page.text.contains("&lt;img src=x onerror=alert(1)&gt; photo"))
            // The thumbnail route: inline image with the safe headers for a member who can view conversations...
            let thumb = try await h.page(src, t.owner)
            Self.assertSafeImageHeaders(thumb, type: image.mediaType)
            XCTAssertTrue(thumb.headers.first(name: "Content-Disposition")?.hasPrefix("inline;") == true)
            XCTAssertTrue(image.matches(thumb.body))
            // ...and nothing for a role without the permission, an anonymous visitor, or another organization.
            let developer = try await h.addMember(owner: t.owner, role: .developer, email: "dev@example.com")
            try await eq(try await h.page(src, developer.session).status, .forbidden)
            let anonymous = try await h.page(src, nil)
            XCTAssertNotEqual(anonymous.status, .ok)
            let other = try await ConsoleConversationsTests.tenant(h, email: "other@example.com", org: "Other Shop", handle: "othershop", body: "Hello")
            try await eq(try await h.page(src, other.owner).status, .notFound)
            try await eq(try await h.page("/dashboard/conversations/\(other.session.uuidString.lowercased())/attachments/\(image.id)", other.owner).status, .notFound)

            // The console adds an image (multipart, CSRF, reply permission) and sends it with a reply.
            let (body, contentType) = BrandKitServerTests.multipart([("_csrf", h.csrf(t.owner))], file: ("file", "photo.png", "image/png", Self.opaquePNG))
            var headers = h.cookieHeaders(t.owner)
            headers["Origin"] = h.origin
            let added = try await h.request(.POST, "\(thread)/attachments", headers: headers, body: body, contentType: contentType)
            XCTAssertEqual(added.status, .seeOther, added.text)
            let forged = BrandKitServerTests.multipart([("_csrf", "forged")], file: ("file", "photo.png", "image/png", Self.opaquePNG))
            try await eq(try await h.request(.POST, "\(thread)/attachments", headers: headers, body: forged.0, contentType: forged.1).status, .forbidden)
            let svg = BrandKitServerTests.multipart([("_csrf", h.csrf(t.owner))], file: ("file", "logo.png", "image/png", Data("<svg onload=alert(1)>".utf8)))
            let svgResult = try await h.request(.POST, "\(thread)/attachments", headers: headers, body: svg.0, contentType: svg.1)
            XCTAssertNotEqual(svgResult.status, .seeOther)
            let auditor = try await h.addMember(owner: t.owner, role: .auditor, email: "auditor@example.com")
            var auditorHeaders = h.cookieHeaders(auditor.session)
            auditorHeaders["Origin"] = h.origin
            let viewerUpload = BrandKitServerTests.multipart([("_csrf", h.csrf(auditor.session))], file: ("file", "photo.png", "image/png", Self.opaquePNG))
            try await eq(try await h.request(.POST, "\(thread)/attachments", headers: auditorHeaders, body: viewerUpload.0, contentType: viewerUpload.1).status, .forbidden)
            let pending = try await XCTUnwrapAsync(await MessageAttachmentRecord.query(on: h.db).filter(\.$side == "business").first())
            XCTAssertTrue(pending.uploaderRef.hasPrefix("console:"))
            let withImage = try await h.page(thread, t.owner)
            XCTAssertTrue(withImage.text.contains("name=\"image_\(pending.id!.uuidString.lowercased())\""), withImage.text)
            let key = try XCTUnwrap(withImage.text.range(of: "name=\"idempotency_key\" value=\"").map { String(withImage.text[$0.upperBound...].prefix { $0 != "\"" }) })
            let reply = try await h.formPost("\(thread)/reply", t.owner, [("body", ""), ("idempotency_key", key), ("image_\(pending.id!.uuidString.lowercased())", "1")])
            XCTAssertEqual(reply.status, .seeOther, reply.text)
            try await eq(try await MessageAttachmentRecord.find(pending.id!, on: h.db)?.state, "attached")
            let customer = try await h.signed(t.consumer, .GET, "/v1/conversations/\(session)/messages").json(Page<ConversationMessage>.self)
            XCTAssertTrue(customer.items.contains { $0.direction == .businessToConsumer && $0.attachments?.first?.id == AttachmentID(pending.id!) })
        }
    }
}

// MARK: - SMS

extension SMSGatewayTests {
    /// A business image in an SMS conversation: the text says an image is waiting in the app, with no link; an inbound MMS is never fetched.
    func testABusinessImageNeverReachesAnSMSThreadAndAnInboundMMSIsIgnored() async throws {
        let store = MemoryObjectStore()
        try await withHarness(overrides: { $0.attachmentStore = store }) { h in
            let airline = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            try await linkPhone(h, consumer)
            try await subscribeMessages(h, airline)
            _ = try await say(h, "Hi")
            _ = try await say(h, "Northwind Air")
            _ = try await say(h, "1")
            // An MMS: the media URL is ignored (never fetched, never stored), only the text is forwarded.
            let path = "/v1/providers/sms/inbound"
            let params: [(String, String)] = [("MessageSid", "SMmmsone"), ("From", phone), ("To", "+15550001111"), ("Body", "Boarding pass attached"),
                                              ("NumMedia", "1"), ("MediaUrl0", "https://media.example.com/evil.svg"), ("MediaContentType0", "image/svg+xml")]
            let signature = TwilioProvider.signature(authToken: RecordingSMSProvider.authToken, url: h.config.publicBaseURL + path, params: params)
            let mms = try await h.request(.POST, path, headers: ["X-Twilio-Signature": signature], body: smsForm(params), contentType: "application/x-www-form-urlencoded")
            XCTAssertEqual(mms.status, .ok, mms.text)
            try await h.runJobs()
            let received = try forwarded(h, to: airline)
            let last = try XCTUnwrap(received.last)
            XCTAssertEqual(last.text, "Boarding pass attached")
            XCTAssertNil(last.attachments)
            try await eq(try await MessageAttachmentRecord.query(on: h.db).count(), 0)
            XCTAssertTrue(store.names.isEmpty)
            // The airline answers with an image in the same (SMS) session.
            let up = try await h.request(.POST, "/v1/business/conversations/\(last.sessionId)/attachments", headers: ["Authorization": "Bearer \(airline.key)"],
                                         body: MessageAttachmentTests.png, contentType: "image/png")
            XCTAssertEqual(up.status, .created, up.text)
            let image = try up.json(MessageAttachment.self)
            for (key, body) in [("sms-img-1", "Here is your new seat map"), ("sms-img-2", "")] {
                let next = key == "sms-img-1" ? image : try await h.request(.POST, "/v1/business/conversations/\(last.sessionId)/attachments",
                                                                             headers: ["Authorization": "Bearer \(airline.key)"], body: MessageAttachmentTests.png,
                                                                             contentType: "image/png").json(MessageAttachment.self)
                let before = h.texts.sent.count
                let sent = try await h.businessPost(airline, "/v1/business/messages", BusinessSendMessageRequest(relationshipId: last.relationshipId, sessionId: last.sessionId,
                                                                                                                  body: body, idempotencyKey: key, attachmentIds: [next.id]))
                XCTAssertEqual(sent.status, .created, sent.text)
                try await h.runJobs()
                let texts = h.texts.sent.dropFirst(before).map(\.body)
                XCTAssertEqual(texts.count, 1, "\(texts)")
                let text = texts.joined()
                XCTAssertTrue(text.contains("Viadere: Northwind Air sent you an image. Open the Viadere app to see it."), text)
                if !body.isEmpty { XCTAssertTrue(text.contains(body), text) }
                for needle in ["http", "://", "www.", "/v1/", next.id.description, "attachments"] { XCTAssertFalse(text.contains(needle), "SMS contains \(needle): \(text)") }
            }
            // The customer sees the image in the app history.
            let page = try await h.signed(consumer, .GET, "/v1/conversations/\(last.sessionId)/messages").json(Page<ConversationMessage>.self)
            XCTAssertTrue(page.items.contains { $0.attachments?.first?.id == image.id })
        }
    }
}
