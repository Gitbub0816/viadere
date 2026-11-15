import Fluent
import Foundation
import Vapor
import ViadereCore
import typealias ViadereCore.SessionID
import XCTest
@testable import ViadereServerKit

/// Rendering input for screenshots of a console thread with images (SECURITY.md §2.113): seeds a customer photo, a business reply with an image
/// and an image waiting to be sent, then writes the thread page to `$CONSOLE_PAGES_DIR/conversation-thread-attachments.html` with each image
/// saved beside it (the page's same-origin image routes are rewritten to those files). Skipped unless that variable is set.
final class ConsoleAttachmentsDump: XCTestCase {
    /// An opaque, photo-like test image (soft gradient and a few discs), generated here so no real photo is needed.
    static func photo(width: Int, height: Int, hue: (UInt8, UInt8, UInt8)) -> Data {
        var rgba = [UInt8]()
        rgba.reserveCapacity(width * height * 4)
        let discs = [(0.3, 0.4, 0.18), (0.7, 0.55, 0.24), (0.5, 0.8, 0.12)]
        for y in 0..<height {
            for x in 0..<width {
                let fx = Double(x) / Double(width), fy = Double(y) / Double(height)
                var r = Double(hue.0) * (0.55 + 0.45 * fy), g = Double(hue.1) * (0.6 + 0.4 * fx), b = Double(hue.2) * (0.7 + 0.3 * (1 - fy))
                for (cx, cy, radius) in discs where (fx - cx) * (fx - cx) + (fy - cy) * (fy - cy) * 0.6 < radius * radius {
                    r = min(255, r * 1.18 + 18); g = min(255, g * 1.12 + 14); b = min(255, b * 1.05 + 10)
                }
                rgba += [UInt8(min(255, r)), UInt8(min(255, g)), UInt8(min(255, b)), 255]
            }
        }
        return BrandImagePipeline.encodePNG(.init(width: width, height: height, rgba: rgba))!
    }

    func testDumpConversationThreadWithAttachments() async throws {
        guard let dir = ProcessInfo.processInfo.environment["CONSOLE_PAGES_DIR"] else { throw XCTSkip("CONSOLE_PAGES_DIR not set") }
        let root = URL(fileURLWithPath: dir, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try await withHarness(overrides: { $0.attachmentStore = MemoryObjectStore() }) { h in
            let (owner, _, businessId) = try await h.verifiedOwner(org: "Acme Roasters and Provisions")
            let business = try await h.testBusiness(businessId)
            let consumer = try await h.readyConsumer()
            _ = try await h.connect(consumer, to: business, optIn: [.support])
            let started = try await h.signedPost(consumer, APIRoutes.conversationStart.template, StartConversationRequest(businessId: business.id))
            let session = try started.json(ConversationSummary.self).id
            func upload(_ data: Data) async throws -> MessageAttachment {
                let path = "/v1/conversations/\(session)/attachments"
                let headers = try await h.signedHeaders(consumer, .POST, path, body: data)
                return try await h.request(.POST, path, headers: headers, body: data, contentType: "image/png").json(MessageAttachment.self)
            }
            let bag = try await upload(Self.photo(width: 960, height: 720, hue: (190, 140, 96)))
            _ = try await h.signedPost(consumer, "/v1/conversations/\(session)/messages",
                                       SendMessageRequest(body: "The bag I picked up today is torn at the seam. Photo attached. <b>Not bold</b>", clientMessageId: "c1", attachmentIds: [bag.id]))
            h.clock.advance(by: 240)
            let label = try await upload(Self.photo(width: 600, height: 800, hue: (120, 150, 170)))
            _ = try await h.signedPost(consumer, "/v1/conversations/\(session)/messages", SendMessageRequest(body: "", clientMessageId: "c2", attachmentIds: [label.id]))
            h.clock.advance(by: 300)
            let thread = "/dashboard/conversations/\(session.uuid.uuidString.lowercased())"
            // The business adds an image in the console and sends it with a reply.
            func consoleImage(_ data: Data) async throws {
                let (body, type) = BrandKitServerTests.multipart([("_csrf", h.csrf(owner))], file: ("file", "replacement.png", "image/png", data))
                var headers = h.cookieHeaders(owner)
                headers["Origin"] = h.origin
                _ = try await h.request(.POST, "\(thread)/attachments", headers: headers, body: body, contentType: type)
            }
            try await consoleImage(Self.photo(width: 800, height: 600, hue: (150, 170, 120)))
            var page = try await h.page(thread, owner)
            let key = page.text.range(of: "name=\"idempotency_key\" value=\"").map { String(page.text[$0.upperBound...].prefix { $0 != "\"" }) } ?? ""
            let pendingId = try await MessageAttachmentRecord.query(on: h.db).filter(\.$side == "business").filter(\.$state == "pending").first()!.id!
            _ = try await h.formPost("\(thread)/reply", owner, [("body", "Sorry about that. Here is the replacement we set aside for you."), ("agent_name", "Dana"),
                                                               ("idempotency_key", key), ("image_\(pendingId.uuidString.lowercased())", "1")])
            // One more image waiting in the reply form.
            try await consoleImage(Self.photo(width: 640, height: 640, hue: (200, 120, 110)))
            page = try await h.page(thread + "?cm=image", owner)
            var html = page.text
            for row in try await MessageAttachmentRecord.query(on: h.db).all() {
                let id = AttachmentID(row.id!)
                let image = try await h.page(ConsoleConversations.attachmentPath(session: session.uuid, attachment: id), owner)
                let file = "att-\(id).\(row.mediaType == "image/png" ? "png" : "jpg")"
                try image.body.write(to: root.appendingPathComponent(file))
                html = html.replacingOccurrences(of: ConsoleConversations.attachmentPath(session: session.uuid, attachment: id), with: file)
            }
            try Data(html.utf8).write(to: root.appendingPathComponent("conversation-thread-attachments.html"))
        }
    }
}
