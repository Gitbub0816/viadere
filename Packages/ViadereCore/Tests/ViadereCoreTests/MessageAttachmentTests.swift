import Crypto
import Foundation
import Testing
@testable import ViadereCore

/// Message attachments (SECURITY.md §2.113): the shared limits, the wire form and the SMS copy. The server's exploit-path tests are in
/// `Server/Tests/ViadereServerKitTests/MessageAttachmentTests.swift`.
@Suite("Message attachments")
struct MessageAttachmentTests {
    @Test func limitsAreThePipelinesOwnAndNoLooser() {
        #expect(MessageAttachmentPolicy.maxUploadBytes == BrandAssetPolicy.maxUploadBytes)
        #expect(MessageAttachmentPolicy.maxSourceDimension == BrandAssetPolicy.maxSourceDimension)
        #expect(MessageAttachmentPolicy.maxSourcePixels == BrandAssetPolicy.maxSourcePixels)
        #expect(MessageAttachmentPolicy.maxStoredDimension <= MessageAttachmentPolicy.maxSourceDimension)
        #expect(MessageAttachmentPolicy.storedMediaTypes == ["image/png", "image/jpeg"])
        #expect(MessageAttachmentPolicy.maxPerMessage == 4)
    }

    @Test func precheckRefusesMarkupSVGAndMislabelsBeforeDecoding() {
        let png: [UInt8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13]
        #expect(throws: Never.self) { try MessageAttachmentPolicy.precheck(declaredContentType: "image/png", byteCount: 100, prefix: Data(png)).get() }
        #expect(MessageAttachmentPolicy.precheck(declaredContentType: "image/jpeg", byteCount: 100, prefix: Data(png)) == .failure(.contentTypeMismatch))
        #expect(MessageAttachmentPolicy.precheck(declaredContentType: "image/png", byteCount: 100, prefix: Data("<svg onload=alert(1)>".utf8)) == .failure(.svgRefused))
        #expect(MessageAttachmentPolicy.precheck(declaredContentType: "image/png", byteCount: 100, prefix: Data("<html><script>".utf8)) == .failure(.markupRefused))
        #expect(MessageAttachmentPolicy.precheck(declaredContentType: "image/gif", byteCount: 100, prefix: Data("GIF89a".utf8)) == .failure(.unsupportedFormat))
        #expect(MessageAttachmentPolicy.precheck(declaredContentType: "image/png", byteCount: MessageAttachmentPolicy.maxUploadBytes + 1, prefix: Data(png)) == .failure(.tooLarge))
        #expect(MessageAttachmentPolicy.precheck(declaredContentType: "image/png", byteCount: 0, prefix: Data()) == .failure(.empty))
    }

    @Test func storedSizeKeepsAspectAndNeverUpscales() {
        #expect(MessageAttachmentPolicy.targetSize(width: 4096, height: 3072) == (2048, 1536))
        #expect(MessageAttachmentPolicy.targetSize(width: 1000, height: 8000) == (256, 2048))
        #expect(MessageAttachmentPolicy.targetSize(width: 640, height: 480) == (640, 480))
    }

    @Test func idListsAreBoundedAndUnique() {
        let a = AttachmentID(), b = AttachmentID()
        #expect(MessageAttachmentPolicy.validate(nil))
        #expect(MessageAttachmentPolicy.validate([]))
        #expect(MessageAttachmentPolicy.validate([a, b]))
        #expect(!MessageAttachmentPolicy.validate([a, a]))
        #expect(!MessageAttachmentPolicy.validate((0...MessageAttachmentPolicy.maxPerMessage).map { _ in AttachmentID() }))
    }

    @Test func wireFormIsMetadataOnlyAndOlderPayloadsStillDecode() throws {
        let attachment = MessageAttachment(id: AttachmentID(), sessionId: SessionID(), mediaType: "image/jpeg", byteSize: 4, width: 2, height: 1,
                                           sha256: Hex.encode(Data(SHA256Hasher.digest(Data([1, 2, 3, 4])))), state: .attached)
        let json = String(decoding: try ViadereJSON.encode(attachment), as: UTF8.self)
        for key in ["\"id\"", "\"sessionId\"", "\"mediaType\"", "\"byteSize\"", "\"width\"", "\"height\"", "\"sha256\"", "\"state\""] { #expect(json.contains(key)) }
        #expect(!json.contains("url") && !json.contains("data") && !json.contains("bytes\""))
        #expect(attachment.matches(Data([1, 2, 3, 4])))
        #expect(!attachment.matches(Data([1, 2, 3, 5])))
        // A message from an older server has no attachments member; a request from an older client has no attachmentIds.
        let message = ConversationMessage(id: MessageID(), sessionId: SessionID(), businessId: BusinessID(), direction: .consumerToBusiness,
                                          attribution: MessageAttribution(senderType: .consumer, displayName: "You"), body: "Hi", channel: .inApp,
                                          createdAt: Date(timeIntervalSince1970: 1_800_000_000), deliveryStatus: .delivered)
        var object = try #require(try JSONSerialization.jsonObject(with: ViadereJSON.encode(message)) as? [String: Any])
        #expect(object["attachments"] == nil)
        object["attachments"] = nil
        #expect(try ViadereJSON.decode(ConversationMessage.self, from: JSONSerialization.data(withJSONObject: object)).attachments == nil)
        let request = try ViadereJSON.decode(SendMessageRequest.self, from: Data(#"{"body":"Hi","clientMessageId":"c1"}"#.utf8))
        #expect(request.attachmentIds == nil)
        let business = try ViadereJSON.decode(BusinessSendMessageRequest.self, from: Data("""
        {"relationshipId":"\(RelationshipID())","body":"","idempotencyKey":"k","attachmentIds":["\(attachment.id)"]}
        """.utf8))
        #expect(business.attachmentIds == [attachment.id])
        #expect(String(decoding: try ViadereJSON.encode(business), as: UTF8.self).contains("attachmentIds"))
    }

    @Test func smsCopyNamesTheBusinessAndCarriesNoLink() {
        let one = MessageAttachmentCopy.smsText(body: "", business: "Acme Roasters", count: 1)
        #expect(one == "Viadere: Acme Roasters sent you an image. Open the Viadere app to see it.")
        let many = MessageAttachmentCopy.smsText(body: "Here is your receipt.", business: "Acme Roasters", count: 3)
        #expect(many == "Here is your receipt.\n\nViadere: Acme Roasters sent you 3 images. Open the Viadere app to see them.")
        #expect(MessageAttachmentCopy.smsText(body: "Text only", business: "Acme", count: 0) == "Text only")
        for text in [one, many] { #expect(!text.contains("http") && !text.contains("://") && !text.contains("www.")) }
        #expect(MessageAttachmentCopy.preview(count: 1) == "Image")
    }

    @Test func theRoutesAreInTheCatalog() {
        let names = Set(APIRoutes.all.map(\.name))
        for name in ["conversations.attachments.upload", "conversations.attachments.get", "business.attachments.upload", "business.attachments.get"] {
            #expect(names.contains(name))
        }
        #expect(APIRoutes.conversationAttachment.auth == .deviceSignedBearer)
        #expect(APIRoutes.businessAttachment.auth == .businessAPIKey)
    }
}

/// Test-only SHA-256 (Crypto is a dependency of Core).
enum SHA256Hasher { static func digest(_ data: Data) -> SHA256.Digest { SHA256.hash(data: data) } }
