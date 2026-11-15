import Foundation
import Testing
@testable import ViadereKit
import ViadereCore

/// Composer and thread image logic (SECURITY.md §2.113): checks before upload, upload states and failures, sending only uploaded images,
/// and never showing bytes that do not match their reference.
@MainActor
@Suite("Message attachments (app)")
struct MessageAttachmentViewModelTests {
    actor FakeAttachments: MessageAttachmentsAPI {
        var uploads: [(Data, String, SessionID)] = []
        var failNext: APIError?
        var stored: [AttachmentID: Data] = [:]
        var served: Data?

        func setFailNext(_ error: APIError?) { failNext = error }
        func serve(_ data: Data?) { served = data }

        func upload(_ data: Data, mediaType: String, to session: SessionID) async throws -> MessageAttachment {
            if let failNext { self.failNext = nil; throw failNext }
            uploads.append((data, mediaType, session))
            let id = AttachmentID()
            stored[id] = data
            return MessageAttachment(id: id, sessionId: session, mediaType: mediaType, byteSize: data.count, width: 4, height: 3,
                                     sha256: SecureToken.sha256Hex(data), state: .pending, expiresAt: Date().addingTimeInterval(3600))
        }

        func download(_ attachment: AttachmentID, in session: SessionID) async throws -> Data {
            if let served { return served }
            guard let data = stored[attachment] else { throw APIError.server(status: 404, code: .notFound, message: "Not found") }
            return data
        }
    }

    static let png = Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] + Array(repeating: 0, count: 32))
    static let jpeg = Data([0xFF, 0xD8, 0xFF, 0xE0] + Array(repeating: 1, count: 32))

    func model(_ fake: FakeAttachments?) async throws -> (ConversationViewModel, MockViadereAPI) {
        let api = MockViadereAPI(seed: false)
        var services = await ViadereServices.mock(api: api)
        services.attachmentsAPI = fake
        let conversation = try await api.startConversation(with: PreviewData.lindenStudio.id)
        return (ConversationViewModel(conversation: conversation, services: services), api)
    }

    @Test func hostileOrOversizedFilesAreRefusedBeforeAnyUpload() async throws {
        let fake = FakeAttachments()
        let (model, _) = try await model(fake)
        await model.addImage(Data("<svg onload=alert(1)>".utf8), mediaType: "image/png")
        #expect(model.errorMessage == "Send a photo or a PNG or JPEG image.")
        await model.addImage(Data("<html><script>".utf8), mediaType: "image/jpeg")
        await model.addImage(Self.jpeg, mediaType: "image/png")
        #expect(model.errorMessage == "The file's type does not match its contents. Send a real PNG or JPEG.")
        await model.addImage(Self.png + Data(count: MessageAttachmentPolicy.maxUploadBytes), mediaType: "image/png")
        #expect(model.errorMessage == "That image is larger than 2 MB.")
        await model.addImage(Data(), mediaType: "image/png")
        #expect(await fake.uploads.isEmpty)
        #expect(model.images.isEmpty)
    }

    @Test func uploadsAreBoundToThisConversationAndOnlyUploadedImagesAreSent() async throws {
        let fake = FakeAttachments()
        let (model, _) = try await model(fake)
        #expect(model.canAddImage)
        #expect(!model.canSend)
        await model.addImage(Self.jpeg, mediaType: "image/jpeg")
        #expect(model.images.count == 1)
        #expect(model.images[0].attachment != nil)
        #expect(await fake.uploads.first?.2 == model.conversation.id)
        // An image alone can be sent; a failed upload stays in the composer and is not sent.
        await fake.setFailNext(.server(status: 422, code: .validationFailed, message: "That image could not be read."))
        await model.addImage(Self.png, mediaType: "image/png")
        #expect(model.images.count == 2)
        #expect(model.images[1].failure == "That image could not be read.")
        #expect(model.canSend)
        await model.send()
        let sent = try #require(model.rows.last?.message)
        #expect(sent.attachments?.count == 1)
        #expect(model.images.count == 1 && model.images[0].failure != nil)
        // Retry turns it into an uploaded image; remove drops it.
        await model.retryImage(model.images[0].id)
        #expect(model.images[0].attachment != nil)
        model.removeImage(model.images[0].id)
        #expect(model.images.isEmpty)
    }

    @Test func atMostFourImagesAndNoPickerWithoutTheAPI() async throws {
        let fake = FakeAttachments()
        let (model, _) = try await model(fake)
        for _ in 0..<MessageAttachmentPolicy.maxPerMessage { await model.addImage(Self.png, mediaType: "image/png") }
        #expect(!model.canAddImage)
        await model.addImage(Self.png, mediaType: "image/png")
        #expect(model.errorMessage == ComposerImageRules.tooMany)
        #expect(model.images.count == MessageAttachmentPolicy.maxPerMessage)
        let (bare, _) = try await self.model(nil)
        #expect(!bare.canAddImage)
        await bare.addImage(Self.png, mediaType: "image/png")
        #expect(bare.images.isEmpty)
    }

    @Test func downloadedBytesAreShownOnlyWhenTheyMatchTheirReference() async throws {
        let fake = FakeAttachments()
        let (model, _) = try await model(fake)
        await model.addImage(Self.jpeg, mediaType: "image/jpeg")
        var attachment = try #require(model.images.first?.attachment)
        attachment.state = .attached
        await model.loadImage(attachment)
        #expect(model.loadedImages[attachment.id] == Self.jpeg)
        // Tampered or substituted bytes are never shown.
        let other = MessageAttachment(id: AttachmentID(), sessionId: model.conversation.id, mediaType: "image/png", byteSize: Self.png.count, width: 1, height: 1,
                                      sha256: String(repeating: "a", count: 64), state: .attached)
        await fake.serve(Self.png)
        await model.loadImage(other)
        #expect(model.loadedImages[other.id] == nil)
        #expect(model.imageErrors.contains(other.id))
        // An attachment of another conversation is not even requested.
        let foreign = MessageAttachment(id: AttachmentID(), sessionId: SessionID(), mediaType: "image/png", byteSize: 1, width: 1, height: 1,
                                        sha256: String(repeating: "b", count: 64), state: .attached)
        await model.loadImage(foreign)
        #expect(model.loadedImages[foreign.id] == nil && !model.imageErrors.contains(foreign.id))
    }
}
