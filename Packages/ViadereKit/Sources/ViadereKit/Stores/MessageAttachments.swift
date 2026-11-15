import Foundation
import ViadereCore

/// The app's attachment calls (SECURITY.md §2.113): upload one image to a conversation, fetch the stored bytes of one.
public protocol MessageAttachmentsAPI: Sendable {
    func upload(_ data: Data, mediaType: String, to session: SessionID) async throws -> MessageAttachment
    func download(_ attachment: AttachmentID, in session: SessionID) async throws -> Data
}

public struct LiveMessageAttachmentsAPI: MessageAttachmentsAPI {
    let client: APIClient
    public init(client: APIClient) { self.client = client }

    public func upload(_ data: Data, mediaType: String, to session: SessionID) async throws -> MessageAttachment {
        try await client.upload(APIRoutes.conversationAttachmentUpload, params: ["sessionId": session.description], body: data, contentType: mediaType)
    }

    public func download(_ attachment: AttachmentID, in session: SessionID) async throws -> Data {
        try await client.data(APIRoutes.conversationAttachment, params: ["sessionId": session.description, "attachmentId": attachment.description])
    }
}

/// One image in the composer, from picking to being sent.
public struct ComposerImage: Identifiable, Sendable, Equatable {
    public enum Status: Sendable, Equatable {
        /// Being uploaded (re-encoded and stored by the server).
        case uploading
        /// Stored as a pending attachment; sent with the next message.
        case ready(MessageAttachment)
        /// Refused or failed; the person can remove it or retry.
        case failed(String)
    }

    public let id: UUID
    /// The re-encoded bytes the app sends (a preview source until sent; never cached to disk).
    public let data: Data
    public let mediaType: String
    public var status: Status

    public var attachment: MessageAttachment? { if case .ready(let a) = status { a } else { nil } }
    public var isUploading: Bool { status == .uploading }
    public var failure: String? { if case .failed(let m) = status { m } else { nil } }
}

/// Pure checks the composer runs before anything leaves the device (MSG-ATT copy in docs/product/UX_COPY.md).
public enum ComposerImageRules {
    /// The type the bytes really are, or the reason they cannot be sent. The app re-encodes a picked photo to JPEG (longest side
    /// `MessageAttachmentPolicy.maxStoredDimension`, orientation applied, no metadata) before calling this, so a refusal here is rare.
    public static func check(_ data: Data, declared: String) -> Result<String, MessageAttachmentPolicy.Rejection> {
        switch MessageAttachmentPolicy.precheck(declaredContentType: declared, byteCount: data.count, prefix: data.prefix(64)) {
        case .failure(let rejection): .failure(rejection)
        case .success(.png): .success("image/png")
        case .success(.jpeg): .success("image/jpeg")
        case .success: .failure(.unsupportedFormat)
        }
    }

    public static let tooMany = "You can send up to \(MessageAttachmentPolicy.maxPerMessage) images in one message."
    public static let uploadFailed = "Couldn't add that image. Try again."
    public static let unavailable = "Images can't be sent from here."
}
