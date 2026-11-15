import Foundation
import ViadereCore

// MARK: Message attachments (SECURITY.md §2.113; scope `messages:write`, capability `message.send`)

extension ViadereBusinessClient {
    /// Uploads one image to a conversation of your business (`POST /v1/business/conversations/{sessionId}/attachments`). The body is the raw
    /// image with `Content-Type: image/png` or `image/jpeg`, at most `MessageAttachmentPolicy.maxUploadBytes` (2 MiB).
    ///
    /// Checked before anything is sent, with the same rules as the server's first step (`MessageAttachmentPolicy.precheck`): not empty, at most
    /// 2 MiB, PNG or JPEG, and the declared type must match the bytes (`ViadereSDKError.attachmentRejected`). The server then decodes and
    /// **re-encodes** the image (no metadata survives) and answers a **pending** attachment: name its id in
    /// `BusinessSendMessageRequest.attachmentIds` with the same `sessionId` within an hour.
    ///
    /// Not retried automatically: the route takes no idempotency key, so a repeat after a lost response would store a second pending copy.
    /// With a request signer the RFC 9421 signature covers the image bytes (`content-digest`) and `content-type`.
    public func uploadAttachment(sessionId: SessionID, data: Data, contentType: String) async throws -> MessageAttachment {
        let declared = contentType.split(separator: ";").first.map { $0.trimmingCharacters(in: .whitespaces).lowercased() } ?? ""
        guard MessageAttachmentPolicy.storedMediaTypes.contains(declared) else { throw ViadereSDKError.attachmentRejected(.unsupportedFormat) }
        if case .failure(let rejection) = MessageAttachmentPolicy.precheck(declaredContentType: declared, byteCount: data.count, prefix: data.prefix(64)) {
            throw ViadereSDKError.attachmentRejected(rejection)
        }
        let response = try await performRaw(APIRoutes.businessAttachmentUpload.descriptor, parameters: ["sessionId": sessionId.description],
                                            body: (data, declared))
        let attachment = try decode(MessageAttachment.self, response)
        // The answer is about this conversation, and is an image type the download can serve.
        guard attachment.sessionId == sessionId, MessageAttachmentPolicy.storedMediaTypes.contains(attachment.mediaType) else {
            throw ViadereSDKError.attachmentMismatch
        }
        return attachment
    }

    /// Downloads the stored image of an attachment reference (from `uploadAttachment`, a sent `ConversationMessage.attachments` or a
    /// `message.received` webhook), `GET /v1/business/conversations/{sessionId}/attachments/{attachmentId}`. The bytes are returned only when
    /// their size and SHA-256 match the reference (`MessageAttachment.matches`) and the response type is the reference's; otherwise
    /// `ViadereSDKError.attachmentMismatch` and nothing is returned. Retried like every `GET`.
    public func downloadAttachment(_ attachment: MessageAttachment) async throws -> Data {
        let response = try await perform(APIRoutes.businessAttachment.descriptor,
                                         parameters: ["sessionId": attachment.sessionId.description, "attachmentId": attachment.id.description],
                                         accept: "image/png, image/jpeg")
        if let type = response.header("Content-Type") {
            let served = type.split(separator: ";").first.map { $0.trimmingCharacters(in: .whitespaces).lowercased() } ?? ""
            guard served == attachment.mediaType.lowercased() else { throw ViadereSDKError.attachmentMismatch }
        }
        guard attachment.matches(response.body) else { throw ViadereSDKError.attachmentMismatch }
        return response.body
    }
}
