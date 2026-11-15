import Foundation
import Vapor
import ViadereCore
import typealias ViadereCore.SessionID

/// The app's and the business API's attachment routes (SECURITY.md §2.113). Uploads are the raw image (`image/png` or `image/jpeg`); the size
/// cap is enforced from `Content-Length` before anything is read (`RequestGuardMiddleware`) and again while collecting a chunked body.
enum MessageAttachmentRoutes {
    static let uploadLimit = MessageAttachmentPolicy.maxUploadBytes

    /// `POST /v1/conversations/{uuid}/attachments` and `POST /v1/business/conversations/{uuid}/attachments`: the only API paths whose body
    /// is an image (not JSON), and whose ceiling is the upload limit.
    static func isUploadPath(_ path: String) -> Bool {
        let parts = path.split(separator: "/", omittingEmptySubsequences: false)
        switch parts.count {
        case 5: return parts[0].isEmpty && parts[1] == "v1" && parts[2] == "conversations" && UUID(uuidString: String(parts[3])) != nil && parts[4] == "attachments"
        case 6: return parts[0].isEmpty && parts[1] == "v1" && parts[2] == "business" && parts[3] == "conversations"
            && UUID(uuidString: String(parts[4])) != nil && parts[5] == "attachments"
        default: return false
        }
    }

    /// The declared type of an upload (`type/subtype`, lowercase, parameters dropped); the pipeline checks it against the bytes.
    static func declaredType(_ req: Request) -> String {
        req.headers.contentType.map { "\($0.type)/\($0.subType)".lowercased() } ?? ""
    }

    static func register(_ routes: any RoutesBuilder) {
        routes.api(APIRoutes.conversationAttachmentUpload, bodyLimit: ByteCount(value: uploadLimit)) { req in
            let consumer = try req.consumer
            let id: SessionID = try req.uuidParameter("sessionId")
            let data = try await req.collectedBody(limit: uploadLimit)
            let attachment = try await MessageAttachmentService(db: req.db, ctx: req.ctx, runtime: req.attachments)
                .consumerUpload(consumer: consumer.consumerId, deviceId: consumer.deviceId, sessionId: id, data: data, contentType: declaredType(req))
            return try req.jsonResponse(attachment, status: .created)
        }
        routes.api(APIRoutes.conversationAttachment) { req in
            let id: SessionID = try req.uuidParameter("sessionId")
            let attachmentId: AttachmentID = try req.uuidParameter("attachmentId")
            let (row, data) = try await MessageAttachmentService(db: req.db, ctx: req.ctx, runtime: req.attachments)
                .consumerDownload(consumer: try req.consumer.consumerId, sessionId: id, attachmentId: attachmentId)
            return MessageAttachmentService.imageResponse(data, row: row, disposition: .attachment)
        }
        routes.api(APIRoutes.businessAttachmentUpload, scope: BusinessAPIKeys.Scope.messagesWrite, bodyLimit: ByteCount(value: uploadLimit)) { req in
            let principal = try req.business
            try await req.requireCapability(.messageSend)
            let id: SessionID = try req.uuidParameter("sessionId")
            let data = try await req.collectedBody(limit: uploadLimit)
            let attachment = try await MessageAttachmentService(db: req.db, ctx: req.ctx, runtime: req.attachments)
                .businessUpload(principal: principal, sessionId: id, data: data, contentType: declaredType(req))
            return try req.jsonResponse(attachment, status: .created)
        }
        routes.api(APIRoutes.businessAttachment, scope: BusinessAPIKeys.Scope.messagesWrite) { req in
            let principal = try req.business
            try await req.requireCapability(.messageSend)
            let id: SessionID = try req.uuidParameter("sessionId")
            let attachmentId: AttachmentID = try req.uuidParameter("attachmentId")
            let service = MessageAttachmentService(db: req.db, ctx: req.ctx, runtime: req.attachments)
            let session = try await service.businessSession(principal: principal, sessionId: id)
            let (row, data) = try await service.businessDownload(businessId: principal.businessId.uuid, session: session, attachmentId: attachmentId)
            return MessageAttachmentService.imageResponse(data, row: row, disposition: .attachment)
        }
    }
}
