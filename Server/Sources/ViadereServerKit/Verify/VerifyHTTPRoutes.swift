import Fluent
import Foundation
import Vapor
import ViadereCore

/// Verify routes (`APIRoutes.verification*`, `providerDiditWebhook`). Every handler checks the release gate first (`404` while
/// `VERIFY_ENABLED` is off); business routes are capability-gated by `VerifyService` / `PolicyService`.
enum VerifyHTTPRoutes {
    @Sendable static func service(_ req: Request) throws -> VerifyService {
        try VerifyService.requireEnabled(req.ctx)
        return VerifyService(db: req.db, ctx: req.ctx, runtime: req.verify)
    }

    static func requestID(_ req: Request) throws -> VerificationRequestID {
        guard let raw = req.parameters.get("requestId"), let id = VerificationRequestID(raw) else { throw APIError.notFound }
        return id
    }

    static func register(_ routes: any RoutesBuilder) {
        // MARK: Business
        routes.api(APIRoutes.verificationRequestCreate) { req in
            let svc = try service(req)
            let body: CreateVerificationRequest = try req.decodeBody()
            let key = try BusinessIdempotency.requireKey(req.idempotencyHeader)
            let result = try await svc.create(principal: try req.business, body: body, idempotencyKey: key)
            return try req.jsonResponse(result.resource, status: result.created ? .created : .ok)
        }
        routes.api(APIRoutes.verificationRequestGet) { req in
            let svc = try service(req)
            return try req.jsonResponse(try await svc.request(principal: try req.business, id: try requestID(req)))
        }
        routes.api(APIRoutes.verificationResultGet) { req in
            let svc = try service(req)
            guard let raw = req.parameters.get("resultRef"), let ref = VerificationResultRef(raw) else { throw APIError.notFound }
            let result = try await svc.retrieve(principal: try req.business, ref: ref)
            let response = try req.jsonResponse(result)
            // A one-time result is never cached by anything on the path.
            response.headers.replaceOrAdd(name: .cacheControl, value: "no-store")
            return response
        }

        // MARK: Consumer
        routes.api(APIRoutes.verificationsList) { req in
            try req.jsonResponse(try await service(req).list(consumer: try req.consumer.consumerId))
        }
        routes.api(APIRoutes.verificationGet) { req in
            let svc = try service(req)
            return try req.jsonResponse(try await svc.prompt(for: try await svc.ownRequest(try req.consumer.consumerId, try requestID(req))))
        }
        routes.api(APIRoutes.verificationConsent) { req in
            let svc = try service(req)
            let body: VerificationConsentRequest = try req.decodeBody()
            return try req.jsonResponse(try await svc.consent(consumer: try req.consumer.consumerId, id: try requestID(req), digest: body.displayDigest))
        }
        routes.api(APIRoutes.verificationDecline) { req in
            try await service(req).decline(consumer: try req.consumer.consumerId, id: try requestID(req))
            return try req.emptyOK()
        }
        routes.api(APIRoutes.verificationRevoke) { req in
            try req.jsonResponse(try await service(req).revoke(consumer: try req.consumer.consumerId, id: try requestID(req)))
        }
        routes.api(APIRoutes.verificationWalletBegin) { req in
            try req.jsonResponse(try await service(req).walletBegin(consumer: try req.consumer.consumerId, id: try requestID(req)))
        }
        routes.api(APIRoutes.verificationWalletComplete) { req in
            let svc = try service(req)
            let body: WalletAttemptComplete = try req.decodeBody()
            return try req.jsonResponse(try await svc.walletComplete(consumer: try req.consumer.consumerId, id: try requestID(req), body: body))
        }
        routes.api(APIRoutes.verificationDocumentBegin) { req in
            try req.jsonResponse(try await service(req).documentBegin(consumer: try req.consumer.consumerId, id: try requestID(req)))
        }
        routes.api(APIRoutes.verificationDocumentComplete) { req in
            let svc = try service(req)
            let body: DocumentAttemptComplete = try req.decodeBody()
            return try req.jsonResponse(try await svc.documentComplete(consumer: try req.consumer.consumerId, id: try requestID(req), body: body))
        }

        // MARK: Provider
        routes.api(APIRoutes.providerDiditWebhook) { req in
            let ctx = req.ctx
            let body = try await req.collectedBody(limit: 256 * 1024)
            let verifier = DiditWebhookVerifier(secrets: ctx.config.verify.diditWebhookSecrets, tolerance: ctx.config.verify.diditWebhookTolerance)
            let headers = DiditWebhookVerifier.Headers(
                signatureV2: req.headers.first(name: "X-Signature-V2"), signatureV2Previous: req.headers.first(name: "X-Signature-V2-Previous"),
                signature: req.headers.first(name: "X-Signature"), signaturePrevious: req.headers.first(name: "X-Signature-Previous"),
                timestamp: req.headers.first(name: "X-Timestamp"))
            let parsed: [String: JSONValue]
            do {
                parsed = try verifier.verify(body: body, headers: headers, now: ctx.now)
            } catch {
                // Unconfigured, unsigned, badly signed, stale and malformed webhooks are all the same 403.
                _ = try? await AuditService(db: req.db, ctx: ctx).record("verification.webhook_rejected", outcome: .denied, actor: AuditActor(kind: .gateway),
                    metadata: ["reason": (error as? DiditWebhookVerifier.Failure)?.rawValue ?? "invalid", "provider": "didit"])
                throw APIError.forbidden
            }
            switch await VerifyService(db: req.db, ctx: ctx, runtime: req.verify).handleDiditWebhook(parsed) {
            case .accepted: return try req.emptyOK()
            case .retry: throw APIError(.serviceUnavailable, .unavailable, "Try again later.")
            }
        }
    }
}
