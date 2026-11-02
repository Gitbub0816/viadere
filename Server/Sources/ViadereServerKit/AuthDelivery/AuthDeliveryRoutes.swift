import Fluent
import Foundation
import Vapor
import ViadereCore

/// `/v1/business/auth-deliveries...` (businesses) and `/v1/auth-deliveries...` (the customer's devices). Every handler checks the release gate first: while
/// `AUTH_DELIVERY_ENABLED` is off the feature does not exist (`404`).
enum AuthDeliveryRoutes {
    typealias Scope = BusinessAPIKeys.Scope

    static func deliveryId(_ req: Request) throws -> AuthDeliveryID {
        guard let raw = req.parameters.get("deliveryId"), let id = AuthDeliveryID(raw) else { throw APIError.notFound }
        return id
    }

    static func register(_ routes: any RoutesBuilder) {
        // MARK: Business
        routes.api(APIRoutes.businessAuthDeliveryCreate, scope: Scope.authDeliveriesWrite) { req in
            try AuthDeliveryGate.require(req.ctx)
            let key = try BusinessIdempotency.requireKey(req.idempotencyHeader)
            let result = try await AuthDeliveryService(db: req.db, ctx: req.ctx).create(principal: try req.business, body: req.bodyBytes, key: key)
            return try req.jsonResponse(result.value, status: result.created ? .created : .ok)
        }
        routes.api(APIRoutes.businessAuthDeliveryGet, scope: Scope.authDeliveriesRead) { req in
            try AuthDeliveryGate.require(req.ctx)
            let service = AuthDeliveryService(db: req.db, ctx: req.ctx)
            try await service.requireLiveKeyAssurance(try req.business)
            return try req.jsonResponse(try await service.view(try await service.record(id: try deliveryId(req), principal: try req.business), withEvents: true))
        }
        routes.api(APIRoutes.businessAuthDeliveryCancel, scope: Scope.authDeliveriesWrite) { req in
            try AuthDeliveryGate.require(req.ctx)
            let key = try BusinessIdempotency.requireKey(req.idempotencyHeader)
            let principal = try req.business
            let id = try deliveryId(req)
            let service = AuthDeliveryService(db: req.db, ctx: req.ctx)
            try await service.requireLiveKeyAssurance(principal)
            _ = try await service.record(id: id, principal: principal)
            let ctx = req.ctx
            let hash = SecureToken.sha256Hex(Data("auth_delivery.cancel\n\(id)".utf8))
            let result = try await BusinessIdempotency(db: req.db, ctx: ctx).once(
                businessId: principal.businessId.uuid, operation: .authDeliveryCancel, key: key, requestHash: hash, sealResult: false,
                perform: { tx in (try await AuthDeliveryService(db: tx, ctx: ctx).cancel(principal: principal, id: id), id.uuid) },
                replay: { _ in try await service.view(try await service.record(id: id, principal: principal)) })
            return try req.jsonResponse(result.value)
        }
        routes.api(APIRoutes.businessAuthDeliveryComplete, scope: Scope.authDeliveriesWrite) { req in
            try AuthDeliveryGate.require(req.ctx)
            let key = try BusinessIdempotency.requireKey(req.idempotencyHeader)
            let principal = try req.business
            let id = try deliveryId(req)
            let body: AuthDeliveryCompleteRequest
            do { body = try ViadereJSON.decode(AuthDeliveryCompleteRequest.self, from: req.bodyBytes) } catch { throw APIError.validation("outcome must be succeeded or failed.", details: ["outcome": "invalid"]) }
            let service = AuthDeliveryService(db: req.db, ctx: req.ctx)
            try await service.requireLiveKeyAssurance(principal)
            _ = try await service.record(id: id, principal: principal)
            let ctx = req.ctx
            let hash = SecureToken.sha256Hex(Data("auth_delivery.complete\n\(id)\n\(body.outcome.rawValue)".utf8))
            let result = try await BusinessIdempotency(db: req.db, ctx: ctx).once(
                businessId: principal.businessId.uuid, operation: .authDeliveryComplete, key: key, requestHash: hash, sealResult: false,
                perform: { tx in (try await AuthDeliveryService(db: tx, ctx: ctx).complete(principal: principal, id: id, outcome: body.outcome), id.uuid) },
                replay: { _ in try await service.view(try await service.record(id: id, principal: principal)) })
            return try req.jsonResponse(result.value)
        }
        routes.api(APIRoutes.businessWebhookUpdate, scope: Scope.webhooksManage) { req in
            try AuthDeliveryGate.require(req.ctx)
            let key = try BusinessIdempotency.requireKey(req.idempotencyHeader)
            let principal = try req.business
            guard let raw = req.parameters.get("webhookId"), let uuid = UUID(uuidString: raw), uuid.uuidString.lowercased() == raw else { throw APIError.notFound }
            let body: UpdateWebhookRequest
            do { body = try ViadereJSON.decode(UpdateWebhookRequest.self, from: req.bodyBytes) } catch { throw APIError.validation("signature_version must be v2.", details: ["signature_version": "invalid"]) }
            guard body.signatureVersion == .v2 else { throw APIError.validation("signature_version must be v2.", details: ["signature_version": "invalid"]) }
            let ctx = req.ctx
            let id = WebhookSubscriptionID(uuid)
            let hash = SecureToken.sha256Hex(Data("webhook.update\n\(id)\nv2".utf8))
            let result = try await BusinessIdempotency(db: req.db, ctx: ctx).once(
                businessId: principal.businessId.uuid, operation: .webhookUpdate, key: key, requestHash: hash, sealResult: false,
                perform: { tx in (try await WebhookService(db: tx, ctx: ctx).moveToV2(businessId: principal.businessId, id: id), uuid) },
                replay: { _ in try await WebhookService(db: req.db, ctx: ctx).moveToV2(businessId: principal.businessId, id: id) })
            return try req.jsonResponse(result.value)
        }
        routes.api(APIRoutes.businessAuthWebhookTest, scope: Scope.webhooksManage) { req in
            try AuthDeliveryGate.require(req.ctx)
            let principal = try req.business
            // Test keys only: a live key cannot trigger sample events at a production endpoint.
            guard !principal.livemode else { throw APIError(.forbidden, .forbidden, "Sample events are sent with a test-mode key.") }
            let body: AuthWebhookTestRequest
            do { body = try ViadereJSON.decode(AuthWebhookTestRequest.self, from: req.bodyBytes) } catch { throw APIError.validation("webhook_id and type are required.") }
            let eventId = try await WebhookService(db: req.db, ctx: req.ctx).enqueueAuthSample(businessId: principal.businessId, subscriptionId: body.webhookId,
                                                                                               type: WebhookEventType(rawValue: body.type))
            return try req.jsonResponse(AuthWebhookTestResponse(eventId: eventId))
        }

        // MARK: Devices
        routes.api(APIRoutes.authDeliveries) { req in
            try AuthDeliveryGate.require(req.ctx)
            return try req.jsonResponse(try await AuthDeliveryDeviceService(db: req.db, ctx: req.ctx).list(principal: try req.consumer))
        }

        // MARK: Push approvals (ADR-0022): behind `AUTH_DELIVERY_ENABLED` and `APPROVE_V2_ENABLED`
        routes.api(APIRoutes.businessAuthApprovalCreate, scope: BusinessAPIKeys.Scope.approvalsManage) { req in
            try AuthApprovalService.requireEnabled(req.ctx)
            _ = try BusinessIdempotency.requireKey(req.idempotencyHeader)
            let result = try await AuthApprovalService(db: req.db, ctx: req.ctx).create(principal: try req.business, body: req.bodyBytes)
            return try req.jsonResponse(result.view, status: result.created ? .created : .ok)
        }
        routes.api(APIRoutes.businessAuthApprovalGet, scope: BusinessAPIKeys.Scope.approvalsManage) { req in
            try AuthApprovalService.requireEnabled(req.ctx)
            let principal = try req.business
            try await AuthDeliveryService(db: req.db, ctx: req.ctx).requireLiveKeyAssurance(principal)
            let service = ApproveRequestService(db: req.db, ctx: req.ctx)
            guard let id = req.parameters.get("requestId"), ApproveIdentifiers.isValidRequestId(id) else { throw APIError.notFound }
            let record = try await service.record(requestId: id, principal: principal)
            guard record.matchDigits != nil else { throw APIError.notFound }
            return try req.jsonResponse(try service.view(record))
        }
        routes.api(APIRoutes.approveRequestDeny) { req in
            try AuthApprovalService.requireEnabled(req.ctx)
            let body: ApproveDenyRequest
            if req.bodyBytes.isEmpty { body = ApproveDenyRequest() } else {
                do { body = try ViadereJSON.decode(ApproveDenyRequest.self, from: req.bodyBytes) } catch { throw APIError.validation("The request failed validation.") }
            }
            return try req.jsonResponse(try await AuthApprovalService(db: req.db, ctx: req.ctx).deny(principal: try req.consumer, deliveryId: try req.uuidPath("approvalId"),
                                                                                                    report: body.report ?? false))
        }
        routes.api(APIRoutes.authDeliveryGet) { req in
            try AuthDeliveryGate.require(req.ctx)
            return try req.jsonResponse(try await AuthDeliveryDeviceService(db: req.db, ctx: req.ctx).get(principal: try req.consumer, id: try deliveryId(req)))
        }
        routes.api(APIRoutes.authDeliveryOpen) { req in
            try AuthDeliveryGate.require(req.ctx)
            let response = try await AuthDeliveryDeviceService(db: req.db, ctx: req.ctx).open(principal: try req.consumer, id: try deliveryId(req))
            let out = try req.jsonResponse(response)
            // The body carries a bearer value: never cache or store it.
            out.headers.replaceOrAdd(name: .cacheControl, value: "no-store")
            return out
        }
        routes.api(APIRoutes.authDeliveryDeny) { req in
            try AuthDeliveryGate.require(req.ctx)
            let body: AuthDeliveryDenyRequest
            if req.bodyBytes.isEmpty { body = AuthDeliveryDenyRequest() } else {
                do { body = try ViadereJSON.decode(AuthDeliveryDenyRequest.self, from: req.bodyBytes) } catch { throw APIError.validation("The request failed validation.") }
            }
            return try req.jsonResponse(try await AuthDeliveryDeviceService(db: req.db, ctx: req.ctx).deny(principal: try req.consumer, id: try deliveryId(req), body: body))
        }
    }
}

/// Log fields allowed on auth-delivery routes (ADR-0020 section 9, ST-PRIV-01): the route template, status, latency and request id. Never a query string, a
/// body, a header, a delivery id in the path, or any other field. An allow-list implemented in the logger, not a regex redaction.
enum AuthLogAllowList {
    static let allowedKeys: Set<String> = ["method", "path", "status", "ms", "requestId"]

    static func isAuthPath(_ path: String) -> Bool {
        path.hasPrefix("/v1/auth-deliveries") || path.hasPrefix("/v1/business/auth-deliveries") || path == "/v1/business/webhooks/test"
    }

    /// `/v1/auth-deliveries/adl_xxx/open` becomes `/v1/auth-deliveries/:id/open`; a query string is dropped.
    static func routeTemplate(_ path: String) -> String {
        let clean = path.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) ?? path
        return clean.split(separator: "/", omittingEmptySubsequences: false).map { $0.hasPrefix("adl_") ? ":id" : String($0) }.joined(separator: "/")
    }

    static func filter(_ metadata: [String: String]) -> [String: String] { metadata.filter { allowedKeys.contains($0.key) } }
}
