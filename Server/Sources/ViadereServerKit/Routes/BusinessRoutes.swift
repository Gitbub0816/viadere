import Fluent
import Foundation
import Vapor
import ViadereCore

enum BusinessRoutes {
    typealias Scope = BusinessAPIKeys.Scope

    static func register(_ routes: any RoutesBuilder) {
        routes.api(APIRoutes.businessIssueInteraction, scope: Scope.interactionsWrite) { req in
            var body: IssueInteractionRequest = try req.decodeBody()
            let principal = try req.business
            // Capability first (a key without it never learns whether a customer reference exists), then the customer addressing.
            try await req.requireCapability(Capability.required(forInteractionKind: body.kind))
            try await SubjectResolver(db: req.db, ctx: req.ctx).resolve(&body, businessId: principal.businessId)
            let result = try await InteractionService(db: req.db, ctx: req.ctx).issue(principal: principal, request: body, headerKey: req.idempotencyHeader)
            if !principal.livemode { try? await OnboardingService(db: req.db, ctx: req.ctx).testEventSent(businessId: principal.businessId.uuid) }
            return try req.jsonResponse(result.interaction, status: result.created ? .created : .ok)
        }
        routes.api(APIRoutes.businessInteractionOutcome, scope: Scope.interactionsRead) { req in
            let id: InteractionID = try req.uuidParameter("interactionId")
            let service = InteractionService(db: req.db, ctx: req.ctx)
            let principal = try req.business
            let record = try await service.record(id: id, businessId: principal.businessId, livemode: principal.livemode)
            try await req.requireCapability(Capability.required(forInteractionKind: InteractionKind(rawValue: record.kind)))
            _ = try await service.expireIfNeeded(record)
            return try req.jsonResponse(try service.outcome(record))
        }
        routes.api(APIRoutes.businessCancelInteraction, scope: Scope.interactionsWrite) { req in
            let id: InteractionID = try req.uuidParameter("interactionId")
            let key = try BusinessIdempotency.requireKey(req.idempotencyHeader)
            let result = try await BusinessIdempotency(db: req.db, ctx: req.ctx).cancelInteraction(principal: try req.business, id: id, key: key)
            return try req.jsonResponse(result.value)
        }
        routes.api(APIRoutes.businessSendMessage, scope: Scope.messagesWrite) { req in
            var body: BusinessSendMessageRequest = try req.decodeBody()
            let principal = try req.business
            try await req.requireCapability(.messageSend)
            try await SubjectResolver(db: req.db, ctx: req.ctx).resolve(&body, businessId: principal.businessId)
            let result = try await ConversationService(db: req.db, ctx: req.ctx).businessSend(principal: principal, request: body, headerKey: req.idempotencyHeader)
            if !principal.livemode { try? await OnboardingService(db: req.db, ctx: req.ctx).testEventSent(businessId: principal.businessId.uuid) }
            return try req.jsonResponse(result.message, status: result.created ? .created : .ok)
        }
        routes.api(APIRoutes.businessUpdateStatus, scope: Scope.statusesWrite) { req in
            var body: BusinessStatusUpdateRequest = try req.decodeBody()
            let principal = try req.business
            try await req.requireCapability(.messageSend)
            try await SubjectResolver(db: req.db, ctx: req.ctx).resolve(&body, businessId: principal.businessId)
            let result = try await InteractionService(db: req.db, ctx: req.ctx).updateStatus(principal: principal, request: body, headerKey: req.idempotencyHeader)
            return try req.jsonResponse(result.interaction, status: result.created ? .created : .ok)
        }
        routes.api(APIRoutes.businessSandboxRelationship, scope: Scope.interactionsWrite) { req in
            let principal = try req.business
            let result = try await Sandbox(db: req.db).create(principal: principal, now: req.ctx.now, ctx: req.ctx)
            try? await OnboardingService(db: req.db, ctx: req.ctx).sandboxRelationshipCreated(businessId: principal.businessId.uuid)
            return try req.jsonResponse(result, status: .created)
        }
        routes.api(APIRoutes.businessWebhooksList, scope: Scope.webhooksManage) { req in
            try req.jsonResponse(try await WebhookService(db: req.db, ctx: req.ctx).list(businessId: try req.business.businessId))
        }
        routes.api(APIRoutes.businessWebhookCreate, scope: Scope.webhooksManage) { req in
            let body: CreateWebhookRequest = try req.decodeBody()
            let key = try BusinessIdempotency.requireKey(req.idempotencyHeader)
            let result = try await BusinessIdempotency(db: req.db, ctx: req.ctx).createWebhook(businessId: try req.business.businessId, request: body, key: key)
            return try req.jsonResponse(result.value, status: result.created ? .created : .ok)
        }
        routes.api(APIRoutes.businessWebhookDelete, scope: Scope.webhooksManage) { req in
            let id: WebhookSubscriptionID = try req.uuidParameter("webhookId")
            try await WebhookService(db: req.db, ctx: req.ctx).delete(businessId: try req.business.businessId, id: id)
            return try req.emptyOK()
        }
        routes.api(APIRoutes.businessWebhookVerify, scope: Scope.webhooksManage) { req in
            let id: WebhookSubscriptionID = try req.uuidParameter("webhookId")
            let result = try await WebhookService(db: req.db, ctx: req.ctx).verifyOwnership(businessId: try req.business.businessId, id: id)
            return try req.jsonResponse(WebhookVerificationResult(verified: result.verified, failure: result.failure))
        }
        routes.api(APIRoutes.businessWebhookTest, scope: Scope.webhooksManage) { req in
            let id: WebhookSubscriptionID = try req.uuidParameter("webhookId")
            try await WebhookService(db: req.db, ctx: req.ctx).sendTestEvent(businessId: try req.business.businessId, id: id)
            return try req.emptyOK()
        }
        routes.api(APIRoutes.businessWebhookPause, scope: Scope.webhooksManage) { req in
            let id: WebhookSubscriptionID = try req.uuidParameter("webhookId")
            let body: PauseWebhookRequest = req.bodyBytes.isEmpty ? PauseWebhookRequest() : try req.decodeBody()
            let principal = try req.business
            try await WebhookService(db: req.db, ctx: req.ctx).setPaused(businessId: principal.businessId, id: id, paused: true, reason: body.reason ?? "paused through the API",
                                                                         actor: AuditActor(kind: .business, id: principal.businessId.description))
            return try req.emptyOK()
        }
        routes.api(APIRoutes.businessWebhookResume, scope: Scope.webhooksManage) { req in
            let id: WebhookSubscriptionID = try req.uuidParameter("webhookId")
            let principal = try req.business
            try await WebhookService(db: req.db, ctx: req.ctx).setPaused(businessId: principal.businessId, id: id, paused: false, reason: "",
                                                                         actor: AuditActor(kind: .business, id: principal.businessId.description))
            return try req.emptyOK()
        }
        routes.api(APIRoutes.businessWebhookRotate, scope: Scope.webhooksManage) { req in
            let id: WebhookSubscriptionID = try req.uuidParameter("webhookId")
            let key = try BusinessIdempotency.requireKey(req.idempotencyHeader)
            let result = try await BusinessIdempotency(db: req.db, ctx: req.ctx).rotateWebhook(businessId: try req.business.businessId, id: id, key: key)
            return try req.jsonResponse(result.value)
        }
    }
}

enum ProviderRoutes {
    private static let twimlEmpty = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Response></Response>"

    static func register(_ routes: any RoutesBuilder) {
        routes.api(APIRoutes.providerSMSInbound) { req in
            let ctx = req.ctx
            let webhook = try await verified(req, template: APIRoutes.providerSMSInbound.template)
            let audit = AuditService(db: req.db, ctx: ctx)
            let sms: InboundSMS
            do { sms = try ctx.sms.parseInbound(webhook) } catch { throw APIError.badRequest("Unrecognized message.") }
            // Floods are dropped silently (a reply would be an amplification vector) but audited.
            let limits = ctx.config.rateLimits
            let globalOK = await ctx.limiter.allow("sms-global", key: "all", rule: limits.smsInboundGlobal)
            let phoneOK = await ctx.limiter.allow("sms-phone", key: ctx.hasher.phoneHash(sms.from), rule: limits.smsInboundPerPhone)
            guard globalOK, phoneOK else {
                _ = try? await audit.record("gateway.rate_limited", outcome: .denied, actor: AuditActor(kind: .gateway, id: sms.from.masked),
                                           metadata: ["scope": globalOK ? "phone" : "global", "phone": sms.from.masked])
                return xml(.ok)
            }
            _ = try await GatewayService(db: req.db, ctx: ctx).handleInbound(sms, provider: ctx.sms.name)
            return xml(.ok)
        }
        routes.api(APIRoutes.providerRCSInbound) { req in
            let ctx = req.ctx
            let adapter = ctx.channels.rcs
            let body = try await req.collectedBody(limit: 16 * 1024)
            let webhook = ProviderWebhookRequest(url: ctx.config.publicBaseURL + APIRoutes.providerRCSInbound.template,
                                                 signature: req.headers.first(name: GenericRBMProvider.signatureHeader), body: body,
                                                 receivedAt: ctx.now)
            // Unconfigured, unsigned, badly signed and stale-timestamp webhooks are all the same 403.
            guard adapter.isEnabled, adapter.verifyInbound(webhook) else {
                _ = try? await AuditService(db: req.db, ctx: ctx).record("gateway.webhook_rejected", outcome: .denied,
                    actor: AuditActor(kind: .gateway), metadata: ["reason": "bad_signature", "provider": "rcs"])
                throw APIError.forbidden
            }
            let events: [ChannelInboundEvent]
            do { events = try adapter.parseInbound(webhook) } catch { throw APIError.badRequest("Unrecognized event.") }
            let limits = ctx.config.rateLimits
            var allowed: [ChannelInboundEvent] = []
            for event in events {
                switch event {
                case .text(let phone, _, _, _), .postback(let phone, _, _, _):
                    // Floods are dropped silently and audited, like SMS.
                    if await ctx.limiter.allow("rcs-phone", key: ctx.hasher.phoneHash(phone), rule: limits.rcsInboundPerPhone) {
                        allowed.append(event)
                    } else {
                        _ = try? await AuditService(db: req.db, ctx: ctx).record("gateway.rate_limited", outcome: .denied,
                            actor: AuditActor(kind: .gateway, id: phone.masked), metadata: ["scope": "rcs_phone", "phone": phone.masked])
                    }
                case .receipt:
                    allowed.append(event)
                }
            }
            try await RCSInbound(db: req.db, ctx: ctx).handle(allowed)
            return try req.emptyOK()
        }
        routes.api(APIRoutes.providerSMSStatus) { req in
            let ctx = req.ctx
            let webhook = try await verified(req, template: APIRoutes.providerSMSStatus.template)
            if let update = try? ctx.sms.parseDeliveryUpdate(webhook) {
                try await OutboundSMS(db: req.db, ctx: ctx).applyDeliveryUpdate(update)
            }
            return xml(.ok)
        }
    }

    /// Verifies the provider signature against the **configured** public URL (never the Host header).
    private static func verified(_ req: Request, template: String) async throws -> ProviderWebhookRequest {
        let ctx = req.ctx
        let body = try await req.collectedBody(limit: 16 * 1024)
        let webhook = ProviderWebhookRequest(url: ctx.config.publicBaseURL + template,
                                             signature: req.headers.first(name: "X-Twilio-Signature"), body: body, receivedAt: ctx.now)
        guard ctx.sms.verifyWebhook(webhook) else {
            _ = try? await AuditService(db: req.db, ctx: ctx).record("gateway.webhook_rejected", outcome: .denied,
                actor: AuditActor(kind: .gateway), metadata: ["reason": "bad_signature"])
            throw APIError.forbidden
        }
        return webhook
    }

    private static func xml(_ status: HTTPStatus) -> Response {
        let response = Response(status: status, body: .init(string: twimlEmpty))
        response.headers.contentType = .xml
        return response
    }
}
