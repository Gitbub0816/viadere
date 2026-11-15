import Fluent
import Foundation
import Vapor
import ViadereCore

enum AuthRoutes {
    static func register(_ routes: any RoutesBuilder) {
        let ceremony = IPRateLimitMiddleware(name: "auth-ceremony") { $0.rateLimits.authCeremony }
        let refresh = IPRateLimitMiddleware(name: "auth-refresh") { $0.rateLimits.refresh }

        let signup = routes.grouped(SignupGateMiddleware(flag: .signupConsumer))
        signup.api(APIRoutes.registerBegin, limiter: ceremony) { req in
            let body: PasskeyRegistrationBeginRequest = try req.decodeBody()
            return try req.jsonResponse(try await AuthService(db: req.db, ctx: req.ctx).registerBegin(body))
        }
        signup.api(APIRoutes.registerFinish, limiter: ceremony) { req in
            let body: PasskeyRegistrationFinishRequest = try req.decodeBody()
            return try req.jsonResponse(try await AuthService(db: req.db, ctx: req.ctx).registerFinish(body), status: .created)
        }
        // Device-first accounts (§2.5a). The begin body, if any, is ignored: nothing a client sends can name an account.
        signup.api(APIRoutes.accountEnrollBegin, limiter: ceremony) { req in
            try req.jsonResponse(try await AccountEnrollmentService(db: req.db, ctx: req.ctx).begin())
        }
        signup.api(APIRoutes.accountCreate, limiter: ceremony) { req in
            let body: AccountCreateRequest = try req.decodeBody()
            let ip = ClientIP.resolve(req, trustedProxies: req.ctx.config.trustedProxyCount)
            return try req.jsonResponse(try await AccountEnrollmentService(db: req.db, ctx: req.ctx).create(body, clientIP: ip), status: .created)
        }
        routes.api(APIRoutes.loginBegin, limiter: ceremony) { req in
            _ = try? req.decodeBody(PasskeyLoginBeginRequest.self)
            return try req.jsonResponse(try await AuthService(db: req.db, ctx: req.ctx).loginBegin())
        }
        routes.api(APIRoutes.loginFinish, limiter: ceremony) { req in
            let body: PasskeyLoginFinishRequest = try req.decodeBody()
            return try req.jsonResponse(try await AuthService(db: req.db, ctx: req.ctx).loginFinish(body))
        }
        routes.api(APIRoutes.authRefresh, limiter: refresh) { req in
            let body: AuthRefreshRequest = try req.decodeBody()
            return try req.jsonResponse(try await AuthService(db: req.db, ctx: req.ctx).refresh(body, http: SignedRequestContext(req)))
        }
        routes.api(APIRoutes.logout) { req in
            try await AuthService(db: req.db, ctx: req.ctx).logout(try req.consumer)
            return try req.emptyOK()
        }
    }
}

enum DeviceRoutes {
    static func register(_ routes: any RoutesBuilder) {
        routes.api(APIRoutes.deviceEnrollBegin) { req in
            try req.jsonResponse(try await AuthService(db: req.db, ctx: req.ctx).enrollBegin(try req.consumer))
        }
        routes.api(APIRoutes.deviceEnroll) { req in
            let body: DeviceEnrollRequest = try req.decodeBody()
            return try req.jsonResponse(try await AuthService(db: req.db, ctx: req.ctx).enroll(try req.consumer, request: body), status: .created)
        }
        routes.api(APIRoutes.devicesList) { req in
            try req.jsonResponse(try await AuthService(db: req.db, ctx: req.ctx).devices(for: try req.consumer.consumerId))
        }
        routes.api(APIRoutes.deviceRevoke) { req in
            let id: DeviceID = try req.uuidParameter("deviceId")
            try await AuthService(db: req.db, ctx: req.ctx).revoke(try req.consumer, deviceId: id)
            return try req.emptyOK()
        }
        routes.api(APIRoutes.phoneLinkMOBegin) { req in
            let body: PhoneLinkMOBeginRequest = try req.decodeBody()
            return try req.jsonResponse(try await PhoneLinkService(db: req.db, ctx: req.ctx).begin(principal: try req.consumer, request: body))
        }
        routes.api(APIRoutes.phoneLinkStatus) { req in
            let id: PhoneLinkID = try req.uuidParameter("phoneLinkId")
            return try req.jsonResponse(try await PhoneLinkService(db: req.db, ctx: req.ctx).status(principal: try req.consumer, id: id))
        }
        routes.api(APIRoutes.phoneLinkKeep) { req in
            let id: PhoneLinkID = try req.uuidParameter("phoneLinkId")
            try await PhoneLinkService(db: req.db, ctx: req.ctx).keep(principal: try req.consumer, id: id)
            return try req.emptyOK()
        }
        // ADR-0027 §4: the SMS-code, link-token and hand-off routes are gone. Old app builds get `410 gone` and the app's own wording.
        for (method, path) in [(HTTPMethod.POST, "v1/phone-links/start"), (.POST, "v1/phone-links/verify"), (.POST, "v1/sms/link-tokens/redeem"),
                               (.GET, "v1/sms/link-tokens/:token/preview"), (.POST, "v1/handoff/redeem")] {
            routes.on(method, path.split(separator: "/").map { PathComponent(stringLiteral: String($0)) }) { _ -> Response in
                throw APIError.gone("Update Viadere to link your number.")
            }
        }
        routes.api(APIRoutes.deviceConfirm) { req in
            let id: DeviceID = try req.uuidParameter("deviceId")
            let body: ConfirmationRequest = try req.decodeBody()
            return try req.jsonResponse(try await AuthService(db: req.db, ctx: req.ctx).confirm(try req.consumer, target: id, proof: body.proof))
        }
        routes.api(APIRoutes.phoneLinkConfirm) { req in
            let id: PhoneLinkID = try req.uuidParameter("phoneLinkId")
            let body: ConfirmationRequest = try req.decodeBody()
            return try req.jsonResponse(try await PhoneLinkService(db: req.db, ctx: req.ctx).confirmLink(principal: try req.consumer, id: id, proof: body.proof))
        }
        routes.api(APIRoutes.phoneLinksList) { req in
            try req.jsonResponse(try await AccountService(db: req.db, ctx: req.ctx).phoneLinks(for: try req.consumer.consumerId))
        }
        routes.api(APIRoutes.phoneLinkDelete) { req in
            let id: PhoneLinkID = try req.uuidParameter("phoneLinkId")
            try await AccountService(db: req.db, ctx: req.ctx).removePhoneLink(principal: try req.consumer, id: id)
            return try req.emptyOK()
        }
        routes.api(APIRoutes.sessionsList) { req in
            try req.jsonResponse(try await AccountService(db: req.db, ctx: req.ctx).sessions(principal: try req.consumer))
        }
        routes.api(APIRoutes.sessionRevoke) { req in
            guard let raw = req.parameters.get("sessionId"), let id = UUID(uuidString: raw) else { throw APIError.notFound }
            try await AccountService(db: req.db, ctx: req.ctx).revokeSession(principal: try req.consumer, id: id)
            return try req.emptyOK()
        }
        routes.api(APIRoutes.securityNotices) { req in
            let principal = try req.consumer
            return try req.jsonResponse(try await SecurityNotices(db: req.db, ctx: req.ctx).pending(for: principal.consumerId.uuid, viewedBy: principal.deviceId?.uuid))
        }
        routes.api(APIRoutes.securityNoticeDismiss) { req in
            guard let raw = req.parameters.get("noticeId"), let id = UUID(uuidString: raw) else { throw APIError.notFound }
            try await SecurityNotices(db: req.db, ctx: req.ctx).dismiss(id, principal: try req.consumer)
            return try req.emptyOK()
        }
        routes.api(APIRoutes.securityNoticeSeen) { req in
            guard let raw = req.parameters.get("noticeId"), let id = UUID(uuidString: raw) else { throw APIError.notFound }
            try await SecurityNotices(db: req.db, ctx: req.ctx).seen(id, principal: try req.consumer)
            return try req.emptyOK()
        }
        routes.api(APIRoutes.accountDelete) { req in
            try await AccountService(db: req.db, ctx: req.ctx).deleteAccount(principal: try req.consumer)
            return try req.emptyOK()
        }
        routes.api(APIRoutes.apnsTokenRegister) { req in
            // The platform-neutral body (`PushRegistration`, with `provider`) or the original APNs one. APNs tokens go to `apns_tokens` (read by the
            // APNs sender only); FCM tokens go to `push_tokens`, and only while FCM is configured (SECURITY.md §2.114). An unknown provider, or FCM
            // while it is off, is refused and stored nowhere.
            let body: APNsTokenRegistration
            if (try? req.decodeBody(PushProviderProbe.self))?.provider != nil {
                let neutral: PushRegistration = try req.decodeBody()
                if neutral.provider == .fcm {
                    try await AuthRoutes.registerFCM(neutral, req: req)
                    return try req.emptyOK()
                }
                guard let apns = neutral.apnsRegistration else {
                    throw APIError.validation("This push provider is not supported yet.", details: ["provider": "unsupported"])
                }
                body = apns
            } else {
                body = try req.decodeBody()
            }
            let principal = try req.consumer
            guard let deviceId = principal.deviceId else { throw APIError.signatureInvalid }
            let token = body.token.lowercased()
            guard (32...200).contains(token.count), token.allSatisfy({ $0.isASCII && $0.isHexDigit }),
                  body.bundleId == req.ctx.config.appBundleID || body.bundleId == req.ctx.config.appClipBundleID else {
                throw APIError.validation("The push token is not valid.", details: ["token": "invalid"])
            }
            let did = deviceId.uuid
            // One provider per device: an APNs registration replaces an FCM one.
            try await PushTokenRecord.query(on: req.db).filter(\.$deviceId == did).delete()
            if let existing = try await APNsTokenRecord.query(on: req.db).filter(\.$deviceId == did).first() {
                existing.token = token
                existing.environment = body.environment.rawValue
                existing.bundleId = body.bundleId
                existing.updatedAt = req.ctx.now
                existing.invalidatedAt = nil
                try await existing.update(on: req.db)
            } else {
                var normalized = body
                normalized.token = token
                try await APNsTokenRecord(consumerId: principal.consumerId.uuid, deviceId: deviceId.uuid, registration: normalized, now: req.ctx.now).create(on: req.db)
            }
            return try req.emptyOK()
        }
        routes.api(APIRoutes.liveActivityTokenRegister) { req in
            let body: LiveActivityTokenRegistration = try req.decodeBody()
            try await LiveActivityService(db: req.db, ctx: req.ctx).register(principal: try req.consumer, body: body)
            return try req.emptyOK()
        }
    }
}

extension AuthRoutes {
    /// An FCM registration token: 32 to 4096 characters of letters, digits, `-`, `_` and `:` (FCM's alphabet).
    static func isFCMToken(_ token: String) -> Bool {
        (32...4096).contains(token.count) && token.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" || $0 == ":") }
    }

    /// An FCM registration for the configured Android app, only while FCM is on (else the same `422` as any unsupported provider).
    static func registerFCM(_ body: PushRegistration, req: Request) async throws {
        let ctx = req.ctx
        guard ctx.push.supports(.fcm), let packageName = ctx.config.android.packageName else {
            throw APIError.validation("This push provider is not supported yet.", details: ["provider": "unsupported"])
        }
        let principal = try req.consumer
        guard let deviceId = principal.deviceId else { throw APIError.signatureInvalid }
        guard isFCMToken(body.token), body.appId == packageName, body.environment == nil else {
            throw APIError.validation("The push token is not valid.", details: ["token": "invalid"])
        }
        let did = deviceId.uuid
        let consumerId = principal.consumerId.uuid
        let now = ctx.now
        try await req.db.transaction { tx in
            // One provider per device: an FCM registration replaces an APNs one, so the APNs sender never picks this device up again.
            try await APNsTokenRecord.query(on: tx).filter(\.$deviceId == did).delete()
            if let existing = try await PushTokenRecord.query(on: tx).filter(\.$deviceId == did).first() {
                existing.provider = PushRegistration.Provider.fcm.rawValue
                existing.token = body.token
                existing.environment = nil
                existing.appId = body.appId
                existing.updatedAt = now
                existing.invalidatedAt = nil
                try await existing.update(on: tx)
            } else {
                try await PushTokenRecord(consumerId: consumerId, deviceId: did, provider: .fcm, token: body.token, appId: body.appId, now: now).create(on: tx)
            }
        }
    }
}

/// Reads only whether a push registration body names a provider.
private struct PushProviderProbe: Decodable { var provider: String? }
