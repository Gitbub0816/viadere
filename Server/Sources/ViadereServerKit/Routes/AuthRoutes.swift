import Fluent
import Foundation
import Vapor
import ViadereCore

enum AuthRoutes {
    static func register(_ routes: any RoutesBuilder) {
        let ceremony = IPRateLimitMiddleware(name: "auth-ceremony") { $0.rateLimits.authCeremony }
        let refresh = IPRateLimitMiddleware(name: "auth-refresh") { $0.rateLimits.refresh }

        routes.api(APIRoutes.registerBegin, limiter: ceremony) { req in
            let body: PasskeyRegistrationBeginRequest = try req.decodeBody()
            return try req.jsonResponse(try await AuthService(db: req.db, ctx: req.ctx).registerBegin(body))
        }
        routes.api(APIRoutes.registerFinish, limiter: ceremony) { req in
            let body: PasskeyRegistrationFinishRequest = try req.decodeBody()
            return try req.jsonResponse(try await AuthService(db: req.db, ctx: req.ctx).registerFinish(body), status: .created)
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
            return try req.jsonResponse(try await AuthService(db: req.db, ctx: req.ctx).refresh(body))
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
        routes.api(APIRoutes.phoneLinkStart) { req in
            let body: PhoneLinkStartRequest = try req.decodeBody()
            return try req.jsonResponse(try await PhoneLinkService(db: req.db, ctx: req.ctx).start(principal: try req.consumer, request: body))
        }
        routes.api(APIRoutes.phoneLinkVerify) { req in
            let body: PhoneLinkVerifyRequest = try req.decodeBody()
            return try req.jsonResponse(try await PhoneLinkService(db: req.db, ctx: req.ctx).verify(principal: try req.consumer, request: body))
        }
        routes.api(APIRoutes.smsLinkRedeem) { req in
            let body: SMSLinkRedeemRequest = try req.decodeBody()
            return try req.jsonResponse(try await PhoneLinkService(db: req.db, ctx: req.ctx).redeemAccountLink(principal: try req.consumer, request: body))
        }
        routes.api(APIRoutes.handoffRedeem) { req in
            let body: HandoffRedeemRequest = try req.decodeBody()
            return try req.jsonResponse(try await PhoneLinkService(db: req.db, ctx: req.ctx).redeemHandoff(principal: try req.consumer, token: body.token))
        }
        routes.api(APIRoutes.apnsTokenRegister) { req in
            let body: APNsTokenRegistration = try req.decodeBody()
            let principal = try req.consumer
            guard let deviceId = principal.deviceId else { throw APIError.signatureInvalid }
            let token = body.token.lowercased()
            guard (32...200).contains(token.count), token.allSatisfy({ $0.isASCII && $0.isHexDigit }),
                  body.bundleId == req.ctx.config.appBundleID || body.bundleId == req.ctx.config.appClipBundleID else {
                throw APIError.validation("The push token is not valid.", details: ["token": "invalid"])
            }
            let did = deviceId.uuid
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
            let principal = try req.consumer
            guard let deviceId = principal.deviceId, (16...400).contains(body.pushToken.count),
                  body.pushToken.allSatisfy({ $0.isASCII && $0.isHexDigit }) else { throw APIError.validation("The push token is not valid.") }
            let record = LiveActivityTokenRecord()
            record.id = UUID()
            record.consumerId = principal.consumerId.uuid
            record.deviceId = deviceId.uuid
            record.kind = body.kind.rawValue
            record.activityId = body.activityId.map { String($0.prefix(128)) }
            record.businessId = body.businessId?.uuid
            record.interactionId = body.interactionId?.uuid
            record.pushToken = body.pushToken.lowercased()
            record.updatedAt = req.ctx.now
            try await record.create(on: req.db)
            return try req.emptyOK()
        }
    }
}
