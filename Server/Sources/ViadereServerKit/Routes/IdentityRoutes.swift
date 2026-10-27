import Fluent
import Foundation
import Vapor
import ViadereCore

/// Account recovery, recovery-code management and pending-replacement cancellation.
enum IdentityRoutes {
    static func register(_ routes: any RoutesBuilder) {
        // Public recovery ceremonies: per-IP budgets on top of the per-account attempt cap and the global budget.
        let begin = IPRateLimitMiddleware(name: "recovery-begin") { _ in .perHour(20, burst: 8) }
        let finish = IPRateLimitMiddleware(name: "recovery-finish") { _ in .perHour(30, burst: 10) }
        let complete = IPRateLimitMiddleware(name: "recovery-complete-ip") { _ in .perMinute(30, burst: 15) }

        routes.api(APIRoutes.recoveryBegin, limiter: begin) { req in
            let body: RecoveryBeginRequest = try req.decodeBody()
            return try req.jsonResponse(try await RecoveryService(db: req.db, ctx: req.ctx).begin(body))
        }
        routes.api(APIRoutes.recoveryFinish, limiter: finish) { req in
            let body: RecoveryFinishRequest = try req.decodeBody()
            return try req.jsonResponse(try await RecoveryService(db: req.db, ctx: req.ctx).finish(body), status: .created)
        }
        routes.api(APIRoutes.recoveryComplete, limiter: complete) { req in
            let body: RecoveryCompleteRequest = try req.decodeBody()
            return try req.jsonResponse(try await RecoveryService(db: req.db, ctx: req.ctx).complete(body))
        }
        routes.api(APIRoutes.recoveryCancel) { req in
            let id: RecoveryID = try req.uuidParameter("recoveryId")
            return try req.jsonResponse(try await RecoveryService(db: req.db, ctx: req.ctx).cancel(try req.consumer, id: id))
        }
        routes.api(APIRoutes.recoveryInfo) { req in
            try req.jsonResponse(try await RecoveryService(db: req.db, ctx: req.ctx).info(try req.consumer))
        }
        routes.api(APIRoutes.recoveryCodesBegin) { req in
            try req.jsonResponse(try await RecoveryService(db: req.db, ctx: req.ctx).regenerateBegin(try req.consumer))
        }
        routes.api(APIRoutes.recoveryCodesRegenerate) { req in
            let body: RecoveryCodesRegenerateRequest = try req.decodeBody()
            return try req.jsonResponse(try await RecoveryService(db: req.db, ctx: req.ctx).regenerate(try req.consumer, request: body), status: .created)
        }
        routes.api(APIRoutes.deviceReplacementCancel) { req in
            let id: DeviceID = try req.uuidParameter("deviceId")
            try await AuthService(db: req.db, ctx: req.ctx).cancelReplacement(try req.consumer, newDeviceId: id)
            return try req.emptyOK()
        }
    }
}
