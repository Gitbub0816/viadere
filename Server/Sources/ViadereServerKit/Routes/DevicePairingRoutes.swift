import Fluent
import Foundation
import Vapor
import ViadereCore

/// Device pairing (WP-D1, SECURITY.md §2.105). The new device's routes are public and budgeted per client network (fail closed); the trusted
/// device's routes are device-signed.
enum DevicePairingRoutes {
    static func register(_ routes: any RoutesBuilder) {
        routes.api(APIRoutes.devicePairingInvite) { req in
            try req.jsonResponse(try await DevicePairingService(db: req.db, ctx: req.ctx).invite(try req.consumer), status: .created)
        }
        // The begin body, if any, is ignored: nothing a client sends here can name an account.
        routes.api(APIRoutes.devicePairingBegin) { req in
            let ip = ClientIP.resolve(req, trustedProxies: req.ctx.config.trustedProxyCount)
            return try req.jsonResponse(try await DevicePairingService(db: req.db, ctx: req.ctx).begin(clientIP: ip))
        }
        routes.api(APIRoutes.devicePairingStart) { req in
            let id: DevicePairingID = try req.uuidParameter("pairingId")
            let body: DevicePairingStartRequest = try req.decodeBody()
            let ip = ClientIP.resolve(req, trustedProxies: req.ctx.config.trustedProxyCount)
            return try req.jsonResponse(try await DevicePairingService(db: req.db, ctx: req.ctx).start(pairingId: id, request: body, clientIP: ip), status: .created)
        }
        routes.api(APIRoutes.devicePairingStatus) { req in
            let id: DevicePairingID = try req.uuidParameter("pairingId")
            let body: DevicePairingStatusRequest = try req.decodeBody()
            let ip = ClientIP.resolve(req, trustedProxies: req.ctx.config.trustedProxyCount)
            return try req.jsonResponse(try await DevicePairingService(db: req.db, ctx: req.ctx).status(pairingId: id, request: body, clientIP: ip))
        }
        routes.api(APIRoutes.devicePairingCancel) { req in
            let id: DevicePairingID = try req.uuidParameter("pairingId")
            let body: DevicePairingStatusRequest = try req.decodeBody()
            let ip = ClientIP.resolve(req, trustedProxies: req.ctx.config.trustedProxyCount)
            return try req.jsonResponse(try await DevicePairingService(db: req.db, ctx: req.ctx).cancel(pairingId: id, request: body, clientIP: ip))
        }
        routes.api(APIRoutes.devicePairingsPending) { req in
            try req.jsonResponse(try await DevicePairingService(db: req.db, ctx: req.ctx).pending(try req.consumer))
        }
        routes.api(APIRoutes.devicePairingApprove) { req in
            let id: DevicePairingID = try req.uuidParameter("pairingId")
            let body: DevicePairingApproveRequest = try req.decodeBody()
            return try req.jsonResponse(try await DevicePairingService(db: req.db, ctx: req.ctx).approve(try req.consumer, pairingId: id, approval: body.approval))
        }
        routes.api(APIRoutes.devicePairingDeny) { req in
            let id: DevicePairingID = try req.uuidParameter("pairingId")
            let body: DevicePairingDenyRequest = (try? req.decodeBody()) ?? DevicePairingDenyRequest()
            try await DevicePairingService(db: req.db, ctx: req.ctx).deny(try req.consumer, pairingId: id, report: body.report == true)
            return try req.emptyOK()
        }
    }
}
