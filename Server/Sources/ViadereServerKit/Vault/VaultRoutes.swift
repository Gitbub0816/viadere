import Fluent
import Foundation
import Vapor
import ViadereCore

/// `/v1/vault/...` (`APIRoutes.vault*`). Every handler checks the release gate first (`404` while `VAULT_SYNC_ENABLED` is off).
enum VaultRoutes {
    /// The service for this request, after the release gate.
    @Sendable static func service(_ req: Request) throws -> VaultService {
        try VaultService.requireEnabled(req.ctx)
        return VaultService(db: req.db, ctx: req.ctx)
    }

    static func register(_ routes: any RoutesBuilder) {
        // A key rotation re-uploads every item, so these routes may carry more than the global body limit (only while sync is enabled).
        let big: ByteCount = "1mb"
        routes.api(APIRoutes.vaultStatus) { req in
            try req.jsonResponse(try await Self.service(req).status(try req.consumer))
        }
        routes.api(APIRoutes.vaultPut, bodyLimit: big) { req in
            let svc = try Self.service(req)
            let body: VaultPutRequest = try req.decodeBody()
            return try req.jsonResponse(try await svc.put(try req.consumer, body))
        }
        routes.api(APIRoutes.vaultDelete) { req in
            try await Self.service(req).delete(try req.consumer)
            return try req.emptyOK()
        }
        routes.api(APIRoutes.vaultManifests) { req in
            let svc = try Self.service(req)
            let after = req.query[UInt64.self, at: "after"] ?? 0
            return try req.jsonResponse(try await svc.manifests(try req.consumer, after: after, limit: req.queryInt("limit", default: 50, range: 1...100)))
        }
        routes.api(APIRoutes.vaultBlobs) { req in
            let svc = try Self.service(req)
            let body: VaultBlobsRequest = try req.decodeBody()
            return try req.jsonResponse(try await svc.blobs(try req.consumer, ids: body.itemIds))
        }
        routes.api(APIRoutes.vaultEnvelope) { req in
            try req.jsonResponse(try await Self.service(req).envelope(try req.consumer))
        }
        routes.api(APIRoutes.vaultRecoveryEnvelope) { req in
            try req.jsonResponse(try await Self.service(req).recoveryEnvelope(try req.consumer))
        }
        routes.api(APIRoutes.vaultDevices) { req in
            try req.jsonResponse(try await Self.service(req).devices(try req.consumer))
        }
        routes.api(APIRoutes.vaultDeviceRemove) { req in
            let svc = try Self.service(req)
            guard let memberId = req.parameters.get("memberId"), Base64URL.isValid(memberId, minLength: 43, maxLength: 43) else { throw APIError.notFound }
            try await svc.removeDevice(try req.consumer, memberId: memberId)
            return try req.emptyOK()
        }
        routes.api(APIRoutes.vaultJoinCreate) { req in
            let svc = try Self.service(req)
            return try req.jsonResponse(try await svc.createJoin(try req.consumer, joinId: req.parameters.get("joinId") ?? ""), status: .created)
        }
        routes.api(APIRoutes.vaultJoinGet) { req in
            let svc = try Self.service(req)
            return try req.jsonResponse(try await svc.join(try req.consumer, joinId: req.parameters.get("joinId") ?? ""))
        }
        routes.api(APIRoutes.vaultJoinRequest) { req in
            let svc = try Self.service(req)
            let body: VaultJoinRequestBody = try req.decodeBody()
            return try req.jsonResponse(try await svc.submitJoinRequest(try req.consumer, joinId: req.parameters.get("joinId") ?? "", body: body))
        }
        routes.api(APIRoutes.vaultJoinCancel) { req in
            let svc = try Self.service(req)
            try await svc.cancelJoin(try req.consumer, joinId: req.parameters.get("joinId") ?? "")
            return try req.emptyOK()
        }
    }
}
