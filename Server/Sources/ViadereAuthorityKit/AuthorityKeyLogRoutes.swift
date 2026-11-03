import Fluent
import Foundation
import Vapor
import ViadereCore

extension AuthorityApplication {
    /// Key-log, recovery and link-service routes (api caller with `Authority.Evidence.Submit` only). Closed JSON bodies; the authority decides from
    /// its own records. `AUTHORITY_KEYLOG_ENABLED` / `AUTHORITY_RECOVERY_ENABLED` off: `404`; `AUTHORITY_ENABLED` off: `503 authority_disabled`.
    static func keyLogRoutes(_ app: Application, verifier: any AuthorityCallerVerifier) throws {
        let api = app.grouped(AuthorityRoleMiddleware(verifier: verifier, roles: [.evidenceSubmit], callerNames: ["api"]))
        func post(_ path: String, allowed: Set<String>, _ handler: @escaping @Sendable (Request, [String: JSONValue]) async throws -> [String: JSONValue]) {
            let components = path.split(separator: "/").map { PathComponent(stringLiteral: String($0)) }
            api.on(.POST, components) { req async throws -> Response in
                let body = try AuthorityBody.object(req, allowed: allowed)
                return try jsonObject(try await handler(req, body))
            }
        }
        post(AuthorityKeyLogRoute.nonces, allowed: ["entry_type"]) { req, o in
            guard Set(o.keys) == ["entry_type"], let type = o["entry_type"]?.stringValue else { throw Abort(.unprocessableEntity, reason: "invalid_request") }
            return try await AuthorityKeyLogService(ctx: req.application.authority, db: req.db).issueNonce(entryType: type)
        }
        post(AuthorityKeyLogRoute.genesis, allowed: ["nonce_id", "keys"]) { req, o in
            try await AuthorityKeyLogService(ctx: req.application.authority, db: req.db).genesis(o, caller: req.authorityCaller)
        }
        post(AuthorityKeyLogRoute.head, allowed: ["account_id"]) { req, o in
            try await AuthorityKeyLogService(ctx: req.application.authority, db: req.db).headFor(o, caller: req.authorityCaller)
        }
        post(AuthorityKeyLogRoute.challenges, allowed: ["purpose", "account_id", "kids", "entry_id", "set_id", "recovery_id"]) { req, o in
            try await AuthorityKeyLogService(ctx: req.application.authority, db: req.db).createChallenge(o, caller: req.authorityCaller)
        }
        post(AuthorityKeyLogRoute.deviceAdded, allowed: ["account_id", "nonce_id", "reported_name", "keys"]) { req, o in
            try await AuthorityKeyLogService(ctx: req.application.authority, db: req.db).submitDeviceAdd(o, caller: req.authorityCaller)
        }
        post(AuthorityKeyLogRoute.evidence, allowed: ["factor", "account_id", "pops", "envelope"]) { req, o in
            try await AuthorityKeyLogService(ctx: req.application.authority, db: req.db).evidence(o, caller: req.authorityCaller)
        }
        post(AuthorityKeyLogRoute.recoveryStart, allowed: ["ach", "envelope", "keys"]) { req, o in
            try await AuthorityRecoveryService(ctx: req.application.authority, db: req.db).start(o, caller: req.authorityCaller)
        }
        post(AuthorityKeyLogRoute.recoveryLegacyStart, allowed: ["account_id", "recovery_id", "nonce_id", "keys"]) { req, o in
            try await AuthorityRecoveryService(ctx: req.application.authority, db: req.db).legacyStart(o, caller: req.authorityCaller)
        }
        post(AuthorityKeyLogRoute.linkRedeem, allowed: ["link_client_id", "business_id", "code_verifier", "code", "ach"]) { req, o in
            try await AuthorityLinkService(ctx: req.application.authority, db: req.db).redeem(o, caller: req.authorityCaller)
        }
    }

    static func jsonObject(_ object: [String: JSONValue], status: HTTPResponseStatus = .ok) throws -> Response {
        let response = Response(status: status, body: .init(data: try CanonicalJSON.serialize(.object(object))))
        response.headers.contentType = .json
        response.headers.replaceOrAdd(name: .cacheControl, value: "no-store")
        return response
    }
}
