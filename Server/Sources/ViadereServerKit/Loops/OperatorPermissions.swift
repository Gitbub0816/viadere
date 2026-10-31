import Fluent
import Foundation
import Vapor
import ViadereCore

/// Grants or revokes an operator-console permission (`loop_reviewer`). Audited with actor `system`: the command runs with production
/// credentials as a one-off job, never from the console, so no operator can grant a permission to themselves.
struct OperatorPermissions {
    let db: any Database
    let ctx: ServerContext

    func set(email rawEmail: String, permission: OperatorPermission, granted: Bool) async throws {
        let auth = DashboardAuthService(db: db, ctx: ctx)
        guard let email = DashboardAuthService.normalizeEmail(rawEmail),
              let user = try await DashboardUserRecord.query(on: db).filter(\.$emailHash == auth.emailHash(email)).filter(\.$kind == "operator").first(),
              let userId = user.id else { throw APIError.validation("No operator with that email.") }
        try await set(userId: userId, permission: permission, granted: granted)
    }

    func set(userId: UUID, permission: OperatorPermission, granted: Bool) async throws {
        let active = try await OperatorPermissionRecord.query(on: db).filter(\.$userId == userId).filter(\.$permission == permission.rawValue).filter(\.$revokedAt == nil).all()
        if granted {
            guard active.isEmpty else { return }
            let row = OperatorPermissionRecord()
            row.userId = userId
            row.permission = permission.rawValue
            row.grantedAt = ctx.now
            try await row.create(on: db)
        } else {
            try await OperatorPermissionRecord.query(on: db).filter(\.$userId == userId).filter(\.$permission == permission.rawValue).filter(\.$revokedAt == nil)
                .set(\.$revokedAt, to: ctx.now).update()
        }
        _ = try await AuditService(db: db, ctx: ctx).record(granted ? "operator.permission_granted" : "operator.permission_revoked", actor: AuditActor(kind: .system),
                                                            subjectType: "operator", subjectId: userId.uuidString.lowercased(), metadata: ["permission": permission.rawValue])
    }
}

/// `ViadereServer grant-operator-permission --email … --permission loop_reviewer [--revoke]`.
public struct GrantOperatorPermissionCommand: AsyncCommand {
    public struct Signature: CommandSignature {
        @Option(name: "email") var email: String?
        @Option(name: "permission") var permission: String?
        @Flag(name: "revoke") var revoke: Bool
        public init() {}
    }

    public let signature = Signature()
    public let help = "Grants (or with --revoke, revokes) an operator-console permission such as loop_reviewer."

    public init() {}

    public func run(using context: CommandContext, signature: Signature) async throws {
        guard let email = signature.email, let raw = signature.permission, let permission = OperatorPermission(rawValue: raw) else {
            context.console.error("Usage: grant-operator-permission --email <address> --permission \(OperatorPermission.allCases.map(\.rawValue).joined(separator: "|")) [--revoke]")
            throw Abort(.badRequest)
        }
        let app = context.application
        try await OperatorPermissions(db: app.db, ctx: app.ctx).set(email: email, permission: permission, granted: !signature.revoke)
        context.console.print(signature.revoke ? "Permission revoked." : "Permission granted.")
    }
}
