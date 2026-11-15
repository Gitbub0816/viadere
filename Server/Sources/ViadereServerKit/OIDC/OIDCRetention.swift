import Fluent
import Foundation

/// Retention of the OIDC front end's browser authorizations (class T, ledger S6-08): a row lives at most `authorizationLifetime` (10 minutes) and can
/// hold the authority's authorization code until the browser is redirected, so it is deleted at expiry by the background tick, not only
/// opportunistically when someone starts another authorization.
enum OIDCRetention {
    @discardableResult
    static func purge(on db: any Database, now: Date) async throws -> Int {
        let expired = OIDCAuthorizationRecord.query(on: db).filter(\.$expiresAt < now)
        let count = try await expired.count()
        if count > 0 { try await OIDCAuthorizationRecord.query(on: db).filter(\.$expiresAt < now).delete() }
        return count
    }
}
