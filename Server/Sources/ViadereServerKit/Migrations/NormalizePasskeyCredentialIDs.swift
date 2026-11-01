import Fluent
import FluentSQL
import SQLKit

/// Credential ids registered before the fix were stored as padded standard base64 (webauthn-swift's form), while sign-in looks them up by
/// the unpadded base64url `id` the client sends, so no stored passkey could sign in. Rewrites them in place to the canonical form
/// (`PasskeyCredentialID`). The mapping is one-to-one, so the unique indexes on `credential_id` cannot collide. Forward-only: the old
/// form was never usable, so revert leaves the rows as they are.
struct NormalizePasskeyCredentialIDs: AsyncMigration {
    var name: String { "NormalizePasskeyCredentialIDs.v1" }
    static let tables = ["passkey_credentials", "dashboard_passkeys"]

    func prepare(on db: any Database) async throws {
        guard let sql = db as? any SQLDatabase else { return }
        for table in Self.tables {
            // Table names are compile-time constants.
            try await sql.raw(SQLQueryString("""
                UPDATE \(unsafeRaw: table) SET credential_id = rtrim(replace(replace(credential_id, '+', '-'), '/', '_'), '=')
                WHERE credential_id LIKE '%=' OR credential_id LIKE '%+%' OR credential_id LIKE '%/%'
                """)).run()
        }
    }

    func revert(on db: any Database) async throws {}
}
