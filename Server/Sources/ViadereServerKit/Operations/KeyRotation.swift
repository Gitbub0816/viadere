@preconcurrency import Crypto
import Fluent
import FluentSQL
import Foundation
import SQLKit
import Vapor
import ViadereCore

// MARK: - Connect-link signing keys

/// `CONNECT_LINK_SIGNING_KEY` with key ids (G-8). New links name the id of the key that signed them (inside the signed context); verification
/// picks the key by that id, so the key can be rotated while links signed under the previous one stay valid until they expire.
struct ConnectKeyring: Sendable {
    /// The implicit id of links signed before key ids existed.
    static let legacyKeyId = "c1"

    let currentId: String
    let current: SymmetricKey
    let previous: [String: SymmetricKey]

    init(config: ServerConfig) {
        currentId = config.operations.connectKeyId
        current = config.connectLinkKey
        previous = config.operations.previousConnectKeys
    }

    func key(for id: String) -> SymmetricKey? { id == currentId ? current : previous[id] }

    /// Builds a link whose context names the signing key.
    func link(code: BusinessCode, context: ConnectContext) throws -> ConnectLink {
        var stamped = context
        stamped.keyId = currentId
        return try ConnectLink(code: code, context: stamped, key: current)
    }

    /// Verifies a link's context with the key it names (or the legacy key when it names none). The named id only selects a key; the
    /// signature, which covers the id, decides.
    func verifiedContext(of link: ConnectLink, now: Date) throws -> ConnectContext {
        let claimed = link.claimedKeyId ?? Self.legacyKeyId
        guard let key = key(for: claimed) else { throw ConnectLink.ContextError.badSignature }
        return try link.verifiedContext(key: key, now: now)
    }
}

extension ServerContext {
    var connectKeys: ConnectKeyring { ConnectKeyring(config: config) }
}

// MARK: - Sealed-column registry and re-encryption

/// Every column the server seals with `FieldCipher`, with the context it is bound to. `rotate-data-key` rewrites each value under the current
/// key; `verify-data-key` opens each one and reports the key ids in use. A new sealed column must be added here (a test compares this list
/// with the `context:` strings used in the source).
struct SealedColumn: Sendable {
    var table: String
    var column: String
    var context: String
    /// The column may hold something that is not sealed (a plain JSON payload, a legacy plaintext webhook body): such values are skipped.
    var mixed = false
}

enum SealedColumns {
    static let all: [SealedColumn] = [
        SealedColumn(table: "business_idempotency", column: "result_sealed", context: "business_idempotency.result"),
        SealedColumn(table: "channel_outbound", column: "phone_ciphertext", context: "channel_outbound.phone"),
        SealedColumn(table: "conversation_messages", column: "body_ciphertext", context: "conversation_messages.body"),
        SealedColumn(table: "dashboard_ceremonies", column: "payload_json", context: "dashboard_ceremonies.payload", mixed: true),
        SealedColumn(table: "dashboard_email_codes", column: "payload", context: "dashboard_email_codes.payload"),
        SealedColumn(table: "dashboard_users", column: "email_ciphertext", context: "dashboard_users.email"),
        SealedColumn(table: "delegation_grants", column: "label_ciphertext", context: "delegation.label"),
        SealedColumn(table: "delegation_invitations", column: "label_ciphertext", context: "delegation.label"),
        SealedColumn(table: "link_tokens", column: "phone_ciphertext", context: "link_tokens.phone"),
        SealedColumn(table: "loyalty_accounts", column: "member_reference_ciphertext", context: "loyalty_accounts.member_reference"),
        SealedColumn(table: "org_invites", column: "email_ciphertext", context: "org_invites.email"),
        SealedColumn(table: "phone_links", column: "phone_ciphertext", context: "phone_links.phone"),
        SealedColumn(table: "refresh_tokens", column: "successor_sealed", context: "refresh_tokens.successor"),
        SealedColumn(table: "sms_contexts", column: "context_ciphertext", context: "sms_contexts.context"),
        SealedColumn(table: "sms_outbound", column: "phone_ciphertext", context: "sms_outbound.phone"),
        SealedColumn(table: "sms_outbound", column: "body_ciphertext", context: "sms_outbound.body"),
        SealedColumn(table: "verification_results", column: "payload", context: "verification_results.payload"),
        SealedColumn(table: "webhook_deliveries", column: "body", context: "webhook_deliveries.body", mixed: true),
        SealedColumn(table: "webhook_subscriptions", column: "secret_ciphertext", context: "webhook_subscriptions.secret"),
        SealedColumn(table: "webhook_subscriptions", column: "previous_secret_ciphertext", context: "webhook_subscriptions.secret"),
        SealedColumn(table: "approve_requests", column: "details_sealed", context: "approve_requests.details"),
        SealedColumn(table: "support_tickets", column: "body_ciphertext", context: "support_tickets.body"),
        SealedColumn(table: "business_security_settings", column: "contacts_ciphertext", context: "business_security_settings.contacts"),
        SealedColumn(table: "data_requests", column: "artifact", context: "data_requests.artifact"),
    ]
}

struct DataKeyRotator {
    let db: any Database
    let ctx: ServerContext

    struct Report: Equatable {
        var scanned = 0
        /// Values per key id, as found before any rewrite.
        var byKeyId: [String: Int] = [:]
        var rewritten = 0
        /// Values that could not be opened with any configured key (their column is named in `failedColumns`).
        var failed = 0
        var failedColumns: Set<String> = []
        var skippedPlain = 0
    }

    private struct Row: Decodable {
        var id: UUID
        var value: String?
    }

    private func isMissingTable(_ error: any Error) -> Bool {
        let text = String(describing: error).lowercased()
        return text.contains("no such table") || text.contains("does not exist") || text.contains("no such column")
    }

    /// Walks every sealed column. With `rewrite`, values under another key id are re-sealed under the current key (compare-and-swap on the old
    /// value, so a concurrent writer is never overwritten). Batched by primary key so it can run against a live database.
    func run(rewrite: Bool, batch: Int = 500) async throws -> Report {
        guard let sql = db as? any SQLDatabase else { throw APIError.internalError }
        var report = Report()
        let currentId = ctx.cipher.currentKeyId
        for column in SealedColumns.all {
            var after: UUID?
            while true {
                let rows: [Row]
                do {
                    var query = SQLQueryString("SELECT id, \(unsafeRaw: column.column) AS value FROM \(unsafeRaw: column.table) WHERE \(unsafeRaw: column.column) IS NOT NULL")
                    if let after { query.appendInterpolation(unsafeRaw: " AND id > "); query.appendInterpolation(bind: after) }
                    query.appendInterpolation(unsafeRaw: " ORDER BY id LIMIT \(batch)")
                    rows = try await sql.raw(query).all(decoding: Row.self)
                } catch {
                    // A column of a feature that is not migrated (yet) holds nothing to rotate.
                    if isMissingTable(error) { break }
                    throw error
                }
                if rows.isEmpty { break }
                for row in rows {
                    after = row.id
                    guard let value = row.value, FieldCipher.isSealed(value) else {
                        if row.value != nil, column.mixed { report.skippedPlain += 1 }
                        continue
                    }
                    report.scanned += 1
                    let keyId = FieldCipher.keyId(of: value) ?? "?"
                    report.byKeyId[keyId, default: 0] += 1
                    let plain: Data
                    do { plain = try ctx.cipher.open(value, context: column.context, rowId: row.id) } catch {
                        report.failed += 1
                        report.failedColumns.insert("\(column.table).\(column.column)")
                        continue
                    }
                    // Legacy column-bound `v1.` values are upgraded too: after a rotation nothing is left under an old format or key.
                    guard rewrite, keyId != currentId || FieldCipher.isLegacy(value) else { continue }
                    let fresh = try ctx.cipher.seal(plain, context: column.context, rowId: row.id)
                    let update = SQLQueryString("UPDATE \(unsafeRaw: column.table) SET \(unsafeRaw: column.column) = \(bind: fresh) WHERE id = \(bind: row.id) AND \(unsafeRaw: column.column) = \(bind: value)")
                    try await sql.raw(update).run()
                    report.rewritten += 1
                }
            }
        }
        return report
    }
}

/// `ViadereServer rotate-data-key` re-seals every column under the current `DATA_ENCRYPTION_KEY` (see docs/ops/KEY-ROTATION.md).
public struct RotateDataKeyCommand: AsyncCommand {
    public struct Signature: CommandSignature { public init() {} }
    public let signature = Signature()
    public let help = "Re-encrypts every sealed column under the current DATA_ENCRYPTION_KEY (idempotent; safe while the server runs)."
    public init() {}

    public func run(using context: CommandContext, signature: Signature) async throws {
        let app = context.application
        let report = try await DataKeyRotator(db: app.db, ctx: app.ctx).run(rewrite: true)
        context.console.print("Scanned \(report.scanned) sealed values; re-encrypted \(report.rewritten); \(report.failed) could not be opened.")
        for (id, count) in report.byKeyId.sorted(by: { $0.key < $1.key }) { context.console.print("  found under key \(id): \(count)") }
        if report.failed > 0 {
            context.console.error("Unopenable columns: \(report.failedColumns.sorted().joined(separator: ", ")). Keep the previous keys configured (DATA_ENCRYPTION_KEYS_PREVIOUS).")
            throw Abort(.internalServerError)
        }
    }
}

/// `ViadereServer verify-data-key [--require-current]` opens every sealed value. With `--require-current` it also fails if any value is still
/// under another key id: run it before removing a previous key from the configuration.
public struct VerifyDataKeyCommand: AsyncCommand {
    public struct Signature: CommandSignature {
        @Flag(name: "require-current") var requireCurrent: Bool
        public init() {}
    }
    public let signature = Signature()
    public let help = "Verifies that every sealed value opens with the configured keys (and, with --require-current, is under the current key)."
    public init() {}

    public func run(using context: CommandContext, signature: Signature) async throws {
        let app = context.application
        let report = try await DataKeyRotator(db: app.db, ctx: app.ctx).run(rewrite: false)
        context.console.print("Verified \(report.scanned) sealed values.")
        for (id, count) in report.byKeyId.sorted(by: { $0.key < $1.key }) { context.console.print("  key \(id): \(count)") }
        if report.failed > 0 {
            context.console.error("\(report.failed) values do not open: \(report.failedColumns.sorted().joined(separator: ", ")).")
            throw Abort(.internalServerError)
        }
        let current = app.ctx.cipher.currentKeyId
        if signature.requireCurrent, report.byKeyId.contains(where: { $0.key != current }) {
            context.console.error("Values remain under previous keys. Run rotate-data-key before removing a previous key.")
            throw Abort(.internalServerError)
        }
    }
}
