import Fluent
import FluentSQL
import Foundation
import SQLKit
import Vapor
import ViadereCore

/// A one-time email code (sign-up or invitation). Only a peppered hash of the code is stored, bound to the row id.
final class DashboardEmailCodeRecord: Model, @unchecked Sendable {
    static let schema = "dashboard_email_codes"
    @ID(key: .id) var id: UUID?
    /// `signup` (subject = the unverified user) or `invite` (subject = the invitation).
    @Field(key: "kind") var kind: String
    @Field(key: "subject_id") var subjectId: UUID
    @Field(key: "email_hash") var emailHash: String
    @Field(key: "code_hash") var codeHash: String
    @Field(key: "attempts") var attempts: Int
    @Field(key: "expires_at") var expiresAt: Date
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "consumed_at") var consumedAt: Date?
    /// Sign-up details to apply on verification (sealed, bound to this row): the organization is created only once the address is proven.
    @OptionalField(key: "payload") var payload: String?

    init() {}
}

/// Email-ownership proof for the dashboard.
///
/// * A 6-digit code from the CSPRNG, stored as an HMAC keyed with the server pepper and the row id; valid for 15 minutes; **5 attempts** per
///   code (the budget is spent atomically *before* the comparison, so concurrent guesses cannot exceed it); single use.
/// * A new code replaces the old one, and sending is rate-limited per email address and per IP by the callers.
/// * An account stays `unverified` until its code is entered. An unverified account cannot sign in, has no organization and cannot accept an
///   invitation. It holds the address only for 24 hours (`purge`) and **never blocks** it: a later sign-up or an invitation for the same
///   address replaces the stale record (`removeUnverified`), so squatting an address without owning the mailbox gains nothing.
struct EmailVerificationService {
    let db: any Database
    let ctx: ServerContext

    static let codeTTL: TimeInterval = 15 * 60
    static let maxAttempts = 5
    static let unverifiedTTL: TimeInterval = 24 * 3600
    static let payloadContext = "dashboard_email_codes.payload"

    /// Six digits, uniform (rejection sampling over a 32-bit value).
    static func generateCode() -> String {
        let limit: UInt32 = UInt32.max - (UInt32.max % 1_000_000)
        while true {
            let bytes = SecureToken.randomBytes(4)
            let value = bytes.reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
            if value < limit { return String(format: "%06d", value % 1_000_000) }
        }
    }

    static func normalize(code raw: String) -> String? {
        let digits = raw.filter { !$0.isWhitespace && $0 != "-" }
        return digits.count == 6 && digits.allSatisfy({ $0.isASCII && $0.isNumber }) ? digits : nil
    }

    func hash(id: UUID, code: String) -> String { ctx.hasher.hmacHex("dashboard-email-code", "\(id.uuidString.lowercased())|\(code)") }

    /// Creates a fresh code for `subjectId`, replacing any earlier one of the same kind. Returns the plaintext code (to be emailed, never stored).
    func issue(kind: String, subjectId: UUID, emailHash: String, payload: String? = nil, on database: (any Database)? = nil) async throws -> String {
        let database = database ?? db
        let code = Self.generateCode()
        let record = DashboardEmailCodeRecord()
        record.id = UUID()
        record.kind = kind
        record.subjectId = subjectId
        record.emailHash = emailHash
        record.codeHash = hash(id: record.id!, code: code)
        record.attempts = 0
        record.createdAt = ctx.now
        record.expiresAt = ctx.now.addingTimeInterval(Self.codeTTL)
        record.payload = try payload.map { try ctx.cipher.seal($0, context: Self.payloadContext, rowId: record.id!) }
        try await DashboardEmailCodeRecord.query(on: database).filter(\.$kind == kind).filter(\.$subjectId == subjectId).delete()
        try await record.create(on: database)
        return code
    }

    /// Best effort: a provider outage must neither fail the request nor reveal anything (the answer is the same whether or not mail goes out).
    func deliver(_ message: EmailMessage) async {
        do { try await ctx.email.send(message) } catch {
            ctx.logger.warning("email delivery failed", metadata: ["kind": "\(message.kind)", "error": "\(type(of: error))"])
        }
    }

    static func codeMessage(to email: String, code: String, kind: String) -> EmailMessage {
        EmailMessage(to: email, subject: "Your Viadere verification code", text: """
            Your Viadere verification code is \(code).

            It expires in 15 minutes and works once. If you did not ask for it, ignore this email: nothing happens until the code is entered.
            """, kind: kind)
    }

    func latest(kind: String, emailHash: String) async throws -> DashboardEmailCodeRecord? {
        try await DashboardEmailCodeRecord.query(on: db).filter(\.$kind == kind).filter(\.$emailHash == emailHash).filter(\.$consumedAt == nil)
            .sort(\.$createdAt, .descending).first()
    }

    /// Whether `code` is the live code of `record`. Spends one of the five attempts first (atomically), then compares in constant time.
    /// Does not consume the code: the caller does that together with whatever the code unlocks (`consume`).
    func check(_ record: DashboardEmailCodeRecord, code raw: String) async throws -> Bool {
        guard let id = record.id, record.consumedAt == nil, record.expiresAt > ctx.now, let code = Self.normalize(code: raw),
              let sql = db as? any SQLDatabase else { return false }
        let reserved = try await sql.raw("UPDATE dashboard_email_codes SET attempts = attempts + 1 WHERE id = \(bind: id) AND attempts < \(bind: Self.maxAttempts) AND consumed_at IS NULL RETURNING attempts").all()
        guard !reserved.isEmpty else { return false }
        return ConstantTime.equals(hash(id: id, code: code), record.codeHash)
    }

    /// Marks the code used; `false` when another request already did.
    func consume(_ record: DashboardEmailCodeRecord, on database: (any Database)? = nil) async throws -> Bool {
        try await DB.swapFromNull(database ?? db, table: DashboardEmailCodeRecord.schema, id: record.id!, column: "consumed_at", newValue: ctx.now)
    }

    // MARK: Unverified accounts

    /// Deletes unverified business accounts (and everything hanging off them) so the address is free again.
    static func removeUnverified(_ users: [DashboardUserRecord], on db: any Database) async throws {
        let ids = users.compactMap(\.id)
        guard !ids.isEmpty else { return }
        try await DashboardEmailCodeRecord.query(on: db).filter(\.$subjectId ~~ ids).delete()
        try await DashboardPasskeyRecord.query(on: db).filter(\.$userId ~~ ids).delete()
        try await DashboardSessionRecord.query(on: db).filter(\.$userId ~~ ids).delete()
        try await DashboardUserRecord.query(on: db).filter(\.$id ~~ ids).filter(\.$status == "unverified").delete()
    }

    /// Removes an unverified account holding `emailHash`, if any (before a verified sign-up or an invitation takes the address).
    static func removeUnverified(emailHash: String, on db: any Database) async throws {
        let users = try await DashboardUserRecord.query(on: db).filter(\.$emailHash == emailHash).filter(\.$status == "unverified").all()
        try await removeUnverified(users, on: db)
    }

    /// Maintenance: sign-ups that sat unverified for 24 hours, and long-dead codes.
    static func purge(on db: any Database, now: Date) async throws {
        let cutoff = now.addingTimeInterval(-unverifiedTTL)
        let stale = try await DashboardUserRecord.query(on: db).filter(\.$status == "unverified").filter(\.$createdAt < cutoff).all()
        if !stale.isEmpty { try await db.transaction { tx in try await removeUnverified(stale, on: tx) } }
        let old = now.addingTimeInterval(-unverifiedTTL)
        if try await DashboardEmailCodeRecord.query(on: db).filter(\.$expiresAt < old).count() > 0 {
            try await DashboardEmailCodeRecord.query(on: db).filter(\.$expiresAt < old).delete()
        }
    }
}
