import Fluent
import Foundation
import NIOHTTP1
import SQLKit
import Vapor
import ViadereCore
import ViadereServiceSupport

/// Retention of the authority's tables (owner decisions 7 and 10: security transaction metadata 30 days; pending secrets until completion or expiry;
/// ADR-0023 §7, ADR-0026). Append-only evidence (`authority_keylog_entries`, `authority_grants`, `authority_audit_events`) is class E and is never
/// purged here; the database triggers refuse it anyway.
enum AuthorityRetention {
    /// Rows that hold a single-use secret or its hash (OIDC codes, link codes, PoP nonces): one day after expiry.
    static let secretGrace: TimeInterval = 86_400
    /// Transaction metadata (challenges and their bindings, closed device-add entries, recovery attempts, sign records, cached heads): 30 days.
    static let metadata: TimeInterval = 30 * 86_400

    /// Deletes what is past retention. Returns the number of rows deleted per table.
    @discardableResult
    static func purge(_ db: any Database, now: Date) async throws -> [String: Int] {
        var deleted: [String: Int] = [:]
        func run<M: Model>(_ type: M.Type, _ query: QueryBuilder<M>) async throws {
            let count = try await query.count()
            if count > 0 { try await query.delete() }
            deleted[M.schema] = count
        }
        let secretCutoff = now.addingTimeInterval(-secretGrace), metadataCutoff = now.addingTimeInterval(-metadata)
        try await run(AuthorityOIDCCode.self, AuthorityOIDCCode.query(on: db).filter(\.$expiresAt < secretCutoff))
        try await run(AuthorityLinkCode.self, AuthorityLinkCode.query(on: db).filter(\.$expiresAt < secretCutoff))
        try await run(AuthorityKeylogNonce.self, AuthorityKeylogNonce.query(on: db).filter(\.$expiresAt < secretCutoff))
        // A replay key is useless once the value it guards has expired.
        try await run(AuthorityReplayRecord.self, AuthorityReplayRecord.query(on: db).filter(\.$expiresAt < now))
        let oldChallenges = try await AuthorityChallenge.query(on: db).filter(\.$expiresAt < metadataCutoff).all().compactMap(\.id)
        if !oldChallenges.isEmpty {
            // Device-add entries keep their challenge until they are purged themselves.
            try await run(AuthorityChallengeBinding.self, AuthorityChallengeBinding.query(on: db).filter(\.$id ~~ oldChallenges))
            try await run(AuthorityChallenge.self, AuthorityChallenge.query(on: db).filter(\.$id ~~ oldChallenges))
        }
        try await run(AuthorityDeviceAddEntry.self, AuthorityDeviceAddEntry.query(on: db).filter(\.$state != "pending").filter(\.$createdAt < metadataCutoff))
        try await run(AuthorityRecoveryAttempt.self, AuthorityRecoveryAttempt.query(on: db).filter(\.$at < metadataCutoff))
        try await run(AuthoritySignRecord.self, AuthoritySignRecord.query(on: db).filter(\.$at < metadataCutoff))
        try await run(AuthorityHeadCache.self, AuthorityHeadCache.query(on: db).filter(\.$signedAt < metadataCutoff))
        return deleted
    }
}

/// The authority's own maintenance (no worker involved): reviewed inventory checks, recovery activation, closure of unconfirmed accounts, expiry of
/// device-add entries and the retention purge. The serving authority runs it every minute while `AUTHORITY_ENABLED` is on.
struct AuthorityMaintenance {
    let ctx: AuthorityContext
    let db: any Database

    func run() async throws {
        let now = ctx.now
        try await AuthorityKeyInventory.verifyPending(kms: ctx.kms, db: db, now: now)
        if ctx.config.recoveryEnabled, ctx.config.keylogEnabled { try await AuthorityRecoveryService(ctx: ctx, db: db).activateDue() }
        try await closeUnconfirmedAccounts()
        try await expireDeviceAddEntries()
        try await AuthorityRetention.purge(db, now: now)
    }

    /// ADR-0032 §1.8 (b): a minted account without `enrollment_confirmed` 24 h after genesis is closed and its keys revoked (reduce-only, audited).
    @discardableResult
    func closeUnconfirmedAccounts() async throws -> Int {
        let now = ctx.now
        var closed = 0
        for state in try await AuthorityAccountState.query(on: db).filter(\.$state == "unconfirmed").limit(200).all() {
            guard let account = try await AuthorityAccount.query(on: db).filter(\.$accountRef == state.id!).first(),
                  account.createdAt <= now.addingTimeInterval(-AuthorityKeyLogService.unconfirmedAccountLifetime) else { continue }
            try await db.transaction { tx in
                for key in try await AuthorityKey.query(on: tx).filter(\.$accountRef == state.id!).filter(\.$revokedAt == nil).all() {
                    try await AuthorityKeyLog.revokeKey(tx, key, reason: "enrollment_not_confirmed", by: "authority", now: now)
                }
                try await AuthorityAccountState.query(on: tx).filter(\.$id == state.id!).filter(\.$state == "unconfirmed").set(\.$state, to: "closed")
                    .set(\.$updatedAt, to: now).update()
            }
            await AuthorityAudit.record(db, "authority.account_closed", outcome: "success", reason: "enrollment_not_confirmed", accountRef: state.id, caller: "authority", at: now)
            closed += 1
        }
        return closed
    }

    /// A device-add entry whose one challenge failed, expired or was denied ends (`abandoned`); new keys and a new PoP nonce are needed.
    func expireDeviceAddEntries() async throws {
        let now = ctx.now
        for entry in try await AuthorityDeviceAddEntry.query(on: db).filter(\.$state == "pending").filter(\.$challengeId != nil).all() {
            guard let challenge = try await AuthorityChallenge.find(entry.challengeId!, on: db) else { continue }
            if challenge.state != "pending" && challenge.state != "used" || (challenge.state == "pending" && challenge.expiresAt <= now) {
                try await AuthorityDeviceAddEntry.query(on: db).filter(\.$id == entry.id!).filter(\.$state == "pending").set(\.$state, to: "abandoned").update()
            }
        }
        // An entry that never got its challenge within the PoP nonce lifetime ends too.
        try await AuthorityDeviceAddEntry.query(on: db).filter(\.$state == "pending").filter(\.$challengeId == nil)
            .filter(\.$createdAt < now.addingTimeInterval(-AuthorityKeyLogService.nonceLifetime)).set(\.$state, to: "abandoned").update()
    }
}

/// Runs `AuthorityMaintenance` every minute for the life of the serving process (never in tests, which call it directly).
final class AuthorityMaintenanceLoop: LifecycleHandler, @unchecked Sendable {
    private var task: Task<Void, Never>?

    func didBootAsync(_ application: Application) async throws {
        let app = application
        task = Task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(60))
                do { try await AuthorityMaintenance(ctx: app.authority, db: app.db).run() } catch { app.logger.error("authority maintenance failed") }
            }
        }
    }

    func shutdownAsync(_ application: Application) async { task?.cancel() }
}

// MARK: - Key Vault AuditEvent reconciliation (ADR-0023 §6, ADR-0028 §2, ADR-0034 §5.2; condition C-11)

/// One Key Vault data-plane operation from the `AuditEvent` diagnostics of `kv-vdr-auth` (Log Analytics).
public struct KeyVaultAuditOperation: Sendable, Equatable {
    /// `KeySign` / `Sign` or `KeyUnwrap` / `UnwrapKey` (both spellings occur in AuditEvent rows; the operations that need an authority record).
    public var operation: String
    /// `name/version` of the key.
    public var keyRef: String
    public var at: Date
    public init(operation: String, keyRef: String, at: Date) {
        self.operation = operation
        self.keyRef = keyRef
        self.at = at
    }

    /// Parses Log Analytics query rows `[TimeGenerated, OperationName, id_s]` (the key id is `https://<vault>/keys/<name>/<version>`).
    public static func parse(rows: [[JSONValue]]) -> [KeyVaultAuditOperation] {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let plain = ISO8601DateFormatter()
        return rows.compactMap { row in
            guard row.count >= 3, let time = row[0].stringValue, let at = formatter.date(from: time) ?? plain.date(from: time), let op = row[1].stringValue,
                  let id = row[2].stringValue, let range = id.range(of: "/keys/") else { return nil }
            let parts = id[range.upperBound...].split(separator: "/")
            guard parts.count >= 2 else { return nil }
            return KeyVaultAuditOperation(operation: op, keyRef: "\(parts[0])/\(parts[1])", at: at)
        }
    }
}

public enum AuthorityReconciliation {
    /// A record is written before the Key Vault call; the event's time is the service's. Allowed distance between the two.
    public static let tolerance: TimeInterval = 120

    public struct Result: Sendable, Equatable {
        /// Key Vault operations without an authority record: each one alerts at high priority.
        public var unmatched: [KeyVaultAuditOperation]
        /// Records without a Key Vault operation (a call that failed before reaching Key Vault): informational.
        public var unusedRecords: Int
    }

    /// Greedy one-to-one matching per key and operation, in time order. Pure; `run` feeds it.
    public static func reconcile(operations: [KeyVaultAuditOperation], records: [(keyRef: String, kind: String, at: Date)]) -> Result {
        var pool: [String: [Date]] = [:]
        for record in records { pool["\(record.kind)|\(record.keyRef)", default: []].append(record.at) }
        for key in pool.keys { pool[key]?.sort() }
        var unmatched: [KeyVaultAuditOperation] = []
        for op in operations.sorted(by: { $0.at < $1.at }) {
            let kind: String
            switch op.operation {
            case "KeySign", "Sign": kind = "sign"
            case "KeyUnwrap", "UnwrapKey": kind = "unwrap"
            default: continue
            }
            let bucket = "\(kind)|\(op.keyRef)"
            // Records precede the operation (written before the call): the earliest record within the tolerance window.
            if let index = pool[bucket]?.firstIndex(where: { $0 <= op.at.addingTimeInterval(5) && op.at.timeIntervalSince($0) <= tolerance }) {
                pool[bucket]?.remove(at: index)
            } else {
                unmatched.append(op)
            }
        }
        return Result(unmatched: unmatched, unusedRecords: pool.values.reduce(0) { $0 + $1.count })
    }

    /// Reconciles `[since, until]` and records one audit event per unmatched operation. Throws (so the scheduled job fails and its alert fires) when any
    /// operation is unmatched.
    public static func run(operations: [KeyVaultAuditOperation], db: any Database, since: Date, until: Date) async throws -> Result {
        let rows = try await AuthoritySignRecord.query(on: db).filter(\.$at >= since.addingTimeInterval(-tolerance)).filter(\.$at <= until).all()
        let result = reconcile(operations: operations.filter { $0.at >= since && $0.at <= until }, records: rows.map { ($0.keyRef, $0.kind, $0.at) })
        for op in result.unmatched {
            await AuthorityAudit.record(db, "authority.kv_unmatched_operation", outcome: "alert", reason: op.operation, kid: op.keyRef, caller: "reconcile", at: until)
        }
        await AuthorityAudit.record(db, "authority.kv_reconciliation", outcome: result.unmatched.isEmpty ? "success" : "alert", caller: "reconcile",
                                    detail: "unmatched:\(result.unmatched.count) unused:\(result.unusedRecords)", at: until)
        if !result.unmatched.isEmpty { throw ReconciliationFailure(unmatched: result.unmatched.count) }
        return result
    }

    public struct ReconciliationFailure: Error, CustomStringConvertible {
        public let unmatched: Int
        public var description: String { "\(unmatched) Key Vault operation(s) without an authority record (high-priority alert)" }
    }
}

/// `ViadereAuthority reconcile` (scheduled job `job-viadere-authority-reconcile`, independent of the worker): reads the `AuditEvent` operations of the
/// authority Key Vault from Log Analytics with its managed identity (Log Analytics Reader on the authority workspace only) and reconciles them.
public struct AuthorityReconcileCommand: AsyncCommand {
    public struct Signature: CommandSignature {
        @Option(name: "window-minutes") var windowMinutes: Int?
        public init() {}
    }

    public var help: String { "Reconciles Key Vault sign and unwrap operations against the authority's sign records (exit 1 on any unmatched operation)" }
    public init() {}

    public func run(using context: CommandContext, signature: Signature) async throws {
        let env = ProcessInfo.processInfo.environment
        guard let workspace = env["AUTHORITY_AUDIT_WORKSPACE_ID"], UUID(uuidString: workspace) != nil,
              let identity = AzureManagedIdentity.fromEnvironment(env) else { throw AuthorityConfigError.missing("AUTHORITY_AUDIT_WORKSPACE_ID and a managed identity") }
        let window = TimeInterval(max(15, min(signature.windowMinutes ?? 75, 24 * 60)) * 60)
        // Log Analytics ingestion lags; reconcile a window that ended 10 minutes ago (the job runs hourly with an overlapping window).
        let until = Date().addingTimeInterval(-600), since = until.addingTimeInterval(-window)
        let query = """
            AzureDiagnostics | where ResourceProvider == "MICROSOFT.KEYVAULT" and Category == "AuditEvent" and OperationName in ("KeySign", "Sign", "KeyUnwrap", "UnwrapKey") \
            | where TimeGenerated between (datetime(\(ISO8601DateFormatter().string(from: since))) .. datetime(\(ISO8601DateFormatter().string(from: until)))) \
            | project TimeGenerated, OperationName, id_s
            """
        let token = try await identity.token(audience: "https://api.loganalytics.io")
        let http = AllowListOutboundHTTP(allowed: ["api.loganalytics.azure.com"], base: StandaloneOutboundHTTP(guard: .fromEnvironment()))
        let body = try CanonicalJSON.serialize(.object(["query": .string(query)]))
        let response = try await http.send(method: .POST, url: "https://api.loganalytics.azure.com/v1/workspaces/\(workspace)/query",
                                           headers: ["Authorization": "Bearer " + token, "Content-Type": "application/json"], body: body)
        guard response.status == 200, case .object(let o)? = try? JSONDecoder().decode(JSONValue.self, from: response.body), case .array(let tables)? = o["tables"],
              case .array(let rows)? = tables.first?.objectValue?["rows"] else { throw AuthorityConfigError.invalid("Log Analytics answer (status \(response.status))") }
        let operations = KeyVaultAuditOperation.parse(rows: rows.compactMap { if case .array(let r) = $0 { r } else { nil } })
        let result = try await AuthorityReconciliation.run(operations: operations, db: context.application.db, since: since, until: until)
        context.console.print("authority reconcile: \(operations.count) operation(s), all matched (\(result.unusedRecords) record(s) without an operation)")
    }
}
