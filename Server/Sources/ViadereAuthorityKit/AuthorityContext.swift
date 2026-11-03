import Fluent
import Foundation
import Vapor
import ViadereCore
import ViadereServiceSupport

/// What every authority route needs. `keys` is nil while `AUTHORITY_ENABLED` is off (no key is even loaded then).
public final class AuthorityContext: Sendable {
    public let config: AuthorityConfig
    let kms: any KeyManagementService
    let keys: AuthorityKeyRing?
    let clock: @Sendable () -> Date
    let bulkhead: ChallengeBulkhead
    /// The active recovery-seal key in memory (`AUTHORITY_RECOVERY_ENABLED` only; ADR-0034 §5.2). `nil`: recovery routes fail closed.
    let seal: SealKeyHolder?

    init(config: AuthorityConfig, kms: any KeyManagementService, keys: AuthorityKeyRing?, clock: @escaping @Sendable () -> Date, seal: SealKeyHolder? = nil) {
        self.config = config
        self.kms = kms
        self.keys = keys
        self.clock = clock
        self.seal = seal
        bulkhead = ChallengeBulkhead(perTenantPerMinute: config.challengeBudgetPerTenantPerMinute)
    }

    var now: Date { clock() }
    var environment: AuthorityEnvironment { config.deployment.statementEnvironment }

    func requireKeys() throws -> AuthorityKeyRing {
        guard config.enabled, let keys else { throw Abort(.serviceUnavailable, reason: "authority_disabled") }
        return keys
    }
}

/// Challenge signing has its own per-tenant budget (ADR-0033 §2, S2-A2-6): a flood for one tenant exhausts only that tenant's challenges, never heads,
/// grants, tokens or other tenants. Over budget: `429 challenge_budget`.
actor ChallengeBulkhead {
    let limit: Int
    private var windows: [String: (start: Date, count: Int)] = [:]

    init(perTenantPerMinute: Int) { limit = perTenantPerMinute }

    func admit(tenant: String, now: Date) -> Bool {
        var window = windows[tenant] ?? (now, 0)
        if now.timeIntervalSince(window.start) >= 60 { window = (now, 0) }
        guard window.count < limit else { windows[tenant] = window; return false }
        window.count += 1
        windows[tenant] = window
        if windows.count > 10_000 { windows = windows.filter { now.timeIntervalSince($0.value.start) < 60 } }
        return true
    }
}

/// Authority audit events: every decision, allow or deny (ADR-0023 §6). Never a nonce, a code, a token or a display text.
enum AuthorityAudit {
    static func record(_ db: any Database, _ event: String, outcome: String, reason: String? = nil, tenant: String? = nil, accountRef: String? = nil,
                       challengeId: String? = nil, kid: String? = nil, policyVersion: String? = nil, caller: String? = nil, detail: String? = nil, at: Date) async {
        let row = AuthorityAuditEvent()
        row.event = event
        row.outcome = outcome
        row.reason = reason
        row.tenantId = tenant
        row.accountRef = accountRef
        row.challengeId = challengeId
        row.kid = kid
        row.policyVersion = policyVersion
        row.caller = caller
        row.detail = detail
        row.at = at
        try? await row.create(on: db)
    }
}

/// Uniform 2-digit codes `10`-`99` (no leading zero) by rejection sampling: no modulo bias (ADR-0022 §2.1).
enum AuthorityMatchCode {
    static func twoDigits() -> String {
        while true {
            let byte = SecureToken.randomBytes(1)[0]
            if byte < 180 { return String(10 + Int(byte) % 90) }
        }
    }
}

extension Abort {
    /// The one answer for refused evidence, whatever the reason (the reason goes to the audit record only).
    static var evidenceInvalid: Abort { Abort(.unauthorized, reason: "evidence_invalid") }
}
