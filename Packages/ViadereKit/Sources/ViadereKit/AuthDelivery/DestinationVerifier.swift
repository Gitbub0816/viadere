@preconcurrency import Crypto
import Foundation
import ViadereCore

// The device check of a business-signed destination (ADR-0031 §2, §4; SECURITY §2.101 "Device verification"): an authority-signed tenant record
// fetched fresh through the api, then the business's `viadere-destination+jws` against that record, then, after Continue, the exact URL bytes
// against `url_sha256`. Every failure is sorted into integrity (`signatureFailed`: S-LINK-09 and `destination_unverified`) or availability
// (`unavailable` / `clockOutsideWindow`: S-LINK-11 / -12, no server call, the delivery stays open).

/// Fetches the tenant record and the revocation list (`GET /v1/auth-tenants/{tenantId}/destination-keys`). The api only relays them.
public protocol TenantDestinationKeysFetching: Sendable {
    func destinationKeys(tenantId: String) async throws -> AuthTenantDestinationKeys
}

public struct LiveTenantDestinationKeys: TenantDestinationKeysFetching {
    let client: APIClient
    public init(client: APIClient) { self.client = client }
    public func destinationKeys(tenantId: String) async throws -> AuthTenantDestinationKeys {
        guard AuthorityTenantRecord.isTenantId(tenantId) else { throw AuthDeliveryError.failed }
        return try await client.call(APIRoutes.authTenantDestinationKeys, params: ["tenantId": tenantId])
    }
}

/// What the device remembers between checks, persisted in the Keychain (`SecretStore`, this device only):
///
/// - the highest tenant-record `seq` accepted per tenant (a lower one is a replayed record: integrity, revision 3.1);
/// - every destination-statement `jti` with the delivery it was first seen on, until `exp + 60 s` (a `jti` on another delivery is a replay);
/// - revoked pinned keys, sticky: the set only grows (ADR-0033 §3.3 (c), (d)).
///
/// A store that cannot be read or written fails the check closed as an availability failure (nothing is opened, nothing is reported).
public final class DestinationVerificationState: @unchecked Sendable {
    struct Snapshot: Codable, Equatable {
        var seqs: [String: Int64] = [:]
        var jtis: [String: JTI] = [:]
        var revoked: [String] = []
        struct JTI: Codable, Equatable {
            var delivery: String
            var until: Int64
        }
    }

    public enum Failure: Error, Sendable { case storage }

    static let account = "viadere.destination-verification.v1"
    static let maxJTIs = 2048
    private let secrets: any SecretStore
    private let lock = NSLock()
    private var cached: Snapshot?

    public init(secrets: any SecretStore) { self.secrets = secrets }

    private func load() throws -> Snapshot {
        if let cached { return cached }
        let snapshot: Snapshot
        do {
            if let data = try secrets.read(Self.account) { snapshot = try JSONDecoder().decode(Snapshot.self, from: data) } else { snapshot = Snapshot() }
        } catch { throw Failure.storage }
        cached = snapshot
        return snapshot
    }

    private func save(_ snapshot: Snapshot) throws {
        do { try secrets.write(try JSONEncoder().encode(snapshot), account: Self.account) } catch { throw Failure.storage }
        cached = snapshot
    }

    private func update<T>(_ body: (inout Snapshot) throws -> T) throws -> T {
        lock.lock()
        defer { lock.unlock() }
        var snapshot = try load()
        let result = try body(&snapshot)
        try save(snapshot)
        return result
    }

    private func read<T>(_ body: (Snapshot) -> T) throws -> T {
        lock.lock()
        defer { lock.unlock() }
        return body(try load())
    }

    func minimumSeq(tenant: String) throws -> Int64 { try read { $0.seqs[tenant] ?? 0 } }

    /// Never lowers a stored `seq`.
    func accept(seq: Int64, tenant: String) throws {
        try update { $0.seqs[tenant] = max($0.seqs[tenant] ?? 0, seq) }
    }

    /// True when `jti` is new, or was first seen on this same delivery (the person reopened the screen); false when another delivery used it.
    func claim(jti: String, delivery: UUID, until: Int64, now: Int64) throws -> Bool {
        try update { s in
            s.jtis = s.jtis.filter { $0.value.until >= now }
            let id = delivery.uuidString.lowercased()
            if let seen = s.jtis[jti] { return seen.delivery == id }
            guard s.jtis.count < Self.maxJTIs else { return false }
            s.jtis[jti] = .init(delivery: id, until: until)
            return true
        }
    }

    func revokedKids() throws -> Set<String> { try read { Set($0.revoked) } }

    /// Sticky: revocations are only ever added.
    func addRevocations(_ kids: [String]) throws {
        try update { s in s.revoked = Array(Set(s.revoked).union(kids)).sorted() }
    }
}

/// `DestinationVerifying` against the authority (ADR-0031 §4), in the ADR's order:
///
/// 1. the tenant record for the tenant the statement names: pinned non-revoked statement key, `typ`, `iss`, `aud`, `env`, ≤ 15 minutes old,
///    `seq` not below the stored one (the revocation list that comes with it is applied first, if it verifies);
/// 2-7. the statement: a key of that record, `not_after`, `typ`/`iss`/`aud`, exact members, `brq` and `purpose` equal to the delivery's, the
///    time window (±60 s), `host` in the record's `allowed_hosts`, `jti` not used by another delivery;
/// and after Continue (`verifyOpened`): SHA-256 of the exact URL bytes equals `url_sha256`, the parsed host equals `host`, the shared
/// validator passes for the record's hosts.
///
/// The name and host the screen shows come from the record and the statement (`verifiedBy`), never from the api's display fields.
public struct AuthorityDestinationVerifier: DestinationVerifying {
    let fetcher: any TenantDestinationKeysFetching
    let state: DestinationVerificationState
    let pinnedKeys: [P256.Signing.PublicKey]
    let sealKids: [String]
    let environment: AuthorityEnvironment
    let clock: @Sendable () -> Date
    private let verified = VerifiedDestinations()

    public init(fetcher: any TenantDestinationKeysFetching, state: DestinationVerificationState, pinnedKeys: [P256.Signing.PublicKey], sealKids: [String],
                environment: AuthorityEnvironment, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.fetcher = fetcher
        self.state = state
        self.pinnedKeys = pinnedKeys
        self.sealKids = sealKids
        self.environment = environment
        self.clock = clock
    }

    public func verify(_ display: AuthLinkDisplay) async -> DestinationCheck {
        verified.forget(display.deliveryId)
        // The build pins no authority key (owner placeholders): nothing can be verified, and that is not evidence of tampering.
        guard !pinnedKeys.isEmpty else { return .notYetSupported }
        // A link-service delivery carries an authority challenge, not a business statement: this screen does not answer it (and must not report it).
        guard !display.linkService else { return .notYetSupported }
        guard let requestId = display.requestId, let purpose = display.purpose, let parsed = try? AuthDestinationStatement.parse(display.destinationStatement) else {
            return .signatureFailed
        }
        let tenant = parsed.statement.tenantId
        let fetched: AuthTenantDestinationKeys
        do { fetched = try await fetcher.destinationKeys(tenantId: tenant) } catch { return .unavailable }
        let now = clock()
        do {
            // The revocation list first: a valid one is stored for good; an invalid one changes nothing (it is not a reason to refuse the record).
            var revoked = try state.revokedKids()
            if let list = fetched.revocationList,
               let accepted = try? AuthorityStatementVerifier.verifyRevocationList(list, statementKeys: pinnedKeys, sealKids: sealKids, alreadyRevoked: revoked,
                                                                                   environment: environment, now: now) {
                try state.addRevocations(accepted.revoked.map(\.kid))
                revoked = try state.revokedKids()
            }
            let record: AuthorityTenantRecord
            do {
                record = try AuthorityStatementVerifier.verifyTenantRecord(fetched.record, pinnedKeys: pinnedKeys, revokedKids: revoked, environment: environment,
                                                                           tenantId: tenant, minimumSeq: try state.minimumSeq(tenant: tenant), now: now)
            } catch AuthorityTenantRecordError.stale {
                return .unavailable
            } catch AuthorityJOSEError.notYetValid {
                // The record was signed more than 60 s after this device's "now": the device clock is behind.
                return .clockOutsideWindow
            } catch {
                return .signatureFailed
            }
            try state.accept(seq: record.seq, tenant: tenant)
            let expectation = record.expectation(requestId: requestId, purpose: purpose, now: now)
            let statement: AuthDestinationStatement
            var storageFailed = false
            do {
                statement = try AuthDestinationStatement.verifyForDevice(display.destinationStatement, expectation: expectation, seenJTI: { jti in
                    do {
                        return try state.claim(jti: jti, delivery: display.deliveryId, until: parsed.statement.expiresAt + AuthDestinationStatement.skew,
                                               now: Int64(now.timeIntervalSince1970))
                    } catch {
                        storageFailed = true
                        return false
                    }
                })
            } catch .replayed where storageFailed {
                return .unavailable
            } catch .expired, .notYetValid {
                // Integrity only when this device's clock agrees with authority time (the record's `issued_at`, verified just now; revision 3.1).
                return Self.clockAgrees(now: now, authorityTime: record.issuedAt) ? .signatureFailed : .clockOutsideWindow
            } catch {
                return .signatureFailed
            }
            verified.remember(display.deliveryId, statement: statement, hosts: Set(record.allowedHosts))
            return .verifiedBy(host: statement.host, business: record.displayName)
        } catch {
            return .unavailable
        }
    }

    public func verifyOpened(_ url: String, for display: AuthLinkDisplay) async -> Bool {
        guard let (statement, hosts) = verified.take(display.deliveryId) else { return false }
        do { try statement.verifyOpened(url: url, allowedHosts: hosts) } catch { return false }
        return true
    }

    /// The device clock agrees with authority time when it lies between `issued_at − 60 s` and `issued_at + 5 min + 60 s` (a served record is at
    /// most 5 minutes old; ADR-0031 §4 revision 3.1).
    static func clockAgrees(now: Date, authorityTime: Int64) -> Bool {
        let t = Int64(now.timeIntervalSince1970)
        return t >= authorityTime - 60 && t <= authorityTime + 300 + 60
    }
}

/// Statements verified before Continue, by delivery, until the URL is checked once.
final class VerifiedDestinations: @unchecked Sendable {
    private let lock = NSLock()
    private var entries: [UUID: (AuthDestinationStatement, Set<String>)] = [:]

    func remember(_ id: UUID, statement: AuthDestinationStatement, hosts: Set<String>) {
        lock.lock()
        defer { lock.unlock() }
        entries[id] = (statement, hosts)
    }

    func forget(_ id: UUID) {
        lock.lock()
        defer { lock.unlock() }
        entries[id] = nil
    }

    func take(_ id: UUID) -> (AuthDestinationStatement, Set<String>)? {
        lock.lock()
        defer { lock.unlock() }
        return entries.removeValue(forKey: id)
    }
}

/// Which verifier a build uses. `FailClosedDestinationVerifier` unless `flags.destinationVerification` is on **and** the build pins authority
/// statement keys; the flag ships off (`AuthDeliveryFlags.shipping` and `.staging`), so nothing changes until the owner turns it on.
public enum DestinationVerifiers {
    public static func make(flags: AuthDeliveryFlags, fetcher: any TenantDestinationKeysFetching, secrets: any SecretStore, environment: AuthorityEnvironment,
                            pinnedKeys: [P256.Signing.PublicKey], sealKids: [String], clock: @escaping @Sendable () -> Date = { Date() }) -> any DestinationVerifying {
        guard flags.destinationVerification, !pinnedKeys.isEmpty else { return FailClosedDestinationVerifier() }
        return AuthorityDestinationVerifier(fetcher: fetcher, state: DestinationVerificationState(secrets: secrets), pinnedKeys: pinnedKeys, sealKids: sealKids,
                                            environment: environment, clock: clock)
    }
}
