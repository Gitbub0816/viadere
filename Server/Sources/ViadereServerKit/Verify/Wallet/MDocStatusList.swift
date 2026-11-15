import AsyncHTTPClient
@preconcurrency import Crypto
import Foundation
import LZ77
import NIOCore
import ViadereCore
import ViadereServiceSupport
@preconcurrency import X509

// MARK: - The credential's status reference

/// The `status` member of an mdoc Mobile Security Object (ISO/IEC 18013-5, aligned with the IETF Token Status List, draft-ietf-oauth-status-list-21
/// §6.3): `{"status_list": {"idx": uint, "uri": tstr, ? "certificate": bstr}}`. `identifier_list` (the ISO alternative) is recognised but not
/// supported, so a credential that offers only it is treated as "status unavailable" (the fail mode decides). Anything else is a malformed MSO.
enum MDocStatusField: Sendable, Equatable {
    /// The MSO has no `status` member.
    case none
    case statusList(MDocStatusReference)
    /// Only a mechanism Viadere does not implement (`identifier_list`).
    case unsupported
}

struct MDocStatusReference: Sendable, Equatable {
    var index: UInt64
    /// The issuer-signed URI exactly as written in the MSO (the token's `sub` must equal it byte for byte).
    var uri: String
    /// Optional: the certificate the issuer designates to sign the status list (DER).
    var certificate: Data?

    static let maxURIBytes = 2048

    static func parse(_ value: CBORValue?) throws -> MDocStatusField {
        guard let value else { return .none }
        guard let entries = value.mapEntries, !entries.isEmpty,
              entries.allSatisfy({ ["status_list", "identifier_list"].contains($0.key.textString ?? "") }) else { throw MDocFailure.badMobileSecurityObject }
        guard let list = value["status_list"] else { return .unsupported }
        guard let members = list.mapEntries, members.allSatisfy({ ["idx", "uri", "certificate"].contains($0.key.textString ?? "") }),
              let index = list["idx"]?.unsignedValue, let uri = list["uri"]?.textString, (1...maxURIBytes).contains(uri.utf8.count) else {
            throw MDocFailure.badMobileSecurityObject
        }
        var certificate: Data?
        if let raw = list["certificate"] {
            guard let der = raw.byteString, (1...4096).contains(der.count) else { throw MDocFailure.badMobileSecurityObject }
            certificate = der
        }
        return .statusList(MDocStatusReference(index: index, uri: uri, certificate: certificate))
    }
}

// MARK: - The Status List Token (CWT)

/// Why a status list was not accepted. Raw values go to the platform-only audit trail (SECURITY §2.60 F1), never to the business.
enum StatusListFailure: String, Error, Sendable {
    case hostNotAllowed = "status_list_host_not_allowed"
    case blockedDestination = "status_list_blocked_destination"
    case fetchFailed = "status_list_fetch_failed"
    case tooLarge = "status_list_too_large"
    case malformed = "status_list_malformed"
    case wrongType = "status_list_wrong_type"
    case unsupportedAlgorithm = "status_list_unsupported_algorithm"
    case untrustedSigner = "status_list_untrusted_signer"
    case badSignature = "status_list_bad_signature"
    case subjectMismatch = "status_list_subject_mismatch"
    case notYetValid = "status_list_not_yet_valid"
    case expired = "status_list_expired"
    case badCompression = "status_list_bad_compression"
    case indexOutOfRange = "status_list_index_out_of_range"
}

/// A verified status list: the decompressed bytes and the token's freshness claims.
struct VerifiedStatusList: Sendable {
    var bits: Int
    var bytes: [UInt8]
    var issuedAt: Date
    var expiresAt: Date?
    var ttl: TimeInterval?

    /// The status of entry `index` (draft §4.1: entries packed from the least significant bit of each byte). Out of range is a refusal, never 0.
    func status(at index: UInt64) throws -> UInt8 {
        let perByte = UInt64(8 / bits)
        let byteIndex = index / perByte
        guard byteIndex < UInt64(bytes.count) else { throw StatusListFailure.indexOutOfRange }
        let shift = Int(index % perByte) * bits
        let mask = UInt8(truncatingIfNeeded: (1 << bits) - 1)
        return (bytes[Int(byteIndex)] >> shift) & mask
    }
}

/// Verifies a Status List Token in CWT form (draft-ietf-oauth-status-list-21 §5.2) for one credential:
///
/// - `COSE_Sign1` (optionally tagged 18 and/or 61), ES256/ES384/ES512 in the **protected** header (the mdoc algorithm set), protected `typ` (16)
///   exactly `application/statuslist+cwt`;
/// - `x5chain` (33) validated like the credential's issuer: RFC 5280 at `now`, **directly** issued by **the same IACA** that anchored the credential
///   (another trusted issuer's list cannot vouch for this credential), keyUsage `digitalSignature`, not a CA, the IACA's country; the signer is
///   either the certificate the MSO names (`status_list.certificate`, exact bytes) or a document signer of that IACA (EKU `id-mdl-kp-mdlDS`;
///   the draft's own EKU, `id-kp-oauthStatusSigning`, has no assigned OID yet);
/// - claims: `sub` (2) equal to the MSO's `uri`, `iat` (6) required and not in the future, `exp` (4) if present in the future, `ttl` (65534) if present
///   a positive integer, `status_list` (65533) = `{bits: 1|2|4|8, lst: bstr, ? aggregation_uri: tstr}` and nothing else;
/// - `lst` is ZLIB/DEFLATE (RFC 1950/1951) decompressed with an output cap and a checksum check; a truncated stream is refused.
enum StatusListToken {
    static let mediaType = "application/statuslist+cwt"
    /// The largest token accepted over the wire, and the largest decompressed list (32 Mi one-bit entries).
    static let maxTokenBytes = 1 << 20
    static let maxListBytes = 4 << 20
    static let skew: TimeInterval = 300

    static let limits = CBOR.Limits(maxDepth: 8, maxBytes: maxTokenBytes + 1024, maxItems: 256, allowedTags: [18, 61], strictShortestForm: true)

    static func verify(_ token: Data, reference: MDocStatusReference, trust: IACATrustStore, anchor: String, now: Date) async throws -> VerifiedStatusList {
        guard token.count <= maxTokenBytes else { throw StatusListFailure.tooLarge }
        guard var value = try? CBOR.decode(token, limits: limits) else { throw StatusListFailure.malformed }
        if let inner = value.content(taggedWith: 61) { value = inner }
        if let inner = value.content(taggedWith: 18) { value = inner }
        let sign1: COSESign1
        do { sign1 = try COSESign1(value) } catch MDocFailure.unsupportedAlgorithm { throw StatusListFailure.unsupportedAlgorithm } catch { throw StatusListFailure.malformed }
        guard let protected = try? RawCBOR.decode(sign1.protectedBytes) else { throw StatusListFailure.malformed }
        guard protected[16]?.textString == mediaType, sign1.unprotected[16] == nil else { throw StatusListFailure.wrongType }
        // x5chain in exactly one header bucket.
        let header: CBORValue
        switch (protected[33], sign1.unprotected[33]) {
        case (.some, nil): header = protected
        case (nil, .some): header = sign1.unprotected
        default: throw StatusListFailure.untrustedSigner
        }
        let chain: [Certificate]
        do { chain = try MDocVerifier.certificateChain(from: header) } catch { throw StatusListFailure.untrustedSigner }
        let signer: IACATrustStore.ValidatedIssuer
        do { signer = try await trust.validateStatusSigner(chain: chain, now: now, anchor: anchor, designated: reference.certificate) } catch {
            throw StatusListFailure.untrustedSigner
        }
        guard let key = COSEVerificationKey(certificateKey: signer.leaf.publicKey), key.curve == sign1.algorithm.curve else { throw StatusListFailure.unsupportedAlgorithm }
        guard let payload = sign1.payload, sign1.verify(key: key, payload: payload) else { throw StatusListFailure.badSignature }

        guard let claims = try? CBOR.decode(payload, limits: limits), claims.mapEntries != nil else { throw StatusListFailure.malformed }
        guard let subject = claims[2]?.textString else { throw StatusListFailure.malformed }
        guard subject == reference.uri else { throw StatusListFailure.subjectMismatch }
        guard let iat = claims[6]?.unsignedValue, iat <= UInt64(Int64.max / 2) else { throw StatusListFailure.malformed }
        let issuedAt = Date(timeIntervalSince1970: TimeInterval(iat))
        guard issuedAt <= now.addingTimeInterval(skew) else { throw StatusListFailure.notYetValid }
        var expiresAt: Date?
        if let raw = claims[4] {
            guard let exp = raw.unsignedValue, exp <= UInt64(Int64.max / 2) else { throw StatusListFailure.malformed }
            expiresAt = Date(timeIntervalSince1970: TimeInterval(exp))
            guard now < expiresAt! else { throw StatusListFailure.expired }
        }
        var ttl: TimeInterval?
        if let raw = claims[65534] {
            guard let seconds = raw.unsignedValue, seconds > 0, seconds <= 10 * 365 * 86_400 else { throw StatusListFailure.malformed }
            ttl = TimeInterval(seconds)
        }
        guard let list = claims[65533], let members = list.mapEntries,
              members.allSatisfy({ ["bits", "lst", "aggregation_uri"].contains($0.key.textString ?? "") }),
              let bitsValue = list["bits"]?.unsignedValue, [1, 2, 4, 8].contains(bitsValue), let compressed = list["lst"]?.byteString, !compressed.isEmpty
        else { throw StatusListFailure.malformed }
        if let aggregation = list["aggregation_uri"], aggregation.textString == nil { throw StatusListFailure.malformed }
        let bytes = try inflate(compressed, limit: maxListBytes)
        guard !bytes.isEmpty else { throw StatusListFailure.malformed }
        return VerifiedStatusList(bits: Int(bitsValue), bytes: bytes, issuedAt: issuedAt, expiresAt: expiresAt, ttl: ttl)
    }

    /// ZLIB (RFC 1950) inflate with an output cap: input is fed in small slices and the output drained after each, so a decompression bomb is stopped
    /// at `limit` bytes, never materialised. The Adler-32 trailer is checked by the inflater; a stream that does not end is refused.
    static func inflate(_ data: Data, limit: Int) throws -> [UInt8] {
        let bytes = [UInt8](data)
        let full = try run(bytes[...], limit: limit)
        guard full.finished, full.consumedAll else { throw StatusListFailure.badCompression }
        // Strict: no compressed bytes after the end of the stream. The inflater cannot say how much of the last slice it used, so the input
        // without its last byte must **not** be a complete stream (it is not when the Adler-32 trailer is the final byte).
        if bytes.count > 1, (try? run(bytes.dropLast(), limit: limit))?.finished == true { throw StatusListFailure.badCompression }
        return full.output
    }

    private static func run(_ bytes: ArraySlice<UInt8>, limit: Int) throws -> (output: [UInt8], finished: Bool, consumedAll: Bool) {
        var inflator = LZ77.Inflator(format: .zlib)
        var out: [UInt8] = []
        var offset = bytes.startIndex
        while offset < bytes.endIndex {
            let end = min(offset + 256, bytes.endIndex)
            let more: Void?
            do { more = try inflator.push(bytes[offset..<end]) } catch { throw StatusListFailure.badCompression }
            out += inflator.pull()
            guard out.count <= limit else { throw StatusListFailure.tooLarge }
            offset = end
            if more == nil { return (out, true, offset == bytes.endIndex) }
        }
        return (out, false, true)
    }
}

// MARK: - Fetching

/// Fetches a status list token. Replaceable in tests; the network implementation is `GuardedStatusListFetcher`.
protocol StatusListFetcher: Sendable {
    func fetch(_ url: URL) async throws -> Data
}

/// Which hosts may serve the status lists of which issuer: `WALLET_STATUS_LIST_HOSTS` binds each host to the SHA-256 of one IACA, so a credential's
/// `uri` (issuer-signed, but chosen by the issuer) can only make the server call a host the operator listed for **that** issuer.
struct StatusListHostPolicy: Sendable, Equatable {
    var hostsByAnchor: [String: Set<String>]

    /// `https`, port 443 or none, no userinfo, no fragment, at most 2048 bytes, and the host listed for this anchor.
    func allows(_ uri: String, anchor: String) -> URL? {
        guard uri.utf8.count <= MDocStatusReference.maxURIBytes, let url = URL(string: uri), url.scheme == "https", let host = url.host?.lowercased(),
              url.user == nil, url.password == nil, url.fragment == nil, url.port == nil || url.port == 443,
              WebhookURLPolicy.validate(url, allowInsecure: false), hostsByAnchor[anchor]?.contains(host) == true else { return nil }
        return url
    }

    /// `<64 hex IACA SHA-256>:<host>` entries, comma separated.
    static func parse(_ raw: String) throws -> StatusListHostPolicy {
        var map: [String: Set<String>] = [:]
        for entry in raw.split(separator: ",").map({ $0.trimmingCharacters(in: .whitespaces) }) where !entry.isEmpty {
            let parts = entry.split(separator: ":", maxSplits: 1).map(String.init)
            guard parts.count == 2 else { throw ServerConfigError.invalid("WALLET_STATUS_LIST_HOSTS (<IACA sha256>:<host>, comma separated)") }
            let fingerprint = parts[0].lowercased()
            let host = parts[1].lowercased()
            guard fingerprint.count == 64, fingerprint.allSatisfy(\.isHexDigit), DomainControl.isValidHostname(host), !WebhookURLPolicy.isIPLiteral(host),
                  !DomainControl.reservedSuffixes.contains(where: { ("." + host).hasSuffix($0) }) else {
                throw ServerConfigError.invalid("WALLET_STATUS_LIST_HOSTS (<IACA sha256>:<host>, comma separated; a public DNS host name)")
            }
            map[fingerprint, default: []].insert(host)
        }
        return StatusListHostPolicy(hostsByAnchor: map)
    }
}

/// The network fetcher: the same SSRF defences as webhooks and the domain check. The identity-endpoint guard first, then **every** resolved address
/// must be public, and the connection is pinned to the vetted address (no second resolution). `GET` with `Accept: application/statuslist+cwt`, no
/// redirects (the draft allows following them; this client does not, so the listed host is the only one ever contacted), short timeouts, `200` with
/// that media type only, the body capped at `StatusListToken.maxTokenBytes`.
struct GuardedStatusListFetcher: StatusListFetcher {
    let destinationGuard: OutboundDestinationGuard
    /// Injectable for tests (DNS rebinding to an internal address without a network).
    var resolve: @Sendable (_ host: String, _ port: Int) async throws -> [SocketAddress] = { host, port in try await HostResolver.resolve(host: host, port: port) }

    func vet(_ url: URL) async throws -> String {
        guard WebhookURLPolicy.validate(url, allowInsecure: false), let host = url.host else { throw StatusListFailure.blockedDestination }
        do { try await destinationGuard.check(url) } catch { throw StatusListFailure.blockedDestination }
        let addresses: [SocketAddress]
        do { addresses = try await resolve(host, url.port ?? 443) } catch { throw StatusListFailure.fetchFailed }
        guard !addresses.isEmpty, addresses.allSatisfy(WebhookURLPolicy.isPublic), !addresses.contains(where: destinationGuard.isRefused),
              let pinned = addresses.first?.ipAddress else { throw StatusListFailure.blockedDestination }
        return pinned
    }

    func fetch(_ url: URL) async throws -> Data {
        let pinned = try await vet(url)
        guard let host = url.host else { throw StatusListFailure.blockedDestination }
        var configuration = HTTPClient.Configuration()
        configuration.redirectConfiguration = .disallow
        configuration.timeout = .init(connect: .seconds(5), read: .seconds(10))
        configuration.dnsOverride = [host: pinned]
        let client = HTTPClient(eventLoopGroupProvider: .singleton, configuration: configuration)
        do {
            var request = HTTPClientRequest(url: url.absoluteString)
            request.method = .GET
            request.headers.add(name: "Accept", value: StatusListToken.mediaType)
            request.headers.add(name: "User-Agent", value: "Viadere-StatusList/1")
            let response = try await client.execute(request, timeout: .seconds(15))
            let type = response.headers.first(name: "Content-Type")?.split(separator: ";").first.map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
            guard response.status == .ok, type == StatusListToken.mediaType else {
                try? await client.shutdown()
                throw StatusListFailure.fetchFailed
            }
            var body = try await response.body.collect(upTo: StatusListToken.maxTokenBytes)
            try? await client.shutdown()
            return Data(body.readBytes(length: body.readableBytes) ?? [])
        } catch let failure as StatusListFailure {
            throw failure
        } catch {
            try? await client.shutdown()
            throw StatusListFailure.fetchFailed
        }
    }
}

// MARK: - Cache

/// Verified lists, per (issuer anchor, uri). An entry is fresh until the earliest of: fetch time + `ttl` (when the token has one), fetch time + the
/// configured cap (`WALLET_STATUS_LIST_MAX_CACHE_SECONDS`, at most one hour), and the token's `exp`. A stale entry is never served: it is fetched again,
/// and if that fails the fail mode applies.
final class StatusListCache: @unchecked Sendable {
    private let lock = NSLock()
    private var entries: [String: (list: VerifiedStatusList, freshUntil: Date)] = [:]
    static let maxEntries = 256

    func fresh(_ key: String, now: Date) -> VerifiedStatusList? {
        lock.withLock {
            guard let entry = entries[key] else { return nil }
            guard now < entry.freshUntil else { entries[key] = nil; return nil }
            return entry.list
        }
    }

    func store(_ key: String, _ list: VerifiedStatusList, fetchedAt: Date, cap: TimeInterval) {
        var until = fetchedAt.addingTimeInterval(min(list.ttl ?? cap, cap))
        if let exp = list.expiresAt { until = min(until, exp) }
        lock.withLock {
            if entries.count >= Self.maxEntries { entries.removeAll(keepingCapacity: true) }
            entries[key] = (list, until)
        }
    }
}

// MARK: - The check and the fail mode

/// The result of checking one credential's status.
enum MDocStatusOutcome: Sendable, Equatable {
    /// The credential carries no status reference.
    case notPresent
    case valid
    /// The issuer says the credential is not valid (`revoked` = 0x01, `suspended` = 0x02, `other` = any other non-zero value).
    case revoked, suspended, otherStatus
    /// A list exists but could not be obtained or trusted (reason for the platform audit).
    case unavailable(String)
}

struct MDocStatusChecker: Sendable {
    let trust: IACATrustStore
    let hosts: StatusListHostPolicy
    let fetcher: any StatusListFetcher
    let cache: StatusListCache
    let maxCache: TimeInterval

    func check(_ field: MDocStatusField, anchor: String, now: Date) async -> MDocStatusOutcome {
        let reference: MDocStatusReference
        switch field {
        case .none: return .notPresent
        case .unsupported: return .unavailable("status_mechanism_unsupported")
        case .statusList(let value): reference = value
        }
        guard let url = hosts.allows(reference.uri, anchor: anchor) else { return .unavailable(StatusListFailure.hostNotAllowed.rawValue) }
        let key = anchor + "|" + reference.uri
        let list: VerifiedStatusList
        if let cached = cache.fresh(key, now: now) {
            list = cached
        } else {
            do {
                let token = try await fetcher.fetch(url)
                list = try await StatusListToken.verify(token, reference: reference, trust: trust, anchor: anchor, now: now)
                cache.store(key, list, fetchedAt: now, cap: maxCache)
            } catch let failure as StatusListFailure {
                return .unavailable(failure.rawValue)
            } catch {
                return .unavailable(StatusListFailure.fetchFailed.rawValue)
            }
        }
        // An index beyond the list is the issuer's error or a forged reference: never read as "valid".
        guard let status = try? list.status(at: reference.index) else { return .unavailable(StatusListFailure.indexOutOfRange.rawValue) }
        switch status {
        case 0: return .valid
        case 1: return .revoked
        case 2: return .suspended
        default: return .otherStatus
        }
    }
}

extension VerifyRuntime {
    /// The status check and the fail mode for one verified Wallet presentation (every Wallet path: Verify requests and profile verification).
    func walletStatusDecision(_ verification: MDocVerification, trust: IACATrustStore, sensitivity: Sensitivity, settings: VerifySettings,
                              now: Date) async -> WalletStatusPolicy.Decision {
        let checker = MDocStatusChecker(trust: trust, hosts: settings.walletStatusHosts, fetcher: statusFetcher, cache: statusCache, maxCache: settings.walletStatusMaxCache)
        let outcome = await checker.check(verification.status, anchor: verification.anchorFingerprint, now: now)
        return WalletStatusPolicy.decide(outcome, sensitivity: sensitivity, failMode: settings.walletStatusFailMode, requireStatus: settings.walletStatusRequired)
    }
}

/// What a status outcome means for one verification (SECURITY §2.60 "Wallet credential status"). Revoked, suspended and any other non-zero status are
/// always refused. A list that cannot be obtained or trusted is refused for capabilities of `high` or `critical` sensitivity (Core
/// `CapabilityDefinition.sensitivity`, the assurance policy; every Verify capability today) and, with `WALLET_STATUS_FAIL_MODE=all`, for every
/// capability. A credential without a reference is accepted as `not_checked` unless `WALLET_STATUS_REQUIRED=true`. Both settings only make it stricter.
enum WalletStatusPolicy {
    enum FailMode: String, Sendable { case highAssurance = "high_assurance", all }

    struct Decision: Sendable, Equatable {
        var accepted: Bool
        var revocation: RevocationState
        /// The platform-audit reason when refused.
        var reason: String?
    }

    static func decide(_ outcome: MDocStatusOutcome, sensitivity: Sensitivity, failMode: FailMode, requireStatus: Bool) -> Decision {
        switch outcome {
        case .valid: return Decision(accepted: true, revocation: .active)
        case .revoked: return Decision(accepted: false, revocation: .revoked, reason: "credential_revoked")
        case .suspended: return Decision(accepted: false, revocation: .revoked, reason: "credential_suspended")
        case .otherStatus: return Decision(accepted: false, revocation: .revoked, reason: "credential_status_invalid")
        case .notPresent:
            return requireStatus ? Decision(accepted: false, revocation: .notChecked, reason: "status_reference_missing") : Decision(accepted: true, revocation: .notChecked)
        case .unavailable(let why):
            let closed = failMode == .all || sensitivity >= .high
            return closed ? Decision(accepted: false, revocation: .notChecked, reason: "status_unavailable:" + why) : Decision(accepted: true, revocation: .notChecked)
        }
    }
}
