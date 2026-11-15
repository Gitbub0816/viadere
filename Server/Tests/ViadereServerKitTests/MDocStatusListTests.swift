@preconcurrency import Crypto
import Fluent
import Foundation
import NIOCore
import ViadereCore
import ViadereServiceSupport
import XCTest
@preconcurrency import X509
@testable import ViadereServerKit

/// Synthetic Status List Tokens (draft-ietf-oauth-status-list-21 §5.2, CWT form) signed by the test PKI's document signer.
enum TestStatusList {
    static let host = "status.dmv-issuer.us"
    static let uri = "https://status.dmv-issuer.us/lists/7"

    /// Packs statuses LSB first (draft §4.1).
    static func pack(_ statuses: [UInt8], bits: Int) -> [UInt8] {
        let perByte = 8 / bits
        var out = [UInt8](repeating: 0, count: (statuses.count + perByte - 1) / perByte)
        for (i, value) in statuses.enumerated() { out[i / perByte] |= value << ((i % perByte) * bits) }
        return out
    }

    static func adler32(_ data: [UInt8]) -> UInt32 {
        var a: UInt32 = 1, b: UInt32 = 0
        for byte in data { a = (a + UInt32(byte)) % 65521; b = (b + a) % 65521 }
        return b << 16 | a
    }

    /// ZLIB with stored (uncompressed) DEFLATE blocks: any content, exactly.
    static func zlibStored(_ data: [UInt8]) -> Data {
        var out: [UInt8] = [0x78, 0x01]
        var chunks = stride(from: 0, to: max(data.count, 1), by: 65_535).map { Array(data[$0..<min($0 + 65_535, data.count)]) }
        if chunks.isEmpty { chunks = [[]] }
        for (i, chunk) in chunks.enumerated() {
            out.append(i == chunks.count - 1 ? 1 : 0)
            let len = UInt16(chunk.count)
            out += [UInt8(len & 0xFF), UInt8(len >> 8), UInt8(~len & 0xFF), UInt8(~len >> 8)]
            out += chunk
        }
        let check = adler32(data)
        out += [UInt8(check >> 24), UInt8((check >> 16) & 0xFF), UInt8((check >> 8) & 0xFF), UInt8(check & 0xFF)]
        return Data(out)
    }

    /// A decompression bomb: one fixed-Huffman block of a zero literal and `matches` copies of 258 bytes at distance 1 (about 13 bits per 258 bytes).
    static func zeroBomb(matches: Int) -> Data {
        var bytes: [UInt8] = []
        var acc: UInt32 = 0
        var n = 0
        func bit(_ value: UInt32) {
            acc |= (value & 1) << n
            n += 1
            if n == 8 { bytes.append(UInt8(acc)); acc = 0; n = 0 }
        }
        func value(_ v: UInt32, _ count: Int) { for i in 0..<count { bit(v >> i) } }
        func huffman(_ code: UInt32, _ length: Int) { for i in stride(from: length - 1, through: 0, by: -1) { bit(code >> i) } }
        value(1, 1); value(1, 2)                 // BFINAL, BTYPE = fixed Huffman
        huffman(0x30, 8)                         // literal 0
        for _ in 0..<matches { huffman(0xC5, 8); huffman(0, 5) } // length 258 (code 285), distance 1 (code 0)
        huffman(0, 7)                            // end of block
        if n > 0 { bytes.append(UInt8(acc)) }
        let length = UInt32(1 + 258 * matches)
        let check = (length % 65521) << 16 | 1
        return Data([0x78, 0x01] + bytes + [UInt8(check >> 24), UInt8((check >> 16) & 0xFF), UInt8((check >> 8) & 0xFF), UInt8(check & 0xFF)])
    }

    struct Options {
        var statuses: [UInt8] = [0, 0, 0, 0]
        var bits = 1
        var issuedAt: Date?
        var expiresAt: Date??
        var ttl: UInt64? = 3600
        var typ: CBORValue? = .text("application/statuslist+cwt")
        var lst: Data?
        var listExtra: [(String, CBORValue)] = []
        var sub: String?
        var bitsValue: CBORValue?
        var tags = true
        var omitSub = false
    }

    static func token(pki: TestMDocPKI, signer: P256.Signing.PrivateKey? = nil, chain: [Data]? = nil, _ options: Options = Options()) -> Data {
        let now = pki.now
        var protected: [(Int64, CBORValue)] = [(1, .negative(-7))]
        if let typ = options.typ { protected.append((16, typ)) }
        let unprotected = CBORValue.intMap([(33, .array((chain ?? pki.chainDER).map { .bytes($0) }))])
        var list: [(String, CBORValue)] = [("bits", options.bitsValue ?? .unsigned(UInt64(options.bits))),
                                           ("lst", .bytes(options.lst ?? zlibStored(pack(options.statuses, bits: options.bits))))]
        list += options.listExtra
        var claims: [(Int64, CBORValue)] = []
        if !options.omitSub { claims.append((2, .text(options.sub ?? uri))) }
        claims.append((6, .unsigned(UInt64((options.issuedAt ?? now.addingTimeInterval(-60)).timeIntervalSince1970))))
        let exp = options.expiresAt ?? .some(now.addingTimeInterval(86_400))
        if let exp { claims.append((4, .unsigned(UInt64(exp.timeIntervalSince1970)))) }
        if let ttl = options.ttl { claims.append((65534, .unsigned(ttl))) }
        claims.append((65533, .textMap(list)))
        let payload = CBOR.encode(.intMap(claims))
        let protectedBytes = CBOR.encode(.intMap(protected))
        let structure = CBOR.encode(.array([.text("Signature1"), .bytes(protectedBytes), .bytes(Data()), .bytes(payload)]))
        let signature = try! (signer ?? pki.dsKey).signature(for: structure).rawRepresentation
        let sign1 = CBORValue.array([.bytes(protectedBytes), unprotected, .bytes(payload), .bytes(signature)])
        return CBOR.encode(options.tags ? .tagged(61, .tagged(18, sign1)) : sign1)
    }

    static func reference(index: UInt64, uri: String = uri) -> CBORValue {
        .textMap([("status_list", .textMap([("idx", .unsigned(index)), ("uri", .text(uri))]))])
    }
}

final class FakeStatusListFetcher: StatusListFetcher, @unchecked Sendable {
    private let lock = NSLock()
    private var answer: Result<Data, StatusListFailure>
    private var urls: [URL] = []
    init(_ token: Data) { answer = .success(token) }
    var fetched: [URL] { lock.withLock { urls } }
    func set(_ token: Data) { lock.withLock { answer = .success(token) } }
    func fail() { lock.withLock { answer = .failure(.fetchFailed) } }
    func fetch(_ url: URL) async throws -> Data {
        try lock.withLock {
            urls.append(url)
            return try answer.get()
        }
    }
}

/// G24: Wallet (mdoc) credential status through the issuer's Token Status List (SECURITY §2.60 "Wallet credential status").
final class MDocStatusListTests: XCTestCase {
    let pki = TestMDocPKI()
    var now: Date { pki.now }

    func checker(_ fetcher: any StatusListFetcher, trust: IACATrustStore? = nil, hosts: [String: Set<String>]? = nil, cap: TimeInterval = 3600,
                 cache: StatusListCache = StatusListCache()) -> MDocStatusChecker {
        MDocStatusChecker(trust: trust ?? pki.trustStore(), hosts: StatusListHostPolicy(hostsByAnchor: hosts ?? [pki.fingerprint: [TestStatusList.host]]),
                          fetcher: fetcher, cache: cache, maxCache: cap)
    }

    func check(_ token: Data, index: UInt64 = 1, uri: String = TestStatusList.uri, at: Date? = nil, trust: IACATrustStore? = nil) async -> MDocStatusOutcome {
        await checker(FakeStatusListFetcher(token), trust: trust).check(.statusList(MDocStatusReference(index: index, uri: uri)), anchor: pki.fingerprint, now: at ?? now)
    }

    func decide(_ outcome: MDocStatusOutcome, _ sensitivity: Sensitivity = .high, mode: WalletStatusPolicy.FailMode = .highAssurance, require: Bool = false) -> WalletStatusPolicy.Decision {
        WalletStatusPolicy.decide(outcome, sensitivity: sensitivity, failMode: mode, requireStatus: require)
    }

    // MARK: Valid, revoked, suspended

    func testAValidEntryIsAcceptedAndRecordedActive() async {
        let outcome = await check(TestStatusList.token(pki: pki, .init(statuses: [1, 0, 1, 1])))
        XCTAssertEqual(outcome, .valid)
        XCTAssertEqual(decide(outcome), .init(accepted: true, revocation: .active))
    }

    func testARevokedCredentialIsRefused() async {
        let outcome = await check(TestStatusList.token(pki: pki, .init(statuses: [0, 1, 0, 0])))
        XCTAssertEqual(outcome, .revoked)
        for sensitivity in [Sensitivity.low, .standard, .high, .critical] {
            XCTAssertFalse(decide(outcome, sensitivity).accepted, "revoked is refused whatever the capability")
        }
        XCTAssertEqual(decide(outcome).reason, "credential_revoked")
    }

    func testSuspendedAndOtherNonZeroStatusesAreRefused() async {
        let suspended = await check(TestStatusList.token(pki: pki, .init(statuses: [0, 2, 0, 0], bits: 2)))
        XCTAssertEqual(suspended, .suspended)
        XCTAssertEqual(decide(suspended, .low).reason, "credential_suspended")
        let other = await check(TestStatusList.token(pki: pki, .init(statuses: [0, 3, 0, 0], bits: 2)))
        XCTAssertEqual(other, .otherStatus)
        XCTAssertFalse(decide(other, .low).accepted)
        let wide = await check(TestStatusList.token(pki: pki, .init(statuses: [0, 0x80], bits: 8)))
        XCTAssertEqual(wide, .otherStatus)
    }

    /// The draft's own example (§4.1): `lst` "eNrbuRgAAhcBXQ" is the byte array [0xB9, 0xA3], one bit per entry, least significant bit first.
    func testTheDraftExampleListDecodes() throws {
        let compressed = try XCTUnwrap(Base64URL.decode("eNrbuRgAAhcBXQ"))
        let bytes = try StatusListToken.inflate(compressed, limit: 1024)
        XCTAssertEqual(bytes, [0xB9, 0xA3])
        let list = VerifiedStatusList(bits: 1, bytes: bytes, issuedAt: now, expiresAt: nil, ttl: nil)
        XCTAssertEqual(try (0..<16).map { try list.status(at: $0) }, [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1])
    }

    // MARK: Signature and signer

    func testASignatureByAnUntrustedKeyIsRefused() async {
        // Another IACA's document signer (unknown to the trust store).
        let stranger = TestMDocPKI(now: now, name: "Stranger IACA")
        let foreign = await check(TestStatusList.token(pki: stranger))
        XCTAssertEqual(foreign, .unavailable(StatusListFailure.untrustedSigner.rawValue))
        XCTAssertFalse(decide(foreign).accepted)
        // A trusted certificate, a different key: the signature does not verify.
        let forged = await check(TestStatusList.token(pki: pki, signer: P256.Signing.PrivateKey()))
        XCTAssertEqual(forged, .unavailable(StatusListFailure.badSignature.rawValue))
        // Another issuer the trust store does trust cannot vouch for this credential: the list must chain to the credential's own IACA.
        let both = IACATrustStore(entries: pki.trustStore().entries + stranger.trustStore().entries)
        let crossIssuer = await checker(FakeStatusListFetcher(TestStatusList.token(pki: stranger)), trust: both, hosts: [pki.fingerprint: [TestStatusList.host]])
            .check(.statusList(MDocStatusReference(index: 1, uri: TestStatusList.uri)), anchor: pki.fingerprint, now: now)
        XCTAssertEqual(crossIssuer, .unavailable(StatusListFailure.untrustedSigner.rawValue))
        // A signer that is not a document signer of the IACA (no mdoc EKU) and not designated by the MSO.
        var options = TestMDocPKI.Options()
        options.dsEKU = false
        let noEKU = TestMDocPKI(now: now, options: options)
        let undelegated = await checker(FakeStatusListFetcher(TestStatusList.token(pki: noEKU)), trust: noEKU.trustStore(), hosts: [noEKU.fingerprint: [TestStatusList.host]])
            .check(.statusList(MDocStatusReference(index: 1, uri: TestStatusList.uri)), anchor: noEKU.fingerprint, now: now)
        XCTAssertEqual(undelegated, .unavailable(StatusListFailure.untrustedSigner.rawValue))
        // The same signer, designated by the issuer-signed MSO (`status_list.certificate`), is accepted; a different designated certificate is not.
        let designated = await checker(FakeStatusListFetcher(TestStatusList.token(pki: noEKU)), trust: noEKU.trustStore(), hosts: [noEKU.fingerprint: [TestStatusList.host]])
            .check(.statusList(MDocStatusReference(index: 1, uri: TestStatusList.uri, certificate: noEKU.dsDER)), anchor: noEKU.fingerprint, now: now)
        XCTAssertEqual(designated, .valid)
        let otherDesignated = await checker(FakeStatusListFetcher(TestStatusList.token(pki: pki)))
            .check(.statusList(MDocStatusReference(index: 1, uri: TestStatusList.uri, certificate: noEKU.dsDER)), anchor: pki.fingerprint, now: now)
        XCTAssertEqual(otherDesignated, .unavailable(StatusListFailure.untrustedSigner.rawValue))
    }

    // MARK: Where the list may come from

    func testAListFromAnotherHostIsNeverFetched() async {
        let fetcher = FakeStatusListFetcher(TestStatusList.token(pki: pki, .init(sub: "https://evil.example.net/l")))
        let c = checker(fetcher)
        for uri in ["https://evil.example.net/l", "http://status.dmv-issuer.us/lists/7", "https://status.dmv-issuer.us:8443/lists/7",
                    "https://user@status.dmv-issuer.us/lists/7", "https://status.dmv-issuer.us/lists/7#x", "https://127.0.0.1/lists/7",
                    "https://status.dmv-issuer.us.evil.net/l", "ftp://status.dmv-issuer.us/l"] {
            let outcome = await c.check(.statusList(MDocStatusReference(index: 1, uri: uri)), anchor: pki.fingerprint, now: now)
            XCTAssertEqual(outcome, .unavailable(StatusListFailure.hostNotAllowed.rawValue), uri)
        }
        // The right host, but listed for another issuer only.
        let otherIssuer = await checker(fetcher, hosts: [String(repeating: "a", count: 64): [TestStatusList.host]])
            .check(.statusList(MDocStatusReference(index: 1, uri: TestStatusList.uri)), anchor: pki.fingerprint, now: now)
        XCTAssertEqual(otherIssuer, .unavailable(StatusListFailure.hostNotAllowed.rawValue))
        XCTAssertTrue(fetcher.fetched.isEmpty, "nothing was fetched")
    }

    /// A listed host whose DNS points inside (loopback, private, link-local metadata, CGNAT, IPv4-mapped) is refused before any connection.
    func testAListedHostThatResolvesToAnInternalAddressIsRefusedByTheGuard() async throws {
        let url = try XCTUnwrap(URL(string: TestStatusList.uri))
        /// The guard and the fetcher see the same (scripted) DNS answers.
        func fetcherResolving(_ addresses: [String]) -> GuardedStatusListFetcher {
            let resolve: @Sendable (String, Int) async throws -> [SocketAddress] = { _, port in try addresses.map { try SocketAddress(ipAddress: $0, port: port) } }
            var fetcher = GuardedStatusListFetcher(destinationGuard: OutboundDestinationGuard(identityEndpoint: nil, resolve: resolve))
            fetcher.resolve = resolve
            return fetcher
        }
        for address in ["127.0.0.1", "10.1.2.3", "192.168.1.10", "172.16.0.5", "169.254.169.254", "100.64.0.1", "::1", "::ffff:10.0.0.1", "fd00::1"] {
            let fetcher = fetcherResolving([address])
            do {
                _ = try await fetcher.fetch(url)
                XCTFail("\(address) must be refused")
            } catch let failure as StatusListFailure {
                XCTAssertEqual(failure, .blockedDestination, address)
            }
        }
        // One public and one internal answer (rebinding): refused.
        let mixed = fetcherResolving(["93.184.215.14", "10.0.0.1"])
        do { _ = try await mixed.vet(url); XCTFail("mixed answers must be refused") } catch let failure as StatusListFailure { XCTAssertEqual(failure, .blockedDestination) }
        // The managed-identity endpoint's host is refused by the guard itself, whatever it resolves to.
        let identity = GuardedStatusListFetcher(destinationGuard: OutboundDestinationGuard(identityEndpoint: "http://\(TestStatusList.host):42356/msi/token"))
        do { _ = try await identity.vet(url); XCTFail("the identity endpoint host must be refused") } catch let failure as StatusListFailure { XCTAssertEqual(failure, .blockedDestination) }
        // A public answer passes the vetting (and is the pinned address).
        let good = fetcherResolving(["93.184.215.14"])
        let pinned = try await good.vet(url)
        XCTAssertEqual(pinned, "93.184.215.14")
        // Plain http never leaves.
        do { _ = try await good.vet(try XCTUnwrap(URL(string: "http://status.dmv-issuer.us/l"))); XCTFail() } catch let failure as StatusListFailure { XCTAssertEqual(failure, .blockedDestination) }
    }

    // MARK: Index, cache, failures

    func testAnIndexOutOfRangeIsRefused() async throws {
        let token = TestStatusList.token(pki: pki, .init(statuses: [0, 0, 0, 0]))  // one byte: indices 0-7
        try await eq(await check(token, index: 7), .valid)
        let outside = await check(token, index: 8)
        XCTAssertEqual(outside, .unavailable(StatusListFailure.indexOutOfRange.rawValue))
        XCTAssertFalse(decide(outside).accepted)
        try await eq(await check(token, index: UInt64.max), .unavailable(StatusListFailure.indexOutOfRange.rawValue))
    }

    func testAStaleCacheBeyondTheCapIsFetchedAgain() async throws {
        let fetcher = FakeStatusListFetcher(TestStatusList.token(pki: pki, .init(ttl: 86_400)))
        let cache = StatusListCache()
        let c = checker(fetcher, cap: 3600, cache: cache)
        let reference = MDocStatusField.statusList(MDocStatusReference(index: 1, uri: TestStatusList.uri))
        try await eq(await c.check(reference, anchor: pki.fingerprint, now: now), .valid)
        try await eq(await c.check(reference, anchor: pki.fingerprint, now: now.addingTimeInterval(1800)), .valid)
        XCTAssertEqual(fetcher.fetched.count, 1, "fresh within the cap")
        // The issuer revokes; past the one-hour cap the server fetches again even though the token's own ttl said a day.
        fetcher.set(TestStatusList.token(pki: pki, .init(statuses: [0, 1, 0, 0], issuedAt: now.addingTimeInterval(3000), ttl: 86_400)))
        try await eq(await c.check(reference, anchor: pki.fingerprint, now: now.addingTimeInterval(3601)), .revoked)
        XCTAssertEqual(fetcher.fetched.count, 2)
        // A shorter ttl wins over the cap.
        let short = FakeStatusListFetcher(TestStatusList.token(pki: pki, .init(ttl: 300)))
        let s = checker(short, cap: 3600)
        _ = await s.check(reference, anchor: pki.fingerprint, now: now)
        _ = await s.check(reference, anchor: pki.fingerprint, now: now.addingTimeInterval(299))
        _ = await s.check(reference, anchor: pki.fingerprint, now: now.addingTimeInterval(301))
        XCTAssertEqual(short.fetched.count, 2)
        // A stale entry is never served when the refetch fails: the fail mode applies.
        fetcher.fail()
        let failed = await c.check(reference, anchor: pki.fingerprint, now: now.addingTimeInterval(3601 + 3601))
        XCTAssertEqual(failed, .unavailable(StatusListFailure.fetchFailed.rawValue))
    }

    /// Fail mode (SECURITY §2.60): closed for high-assurance capabilities (every Verify capability today), configurable only toward stricter.
    func testAFetchFailureFollowsTheDocumentedFailMode() async {
        let fetcher = FakeStatusListFetcher(Data())
        fetcher.fail()
        let outcome = await checker(fetcher).check(.statusList(MDocStatusReference(index: 1, uri: TestStatusList.uri)), anchor: pki.fingerprint, now: now)
        XCTAssertEqual(outcome, .unavailable(StatusListFailure.fetchFailed.rawValue))
        for capability in [Capability.ageMinimum, .identityName, .identityAddress, .identityVerified] {
            let sensitivity = capability.definition?.sensitivity ?? .critical
            XCTAssertGreaterThanOrEqual(sensitivity, .high, "\(capability)")
            XCTAssertFalse(decide(outcome, sensitivity).accepted, "\(capability) fails closed")
        }
        XCTAssertEqual(decide(outcome, .high).reason, "status_unavailable:status_list_fetch_failed")
        // Below high: accepted but recorded as not checked; `all` refuses that too.
        XCTAssertEqual(decide(outcome, .standard), .init(accepted: true, revocation: .notChecked))
        XCTAssertFalse(decide(outcome, .low, mode: .all).accepted)
        // An unsupported mechanism is "unavailable", never "valid".
        let unsupported = await checker(fetcher).check(.unsupported, anchor: pki.fingerprint, now: now)
        XCTAssertFalse(decide(unsupported).accepted)
        // No reference at all: accepted as not checked, unless WALLET_STATUS_REQUIRED.
        XCTAssertEqual(decide(.notPresent), .init(accepted: true, revocation: .notChecked))
        XCTAssertFalse(decide(.notPresent, require: true).accepted)
    }

    // MARK: Strict decoding

    func testMalformedOrOversizedListsAreRefused() async throws {
        func expect(_ options: TestStatusList.Options, _ failure: StatusListFailure, _ label: String, file: StaticString = #filePath, line: UInt = #line) async {
            let outcome = await check(TestStatusList.token(pki: pki, options))
            XCTAssertEqual(outcome, .unavailable(failure.rawValue), label, file: file, line: line)
        }
        var o = TestStatusList.Options()
        o.typ = .text("application/statuslist+jwt"); await expect(o, .wrongType, "jwt typ")
        o = .init(); o.typ = nil; await expect(o, .wrongType, "no typ")
        o = .init(); o.sub = "https://status.dmv-issuer.us/lists/8"; await expect(o, .subjectMismatch, "sub of another list")
        o = .init(); o.omitSub = true; await expect(o, .malformed, "no sub")
        o = .init(); o.bitsValue = .unsigned(3); await expect(o, .malformed, "bits 3")
        o = .init(); o.listExtra = [("extra", .bool(true))]; await expect(o, .malformed, "unknown status_list member")
        o = .init(); o.lst = Data([1, 2, 3, 4, 5]); await expect(o, .badCompression, "not zlib")
        o = .init(); o.lst = TestStatusList.zlibStored([0, 0, 0, 0]).dropLast(3); await expect(o, .badCompression, "truncated")
        o = .init(); o.lst = TestStatusList.zlibStored([0, 0]) + Data([0, 0]); await expect(o, .badCompression, "trailing bytes")
        o = .init(); var badCheck = [UInt8](TestStatusList.zlibStored([0, 0])); badCheck[badCheck.count - 1] ^= 1; o.lst = Data(badCheck); await expect(o, .badCompression, "checksum")
        o = .init(); o.lst = TestStatusList.zeroBomb(matches: 20_000); await expect(o, .tooLarge, "decompression bomb (5 MiB of zeros)")
        o = .init(); o.expiresAt = .some(now.addingTimeInterval(-1)); await expect(o, .expired, "expired")
        o = .init(); o.issuedAt = now.addingTimeInterval(3600); await expect(o, .notYetValid, "issued in the future")
        o = .init(); o.ttl = 0; await expect(o, .malformed, "ttl 0")
        // Untagged is accepted; an oversized token is refused before parsing.
        o = .init(); o.tags = false
        try await eq(await check(TestStatusList.token(pki: pki, o)), .valid)
        try await eq(await check(Data(repeating: 0, count: StatusListToken.maxTokenBytes + 1)), .unavailable(StatusListFailure.tooLarge.rawValue))
        try await eq(await check(Data([0xFF, 0x00])), .unavailable(StatusListFailure.malformed.rawValue))
        // The bomb itself inflates to exactly what it claims under a large enough limit (the encoder is right; the cap is what refused it).
        XCTAssertEqual(try StatusListToken.inflate(TestStatusList.zeroBomb(matches: 100), limit: 1 << 20).count, 1 + 258 * 100)
    }

    /// A malformed status reference in the issuer-signed MSO refuses the presentation itself.
    func testAMalformedStatusReferenceRefusesTheMSO() throws {
        for bad: CBORValue in [.text("x"), .map([]), .textMap([("status_list", .textMap([("idx", .negative(-1)), ("uri", .text(TestStatusList.uri))]))]),
                               .textMap([("status_list", .textMap([("idx", .unsigned(1))]))]),
                               .textMap([("status_list", .textMap([("idx", .unsigned(1)), ("uri", .text(TestStatusList.uri)), ("other", .bool(true))]))]),
                               .textMap([("other", .bool(true))])] {
            XCTAssertThrowsError(try MDocStatusReference.parse(bad), "\(bad)")
        }
        XCTAssertEqual(try MDocStatusReference.parse(nil), MDocStatusField.none)
        XCTAssertEqual(try MDocStatusReference.parse(.textMap([("identifier_list", .textMap([]))])), .unsupported)
        XCTAssertEqual(try MDocStatusReference.parse(TestStatusList.reference(index: 9)), .statusList(MDocStatusReference(index: 9, uri: TestStatusList.uri)))
    }

    // MARK: Configuration only toward stricter

    func testTheSettingsCanOnlyBeMadeStricter() throws {
        var config = ServerConfig.testing()
        try config.applyVerifyEnvironment([:], production: false)
        XCTAssertEqual(config.verify.walletStatusMaxCache, 3600)
        XCTAssertEqual(config.verify.walletStatusFailMode, .highAssurance)
        XCTAssertFalse(config.verify.walletStatusRequired)
        for bad in [["WALLET_STATUS_FAIL_MODE": "open"], ["WALLET_STATUS_FAIL_MODE": "none"], ["WALLET_STATUS_LIST_MAX_CACHE_SECONDS": "7200"],
                    ["WALLET_STATUS_LIST_MAX_CACHE_SECONDS": "10"], ["WALLET_STATUS_REQUIRED": "yes"], ["WALLET_STATUS_LIST_HOSTS": "status.dmv-issuer.us"],
                    ["WALLET_STATUS_LIST_HOSTS": pki.fingerprint + ":10.0.0.1"], ["WALLET_STATUS_LIST_HOSTS": pki.fingerprint + ":printer.local"],
                    ["WALLET_STATUS_LIST_HOSTS": "abc:status.dmv-issuer.us"],
                    ["WALLET_IACA_SHA256": String(repeating: "b", count: 64), "WALLET_STATUS_LIST_HOSTS": pki.fingerprint + ":status.dmv-issuer.us"]] {
            var c = ServerConfig.testing()
            XCTAssertThrowsError(try c.applyVerifyEnvironment(bad, production: false), "\(bad)")
        }
        try config.applyVerifyEnvironment(["WALLET_STATUS_FAIL_MODE": "all", "WALLET_STATUS_LIST_MAX_CACHE_SECONDS": "600", "WALLET_STATUS_REQUIRED": "true",
                                           "WALLET_IACA_SHA256": pki.fingerprint, "WALLET_STATUS_LIST_HOSTS": "\(pki.fingerprint.uppercased()):Status.DMV-Issuer.US"], production: false)
        XCTAssertEqual(config.verify.walletStatusFailMode, .all)
        XCTAssertEqual(config.verify.walletStatusMaxCache, 600)
        XCTAssertTrue(config.verify.walletStatusRequired)
        XCTAssertEqual(config.verify.walletStatusHosts.hostsByAnchor, [pki.fingerprint: ["status.dmv-issuer.us"]])
    }
}

// MARK: End to end through the Wallet route

extension VerifyFlowTests {
    func statusRig(_ h: TestHarness, _ fake: FakeDidit, token: Data) async throws -> (Rig, FakeStatusListFetcher) {
        let fetcher = FakeStatusListFetcher(token)
        h.app.verify.statusFetcher = fetcher
        return (try await rig(h, fake), fetcher)
    }

    func testAWalletCredentialWhoseIssuerRevokedItIsNotVerified() async throws {
        try await withVerify(configure: { $0.verify.walletStatusHosts = StatusListHostPolicy(hostsByAnchor: [self.pki.fingerprint: [TestStatusList.host]]) }) { h, fake in
            let (r, fetcher) = try await statusRig(h, fake, token: TestStatusList.token(pki: pki, .init(statuses: [0, 0, 0, 1])))
            let id = try await createdID(r)
            try await consent(r, id)
            var flaws = TestMDoc.Flaws()
            flaws.msoStatus = TestStatusList.reference(index: 3)
            let revoked = try await wallet(r, id, elements: ageOver(21), flaws: flaws)
            XCTAssertEqual(try attemptOutcome(revoked.result).status, .consented)
            try await eq(try await VerificationAttemptRecord.query(on: h.db).filter(\.$id == revoked.start.attemptId).first()?.failureReason, "credential_revoked")
            try await eq(try await resource(r, id).status, .pending)
            XCTAssertEqual(fetcher.fetched.map(\.absoluteString), [TestStatusList.uri])
            // The same issuer's valid entry: verified, provenance records the check.
            flaws.msoStatus = TestStatusList.reference(index: 2)
            let valid = try await wallet(r, id, elements: ageOver(21), flaws: flaws)
            XCTAssertEqual(try attemptOutcome(valid.result).status, .released, valid.result.text)
            let provenance = try ViadereJSON.decode(VerificationProvenance.self, from: Data(try unwrap(try await VerificationResultRecord.query(on: h.db).first()?.provenance).utf8))
            XCTAssertEqual(provenance.revocation, .active)
            XCTAssertEqual(fetcher.fetched.count, 1, "the second check used the cached list")
            // The business's audit trail says nothing about why the first attempt failed (F1).
            let business = try await AuditEventRecord.query(on: h.db).filter(\.$businessId == r.b.id.uuid).all()
            XCTAssertFalse(business.contains { $0.metadataJSON.contains("revoked") || $0.metadataJSON.contains("status_list") })
        }
    }

    func testAWalletCredentialWhoseStatusListIsUnreachableFailsClosed() async throws {
        try await withVerify(configure: { $0.verify.walletStatusHosts = StatusListHostPolicy(hostsByAnchor: [self.pki.fingerprint: [TestStatusList.host]]) }) { h, fake in
            let (r, fetcher) = try await statusRig(h, fake, token: Data())
            fetcher.fail()
            let id = try await createdID(r)
            try await consent(r, id)
            var flaws = TestMDoc.Flaws()
            flaws.msoStatus = TestStatusList.reference(index: 0)
            let down = try await wallet(r, id, elements: ageOver(21), flaws: flaws)
            XCTAssertEqual(try attemptOutcome(down.result).status, .consented)
            try await eq(try await VerificationAttemptRecord.query(on: h.db).filter(\.$id == down.start.attemptId).first()?.failureReason,
                         "status_unavailable:status_list_fetch_failed")
            // A credential without a reference still verifies (recorded as not checked) under the default settings.
            let plain = try await wallet(r, id, elements: ageOver(21))
            XCTAssertEqual(try attemptOutcome(plain.result).status, .released, plain.result.text)
            let provenance = try ViadereJSON.decode(VerificationProvenance.self, from: Data(try unwrap(try await VerificationResultRecord.query(on: h.db).first()?.provenance).utf8))
            XCTAssertEqual(provenance.revocation, .notChecked)
        }
    }

    /// Profile verification reads Wallet credentials through the same check: a revoked credential keeps no verified fact.
    func testProfileVerificationKeepsNothingFromARevokedWalletCredential() async throws {
        try await withVerify(configure: { $0.verify.walletStatusHosts = StatusListHostPolicy(hostsByAnchor: [self.pki.fingerprint: [TestStatusList.host]]) }) { h, _ in
            h.app.verify.statusFetcher = FakeStatusListFetcher(TestStatusList.token(pki: pki, .init(statuses: [1, 0, 0, 0])))
            let jane = try await h.readyConsumer(name: "Jane Doe")
            func attempt(index: UInt64) async throws -> ProfileVerificationOutcome {
                let begin = try await h.signedPost(jane, APIRoutes.profileVerificationBegin.template, ProfileVerificationBegin(method: .wallet, keep: [.identity]))
                XCTAssertEqual(begin.status, .ok, begin.text)
                let start = try begin.json(ProfileVerificationStart.self)
                var doc = TestMDoc(pki: pki, elements: [WalletElementPlan.isoNamespace: [("issuing_authority", .text("Test State DMV"))]])
                doc.flaws.msoStatus = TestStatusList.reference(index: index)
                let envelope = try TestWalletSealer.seal(doc, nonce: try XCTUnwrap(Base64URL.decode(try XCTUnwrap(start.nonce))), recipient: merchantKey.publicKey)
                let path = APIRoutes.profileVerificationComplete.template.replacingOccurrences(of: "{attemptId}", with: start.attemptId.description)
                let done = try await h.signedPost(jane, path, ProfileVerificationComplete(envelope: Base64URL.encode(envelope)))
                XCTAssertEqual(done.status, .ok, done.text)
                return try done.json(ProfileVerificationOutcome.self)
            }
            let revoked = try await attempt(index: 0)
            XCTAssertEqual(revoked.status, .notVerified)
            XCTAssertTrue(revoked.facts.isEmpty)
            let valid = try await attempt(index: 1)
            XCTAssertEqual(valid.status, .verified)
            XCTAssertFalse(valid.facts.isEmpty)
        }
    }
}
