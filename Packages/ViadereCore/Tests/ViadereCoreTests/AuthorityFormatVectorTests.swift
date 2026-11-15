@preconcurrency import Crypto
import Foundation
import Testing
@testable import ViadereCore

// Cross-language vectors for the authority and destination formats (ledger L-11, L-15), generated independently of this code by
// `docs/protocol/vectors/generate_authority_v1.py`: every positive case is reproduced byte for byte and every negative case refused with the
// expected reason.

enum AuthorityVectorFile {
    static func load(_ name: String) throws -> JSONValue {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { url.deleteLastPathComponent() }
        return try JSONDecoder().decode(JSONValue.self, from: Data(contentsOf: url.appendingPathComponent("docs/protocol/vectors/\(name)")))
    }
}

extension JSONValue {
    fileprivate func at(_ member: String) -> JSONValue { objectValue?[member] ?? .null }
    fileprivate var items: [JSONValue] { if case .array(let values) = self { values } else { [] } }
    fileprivate var text: String { stringValue ?? "" }
    fileprivate var number: Int64 { authorityInteger ?? 0 }
    fileprivate var flag: Bool { if case .bool(let value) = self { value } else { false } }
    fileprivate var bytes: Data { Base64URL.decode(text) ?? Data() }
    fileprivate var isPresent: Bool { if case .null = self { false } else { true } }
}

/// The refusal code a vector names for a Core error.
private func vectorCode(_ error: any Error) -> String {
    switch error {
    case let e as AuthorityJOSEError:
        switch e {
        case .malformed: "malformed"
        case .unsupportedAlgorithm: "unsupported_algorithm"
        case .wrongType: "wrong_type"
        case .unknownKey: "unknown_key"
        case .badSignature: "bad_signature"
        case .claims: "claims"
        case .expired: "expired"
        case .notYetValid: "not_yet_valid"
        }
    case let e as AuthorityStatementVerifier.HeadError:
        switch e {
        case .stale: "stale"
        case .rollback: "rollback"
        case .notMyAccount: "not_my_account"
        case .entryMismatch: "entry_mismatch"
        case .recoveryMismatch: "recovery_mismatch"
        }
    case let e as AuthDestinationStatementError: e.rawValue
    case let e as RecoverySealError:
        switch e {
        case .malformed: "malformed"
        case .wrongKey: "wrong_key"
        case .openFailed: "open_failed"
        case .plaintext(let reason): "plaintext_\(reason)"
        }
    default: "unexpected \(error)"
    }
}

private func signingKey(_ v: JSONValue) throws -> P256.Signing.PublicKey { try P256.Signing.PublicKey(x963Representation: v.at("x963").bytes) }
private func date(_ seconds: Int64) -> Date { Date(timeIntervalSince1970: TimeInterval(seconds)) }
private func canonicalText(_ value: JSONValue) throws -> String { String(decoding: try CanonicalJSON.serialize(value), as: UTF8.self) }
private func signingInput(of compact: String) -> String { compact.split(separator: ".", omittingEmptySubsequences: false).prefix(2).joined(separator: ".") }

// MARK: - keylog-v1.json

@Suite("Key-log vectors (keylog-v1.json)")
struct KeyLogVectorTests {
    let v = try! AuthorityVectorFile.load("keylog-v1.json")

    @Test func popMessagesAndSignatures() throws {
        let cases = v.at("pop").items
        #expect(cases.count >= 15)
        for c in cases {
            let environment = try #require(AuthorityEnvironment(rawValue: c.at("env").text))
            let message = AuthorityKeyLogFormat.popMessage(environment: environment, type: c.at("type").text, kid: c.at("kid").text, nonce: c.at("nonce").text,
                                                           extra: c.at("extra").items.map(\.text))
            #expect(message == Data(c.at("message").text.utf8), "\(c.at("name").text)")
            let key = try P256.Signing.PublicKey(x963Representation: c.at("public_key").bytes)
            #expect(AuthorityKeyLogFormat.verifyPoP(c.at("pop").text, key: key, message: message) == (c.at("expect").text == "accept"), "\(c.at("name").text)")
        }
    }

    @Test func entryHashChain() throws {
        let entries = v.at("entries").items
        #expect(entries.count == 4)
        var previous = v.at("zero_hash").text
        #expect(previous == AuthorityKeyLogFormat.zeroHash)
        for e in entries {
            let entry = try #require(e.at("entry").objectValue)
            #expect(try canonicalText(.object(entry)) == e.at("canonical").text)
            #expect(entry["prev_hash"]?.stringValue == previous)
            let hash = try AuthorityKeyLogFormat.entryHash(entry)
            #expect(hash == e.at("entry_hash").text)
            #expect(hash != e.at("wrong_domain_hash").text && hash != e.at("undomained_hash").text)
            previous = hash
        }
        let tampered = try #require(v.at("tampered_entry").at("entry").objectValue)
        #expect(try AuthorityKeyLogFormat.entryHash(tampered) != v.at("tampered_entry").at("original_hash").text)
    }

    @Test func comparisonCodes() throws {
        let cases = v.at("comparison_codes").items
        #expect(cases.contains { $0.at("code").text.hasPrefix("00") })
        for c in cases {
            let environment = try #require(AuthorityEnvironment(rawValue: c.at("env").text))
            let code = AuthorityDeviceAddCode.code(environment: environment, nonce: c.at("nonce").text, kids: c.at("kids").items.map(\.text))
            #expect(code == c.at("code").text, "\(c.at("name").text)")
            #expect(code.count == 6)
            if c.at("unsorted_join_code").text != c.at("code").text { #expect(code != c.at("unsorted_join_code").text) }
        }
    }

    @Test func reportedNamesAndAccountRefs() {
        for c in v.at("reported_names").items {
            let expected: String? = c.at("accepted").flag ? c.at("nfc").text : nil
            #expect(AuthorityKeyLogFormat.reportedName(c.at("raw").text) == expected, "\(c.at("raw").text.unicodeScalars.map { $0.value })")
        }
        for c in v.at("account_refs").items {
            #expect(AuthorityKeyLogFormat.isAccountRef(c.at("value").text) == c.at("valid").flag, "\(c.at("value").text)")
        }
    }
}

// MARK: - device-statements-v1.json

@Suite("Device statement vectors (device-statements-v1.json)")
struct DeviceStatementVectorTests {
    let v = try! AuthorityVectorFile.load("device-statements-v1.json")

    var pinned: [P256.Signing.PublicKey] { v.at("pinned_keys").items.compactMap { try? signingKey($0) } }

    @Test func rfc7638AndDeviceKidsAgree() throws {
        #expect(pinned.count == 2)
        for k in v.at("rfc7638").items + v.at("pinned_keys").items + [v.at("unknown_key")] {
            let key = try signingKey(k)
            #expect(JWKThumbprint.p256(key) == k.at("kid").text)
            #expect(JWKThumbprint.p256JWK(key)["x"]?.stringValue == k.at("x").text && JWKThumbprint.p256JWK(key)["y"]?.stringValue == k.at("y").text)
            if k.at("device_kid").isPresent { #expect(KeyIdentifier.make(key) == k.at("device_kid").text) }
        }
    }

    @Test func displayDigestsAndBuilders() throws {
        for d in v.at("displays").items {
            let display = d.at("display")
            #expect(try canonicalText(display) == d.at("canonical").text)
            let digest = try AuthorityDisplay.digest(display)
            #expect(digest == d.at("digest").text && digest != d.at("wrong_domain_digest").text)
            let o = display
            let rebuilt: JSONValue
            switch o.at("purpose").text {
            case "oidc_login":
                rebuilt = AuthorityDisplay.oidcLogin(clientName: o.at("client_name").text, redirectURI: o.at("redirect_uri").text,
                                                     matchDigits: o.at("match_digits").isPresent ? Int(o.at("match_digits").number) : nil)
            case "link_open":
                rebuilt = AuthorityDisplay.linkOpen(tenantName: o.at("tenant_name").text, clientName: o.at("client_name").text, returnURL: o.at("return_url").text,
                                                    matchDigits: o.at("match_digits").isPresent ? Int(o.at("match_digits").number) : nil)
            case "keylog_device_added":
                rebuilt = AuthorityDisplay.deviceAdded(reportedName: o.at("reported_name").text, kids: o.at("kids").items.map(\.text))
            default:
                rebuilt = AuthorityDisplay.recoveryCodesSet(setId: o.at("set_id").text, count: Int(o.at("count").number))
            }
            #expect(rebuilt == display, "\(d.at("name").text)")
        }
    }

    @Test func challengeStatements() throws {
        let cases = v.at("challenges").items
        #expect(cases.count >= 40)
        for c in cases {
            let name = c.at("name").text
            let outcome: String
            do {
                let s = try AuthorityStatementVerifier.verifyChallenge(c.at("jws").text, pinnedKeys: pinned, revokedKids: Set(c.at("revoked_kids").items.map(\.text)),
                                                                       environment: .staging, now: date(c.at("now").number))
                #expect(try canonicalText(.object(s.payload)) == c.at("payload_canonical").text, "\(name)")
                let header = try AuthorityJWS.parse(c.at("jws").text, expectedType: AuthorityChallengeStatement.type, allowedAlgorithms: ["ES256"])
                #expect(try AuthorityJWS.signingInput(alg: "ES256", kid: header.kid, typ: AuthorityChallengeStatement.type, payload: s.payload)
                        == signingInput(of: c.at("jws").text), "\(name)")
                outcome = "accept"
            } catch { outcome = vectorCode(error) }
            #expect(outcome == c.at("expect").text, "\(name)")
        }
    }

    func verifyHead(_ c: JSONValue) -> (AuthorityKeyLogHead?, String) {
        do {
            let head = try AuthorityStatementVerifier.verifyHead(c.at("jws").text, pinnedKeys: pinned, revokedKids: Set(c.at("revoked_kids").items.map(\.text)),
                                                                 environment: .staging, ownKids: c.at("own_kids").items.map(\.text),
                                                                 minimumSeq: c.at("minimum_seq").number, now: date(c.at("now").number))
            return (head, "accept")
        } catch { return (nil, vectorCode(error)) }
    }

    @Test func keyLogHeads() throws {
        let cases = v.at("heads").items
        #expect(cases.count >= 20)
        for c in cases {
            let name = c.at("name").text
            let (head, outcome) = verifyHead(c)
            #expect(outcome == c.at("expect").text, "\(name)")
            guard let head else { continue }
            #expect(try canonicalText(.object(head.payload)) == c.at("payload_canonical").text, "\(name)")
            let kid = try AuthorityJWS.parse(c.at("jws").text, expectedType: AuthorityKeyLogHead.type, allowedAlgorithms: ["ES256"]).kid
            #expect(try AuthorityJWS.signingInput(alg: "ES256", kid: kid, typ: AuthorityKeyLogHead.type, payload: head.payload) == signingInput(of: c.at("jws").text))
            for e in c.at("exact_entry").items {
                let result: String
                do { try AuthorityStatementVerifier.requireExactEntry(head, ownKids: e.at("own_kids").items.map(\.text)); result = "accept" } catch { result = vectorCode(error) }
                #expect(result == e.at("expect").text, "\(name) exact entry \(e.at("own_kids").items.count)")
            }
            for e in c.at("exact_pending").items {
                let result: String
                do { try AuthorityStatementVerifier.requireExactPendingRecovery(head, newKids: e.at("new_kids").items.map(\.text)); result = "accept" } catch { result = vectorCode(error) }
                #expect(result == e.at("expect").text, "\(name) exact pending \(e.at("new_kids").items.count)")
            }
        }
    }

    @Test("Each of the four statement types is refused by every verifier of another type")
    func crossType() {
        let cases = v.at("cross_typ").items
        #expect(cases.count == 4 * 2 + 6)
        for c in cases {
            let compact = c.at("jws").text
            let outcome: String
            do {
                if c.at("verifier").text == AuthorityChallengeStatement.type {
                    _ = try AuthorityStatementVerifier.verifyChallenge(compact, pinnedKeys: pinned, environment: .staging, now: date(1_800_000_000))
                } else {
                    _ = try AuthorityStatementVerifier.verifyHead(compact, pinnedKeys: pinned, environment: .staging,
                                                                  ownKids: [], minimumSeq: 0, now: date(1_800_000_000))
                }
                outcome = "accept"
            } catch { outcome = vectorCode(error) }
            #expect(outcome == c.at("expect").text, "\(c.at("typ").text) as \(c.at("verifier").text)")
            // No device statement is ever a destination statement either.
            #expect(throws: AuthDestinationStatementError.self) { try AuthDestinationStatement.parse(compact) }
        }
    }
}

// MARK: - auth-destination-v1.json

@Suite("Destination statement vectors (auth-destination-v1.json)")
struct AuthDestinationVectorTests {
    let v = try! AuthorityVectorFile.load("auth-destination-v1.json")

    func expectation(_ c: JSONValue) throws -> AuthDestinationStatement.Expectation {
        let base = v.at("expectation"), over = c.at("expectation")
        func pick(_ member: String) -> JSONValue { over.at(member).isPresent ? over.at(member) : base.at(member) }
        var keys: [String: (key: DevicePublicKey, notAfter: Date?)] = [:]
        for k in pick("keys").items { keys[k.at("kid").text] = (try DevicePublicKey(bytes: k.at("x963").bytes), date(k.at("not_after").number)) }
        return .init(keys: keys, allowedHosts: Set(pick("allowed_hosts").items.map(\.text)), tenantId: pick("tenant_id").text, requestId: pick("request_id").text,
                     purpose: try #require(AuthDeliveryPurpose(rawValue: pick("purpose").text)), now: date(pick("now").number))
    }

    func outcome(_ c: JSONValue) throws -> (AuthDestinationStatement?, String) {
        let seen = c.at("jti_seen_before").flag
        let expectation = try expectation(c)
        do {
            return (try AuthDestinationStatement.verifyForDevice(c.at("jws").text.isEmpty ? nil : c.at("jws").text, expectation: expectation, seenJTI: { _ in !seen }), "accept")
        } catch { return (nil, vectorCode(error)) }
    }

    @Test func theSDKStatementIsReproducedByteForByte() throws {
        let url = v.at("url").text
        #expect(AuthDestinationStatement.digest(of: url) == v.at("url_sha256").text)
        let built = try AuthDestinationStatement.build(url: url, tenantId: v.at("tenant_id").text, subjectRef: try #require(SubjectRef(v.at("subject_ref").text)),
                                                       requestId: v.at("request_id").text, purpose: .signIn, kid: v.at("kid").text, issuedAt: date(v.at("iat").number),
                                                       lifetime: v.at("lifetime").number, jti: v.at("jti").text)
        let header = try CanonicalJSON.serialize(.object(["alg": .string("ES256"), "kid": .string(built.kid), "typ": .string(AuthDestinationStatement.type)]))
        let input = Base64URL.encode(header) + "." + Base64URL.encode(try CanonicalJSON.serialize(.object(built.payload)))
        let valid = try #require(v.at("cases").items.first { $0.at("name").text == "valid sign_in" })
        #expect(input == signingInput(of: valid.at("jws").text))
    }

    @Test func deviceVerificationBeforeContinueAndAfterOpen() throws {
        let cases = v.at("cases").items
        #expect(cases.count >= 45)
        for c in cases {
            let name = c.at("name").text
            let (statement, result) = try outcome(c)
            #expect(result == c.at("expect").text, "\(name)")
            guard c.at("opened_url").isPresent else { continue }
            let s = try #require(statement, "\(name)")
            let hosts = try expectation(c).allowedHosts
            let opened: String
            do { try s.verifyOpened(url: c.at("opened_url").text, allowedHosts: hosts); opened = "accept" } catch { opened = error.rawValue }
            #expect(opened == c.at("opened_expect").text, "\(name)")
        }
    }

    /// ADR-0031 §3 allows only `sign_in`, `step_up` and `verify_contact`; Core accepts any `AuthDeliveryPurpose`. Recorded as a finding, not fixed here.
    @Test func specDisagreements() throws {
        for c in v.at("spec_disagreements").items {
            let (_, result) = try outcome(c)
            withKnownIssue("Core accepts purpose \(c.at("expectation").at("purpose").text) in a destination statement (ADR-0031 §3)") {
                #expect(result == c.at("expect").text, "\(c.at("name").text)")
            }
        }
    }
}

// MARK: - recovery-seal-v1.json

@Suite("Recovery seal vectors (recovery-seal-v1.json)")
struct RecoverySealVectorTests {
    let v = try! AuthorityVectorFile.load("recovery-seal-v1.json")

    var sealKey: P256.KeyAgreement.PrivateKey { try! P256.KeyAgreement.PrivateKey(rawRepresentation: v.at("seal_key").at("d").bytes) }

    @Test("RFC 9180 A.3.1 (DHKEM(P-256, HKDF-SHA256), HKDF-SHA256) opens in Core's HPKE")
    func rfc9180() throws {
        let a = v.at("rfc9180_a31")
        func hex(_ member: String) -> Data { Hex.decode(a.at(member).text) ?? Data() }
        let recipientKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: hex("skRm"))
        #expect(recipientKey.publicKey.x963Representation == hex("pkRm"))
        var recipient = try HPKE.Recipient(privateKey: recipientKey, ciphersuite: HPKE.Ciphersuite(kem: .P256_HKDF_SHA256, kdf: .HKDF_SHA256, aead: .AES_GCM_128),
                                           info: hex("info"), encapsulatedKey: hex("enc"))
        #expect(try recipient.open(hex("ct"), authenticating: hex("aad")) == hex("pt"))
    }

    @Test func sealKeyAndKid() {
        #expect(sealKey.publicKey.x963Representation == v.at("seal_key").at("x963").bytes)
        #expect(RecoverySeal.kid(sealKey.publicKey) == v.at("seal_key").at("kid").text)
        let other = try? P256.KeyAgreement.PublicKey(x963Representation: v.at("other_seal_key").at("x963").bytes)
        #expect(other.map(RecoverySeal.kid) == v.at("other_seal_key").at("kid").text)
    }

    @Test func envelopes() throws {
        let cases = v.at("cases").items
        #expect(cases.count >= 40)
        for c in cases {
            let name = c.at("name").text
            let o = c.at("open_with")
            let purpose = try #require(RecoverySealPurpose(rawValue: o.at("purpose").text))
            let environment = try #require(AuthorityEnvironment(rawValue: o.at("env").text))
            #expect(String(decoding: RecoverySeal.info(purpose, environment), as: UTF8.self) == c.at("info").text || c.at("expect").text == "open_failed", "\(name)")
            #expect(String(decoding: RecoverySeal.aad(challengeId: o.at("challenge_id").text, nonce: o.at("nonce").text), as: UTF8.self) == c.at("aad").text
                    || c.at("expect").text == "open_failed", "\(name)")
            let result: String
            do {
                let envelope = try RecoverySealEnvelope.parse(c.at("envelope"))
                #expect(envelope.digest == c.at("envelope_digest").text, "\(name)")
                #expect(envelope.json == c.at("envelope"), "\(name)")
                let plaintext = try RecoverySeal.open(envelope, with: sealKey, purpose: purpose, environment: environment, challengeId: o.at("challenge_id").text,
                                                      nonce: o.at("nonce").text)
                if c.at("plaintext").isPresent { #expect(try canonicalText(.object(plaintext)) == c.at("plaintext").text, "\(name)") }
                if purpose == .codesSet {
                    let set = try RecoverySeal.parseSet(plaintext)
                    let authority = c.at("authority")
                    if authority.isPresent {
                        let verdict = set.accountRef != authority.at("authorizing_account_ref").text ? "account_mismatch"
                            : set.setId != authority.at("challenge_set_id").text ? "set_id_mismatch" : "accept"
                        #expect(verdict == authority.at("expect").text, "\(name)")
                    }
                } else {
                    let start = try RecoverySeal.parseStart(plaintext)
                    let authority = c.at("authority")
                    if authority.isPresent {
                        // The authority's rule (ADR-0032 §3.2): the PoP keys equal the sealed `new_kids` exactly.
                        let pop = authority.at("pop_kids").items.map(\.text)
                        let verdict = RecoverySeal.sortedKids(pop) == start.newKids ? "accept" : "new_kids_mismatch"
                        #expect(verdict == authority.at("expect").text, "\(name)")
                    }
                }
                if c.at("claimed_digest").isPresent { #expect(envelope.digest != c.at("claimed_digest").text, "\(name)") }
                result = "accept"
            } catch { result = vectorCode(error) }
            #expect(result == c.at("expect").text, "\(name)")
        }
    }

    /// SECURITY §2.1 base64url has no padding; `RecoverySealEnvelope.parse` decodes `enc` and `ct` without the strict check. Recorded as a finding.
    @Test func specDisagreements() {
        for c in v.at("spec_disagreements").items {
            let result: String
            do { _ = try RecoverySealEnvelope.parse(c.at("envelope")); result = "accept" } catch { result = vectorCode(error) }
            withKnownIssue("Core accepts padded base64url in a recovery envelope (SECURITY §2.1, ADR-0034 §1)") {
                #expect(result == c.at("expect").text, "\(c.at("name").text)")
            }
        }
    }
}
