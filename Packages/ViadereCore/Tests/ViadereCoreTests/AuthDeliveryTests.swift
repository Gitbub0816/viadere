import Crypto
import Foundation
import Testing
@testable import ViadereCore

/// Auth delivery contract (ADR-0020, ADR-0021, ADR-0031): ids, state machine, strict decoding, destination policy, destination statements, push payload
/// schema and the route catalog. Test names carry the THREAT_MODEL catalogue ids they cover.
@Suite("Auth delivery contract")
struct AuthDeliveryTests {
    static let subject = SubjectRef("sub_" + Base64URL.encode(Data(SHA256.hash(data: Data("auth-delivery-test".utf8)))))!

    static func body(_ overrides: [String: Any] = [:], remove: [String] = []) -> Data {
        var object: [String: Any] = [
            "method": "magic_link", "request_id": "req-1", "subject_ref": subject.rawValue, "purpose": "sign_in", "template": "auth.sign_in_link.v1",
            "destination": ["link_mode": "business", "url": "https://login.example.com/m?t=abc", "signature": "x.y.z"],
        ]
        for (k, v) in overrides { object[k] = v }
        for k in remove { object.removeValue(forKey: k) }
        return try! JSONSerialization.data(withJSONObject: object)
    }

    // MARK: Ids and the state machine

    @Test func deliveryIdIsCanonicalAndRoundTrips() {
        let id = AuthDeliveryID()
        #expect(id.description.hasPrefix("adl_") && id.description.count == 26)
        #expect(AuthDeliveryID(id.description) == id)
        #expect(AuthDeliveryID("adl_" + String(repeating: "A", count: 21)) == nil)
        #expect(AuthDeliveryID("xdl_" + id.description.dropFirst(4)) == nil)
        // A non-canonical spelling of the same 16 bytes (the last character carries 2 unused bits) is refused: one delivery, one id string.
        let canonical = id.description
        let last = canonical.last!
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        let index = alphabet.firstIndex(of: last)!
        let other = alphabet[index ^ 1]
        #expect(AuthDeliveryID(String(canonical.dropLast()) + String(other)) == nil)
    }

    /// ST-DLV-03 (contract part): sent, delivered and opened are never completion; only the business completes, and only from `opened`.
    @Test func openedIsNeverSuccessAndOnlyTheBusinessCompletes() {
        for actor in AuthDeliveryActor.allCases {
            for from in AuthDeliveryStatus.allCases where from != .opened {
                #expect(!AuthDeliveryStateMachine.isAllowed(from: from, to: .completed, by: actor), "\(from) -> completed by \(actor)")
            }
            if actor != .business { #expect(!AuthDeliveryStateMachine.isAllowed(from: .opened, to: .completed, by: actor)) }
        }
        #expect(AuthDeliveryStateMachine.isAllowed(from: .opened, to: .completed, by: .business))
        #expect(AuthDeliveryStateMachine.isAllowed(from: .opened, to: .failed, by: .business))
        // The device can open, never complete; the worker can send, never open.
        #expect(AuthDeliveryStateMachine.isAllowed(from: .delivered, to: .opened, by: .device))
        #expect(!AuthDeliveryStateMachine.isAllowed(from: .delivered, to: .opened, by: .worker))
        #expect(!AuthDeliveryStateMachine.isAllowed(from: .sent, to: .opened, by: .business))
    }

    @Test func terminalStatesNeverMove() {
        for from in AuthDeliveryStatus.allCases where from.isTerminal {
            for to in AuthDeliveryStatus.allCases { for actor in AuthDeliveryActor.allCases { #expect(!AuthDeliveryStateMachine.isAllowed(from: from, to: to, by: actor)) } }
        }
        #expect(AuthDeliveryStatus.allCases.filter(\.isTerminal).count == 5)
    }

    @Test func denyCancelAndExpireWorkFromEveryLiveState() {
        for from in AuthDeliveryStatus.allCases where !from.isTerminal {
            #expect(AuthDeliveryStateMachine.isAllowed(from: from, to: .denied, by: .device))
            #expect(AuthDeliveryStateMachine.isAllowed(from: from, to: .cancelled, by: .business))
            #expect(AuthDeliveryStateMachine.isAllowed(from: from, to: .expired, by: .system))
        }
        // A business cannot deny on the customer's behalf and a device cannot cancel for the business.
        #expect(!AuthDeliveryStateMachine.isAllowed(from: .queued, to: .denied, by: .business))
        #expect(!AuthDeliveryStateMachine.isAllowed(from: .queued, to: .cancelled, by: .device))
    }

    // MARK: Strict decoding (ST-GW-10, ST-TOTP-01, ST-DLV-04)

    @Test func aValidMagicLinkBodyDecodes() {
        guard case .request(let request) = AuthDeliveryValidation.decodeCreate(Self.body()) else { Issue.record("expected a request"); return }
        #expect(request.method == .magicLink && request.destination?.linkMode == .business)
    }

    /// ST-GW-10: the tenant comes from the credential. `tenant_id` and `audience` (and every other unknown member) are refused.
    @Test func tenantIdAudienceAndUnknownMembersAreRefused() {
        for key in ["tenant_id", "audience", "business_id", "extra"] {
            guard case .invalid(let issue) = AuthDeliveryValidation.decodeCreate(Self.body([key: "x"])) else { Issue.record("\(key) accepted"); continue }
            #expect(issue.field == key && issue.code == "unknown_member")
        }
        // Also nested.
        let nested = Self.body(["destination": ["link_mode": "business", "url": "https://login.example.com/m", "signature": "x.y.z", "tenant_id": "t"]])
        guard case .invalid = AuthDeliveryValidation.decodeCreate(nested) else { Issue.record("nested unknown member accepted"); return }
    }

    @Test func duplicateMembersOversizedAndNonObjectBodiesAreRefused() {
        let duplicate = Data(#"{"method":"notice","method":"otp","request_id":"r","subject_ref":"x","purpose":"account_notice","template":"auth.security_notice.v1"}"#.utf8)
        guard case .invalid(let issue) = AuthDeliveryValidation.decodeCreate(duplicate) else { Issue.record("duplicate accepted"); return }
        #expect(issue.code == "duplicate_member")
        guard case .invalid(let big) = AuthDeliveryValidation.decodeCreate(Data(repeating: 0x20, count: AuthDeliveryCreateRequest.maxBytes + 1)) else { Issue.record("oversized accepted"); return }
        #expect(big.code == "size")
        guard case .invalid = AuthDeliveryValidation.decodeCreate(Data("[]".utf8)) else { Issue.record("array accepted"); return }
    }

    /// ST-DLV-04: SMS is not a channel. The enum has no member for it, so no adapter can be selected for any method.
    @Test func smsIsNotAChannel() {
        #expect(AuthDeliveryChannel(rawValue: "sms") == nil)
        #expect(Set(AuthDeliveryChannel.allCases.map(\.rawValue)) == ["push", "inbox", "email"])
        guard case .invalid = AuthDeliveryValidation.decodeCreate(Self.body(["channels": ["push", "sms"]])) else { Issue.record("sms accepted"); return }
    }

    /// ST-TOTP-01: `otpauth://` is refused in any field, in any case, also after one percent-decode.
    @Test func otpauthIsRefusedEverywhere() {
        let spellings = ["otpauth://totp/x?secret=ABC", "OTPAUTH://totp/x", "OtpAuth://x", "otpauth%3A%2F%2Ftotp%2Fx", "see otpauth://totp/a"]
        for spelling in spellings {
            for body in [
                Self.body(["correlation_id": spelling]),
                Self.body(["variables": ["reference": spelling]]),
                Self.body(["client_transaction_ref": spelling]),
                Self.body(["destination": ["link_mode": "business", "url": "https://login.example.com/?x=\(spelling)", "signature": "a.b.c"]]),
                Self.body(["method": "otp", "template": "auth.sign_in_code.v1", "otp": ["code": "ABCD", "code_kind": "totp", "note": spelling]], remove: ["destination"]),
            ] {
                guard case .invalid(let issue) = AuthDeliveryValidation.decodeCreate(body) else { Issue.record("accepted \(spelling)"); continue }
                #expect(issue.code == "otpauth_refused" || issue.code == "unknown_member")
            }
        }
        #expect(AuthDeliveryValidation.containsOTPAuth("otpauth%3A%2F%2Fx"))
        #expect(!AuthDeliveryValidation.containsOTPAuth("authenticator app"))
    }

    @Test func sessionHandleIsOptionalAndValidated() {
        guard case .request(let r) = AuthDeliveryValidation.decodeCreate(Self.body(["session_handle": "sess_A-1"])) else { Issue.record("refused"); return }
        #expect(r.sessionHandle == "sess_A-1")
        for bad in ["", String(repeating: "a", count: 65), "a b", "a.b", "\u{e9}"] {
            guard case .invalid = AuthDeliveryValidation.decodeCreate(Self.body(["session_handle": bad])) else { Issue.record("accepted \(bad)"); continue }
        }
    }

    @Test func otpCodesAndKindsAreValidated() {
        func otp(_ code: String) -> Data { Self.body(["method": "otp", "template": "auth.sign_in_code.v1", "otp": ["code": code, "code_kind": "otp"]], remove: ["destination"]) }
        for ok in ["1234", "ABCD123456", "7Z9Q"] { guard case .request = AuthDeliveryValidation.decodeCreate(otp(ok)) else { Issue.record("\(ok) refused"); continue } }
        for bad in ["123", "12345678901", "abcd", "12 34", "12-34", "١٢٣٤"] { guard case .invalid = AuthDeliveryValidation.decodeCreate(otp(bad)) else { Issue.record("\(bad) accepted"); continue } }
    }

    @Test func templatesFixMethodPurposeVariablesAndLifetime() {
        // The business cannot supply text: an unknown template, a template of another method, a purpose the template does not allow.
        for body in [Self.body(["template": "auth.custom.v1"]), Self.body(["template": "auth.sign_in_code.v1"]), Self.body(["purpose": "step_up"]),
                     Self.body(["variables": ["body": "Click here"]]), Self.body(["expires_in_seconds": 119]), Self.body(["expires_in_seconds": 601])] {
            guard case .invalid = AuthDeliveryValidation.decodeCreate(body) else { Issue.record("accepted \(String(decoding: body, as: UTF8.self))"); continue }
        }
        // N-06 never takes business text: the notice template declares no variable.
        let notice = Self.body(["method": "notice", "template": "auth.security_notice.v1", "purpose": "account_notice", "variables": ["reference": "x"]], remove: ["destination"])
        guard case .invalid = AuthDeliveryValidation.decodeCreate(notice) else { Issue.record("notice variable accepted"); return }
    }

    @Test func variablesAreTreatedAsPersonalDataAndRefuseContactsAndLinks() {
        func variable(_ value: String) -> Data {
            Self.body(["template": "auth.step_up_link.v1", "purpose": "step_up", "variables": ["action_display": value]])
        }
        guard case .request = AuthDeliveryValidation.decodeCreate(variable("Transfer to savings")) else { Issue.record("plain text refused"); return }
        for bad in ["see https://evil.example", "pay at evil.example.com", "mail a@b.co", "call +1 415 555 0100", "tel 4155550100", "zero\u{200B}width", "bidi\u{202E}text",
                    "line\nbreak", "Cafe\u{0301}", String(repeating: "a", count: 61), "", "javascript:alert(1)"] {
            guard case .invalid = AuthDeliveryValidation.decodeCreate(variable(bad)) else { Issue.record("accepted \(bad.debugDescription)"); continue }
        }
    }

    // MARK: Destination policy (ST-ML-04, ST-ML-05)

    static let hosts: Set<String> = ["login.example.com"]

    @Test func destinationAcceptsExactlyAllowedHttpsHosts() throws {
        let ok = try AuthDestinationValidator.validate("https://login.example.com/m?t=abc#frag", allowedHosts: Self.hosts)
        #expect(ok.host == "login.example.com")
        let sub = try? AuthDestinationValidator.validate("https://other.example.com/m", allowedHosts: Self.hosts)
        #expect(sub == nil)
    }

    /// ST-ML-05: host-confusion corpus.
    @Test func hostConfusionCorpusIsRefused() {
        let corpus = [
            "http://login.example.com/", "HTTPS://login.example.com/", "https://user@login.example.com/", "https://login.example.com@evil.test/",
            "https://login.example.com:443/", "https://login.example.com:8443/", "https://login.example.com./", "https://LOGIN.example.com/",
            "https://login.example.com\\@evil.test/", "https://evil.test\\.login.example.com/", "https://login.example.com%2e/", "https://login.exämple.com/",
            "https://аpple.example.com/", "https://127.0.0.1/", "https://[::1]/", "https://2130706433/", "https://1.2.3.4/", "https://login..example.com/",
            "//login.example.com/", "https:login.example.com", "https://login.example.com/\u{0}", "https://login.example.com/ x", "https://login.example.com/%zz",
            "https://login.example.com/a b", "javascript:alert(1)", "https://xn--login-.example.com/",
        ]
        for url in corpus { #expect((try? AuthDestinationValidator.validate(url, allowedHosts: Self.hosts.union(["login.exämple.com"]))) == nil, "\(url) was accepted") }
        #expect((try? AuthDestinationValidator.validate("https://login.example.com/" + String(repeating: "a", count: 2048), allowedHosts: Self.hosts)) == nil)
    }

    /// ST-ML-04: a query value that is an absolute or scheme-relative URL to a non-allowed host is refused, raw and after one percent-decode.
    @Test func openRedirectValuesAreRefused() {
        let bad = [
            "https://login.example.com/m?next=https://evil.test/", "https://login.example.com/m?next=https%3A%2F%2Fevil.test%2F", "https://login.example.com/m?u=//evil.test/x",
            "https://login.example.com/m?u=%2F%2Fevil.test", "https://login.example.com/m?u=http://evil.test", "https://login.example.com/m?u=%5C%5Cevil.test",
            "https://login.example.com/m?a=1&r=HTTPS://evil.test", "https://login.example.com/m?u=/%5Cevil.test",
        ]
        for url in bad { #expect((try? AuthDestinationValidator.validate(url, allowedHosts: Self.hosts)) == nil, "\(url) was accepted") }
        // An absolute value on an allowed host is fine; a plain relative path too.
        #expect((try? AuthDestinationValidator.validate("https://login.example.com/m?next=https://login.example.com/home", allowedHosts: Self.hosts)) != nil)
        #expect((try? AuthDestinationValidator.validate("https://login.example.com/m?next=/home", allowedHosts: Self.hosts)) != nil)
    }

    // MARK: Destination statement (ADR-0031; ST-ML-10, ST-ML-11, ST-ML-12)

    struct Fixture {
        let key = SoftwareP256SigningKey()
        let kid = "tk_1"
        let url = "https://login.example.com/m?t=abc"
        let tenant = "ten_7a1b2c3d4e5f60718293a4b5c6d7e8f9"
        let now = Date(timeIntervalSince1970: 1_800_000_000)

        func statement(url: String? = nil, request: String = "req-1", purpose: AuthDeliveryPurpose = .signIn, issued: Date? = nil, lifetime: Int64 = 300,
                       tenant: String? = nil, kid: String? = nil, jti: String = AuthDestinationStatement.newJTI()) async throws -> String {
            let s = try AuthDestinationStatement.build(url: url ?? self.url, tenantId: tenant ?? self.tenant, subjectRef: AuthDeliveryTests.subject, requestId: request,
                                                       purpose: purpose, kid: kid ?? self.kid, issuedAt: issued ?? now, lifetime: lifetime, jti: jti)
            return try await s.sign(with: key)
        }

        func expectation(keys: Bool = true, hosts: Set<String> = ["login.example.com"], request: String = "req-1", purpose: AuthDeliveryPurpose = .signIn,
                         at: Date? = nil, notAfter: Date? = nil) -> AuthDestinationStatement.Expectation {
            .init(keys: keys ? [kid: (key.publicKey, notAfter)] : [:], allowedHosts: hosts, tenantId: tenant, requestId: request, purpose: purpose, now: at ?? now)
        }
    }

    @Test func aGoodStatementVerifiesAndBindsTheUrlBytes() async throws {
        let f = Fixture()
        let compact = try await f.statement()
        var seen = Set<String>()
        let verified = try AuthDestinationStatement.verifyForDevice(compact, expectation: f.expectation()) { seen.insert($0).inserted }
        #expect(verified.host == "login.example.com" && verified.requestId == "req-1")
        try verified.verifyOpened(url: f.url, allowedHosts: ["login.example.com"])
        // The statement carries a digest, not the URL.
        #expect(!compact.contains("login.example.com"))
        let payload = String(decoding: Base64URL.decode(String(compact.split(separator: ".")[1]))!, as: UTF8.self)
        #expect(!payload.contains(f.url))
    }

    /// ST-ML-10 (device half): any byte of the URL rewritten after create fails the digest check, so the device refuses to open it.
    @Test func anyRewrittenByteOfTheUrlIsRefused() async throws {
        let f = Fixture()
        let verified = try AuthDestinationStatement.verifyForDevice(try await f.statement(), expectation: f.expectation()) { _ in true }
        for tampered in ["https://login.example.com/m?t=abd", "https://login.example.com/m?t=abc&x=1", "https://login.example.com/M?t=abc", "https://login.example.com/m?t=abc#"] {
            #expect(throws: AuthDestinationStatementError.urlMismatch) { try verified.verifyOpened(url: tampered, allowedHosts: ["login.example.com"]) }
        }
    }

    /// ST-ML-11: the device's refusal corpus.
    @Test func theDeviceRefusalCorpus() async throws {
        let f = Fixture()
        func verify(_ compact: String?, _ e: AuthDestinationStatement.Expectation, seen: @escaping (String) -> Bool = { _ in true }) -> AuthDestinationStatementError? {
            do { _ = try AuthDestinationStatement.verifyForDevice(compact, expectation: e, seenJTI: seen); return nil } catch { return error }
        }
        // missing
        #expect(verify(nil, f.expectation()) == .missing)
        // key not in the authority record (or no record at all: fail closed)
        #expect(verify(try await f.statement(), f.expectation(keys: false)) == .unknownKey)
        #expect(verify(try await f.statement(kid: "other"), f.expectation()) == .unknownKey)
        // key revoked / past not_after
        #expect(verify(try await f.statement(), f.expectation(notAfter: f.now.addingTimeInterval(-1))) == .keyExpired)
        // signed by a different key
        let imposter = SoftwareP256SigningKey()
        let forged = try await AuthDestinationStatement.build(url: f.url, tenantId: f.tenant, subjectRef: Self.subject, requestId: "req-1", purpose: .signIn, kid: f.kid, issuedAt: f.now).sign(with: imposter)
        #expect(verify(forged, f.expectation()) == .badSignature)
        // expired and not-yet-valid (outside +-60 s)
        #expect(verify(try await f.statement(), f.expectation(at: f.now.addingTimeInterval(301 + 61))) == .expired)
        #expect(verify(try await f.statement(issued: f.now.addingTimeInterval(120)), f.expectation()) == .notYetValid)
        // a lifetime over 600 s is clamped at build (so still valid at +500 s, expired after 660 s)
        #expect(verify(try await f.statement(lifetime: 900), f.expectation(at: f.now.addingTimeInterval(500))) == nil)
        #expect(verify(try await f.statement(lifetime: 900), f.expectation(at: f.now.addingTimeInterval(661))) == .expired)
        // wrong brq / purpose / issuer
        #expect(verify(try await f.statement(request: "req-2"), f.expectation()) == .wrongRequest)
        #expect(verify(try await f.statement(purpose: .stepUp), f.expectation()) == .wrongPurpose)
        #expect(verify(try await f.statement(tenant: "ten_other"), f.expectation()) == .wrongIssuer)
        // host not in allowed_hosts
        #expect(verify(try await f.statement(), f.expectation(hosts: ["other.example.com"])) == .hostNotAllowed)
        // replayed jti
        var seen = Set<String>()
        let once = try await f.statement()
        #expect(verify(once, f.expectation(), seen: { seen.insert($0).inserted }) == nil)
        #expect(verify(once, f.expectation(), seen: { seen.insert($0).inserted }) == .replayed)
    }

    @Test func headerConfusionIsRefused() async throws {
        let f = Fixture()
        let good = try await f.statement()
        let parts = good.split(separator: ".").map(String.init)
        func header(_ members: [String: JSONValue]) throws -> String { Base64URL.encode(try CanonicalJSON.serialize(.object(members))) }
        let wrongType = try header(["alg": .string("ES256"), "kid": .string(f.kid), "typ": .string("viadere-grant+jwt")])
        let none = try header(["alg": .string("none"), "kid": .string(f.kid), "typ": .string(AuthDestinationStatement.type)])
        let crit = try header(["alg": .string("ES256"), "kid": .string(f.kid), "typ": .string(AuthDestinationStatement.type), "crit": .array([.string("x")])])
        let jwk = try header(["alg": .string("ES256"), "kid": .string(f.kid), "typ": .string(AuthDestinationStatement.type), "jwk": .object([:])])
        for (replacement, expected) in [(wrongType, AuthDestinationStatementError.wrongType), (none, .unsupportedAlgorithm), (crit, .unknownCriticalHeader), (jwk, .malformed)] {
            let tampered = [replacement, parts[1], parts[2]].joined(separator: ".")
            #expect(throws: expected) { _ = try AuthDestinationStatement.parse(tampered) }
        }
        #expect(throws: AuthDestinationStatementError.malformed) { _ = try AuthDestinationStatement.parse("a.b") }
    }

    // MARK: Push payload schema (ST-PRIV-02) and the route catalog (ST-OTP-02, ST-DLV-04)

    @Test func pushPayloadSchemaAllowsOnlyTheGenericAlertAndTheDeliveryId() {
        let id = AuthDeliveryID().description
        let good: [String: Any] = ["aps": ["alert": ["title": "Viadere", "body": "You have a new security item."], "category": "viadere.auth.link", "thread-id": "x",
                                            "interruption-level": "active", "mutable-content": 1], "adl": id]
        #expect(AuthPushPayloadPolicy.isAllowed(good))
        var withURL = good; withURL["url"] = "https://login.example.com/m"
        #expect(!AuthPushPayloadPolicy.isAllowed(withURL))
        var withBusiness = good; withBusiness["business"] = "Northwind"
        #expect(!AuthPushPayloadPolicy.isAllowed(withBusiness))
        var customBody = good
        customBody["aps"] = ["alert": ["title": "Viadere", "body": "Your code is 123456"], "category": "viadere.auth.code", "interruption-level": "active"]
        #expect(!AuthPushPayloadPolicy.isAllowed(customBody))
        var badId = good; badId["adl"] = "not-an-id"
        #expect(!AuthPushPayloadPolicy.isAllowed(badId))
        var timeSensitive = good
        timeSensitive["aps"] = ["alert": ["title": "Viadere", "body": "You have a new security item."], "category": "viadere.auth.link", "interruption-level": "time-sensitive"]
        #expect(!AuthPushPayloadPolicy.isAllowed(timeSensitive))
    }

    /// ST-OTP-02: no Viadere route verifies a business OTP or TOTP; ST-DLV-04: no route delivers by SMS.
    @Test func noRouteVerifiesAnOTPOrDeliversBySMS() {
        for route in APIRoutes.authDeliveryEndpoints {
            let lower = route.template.lowercased() + route.name.lowercased()
            #expect(!lower.contains("verify") && !lower.contains("sms") && !lower.contains("check") && !lower.contains("validate"), "\(route.template)")
        }
        // The only POST under a delivery that takes a business outcome is `complete`, and it takes an outcome, not a code.
        let complete = Data(#"{"outcome":"succeeded","code":"123456"}"#.utf8)
        #expect((try? ViadereJSON.decode(AuthDeliveryCompleteRequest.self, from: complete)) == nil)
    }

    @Test func auth_routesUseTheRightAuthenticationRequirements() {
        for route in APIRoutes.authDeliveryEndpoints {
            if route.template.hasPrefix("/v1/business/") { #expect(route.auth == .businessAPIKey) } else { #expect(route.auth == .deviceSignedBearer) }
        }
        #expect(APIRoutes.all.contains(APIRoutes.businessAuthDeliveryCreate.descriptor))
    }
}
