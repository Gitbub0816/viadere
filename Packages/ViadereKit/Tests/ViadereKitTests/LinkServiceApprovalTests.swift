import Crypto
import Foundation
import Testing
import ViadereCore
@testable import ViadereKit

/// The phone side of the Viadere link service (`link_mode: "viadere"`, SECURITY.md §2.110, ADR-0021 §5.3): the same checks as the OIDC sign-in
/// sheet (`OIDCSignInTests`) applied to a delivery's `link_open` challenge.
@MainActor
struct LinkServiceApprovalTests {
    nonisolated static let now = Date(timeIntervalSince1970: 1_800_000_000)
    nonisolated static let returnURL = "https://login.acme.example/viadere/return?session=abc"
    nonisolated static let fixedCode = String(repeating: "A", count: 43)
    let statementKey = P256.Signing.PrivateKey()
    let ach = AuthorityChallengeID.generate()
    let deliveryId = UUID()

    static func display(tenant: String = "Acme Bank", client: String = "Acme online banking", returnURL: String = returnURL, matchDigits: Int? = nil) -> JSONValue {
        AuthorityDisplay.linkOpen(tenantName: tenant, clientName: client, returnURL: returnURL, matchDigits: matchDigits)
    }

    /// An authority-built `link_open` statement, signed like the authority signs it.
    func statement(key: P256.Signing.PrivateKey? = nil, environment: AuthorityEnvironment = .staging, purpose: AuthorityPurpose = .linkOpen,
                   display: JSONValue? = nil, returnURL: String = returnURL, matchRequired: Bool = false, lifetime: Int64 = 120) throws -> String {
        let signer = key ?? statementKey
        let t = Int64(Self.now.timeIntervalSince1970)
        let shown = display ?? Self.display(matchDigits: matchRequired ? 2 : nil)
        let payload = AuthorityChallengeStatement(environment: environment, challengeId: ach, nonce: AuthorityNonce.generate(), purpose: purpose, display: shown,
                                                  returnURL: purpose == .linkOpen ? returnURL : nil,
                                                  redirectURI: purpose == .oidcLogin ? returnURL : nil,
                                                  matchRequired: matchRequired, issuedAt: t, expiresAt: t + lifetime).payload
        let input = try AuthorityJWS.signingInput(alg: "ES256", kid: JWKThumbprint.p256(signer.publicKey), typ: AuthorityChallengeStatement.type, payload: payload)
        return input + "." + ViadereSignatureEncoding.encode(try signer.signature(for: Data(input.utf8)))
    }

    func api(_ challenge: String?, state: AuthLinkDisplay.State = .open, expiresIn: TimeInterval = 300) async -> MockLinkServiceDeviceAPI {
        let api = MockLinkServiceDeviceAPI()
        await api.set(LinkServiceDelivery(deliveryId: deliveryId, state: state, expiresAt: Self.now.addingTimeInterval(expiresIn), challenge: challenge))
        return api
    }

    func make(_ api: any LinkServiceDeviceAPI, keys: SoftwareDeviceKeyStore, pinned: [P256.Signing.PublicKey]? = nil, opener: LinkServiceOpener = LinkServiceOpener(),
              clock: @escaping @Sendable () -> Date = { LinkServiceApprovalTests.now },
              makeCode: @escaping @Sendable () -> String = { LinkServiceApprovalTests.fixedCode }) -> LinkServiceViewModel {
        LinkServiceViewModel(deliveryId: deliveryId, api: api, signer: DeviceKeyFactorSigner(keys: keys, biometricOnly: true),
                             pinnedKeys: pinned ?? [statementKey.publicKey], environment: .staging, opener: opener, clock: clock, makeCode: makeCode)
    }

    /// True when a stored property of the model itself (recursively; not its collaborators, the recording opener and mock included) holds
    /// `secret`: the code must not outlive the hand-off.
    func holds(_ model: LinkServiceViewModel, _ secret: String) -> Bool {
        func scan(_ value: Any, depth: Int) -> Bool {
            if String(describing: value).contains(secret) { return true }
            guard depth < 4 else { return false }
            return Mirror(reflecting: value).children.contains { scan($0.value, depth: depth + 1) }
        }
        let collaborators: Set<String> = ["api", "_api", "opener", "_opener", "signer", "_signer"]
        return Mirror(reflecting: model).children.contains { child in !collaborators.contains(child.label ?? "") && scan(child.value, depth: 1) }
    }

    func keys(_ purpose: DeviceKeyPurpose = .approvalBiometric) async throws -> (SoftwareDeviceKeyStore, any ManagedSigningKey) {
        let store = SoftwareDeviceKeyStore(secrets: InMemorySecretStore())
        let key = try await store.createKey(for: purpose)
        return (store, key)
    }

    // MARK: Same device

    @Test func approveSignsTheVerifiedDisplayWithTheBiometricKeyAndACodeHash() async throws {
        let api = await api(try statement())
        let (store, key) = try await keys()
        let opener = LinkServiceOpener()
        let model = make(api, keys: store, opener: opener)
        await model.load()
        #expect(model.phase == .reviewing)
        // Who and where come from the signed display only.
        #expect(model.title == "Sign in to Acme Bank?")
        #expect(model.host?.full == "login.acme.example")
        #expect(model.service == "Acme online banking")
        #expect(model.subtitle == "Only approve if you asked Acme Bank to sign you in.")
        #expect(!model.asksForNumber && model.numberLabel == nil && model.canApprove)
        // Equal weight, safe actions first.
        #expect(model.buttons.map(\.role) == [.notMe, .deny, .approve])
        #expect(Set(model.buttons.map(\.style)) == [.neutralEqual])
        #expect(await api.submitted.isEmpty, "nothing is signed before a tap")
        #expect(opener.opened.isEmpty, "nothing is opened before a tap")

        await model.approve()
        #expect(model.phase == .opened)
        #expect(model.message == "Opened \u{2068}login.acme.example\u{2069}. Finish signing in there.")
        let sent = await api.submitted
        #expect(sent.count == 1 && sent[0].deliveryId == deliveryId)
        let parsed = try FactorAssertion.parse(sent[0].factor)
        try FactorAssertion.verifySignature(parsed, loggedKey: try key.publicKey.signingKey())
        #expect(parsed.claims.purpose == .linkOpen && parsed.claims.challengeId == ach && parsed.claims.decision == .approve)
        #expect(parsed.claims.userVerification == .biometric)
        #expect(parsed.claims.returnURL == Self.returnURL, "the exact signed return URL")
        #expect(parsed.claims.match == nil)
        #expect(parsed.claims.displayDigest == (try AuthorityDisplay.digest(Self.display())))
        #expect(parsed.claims.codeHash == Base64URL.encode(Data(SHA256.hash(data: Data(Self.fixedCode.utf8)))), "only the hash is sent")
        #expect(!sent[0].factor.contains(Self.fixedCode))
        // After acceptance: the signed return URL with the code in the fragment, opened once through the system, and the code is not kept.
        #expect(opener.opened.map(\.absoluteString) == [Self.returnURL + "#vdr_code=" + Self.fixedCode])
        #expect(!holds(model, Self.fixedCode))
    }

    @Test func denyAndThisWasntMeSignTheirDecisionWithoutCodeOrNumber() async throws {
        for (report, expected) in [(false, FactorDecision.deny), (true, .report)] {
            let api = await api(try statement())
            let (store, _) = try await keys()
            let model = make(api, keys: store)
            await model.load()
            if report { await model.thisWasntMe() } else { await model.deny() }
            #expect(model.phase == (report ? .reported : .denied))
            let parsed = try FactorAssertion.parse(try #require(await api.submitted.first).factor)
            #expect(parsed.claims.decision == expected && parsed.claims.codeHash == nil && parsed.claims.match == nil)
        }
    }

    // MARK: Statement verification

    @Test func aStatementThatDoesNotVerifyShowsNothingAndSignsNothing() async throws {
        let (store, _) = try await keys()
        let other = P256.Signing.PrivateKey()
        let base = Self.display()
        func replacing(_ key: String, _ value: JSONValue?) -> JSONValue {
            guard case .object(var o) = base else { return base }
            o[key] = value
            return .object(o)
        }
        let cases: [(String?, [P256.Signing.PublicKey]?)] = [
            (try statement(key: other), nil),                                                  // not a pinned key
            (try statement(), []),                                                             // no pins in this build: fail closed
            (try statement(environment: .production), nil),                                    // another environment
            (try statement(purpose: .oidcLogin, display: AuthorityDisplay.oidcLogin(clientName: "Acme", redirectURI: Self.returnURL, matchDigits: 2),
                           matchRequired: true), nil),                                         // another purpose
            (try statement(display: replacing("return_host", .string("evil.example"))), nil),  // host that is not the return URL's
            (try statement(display: replacing("return_url", .string("https://evil.example/x"))), nil), // display URL is not the signed one
            (try statement(display: replacing("extra", .string("x"))), nil),                   // a member the authority never builds
            (try statement(display: replacing("tenant_name", .string(""))), nil),              // no name
            (try statement(display: replacing("match_digits", .integer(2))), nil),             // a number without match_required
            (try statement(display: Self.display(), matchRequired: true), nil),                // match_required without match_digits
            (try statement(display: Self.display(returnURL: "http://login.acme.example/x"),
                           returnURL: "http://login.acme.example/x"), nil),                    // not https
            (nil, nil),                                                                        // no statement at all
            ("eyJhbGciOiJub25lIn0.e30.", nil),                                                 // garbage
        ]
        for (compact, pins) in cases {
            let api = await api(compact)
            let model = make(api, keys: store, pinned: pins)
            await model.load()
            #expect(model.phase == .cannotVerify)
            #expect(model.display == nil && model.title.isEmpty && !model.canApprove && !model.canRefuse)
            await model.approve()
            await model.deny()
            #expect(await api.submitted.isEmpty)
        }
    }

    @Test func endedDeliveriesAndMissingKeysStopBeforeAnythingIsShown() async throws {
        let (store, _) = try await keys()
        for (state, phase) in [(AuthLinkDisplay.State.expired, LinkServiceViewModel.Phase.expired), (.used, .alreadyAnswered), (.cancelled, .gone)] {
            let model = make(await api(try statement(), state: state), keys: store)
            await model.load()
            #expect(model.phase == phase)
        }
        let late = make(await api(try statement(), expiresIn: -1), keys: store)
        await late.load()
        #expect(late.phase == .expired)
        let expiredStatement = make(await api(try statement(lifetime: 30)), keys: store, clock: { LinkServiceApprovalTests.now.addingTimeInterval(60) })
        await expiredStatement.load()
        #expect(expiredStatement.phase == .expired)
        // Only the biometric approval key signs: a user-presence key alone is no key here.
        let (presenceOnly, _) = try await keys(.approvalUserPresence)
        let noKey = make(await api(try statement()), keys: presenceOnly)
        await noKey.load()
        #expect(noKey.phase == .noKey && noKey.display == nil)
        // Offline and unknown deliveries.
        let offlineAPI = MockLinkServiceDeviceAPI()
        await offlineAPI.set(readError: .offline)
        let offline = make(offlineAPI, keys: store)
        await offline.load()
        #expect(offline.phase == .offline && offline.offersTryAgain)
        let unknown = make(MockLinkServiceDeviceAPI(), keys: store)
        await unknown.load()
        #expect(unknown.phase == .gone)
    }

    // MARK: Number matching (a challenge that asks for one)

    @Test func aNumberIsTypedWhenTheChallengeAsksAndThreeRefusalsStop() async throws {
        let api = await api(try statement(matchRequired: true))
        let (store, _) = try await keys()
        let opener = LinkServiceOpener()
        let model = make(api, keys: store, opener: opener)
        await model.load()
        #expect(model.asksForNumber && model.numberLabel == "Number on Acme Bank")
        #expect(!model.canApprove)
        model.setEntry("42")   // a paste is refused
        #expect(model.entry.isEmpty)
        model.setEntry("4")
        model.setEntry("42")
        #expect(model.canApprove)
        await api.set(submitError: .refused)
        await model.approve()
        #expect(model.phase == .reviewing && model.wrongEntries == 1 && model.entry.isEmpty)
        #expect(model.notice == "That number doesn't match the one on Acme Bank. Check it and try again.")
        let first = try FactorAssertion.parse(try #require(await api.submitted.first).factor)
        #expect(first.claims.match == "42" && first.claims.codeHash == nil, "cross device: the number, never a code")
        for _ in 0..<2 {
            model.setEntry("1")
            model.setEntry("13")
            await model.approve()
        }
        #expect(model.phase == .stopped && opener.opened.isEmpty)

        // An accepted number: approved, and no hand-off (nothing opens on the phone).
        let ok = await self.api(try statement(matchRequired: true))
        let accepted = make(ok, keys: store, opener: opener)
        await accepted.load()
        accepted.setEntry("7")
        accepted.setEntry("73")
        await accepted.approve()
        #expect(accepted.phase == .approved && opener.opened.isEmpty)
        #expect(accepted.message == "Approved. Go back to Acme Bank to finish signing in.")
    }

    @Test func refusalsAndConflictsAfterSigningAreShownPlainly() async throws {
        let (store, _) = try await keys()
        for (error, phase) in [(LinkServiceError.refused, LinkServiceViewModel.Phase.refused), (.alreadyAnswered, .alreadyAnswered), (.expired, .expired),
                               (.offline, .offline), (.unavailable, .gone)] {
            let api = await api(try statement())
            await api.set(submitError: error)
            let opener = LinkServiceOpener()
            let model = make(api, keys: store, opener: opener)
            await model.load()
            await model.approve()
            #expect(model.phase == phase)
            #expect(opener.opened.isEmpty, "nothing is opened unless the authority accepted")
            #expect(!holds(model, Self.fixedCode), "and the code is discarded")
        }
    }

    // MARK: Same-device hand-off (ADR-0021 §5.3; SECURITY.md §2.110 "Device side")

    @Test func theHandOffOpensOnlyTheExactSignedReturnURLWithTheFragmentOnce() async throws {
        // A return URL with a query and percent-encoding: opened byte for byte, nothing rewritten, the code only in the fragment.
        let url = "https://login.acme.example/viadere/return?session=a%2Fb&x=1"
        let api = await api(try statement(display: Self.display(returnURL: url), returnURL: url))
        let (store, _) = try await keys()
        let opener = LinkServiceOpener()
        let model = make(api, keys: store, opener: opener)
        await model.load()
        await model.approve()
        #expect(model.phase == .opened)
        let opened = try #require(opener.opened.first)
        #expect(opened.absoluteString == url + "#vdr_code=" + Self.fixedCode, "the signed return_url, byte for byte, plus #vdr_code=")
        #expect(opened.scheme == "https" && opened.host == "login.acme.example" && opened.fragment == "vdr_code=" + Self.fixedCode)
        #expect(opened.query == "session=a%2Fb&x=1", "the code is never in the query, so the first request does not carry it")
        // Once: further taps (or a re-entrant approve) open nothing more.
        await model.approve()
        await model.deny()
        #expect(opener.opened.count == 1)
        #expect(await api.submitted.count == 1)
    }

    @Test func theDefaultCodeIs32RandomBytesAndOnlyItsHashWasSent() async throws {
        let (store, _) = try await keys()
        var seen = Set<String>()
        for _ in 0..<2 {
            let api = await api(try statement())
            let opener = LinkServiceOpener()
            let model = LinkServiceViewModel(deliveryId: deliveryId, api: api, signer: DeviceKeyFactorSigner(keys: store, biometricOnly: true),
                                             pinnedKeys: [statementKey.publicKey], environment: .staging, opener: opener, clock: { LinkServiceApprovalTests.now })
            await model.load()
            await model.approve()
            let fragment = try #require(opener.opened.first?.fragment)
            #expect(fragment.hasPrefix("vdr_code="))
            let code = String(fragment.dropFirst("vdr_code=".count))
            #expect(Base64URL.decode(code)?.count == 32 && code.count == 43, "32 random bytes, base64url without padding")
            let sent = try #require(await api.submitted.first)
            #expect(!sent.factor.contains(code), "the code itself never left the phone before the hand-off")
            #expect(try FactorAssertion.parse(sent.factor).claims.codeHash == Base64URL.encode(Data(SHA256.hash(data: Data(code.utf8)))))
            #expect(!holds(model, code))
            seen.insert(code)
        }
        #expect(seen.count == 2, "a fresh code for every approval")
    }

    @Test func nothingOpensOnDenyReportRefusalTimeoutOrAnAnswerOtherThanApprove() async throws {
        let (store, _) = try await keys()
        // Deny and This wasn't me.
        for report in [false, true] {
            let opener = LinkServiceOpener()
            let model = make(await api(try statement()), keys: store, opener: opener)
            await model.load()
            if report { await model.thisWasntMe() } else { await model.deny() }
            #expect(opener.opened.isEmpty)
        }
        // Every failure of the submission, a timeout (offline) included.
        for error in [LinkServiceError.refused, .alreadyAnswered, .expired, .offline, .unavailable, .notActive] {
            let api = await api(try statement())
            await api.set(submitError: error)
            let opener = LinkServiceOpener()
            let model = make(api, keys: store, opener: opener)
            await model.load()
            await model.approve()
            #expect(opener.opened.isEmpty, "\(error)")
        }
        // The server answered an approve with something other than an acceptance.
        for answer in [FactorDecision.deny, .report] {
            let api = FixedAnswerLinkServiceAPI(inner: await api(try statement()), answer: answer)
            let opener = LinkServiceOpener()
            let model = make(api, keys: store, opener: opener)
            await model.load()
            await model.approve()
            #expect(model.phase == .denied && opener.opened.isEmpty)
        }
    }

    @Test func nothingOpensWhenTheRequestExpiredBeforeTheAcceptanceArrived() async throws {
        let (store, _) = try await keys()
        let clock = TestClock(LinkServiceApprovalTests.now)
        // The acceptance arrives after the signed statement expired (a slow network): the code is discarded and nothing opens.
        let api = FixedAnswerLinkServiceAPI(inner: await api(try statement(lifetime: 120)), answer: .approve, advance: (clock, 200))
        let opener = LinkServiceOpener()
        let model = make(api, keys: store, opener: opener, clock: { clock.now })
        await model.load()
        await model.approve()
        #expect(opener.opened.isEmpty)
        #expect(model.phase == .notFinished)
        #expect(model.message == "We couldn't open \u{2068}login.acme.example\u{2069}, so you're not signed in. Ask for a new link where you started signing in.")
        #expect(!holds(model, Self.fixedCode))
    }

    @Test func aSystemThatCannotOpenTheLinkDiscardsTheCodeAndSaysTheSignInDidNotFinish() async throws {
        let (store, _) = try await keys()
        let opener = LinkServiceOpener(result: false)
        let model = make(await api(try statement()), keys: store, opener: opener)
        await model.load()
        await model.approve()
        #expect(opener.opened.count == 1, "tried once, never retried")
        #expect(model.phase == .notFinished)
        #expect(model.message == "We couldn't open \u{2068}login.acme.example\u{2069}, so you're not signed in. Ask for a new link where you started signing in.")
        #expect(!holds(model, Self.fixedCode))
        await model.approve()
        #expect(opener.opened.count == 1)
    }

    @Test func aHandOffThatWouldNotBeTheExactSignedURLIsNeverSigned() async throws {
        let (store, _) = try await keys()
        // A code that is not 32 bytes of base64url (the generator is replaceable only in tests): nothing is signed, sent or opened.
        for bad in [String(repeating: "A", count: 42), String(repeating: "A", count: 42) + "+", String(repeating: "A", count: 42) + "&", ""] {
            let api = await api(try statement())
            let opener = LinkServiceOpener()
            let model = make(api, keys: store, opener: opener, makeCode: { bad })
            await model.load()
            await model.approve()
            #expect(model.phase == .notFinished && opener.opened.isEmpty)
            #expect(await api.submitted.isEmpty)
        }
        // A signed return URL the system would not open as signed (a port other than 443): refused before signing.
        let ported = "https://login.acme.example:8443/viadere/return"
        let api = await api(try statement(display: Self.display(returnURL: ported), returnURL: ported))
        let opener = LinkServiceOpener()
        let model = make(api, keys: store, opener: opener)
        await model.load()
        await model.approve()
        #expect(model.phase == .notFinished && opener.opened.isEmpty)
        #expect(await api.submitted.isEmpty)
    }

    @Test func theHandOffURLBuilderKeepsTheSignedBytes() {
        let code = Self.fixedCode
        #expect(LinkServiceHandoff.url(returnURL: Self.returnURL, host: "login.acme.example", code: code)?.absoluteString == Self.returnURL + "#vdr_code=" + code)
        // Every way the result would differ from the signed URL, or leave https on the signed host, is refused.
        #expect(LinkServiceHandoff.url(returnURL: Self.returnURL, host: "evil.example", code: code) == nil)
        #expect(LinkServiceHandoff.url(returnURL: "http://login.acme.example/x", host: "login.acme.example", code: code) == nil)
        #expect(LinkServiceHandoff.url(returnURL: "HTTPS://login.acme.example/x", host: "login.acme.example", code: code) == nil)
        #expect(LinkServiceHandoff.url(returnURL: "https://login.acme.example/x#frag", host: "login.acme.example", code: code) == nil)
        #expect(LinkServiceHandoff.url(returnURL: "https://user@login.acme.example/x", host: "login.acme.example", code: code) == nil)
        #expect(LinkServiceHandoff.url(returnURL: "https://login.acme.example/a b", host: "login.acme.example", code: code) == nil)
        #expect(LinkServiceHandoff.url(returnURL: "https://login.acme.example/x", host: "login.acme.example", code: "short") == nil)
        #expect(LinkServiceHandoff.url(returnURL: "https://login.acme.example/" + String(repeating: "a", count: 2048), host: "login.acme.example", code: code) == nil)
    }

    // MARK: Routing

    @Test func aLinkServiceDeliveryRoutesToItsOwnScreen() async throws {
        let api = MockAuthDeliveryAPI()
        var display = AuthDeliveryDisplay(id: AuthDeliveryID(deliveryId), method: .magicLink, purpose: .signIn, template: "auth.sign_in_link.v1", status: .delivered,
                                          businessId: BusinessID(), businessName: "Acme Bank", expiresAt: Self.now.addingTimeInterval(300), createdAt: Self.now,
                                          requestId: "req-1", destinationHost: "login.acme.example")
        display.linkMode = .viadere
        display.authorityChallenge = try statement()
        let item = try AuthDeliveryItem(display: display)
        #expect(item.linkService)
        await api.add(item)
        #expect(await AuthDeliverySurface.resolve(deliveryId: deliveryId, api: api) == .linkService)
        // A business link stays on the business-link screen.
        display.linkMode = nil
        display.authorityChallenge = nil
        let business = try AuthDeliveryItem(display: display)
        await api.add(business)
        #expect(await AuthDeliverySurface.resolve(deliveryId: deliveryId, api: api) == .link)
        #expect(AuthDeliverySurface.linkService.message == nil)
    }

    @Test func theUnavailableClientFailsClosed() async {
        let api = UnavailableLinkServiceDeviceAPI()
        await #expect(throws: LinkServiceError.unavailable) { _ = try await api.delivery(deliveryId: UUID()) }
        await #expect(throws: LinkServiceError.unavailable) { _ = try await api.submit(deliveryId: UUID(), factor: "x") }
    }
}

/// The system opener, recorded. `result: false` is a device that has no handler for the URL.
@MainActor
final class LinkServiceOpener: SystemURLOpening {
    private(set) var opened: [URL] = []
    let result: Bool
    nonisolated init(result: Bool = true) { self.result = result }
    func open(_ url: URL) async -> Bool { opened.append(url); return result }
}

final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Date
    init(_ value: Date) { self.value = value }
    var now: Date { lock.withLock { value } }
    func advance(_ seconds: TimeInterval) { lock.withLock { value = value.addingTimeInterval(seconds) } }
}

/// Wraps the mock and answers every submission with `answer` (optionally moving the clock first, as a slow network would).
struct FixedAnswerLinkServiceAPI: LinkServiceDeviceAPI {
    let inner: MockLinkServiceDeviceAPI
    let answer: FactorDecision
    var advance: (TestClock, TimeInterval)? = nil
    func delivery(deliveryId: UUID) async throws -> LinkServiceDelivery { try await inner.delivery(deliveryId: deliveryId) }
    func submit(deliveryId: UUID, factor: String) async throws -> FactorDecision {
        _ = try await inner.submit(deliveryId: deliveryId, factor: factor)
        if let (clock, seconds) = advance { clock.advance(seconds) }
        return answer
    }
}
