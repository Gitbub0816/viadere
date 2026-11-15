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

    func make(_ api: MockLinkServiceDeviceAPI, keys: SoftwareDeviceKeyStore, pinned: [P256.Signing.PublicKey]? = nil,
              clock: @escaping @Sendable () -> Date = { LinkServiceApprovalTests.now }) -> LinkServiceViewModel {
        LinkServiceViewModel(deliveryId: deliveryId, api: api, signer: DeviceKeyFactorSigner(keys: keys, biometricOnly: true),
                             pinnedKeys: pinned ?? [statementKey.publicKey], environment: .staging, clock: clock, makeCode: { LinkServiceApprovalTests.fixedCode })
    }

    func keys(_ purpose: DeviceKeyPurpose = .approvalBiometric) async throws -> (SoftwareDeviceKeyStore, any ManagedSigningKey) {
        let store = SoftwareDeviceKeyStore(secrets: InMemorySecretStore())
        let key = try await store.createKey(for: purpose)
        return (store, key)
    }

    // MARK: Same device

    @Test func approveSignsTheVerifiedDisplayWithTheBiometricKeyAndACodeHashAndOpensNothing() async throws {
        let api = await api(try statement())
        let (store, key) = try await keys()
        let model = make(api, keys: store)
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

        await model.approve()
        #expect(model.phase == .approved)
        #expect(model.message == "Approved. Go back to Acme Bank to finish signing in.")
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
        // The hand-off is kept, redacted, and never opened (there is no opener to call).
        #expect(model.handoff?.url == Self.returnURL + "#vdr_code=" + Self.fixedCode)
        #expect(!String(describing: model.handoff as Any).contains(Self.fixedCode))
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
            #expect(model.handoff == nil)
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
        let model = make(api, keys: store)
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
        #expect(model.phase == .stopped && model.handoff == nil)

        // An accepted number: approved, and no hand-off (nothing opens on the phone).
        let ok = await self.api(try statement(matchRequired: true))
        let accepted = make(ok, keys: store)
        await accepted.load()
        accepted.setEntry("7")
        accepted.setEntry("73")
        await accepted.approve()
        #expect(accepted.phase == .approved && accepted.handoff == nil)
    }

    @Test func refusalsAndConflictsAfterSigningAreShownPlainly() async throws {
        let (store, _) = try await keys()
        for (error, phase) in [(LinkServiceError.refused, LinkServiceViewModel.Phase.refused), (.alreadyAnswered, .alreadyAnswered), (.expired, .expired),
                               (.offline, .offline), (.unavailable, .gone)] {
            let api = await api(try statement())
            await api.set(submitError: error)
            let model = make(api, keys: store)
            await model.load()
            await model.approve()
            #expect(model.phase == phase)
            #expect(model.handoff == nil, "nothing is kept unless the authority accepted")
        }
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
