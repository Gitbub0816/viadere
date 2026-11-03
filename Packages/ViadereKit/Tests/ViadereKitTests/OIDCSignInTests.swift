import Crypto
import Foundation
import Testing
import ViadereCore
@testable import ViadereKit

/// The phone side of "Sign in with Viadere" (ADR-0024 §4 method 2, §8; UX_COPY OIDC-05, OIDC-08 to OIDC-10; FLOW_MATRIX F13).
@MainActor
struct OIDCSignInTests {
    nonisolated static let now = Date(timeIntervalSince1970: 1_800_000_000)
    let statementKey = P256.Signing.PrivateKey()
    let ach = AuthorityChallengeID.generate()

    /// An authority-built `oidc_login` statement, signed like the authority signs it (`viadere-challenge+jws`, kid = RFC 7638 thumbprint).
    func statement(key: P256.Signing.PrivateKey? = nil, challengeId: String? = nil, environment: AuthorityEnvironment = .staging, display: JSONValue? = nil,
                   redirect: String = "https://rp.example.com/callback", lifetime: Int64 = 120) throws -> String {
        let signer = key ?? statementKey
        let t = Int64(Self.now.timeIntervalSince1970)
        let shown = display ?? AuthorityDisplay.oidcLogin(clientName: "Example Shop", redirectURI: redirect, matchDigits: 2)
        let payload = AuthorityChallengeStatement(environment: environment, challengeId: challengeId ?? ach, nonce: AuthorityNonce.generate(), purpose: .oidcLogin,
                                                  display: shown, redirectURI: redirect, matchRequired: true, issuedAt: t, expiresAt: t + lifetime).payload
        let input = try AuthorityJWS.signingInput(alg: "ES256", kid: JWKThumbprint.p256(signer.publicKey), typ: AuthorityChallengeStatement.type, payload: payload)
        return input + "." + ViadereSignatureEncoding.encode(try signer.signature(for: Data(input.utf8)))
    }

    func make(_ api: MockOIDCDeviceAPI, keys: SoftwareDeviceKeyStore, pinned: [P256.Signing.PublicKey]? = nil,
              clock: @escaping @Sendable () -> Date = { OIDCSignInTests.now }) -> OIDCSignInViewModel {
        OIDCSignInViewModel(challengeId: ach, api: api, signer: DeviceKeyFactorSigner(keys: keys), pinnedKeys: pinned ?? [statementKey.publicKey],
                            environment: .staging, clock: clock)
    }

    func keys(_ purpose: DeviceKeyPurpose = .approvalBiometric) async throws -> (SoftwareDeviceKeyStore, any ManagedSigningKey) {
        let store = SoftwareDeviceKeyStore(secrets: InMemorySecretStore())
        let key = try await store.createKey(for: purpose)
        return (store, key)
    }

    // MARK: Statement verification

    @Test func approveSignsTheTypedNumberOverTheVerifiedDisplayAndShowsApprovedOnlyAfterTheAuthorityAccepted() async throws {
        let api = MockOIDCDeviceAPI()
        await api.set(statement: try statement(), for: ach)
        let (store, key) = try await keys()
        let model = make(api, keys: store)
        await model.load()
        #expect(model.phase == .reviewing)
        #expect(model.title == "Sign in to Example Shop?")
        #expect(model.host?.full == "rp.example.com")
        #expect(model.consentText?.contains("You'll return to rp.example.com.") == true)
        #expect(!model.canApprove)
        model.setEntry("42")          // a paste is refused
        #expect(model.entry.isEmpty)
        model.setEntry("0")           // no leading zero
        #expect(model.entry.isEmpty)
        model.setEntry("4")
        model.setEntry("4x")
        #expect(model.entry == "4")
        model.setEntry("42")
        model.setEntry("427")
        #expect(model.entry == "42")
        #expect(model.canApprove)
        await model.approve()
        #expect(model.phase == .approved)

        let sent = await api.submitted
        #expect(sent.count == 1)
        let parsed = try FactorAssertion.parse(sent[0].factor)
        try FactorAssertion.verifySignature(parsed, loggedKey: try key.publicKey.signingKey())
        #expect(parsed.claims.challengeId == ach)
        #expect(parsed.claims.match == "42")
        #expect(parsed.claims.decision == .approve)
        #expect(parsed.claims.userVerification == .biometric)
        #expect(parsed.claims.audience == AuthorityEnvironment.staging.authorityURN)
        let display = AuthorityDisplay.oidcLogin(clientName: "Example Shop", redirectURI: "https://rp.example.com/callback", matchDigits: 2)
        #expect(parsed.claims.displayDigest == (try AuthorityDisplay.digest(display)))
    }

    @Test func aStatementThatDoesNotVerifyShowsNothingAndSignsNothing() async throws {
        let (store, _) = try await keys()
        let other = P256.Signing.PrivateKey()
        let cases: [(String, [P256.Signing.PublicKey]?)] = [
            (try statement(key: other), nil),                                   // not a pinned key
            (try statement(), []),                                              // no pins in this build: fail closed
            (try statement(challengeId: AuthorityChallengeID.generate()), nil), // another challenge
            (try statement(environment: .production), nil),                     // another environment
            (try statement(display: .object(["v": .integer(1), "purpose": .string("oidc_login"), "client_name": .string("Example Shop"),
                                              "redirect_uri": .string("https://rp.example.com/callback"), "redirect_host": .string("evil.example"),
                                              "match_digits": .integer(2)])), nil), // host that is not the redirect's
            (try statement(display: .object(["v": .integer(1), "purpose": .string("oidc_login"), "client_name": .string("Example Shop"),
                                              "redirect_uri": .string("https://rp.example.com/callback"), "redirect_host": .string("rp.example.com"),
                                              "match_digits": .integer(2), "note": .string("Approve now")])), nil), // a member the authority never builds
        ]
        for (compact, pins) in cases {
            let api = MockOIDCDeviceAPI()
            await api.set(statement: compact, for: ach)
            let model = make(api, keys: store, pinned: pins)
            await model.load()
            #expect(model.phase == .cannotVerify)
            #expect(model.message == OIDCCopy.cannotVerify)
            #expect(model.display == nil)
            model.setEntry("4")
            model.setEntry("42")
            await model.approve()
            #expect(await api.submitted.isEmpty)
        }
    }

    @Test func expiredStatementAndMissingApprovalKeyStopBeforeSigning() async throws {
        let api = MockOIDCDeviceAPI()
        await api.set(statement: try statement(lifetime: 30), for: ach)
        let (store, _) = try await keys()
        let late = make(api, keys: store, clock: { OIDCSignInTests.now.addingTimeInterval(200) })
        await late.load()
        #expect(late.phase == .cannotVerify || late.phase == .expired)
        let noKey = make(api, keys: SoftwareDeviceKeyStore(secrets: InMemorySecretStore()))
        await noKey.load()
        #expect(noKey.phase == .noKey)
    }

    // MARK: Consent (OIDC-05) and refusals

    @Test func consentCopyIsShownOnlyOnFirstUse() async throws {
        let api = MockOIDCDeviceAPI()
        await api.set(statement: try statement(), for: ach)
        await api.set(consents: [OIDCConsentView(clientId: "ocl_example", clientName: "Example Shop", host: "rp.example.com", grantedAt: Self.now, lastUsedAt: Self.now)])
        let (store, _) = try await keys()
        let model = make(api, keys: store)
        await model.load()
        #expect(!model.showsConsent)
        #expect(model.consentText == nil)
        // Same name on another host is not the same consent.
        await api.set(consents: [OIDCConsentView(clientId: "ocl_example", clientName: "Example Shop", host: "other.example", grantedAt: Self.now, lastUsedAt: Self.now)])
        let again = make(api, keys: store)
        await again.load()
        #expect(again.showsConsent)
    }

    @Test func threeRefusedNumbersStopTheScreenAndTheEntryNeverPersists() async throws {
        let api = MockOIDCDeviceAPI()
        await api.set(statement: try statement(), for: ach)
        await api.set(submitError: .refused)
        let (store, _) = try await keys()
        let model = make(api, keys: store)
        await model.load()
        for attempt in 1...3 {
            model.setEntry("1")
            model.setEntry("1\(attempt)")
            await model.approve()
            #expect(model.entry.isEmpty)
            if attempt < 3 {
                #expect(model.phase == .reviewing)
                #expect(model.notice == OIDCCopy.wrongNumber)
            }
        }
        #expect(model.phase == .stopped)
        #expect(!model.canApprove && !model.canRefuse)
        #expect(await api.submitted.count == 3)
    }

    @Test func denyAndThisWasntMeSignNoNumber() async throws {
        let (store, _) = try await keys(.approvalUserPresence)
        for report in [false, true] {
            let api = MockOIDCDeviceAPI()
            await api.set(statement: try statement(), for: ach)
            let model = make(api, keys: store)
            await model.load()
            model.setEntry("4")
            if report { await model.thisWasntMe() } else { await model.deny() }
            #expect(model.phase == (report ? .reported : .denied))
            let parsed = try FactorAssertion.parse(try #require(await api.submitted.first).factor)
            #expect(parsed.claims.decision == (report ? .report : .deny))
            #expect(parsed.claims.match == nil)
            #expect(parsed.claims.userVerification == .userPresence)
        }
    }

    @Test func aUserPresenceKeyNeverClaimsBiometric() async throws {
        let (store, _) = try await keys(.approvalUserPresence)
        let signer = DeviceKeyFactorSigner(keys: store)
        #expect(await signer.userVerification() == .userPresence)
        let claims = FactorAssertionClaims(audience: "urn:viadere:authority:stg", challengeId: ach, nonce: AuthorityNonce.generate(), purpose: .oidcLogin,
                                           displayDigest: String(repeating: "a", count: 64), decision: .approve, userVerification: .biometric, match: "42",
                                           issuedAt: 1, expiresAt: 2)
        await #expect(throws: AuthorityFactorSigningError.keyMismatch) { try await signer.sign(claims, prompt: .generic) }
    }

    // MARK: Consent list (OIDC-09, OIDC-10)

    @Test func consentListAndReduceOnlyRevoke() async throws {
        let api = MockOIDCDeviceAPI()
        let older = OIDCConsentView(clientId: "ocl_older", clientName: "Older Shop", host: "older.example", grantedAt: Self.now, lastUsedAt: Self.now)
        let newer = OIDCConsentView(clientId: "ocl_newer", clientName: "Newer Shop", host: "newer.example", grantedAt: Self.now, lastUsedAt: Self.now.addingTimeInterval(60))
        await api.set(consents: [older, newer])
        let model = OIDCConsentsViewModel(api: api)
        await model.load()
        #expect(model.title == "Apps you've signed in to with Viadere")
        #expect(model.consents.map(\.clientId) == ["ocl_newer", "ocl_older"])
        #expect(model.row(newer, formatter: { _ in "today" }) == "Newer Shop, last used today")
        #expect(model.revokeTitle(older) == "Stop Older Shop recognizing me")
        await model.revoke(older)
        #expect(model.consents.map(\.clientId) == ["ocl_newer"])
        #expect(await api.revoked == ["ocl_older"])

        let off = OIDCConsentsViewModel(api: UnavailableOIDCDeviceAPI())
        await off.load()
        #expect(off.phase == .unavailable)
    }

    // MARK: Routing and pins

    @Test func theQRUniversalLinkAndThePushOpenTheConfirmScreenOnly() async throws {
        let domain = LinkDomain("viadere.cksites.dev")!
        #expect(DeepLinkRouter.route("https://viadere.cksites.dev/o/\(ach)", domain: domain) == .oidcSignIn(challengeId: ach))
        for bad in ["https://viadere.cksites.dev/o/\(ach)?x=1", "https://viadere.cksites.dev/o/\(ach)#n=42", "https://evil.example/o/\(ach)",
                    "https://viadere.cksites.dev/o/ach_short", "https://viadere.cksites.dev/o/\(ach)/more", "http://viadere.cksites.dev/o/\(ach)",
                    "https://viadere.cksites.dev:8443/o/\(ach)", "viadere://o/\(ach)"] {
            #expect(DeepLinkRouter.route(bad, domain: domain) == nil, "\(bad)")
        }
        #expect(PushPayload.target(category: "viadere.oidc", userInfo: ["ach": ach]) == .oidcSignIn(ach))
        #expect(PushPayload.target(category: "viadere.oidc", userInfo: ["ach": "nope"]) == nil)
        #expect(PushPayload.target(category: "viadere.approve", userInfo: ["ach": ach]) == .pendingRequests)
        #expect(AuthNotificationCategory.oidcCategory.actions.map(\.identifier) == [AuthNotificationCategory.reviewAction])

        let services = await ViadereServices.mock()
        let outcome = await services.notificationHandler.handle(NotificationResponseInfo(actionIdentifier: "com.apple.UNNotificationDefaultActionIdentifier",
                                                                                         categoryIdentifier: "viadere.oidc", userInfo: ["ach": ach]))
        #expect(outcome == .openOIDCSignIn(ach))
        let watch = await services.notificationHandler.handle(NotificationResponseInfo(actionIdentifier: "com.apple.UNNotificationDefaultActionIdentifier",
                                                                                       categoryIdentifier: "viadere.oidc", userInfo: ["ach": ach]), fromWatch: true)
        #expect(watch == .ignored)
    }

    @Test func statementKeysMustBeInTheBuildAndInCore() {
        let key = P256.Signing.PrivateKey().publicKey
        let encoded = Base64URL.encode(key.x963Representation)
        #expect(AuthorityStatementKeyPins.parse(encoded).count == 1)
        #expect(AuthorityStatementKeyPins.parse(encoded + ",broken").isEmpty)
        #expect(AuthorityStatementKeyPins.parse("$(VIADERE_AUTHORITY_STATEMENT_KEYS)").isEmpty)
        #expect(AuthorityStatementKeyPins.parse(encoded + "," + encoded).isEmpty)
        #expect(AuthorityStatementKeyPins.effective([key], pinnedKids: []).isEmpty)
        #expect(AuthorityStatementKeyPins.effective([key], pinnedKids: [JWKThumbprint.p256(key)]).count == 1)
        // Core pins nothing yet: every build fails closed until the attested inventory is pinned (S6-06).
        var configuration = ViadereConfiguration.local
        configuration.authorityStatementKeys = [encoded]
        #expect(AuthorityStatementKeyPins.effective(configuration: configuration).isEmpty == AuthorityPinnedKeys.deviceStatementKids(.staging).isEmpty)
    }
}
