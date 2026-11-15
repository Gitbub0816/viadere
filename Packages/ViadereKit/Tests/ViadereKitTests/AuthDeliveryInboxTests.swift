import Testing
import Foundation
import ViadereCore
@testable import ViadereKit

// `MovableClock` (a clock the test moves) is shared with OrganizationKitTests.

private let t0 = Date(timeIntervalSince1970: 1_800_000_000)
private let acme = BusinessID()

private func item(_ kind: AuthDeliveryItem.Kind, id: UUID = UUID(), business: String = "Acme", businessId: BusinessID = acme, createdAgo: TimeInterval = 10,
                  expiresIn: TimeInterval = 300, state: AuthLinkDisplay.State = .open, silent: Bool = false) -> AuthDeliveryItem {
    AuthDeliveryItem(deliveryId: id, kind: kind, businessId: businessId, business: business, host: kind == .link ? "login.acme.com" : nil,
                     createdAt: t0.addingTimeInterval(-createdAgo), expiresAt: t0.addingTimeInterval(expiresIn), state: state, silent: silent)
}

private func wire(_ id: UUID, method: AuthDeliveryMethod, status: AuthDeliveryStatus = .delivered, name: String = "Acme", host: String? = nil,
                  codeKind: AuthCodeKind? = nil, expiresIn: TimeInterval = 300) -> AuthDeliveryDisplay {
    AuthDeliveryDisplay(id: AuthDeliveryID(id), method: method, purpose: .signIn, template: "auth.sign_in_code.v1", status: status, businessId: acme,
                        businessName: name, expiresAt: t0.addingTimeInterval(expiresIn), createdAt: t0, requestId: "req-1", destinationHost: host,
                        destinationStatement: host == nil ? nil : "eyJ.statement.sig", codeKind: codeKind, variables: ["reference": "A-17"])
}

private func body<T: Encodable>(_ value: T) -> String { String(decoding: try! ViadereJSON.encode(value), as: UTF8.self) }

// MARK: - The live client

@Suite("Auth delivery: live client (ADR-0020 device routes)")
struct LiveAuthDeliveryAPITests {
    @Test func theListIsReadFromTheRouteCatalogAndMalformedRowsAreDropped() async throws {
        let env = try await ClientEnv()
        let link = UUID(), code = UUID(), bad = UUID()
        let rows = [wire(link, method: .magicLink, host: "login.acme.com"), wire(code, method: .otp, codeKind: .totp),
                    wire(bad, method: .magicLink, host: "LOGIN.acme.com"), wire(code, method: .otp)]
        let transport = FakeTransport { _, _ in json(body(rows)) }
        let api = LiveAuthDeliveryAPI(client: env.client(transport: transport).0)

        let items = try await api.deliveries()
        #expect(items.map(\.deliveryId) == [link, code], "an upper-case host is refused; a repeated id is listed once")
        #expect(items[0].kind == .link && items[0].host == "login.acme.com")
        #expect(items[1].kind == .code(.totp))
        let request = try #require(transport.requests.first)
        #expect(request.method == .GET && pathAndQuery(request.url) == "/v1/auth-deliveries")
        #expect(request.headers["Authorization"] == "Bearer tok-1")
        _ = try SignedRequestHeaders(headers: request.headers)
        #expect(transport.requests.count == 1)
    }

    @Test func theDisplayObjectCarriesNoSecretAndMustBeAboutTheDeliveryAskedFor() async throws {
        let env = try await ClientEnv()
        let id = UUID()
        let transport = FakeTransport { _, _ in json(body(wire(id, method: .magicLink, host: "login.acme.com"))) }
        let api = LiveAuthDeliveryAPI(client: env.client(transport: transport).0)

        let display = try await api.linkDisplay(deliveryId: id)
        #expect(display.host == "login.acme.com" && display.business == "Acme" && display.state == .open)
        #expect(!display.businessVerified, "the name is the api's, not the authority record's")
        #expect(pathAndQuery(try #require(transport.requests.first).url) == "/v1/auth-deliveries/\(AuthDeliveryID(id).description)")
        #expect(transport.requests.allSatisfy { $0.method == .GET }, "looking never opens")
        // The item has no place for a URL, a code or the variables. The destination statement is a digest of the URL, not a bearer value (class T,
        // ADR-0031 §3); it rides along, with the request id, only so the link screen can verify it (ADR-0031 §4).
        let labels = Set(Mirror(reflecting: try await api.item(deliveryId: id)).children.compactMap(\.label))
        #expect(labels == ["deliveryId", "kind", "businessId", "business", "host", "purpose", "createdAt", "expiresAt", "state", "silent", "requestId",
                           "destinationStatement", "linkService"])

        await #expect(throws: AuthDeliveryError.failed) { _ = try await api.item(deliveryId: UUID()) }
    }

    @Test func aCodeIsNotALinkAndAHostOnACodeIsRefused() async throws {
        let env = try await ClientEnv()
        let id = UUID()
        let code = LiveAuthDeliveryAPI(client: env.client(transport: FakeTransport { _, _ in json(body(wire(id, method: .otp))) }).0)
        await #expect(throws: AuthDeliveryError.notActive) { _ = try await code.linkDisplay(deliveryId: id) }
        let odd = LiveAuthDeliveryAPI(client: env.client(transport: FakeTransport { _, _ in json(body(wire(id, method: .otp, host: "acme.com"))) }).0)
        await #expect(throws: AuthDeliveryError.failed) { _ = try await odd.item(deliveryId: id) }
        let unreadable = LiveAuthDeliveryAPI(client: env.client(transport: FakeTransport { _, _ in json(#"{"id":"nope"}"#) }).0)
        await #expect(throws: AuthDeliveryError.failed) { _ = try await unreadable.item(deliveryId: id) }
    }

    @Test func statusesMapToWhatTheScreensKnow() throws {
        let id = UUID()
        func state(_ status: AuthDeliveryStatus) throws -> AuthLinkDisplay.State { try AuthDeliveryItem(display: wire(id, method: .otp, status: status)).state }
        for status in [AuthDeliveryStatus.queued, .sent, .delivered] { #expect(try state(status) == .open) }
        for status in [AuthDeliveryStatus.opened, .completed, .failed] { #expect(try state(status) == .used) }
        #expect(try state(.expired) == .expired)
        for status in [AuthDeliveryStatus.cancelled, .denied] { #expect(try state(status) == .cancelled) }
    }

    @Test func openingACodeReturnsItOnceAndChecksWhatCameBack() async throws {
        let env = try await ClientEnv()
        let id = UUID()
        let good = AuthDeliveryOpenResponse(id: AuthDeliveryID(id), method: .otp, code: "482913", codeKind: .otp, openedAt: t0)
        let transport = FakeTransport { _, _ in json(body(good)) }
        let api = LiveAuthDeliveryAPI(client: env.client(transport: transport).0)
        let code = try await api.openCode(deliveryId: id)
        #expect(code.value == "482913" && code.kind == .otp)
        let request = try #require(transport.requests.first)
        #expect(request.method == .POST && pathAndQuery(request.url) == "/v1/auth-deliveries/\(AuthDeliveryID(id).description)/open")

        // A URL where a code was asked for, a code that is not a code, or an answer about another delivery: refused.
        let wrong = [AuthDeliveryOpenResponse(id: AuthDeliveryID(id), method: .magicLink, url: "https://login.acme.com/x", openedAt: t0),
                     AuthDeliveryOpenResponse(id: AuthDeliveryID(id), method: .otp, url: "https://login.acme.com/x", code: "482913", openedAt: t0),
                     AuthDeliveryOpenResponse(id: AuthDeliveryID(id), method: .otp, code: "48 29", openedAt: t0),
                     AuthDeliveryOpenResponse(id: AuthDeliveryID(id), method: .otp, code: nil, openedAt: t0),
                     AuthDeliveryOpenResponse(id: AuthDeliveryID(), method: .otp, code: "482913", openedAt: t0)]
        for answer in wrong {
            let api = LiveAuthDeliveryAPI(client: env.client(transport: FakeTransport { _, _ in json(body(answer)) }).0)
            await #expect(throws: AuthDeliveryError.failed) { _ = try await api.openCode(deliveryId: id) }
        }
    }

    @Test func serverRefusalsMapToTypedErrorsAndOnlyTransportIsOffline() async throws {
        let env = try await ClientEnv()
        let id = UUID()
        func open(_ status: Int, _ code: String) async -> AuthDeliveryError? {
            let api = LiveAuthDeliveryAPI(client: env.client(transport: FakeTransport { _, _ in json(status, errorBody(code)) }).0)
            do { _ = try await api.openCode(deliveryId: id); return nil } catch { return error as? AuthDeliveryError }
        }
        #expect(await open(410, "gone") == .expired)
        #expect(await open(409, "already_opened") == .alreadyUsed)
        #expect(await open(409, "conflict") == .alreadyUsed)
        #expect(await open(404, "not_found") == .notActive)
        #expect(await open(429, "rate_limited") == .failed)
        #expect(await open(500, "internal") == .failed)

        let offline = FakeTransport { _, _ in throw APIError.transport("offline") }
        let api = LiveAuthDeliveryAPI(client: env.client(transport: offline).0)
        await #expect(throws: AuthDeliveryError.offline) { _ = try await api.openCode(deliveryId: id) }
        await #expect(throws: AuthDeliveryError.offline) { _ = try await api.deliveries() }
        await #expect(throws: AuthDeliveryError.offline) { _ = try await api.item(deliveryId: id) }
        #expect(offline.requests.count == 3, "one attempt each: nothing is retried or queued")
    }

    @Test func aLinkIsNeverOpenedWhileDestinationsCannotBeVerified() async throws {
        let env = try await ClientEnv()
        let id = UUID()
        let answer = AuthDeliveryOpenResponse(id: AuthDeliveryID(id), method: .magicLink, url: "https://login.acme.com/finish?t=1", openedAt: t0)
        let transport = FakeTransport { _, _ in json(body(answer)) }
        // What ships: destination verification is off, so the URL is never even requested and the delivery is never consumed.
        let shipping = LiveAuthDeliveryAPI(client: env.client(transport: transport).0)
        await #expect(throws: AuthDeliveryError.unavailable) { _ = try await shipping.openLink(deliveryId: id) }
        let staging = LiveAuthDeliveryAPI(client: env.client(transport: transport).0, flags: .staging)
        await #expect(throws: AuthDeliveryError.unavailable) { _ = try await staging.openLink(deliveryId: id) }
        #expect(transport.requests.isEmpty)

        // With verification (Stage 6) the URL comes back once and must be a strict https destination.
        let verified = LiveAuthDeliveryAPI(client: env.client(transport: transport).0, flags: AuthDeliveryFlags(destinationVerification: true))
        #expect(try await verified.openLink(deliveryId: id).absoluteString == "https://login.acme.com/finish?t=1")
        for bad in ["http://login.acme.com/x", "https://user@login.acme.com/x", "https://login.acme.com:8443/x", "javascript:alert(1)"] {
            let answer = AuthDeliveryOpenResponse(id: AuthDeliveryID(id), method: .magicLink, url: bad, openedAt: t0)
            let api = LiveAuthDeliveryAPI(client: env.client(transport: FakeTransport { _, _ in json(body(answer)) }).0,
                                          flags: AuthDeliveryFlags(destinationVerification: true))
            await #expect(throws: AuthDeliveryError.failed) { _ = try await api.openLink(deliveryId: id) }
        }
    }

    @MainActor @Test func theLinkScreenLoadsFromTheLiveClientAndStillOpensNothing() async throws {
        let env = try await ClientEnv()
        let id = UUID()
        let transport = FakeTransport { request, _ in
            request.method == .GET ? json(body(wire(id, method: .magicLink, host: "login.acme.com"))) : json(body(AuthDeliveryView?.none))
        }
        let api = LiveAuthDeliveryAPI(client: env.client(transport: transport).0)
        let opener = RecordingOpener()
        let model = LinkConfirmationViewModel(deliveryId: id, api: api, verifier: FailClosedDestinationVerifier(), opener: opener, clock: { t0 })
        await model.load()
        // Who, what, when, where are on screen; Continue never enables; nothing is opened, nothing is asked beyond the display object.
        #expect(model.display?.host == "login.acme.com")
        #expect(model.title == AuthDeliveryCopy.linkTitle(business: "Acme"))
        #expect(model.phase == .notOpened(.signatureFailed))
        #expect(model.message == AuthDeliveryCopy.linkSignatureFailed(business: "Acme"))
        #expect(!model.canContinue)
        await model.proceed()
        #expect(opener.opened.isEmpty)
        #expect(transport.requests.count == 1 && transport.requests[0].method == .GET, "no open, no prefetch, no report for a build that cannot verify")
    }
}

// MARK: - The code sheet

@Suite("Auth delivery: one-time code sheet (F5, F6; C-OTP-01)")
@MainActor
struct CodeDeliveryTests {
    let id = UUID()

    func make(_ shown: AuthDeliveryItem? = nil, code: String = "482913", kind: AuthCodeKind = .otp) async -> (CodeDeliveryViewModel, MockAuthDeliveryAPI, MovableClock) {
        let api = MockAuthDeliveryAPI()
        await api.add(shown ?? item(.code(kind), id: id), code: DeliveredCode(value: code, kind: kind))
        let clock = MovableClock(t0)
        return (CodeDeliveryViewModel(deliveryId: id, api: api, clock: { clock.now }), api, clock)
    }

    @Test func theCodeIsNotOnTheDeviceBeforeAnExplicitTap() async {
        let (model, api, _) = await make()
        await model.load()
        #expect(model.phase == .ready)
        #expect(model.code == nil && model.displayCode.isEmpty && model.spokenCode.isEmpty)
        #expect(model.canReveal && !model.canCopy && model.copyRequest() == nil)
        #expect(await api.openCodeCalls.isEmpty, "looking at the sheet consumes nothing")
        #expect(model.title == AuthDeliveryCopy.codeTitle(business: "Acme"))
        #expect(model.expiryLine { _ in "10:42" } == "Expires at 10:42")

        await model.reveal()
        #expect(model.phase == .revealed && model.code == "482913")
        #expect(model.displayCode == "482 913" && model.spokenCode == "4 8 2 9 1 3")
        #expect(await api.openCodeCalls == [id])
        // A second tap asks for nothing more.
        await model.reveal()
        #expect(await api.openCodeCalls.count == 1)
    }

    @Test func expiryClearsTheCodeFromScreenAndMemory() async {
        let (model, _, clock) = await make()
        await model.load()
        await model.reveal()
        clock.advance(299)
        model.tick()
        #expect(model.phase == .revealed && model.code != nil)
        clock.advance(1)
        model.tick()
        #expect(model.phase == .expired && model.code == nil && model.displayCode.isEmpty)
        #expect(model.copyRequest() == nil && !model.canReport)
        #expect(model.message == AuthDeliveryCopy.codeExpired(business: "Acme"))
    }

    @Test func aCodeThatExpiresWhileItTravelsIsNeverShown() async {
        let (model, api, clock) = await make(item(.code(.otp), id: id, expiresIn: 5))
        await model.load()
        #expect(model.phase == .ready)
        clock.advance(6)
        await model.reveal()
        #expect(model.phase == .expired && model.code == nil)
        #expect(await api.openCodeCalls.isEmpty, "an expired delivery is not opened")
    }

    @Test func closingTheSheetKeepsNothing() async {
        let (model, _, _) = await make()
        await model.load()
        await model.reveal()
        model.close()
        #expect(model.phase == .closed && model.code == nil && model.copyRequest() == nil)
        await model.reveal()
        #expect(model.code == nil)
    }

    @Test func copyingIsLocalOnlyAndNeverOutlivesTheCode() async {
        let (model, _, clock) = await make()
        await model.load()
        await model.reveal()
        let copy = try! #require(model.copyRequest())
        #expect(copy.value == "482913" && copy.localOnly)
        #expect(copy.expiresAt == t0.addingTimeInterval(SensitiveCopyPolicy.pasteboardLifetime))
        clock.advance(280)
        #expect(model.copyRequest()?.expiresAt == t0.addingTimeInterval(300), "20 seconds left: the pasteboard item expires with the code")
        #expect(SensitiveCopy.make("", validUntil: t0.addingTimeInterval(60), now: t0) == nil)
        #expect(SensitiveCopy.make("1234", validUntil: t0, now: t0) == nil)
    }

    @Test func expiredUsedAndUnknownDeliveriesMapToTheirPhases() async {
        let (expired, _, _) = await make(item(.code(.otp), id: id, state: .expired))
        await expired.load()
        #expect(expired.phase == .expired)
        let (late, _, _) = await make(item(.code(.otp), id: id, expiresIn: -1))
        await late.load()
        #expect(late.phase == .expired, "the device clock decides, even if the server still lists it")
        let (used, usedAPI, _) = await make(item(.code(.otp), id: id, state: .used))
        await used.load()
        #expect(used.phase == .gone && used.message == AuthDeliveryCopy.noLongerActive)
        await used.reveal()
        #expect(await usedAPI.openCodeCalls.isEmpty)
        let (cancelled, _, _) = await make(item(.code(.otp), id: id, state: .cancelled))
        await cancelled.load()
        #expect(cancelled.phase == .gone)

        let unknown = CodeDeliveryViewModel(deliveryId: UUID(), api: MockAuthDeliveryAPI(), clock: { t0 })
        await unknown.load()
        #expect(unknown.phase == .gone && unknown.code == nil)
        let unavailable = CodeDeliveryViewModel(deliveryId: id, api: UnavailableAuthDeliveryAPI(), clock: { t0 })
        await unavailable.load()
        #expect(unavailable.phase == .gone)

        // A link is not a code: the code sheet asks for nothing.
        let (link, linkAPI, _) = await make(item(.link, id: id))
        await link.load()
        #expect(link.phase == .gone)
        await link.reveal()
        #expect(await linkAPI.openCodeCalls.isEmpty)
    }

    @Test func theServersRefusalAtOpenIsShownAndNothingIsRetried() async {
        let (model, api, _) = await make()
        await model.load()
        await api.failOpen(with: .alreadyUsed)
        await model.reveal()
        #expect(model.phase == .gone && model.code == nil)

        let (gone, goneAPI, _) = await make()
        await gone.load()
        await goneAPI.failOpen(with: .expired)
        await gone.reveal()
        #expect(gone.phase == .gone, "`410` with time left on the device clock: ended early, not expired")
        #expect(await goneAPI.openCodeCalls.count == 1)
    }

    @Test func offlineSendsNothingAndQueuesNothing() async {
        let (model, api, _) = await make()
        await api.failRead(with: .offline)
        await model.load()
        #expect(model.phase == .offline && model.message == AuthDeliveryCopy.offline && model.offersTryAgain)
        await model.reveal()
        await model.thisWasntMe()
        #expect(model.copyRequest() == nil)
        #expect(await api.openCodeCalls.isEmpty)
        #expect(await api.reduceCalls.isEmpty)

        // Back online: Try again loads, and an open that fails offline is one attempt, shown, with no code.
        await api.failRead(with: nil)
        await model.tryAgain()
        #expect(model.phase == .ready)
        await api.failOpen(with: .offline)
        await model.reveal()
        #expect(model.phase == .offline && model.code == nil)
        #expect(await api.openCodeCalls.count == 1)
    }

    @Test func thisWasntMeReportsAndTakesTheCodeOffTheScreen() async {
        let (model, api, _) = await make()
        await model.load()
        await model.reveal()
        await model.thisWasntMe()
        #expect(model.phase == .reported && model.code == nil)
        let calls = await api.reduceCalls
        #expect(calls.count == 1 && calls[0].0 == .delivery(id) && calls[0].1 == .report)
        #expect(model.message == AuthDeliveryCopy.linkReported(business: "Acme"))
    }

    @Test func displayStringsPassThroughTheUntrustedTextSanitizer() async {
        let hostile = "Ac\u{202E}me\u{200B}\nBank"
        let (model, _, _) = await make(item(.code(.totp), id: id, business: hostile), kind: .totp)
        await model.load()
        #expect(model.business == "Acme Bank")
        for text in [model.title, model.useOnlyLine, model.neverShareLine, model.kindLabel ?? ""] {
            #expect(!text.unicodeScalars.contains { $0.value == 0x202E || $0.value == 0x200B || $0.value == 0x0A })
        }
        #expect(model.kindLabel == AuthDeliveryCopy.totpLabel(business: "Acme Bank"))
        let (fake, _, _) = await make(item(.code(.otp), id: id, business: "Viadere Security"))
        await fake.load()
        #expect(fake.business == "\u{201C}Viadere Security\u{201D}", "a name that imitates Viadere is shown quoted")
        #expect(AuthDeliveryInboxViewModel.row(item(.link, business: hostile)).business == "Acme Bank")
        #expect(AuthDeliveryInboxViewModel.row(item(.link, business: "")).business == "Unnamed business")
    }

    @Test func theCodeNeverReachesADescriptionOrALog() {
        let code = DeliveredCode(value: "482913", kind: .otp)
        var dumped = ""
        dump(code, to: &dumped)
        for text in ["\(code)", String(describing: code), String(reflecting: code), dumped, "\(Optional(code) as Any)"] {
            #expect(!text.contains("482913"))
        }
    }

    @Test func theApprovedCopyIsPinned() {
        #expect(AuthDeliveryCopy.codeTitle(business: "Acme") == "Your \u{2068}Acme\u{2069} code")
        #expect(AuthDeliveryCopy.codeUseOnly(business: "Acme") == "Use it only on \u{2068}Acme\u{2069}.")
        #expect(AuthDeliveryCopy.codeNeverShare(business: "Acme") == "Never share this code. \u{2068}Acme\u{2069} will never ask you for it by phone, text or email.")
        #expect(AuthDeliveryCopy.codeExpired(business: "Acme") == "This code has expired. Ask \u{2068}Acme\u{2069} for a new one.")
        #expect(AuthDeliveryCopy.totpLabel(business: "Acme") == "Sign-in code for \u{2068}Acme\u{2069}. Viadere passed it on; \u{2068}Acme\u{2069} checks it.")
        #expect(AuthDeliveryCopy.copyCode == "Copy code" && AuthDeliveryCopy.showCode == "Show code")
        #expect(AuthDeliveryCopy.n02Body(business: "Acme") == "\u{2068}Acme\u{2069} sign-in link is ready. Tap to continue.")
        #expect(AuthDeliveryCopy.n05Body(business: "Acme") == "Your \u{2068}Acme\u{2069} code is ready. Open Viadere to see it.")
        #expect(AuthDeliveryCopy.n06Body(business: "Acme") == "\u{2068}Acme\u{2069} sent a security notice.")
    }
}

// MARK: - The inbox

@Suite("Auth delivery: inbox (Alerts, Needs you)")
@MainActor
struct AuthDeliveryInboxTests {
    @Test func pendingDeliveriesAreNewestFirstAndExpireByTheDeviceClock() async {
        let api = MockAuthDeliveryAPI()
        let old = item(.link, createdAgo: 120, expiresIn: 30), new = item(.code(.otp), createdAgo: 5), notice = item(.notice, createdAgo: 60)
        for entry in [old, new, notice, item(.code(.otp), state: .used), item(.link, state: .cancelled)] { await api.add(entry) }
        let clock = MovableClock(t0)
        let inbox = AuthDeliveryInboxViewModel(api: api, clock: { clock.now })
        #expect(inbox.pending().isEmpty && !inbox.hasLoaded)
        await inbox.refresh()
        #expect(inbox.hasLoaded)
        #expect(inbox.pending().map(\.deliveryId) == [new.deliveryId, notice.deliveryId, old.deliveryId])
        #expect(inbox.waitingExpiries().count == 2, "a notice asks for nothing")

        // The link expires on the device clock before the server says so: it leaves the list without a refresh.
        clock.advance(31)
        #expect(inbox.pending().map(\.deliveryId) == [new.deliveryId, notice.deliveryId])
        #expect(await api.listCalls == 1)
        inbox.markHandled(new.deliveryId)
        #expect(inbox.pending().map(\.deliveryId) == [notice.deliveryId])
        inbox.reset()
        #expect(inbox.pending().isEmpty && !inbox.hasLoaded)
    }

    @Test func rowsUseApprovedCopyAndNarrowToTheBusinessContext() async {
        let other = BusinessID()
        let inbox = AuthDeliveryInboxViewModel(api: MockAuthDeliveryAPI(), clock: { t0 }, initial: [
            item(.link, createdAgo: 1), item(.code(.otp), createdAgo: 2), item(.notice, createdAgo: 3),
            item(.link, business: "Borealis", businessId: other, createdAgo: 4, silent: true),
        ])
        let rows = inbox.rows()
        #expect(rows.map(\.line) == [AuthDeliveryCopy.linkTitle(business: "Acme"), AuthDeliveryCopy.codeTitle(business: "Acme"),
                                     AuthDeliveryCopy.n06Body(business: "Acme"), AuthDeliveryCopy.silentPendingSignIn(business: "Borealis")])
        #expect(rows.map(\.opens) == [true, true, false, true])
        #expect(rows.allSatisfy { !$0.symbol.contains("shield") })
        #expect(inbox.rows(business: other).map(\.business) == ["Borealis"])
        #expect(inbox.rows(business: acme).count == 3)
        #expect(inbox.canOpen(rows[0]) && !inbox.canOpen(rows[2]))
    }

    @Test func offlineKeepsTheListButOpensNothingAndOtherFailuresEmptyIt() async {
        let api = MockAuthDeliveryAPI()
        await api.add(item(.code(.otp)))
        let inbox = AuthDeliveryInboxViewModel(api: api, clock: { t0 })
        await inbox.refresh()
        await api.failRead(with: .offline)
        await inbox.refresh()
        #expect(inbox.isOffline && inbox.rows().count == 1)
        #expect(!inbox.canOpen(inbox.rows()[0]))
        await api.failRead(with: .failed)
        await inbox.refresh()
        #expect(!inbox.isOffline && inbox.rows().isEmpty)

        let none = AuthDeliveryInboxViewModel(api: UnavailableAuthDeliveryAPI(), clock: { t0 }, initial: [item(.link)])
        await none.refresh()
        #expect(none.rows().isEmpty, "a process with no client shows nothing")
    }

    @Test func theSheetIsChosenFromTheDisplayObjectWithoutOpeningAnything() async {
        let api = MockAuthDeliveryAPI()
        let link = item(.link), code = item(.code(.otp)), notice = item(.notice)
        for entry in [link, code, notice] { await api.add(entry, code: DeliveredCode(value: "1234", kind: .otp)) }
        #expect(await AuthDeliverySurface.resolve(deliveryId: link.deliveryId, api: api) == .link)
        #expect(await AuthDeliverySurface.resolve(deliveryId: code.deliveryId, api: api) == .code)
        let resolvedNotice = await AuthDeliverySurface.resolve(deliveryId: notice.deliveryId, api: api)
        #expect(resolvedNotice == .notice(business: "Acme") && resolvedNotice.message == AuthDeliveryCopy.n06Body(business: "Acme"))
        let used = item(.code(.otp), state: .used)
        await api.add(used)
        #expect(await AuthDeliverySurface.resolve(deliveryId: used.deliveryId, api: api) == .code, "the code sheet says it was used")
        #expect(await AuthDeliverySurface.resolve(deliveryId: UUID(), api: api) == .none(.gone))
        await api.failRead(with: .offline)
        let offline = await AuthDeliverySurface.resolve(deliveryId: code.deliveryId, api: api)
        #expect(offline == .none(.offline) && offline.message == AuthDeliveryCopy.offline)
        #expect(await api.openCodeCalls.isEmpty)
        #expect(await api.openCalls.isEmpty)
    }
}

// MARK: - The notification service extension's text

@Suite("Auth delivery: notification text after fetch (N-02, N-05, N-06, N-08)")
struct AuthDeliveryNotificationTextTests {
    @Test func thePushNamesItsDeliveryByWireIdOnlyInAnAuthCategory() {
        let id = UUID()
        let wireId = AuthDeliveryID(id).description
        #expect(AuthDeliveryNotificationText.deliveryId(category: "viadere.auth.code", userInfo: ["adl": wireId, "aps": ["alert": "x"]]) == id)
        #expect(AuthDeliveryNotificationText.deliveryId(category: "viadere.auth.link", userInfo: ["adl": id.uuidString]) == id)
        #expect(AuthDeliveryNotificationText.deliveryId(category: "viadere.auth.notice", userInfo: ["adl": wireId]) == id)
        #expect(AuthDeliveryNotificationText.deliveryId(category: "viadere.approve", userInfo: ["adl": wireId]) == nil)
        #expect(AuthDeliveryNotificationText.deliveryId(category: "viadere.auth.code", userInfo: ["adl": "adl_short"]) == nil)
        #expect(AuthDeliveryNotificationText.deliveryId(category: "viadere.auth.code", userInfo: ["iid": id.uuidString]) == nil)
        // The tap follows the same id: the server sends the wire form (`AuthPushPayloadPolicy`), which used to resolve to the request list.
        #expect(PushPayload.target(category: "viadere.auth.link", userInfo: ["adl": wireId]) == .authDelivery(id))
        #expect(PushPayload.target(category: "viadere.auth.code", userInfo: ["adl": wireId]) == .authDelivery(id))
        #expect(PushPayload.target(category: "viadere.auth.code", userInfo: ["adl": "adl_!!"]) == .pendingRequests)
        // A tapped notice opens its delivery (the sheet shows N-06); it is an auth category for the action handler and the watch.
        #expect(PushPayload.target(category: "viadere.auth.notice", userInfo: ["adl": wireId]) == .authDelivery(id))
        #expect(AuthNotificationCategory.all.contains(AuthNotificationCategory.notice))
    }

    @Test func fetchedTextIsTheApprovedLineForTheMethodAndNeverACodeOrHost() {
        let link = AuthDeliveryNotificationText.make(item: item(.link), category: "viadere.auth.link", now: t0, showsBusinessName: true)
        #expect(link == AuthDeliveryNotificationText(title: "Acme", body: AuthDeliveryCopy.n02Body(business: "Acme")))
        let code = AuthDeliveryNotificationText.make(item: item(.code(.otp)), category: "viadere.auth.code", now: t0, showsBusinessName: true)
        #expect(code == AuthDeliveryNotificationText(title: "Acme", body: AuthDeliveryCopy.n05Body(business: "Acme")))
        let notice = AuthDeliveryNotificationText.make(item: item(.notice), category: "viadere.auth.notice", now: t0, showsBusinessName: true)
        #expect(notice.body == AuthDeliveryCopy.n06Body(business: "Acme"))
        for text in [link, code, notice] {
            #expect(!text.body.contains("login.acme.com") && !text.title.contains("login.acme.com"))
            #expect(!text.body.contains { $0.isNumber }, "no code, number or amount")
            #expect(!text.body.contains("http"))
        }
    }

    @Test func anythingThatDoesNotAddUpIsTheGenericLine() {
        let generic = AuthDeliveryNotificationText.generic
        #expect(generic.title == "Viadere" && generic.body == "You have a new security item. Open Viadere to review it.")
        // The fetched method must be the one the push's category named.
        #expect(AuthDeliveryNotificationText.make(item: item(.code(.otp)), category: "viadere.auth.link", now: t0, showsBusinessName: true) == generic)
        #expect(AuthDeliveryNotificationText.make(item: item(.link), category: "viadere.auth.code", now: t0, showsBusinessName: true) == generic)
        // Finished or expired: never a stale business name.
        #expect(AuthDeliveryNotificationText.make(item: item(.link, state: .used), category: "viadere.auth.link", now: t0, showsBusinessName: true) == generic)
        #expect(AuthDeliveryNotificationText.make(item: item(.link, expiresIn: -1), category: "viadere.auth.link", now: t0, showsBusinessName: true) == generic)
        // A name that imitates Viadere, or no name, never becomes the title.
        #expect(AuthDeliveryNotificationText.make(item: item(.link, business: "V1adere Security"), category: "viadere.auth.link", now: t0, showsBusinessName: true) == generic)
        #expect(AuthDeliveryNotificationText.make(item: item(.link, business: "\u{200B}"), category: "viadere.auth.link", now: t0, showsBusinessName: true) == generic)
        // Hostile characters are removed from what is shown.
        let cleaned = AuthDeliveryNotificationText.make(item: item(.code(.otp), business: "Ac\u{202E}me"), category: "viadere.auth.code", now: t0, showsBusinessName: true)
        #expect(cleaned.title == "Acme")
    }

    @Test func theNoticeCategoryIsRegisteredWithoutActions() {
        #expect(AuthNotificationCategory.categories.contains { $0.identifier == "viadere.auth.notice" && $0.actions.isEmpty })
        #expect(AuthPushPayloadPolicy.allowedCategories == [AuthNotificationCategory.link, AuthNotificationCategory.code, AuthNotificationCategory.notice])
    }
}
