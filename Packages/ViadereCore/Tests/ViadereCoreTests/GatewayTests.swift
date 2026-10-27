import Foundation
import Testing
@testable import ViadereCore

/// In-memory directory for engine tests.
final class MockDirectory: DirectoryLookup, @unchecked Sendable {
    private let lock = NSLock()
    private var _businesses: [BusinessSummary]
    private var _recent: [BusinessSummary]
    private var _failing = false

    init(businesses: [BusinessSummary], recent: [BusinessSummary] = []) {
        _businesses = businesses
        _recent = recent
    }

    var failing: Bool {
        get { lock.withLock { _failing } }
        set { lock.withLock { _failing = newValue } }
    }

    func setStatus(_ id: BusinessID, _ status: VerificationStatus) {
        lock.withLock {
            if let i = _businesses.firstIndex(where: { $0.id == id }) { _businesses[i].verificationStatus = status }
        }
    }

    private func all() throws -> [BusinessSummary] {
        try lock.withLock {
            if _failing { throw URLError(.timedOut) }
            return _businesses
        }
    }

    func business(byCode code: BusinessCode) async throws -> BusinessSummary? { try all().first { $0.code == code } }
    func business(byHandle handle: BusinessHandle) async throws -> BusinessSummary? { try all().first { $0.handle == handle } }
    func business(byId id: BusinessID) async throws -> BusinessSummary? { try all().first { $0.id == id } }
    func search(name: String, limit: Int) async throws -> [BusinessSummary] {
        let q = name.lowercased()
        return Array(try all().filter { $0.displayName.lowercased().contains(q) }.prefix(limit))
    }
    func recentBusinesses(consumerId: ConsumerID?, phone: PhoneNumber, limit: Int) async throws -> [BusinessSummary] {
        let ids = Set(try all().map(\.id))
        return Array(lock.withLock { _recent }.filter { ids.contains($0.id) }.prefix(limit))
    }
}

/// Drives the engine like the server would: persist context, apply transitions.
final class GatewayHarness: @unchecked Sendable {
    let engine: SMSGatewayEngine
    let directory: MockDirectory
    var context: ConversationContext
    var clock: Date
    var counter = 0
    var lastEffects: [GatewayEffect] = []
    let phone = PhoneNumber("+14805550123")!

    init(linked: Bool = true, directory: MockDirectory = GatewayHarness.defaultDirectory(),
         configuration: GatewayConfiguration = GatewayConfiguration()) {
        self.directory = directory
        self.engine = SMSGatewayEngine(configuration: configuration, directory: directory)
        self.context = ConversationContext(phone: PhoneNumber("+14805550123")!, consumerId: linked ? ConsumerID() : nil)
        self.clock = Fixtures.now
    }

    static let airline = Fixtures.business("Sky Air", handle: "skyair", code: "SK1234")
    static let hotel = Fixtures.business("Harbor Hotel", handle: "harborhotel", code: "HH2345")
    static let amazonCo = Fixtures.business("Amazon", handle: "amazon", code: "AF2345")
    static let bankIO = Fixtures.business("IO Bank", handle: "iobank", code: "103456")
    static let coffee1 = Fixtures.business("Bean Coffee Downtown", handle: "beandowntown", code: "BC1001")
    static let coffee2 = Fixtures.business("Bean Coffee Airport", handle: "beanairport", code: "BC1002")
    static let suspended = Fixtures.business("Shady Shop", handle: "shady", code: "SH6666", status: .suspended)

    static func defaultDirectory() -> MockDirectory {
        MockDirectory(businesses: [airline, hotel, amazonCo, bankIO, coffee1, coffee2, suspended],
                      recent: [airline, hotel, suspended, amazonCo])
    }

    @discardableResult
    func send(_ text: String, id: String? = nil, receivedAt: Date? = nil, advance: TimeInterval = 5) async -> GatewayTransition {
        clock = clock.addingTimeInterval(advance)
        counter += 1
        let inbound = InboundSMS(providerMessageId: id ?? "SM\(counter)", from: phone, text: text, receivedAt: receivedAt ?? clock)
        let t = await engine.handle(inbound, context: context, now: clock)
        context = t.context
        lastEffects = t.effects
        return t
    }

    var state: GatewayState { context.state }

    func forwards(_ t: GatewayTransition) -> [(BusinessID, SessionID, String)] {
        t.effects.compactMap {
            if case .forwardToBusiness(let b, let s, let text, _) = $0 { return (b, s, text) }
            return nil
        }
    }

    /// Connects to a business via @handle + confirmation.
    func connect(_ business: BusinessSummary) async {
        await send("@\(business.handle?.value ?? "")")
        await send("1")
    }
}

@Suite("SMS gateway engine")
struct GatewayTests {
    // MARK: Acceptance 1 — new user gets a four-option menu

    @Test("New linked user receives the four-option main menu")
    func newLinkedUser() async {
        let h = GatewayHarness()
        let t = await h.send("Hi")
        #expect(h.state == .idleMenu)
        #expect(t.smsBodies.last?.contains("1. Recent businesses\n2. Find a business\n3. Account help\n4. More options") == true)
        #expect(h.context.menu?.options.count == 4)
    }

    @Test("New unlinked user receives a four-option menu and limited discovery")
    func newUnlinkedUser() async {
        let h = GatewayHarness(linked: false)
        let t = await h.send("hello")
        #expect(h.state == .unlinked)
        #expect(t.smsBodies.last?.contains("1. Link your account\n2. Find a business\n3. Help\n4. More options") == true)
    }

    // MARK: Acceptance 2 / spec §19 #8 — digits only with an active menu

    @Test("Menu option 4 triggers search; '4' while connected forwards unchanged")
    func optionFourVersusOrderNumber() async {
        let h = GatewayHarness()
        await h.send("Hi")
        await h.send("1") // recent
        #expect(h.state == .recentMenu)
        #expect(h.context.menu?.options.last?.label == "Search by name")
        await h.send("4")
        #expect(h.state == .searchPending)
        #expect(h.lastEffects.contains(.sendSMS(GatewayCopy.searchPrompt)))

        await h.connect(GatewayHarness.airline)
        #expect(h.state == .connected)
        for text in ["4", "1", "12", "  3 "] {
            let t = await h.send(text)
            let fwd = h.forwards(t)
            #expect(fwd.count == 1)
            #expect(fwd.first?.2 == text)
            #expect(fwd.first?.0 == GatewayHarness.airline.id)
            #expect(h.state == .connected)
        }
    }

    @Test("Recent menu shows at most three verified businesses plus search")
    func recentMenu() async {
        let h = GatewayHarness()
        await h.send("Hi")
        let t = await h.send("1")
        let options = h.context.menu?.options ?? []
        #expect(options.count == 4)
        #expect(!(t.smsBodies.last ?? "").contains("Shady"))
        #expect(options.prefix(3).map(\.action) == [.selectBusiness(GatewayHarness.airline), .selectBusiness(GatewayHarness.hotel),
                                                      .selectBusiness(GatewayHarness.amazonCo)])
        // Selecting from the list connects directly (explicit selection).
        let s = await h.send("2")
        #expect(h.state == .connected)
        #expect(h.context.session?.business.id == GatewayHarness.hotel.id)
        #expect(s.effects.contains { if case .openSession(let b, _) = $0 { b == GatewayHarness.hotel.id } else { false } })
    }

    // MARK: Acceptance 3 — search by name, @handle, normalized code; disambiguation

    @Test func searchByHandleNameAndCode() async {
        let h = GatewayHarness()
        await h.send("Hi")
        await h.send("2")
        #expect(h.state == .searchPending)
        await h.send("@SkyAir")
        #expect(h.state == .confirmDestination)
        #expect(h.context.pending?.business.id == GatewayHarness.airline.id)

        await h.send("BACK")
        await h.send("2")
        await h.send("io-3456") // normalizes to 103456
        #expect(h.state == .confirmDestination)
        #expect(h.context.pending?.business.id == GatewayHarness.bankIO.id)

        await h.send("BACK")
        await h.send("2")
        await h.send("i o 3 4 5 6")
        #expect(h.context.pending?.business.id == GatewayHarness.bankIO.id)

        await h.send("BACK")
        await h.send("2")
        await h.send("harbor")
        #expect(h.state == .confirmDestination)
        #expect(h.context.pending?.business.id == GatewayHarness.hotel.id)
    }

    @Test("Ambiguous names request explicit selection")
    func disambiguation() async {
        let h = GatewayHarness()
        await h.send("Hi")
        await h.send("2")
        let t = await h.send("bean coffee")
        #expect(h.state == .disambiguation)
        #expect(t.smsBodies.last?.contains("Which one did you mean?") == true)
        #expect(h.context.menu?.options.count == 3)
        #expect(h.context.menu?.options.last?.action == .findBusiness)
        #expect(t.effects.allSatisfy { if case .forwardToBusiness = $0 { false } else { true } })
        await h.send("2")
        #expect(h.state == .connected)
        #expect(h.context.session?.business.id == GatewayHarness.coffee2.id)
    }

    @Test("Unknown and unverified destinations are never routed")
    func unknownNeverRouted() async {
        let h = GatewayHarness()
        await h.send("Hi")
        for input in ["@nobody hello there", "@shady give me money", "ZZ9999 where is it", "no such business"] {
            let t = await h.send(input)
            #expect(h.forwards(t).isEmpty, "\(input)")
            #expect(t.effects.allSatisfy { if case .openSession = $0 { false } else { true } })
            #expect(h.state == .searchPending)
        }
    }

    // MARK: Acceptance 4 — account link flow

    @Test("Unlinked user must link before routing; pending destination survives linking")
    func linkFlow() async {
        let h = GatewayHarness(linked: false)
        await h.send("Hi")
        let t = await h.send("@amazon I need help with my order")
        #expect(h.state == .confirmDestination)
        let c = await h.send("1")
        #expect(h.state == .linkPending)
        #expect(c.effects.contains(.sendAccountLink))
        #expect(h.forwards(c).isEmpty)
        #expect(h.context.pending?.message == "I need help with my order")
        _ = t

        // While pending, digits never route.
        let d = await h.send("1")
        #expect(h.forwards(d).isEmpty)

        let linked = h.engine.accountLinked(consumerId: ConsumerID(), context: h.context, now: h.clock)
        h.context = linked.context
        #expect(h.state == .confirmDestination)
        #expect(linked.smsBodies.first == GatewayCopy.linked)
        let done = await h.send("1")
        #expect(h.state == .connected)
        #expect(h.forwards(done).map(\.2) == ["I need help with my order"])
    }

    @Test("Expired link-pending falls back to UNLINKED")
    func linkExpiry() async {
        let h = GatewayHarness(linked: false)
        await h.send("Hi")
        await h.send("1")
        #expect(h.state == .linkPending)
        await h.send("Hi", advance: 16 * 60)
        #expect(h.state == .unlinked)
        #expect(h.context.menu?.kind == .unlinkedMain)
    }

    @Test func accountHelpIsHandedOffSecurely() async {
        let h = GatewayHarness()
        await h.send("Hi")
        let t = await h.send("3")
        #expect(t.effects.contains(.sendSecureHandoff(.accountHelp)))
    }

    // MARK: Acceptance 5 & 9 — confirm, route, attributed replies

    @Test("Direct addressing confirms, then forwards the carried message; replies are attributed")
    func directAddressing() async {
        let h = GatewayHarness()
        let t = await h.send("AF2345 where is my package")
        #expect(h.state == .confirmDestination)
        #expect(h.forwards(t).isEmpty)
        #expect(t.smsBodies.last?.contains("Connect to Amazon (@amazon), code AF-2345?") == true)
        let c = await h.send("YES")
        #expect(h.state == .connected)
        let fwd = h.forwards(c)
        #expect(fwd.count == 1 && fwd[0].2 == "where is my package" && fwd[0].0 == GatewayHarness.amazonCo.id)
        #expect(c.smsBodies.contains(GatewayCopy.connected(GatewayHarness.amazonCo)))

        guard let session = h.context.session else { Issue.record("no session"); return }
        let reply = h.engine.deliverBusinessMessage(businessId: GatewayHarness.amazonCo.id, sessionId: session.sessionId,
                                                    text: "It arrives today.", context: h.context, now: h.clock)
        #expect(reply.smsBodies == ["[Amazon]: It arrives today."])
    }

    @Test("Declining confirmation routes nothing")
    func declineConfirmation() async {
        let h = GatewayHarness()
        await h.send("@amazon hello")
        let t = await h.send("2")
        #expect(h.forwards(t).isEmpty)
        #expect(h.state == .idleMenu)
        #expect(h.context.pending == nil)
    }

    @Test("Business verification is re-checked at confirmation time")
    func reverifyOnConfirm() async {
        let h = GatewayHarness()
        await h.send("@amazon hello")
        h.directory.setStatus(GatewayHarness.amazonCo.id, .suspended)
        let t = await h.send("1")
        #expect(h.forwards(t).isEmpty)
        #expect(h.state == .idleMenu)
        #expect(t.smsBodies.first == GatewayCopy.businessUnavailable(GatewayHarness.amazonCo))
    }

    // MARK: Acceptance 6 / spec §19 #9 — switching without leakage

    @Test("Switch from airline to hotel in one thread without leaking tenant history")
    func switchWithoutLeakage() async {
        let h = GatewayHarness()
        await h.connect(GatewayHarness.airline)
        guard let airlineSession = h.context.session else { Issue.record("no session"); return }
        let a = await h.send("My flight AB123 was cancelled")
        #expect(h.forwards(a).map(\.1) == [airlineSession.sessionId])

        let menu = await h.send("menu")
        #expect(h.state == .sessionMenu)
        #expect(menu.smsBodies.last?.contains("1. Continue with Sky Air\n2. Switch business\n3. End conversation") == true)
        let sw = await h.send("2")
        #expect(sw.effects.contains(.closeSession(businessId: GatewayHarness.airline.id, sessionId: airlineSession.sessionId, reason: .switched)))
        #expect(h.state == .recentMenu)
        await h.send("2") // Harbor Hotel
        #expect(h.state == .connected)
        guard let hotelSession = h.context.session else { Issue.record("no session"); return }
        #expect(hotelSession.business.id == GatewayHarness.hotel.id)
        #expect(hotelSession.sessionId != airlineSession.sessionId)

        let m = await h.send("Need a room for tonight")
        #expect(h.forwards(m).map(\.0) == [GatewayHarness.hotel.id])
        #expect(h.forwards(m).map(\.1) == [hotelSession.sessionId])

        // A late airline reply is held, never rendered into the hotel context.
        let late = h.engine.deliverBusinessMessage(businessId: GatewayHarness.airline.id, sessionId: airlineSession.sessionId,
                                                   text: "Rebooked you on AB456", context: h.context, now: h.clock)
        #expect(late.smsBodies.isEmpty)
        #expect(late.effects == [.holdBusinessMessage(businessId: GatewayHarness.airline.id, sessionId: airlineSession.sessionId)])
        // A forged pairing (hotel business id with airline session) is also held.
        let forged = h.engine.deliverBusinessMessage(businessId: GatewayHarness.hotel.id, sessionId: airlineSession.sessionId,
                                                     text: "x", context: h.context, now: h.clock)
        #expect(forged.smsBodies.isEmpty)
        let hotelReply = h.engine.deliverBusinessMessage(businessId: GatewayHarness.hotel.id, sessionId: hotelSession.sessionId,
                                                         text: "Room 12 is ready", context: h.context, now: h.clock)
        #expect(hotelReply.smsBodies == ["[Harbor Hotel]: Room 12 is ready"])
        #expect(!hotelReply.smsBodies.joined().contains("Sky Air"))
    }

    @Test("@handle of another business while connected asks to switch and never forwards to the current one")
    func directAddressWhileConnected() async {
        let h = GatewayHarness()
        await h.connect(GatewayHarness.airline)
        let t = await h.send("@harborhotel do you have rooms?")
        #expect(h.forwards(t).isEmpty)
        #expect(h.state == .confirmDestination)
        #expect(h.context.pending?.message == "do you have rooms?")
        // Cancel returns to the airline conversation.
        await h.send("2")
        #expect(h.state == .connected)
        #expect(h.context.session?.business.id == GatewayHarness.airline.id)
        // @ of the same business or an unknown handle is ordinary content.
        let same = await h.send("@skyair thanks")
        #expect(h.forwards(same).map(\.2) == ["@skyair thanks"])
        let unknown = await h.send("@john will pick it up")
        #expect(h.forwards(unknown).map(\.2) == ["@john will pick it up"])
        // Confirming a switch forwards to the new business only.
        await h.send("@harborhotel need a room")
        let c = await h.send("1")
        #expect(h.forwards(c).map(\.0) == [GatewayHarness.hotel.id])
        #expect(c.effects.contains { if case .closeSession(let b, _, .switched) = $0 { b == GatewayHarness.airline.id } else { false } })
    }

    // MARK: Acceptance 7 — MENU/BACK/HELP/STOP and stale menus

    @Test("HELP works in every non-opted-out state without changing it", arguments: ["HELP", "help", " Info. ", "\\HELP"])
    func help(word: String) async {
        let h = GatewayHarness()
        await h.connect(GatewayHarness.airline)
        let before = h.context.state
        let t = await h.send(word)
        #expect(t.smsBodies == [GatewayCopy.help])
        #expect(h.forwards(t).isEmpty)
        #expect(h.state == before)
    }

    @Test("Opt-out keywords work in every state", arguments: ["STOP", "stop", " Stop. ", "STOPALL", "UNSUBSCRIBE", "CANCEL", "END", "QUIT", "\\STOP"])
    func optOut(word: String) async {
        let h = GatewayHarness()
        await h.connect(GatewayHarness.airline)
        let session = h.context.session
        let t = await h.send(word)
        #expect(h.state == .optedOut)
        #expect(t.smsBodies == [GatewayCopy.optOutConfirmation])
        #expect(h.forwards(t).isEmpty)
        #expect(t.effects.contains(.closeSession(businessId: GatewayHarness.airline.id, sessionId: session!.sessionId, reason: .optedOut)))
        #expect(t.effects.contains { if case .recordConsent(true, _, _) = $0 { true } else { false } })
        #expect(h.context.consent.optedOut)
    }

    @Test("Opted-out users get nothing except START handling")
    func optedOutSilence() async {
        let h = GatewayHarness()
        await h.send("Hi")
        await h.send("STOP")
        for text in ["Hi", "1", "MENU", "HELP", "@amazon hi", "STOP", "BACK"] {
            let t = await h.send(text)
            #expect(t.smsBodies.isEmpty, "\(text)")
            #expect(h.forwards(t).isEmpty)
            #expect(h.state == .optedOut)
        }
        // Business messages are held, not sent.
        let held = h.engine.deliverBusinessMessage(businessId: GatewayHarness.airline.id, sessionId: SessionID(), text: "promo",
                                                   context: h.context, now: h.clock)
        #expect(held.smsBodies.isEmpty)
        let t = await h.send("start")
        #expect(h.state == .idleMenu)
        #expect(t.smsBodies.first?.hasPrefix(GatewayCopy.resubscribed) == true)
        #expect(t.effects.contains { if case .recordConsent(false, "START", _) = $0 { true } else { false } })
        #expect(!h.context.consent.optedOut)
    }

    @Test("START/UNSTOP/YES are only opt-in keywords from OPTED_OUT")
    func startElsewhereIsContent() async {
        let h = GatewayHarness()
        await h.connect(GatewayHarness.airline)
        for word in ["START", "YES", "unstop"] {
            let t = await h.send(word)
            #expect(h.forwards(t).map(\.2) == [word])
            #expect(!t.effects.contains { if case .recordConsent = $0 { true } else { false } })
        }
        let h2 = GatewayHarness()
        await h2.send("STOP")
        await h2.send("YES")
        #expect(h2.state == .idleMenu)
    }

    @Test("MENU and BACK are gateway controls; escape sends them literally")
    func menuBackEscape() async {
        let h = GatewayHarness()
        await h.connect(GatewayHarness.airline)
        let back = await h.send("back")
        #expect(h.forwards(back).isEmpty)
        #expect(back.smsBodies.first?.contains("\\BACK") == true)
        let esc = await h.send("\\MENU")
        #expect(h.forwards(esc).map(\.2) == ["MENU"])
        let esc2 = await h.send("\\back")
        #expect(h.forwards(esc2).map(\.2) == ["back"])
        await h.send("MENU")
        #expect(h.state == .sessionMenu)
        await h.send("BACK")
        #expect(h.state == .connected)
        await h.send("MENU")
        let end = await h.send("3")
        #expect(end.effects.contains { if case .closeSession(_, _, .endedByUser) = $0 { true } else { false } })
        #expect(h.state == .idleMenu)
        let esc3 = await h.send("\\hello")
        #expect(h.forwards(esc3).isEmpty)
        #expect(esc3.smsBodies == [GatewayCopy.notConnected])
        // BACK from submenus returns to the main menu.
        await h.send("4")
        #expect(h.context.menu?.kind == .more)
        await h.send("BACK")
        #expect(h.context.menu?.kind == .main)
    }

    @Test("Stale replies (sent before the current menu) re-display it and never route")
    func staleMenu() async {
        let h = GatewayHarness()
        await h.send("Hi")
        let menuIssued = h.clock
        await h.send("1") // recent menu issued now
        let recentIssued = h.clock
        #expect(recentIssued > menuIssued)
        // A delayed "2" that the user sent in reply to the *main* menu arrives after the recent menu.
        let t = await h.send("2", receivedAt: menuIssued.addingTimeInterval(1))
        #expect(h.state == .recentMenu)
        #expect(t.smsBodies.first?.hasPrefix(GatewayCopy.staleReply) == true)
        #expect(t.effects.allSatisfy { if case .openSession = $0 { false } else { true } })
        #expect((h.context.menu?.version ?? 0) > 2)
    }

    @Test("Expired menus re-display and never route")
    func expiredMenu() async {
        let h = GatewayHarness()
        await h.send("Hi")
        await h.send("1")
        let t = await h.send("1", advance: 11 * 60)
        #expect(t.smsBodies.first?.hasPrefix(GatewayCopy.expiredMenu) == true)
        #expect(h.forwards(t).isEmpty)
        #expect(t.effects.allSatisfy { if case .openSession = $0 { false } else { true } })
        #expect(h.state == .recentMenu)
        // After re-display the fresh menu works.
        await h.send("1")
        #expect(h.state == .connected)
    }

    @Test("Invalid numbers re-display the menu", arguments: ["5", "0", "9.", "42"])
    func invalidChoice(text: String) async {
        let h = GatewayHarness()
        await h.send("Hi")
        let t = await h.send(text)
        #expect(t.smsBodies.first?.hasPrefix(GatewayCopy.invalidChoice) == true)
        #expect(h.state == .idleMenu)
    }

    @Test("Numbers without an active menu are never treated as choices")
    func digitWithoutMenu() async {
        let h = GatewayHarness()
        await h.send("Hi")
        await h.send("2")
        #expect(h.state == .searchPending)
        #expect(h.context.menu == nil)
        let t = await h.send("1")
        #expect(t.effects.allSatisfy { if case .openSession = $0 { false } else { true } })
        #expect(h.state == .searchPending) // treated as a (failed) search
    }

    // MARK: Acceptance 8 — duplicate / delayed / failed webhooks

    @Test("Duplicate provider deliveries are idempotent")
    func duplicates() async {
        let h = GatewayHarness()
        await h.connect(GatewayHarness.airline)
        let first = await h.send("Where is my bag?", id: "SMdup")
        let ctx = h.context
        let second = await h.send("Where is my bag?", id: "SMdup")
        #expect(h.forwards(first).count == 1)
        #expect(second.effects.isEmpty)
        #expect(h.context == ctx)
    }

    @Test("Directory failures never route and never forward an ambiguous @mention")
    func directoryFailure() async {
        let h = GatewayHarness()
        await h.connect(GatewayHarness.airline)
        h.directory.failing = true
        let t = await h.send("@harborhotel hi")
        #expect(h.forwards(t).isEmpty)
        #expect(t.smsBodies == [GatewayCopy.directoryUnavailable])
        #expect(h.state == .connected)
        // Plain text still forwards (no lookup needed).
        let p = await h.send("ok thanks")
        #expect(h.forwards(p).count == 1)
        let h2 = GatewayHarness()
        await h2.send("Hi")
        h2.directory.failing = true
        let r = await h2.send("1")
        #expect(r.smsBodies == [GatewayCopy.directoryUnavailable])
    }

    @Test("Idle sessions expire; the next message is held, not routed")
    func sessionExpiry() async {
        let h = GatewayHarness()
        await h.connect(GatewayHarness.airline)
        let t = await h.send("Is my flight on time?", advance: 25 * 3600)
        #expect(h.state == .expired)
        #expect(h.forwards(t).isEmpty)
        #expect(t.effects.contains { if case .closeSession(_, _, .expired) = $0 { true } else { false } })
        #expect(t.smsBodies.last?.contains("1. Send it to Sky Air\n2. Main menu") == true)
        let r = await h.send("1")
        #expect(h.state == .connected)
        #expect(h.forwards(r).map(\.2) == ["Is my flight on time?"])
        #expect(h.forwards(r).map(\.0) == [GatewayHarness.airline.id])
    }

    // MARK: Invariants

    @Test("Menus never exceed four options and states stay consistent across a long scripted session")
    func invariants() async {
        let h = GatewayHarness(linked: false)
        let script = ["Hi", "2", "bean", "9", "1", "MENU", "4", "1", "BACK", "@amazon yo", "BACK", "3", "1", "HELP", "STOP",
                      "x", "START", "4", "2", "3", "4", "BACK", "AF-2345", "2"]
        for text in script {
            let t = await h.send(text)
            if let menu = h.context.menu { #expect(menu.options.count <= 4) }
            if h.state == .connected { #expect(h.context.session != nil) }
            if h.forwards(t).count > 0 { #expect(h.state == .connected) }
            #expect(h.context.revision > 0)
        }
    }

    @Test func keywordNormalization() {
        #expect(GatewayKeyword.classify(" stop.  ") == .optOut)
        #expect(GatewayKeyword.classify("Stop!") == .optOut)
        #expect(GatewayKeyword.classify("stop sending") == nil)
        #expect(GatewayKeyword.classify("cancel my order") == nil)
        #expect(GatewayKeyword.classify("info") == .help)
        #expect(GatewayKeyword.classify("Menu") == .menu)
        #expect(GatewayKeyword.classify("unstop") == .optIn)
    }

    @Test("Multi-word messages containing keywords are ordinary content while connected")
    func keywordsInsideText() async {
        let h = GatewayHarness()
        await h.connect(GatewayHarness.airline)
        let t = await h.send("cancel my order please")
        #expect(h.forwards(t).map(\.2) == ["cancel my order please"])
        #expect(h.state == .connected)
    }

    @Test func contextIsCodable() async throws {
        let h = GatewayHarness()
        await h.send("Hi")
        await h.send("1")
        let data = try ViadereJSON.encode(h.context)
        let decoded = try ViadereJSON.decode(ConversationContext.self, from: data)
        #expect(decoded.state == h.context.state)
        #expect(decoded.menu?.options == h.context.menu?.options)
        let effects = try ViadereJSON.decode([GatewayEffect].self, from: ViadereJSON.encode(h.lastEffects))
        #expect(effects.count == h.lastEffects.count)
    }
}
