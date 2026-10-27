import Foundation

/// The pure, deterministic SMS gateway state machine.
///
/// Given the persisted `ConversationContext`, an inbound message, the current time and a
/// `DirectoryLookup`, it returns the next context and an ordered list of `GatewayEffect`s.
/// It performs no I/O other than directory reads and holds no state of its own.
///
/// Processing order for an inbound message:
/// 1. **Idempotency**: a provider message id already in `recentProviderMessageIds` yields no effects.
/// 2. **Opt-out keywords** (all states): opt out, close any session, confirm once.
/// 3. **OPTED_OUT gate**: only START/UNSTOP/YES are acted on; everything else is silently dropped.
/// 4. **HELP/INFO** (all other states): help text; state unchanged.
/// 5. **Session idle expiry**: an idle CONNECTED/SESSION_MENU session moves to EXPIRED; the message is held, never routed.
/// 6. **Escape** (`\…`): literal text to the connected business; otherwise "not connected".
/// 7. **MENU / BACK** gateway controls.
/// 8. **State handling**: menu digits (only with an active, unexpired, current menu), confirmation,
///    search queries, direct addressing (`@handle text`, `CODE text`), and verbatim forwarding in CONNECTED.
///
/// Routing invariants: messages are only forwarded in CONNECTED to `context.session`; switching
/// requires an explicit selection or confirmation; ambiguous/unknown input is never routed;
/// business replies are only rendered when they belong to the active session.
public struct SMSGatewayEngine: Sendable {
    public let configuration: GatewayConfiguration
    public let directory: any DirectoryLookup
    private let makeSessionID: @Sendable () -> SessionID

    /// - Parameter makeSessionID: Injected for deterministic tests; defaults to random UUIDs.
    public init(configuration: GatewayConfiguration = GatewayConfiguration(), directory: any DirectoryLookup,
                makeSessionID: @escaping @Sendable () -> SessionID = { SessionID() }) {
        self.configuration = configuration
        self.directory = directory
        self.makeSessionID = makeSessionID
    }

    // MARK: - Public entry points

    /// Handles one inbound SMS.
    public func handle(_ inbound: InboundSMS, context: ConversationContext, now: Date) async -> GatewayTransition {
        if context.recentProviderMessageIds.contains(inbound.providerMessageId) {
            return GatewayTransition(context: context, effects: [])
        }
        var run = Run(engine: self, context: context, now: now, inbound: inbound)
        run.context.recentProviderMessageIds.append(inbound.providerMessageId)
        if run.context.recentProviderMessageIds.count > configuration.dedupMemory {
            run.context.recentProviderMessageIds.removeFirst(run.context.recentProviderMessageIds.count - configuration.dedupMemory)
        }
        run.context.revision += 1
        await run.process()
        return run.finish()
    }

    /// The server calls this after an account-link token is redeemed for this phone number.
    public func accountLinked(consumerId: ConsumerID, context: ConversationContext, now: Date) -> GatewayTransition {
        var run = Run(engine: self, context: context, now: now, inbound: nil)
        run.context.revision += 1
        run.context.consumerId = consumerId
        run.context.linkPendingUntil = nil
        guard run.context.state != .optedOut else {
            run.audit("gateway.account_linked")
            return run.finish()
        }
        run.send(GatewayCopy.linked)
        if let pending = run.context.pending {
            run.showConfirm(pending.business, message: pending.message, providerMessageId: pending.providerMessageId)
        } else if [.new, .unlinked, .linkPending].contains(run.context.state) {
            run.showMainMenu(header: nil)
        }
        run.audit("gateway.account_linked")
        return run.finish()
    }

    /// Renders a business → consumer message. Only shown when it belongs to the active session
    /// in CONNECTED/SESSION_MENU; otherwise held in history (never shown in another tenant's context).
    public func deliverBusinessMessage(businessId: BusinessID, sessionId: SessionID, text: String,
                                       context: ConversationContext, now: Date) -> GatewayTransition {
        var ctx = context
        guard ctx.state == .connected || ctx.state == .sessionMenu, !ctx.consent.optedOut,
              var session = ctx.session, session.business.id == businessId, session.sessionId == sessionId
        else {
            return GatewayTransition(context: ctx, effects: [.holdBusinessMessage(businessId: businessId, sessionId: sessionId)])
        }
        session.lastActivityAt = now
        ctx.session = session
        ctx.revision += 1
        let body = GatewayCopy.attribution(session.business)
            + SMSEncoding.businessLine(text)
        return GatewayTransition(context: ctx, effects: [.sendSMS(body)])
    }

    // MARK: - Run

    fileprivate struct Run {
        let engine: SMSGatewayEngine
        var context: ConversationContext
        let now: Date
        let inbound: InboundSMS?
        var effects: [GatewayEffect] = []
        let initialState: GatewayState

        init(engine: SMSGatewayEngine, context: ConversationContext, now: Date, inbound: InboundSMS?) {
            self.engine = engine
            self.context = context
            self.now = now
            self.inbound = inbound
            self.initialState = context.state
        }

        var config: GatewayConfiguration { engine.configuration }
        var directory: any DirectoryLookup { engine.directory }

        func finish() -> GatewayTransition { GatewayTransition(context: context, effects: effects) }

        mutating func send(_ body: String) { effects.append(.sendSMS(body)) }

        mutating func audit(_ action: String, business: BusinessID? = nil, session: SessionID? = nil) {
            effects.append(.audit(GatewayAudit(action: action, from: initialState, to: context.state, businessId: business,
                                               sessionId: session, providerMessageId: inbound?.providerMessageId)))
        }

        // MARK: Processing

        mutating func process() async {
            guard let inbound else { return }
            let text = inbound.text
            let keyword = GatewayKeyword.classify(text)

            // 2. Opt-out (all states, not escapable).
            if keyword == .optOut || isEscapedCarrierKeyword(text, .optOut) {
                optOut(keyword: GatewayKeyword.normalize(text))
                return
            }
            // 3. Opted-out gate.
            if context.state == .optedOut || context.consent.optedOut {
                if keyword == .optIn {
                    context.consent = SMSConsentState(optedOut: false, consentVersion: context.consent.consentVersion, updatedAt: now)
                    effects.append(.recordConsent(optedOut: false, keyword: GatewayKeyword.normalize(text), at: now))
                    showMainMenu(header: GatewayCopy.resubscribed)
                    audit("gateway.opt_in")
                } else if keyword == .help || isEscapedCarrierKeyword(text, .help) {
                    // Carrier/CTIA guidance: HELP must always be answered, even after opt-out.
                    send(GatewayCopy.help)
                    audit("gateway.help")
                } else {
                    audit("gateway.dropped_opted_out")
                }
                return
            }
            context.lastActivityAt = now
            // 4. HELP / INFO (not escapable).
            if keyword == .help || isEscapedCarrierKeyword(text, .help) {
                send(GatewayCopy.help)
                audit("gateway.help")
                return
            }
            // Link-pending expiry is silent: fall back to UNLINKED.
            if context.state == .linkPending, let until = context.linkPendingUntil, now >= until {
                context.state = .unlinked
                context.linkPendingUntil = nil
            }
            // 5. Session idle expiry.
            if let session = context.session, context.state == .connected || context.state == .sessionMenu,
               now.timeIntervalSince(session.lastActivityAt) >= config.sessionIdleTTL {
                let held = context.state == .sessionMenu ? nil : heldText(for: text, keyword: keyword)
                expireSession(session, heldText: held, inbound: inbound, keyword: keyword)
                return
            }
            // 6. Escape.
            if text.trimmingCharacters(in: .whitespacesAndNewlines).first == GatewayKeyword.escapePrefix {
                let literal = String(text.trimmingCharacters(in: .whitespacesAndNewlines).dropFirst())
                if context.state == .connected || context.state == .sessionMenu, let session = context.session, !literal.isEmpty {
                    forward(literal, session: session, providerMessageId: inbound.providerMessageId)
                } else {
                    send(GatewayCopy.notConnected)
                    audit("gateway.escape_not_connected")
                }
                return
            }
            // 7. Gateway controls.
            if keyword == .menu {
                if let session = context.session, context.state == .connected || context.state == .sessionMenu {
                    showSessionMenu(session)
                } else {
                    context.pending = nil
                    showMainMenu(header: nil)
                }
                audit("gateway.menu")
                return
            }
            if keyword == .back {
                back()
                audit("gateway.back")
                return
            }
            // 8. State handling.
            await handleText(text, inbound: inbound)
        }

        /// `\STOP` / `\HELP` are still carrier keywords.
        func isEscapedCarrierKeyword(_ text: String, _ keyword: GatewayKeyword) -> Bool {
            let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
            guard trimmed.first == GatewayKeyword.escapePrefix else { return false }
            return GatewayKeyword.classify(String(trimmed.dropFirst())) == keyword
        }

        func heldText(for text: String, keyword: GatewayKeyword?) -> String? {
            if keyword != nil { return nil }
            let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.first == GatewayKeyword.escapePrefix {
                let literal = String(trimmed.dropFirst())
                return literal.isEmpty ? nil : literal
            }
            return trimmed.isEmpty ? nil : text
        }

        mutating func handleText(_ text: String, inbound: InboundSMS) async {
            switch context.state {
            case .connected:
                await handleConnected(text, inbound: inbound)
            case .confirmDestination:
                let word = GatewayKeyword.normalize(text)
                if ["YES", "Y"].contains(word) {
                    await handleDigit(1, inbound: inbound)
                } else if ["NO", "N"].contains(word) {
                    await handleDigit(2, inbound: inbound)
                } else if let digit = Self.menuDigit(text) {
                    await handleDigit(digit, inbound: inbound)
                } else {
                    await resolve(text, inbound: inbound, isSearch: true)
                }
            case .searchPending:
                await resolve(text, inbound: inbound, isSearch: true)
            case .new:
                if Self.looksLikeDirectAddress(text) {
                    await resolve(text, inbound: inbound, isSearch: false)
                } else {
                    showMainMenu(header: GatewayCopy.welcome)
                    audit("gateway.welcome")
                }
            case .unlinked, .linkPending, .idleMenu, .recentMenu, .disambiguation, .sessionMenu, .expired:
                if let digit = Self.menuDigit(text) {
                    await handleDigit(digit, inbound: inbound)
                } else if Self.isGreeting(text) {
                    if let session = context.session, context.state == .sessionMenu { showSessionMenu(session) } else { showMainMenu(header: nil) }
                } else {
                    await resolve(text, inbound: inbound, isSearch: true)
                }
            case .optedOut:
                break
            }
        }

        mutating func handleDigit(_ digit: Int, inbound: InboundSMS) async {
            guard let menu = context.menu else {
                // A bare number with no menu: never route; show the right menu.
                if let session = context.session, context.state == .sessionMenu { showSessionMenu(session) } else { showMainMenu(header: nil) }
                audit("gateway.digit_without_menu")
                return
            }
            if !menu.isActive(at: now) {
                reissue(menu, header: GatewayCopy.expiredMenu)
                audit("gateway.menu_expired")
                return
            }
            if inbound.receivedAt < menu.issuedAt {
                reissue(menu, header: GatewayCopy.staleReply)
                audit("gateway.menu_stale")
                return
            }
            guard let option = menu.options.first(where: { $0.number == digit }) else {
                reissue(menu, header: GatewayCopy.invalidChoice)
                audit("gateway.menu_invalid")
                return
            }
            await perform(option.action)
        }

        mutating func handleConnected(_ text: String, inbound: InboundSMS) async {
            guard let session = context.session else {
                showMainMenu(header: nil)
                return
            }
            // Direct addressing to a *different* verified business requires confirmation; the
            // message is held (never sent to the current business).
            if let first = text.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: " ", maxSplits: 1).first,
               first.hasPrefix("@"), let handle = BusinessHandle(parsing: String(first)) {
                let found: BusinessSummary?
                do { found = try await directory.business(byHandle: handle) } catch {
                    // Uncertain whether this was a switch: do not forward to the current business.
                    send(GatewayCopy.directoryUnavailable)
                    audit("gateway.directory_error")
                    return
                }
                if let found, found.isVerified, found.id != session.business.id {
                    let rest = Self.remainder(after: first, in: text)
                    showConfirm(found, message: rest, providerMessageId: inbound.providerMessageId)
                    audit("gateway.switch_requested", business: found.id)
                    return
                }
            }
            forward(text, session: session, providerMessageId: inbound.providerMessageId)
        }

        mutating func forward(_ text: String, session: ActiveSession, providerMessageId: String) {
            var session = session
            session.lastActivityAt = now
            context.session = session
            context.state = .connected
            context.menu = nil
            let body = text.count > config.maxForwardLength ? String(text.prefix(config.maxForwardLength)) : text
            effects.append(.forwardToBusiness(businessId: session.business.id, sessionId: session.sessionId, text: body,
                                              providerMessageId: providerMessageId))
            audit("gateway.forwarded", business: session.business.id, session: session.sessionId)
        }

        // MARK: Resolution

        /// Resolves a name / @handle / code query, with optional direct-addressed message.
        mutating func resolve(_ text: String, inbound: InboundSMS, isSearch: Bool) async {
            let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else {
                showMainMenu(header: nil)
                return
            }
            let parts = trimmed.split(separator: " ", maxSplits: 1)
            let first = String(parts[0])
            let rest = Self.remainder(after: parts[0], in: trimmed)
            do {
                if first.hasPrefix("@") {
                    guard let handle = BusinessHandle(parsing: first),
                          let business = try await directory.business(byHandle: handle), business.isVerified else {
                        noMatch(first)
                        return
                    }
                    showConfirm(business, message: rest, providerMessageId: rest == nil ? nil : inbound.providerMessageId)
                    audit("gateway.resolved_handle", business: business.id)
                    return
                }
                if let code = BusinessCode(parsing: first), let business = try await directory.business(byCode: code), business.isVerified {
                    showConfirm(business, message: rest, providerMessageId: rest == nil ? nil : inbound.providerMessageId)
                    audit("gateway.resolved_code", business: business.id)
                    return
                }
                // Whole input as a code ("af 2345").
                if rest != nil, let code = BusinessCode(parsing: trimmed), let business = try await directory.business(byCode: code),
                   business.isVerified {
                    showConfirm(business, message: nil, providerMessageId: nil)
                    audit("gateway.resolved_code", business: business.id)
                    return
                }
                let query = String(trimmed.prefix(64))
                let matches = try await directory.search(name: query, limit: 10).filter(\.isVerified)
                var seen = Set<BusinessID>()
                let unique = matches.filter { seen.insert($0.id).inserted }
                switch unique.count {
                case 0:
                    noMatch(query)
                case 1:
                    showConfirm(unique[0], message: nil, providerMessageId: nil)
                    audit("gateway.resolved_search", business: unique[0].id)
                default:
                    showDisambiguation(Array(unique.prefix(3)))
                    audit("gateway.disambiguation")
                }
            } catch {
                send(GatewayCopy.directoryUnavailable)
                audit("gateway.directory_error")
            }
        }

        mutating func noMatch(_ query: String) {
            context.pending = nil
            context.state = .searchPending
            context.menu = nil
            send(GatewayCopy.noMatch(query))
            audit("gateway.no_match")
        }

        // MARK: Actions

        mutating func perform(_ action: MenuAction) async {
            switch action {
            case .showRecent:
                await showRecent()
            case .findBusiness:
                promptSearch(header: nil)
            case .accountHelp:
                effects.append(.sendSecureHandoff(.accountHelp))
                audit("gateway.handoff_account_help")
            case .moreOptions:
                showMenu(kind: .more, state: mainState, header: "Viadere: More options", options: [
                    MenuOption(number: 1, label: "How Viadere works", action: .howItWorks),
                    MenuOption(number: 2, label: "Privacy & opt-out", action: .privacy),
                    MenuOption(number: 3, label: "Manage businesses in app", action: .manageInApp),
                    MenuOption(number: 4, label: "Back", action: .mainMenu),
                ])
            case .linkAccount:
                startLink(header: GatewayCopy.linkSent)
            case .help:
                send(GatewayCopy.help)
            case .selectBusiness(let business):
                // Selecting from a numbered list of verified businesses is an explicit choice.
                await connect(business, message: nil, providerMessageId: nil)
            case .confirmDestination:
                guard let pending = context.pending else {
                    showMainMenu(header: nil)
                    return
                }
                await connect(pending.business, message: pending.message, providerMessageId: pending.providerMessageId)
            case .cancelDestination:
                context.pending = nil
                if let session = context.session {
                    // Cancelling a switch returns to the existing conversation.
                    context.state = .connected
                    context.menu = nil
                    send(GatewayCopy.continued(session.business))
                } else {
                    showMainMenu(header: nil)
                }
                audit("gateway.confirm_cancelled")
            case .continueSession:
                guard let session = context.session else {
                    showMainMenu(header: nil)
                    return
                }
                context.state = .connected
                context.menu = nil
                send(GatewayCopy.continued(session.business))
            case .switchBusiness:
                closeSession(reason: .switched, announce: false)
                await showRecent()
            case .endSession:
                closeSession(reason: .endedByUser, announce: true)
                showMainMenu(header: nil)
            case .resume(let business):
                let held = context.pending?.business.id == business.id ? context.pending : nil
                await connect(business, message: held?.message, providerMessageId: held?.providerMessageId)
            case .mainMenu:
                context.pending = nil
                showMainMenu(header: nil)
            case .howItWorks:
                send(GatewayCopy.howItWorks)
            case .privacy:
                send(GatewayCopy.privacy)
            case .manageInApp:
                effects.append(.sendSecureHandoff(.manageBusinesses))
                audit("gateway.handoff_manage")
            }
        }

        mutating func connect(_ candidate: BusinessSummary, message: String?, providerMessageId: String?) async {
            // Re-check verification at the moment of routing.
            let current: BusinessSummary?
            do { current = try await directory.business(byId: candidate.id) } catch {
                send(GatewayCopy.directoryUnavailable)
                audit("gateway.directory_error")
                return
            }
            guard let business = current, business.isVerified else {
                context.pending = nil
                send(GatewayCopy.businessUnavailable(candidate))
                showMainMenu(header: nil)
                audit("gateway.business_unavailable", business: candidate.id)
                return
            }
            if config.requireLinkForRouting && !context.isLinked {
                context.pending = PendingDestination(business: business, message: message, providerMessageId: providerMessageId)
                startLink(header: GatewayCopy.linkRequired(business))
                return
            }
            if let existing = context.session {
                if existing.business.id == business.id {
                    context.pending = nil
                    context.state = .connected
                    context.menu = nil
                    send(GatewayCopy.continued(business))
                    if let message, let providerMessageId {
                        forward(message, session: existing, providerMessageId: providerMessageId)
                    }
                    return
                }
                closeSession(reason: .switched, announce: false)
            }
            let session = ActiveSession(sessionId: engine.makeSessionID(), business: business, startedAt: now, lastActivityAt: now)
            context.session = session
            context.pending = nil
            context.menu = nil
            context.state = .connected
            effects.append(.openSession(businessId: business.id, sessionId: session.sessionId))
            send(GatewayCopy.connected(business))
            audit("gateway.session_opened", business: business.id, session: session.sessionId)
            if let message, !message.isEmpty, let providerMessageId {
                forward(message, session: session, providerMessageId: providerMessageId)
            }
        }

        mutating func closeSession(reason: SessionCloseReason, announce: Bool) {
            guard let session = context.session else { return }
            effects.append(.closeSession(businessId: session.business.id, sessionId: session.sessionId, reason: reason))
            if announce { send(GatewayCopy.ended(session.business)) }
            context.session = nil
            audit("gateway.session_closed", business: session.business.id, session: session.sessionId)
        }

        mutating func optOut(keyword: String) {
            guard context.state != .optedOut else {
                // Already opted out: no further messages.
                audit("gateway.opt_out_repeat")
                return
            }
            if let session = context.session {
                effects.append(.closeSession(businessId: session.business.id, sessionId: session.sessionId, reason: .optedOut))
            }
            context.session = nil
            context.pending = nil
            context.menu = nil
            context.linkPendingUntil = nil
            context.state = .optedOut
            context.consent = SMSConsentState(optedOut: true, consentVersion: context.consent.consentVersion, updatedAt: now)
            effects.append(.recordConsent(optedOut: true, keyword: keyword, at: now))
            send(GatewayCopy.optOutConfirmation)
            audit("gateway.opt_out")
        }

        mutating func expireSession(_ session: ActiveSession, heldText: String?, inbound: InboundSMS, keyword: GatewayKeyword?) {
            effects.append(.closeSession(businessId: session.business.id, sessionId: session.sessionId, reason: .expired))
            context.session = nil
            audit("gateway.session_expired", business: session.business.id, session: session.sessionId)
            if keyword == .menu {
                showMainMenu(header: GatewayCopy.expiredSession(session.business, messageHeld: false))
                return
            }
            context.pending = heldText.map {
                PendingDestination(business: session.business, message: $0, providerMessageId: inbound.providerMessageId)
            }
            let label = heldText == nil ? "Continue with \(GatewayCopy.safeName(session.business))"
                : "Send it to \(GatewayCopy.safeName(session.business))"
            showMenu(kind: .expired, state: .expired, header: GatewayCopy.expiredSession(session.business, messageHeld: heldText != nil),
                     options: [
                        MenuOption(number: 1, label: label, action: .resume(session.business)),
                        MenuOption(number: 2, label: "Main menu", action: .mainMenu),
                     ])
        }

        mutating func back() {
            switch context.state {
            case .connected:
                if let session = context.session { send(GatewayCopy.backWhileConnected(session.business)) }
            case .sessionMenu:
                if let session = context.session {
                    context.state = .connected
                    context.menu = nil
                    send(GatewayCopy.continued(session.business))
                } else {
                    showMainMenu(header: nil)
                }
            case .confirmDestination:
                context.pending = nil
                if let session = context.session {
                    context.state = .connected
                    context.menu = nil
                    send(GatewayCopy.continued(session.business))
                } else {
                    showMainMenu(header: nil)
                }
            default:
                context.pending = nil
                showMainMenu(header: nil)
            }
        }

        // MARK: Menus

        var mainState: GatewayState {
            if context.isLinked { return .idleMenu }
            if let until = context.linkPendingUntil, now < until { return .linkPending }
            return .unlinked
        }

        mutating func showMainMenu(header: String?) {
            let state = mainState
            var lines: [String] = []
            if let header { lines.append(header) }
            switch state {
            case .idleMenu:
                lines.append("Viadere: How can we help?")
                showMenu(kind: .main, state: state, header: lines.joined(separator: "\n"), options: [
                    MenuOption(number: 1, label: "Recent businesses", action: .showRecent),
                    MenuOption(number: 2, label: "Find a business", action: .findBusiness),
                    MenuOption(number: 3, label: "Account help", action: .accountHelp),
                    MenuOption(number: 4, label: "More options", action: .moreOptions),
                ])
            case .linkPending:
                lines.append("Viadere: Waiting for you to open your account link.")
                showMenu(kind: .linkPending, state: state, header: lines.joined(separator: "\n"), options: [
                    MenuOption(number: 1, label: "Resend link", action: .linkAccount),
                    MenuOption(number: 2, label: "Find a business", action: .findBusiness),
                    MenuOption(number: 3, label: "Help", action: .help),
                    MenuOption(number: 4, label: "More options", action: .moreOptions),
                ])
            default:
                lines.append("Viadere: How can we help?")
                showMenu(kind: .unlinkedMain, state: .unlinked, header: lines.joined(separator: "\n"), options: [
                    MenuOption(number: 1, label: "Link your account", action: .linkAccount),
                    MenuOption(number: 2, label: "Find a business", action: .findBusiness),
                    MenuOption(number: 3, label: "Help", action: .help),
                    MenuOption(number: 4, label: "More options", action: .moreOptions),
                ])
            }
        }

        mutating func showRecent() async {
            let recent: [BusinessSummary]
            do {
                recent = try await directory.recentBusinesses(consumerId: context.consumerId, phone: context.phone, limit: 6)
                    .filter(\.isVerified)
            } catch {
                send(GatewayCopy.directoryUnavailable)
                audit("gateway.directory_error")
                return
            }
            guard !recent.isEmpty else {
                promptSearch(header: GatewayCopy.noRecent)
                return
            }
            var options = recent.prefix(3).enumerated().map { index, business in
                MenuOption(number: index + 1, label: GatewayCopy.label(business), action: .selectBusiness(business))
            }
            options.append(MenuOption(number: 4, label: "Search by name", action: .findBusiness))
            showMenu(kind: .recent, state: .recentMenu, header: "Viadere: Recent businesses", options: options)
        }

        mutating func showDisambiguation(_ matches: [BusinessSummary]) {
            context.pending = nil
            var options = matches.enumerated().map { index, business in
                MenuOption(number: index + 1, label: GatewayCopy.label(business) + " " + business.code.display,
                           action: .selectBusiness(business))
            }
            options.append(MenuOption(number: 4, label: "Search again", action: .findBusiness))
            showMenu(kind: .disambiguation, state: .disambiguation, header: "Viadere: Which one did you mean?", options: options)
        }

        mutating func showConfirm(_ business: BusinessSummary, message: String?, providerMessageId: String?) {
            let message = message?.isEmpty == true ? nil : message
            context.pending = PendingDestination(business: business, message: message, providerMessageId: message == nil ? nil : providerMessageId)
            showMenu(kind: .confirm, state: .confirmDestination,
                     header: GatewayCopy.confirm(business, hasPendingMessage: message != nil), options: [
                        MenuOption(number: 1, label: "Yes, connect", action: .confirmDestination),
                        MenuOption(number: 2, label: "No, go back", action: .cancelDestination),
                     ])
        }

        mutating func showSessionMenu(_ session: ActiveSession) {
            let name = GatewayCopy.safeName(session.business)
            showMenu(kind: .session, state: .sessionMenu, header: GatewayCopy.sessionHeader(session.business), options: [
                MenuOption(number: 1, label: "Continue with \(name)", action: .continueSession),
                MenuOption(number: 2, label: "Switch business", action: .switchBusiness),
                MenuOption(number: 3, label: "End conversation", action: .endSession),
            ])
        }

        mutating func promptSearch(header: String?) {
            context.menu = nil
            context.pending = nil
            context.state = .searchPending
            send(([header].compactMap { $0 } + [GatewayCopy.searchPrompt]).joined(separator: "\n"))
        }

        mutating func startLink(header: String) {
            context.linkPendingUntil = now.addingTimeInterval(config.linkTTL)
            context.state = .linkPending
            context.menu = nil
            send(header)
            effects.append(.sendAccountLink)
            audit("gateway.link_issued")
        }

        mutating func showMenu(kind: MenuKind, state: GatewayState, header: String, options: [MenuOption]) {
            assert(options.count <= ChannelRenderer.maxSMSChoices, "SMS menus have at most 4 options")
            let options = Array(options.prefix(ChannelRenderer.maxSMSChoices))
            context.menuVersion += 1
            let menu = ActiveMenu(id: "\(kind.rawValue)-\(context.menuVersion)", version: context.menuVersion, kind: kind,
                                  options: options, issuedAt: now, expiresAt: now.addingTimeInterval(config.menuTTL))
            context.menu = menu
            context.state = state
            send(GatewayCopy.menu(header: header, options: options))
        }

        /// Re-displays a menu with a fresh version and expiry (same options).
        mutating func reissue(_ menu: ActiveMenu, header: String) {
            showMenu(kind: menu.kind, state: context.state, header: header, options: menu.options)
        }

        // MARK: Parsing helpers

        /// A bare one- or two-digit number (allowing surrounding whitespace and a trailing `.` or `)`).
        /// Only meaningful while a menu is displayed; out-of-range numbers re-display the menu.
        static func menuDigit(_ text: String) -> Int? {
            var s = Substring(text.trimmingCharacters(in: .whitespacesAndNewlines))
            if let last = s.last, last == "." || last == ")" { s = s.dropLast() }
            guard (1...2).contains(s.count), s.allSatisfy({ $0.isASCII && $0.isNumber }) else { return nil }
            return Int(s)
        }

        /// Greetings re-display the menu instead of being searched.
        static func isGreeting(_ text: String) -> Bool {
            ["HI", "HELLO", "HEY", "HOLA", "YO", "HIYA"].contains(GatewayKeyword.normalize(text))
        }

        /// `@handle …` or `CODE …` at the start of the message.
        static func looksLikeDirectAddress(_ text: String) -> Bool {
            let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
            guard let first = trimmed.split(separator: " ", maxSplits: 1).first else { return false }
            if first.hasPrefix("@") { return BusinessHandle(parsing: String(first)) != nil }
            // Require at least one digit so ordinary 6-letter words ("Thanks") are not treated as codes.
            return BusinessCode(parsing: String(first)) != nil && first.contains(where: \.isNumber)
        }

        /// Text after the first token, trimmed; `nil` if empty.
        static func remainder(after token: Substring, in text: String) -> String? {
            let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
            guard trimmed.count > token.count else { return nil }
            let rest = trimmed.dropFirst(token.count).trimmingCharacters(in: .whitespacesAndNewlines)
            return rest.isEmpty ? nil : rest
        }
    }
}
