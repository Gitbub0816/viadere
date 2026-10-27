import Crypto
import Foundation
import ViadereCore

/// An in-memory Viadere server for previews, tests and offline demos.
///
/// It is deliberately **strict**: device enrollment proofs and signed decisions are verified with ViadereCore's
/// `DeviceEnrollment` and `DecisionVerifier`, the same code the real server runs, so flows exercised against
/// the mock exercise the real cryptography.
public actor MockViadereAPI: ViadereAPI {
    public let consumerId: ConsumerID
    let clock: @Sendable () -> Date
    private var envelopes: [InteractionID: InteractionEnvelope] = [:]
    private var interactionOrder: [InteractionID] = []
    private var relationshipList: [Relationship] = []
    private var consentStore: [RelationshipID: [ConsentGrant]] = [:]
    var deviceList: [Device] = []
    var deviceKeys: [DeviceID: [DeviceKeyPurpose: DevicePublicKey]] = [:]
    private var enrollmentChallenges: Set<String> = []
    private var conversationList: [ConversationSummary] = []
    private var messageStore: [SessionID: [ConversationMessage]] = [:]
    private var phones: [PhoneLink] = []
    private var pendingPhoneCodes: [PhoneLinkID: String] = [:]
    private var consumerSessions: [ConsumerSession]
    private var consumedChallenges: Set<String> = []
    public private(set) var registeredAPNsTokens: [APNsTokenRegistration] = []
    public private(set) var liveActivityTokens: [LiveActivityTokenRegistration] = []
    public private(set) var decisionLog: [(InteractionID, Decision, DecisionAssurance)] = []
    public private(set) var accountDeleted = false
    /// P3 state: loyalty, rewards, Wallet, household, acknowledgments (see `MockP3.swift`).
    var p3 = MockP3State()
    /// Artificial latency, for demoing loading states.
    public var latency: Duration = .zero

    /// A server seeded with everything P3 shows: loyalty, Wallet, orders, appointments, travel, events, household.
    public static func p3Demo(clock: @escaping @Sendable () -> Date = { Date() }) -> MockViadereAPI {
        MockViadereAPI(seed: true, p3: true, clock: clock)
    }

    /// - Parameter p3: also seed the P3 world (extra businesses, loyalty, passes, activity). Off by default so the
    ///   P2 fixtures and their tests stay exactly as they were.
    public init(seed: Bool = true, p3: Bool = false, consumerId: ConsumerID = PreviewData.consumerId, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.consumerId = consumerId
        self.clock = clock
        let now = clock()
        consumerSessions = [ConsumerSession(id: "current", deviceName: "This iPhone", createdAt: now.addingTimeInterval(-3_600), lastSeenAt: now, isCurrent: true)]
        if seed {
            let data = Self.makeSeed(now: now, consumerId: consumerId)
            envelopes = data.envelopes
            interactionOrder = data.order
            relationshipList = data.relationships
            consentStore = data.consents
            conversationList = data.conversations
            messageStore = data.messages
            if p3 {
                let extra = Self.makeP3Seed(now: now, consumerId: consumerId, relationships: &relationshipList, consents: &consentStore)
                self.p3 = extra.state
                for envelope in extra.envelopes {
                    envelopes[envelope.id] = envelope
                    interactionOrder.append(envelope.id)
                }
            }
        }
    }

    private struct Seed {
        var envelopes: [InteractionID: InteractionEnvelope] = [:]
        var order: [InteractionID] = []
        var relationships: [Relationship] = []
        var consents: [RelationshipID: [ConsentGrant]] = [:]
        var conversations: [ConversationSummary] = []
        var messages: [SessionID: [ConversationMessage]] = [:]
    }

    private static func makeSeed(now: Date, consumerId: ConsumerID) -> Seed {
        var seed = Seed()
        let connected = [PreviewData.harborBank, PreviewData.northfield, PreviewData.lindenDental, PreviewData.juniperAir]
        for business in connected {
            let relationship = PreviewData.relationship(business, connectedAt: now.addingTimeInterval(-86_400 * 30))
            seed.relationships.append(relationship)
            seed.consents[relationship.id] = defaultConsents(for: relationship, consumerId: consumerId, now: now)
        }
        func rel(_ b: BusinessSummary) -> RelationshipID { seed.relationships.first { $0.business.id == b.id }?.id ?? RelationshipID() }
        let list = [
            PreviewData.authorize(now: now, relationship: rel(PreviewData.northfield)),
            PreviewData.authenticate(now: now, relationship: rel(PreviewData.harborBank)),
            PreviewData.choose(now: now, relationship: rel(PreviewData.lindenDental)),
            PreviewData.flightStatus(now: now, relationship: rel(PreviewData.juniperAir)),
        ]
        for envelope in list {
            seed.envelopes[envelope.id] = envelope
            seed.order.append(envelope.id)
        }
        let (summary, messages) = PreviewData.conversation(for: PreviewData.lindenDental, now: now)
        seed.conversations = [summary]
        seed.messages[summary.id] = messages
        return seed
    }

    /// Adds an interaction for demos and tests.
    public func add(_ envelope: InteractionEnvelope) {
        envelopes[envelope.id] = envelope
        interactionOrder.insert(envelope.id, at: 0)
    }

    private static func defaultConsents(for relationship: Relationship, consumerId: ConsumerID, now: Date) -> [ConsentGrant] {
        InteractionPurpose.allCases.map { purpose in
            ConsentGrant(id: ConsentGrantID(), consumerId: consumerId, businessId: relationship.business.id,
                         relationshipId: relationship.id, purpose: purpose, granted: purpose.isGrantedByDefault, version: 1,
                         policyVersion: "2026-10", source: .app, channels: [.nativePush, .inApp], createdAt: now, updatedAt: now)
        }
    }

    func pause() async {
        if latency > .zero { try? await Task.sleep(for: latency) }
    }

    private static func notFound() -> APIError { .server(status: 404, code: .notFound, message: "Not found") }

    // MARK: Auth

    public func beginRegistration(displayName: String) async throws -> PasskeyRegistrationOptions {
        await pause()
        return PasskeyRegistrationOptions(ceremonyId: CeremonyID(), challenge: SecureToken.generate(), relyingPartyId: ViadereCore.domain,
                                          relyingPartyName: "Viadere", userId: SecureToken.generate(byteCount: 16),
                                          userName: displayName, userDisplayName: displayName)
    }
    public func finishRegistration(_ request: PasskeyRegistrationFinishRequest) async throws -> AuthSession { grant() }
    public func beginLogin() async throws -> PasskeyAssertionOptions {
        await pause()
        return PasskeyAssertionOptions(ceremonyId: CeremonyID(), challenge: SecureToken.generate(), relyingPartyId: ViadereCore.domain)
    }
    public func finishLogin(_ request: PasskeyLoginFinishRequest) async throws -> AuthSession { grant() }
    public func logout() async throws {}
    public func deleteAccount() async throws { accountDeleted = true }

    private func grant() -> AuthSession {
        AuthSession(consumerId: consumerId, accessToken: SecureToken.generate(), expiresAt: clock().addingTimeInterval(900),
                    refreshToken: SecureToken.generate(), refreshExpiresAt: clock().addingTimeInterval(86_400 * 30))
    }

    // MARK: Devices

    public func beginDeviceEnrollment() async throws -> DeviceEnrollmentChallenge {
        let challenge = SecureToken.generate()
        enrollmentChallenges.insert(challenge)
        return DeviceEnrollmentChallenge(challenge: challenge, expiresAt: clock().addingTimeInterval(300))
    }

    public func enrollDevice(_ request: DeviceEnrollRequest) async throws -> Device {
        guard enrollmentChallenges.remove(request.challenge) != nil else {
            throw APIError.server(status: 400, code: .badRequest, message: "Unknown or reused challenge")
        }
        guard request.keys.contains(where: { $0.purpose == .request }) else {
            throw APIError.server(status: 400, code: .validationFailed, message: "A request key is required")
        }
        for registration in request.keys where !DeviceEnrollment.verify(registration, consumerId: consumerId, challenge: request.challenge) {
            throw APIError.server(status: 400, code: .signatureInvalid, message: "Invalid key proof")
        }
        let deviceId = DeviceID()
        let now = clock()
        let keys = request.keys.map {
            DeviceKey(id: DeviceKeyID(), purpose: $0.purpose, publicKey: $0.publicKey, hardwareBacked: $0.hardwareBacked, createdAt: now)
        }
        let device = Device(id: deviceId, consumerId: consumerId, name: request.name, platform: request.platform, keys: keys,
                            createdAt: now, lastSeenAt: now)
        deviceList.append(device)
        deviceKeys[deviceId] = Dictionary(uniqueKeysWithValues: keys.map { ($0.purpose, $0.publicKey) })
        return device
    }

    public func devices() async throws -> [Device] { deviceList }

    public func revokeDevice(_ id: DeviceID) async throws {
        guard let index = deviceList.firstIndex(where: { $0.id == id }) else { throw Self.notFound() }
        deviceList[index].revokedAt = clock()
    }

    // MARK: Phones & sessions

    public func startPhoneLink(phone: PhoneNumber) async throws -> PhoneLinkStartResponse {
        let id = PhoneLinkID()
        pendingPhoneCodes[id] = "123456"
        return PhoneLinkStartResponse(phoneLinkId: id, expiresAt: clock().addingTimeInterval(600))
    }

    public func verifyPhoneLink(id: PhoneLinkID, code: String) async throws -> PhoneLink {
        guard let expected = pendingPhoneCodes[id], ConstantTime.equals(expected, code) else {
            throw APIError.server(status: 400, code: .validationFailed, message: "That code isn't right")
        }
        pendingPhoneCodes[id] = nil
        let link = PhoneLink(id: id, maskedPhone: "+1 ••• ••• 0123", verifiedAt: clock())
        phones.append(link)
        return link
    }

    public func redeemSMSLink(token: String, confirmPhoneLast4: String) async throws -> PhoneLink {
        guard confirmPhoneLast4.count == 4 else { throw APIError.server(status: 400, code: .validationFailed, message: "Enter the last 4 digits") }
        let link = PhoneLink(id: PhoneLinkID(), maskedPhone: "+1 ••• ••• \(confirmPhoneLast4)", verifiedAt: clock())
        phones.append(link)
        return link
    }

    public func phoneLinks() async throws -> [PhoneLink] { phones }
    public func removePhoneLink(_ id: PhoneLinkID) async throws { phones.removeAll { $0.id == id } }
    public func sessions() async throws -> [ConsumerSession] { consumerSessions }
    public func revokeSession(_ id: String) async throws { consumerSessions.removeAll { $0.id == id && !$0.isCurrent } }

    // MARK: Directory

    private var directory: [BusinessSummary] { PreviewData.allBusinesses }

    public func searchDirectory(query: String) async throws -> [BusinessSummary] {
        await pause()
        let q = query.lowercased()
        guard q.count >= 2 else { return [] }
        return directory.filter { $0.displayName.lowercased().contains(q) || ($0.handle?.value.contains(q) ?? false) }
    }

    public func businessProfile(handle: BusinessHandle) async throws -> BusinessProfile {
        await pause()
        guard let match = directory.first(where: { $0.handle == handle }) else { throw Self.notFound() }
        return PreviewData.profile(for: match)
    }

    public func businessProfile(code: BusinessCode) async throws -> BusinessProfile {
        await pause()
        guard let match = directory.first(where: { $0.code == code }) else { throw Self.notFound() }
        return PreviewData.profile(for: match)
    }

    public func resolve(input: String) async throws -> DirectoryResolveResponse {
        await pause()
        switch DirectoryInput(parsing: input) {
        case .link(let link):
            guard let match = directory.first(where: { $0.code == link.code }) else { throw Self.notFound() }
            return DirectoryResolveResponse(method: .link, matches: [match])
        case .handle(let handle):
            guard let match = directory.first(where: { $0.handle == handle }) else { throw Self.notFound() }
            return DirectoryResolveResponse(method: .handle, matches: [match])
        case .code(let code):
            guard let match = directory.first(where: { $0.code == code }) else { throw Self.notFound() }
            return DirectoryResolveResponse(method: .code, matches: [match])
        case .name(let name):
            return DirectoryResolveResponse(method: .name, matches: try await searchDirectory(query: name))
        }
    }

    // MARK: Relationships & consent

    public func connect(_ request: ConnectRequest) async throws -> Relationship {
        await pause()
        if let existing = relationshipList.first(where: { $0.business.id == request.businessId && $0.status == .active }) { return existing }
        guard let business = directory.first(where: { $0.id == request.businessId }) else { throw Self.notFound() }
        let relationship = Relationship(id: RelationshipID(), consumerId: consumerId, business: business, status: .active,
                                        source: request.source, connectedAt: clock())
        relationshipList.insert(relationship, at: 0)
        var grants = Self.defaultConsents(for: relationship, consumerId: consumerId, now: clock())
        for index in grants.indices where request.optInPurposes.contains(grants[index].purpose) { grants[index].granted = true }
        consentStore[relationship.id] = grants
        return relationship
    }

    public func relationships() async throws -> [Relationship] { relationshipList.filter { $0.status == .active } }

    public func disconnect(_ id: RelationshipID) async throws {
        guard let index = relationshipList.firstIndex(where: { $0.id == id }) else { throw Self.notFound() }
        relationshipList[index].status = .disconnected
        relationshipList[index].disconnectedAt = clock()
    }

    public func consents(for id: RelationshipID) async throws -> [ConsentGrant] {
        guard let grants = consentStore[id] else { throw Self.notFound() }
        return grants
    }

    public func updateConsents(for id: RelationshipID, _ request: ConsentUpdateRequest) async throws -> [ConsentGrant] {
        guard var grants = consentStore[id] else { throw Self.notFound() }
        for change in request.changes {
            guard change.purpose.isRevocable || change.granted else {
                throw APIError.server(status: 400, code: .validationFailed, message: "Security and account notices can't be turned off")
            }
            if let index = grants.firstIndex(where: { $0.purpose == change.purpose }) {
                grants[index].granted = change.granted
                grants[index].version += 1
                grants[index].policyVersion = request.policyVersion
                grants[index].updatedAt = clock()
            }
        }
        consentStore[id] = grants
        return grants
    }

    // MARK: Interactions

    public func interactions(status: InteractionStatus?, cursor: String?) async throws -> Page<InteractionEnvelope> {
        await pause()
        let items = interactionOrder.compactMap { envelopes[$0] }.filter { status == nil || $0.status == status }
        return Page(items: items)
    }

    public func interaction(_ id: InteractionID) async throws -> InteractionEnvelope {
        guard let envelope = envelopes[id] else { throw Self.notFound() }
        return envelope
    }

    public func redeemHandoff(token: String) async throws -> HandoffRedeemResponse {
        guard let id = interactionOrder.first(where: { envelopes[$0]?.status == .pending }) else { throw Self.notFound() }
        return HandoffRedeemResponse(purpose: .interaction, interactionId: id)
    }

    public func decide(_ id: InteractionID, _ request: DecideInteractionRequest) async throws -> InteractionOutcome {
        await pause()
        guard var envelope = envelopes[id] else { throw Self.notFound() }
        guard envelope.status == .pending else { throw APIError.server(status: 409, code: .conflict, message: "Already decided") }
        let verifier = DecisionVerifier()
        let now = clock()
        do {
            let claimed = try verifier.decodeUnverified(request.signedDecision)
            guard let key = deviceKeys[claimed.deviceId]?[DeviceKeyPurpose.required(for: claimed.assurance)],
                  deviceList.first(where: { $0.id == claimed.deviceId })?.isRevoked == false else {
                throw DecisionVerificationError.deviceMismatch
            }
            let payload = try verifier.verify(request.signedDecision, for: envelope.interaction, deviceId: claimed.deviceId,
                                              publicKey: key, channel: request.channel, now: now)
            guard consumedChallenges.insert("decision:\(id):\(payload.challenge.value)").inserted else { throw DecisionVerificationError.replayed }
            envelope.status = InteractionStatus(decision: payload.decision)
            envelopes[id] = envelope
            decisionLog.append((id, payload.decision, payload.assurance))
            recordAcknowledgment(for: envelope, decision: payload.decision, at: now)
            return InteractionOutcome(interactionId: id, businessId: envelope.business.id, status: envelope.status, decision: payload.decision,
                                      selectedOptionIds: payload.selectedOptionIds, reply: payload.reply, assurance: payload.assurance,
                                      channel: request.channel, decidedAt: now, signedDecision: request.signedDecision)
        } catch let error as DecisionVerificationError {
            switch error {
            case .expired: throw APIError.server(status: 410, code: .expired, message: "This request has expired")
            case .replayed: throw APIError.server(status: 409, code: .conflict, message: "Already decided")
            case .insufficientAssurance: throw APIError.server(status: 403, code: .insufficientAssurance, message: "Stronger verification required")
            case .badSignature, .deviceMismatch: throw APIError.server(status: 401, code: .signatureInvalid, message: "Invalid signature")
            default: throw APIError.server(status: 400, code: .validationFailed, message: "Invalid decision")
            }
        }
    }

    // MARK: Conversations

    public func conversations() async throws -> [ConversationSummary] { conversationList }

    public func startConversation(with business: BusinessID) async throws -> ConversationSummary {
        if let existing = conversationList.first(where: { $0.business.id == business }) { return existing }
        guard let summary = directory.first(where: { $0.id == business }) else { throw Self.notFound() }
        let conversation = ConversationSummary(id: SessionID(), business: summary, state: .open)
        conversationList.insert(conversation, at: 0)
        messageStore[conversation.id] = []
        return conversation
    }

    public func messages(in session: SessionID, cursor: String?) async throws -> Page<ConversationMessage> {
        guard let list = messageStore[session] else { throw Self.notFound() }
        return Page(items: list)
    }

    public func sendMessage(in session: SessionID, _ request: SendMessageRequest) async throws -> ConversationMessage {
        guard let index = conversationList.firstIndex(where: { $0.id == session }) else { throw Self.notFound() }
        let business = conversationList[index].business
        if let existing = messageStore[session]?.first(where: { $0.body == request.body && $0.direction == .consumerToBusiness && $0.id.description == request.clientMessageId }) {
            return existing
        }
        let message = ConversationMessage(
            id: MessageID(), sessionId: session, businessId: business.id, direction: .consumerToBusiness,
            attribution: MessageAttribution(senderType: .consumer, displayName: "You"), body: request.body, channel: .inApp,
            createdAt: clock(), deliveryStatus: .sent)
        messageStore[session, default: []].append(message)
        conversationList[index].lastMessagePreview = request.body
        conversationList[index].lastMessageAt = message.createdAt
        return message
    }

    // MARK: Push

    public func registerAPNsToken(_ registration: APNsTokenRegistration) async throws { registeredAPNsTokens.append(registration) }
    public func registerLiveActivityToken(_ registration: LiveActivityTokenRegistration) async throws { liveActivityTokens.append(registration) }
}
