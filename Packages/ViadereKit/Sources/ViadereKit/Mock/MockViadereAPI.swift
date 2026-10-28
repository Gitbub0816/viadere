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
    private var enrollmentChallenges: [String: PasskeyAssertionOptions] = [:]
    private let replayGuard = InMemoryReplayGuard()
    /// The session was minted by sign-up or sign-in and has not enrolled a device: it may enroll once without a passkey assertion.
    private var freshSession = true
    /// Tests can make the begin response claim `assertionOptional` (or not) whatever the session state is.
    private var assertionOptionalOverride: Bool?
    /// One entry per enrollment: whether it carried a passkey assertion.
    public private(set) var enrollmentLog: [(deviceId: DeviceID, hadAssertion: Bool)] = []
    public private(set) var confirmationLog: [(subject: ConfirmationProof.Subject, id: String)] = []
    private var conversationList: [ConversationSummary] = []
    private var messageStore: [SessionID: [ConversationMessage]] = [:]
    private var phones: [PhoneLink] = []
    private var pendingPhoneCodes: [PhoneLinkID: String] = [:]
    private var consumerSessions: [ConsumerSession]
    private var noticeList: [SecurityNotice] = []
    /// Test hook: when true, dismissing answers `403 device_cool_down` like a device that is not trusted yet.
    public var dismissNeedsTrustedDevice = false
    public private(set) var dismissedNoticeIds: [UUID] = []
    /// Test hook: refuse an enrollment that carries no App Attest evidence (`403 attestation_required`), like `APP_ATTEST_MODE=require`.
    public var requiresAttestation = false
    /// Every enrollment request the server received.
    public private(set) var enrollRequests: [DeviceEnrollRequest] = []
    /// Test hook: a live device being replaced is revoked at once instead of waiting for the owner (`false` = the server's real rule).
    public var replacesLiveDevicesImmediately = false
    /// Recovery state (§2.26).
    private var recoverySet: RecoveryCodeSet?
    private var recoveryRecord: MockRecoveryRecord?
    /// Further holding recoveries of the account (the real server allows one; this models an older server or a racing client).
    private var extraRecoveries: [MockRecoveryRecord] = []
    private var recoveryCodesChallenges: [CeremonyID: String] = [:]
    /// Sessions the server minted for replacement devices (`Device.replacementSession`).
    public private(set) var replacementSessions: [AuthSession] = []
    public private(set) var cancelledReplacementIds: [DeviceID] = []
    public private(set) var cancelledRecoveryIds: [RecoveryID] = []
    public private(set) var recoveryCompleteCalls = 0
    private var consumedChallenges: Set<String> = []
    public private(set) var registeredAPNsTokens: [APNsTokenRegistration] = []
    public private(set) var liveActivityTokens: [LiveActivityTokenRegistration] = []
    /// Every `decide` call that reached the server, accepted or not.
    public private(set) var decideAttempts = 0
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
    public func finishRegistration(_ request: PasskeyRegistrationFinishRequest) async throws -> AuthSession {
        freshSession = true
        var session = grant()
        // Recovery codes arrive exactly once, with the session that created the account.
        session.recoveryCodes = issueRecoveryCodes()
        return session
    }
    public func beginLogin() async throws -> PasskeyAssertionOptions {
        await pause()
        return PasskeyAssertionOptions(ceremonyId: CeremonyID(), challenge: SecureToken.generate(), relyingPartyId: ViadereCore.domain)
    }
    public func finishLogin(_ request: PasskeyLoginFinishRequest) async throws -> AuthSession {
        freshSession = true
        return grant()
    }
    /// Test hook: makes logout and device revocation fail, like a 401/403 from the server.
    public var signOutCallsFail: APIError?
    public private(set) var logoutCalls = 0
    public func logout() async throws {
        logoutCalls += 1
        if let failure = signOutCallsFail { throw failure }
    }
    public func deleteAccount() async throws { accountDeleted = true }

    private func grant() -> AuthSession {
        AuthSession(consumerId: consumerId, accessToken: SecureToken.generate(), expiresAt: clock().addingTimeInterval(900),
                    refreshToken: SecureToken.generate(), refreshExpiresAt: clock().addingTimeInterval(86_400 * 30))
    }

    // MARK: Devices

    /// The server rule: after `lockHours` a new device with approval keys may approve high-risk requests (when another trusted device exists).
    static let newDeviceCoolDown: TimeInterval = 24 * 3_600
    static let appClipLifetime: TimeInterval = 7 * 24 * 3_600

    /// Makes the next `beginDeviceEnrollment` claim `assertionOptional` (or not) regardless of the session; `nil` restores the real rule.
    public func setAssertionOptional(_ value: Bool?) { assertionOptionalOverride = value }

    public func beginDeviceEnrollment() async throws -> DeviceEnrollmentChallenge {
        let challenge = SecureToken.generate()
        let options = PasskeyAssertionOptions(ceremonyId: CeremonyID(), challenge: challenge, relyingPartyId: ViadereCore.domain,
                                              timeoutMilliseconds: 300_000)
        enrollmentChallenges[challenge] = options
        return DeviceEnrollmentChallenge(challenge: challenge, expiresAt: clock().addingTimeInterval(300), assertion: options,
                                         assertionOptional: assertionOptionalOverride ?? freshSession)
    }

    /// Verifies like the server: one key per purpose with proof of possession, an App Clip registers a request key only, and a
    /// user-verified passkey assertion over this very challenge is required unless the session is a fresh sign-in (once).
    public func enrollDevice(_ request: DeviceEnrollRequest) async throws -> Device {
        let purposes = request.keys.map(\.purpose)
        guard purposes.contains(.request), Set(purposes).count == purposes.count else {
            throw APIError.server(status: 422, code: .validationFailed, message: "Provide exactly one key per purpose, including a request key.")
        }
        let kind = request.effectiveClientKind
        if kind == .appClip, purposes != [.request] {
            throw APIError.server(status: 422, code: .validationFailed, message: "An App Clip device can only register a request key.")
        }
        enrollRequests.append(request)
        if let evidence = request.appAttest {
            // The mock "attestation" is `mock-attestation:` + clientDataHash: it must vouch for exactly these keys, this challenge and account.
            let prefix = Data("mock-attestation:".utf8)
            if let raw = Base64URL.decode(evidence.attestation), raw.starts(with: prefix),
               Data(raw.dropFirst(prefix.count)) != AppAttestBinding.clientDataHash(consumerId: consumerId, challenge: request.challenge, keys: request.keys) {
                throw APIError.server(status: 403, code: .attestationRequired, message: "The attestation does not match this enrollment.")
            }
        } else if requiresAttestation {
            throw APIError.server(status: 403, code: .attestationRequired, message: "This device could not be verified.")
        }
        guard let options = enrollmentChallenges[request.challenge] else {
            throw APIError.server(status: 401, code: .unauthorized, message: "The enrollment challenge is invalid or expired.")
        }
        for registration in request.keys where !DeviceEnrollment.verify(registration, consumerId: consumerId, challenge: request.challenge) {
            throw APIError.server(status: 401, code: .signatureInvalid, message: "Key proof of possession failed.")
        }
        let required = APIError.server(status: 401, code: .passkeyAssertionRequired, message: "Confirm with your passkey to add this device.")
        if let assertion = request.assertion {
            guard Self.assertionIsUserVerified(assertion, challenge: options.challenge) else { throw required }
        } else if !freshSession {
            throw required
        }
        enrollmentChallenges[request.challenge] = nil
        let now = clock()
        // A device that can approve and joins an account that already has a trusted app device starts in its cool-down.
        let others = deviceList.filter { $0.revokedAt == nil && $0.clientKind == .app && !$0.isExpired(at: now) }
        let coolDown = kind == .app && purposes.contains { $0 != .request } && !others.isEmpty
        let deviceId = DeviceID()
        let keys = request.keys.map {
            DeviceKey(id: DeviceKeyID(), purpose: $0.purpose, publicKey: $0.publicKey, hardwareBacked: $0.hardwareBacked, createdAt: now)
        }
        var device = Device(id: deviceId, consumerId: consumerId, name: request.name, platform: request.platform, keys: keys,
                            createdAt: now, lastSeenAt: now, clientKind: kind,
                            approvalsLockedUntil: coolDown ? now.addingTimeInterval(Self.newDeviceCoolDown) : nil,
                            expiresAt: kind == .appClip ? now.addingTimeInterval(Self.appClipLifetime) : nil)
        // "Set up again". A device that is already revoked is replaced at once. A LIVE one keeps working: it is marked as pending
        // replacement, and the response carries a session bound to the new device (the caller's own session stays with the old one).
        if let replaced = request.replacesDeviceId, let index = deviceList.firstIndex(where: { $0.id == replaced }) {
            if deviceList[index].revokedAt != nil || replacesLiveDevicesImmediately {
                if deviceList[index].revokedAt == nil { deviceList[index].revokedAt = now }
            } else {
                deviceList[index].pendingReplacementBy = deviceId
                deviceList[index].pendingReplacementAt = now.addingTimeInterval(Self.newDeviceCoolDown)
                let session = grant()
                replacementSessions.append(session)
                device.replacementSession = session
                addNotice(rawKind: "devicePendingReplacement", message: "A new iPhone is replacing one of your devices.",
                          subjectId: deviceId.description, action: .cancelDeviceReplacement)
            }
        }
        deviceList.append(device)
        enrollmentLog.append((deviceId, request.assertion != nil))
        freshSession = false
        deviceKeys[deviceId] = Dictionary(uniqueKeysWithValues: keys.map { ($0.purpose, $0.publicKey) })
        return device
    }

    /// A WebAuthn-shaped check: the client data carries this challenge and the authenticator data has the user-present and
    /// user-verified flags (what `MockPasskeyService` produces; the real server also checks the signature, RP id and sign count).
    static func assertionIsUserVerified(_ assertion: PasskeyAssertionCredential, challenge: String) -> Bool {
        guard let clientData = Base64URL.decode(assertion.clientDataJSON),
              let object = try? JSONSerialization.jsonObject(with: clientData) as? [String: Any],
              object["type"] as? String == "webauthn.get", object["challenge"] as? String == challenge,
              let authData = Base64URL.decode(assertion.authenticatorData), authData.count >= 37 else { return false }
        let flags = authData[authData.startIndex + 32]
        return flags & 0x01 != 0 && flags & 0x04 != 0
    }

    /// Test hook: `GET /v1/devices` fails (offline), so a client-side pre-check can't run and the server's own answer is what counts.
    public func setDeviceListUnavailable(_ value: Bool) { deviceListUnavailable = value }
    private var deviceListUnavailable = false

    public func devices() async throws -> [Device] {
        if deviceListUnavailable { throw APIError.transport("offline") }
        return deviceList
    }

    public func revokeDevice(_ id: DeviceID) async throws {
        if let failure = signOutCallsFail { throw failure }
        guard let index = deviceList.firstIndex(where: { $0.id == id }) else { throw Self.notFound() }
        deviceList[index].revokedAt = clock()
    }

    private func addNotice(rawKind: String, message: String, subjectId: String?, action: SecurityNoticeAction?) {
        noticeList.append(SecurityNotice(id: UUID(), rawKind: rawKind, message: message, createdAt: clock(), subjectId: subjectId, action: action))
    }

    public func cancelVaultRecoveryRelease(_ id: UUID) async throws {
        if dismissNeedsTrustedDevice { throw APIError.server(status: 403, code: .deviceCoolDown, message: "") }
        guard noticeList.contains(where: { $0.action == .cancelVaultRecovery && $0.subjectId == id.uuidString.lowercased() }) else { throw Self.notFound() }
        noticeList.removeAll { $0.action == .cancelVaultRecovery && $0.subjectId == id.uuidString.lowercased() }
    }

    /// "Not you? Cancel": revokes the NEW device and clears the pending mark on the old one.
    public func cancelDeviceReplacement(_ id: DeviceID) async throws {
        if dismissNeedsTrustedDevice { throw APIError.server(status: 403, code: .deviceCoolDown, message: "") }
        guard let index = deviceList.firstIndex(where: { $0.id == id && $0.revokedAt == nil }),
              deviceList.contains(where: { $0.pendingReplacementBy == id }) else { throw Self.notFound() }
        deviceList[index].revokedAt = clock()
        for old in deviceList.indices where deviceList[old].pendingReplacementBy == id {
            deviceList[old].pendingReplacementBy = nil
            deviceList[old].pendingReplacementAt = nil
        }
        noticeList.removeAll { $0.action == .cancelDeviceReplacement && $0.subjectId == id.description }
        cancelledReplacementIds.append(id)
    }

    /// Test hook: puts a device into (or out of) its new-device cool-down.
    public func setApprovalsLockedUntil(_ date: Date?, for id: DeviceID) {
        guard let index = deviceList.firstIndex(where: { $0.id == id }) else { return }
        deviceList[index].approvalsLockedUntil = date
    }

    /// Same rules as the server: the confirming device is another, trusted (not cooling down) app device of this account, and the
    /// proof is a fresh, single-use signature by its user-verified approval key for exactly this device.
    public func confirmDevice(_ id: DeviceID, proof: ConfirmationProof) async throws -> Device {
        let confirmer = try trustedConfirmer(for: proof, target: id)
        guard let index = deviceList.firstIndex(where: { $0.id == id && $0.revokedAt == nil }) else { throw APIError.server(status: 403, code: .forbidden, message: "") }
        if deviceList[index].approvalsLockedUntil != nil {
            try await verify(proof, subject: .device, subjectId: id.description, confirmer: confirmer)
            deviceList[index].approvalsLockedUntil = nil
            confirmationLog.append((.device, id.description))
        }
        return deviceList[index]
    }

    private func trustedConfirmer(for proof: ConfirmationProof, target: String?) throws -> Device {
        let forbidden = APIError.server(status: 403, code: .forbidden, message: "")
        guard let confirmer = deviceList.first(where: { $0.id == proof.deviceId }), confirmer.revokedAt == nil, confirmer.clientKind == .app,
              !confirmer.isExpired(at: clock()), !confirmer.isCoolingDown(at: clock()) else { throw forbidden }
        return confirmer
    }

    private func trustedConfirmer(for proof: ConfirmationProof, target: DeviceID) throws -> Device {
        guard proof.deviceId != target else { throw APIError.server(status: 403, code: .forbidden, message: "") }
        return try trustedConfirmer(for: proof, target: target.description)
    }

    private func verify(_ proof: ConfirmationProof, subject: ConfirmationProof.Subject, subjectId: String, confirmer: Device) async throws {
        guard let purpose = proof.requiredKeyPurpose, let key = deviceKeys[confirmer.id]?[purpose] else {
            throw APIError.server(status: 403, code: .insufficientAssurance, message: "Confirm with Face ID or your passcode.")
        }
        do {
            try await proof.verify(subject: subject, subjectId: subjectId, publicKey: key, now: clock(), replayGuard: replayGuard)
        } catch ConfirmationProof.Failure.replayed {
            throw APIError.server(status: 401, code: .replayDetected, message: "This confirmation was already used.")
        } catch ConfirmationProof.Failure.assuranceTooLow {
            throw APIError.server(status: 403, code: .insufficientAssurance, message: "Confirm with Face ID or your passcode.")
        } catch {
            throw APIError.server(status: 401, code: .signatureInvalid, message: "Invalid signature")
        }
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

    /// What the mock's link preview reports (tests change it).
    public private(set) var linkPreviewPhone = "+1 ••• ••• 0123"
    public private(set) var previewedLinkTokens: [String] = []
    public private(set) var redeemRequests: [SMSLinkRedeemRequest] = []
    public func setLinkPreview(_ masked: String) { linkPreviewPhone = masked }

    public func previewPhoneLink(token: String) async throws -> SMSLinkPreview {
        guard token.count >= 8 else { throw APIError.server(status: 404, code: .notFound, message: "This link isn't valid anymore.") }
        previewedLinkTokens.append(token)
        return SMSLinkPreview(maskedPhone: linkPreviewPhone, expiresAt: clock().addingTimeInterval(600))
    }

    /// Like the server: the confirmation must match the number the token is bound to, and a number linked from a token is not
    /// usable for 24 hours unless a trusted device confirms it.
    public func redeemSMSLink(_ request: SMSLinkRedeemRequest) async throws -> PhoneLink {
        let digits = linkPreviewPhone.filter { $0.isASCII && $0.isNumber }
        guard request.confirmPhoneLast4 == String(digits.suffix(4)),
              request.confirmMaskedPhone.map({ $0 == linkPreviewPhone }) ?? true else {
            throw APIError.server(status: 403, code: .forbidden, message: "That doesn't match the number this link is for.")
        }
        redeemRequests.append(request)
        let now = clock()
        let link = PhoneLink(id: PhoneLinkID(), maskedPhone: linkPreviewPhone, verifiedAt: now, usableFrom: now.addingTimeInterval(Self.newDeviceCoolDown))
        phones.append(link)
        return link
    }

    public func confirmPhoneLink(_ id: PhoneLinkID, proof: ConfirmationProof) async throws -> PhoneLink {
        let confirmer = try trustedConfirmer(for: proof, target: nil)
        guard let index = phones.firstIndex(where: { $0.id == id }) else { throw Self.notFound() }
        if phones[index].usableFrom != nil {
            try await verify(proof, subject: .phoneLink, subjectId: id.description, confirmer: confirmer)
            phones[index].usableFrom = nil
            confirmationLog.append((.phoneLink, id.description))
        }
        return phones[index]
    }

    public func phoneLinks() async throws -> [PhoneLink] { phones }
    public func removePhoneLink(_ id: PhoneLinkID) async throws { phones.removeAll { $0.id == id } }
    public func sessions() async throws -> [ConsumerSession] { consumerSessions }
    public func revokeSession(_ id: String) async throws { consumerSessions.removeAll { $0.id == id && !$0.isCurrent } }

    public func securityNotices() async throws -> [SecurityNotice] { noticeList.sorted { $0.createdAt > $1.createdAt } }
    public func dismissSecurityNotice(_ id: UUID) async throws {
        if dismissNeedsTrustedDevice {
            throw APIError.server(status: 403, code: .deviceCoolDown, message: "")
        }
        guard noticeList.contains(where: { $0.id == id }) else { throw Self.notFound() }
        noticeList.removeAll { $0.id == id }
        dismissedNoticeIds.append(id)
    }
    /// Test hook: puts notices on the account.
    public func setDismissNeedsTrustedDevice(_ value: Bool) { dismissNeedsTrustedDevice = value }
    public func setRequiresAttestation(_ value: Bool) { requiresAttestation = value }
    public func setSignOutCallsFail(_ failure: APIError?) { signOutCallsFail = failure }
    public func setSecurityNotices(_ notices: [SecurityNotice]) { noticeList = notices }

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
        decideAttempts += 1
        guard var envelope = envelopes[id] else { throw Self.notFound() }
        guard envelope.status == .pending else { throw APIError.server(status: 409, code: .conflict, message: "Already decided") }
        let verifier = DecisionVerifier()
        let now = clock()
        do {
            let claimed = try verifier.decodeUnverified(request.signedDecision)
            guard let key = deviceKeys[claimed.deviceId]?[DeviceKeyPurpose.required(for: claimed.assurance)],
                  let device = deviceList.first(where: { $0.id == claimed.deviceId }), !device.isRevoked else {
                throw DecisionVerificationError.deviceMismatch
            }
            // App Clip devices can request but never decide. A device in its new-device cool-down cannot approve high or critical
            // requests (deny, report and decline stay available).
            guard device.clientKind == .app else { throw APIError.server(status: 403, code: .forbidden, message: "This device can't respond to requests.") }
            if device.isCoolingDown(at: now), CoolDownPolicy.restricts(claimed.decision, on: envelope.interaction) {
                throw APIError.server(status: 403, code: .deviceCoolDown, message: "This device was added recently. Confirm it from another device you trust before approving this request.")
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
            case .contextDigestRequired: throw APIError.server(status: 400, code: .contextDigestRequired, message: "The decision must be signed over what was shown.")
            case .contextMismatch: throw APIError.server(status: 409, code: .contextMismatch, message: "This request changed. Review it again.")
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

// MARK: - Account recovery (§2.26)

struct MockRecoveryRecord {
    var id: RecoveryID
    var state: RecoveryState
    var startedAt: Date
    var activatesAt: Date?
    var statusToken: String?
    var ceremonyId: CeremonyID
    var codesDelivered = false
}

extension MockViadereAPI {
    /// A fresh recovery ID and ten codes; the previous set dies.
    func issueRecoveryCodes() -> RecoveryCodeSet {
        let set = RecoveryCodeSet(recoveryId: RecoveryCodeFormat.generateRecoveryID(),
                                  codes: (0..<RecoveryPolicy.codeCount).map { _ in RecoveryCodeFormat.generateCode() }, issuedAt: clock())
        recoverySet = set
        return set
    }

    /// Test hook: what the server holds as the account's active codes (a real server holds only HMACs).
    public var activeRecoveryCodes: RecoveryCodeSet? { recoverySet }

    public func beginRecovery(_ request: RecoveryBeginRequest) async throws -> PasskeyRegistrationOptions {
        await pause()
        let denied = APIError.server(status: 401, code: .unauthorized, message: "")
        guard var set = recoverySet, let id = RecoveryCodeFormat.normalizeRecoveryID(request.recoveryId),
              id == RecoveryCodeFormat.normalizeRecoveryID(set.recoveryId),
              let code = RecoveryCodeFormat.normalizeCode(request.code),
              let index = set.codes.firstIndex(where: { RecoveryCodeFormat.normalizeCode($0) == code }) else { throw denied }
        if let record = recoveryRecord, record.state == .awaitingPasskey || record.state == .holding { throw denied }
        set.codes.remove(at: index)   // the code is spent
        recoverySet = set
        let ceremony = CeremonyID()
        recoveryRecord = MockRecoveryRecord(id: RecoveryID(), state: .awaitingPasskey, startedAt: clock(), ceremonyId: ceremony)
        return PasskeyRegistrationOptions(ceremonyId: ceremony, challenge: SecureToken.generate(), relyingPartyId: ViadereCore.domain,
                                          relyingPartyName: "Viadere", userId: SecureToken.generate(byteCount: 16),
                                          userName: "Viadere", userDisplayName: "Viadere")
    }

    public func finishRecovery(_ request: RecoveryFinishRequest) async throws -> RecoveryStatus {
        guard var record = recoveryRecord, record.state == .awaitingPasskey, record.ceremonyId == request.ceremonyId else {
            throw APIError.server(status: 401, code: .unauthorized, message: "")
        }
        record.state = .holding
        record.startedAt = clock()
        record.activatesAt = clock().addingTimeInterval(RecoveryPolicy.holdSeconds)
        record.statusToken = SecureToken.generate()
        recoveryRecord = record
        // Every existing device hears about it.
        addNotice(rawKind: "recoveryStarted", message: "Account recovery was started.", subjectId: record.id.description, action: .cancelRecovery)
        return RecoveryStatus(id: record.id, state: .holding, startedAt: record.startedAt, activatesAt: record.activatesAt, statusToken: record.statusToken)
    }

    public func completeRecovery(_ request: RecoveryCompleteRequest) async throws -> RecoveryStatus {
        recoveryCompleteCalls += 1
        guard var record = recoveryRecord, record.id == request.recoveryId, record.statusToken == request.statusToken else {
            throw APIError.server(status: 401, code: .unauthorized, message: "")
        }
        if record.state == .holding, let at = record.activatesAt, at <= clock() {
            record.state = .activated
            let now = clock()
            for index in deviceList.indices where deviceList[index].revokedAt == nil { deviceList[index].revokedAt = now }
            freshSession = true
        }
        var status = RecoveryStatus(id: record.id, state: record.state, startedAt: record.startedAt, activatesAt: record.activatesAt)
        if record.state == .activated, !record.codesDelivered {
            record.codesDelivered = true
            status.recoveryCodes = issueRecoveryCodes()
        }
        recoveryRecord = record
        return status
    }

    public func cancelRecovery(_ id: RecoveryID) async throws -> RecoveryStatus {
        if dismissNeedsTrustedDevice { throw APIError.server(status: 403, code: .deviceCoolDown, message: "") }
        if let index = extraRecoveries.firstIndex(where: { $0.id == id }) {
            extraRecoveries[index].state = .cancelled
            cancelledRecoveryIds.append(id)
            return RecoveryStatus(id: id, state: .cancelled, startedAt: extraRecoveries[index].startedAt, activatesAt: extraRecoveries[index].activatesAt)
        }
        guard var record = recoveryRecord, record.id == id else { throw APIError.server(status: 404, code: .notFound, message: "") }
        if record.state == .holding || record.state == .awaitingPasskey { record.state = .cancelled }
        recoveryRecord = record
        // Whoever started it held a code: the rest are invalidated.
        if var set = recoverySet { set.codes = []; recoverySet = set }
        noticeList.removeAll { $0.action == .cancelRecovery }
        cancelledRecoveryIds.append(id)
        return RecoveryStatus(id: record.id, state: record.state, startedAt: record.startedAt, activatesAt: record.activatesAt)
    }

    public func recoveryInfo() async throws -> RecoveryInfo {
        let pending = ([recoveryRecord].compactMap { $0 } + extraRecoveries).compactMap { record -> PendingRecovery? in
            guard record.state == .holding, let at = record.activatesAt else { return nil }
            return PendingRecovery(id: record.id, startedAt: record.startedAt, activatesAt: at)
        }
        return RecoveryInfo(remainingCodes: recoverySet?.codes.count ?? 0, issuedAt: recoverySet?.issuedAt, pending: pending.first, pendingRecoveries: pending)
    }

    public func beginRecoveryCodes() async throws -> PasskeyAssertionOptions {
        if dismissNeedsTrustedDevice { throw APIError.server(status: 403, code: .deviceCoolDown, message: "") }
        let options = PasskeyAssertionOptions(ceremonyId: CeremonyID(), challenge: SecureToken.generate(), relyingPartyId: ViadereCore.domain)
        recoveryCodesChallenges[options.ceremonyId] = options.challenge
        return options
    }

    public func regenerateRecoveryCodes(_ request: RecoveryCodesRegenerateRequest) async throws -> RecoveryCodeSet {
        if dismissNeedsTrustedDevice { throw APIError.server(status: 403, code: .deviceCoolDown, message: "") }
        guard let challenge = recoveryCodesChallenges.removeValue(forKey: request.ceremonyId), Self.assertionIsUserVerified(request.assertion, challenge: challenge) else {
            throw APIError.server(status: 401, code: .passkeyAssertionRequired, message: "")
        }
        // New codes close every recovery still waiting (the old codes started them).
        if var record = recoveryRecord, record.state == .holding || record.state == .awaitingPasskey { record.state = .cancelled; recoveryRecord = record }
        for index in extraRecoveries.indices where extraRecoveries[index].state == .holding { extraRecoveries[index].state = .cancelled }
        noticeList.removeAll { $0.action == .cancelRecovery }
        return issueRecoveryCodes()
    }

    /// Test hook: another recovery is holding for this account; returns its id.
    @discardableResult
    public func addHoldingRecovery() -> RecoveryID {
        let record = MockRecoveryRecord(id: RecoveryID(), state: .holding, startedAt: clock(), activatesAt: clock().addingTimeInterval(RecoveryPolicy.holdSeconds),
                                        statusToken: SecureToken.generate(), ceremonyId: CeremonyID())
        extraRecoveries.append(record)
        return record.id
    }

    /// Test hook: the 72 h hold passes (the next `complete` activates the recovery).
    public func elapseRecoveryHold() {
        guard var record = recoveryRecord else { return }
        record.activatesAt = clock().addingTimeInterval(-1)
        recoveryRecord = record
    }

    /// Test hook: puts a recovery code set on the account (e.g. an account that predates recovery codes has none).
    public func setRecoveryCodes(_ set: RecoveryCodeSet?) { recoverySet = set }
}
