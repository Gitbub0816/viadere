import Crypto
import Foundation
import Testing
import ViadereCore
@testable import ViadereKit

#if DEBUG

/// A relay and a business in one actor: an in-memory transparency log, the business's keys, and the relay's records. Every "attack" is a
/// switch on this type, so the tests show what the device does when the relay misbehaves.
actor FakeRelay: ApproveAPI {
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    let businessId: BusinessID
    let relationshipId = RelationshipID()
    let subject = SubjectRef("sub_" + Base64URL.encode(Data(repeating: 7, count: 32)))!
    let logKey: SoftwareP256SigningKey
    var root = SoftwareP256SigningKey()
    var confirmationKey = SoftwareP256SigningKey()
    var requestKey = SoftwareP256SigningKey()
    let summary: BusinessSummary
    var tree = MerkleTree()
    var entries: [(entry: KeyLogEntry, bytes: Data)] = []
    var serial: Int64 = 0

    var enrollmentId = UUID()
    var deviceStatement: SignedStatement?
    var confirmation: BusinessSignedStatement?
    var keyRevoked = false
    var requests: [ApproveDeviceRequest] = []
    var submitted: [(UUID, String)] = []
    /// Attack switches.
    var substituteKey: SoftwareP256SigningKey?
    var serveHeadSize: Int?
    /// What the phone sent with its statement (the relay sees this).
    var receivedBindingTag: String?
    /// Holds the next directory response until `release()`: lets a test interleave two refreshes.
    var stallNextDirectory = false
    private var stalled: CheckedContinuation<Void, Never>?
    private var isStalled = false

    init(businessId: BusinessID = BusinessID(), logKey: SoftwareP256SigningKey = SoftwareP256SigningKey()) async throws {
        self.businessId = businessId
        self.logKey = logKey
        summary = BusinessSummary(id: businessId, displayName: "Harbor Bank", handle: nil, code: try BusinessCode("SK1234"), verificationStatus: .verified)
        try await register(root: root)
    }

    var logPublicKey: DevicePublicKey { logKey.publicKey }
    var rootKid: String { KeyIdentifier.make(try! root.publicKey.signingKey()) }

    private func append(_ entry: KeyLogEntry) throws {
        let bytes = try entry.leafData()
        entries.append((entry, bytes))
        tree.append(leafData: bytes)
    }

    func register(root: SoftwareP256SigningKey) async throws {
        self.root = root
        try append(try await KeyLogEntry.sign(.root(RootRegistration(businessId: businessId, publicKey: root.publicKey, createdAt: now)), rootKey: root))
        serial = 0
    }

    @discardableResult
    func publish(_ purpose: BusinessKeyPurpose, _ key: Data) async throws -> String {
        serial += 1
        let statement = try KeyPublication(businessId: businessId, rootKid: rootKid, purpose: purpose, publicKey: key, notBefore: now.addingTimeInterval(-60),
                                           notAfter: now.addingTimeInterval(86_400 * 30), serial: serial)
        try append(try await KeyLogEntry.sign(.key(statement), rootKey: root))
        return statement.kid
    }

    func publishOperationalKeys() async throws {
        try await publish(.approvalEnrollmentConfirmation, confirmationKey.publicKey.x963)
        try await publish(.approvalRequestSigning, requestKey.publicKey.x963)
    }

    /// Replaces the business root through a proper two-signature succession.
    func rotateRoot() async throws {
        let next = SoftwareP256SigningKey()
        let succession = RootSuccession(businessId: businessId, oldRootKid: rootKid, newPublicKey: next.publicKey, createdAt: now)
        try append(try await KeyLogEntry.sign(.succession(succession), rootKey: root, newRootKey: next))
        root = next
        // Keys of the old root are not inherited, and a published key can never be published again: the new root brings its own.
        confirmationKey = SoftwareP256SigningKey()
        requestKey = SoftwareP256SigningKey()
        try await publishOperationalKeys()
    }

    /// The business confirms the key it sees: honest, or the attacker's.
    func businessConfirms() async throws {
        guard let signed = deviceStatement else { return }
        let statement = try ApprovalEnrollmentStatement.verify(signed)
        confirmation = try await ApprovalEnrollmentConfirmation(confirming: statement, signed: signed, at: now).sign(with: confirmationKey)
    }

    // MARK: ApproveAPI

    func lookupEnrollment(code: String) async throws -> ApproveEnrollmentPreview {
        ApproveEnrollmentPreview(enrollmentId: enrollmentId, business: summary, relationshipId: relationshipId, subjectRef: subject, capability: .transactionApprove,
                                 requiredAssurance: .biometric, expiresAt: now.addingTimeInterval(600))
    }

    func completeEnrollment(id: UUID, statement: SignedStatement, bindingTag: String?) async throws -> ApproveKey {
        receivedBindingTag = bindingTag
        let honest = try ApprovalEnrollmentStatement.verify(statement)
        if let attacker = substituteKey {
            // The relay swaps in its own key (and reports the device's key id back so the device does not notice at once).
            let forged = try ApprovalEnrollmentStatement(businessId: businessId, subject: subject, enrollmentId: id, publicKey: attacker.publicKey, hpkePublicKey: honest.hpkePublicKey,
                                                     assurance: .biometric, createdAt: now)
            deviceStatement = try await forged.sign(with: attacker)
        } else {
            deviceStatement = statement
        }
        return key(kid: honest.kid, statement: statement)
    }

    private func key(kid: String, statement: SignedStatement) -> ApproveKey {
        ApproveKey(kid: kid, enrollmentId: enrollmentId, business: summary, relationshipId: relationshipId, subjectRef: subject, deviceId: DeviceID(),
                   status: keyRevoked ? .revoked : (confirmation == nil ? .pending : .active), assurance: .biometric, createdAt: now, activatedAt: nil, revokedAt: nil,
                   revokedBy: nil, statement: deviceStatement ?? statement, confirmation: confirmation)
    }

    func keys() async throws -> [ApproveKey] {
        guard let statement = deviceStatement, let honest = try? ApprovalEnrollmentStatement.verify(statement) else { return [] }
        return [key(kid: honest.kid, statement: statement)]
    }

    func revokeKey(kid: String) async throws -> ApproveKey {
        keyRevoked = true
        return key(kid: kid, statement: deviceStatement!)
    }

    func requests() async throws -> [ApproveDeviceRequest] { requests }
    func request(id: UUID) async throws -> ApproveDeviceRequest { requests.first { $0.id == id }! }
    func submitResult(id: UUID, result: String) async throws -> SubmitApprovalResultResponse {
        submitted.append((id, result))
        return SubmitApprovalResultResponse(id: id, status: .approved)
    }
    func freezeState() async throws -> ApproveFreezeState { ApproveFreezeState(entries: []) }
    func setFreeze(_ request: ApproveFreezeRequest) async throws -> ApproveFreezeState { ApproveFreezeState(entries: []) }

    func keyDirectory(businessId: BusinessID, since: Int?) async throws -> KeyDirectoryResponse {
        let size = serveHeadSize ?? tree.size
        let head = try await SignedTreeHead.sign(TreeHead(treeSize: size, rootHash: tree.root(size: size), timestamp: now), with: logKey)
        var from: Int?
        var proof: [String]?
        if let since, since > 0, since < size {
            from = since
            proof = tree.consistencyProof(first: since, second: size)!.map(Hex.encode)
        }
        let items = entries.prefix(size).enumerated().filter { $0.element.entry.businessId == businessId }.map { index, item in
            KeyLogEntryProof(index: index, entry: Base64URL.encode(item.bytes), inclusionProof: tree.inclusionProof(index: index, size: size)!.map(Hex.encode))
        }
        let response = KeyDirectoryResponse(sth: head, consistencyFrom: from, consistencyProof: proof, entries: items)
        if stallNextDirectory {
            stallNextDirectory = false
            isStalled = true
            await withCheckedContinuation { stalled = $0 }
        }
        return response
    }

    var hasStalledCall: Bool { isStalled && stalled != nil }
    func release() { isStalled = false; stalled?.resume(); stalled = nil }

    // MARK: Requests

    static let details = ApprovalSubject.transaction(TransactionDetails(currency: "USD", amountMinor: 250_000, payeeDisplay: "Example Merchant", transactionReference: "bank_tx_123"))

    /// Queues an end-to-end request for the enrolled key, as the business would send it.
    @discardableResult
    func deliverEndToEnd(to enrolled: LocalApprovalKey, signedBy signer: SoftwareP256SigningKey? = nil, requestId: String = "req_0123456789abcdef",
                         details: ApprovalSubject = FakeRelay.details, toKid: String? = nil, count: Int = 1) async throws -> ApproveDeviceRequest {
        let challenge = ChallengeNonce.generate().value
        let content = ApprovalRequestContent(businessId: businessId, subject: subject, requestId: requestId, challenge: challenge, details: details, toKid: toKid ?? enrolled.kid,
                                             issuedAt: now, expiresAt: now.addingTimeInterval(300))
        let plaintext = try await content.sealedPlaintext(signedWith: signer ?? requestKey)
        let hpke = try ApprovalEnrollmentStatement.verify(enrolled.statement).hpkePublicKey
        let envelope = try E2EE.seal(plaintext, to: hpke, context: E2EEContext(purpose: "approve.request", requestId: requestId, sender: "biz_" + businessId.description,
                                                                                 recipient: "ak_" + enrolled.kid, expiresAt: now.addingTimeInterval(300)))
        let request = ApproveDeviceRequest(id: UUID(), requestId: requestId, business: summary, subjectRef: subject, capability: .transactionApprove, kid: enrolled.kid,
                                           protection: .endToEnd, status: .pending, createdAt: now, expiresAt: now.addingTimeInterval(300), envelope: envelope,
                                           requestsInWindow: count, showFatigueWarning: count >= 3)
        requests.append(request)
        return request
    }

    func deliverServerVisible(to enrolled: LocalApprovalKey, amountMinor: Int64 = 100) -> ApproveDeviceRequest {
        let transaction = TransactionDetails(currency: "USD", amountMinor: amountMinor, payeeDisplay: "Example Merchant", transactionReference: "ref_1")
        let request = ApproveDeviceRequest(id: UUID(), requestId: "req_server_visible_1", business: summary, subjectRef: subject, capability: .transactionApprove, kid: enrolled.kid,
                                           protection: .serverVisible, status: .pending, createdAt: now, expiresAt: now.addingTimeInterval(300),
                                           challenge: ChallengeNonce.generate().value, transaction: transaction)
        requests.append(request)
        return request
    }
}

let testSecret = ApprovalEnrollmentSecret()

/// A fresh Face ID / Touch ID proof that succeeds, or fails like a cancelled prompt.
struct AllowAuthorizer: RootChangeAuthorizer { func authorize(reason: String) async throws {} }
struct DenyAuthorizer: RootChangeAuthorizer { func authorize(reason: String) async throws { throw KeyStoreError.userCancelled } }

struct ApprovePhone {
    let relay: FakeRelay
    let vault: SoftwareApprovalKeyVault
    let store: SecretApproveLocalStore
    let directory: BusinessDirectoryClient
    let enrollment: ApproveEnrollmentFlow
    let handler: ApproveRequestHandler
    let now: Date

    init(relay: FakeRelay, logKey: DevicePublicKey?, store: SecretApproveLocalStore = SecretApproveLocalStore(secrets: InMemorySecretStore()),
         vault: SoftwareApprovalKeyVault = SoftwareApprovalKeyVault(), now: Date) {
        self.relay = relay
        self.vault = vault
        self.store = store
        self.now = now
        directory = BusinessDirectoryClient(api: relay, store: store, logKeys: logKey.map { [$0] } ?? [], clock: { now })
        enrollment = ApproveEnrollmentFlow(api: relay, vault: vault, store: store, directory: directory, clock: { now })
        handler = ApproveRequestHandler(api: relay, vault: vault, store: store, directory: directory, clock: { now })
    }

    /// Lookup, enroll, and let the business confirm.
    func enrolled(expectedRoot: String? = nil) async throws -> LocalApprovalKey {
        let offer = try await enrollment.lookup(code: "ABCD2345", expectedRootKid: expectedRoot, secret: testSecret)
        let key = try await enrollment.enroll(offer)
        try await relay.businessConfirms()
        _ = try await enrollment.refreshConfirmations()
        return try #require(try await store.load().keys.first { $0.kid == key.kid })
    }
}

func makeRelay() async throws -> FakeRelay {
    let relay = try await FakeRelay()
    try await relay.publishOperationalKeys()
    return relay
}

@Suite("Approve v2 on the device: enrollment")
struct ApproveEnrollmentDeviceTests {
    @Test func enrollmentActivatesOnlyWhenTheBusinessConfirmsTheDevicesKey() async throws {
        let relay = try await makeRelay()
        let phone = ApprovePhone(relay: relay, logKey: await relay.logPublicKey, now: relay.now)
        let offer = try await phone.enrollment.lookup(code: "ABCD-2345", secret: testSecret)
        #expect(offer.preview.business.displayName == "Harbor Bank")
        #expect(offer.trust == .firstUse)
        let key = try await phone.enrollment.enroll(offer)
        #expect(key.status == .pendingConfirmation)
        // Not confirmed yet: it cannot approve anything.
        #expect(try await phone.enrollment.refreshConfirmations() == [.stillWaiting(kid: key.kid)])
        #expect(try await phone.store.load().keys.first?.status == .pendingConfirmation)
        try await relay.businessConfirms()
        #expect(try await phone.enrollment.refreshConfirmations() == [.activated(kid: key.kid)])
        #expect(try await phone.store.load().keys.first?.status == .active)
        #expect(try await phone.vault.approvalKey(enrollment: key.enrollmentId) != nil)
    }

    @Test func aRelayThatSubstitutesTheKeyIsDetectedAndTheKeyIsRemoved() async throws {
        let relay = try await makeRelay()
        await relay.setSubstitute(SoftwareP256SigningKey())
        let phone = ApprovePhone(relay: relay, logKey: await relay.logPublicKey, now: relay.now)
        let offer = try await phone.enrollment.lookup(code: "ABCD2345", secret: testSecret)
        let key = try await phone.enrollment.enroll(offer)
        try await relay.businessConfirms() // the business confirms what it was shown: the attacker's key
        let outcomes = try await phone.enrollment.refreshConfirmations()
        #expect(outcomes == [.substitutionDetected(kid: key.kid)])
        let local = try #require(try await phone.store.load().keys.first)
        #expect(local.status == .substitutionDetected)
        #expect(try await phone.vault.approvalKey(enrollment: key.enrollmentId) == nil, "the private keys are deleted")
        #expect(try await phone.vault.hpkeKey(enrollment: key.enrollmentId) == nil)
        #expect(await relay.keyRevoked)
    }

    @Test func aConfirmationSignedByAnUnpublishedKeyDoesNotActivate() async throws {
        let relay = try await makeRelay()
        let phone = ApprovePhone(relay: relay, logKey: await relay.logPublicKey, now: relay.now)
        let key = try await phone.enrollment.enroll(try await phone.enrollment.lookup(code: "ABCD2345", secret: testSecret))
        // The relay forges a confirmation with a key the business never published.
        let statement = try ApprovalEnrollmentStatement.verify(key.statement)
        let forged = try await ApprovalEnrollmentConfirmation(confirming: statement, signed: key.statement, at: relay.now).sign(with: SoftwareP256SigningKey())
        await relay.setConfirmation(forged)
        #expect(try await phone.enrollment.refreshConfirmations() == [.substitutionDetected(kid: key.kid)])
    }

    @Test func aBusinessWithoutAConfirmationKeyIsNotReady() async throws {
        let relay = try await FakeRelay()
        let phone = ApprovePhone(relay: relay, logKey: await relay.logPublicKey, now: relay.now)
        await #expect(throws: ApproveError.businessNotReady) { try await phone.enrollment.lookup(code: "ABCD2345", secret: testSecret) }
    }

    @Test func aLinkRootThatDiffersFromTheLogIsRefused() async throws {
        let relay = try await makeRelay()
        let phone = ApprovePhone(relay: relay, logKey: await relay.logPublicKey, now: relay.now)
        await #expect(throws: ApproveError.rootMismatchWithLink) { try await phone.enrollment.lookup(code: "ABCD2345", expectedRootKid: "bk_other", secret: testSecret) }
        let kid = await relay.rootKid
        let offer = try await phone.enrollment.lookup(code: "ABCD2345", expectedRootKid: kid, secret: testSecret)
        #expect(offer.trust == .verifiedOutOfBand)
    }

    @Test func withoutAPinnedLogKeyNothingIsVerifiedAndNothingIsEnrolled() async throws {
        let relay = try await makeRelay()
        let phone = ApprovePhone(relay: relay, logKey: nil, now: relay.now)
        await #expect(throws: ApproveError.notConfigured) { try await phone.enrollment.lookup(code: "ABCD2345", secret: testSecret) }
        // A log signed by some other key is not the app's log.
        let other = ApprovePhone(relay: relay, logKey: SoftwareP256SigningKey().publicKey, now: relay.now)
        await #expect(throws: ApproveError.directory(.treeHeadSignature)) { try await other.enrollment.lookup(code: "ABCD2345", secret: testSecret) }
    }

    @Test func aDeviceWithoutBiometricsCannotEnrollAndCreatesNoKey() async throws {
        let relay = try await makeRelay()
        let vault = SoftwareApprovalKeyVault(unsupported: [.biometric])
        let phone = ApprovePhone(relay: relay, logKey: await relay.logPublicKey, vault: vault, now: relay.now)
        let offer = try await phone.enrollment.lookup(code: "ABCD2345", secret: testSecret)
        await #expect(throws: ApproveError.deviceCannotSatisfy) { try await phone.enrollment.enroll(offer) }
        #expect(try await phone.store.load().keys.isEmpty)
    }

    @Test func revokingRemovesTheKeysOnTheDevice() async throws {
        let relay = try await makeRelay()
        let phone = ApprovePhone(relay: relay, logKey: await relay.logPublicKey, now: relay.now)
        let key = try await phone.enrolled()
        try await phone.enrollment.revoke(kid: key.kid)
        #expect(try await phone.store.load().keys.first?.status == .revoked)
        #expect(try await phone.vault.approvalKey(enrollment: key.enrollmentId) == nil)
    }
}

@Suite("Approve v2 on the device: directory pinning")
struct ApproveDirectoryDeviceTests {
    @Test func aValidRootSuccessionIsSurfacedNotAccepted() async throws {
        let relay = try await makeRelay()
        let phone = ApprovePhone(relay: relay, logKey: await relay.logPublicKey, now: relay.now)
        let key = try await phone.enrolled()
        try await relay.rotateRoot()
        await #expect(throws: ApproveError.rootChanged(key.businessId)) { try await phone.directory.verify(businessId: key.businessId) }
        let alert = try #require(try await phone.directory.alert(for: key.businessId))
        guard case .rootChanged(let change) = alert else { Issue.record("expected a root change"); return }
        #expect(change.pinnedKid != change.newKid)
        // Requests from the business are held back until the person decides.
        _ = try await relay.deliverEndToEnd(to: key)
        let loaded = try await phone.handler.load()
        #expect(loaded.prompts.isEmpty)
        #expect(loaded.rejected.first?.reason == "root_changed")
        try await phone.directory.acceptRootChange(businessId: key.businessId, authorizer: AllowAuthorizer())
        #expect(try await phone.directory.alert(for: key.businessId) == nil)
    }

    @Test func aDifferentHistoryForAPinnedBusinessIsAConflictThatNetworkCannotClear() async throws {
        let relay = try await makeRelay()
        let phone = ApprovePhone(relay: relay, logKey: await relay.logPublicKey, now: relay.now)
        let key = try await phone.enrolled()
        // The relay serves a fresh log (same signing key) in which the business was registered by an attacker's root.
        let attacker = try await FakeRelay(businessId: key.businessId, logKey: relay.logKey)
        try await attacker.publishOperationalKeys()
        let victim = BusinessDirectoryClient(api: attacker, store: phone.store, logKeys: [await relay.logPublicKey], clock: { phone.now })
        do {
            _ = try await victim.verify(businessId: key.businessId)
            Issue.record("a forked history must not verify")
        } catch let error as ApproveError {
            // Either the log is inconsistent with the head seen before, or the pinned root is missing from the history.
            #expect(error == .rootConflict(key.businessId) || error == .directory(.consistencyFailed) || error == .directory(.forkDetected) || error == .directory(.consistencyProofMissing))
        }
    }

    @Test func aRelayServingAnOlderHeadIsRefused() async throws {
        let relay = try await makeRelay()
        let phone = ApprovePhone(relay: relay, logKey: await relay.logPublicKey, now: relay.now)
        let key = try await phone.enrolled()
        try await relay.publish(.hpkeEncryption, SoftwareE2EEPrivateKey().publicKey.x963)
        _ = try await phone.directory.verify(businessId: key.businessId)
        await relay.setServeHead(2)
        await #expect(throws: ApproveError.self) { try await phone.directory.verify(businessId: key.businessId) }
    }
}

@Suite("Approve v2 on the device: requests")
struct ApproveRequestDeviceTests {
    @Test func anEndToEndRequestIsDecryptedVerifiedAndAnsweredWithAResultTheBusinessCanVerify() async throws {
        let relay = try await makeRelay()
        let phone = ApprovePhone(relay: relay, logKey: await relay.logPublicKey, now: relay.now)
        let key = try await phone.enrolled()
        _ = try await relay.deliverEndToEnd(to: key)
        let loaded = try await phone.handler.load()
        let prompt = try #require(loaded.prompts.first)
        #expect(prompt.assurance == .endToEndSigned)
        #expect(prompt.content.details == FakeRelay.details)
        #expect(try await phone.handler.answer(prompt, decision: .approve) == .approved)
        // The business verifies the result with the key it enrolled, independent of anything the relay said.
        let (_, jws) = try #require(await relay.submitted.first)
        let enrolled = EnrolledApprovalKey(kid: key.kid, publicKey: try ApprovalEnrollmentStatement.verify(key.statement).publicKey, subject: key.subject, assurance: .biometric)
        let expectation = ApprovalExpectation(audience: key.businessId, subject: key.subject, requestId: prompt.content.requestId, challenge: prompt.content.challenge,
                                              subjectDetails: FakeRelay.details, requestExpiresAt: prompt.content.expiresAtDate, minimumAMR: .biometric)
        let verified = try ApprovalResultVerifier.verify(jws, expecting: expectation, keys: [enrolled], now: relay.now)
        #expect(verified.claims.decision == .approve)
        // Another amount is not what was signed.
        let other = ApprovalExpectation(audience: key.businessId, subject: key.subject, requestId: prompt.content.requestId, challenge: prompt.content.challenge,
                                        subjectDetails: .transaction(TransactionDetails(currency: "USD", amountMinor: 1, payeeDisplay: "Example Merchant", transactionReference: "bank_tx_123")),
                                        requestExpiresAt: prompt.content.expiresAtDate, minimumAMR: .biometric)
        #expect(throws: ApprovalVerificationError.self) { try ApprovalResultVerifier.verify(jws, expecting: other, keys: [enrolled], now: relay.now) }
    }

    @Test func aRequestSignedByAKeyTheBusinessNeverPublishedIsHiddenNotShown() async throws {
        let relay = try await makeRelay()
        let phone = ApprovePhone(relay: relay, logKey: await relay.logPublicKey, now: relay.now)
        let key = try await phone.enrolled()
        // The relay knows the device's public HPKE key (it is in the enrollment) and can encrypt anything to it, but cannot sign as the business.
        _ = try await relay.deliverEndToEnd(to: key, signedBy: SoftwareP256SigningKey())
        let loaded = try await phone.handler.load()
        #expect(loaded.prompts.isEmpty)
        #expect(loaded.rejected.count == 1)
        #expect(loaded.rejected.first?.reason == "signer_not_published")
    }

    @Test func aRequestForAnotherKeyOrAnotherRequestIdIsRejected() async throws {
        let relay = try await makeRelay()
        let phone = ApprovePhone(relay: relay, logKey: await relay.logPublicKey, now: relay.now)
        let key = try await phone.enrolled()
        _ = try await relay.deliverEndToEnd(to: key, requestId: "req_aaaaaaaaaaaaaaaa", toKid: "ak_someoneelse")
        let loaded = try await phone.handler.load()
        #expect(loaded.prompts.isEmpty)
        #expect(loaded.rejected.first?.reason == "signature_or_binding_invalid")
    }

    @Test func aServerVisibleRequestIsMarkedAsRelayAsserted() async throws {
        let relay = try await makeRelay()
        let phone = ApprovePhone(relay: relay, logKey: await relay.logPublicKey, now: relay.now)
        let key = try await phone.enrolled()
        _ = await relay.deliverServerVisible(to: key)
        let prompt = try #require(try await phone.handler.load().prompts.first)
        #expect(prompt.assurance == .relayAsserted)
    }

    @Test func denyingAndReportingAreSignedResultsAndFatigueIsReported() async throws {
        let relay = try await makeRelay()
        let phone = ApprovePhone(relay: relay, logKey: await relay.logPublicKey, now: relay.now)
        let key = try await phone.enrolled()
        _ = try await relay.deliverEndToEnd(to: key, requestId: "req_denyaaaaaaaaaaaa", count: 3)
        let prompt = try #require(try await phone.handler.load().prompts.first)
        #expect(prompt.showFatigueWarning)
        _ = try await phone.handler.answer(prompt, decision: .report)
        let (_, jws) = try #require(await relay.submitted.last)
        let enrolled = EnrolledApprovalKey(kid: key.kid, publicKey: try ApprovalEnrollmentStatement.verify(key.statement).publicKey, subject: key.subject, assurance: .biometric)
        let expectation = ApprovalExpectation(audience: key.businessId, subject: key.subject, requestId: prompt.content.requestId, challenge: prompt.content.challenge,
                                              subjectDetails: FakeRelay.details, requestExpiresAt: prompt.content.expiresAtDate, minimumAMR: .biometric)
        let verified = try ApprovalResultVerifier.verify(jws, expecting: expectation, keys: [enrolled], now: relay.now)
        #expect(verified.claims.decision == .report)
        #expect(try await phone.store.load().decisions.last?.decision == .report)
    }

    @Test func aKeyThatNoLongerExistsCannotAnswer() async throws {
        let relay = try await makeRelay()
        let phone = ApprovePhone(relay: relay, logKey: await relay.logPublicKey, now: relay.now)
        let key = try await phone.enrolled()
        _ = try await relay.deliverEndToEnd(to: key)
        let prompt = try #require(try await phone.handler.load().prompts.first)
        try await phone.vault.delete(enrollment: key.enrollmentId)
        await #expect(throws: ApproveError.keyMissing) { try await phone.handler.answer(prompt, decision: .approve) }
        #expect(await relay.submitted.isEmpty)
    }
}

@Suite("Approve v2 on the device: routing and controller")
struct ApproveControllerTests {
    @Test func enrollmentLinksRouteWithTheRootKeyId() {
        let kid = KeyIdentifier.make(try! SoftwareP256SigningKey().publicKey.signingKey())
        #expect(DeepLinkRouter.route("https://viadere.com/a/ABCD2345?rk=\(kid)") == .approveEnrollment(code: "ABCD2345", rootKid: kid, secret: nil))
        #expect(DeepLinkRouter.route("https://viadere.com/a/ABCD2345") == .approveEnrollment(code: "ABCD2345", rootKid: nil, secret: nil))
        // Anything else on that path is refused: extra segments, a fragment, odd query items, another host.
        #expect(DeepLinkRouter.route("https://viadere.com/a/ABCD2345/x") == nil)
        #expect(DeepLinkRouter.route("https://viadere.com/a/ABCD2345?rk=\(kid)&x=1") == nil)
        #expect(DeepLinkRouter.route("https://evil.example/a/ABCD2345") == nil)
        #expect(DeepLinkRouter.route("https://viadere.com/a/ABCD2345#f") == nil)
    }

    @MainActor
    @Test func theControllerEnrollsAndShowsVerifiedRequests() async throws {
        let relay = try await makeRelay()
        let now = relay.now
        let secrets = InMemorySecretStore()
        let store = SecretApproveLocalStore(secrets: secrets)
        let environment = ApproveEnvironment(api: relay, vault: SoftwareApprovalKeyVault(), store: store, logKeys: [await relay.logPublicKey],
                                             keys: SoftwareDeviceKeyStore(secrets: secrets), records: SecretDeviceRecordStore(secrets: secrets), clock: { now })
        let controller = ApproveController(environment: environment)
        #expect(controller.isAvailable)
        await controller.lookup(code: "ABCD2345", expectedRootKid: nil, secret: testSecret)
        #expect(controller.offer?.preview.business.displayName == "Harbor Bank")
        #expect(await controller.confirmEnrollment())
        try await relay.businessConfirms()
        await controller.refresh()
        let key = try #require(controller.keys.first)
        #expect(key.status == .active)
        _ = try await relay.deliverEndToEnd(to: key)
        await controller.refresh()
        let prompt = try #require(controller.prompts.first)
        #expect(await controller.answer(prompt, .deny))
        #expect(controller.prompts.isEmpty)
    }

    @MainActor
    @Test func withoutALogKeyTheControllerIsUnavailable() async throws {
        let relay = try await makeRelay()
        let secrets = InMemorySecretStore()
        let environment = ApproveEnvironment(api: relay, vault: SoftwareApprovalKeyVault(), store: SecretApproveLocalStore(secrets: secrets), logKeys: [],
                                             keys: SoftwareDeviceKeyStore(secrets: secrets), records: SecretDeviceRecordStore(secrets: secrets))
        let controller = ApproveController(environment: environment)
        #expect(!controller.isAvailable)
        await controller.lookup(code: "ABCD2345", expectedRootKid: nil, secret: testSecret)
        #expect(controller.offer == nil)
        #expect(controller.message == ApproveText.notAvailable)
    }
}

@Suite("Approve v2 on the device: gate fixes")
struct ApproveGateDeviceTests {
    @Test func withoutTheLinkSecretOrTheCheckCodeNoKeyIsCreated() async throws {
        // F1: the business could not tell this phone's key from one the relay made, so the phone makes none.
        let relay = try await makeRelay()
        let phone = ApprovePhone(relay: relay, logKey: await relay.logPublicKey, now: relay.now)
        await #expect(throws: ApproveError.enrollmentSecretRequired) { try await phone.enrollment.lookup(code: "ABCD2345") }
        await #expect(throws: ApproveError.enrollmentSecretRequired) { try await phone.enrollment.lookup(code: "ABCD2345", checkCode: "short") }
        // An offer assembled without either (a relay-supplied preview) cannot be enrolled either.
        let offer = EnrollmentOffer(preview: ApproveEnrollmentPreview(enrollmentId: UUID(), business: relay.summary, relationshipId: RelationshipID(), subjectRef: relay.subject,
                                                                       capability: .transactionApprove, requiredAssurance: .biometric, expiresAt: relay.now.addingTimeInterval(600)),
                                    rootFingerprint: "x", trust: .firstUse, expectedRootKid: nil)
        await #expect(throws: ApproveError.enrollmentSecretRequired) { try await phone.enrollment.enroll(offer) }
        #expect(try await phone.store.load().keys.isEmpty)
    }

    @Test func theLinkPathSendsATagOnlyTheSecretHolderCanCheck() async throws {
        let relay = try await makeRelay()
        let phone = ApprovePhone(relay: relay, logKey: await relay.logPublicKey, now: relay.now)
        let secret = ApprovalEnrollmentSecret()
        let key = try await phone.enrollment.enroll(try await phone.enrollment.lookup(code: "ABCD2345", secret: secret))
        let tag = try #require(await relay.receivedBindingTag)
        #expect(secret.verifyBindingTag(tag, for: key.statement))
        #expect(!ApprovalEnrollmentSecret().verifyBindingTag(tag, for: key.statement), "the relay, without the secret, cannot produce or move it")
        #expect(key.verificationCode == nil)
    }

    @Test func theTypedPathShowsASixDigitNumberTheBusinessCanRecomputeAndSendsNothingSecret() async throws {
        let relay = try await makeRelay()
        let phone = ApprovePhone(relay: relay, logKey: await relay.logPublicKey, now: relay.now)
        let secret = ApprovalEnrollmentSecret()
        let offer = try await phone.enrollment.lookup(code: "ABCD2345", checkCode: ApprovalEnrollmentCode.display(secret.checkCode).lowercased())
        let key = try await phone.enrollment.enroll(offer)
        #expect(await relay.receivedBindingTag == nil)
        let sas = try #require(key.verificationCode)
        #expect(secret.verifySAS(sas, for: key.statement), "the business, holding `es`, derives the same digits")
        // The number is shown only until the business has confirmed.
        try await relay.businessConfirms()
        _ = try await phone.enrollment.refreshConfirmations()
        #expect(try await phone.store.load().keys.first?.verificationCode == nil)
    }

    @Test func aKeyTheBusinessNeverConfirmsIsRemovedAndReported() async throws {
        let relay = try await makeRelay()
        let phone = ApprovePhone(relay: relay, logKey: await relay.logPublicKey, now: relay.now)
        let key = try await phone.enrollment.enroll(try await phone.enrollment.lookup(code: "ABCD2345", secret: testSecret))
        #expect(try await phone.enrollment.refreshConfirmations() == [.stillWaiting(kid: key.kid)])
        // Later than the enrollment's expiry plus the relay's grace: a relay holding the key back for later is not waited for.
        let later = relay.now.addingTimeInterval(600 + 300 + 10)
        let lated = ApprovePhone(relay: relay, logKey: await relay.logPublicKey, store: phone.store, vault: phone.vault, now: later)
        #expect(try await lated.enrollment.refreshConfirmations() == [.unconfirmedExpired(kid: key.kid)])
        #expect(try await phone.store.load().keys.first?.status == .revoked)
        #expect(try await phone.vault.approvalKey(enrollment: key.enrollmentId) == nil)
        #expect(await relay.keyRevoked)
    }

    @Test func theDeepLinkCarriesTheSecretFromTheFragment() throws {
        let secret = ApprovalEnrollmentSecret()
        let link = "https://viadere.com/a/ABCD2345#es=\(secret.base64URL)"
        #expect(DeepLinkRouter.route(link) == .approveEnrollment(code: "ABCD2345", rootKid: nil, secret: secret))
        #expect(DeepLinkRouter.route("https://viadere.com/a/ABCD2345#es=short") == nil)
    }

    // MARK: F4

    @Test func theSeenHeadOnlyMovesForward() {
        func head(_ size: Int, _ root: String, _ t: Int64 = 1) -> SeenTreeHead { SeenTreeHead(treeSize: size, rootHash: root, timestamp: t) }
        var state = ApproveLocalState()
        state.advanceHead(to: head(5, "aa"))
        state.advanceHead(to: head(3, "bb"))
        #expect(state.lastSeenHead == head(5, "aa"), "an older tree never replaces a newer one")
        state.advanceHead(to: head(5, "aa", 9))
        #expect(state.lastSeenHead == head(5, "aa", 9), "the same tree refreshes its timestamp")
        state.advanceHead(to: head(5, "cc", 99))
        #expect(state.lastSeenHead == head(5, "aa", 9), "an equal size with another root never replaces it")
        state.advanceHead(to: head(8, "dd"))
        #expect(state.lastSeenHead == head(8, "dd"))
    }

    @Test func aSlowerRefreshCannotRollTheHeadBack() async throws {
        let relay = try await makeRelay()
        let phone = ApprovePhone(relay: relay, logKey: await relay.logPublicKey, now: relay.now)
        let business = await relay.businessId
        _ = try await phone.directory.verify(businessId: business)
        let first = try #require(try await phone.store.load().lastSeenHead)
        // Refresh A reads the log, then stalls; the log grows and refresh B completes; then A finishes with its older tree.
        await relay.stallNext()
        let slow = Task { try await phone.directory.verify(businessId: business) }
        while !(await relay.hasStalledCall) { await Task.yield() }
        try await relay.publish(.hpkeEncryption, SoftwareE2EEPrivateKey().publicKey.x963)
        _ = try await phone.directory.verify(businessId: business)
        let advanced = try #require(try await phone.store.load().lastSeenHead)
        #expect(advanced.treeSize > first.treeSize)
        await relay.release()
        _ = try await slow.value
        #expect(try await phone.store.load().lastSeenHead == advanced, "the late, older refresh did not overwrite the newer head")
    }

    @Test func twoRefreshesThatSawDifferentTreesOfOneSizeAreAForkAndFailClosed() async throws {
        let relay = try await makeRelay()
        let phone = ApprovePhone(relay: relay, logKey: await relay.logPublicKey, now: relay.now)
        let business = await relay.businessId
        _ = try await phone.directory.verify(businessId: business)
        let seen = try #require(try await phone.store.load().lastSeenHead)
        await relay.stallNext()
        let slow = Task { try await phone.directory.verify(businessId: business) }
        while !(await relay.hasStalledCall) { await Task.yield() }
        // Meanwhile another refresh stored a different tree of the same size.
        try await phone.store.update { $0.lastSeenHead = SeenTreeHead(treeSize: seen.treeSize, rootHash: String(repeating: "ab", count: 32), timestamp: seen.timestamp) }
        await relay.release()
        await #expect(throws: ApproveError.directory(.forkDetected)) { _ = try await slow.value }
    }

    // MARK: F5

    @Test func aChangedRootNeedsAFreshBiometricProofBeforeItIsTrusted() async throws {
        let relay = try await makeRelay()
        let phone = ApprovePhone(relay: relay, logKey: await relay.logPublicKey, now: relay.now)
        let key = try await phone.enrolled()
        try await relay.rotateRoot()
        await #expect(throws: ApproveError.rootChanged(key.businessId)) { try await phone.directory.verify(businessId: key.businessId) }
        // A tap alone (a thief on an unlocked phone) is not enough: the proof is cancelled or fails, nothing is pinned.
        await #expect(throws: ApproveError.userCancelled) { try await phone.directory.acceptRootChange(businessId: key.businessId, authorizer: DenyAuthorizer()) }
        guard case .rootChanged? = try await phone.directory.alert(for: key.businessId) else { Issue.record("the change must still be pending"); return }
        await #expect(throws: ApproveError.rootChanged(key.businessId)) { try await phone.directory.verify(businessId: key.businessId) }
        try await phone.directory.acceptRootChange(businessId: key.businessId, authorizer: AllowAuthorizer())
        #expect(try await phone.directory.alert(for: key.businessId) == nil)
    }

    @Test func theDeviceAuthorizerSignsAChallengeWithTheBiometricKey() async throws {
        let secrets = InMemorySecretStore()
        let keys = SoftwareDeviceKeyStore(secrets: secrets)
        _ = try await keys.createKey(for: .approvalBiometric)
        try await DeviceBiometricAuthorizer(keys: keys).authorize(reason: "test")
        await #expect(throws: KeyStoreError.self) { try await DeviceBiometricAuthorizer(keys: SoftwareDeviceKeyStore(secrets: InMemorySecretStore())).authorize(reason: "test") }
    }
}

extension FakeRelay {
    func setSubstitute(_ key: SoftwareP256SigningKey?) { substituteKey = key }
    func setConfirmation(_ value: BusinessSignedStatement?) { confirmation = value }
    func setServeHead(_ size: Int?) { serveHeadSize = size }
    func stallNext() { stallNextDirectory = true }
}

#endif
