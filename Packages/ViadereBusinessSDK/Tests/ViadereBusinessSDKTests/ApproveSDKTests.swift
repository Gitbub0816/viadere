import Crypto
import Foundation
import Testing
import ViadereCore
@testable import ViadereBusinessSDK

private enum Approve {
    static let now = Date(timeIntervalSince1970: 1_800_000_000)
    static let business = BusinessID()
    static let subject = SubjectRef("sub_" + Base64URL.encode(Data(repeating: 7, count: 32)))!
    static let details = ApprovalSubject.transaction(TransactionDetails(currency: "USD", amountMinor: 250_000, payeeDisplay: "Example Merchant", transactionReference: "bank_tx_123"))

    struct Phone {
        let key = SoftwareP256SigningKey()
        let hpke = SoftwareE2EEPrivateKey()
        var kid: String { KeyIdentifier.make(try! key.publicKey.signingKey()) }
        var enrolled: EnrolledApprovalKey { EnrolledApprovalKey(kid: kid, publicKey: key.publicKey, subject: subject, assurance: .biometric) }
    }

    static func pending(requestId: String = "req_0123456789abcdef", challenge: String = BusinessChallenge.value, details: ApprovalSubject = Approve.details) -> PendingApproval {
        PendingApproval(requestId: requestId, subject: subject, challenge: challenge, details: details, expiresAt: now.addingTimeInterval(120))
    }

    static func result(_ phone: Phone, _ pending: PendingApproval, decision: ApprovalDecision = .approve, amr: ApprovalAMR = .biometric, shown: ApprovalSubject? = nil,
                       audience: BusinessID? = nil, at: Date? = nil) async throws -> String {
        let content = ApprovalRequestContent(businessId: audience ?? business, subject: pending.subject, requestId: pending.requestId, challenge: pending.challenge, details: shown ?? pending.details,
                                            toKid: phone.kid, issuedAt: now, expiresAt: pending.expiresAt)
        return try await ApprovalResultFactory.sign(displayed: content, decision: decision, amr: amr, key: phone.key, now: at ?? now)
    }

    static func verifier(_ phone: Phone, minimum: ApprovalAMR? = .biometric, store: InMemoryApprovalKeyStore? = nil, cache: InMemoryReplayGuard = InMemoryReplayGuard()) async -> ApprovalVerifier {
        let store = store ?? InMemoryApprovalKeyStore()
        await store.add(phone.enrolled)
        return ApprovalVerifier(businessId: business, keys: store, replayCache: cache, minimumAMR: minimum, clock: { now })
    }
}

enum BusinessChallenge { static let value = Base64URL.encode(Data(repeating: 9, count: 32)) }

@Suite("Approval verifier (business side)")
struct ApprovalVerifierTests {
    @Test func aSignedApprovalVerifiesAndTheChallengeIsConsumed() async throws {
        let phone = Approve.Phone()
        let pending = Approve.pending()
        let verifier = await Approve.verifier(phone)
        let jws = try await Approve.result(phone, pending)
        let verified = try await verifier.verify(result: jws, for: pending)
        #expect(verified.decision == .approve)
        #expect(verified.claims.kid == phone.kid)
        // The same result again, or a re-signed one for the same challenge, is a replay.
        await #expect(throws: ApprovalVerificationError.replayed) { _ = try await verifier.verify(result: jws, for: pending) }
        let resigned = try await Approve.result(phone, pending, at: Approve.now.addingTimeInterval(1))
        await #expect(throws: ApprovalVerificationError.replayed) { _ = try await verifier.verify(result: resigned, for: pending) }
    }

    @Test func everySubstitutionIsRefused() async throws {
        let phone = Approve.Phone()
        let verifier = await Approve.verifier(phone)
        guard case .transaction(let t) = Approve.details else { return }
        func shown(_ transform: (inout TransactionDetails) -> Void) -> ApprovalSubject { var copy = t; transform(&copy); return .transaction(copy) }
        // The device signed something other than what the business recorded.
        let variants: [(String, ApprovalSubject)] = [
            ("amount", shown { $0.amountMinor = 25_000_000 }), ("payee", shown { $0.payeeDisplay = "Mallory Ltd" }),
            ("currency", shown { $0.currency = "EUR" }), ("reference", shown { $0.transactionReference = "bank_tx_999" }),
        ]
        for (name, display) in variants {
            let jws = try await Approve.result(phone, Approve.pending(), shown: display)
            await #expect(throws: ApprovalVerificationError.transactionMismatch, "\(name)") { _ = try await verifier.verify(result: jws, for: Approve.pending()) }
        }
        // Other business, other customer, other request, other nonce, expired result.
        let good = try await Approve.result(phone, Approve.pending())
        await #expect(throws: ApprovalVerificationError.wrongAudience) { _ = try await verifier.verify(result: try await Approve.result(phone, Approve.pending(), audience: BusinessID()), for: Approve.pending()) }
        await #expect(throws: ApprovalVerificationError.wrongRequest) { _ = try await verifier.verify(result: good, for: Approve.pending(requestId: "req_other_request_id_1")) }
        await #expect(throws: ApprovalVerificationError.challengeMismatch) { _ = try await verifier.verify(result: good, for: Approve.pending(challenge: Base64URL.encode(Data(repeating: 1, count: 32)))) }
        let other = PendingApproval(requestId: "req_0123456789abcdef", subject: SubjectRef("sub_" + Base64URL.encode(Data(repeating: 1, count: 32)))!, challenge: BusinessChallenge.value, details: Approve.details, expiresAt: Approve.now.addingTimeInterval(120))
        await #expect(throws: ApprovalVerificationError.unknownKey) { _ = try await verifier.verify(result: good, for: other) }
        let lateStore = InMemoryApprovalKeyStore()
        await lateStore.add(phone.enrolled)
        let late = ApprovalVerifier(businessId: Approve.business, keys: lateStore, replayCache: InMemoryReplayGuard(), clock: { Approve.now.addingTimeInterval(400) })
        await #expect(throws: ApprovalVerificationError.expired) { _ = try await late.verify(result: good, for: Approve.pending()) }
        // Nothing above consumed the challenge: the genuine result still works.
        _ = try await verifier.verify(result: good, for: Approve.pending())
    }

    @Test func onlyKeysYouRecordedCanApproveAndRevocationIsHonoured() async throws {
        let phone = Approve.Phone()
        let attacker = Approve.Phone()
        let store = InMemoryApprovalKeyStore()
        await store.add(phone.enrolled)
        let verifier = ApprovalVerifier(businessId: Approve.business, keys: store, replayCache: InMemoryReplayGuard(), clock: { Approve.now })
        // A relay that signs with a key of its own: not in your records.
        await #expect(throws: ApprovalVerificationError.unknownKey) { _ = try await verifier.verify(result: try await Approve.result(attacker, Approve.pending()), for: Approve.pending()) }
        // The same key the relay might add to ITS list is still not in yours.
        await store.revoke(kid: phone.kid, subject: Approve.subject)
        await #expect(throws: ApprovalVerificationError.keyRevoked) { _ = try await verifier.verify(result: try await Approve.result(phone, Approve.pending()), for: Approve.pending()) }
    }

    @Test func deniedAndWeakResultsDoNotAuthorize() async throws {
        let phone = Approve.Phone()
        let verifier = await Approve.verifier(phone)
        await #expect(throws: ApprovalVerificationError.notApproved(.deny)) { _ = try await verifier.verify(result: try await Approve.result(phone, Approve.pending(), decision: .deny), for: Approve.pending()) }
        await #expect(throws: ApprovalVerificationError.notApproved(.report)) { _ = try await verifier.verify(result: try await Approve.result(phone, Approve.pending(), decision: .report), for: Approve.pending()) }
        #expect(try await verifier.decision(of: try await Approve.result(phone, Approve.pending(), decision: .deny), for: Approve.pending()) == .deny)
        // A presence-class key may not claim biometric authentication, and a business minimum is enforced.
        let weakPhone = Approve.Phone()
        let store = InMemoryApprovalKeyStore()
        await store.add(EnrolledApprovalKey(kid: weakPhone.kid, publicKey: weakPhone.key.publicKey, subject: Approve.subject, assurance: .presence))
        let relaxed = ApprovalVerifier(businessId: Approve.business, keys: store, replayCache: InMemoryReplayGuard(), minimumAMR: nil, clock: { Approve.now })
        await #expect(throws: ApprovalVerificationError.amrExceedsKey) { _ = try await relaxed.verify(result: try await Approve.result(weakPhone, Approve.pending(), amr: .biometric), for: Approve.pending()) }
        _ = try await relaxed.verify(result: try await Approve.result(weakPhone, Approve.pending(), amr: .presence), for: Approve.pending())
        let strict = ApprovalVerifier(businessId: Approve.business, keys: store, replayCache: InMemoryReplayGuard(), minimumAMR: .biometric, clock: { Approve.now })
        await #expect(throws: ApprovalVerificationError.insufficientAuthentication) { _ = try await strict.verify(result: try await Approve.result(weakPhone, Approve.pending(), amr: .presence), for: Approve.pending()) }
    }

    @Test func aRelayStatusIsNotAnInputAtAll() async throws {
        // The API of the verifier takes a compact JWS and your own records. There is no parameter for "the relay says approved".
        let phone = Approve.Phone()
        let verifier = await Approve.verifier(phone)
        await #expect(throws: ApprovalVerificationError.self) { _ = try await verifier.verify(result: "approved", for: Approve.pending()) }
        await #expect(throws: ApprovalVerificationError.self) { _ = try await verifier.verify(result: "", for: Approve.pending()) }
    }
}

@Suite("Approval request builder")
struct ApprovalRequestBuilderTests {
    @Test func theServerVisibleBodyIsTheSpecShape() throws {
        let builder = ApprovalRequestBuilder(businessId: Approve.business)
        let body = try builder.serverVisible(requestId: "req_0123456789abcdef", subject: Approve.subject, challenge: BusinessChallenge.value, details: Approve.details, expiresIn: 120)
        guard case .object(let members) = try JSONDecoder().decode(JSONValue.self, from: try ViadereJSON.encode(body)) else { Issue.record("not an object"); return }
        #expect(Set(members.keys) == ["request_id", "subject_ref", "capability", "challenge", "transaction", "expires_in_seconds"])
        #expect(members["capability"] == .string("transaction.approve"))
        guard case .object(let transaction)? = members["transaction"] else { Issue.record("no transaction"); return }
        #expect(Set(transaction.keys) == ["currency", "amount_minor", "payee_display", "transaction_reference"])
        #expect(transaction["amount_minor"] == .integer(250_000))
        // Hostile display text is refused before it leaves your server.
        let hostile = ApprovalSubject.transaction(TransactionDetails(currency: "USD", amountMinor: 1, payeeDisplay: "Pay\u{202E}eziL", transactionReference: "r"))
        #expect(throws: ApprovalTransactionError.self) { _ = try builder.serverVisible(requestId: "req_0123456789abcdef", subject: Approve.subject, challenge: BusinessChallenge.value, details: hostile) }
        #expect(ApprovalRequestBuilder.newChallenge().count == 43)
        #expect(ApprovalRequestBuilder.newRequestId().hasPrefix("req_"))
    }

    @Test func theEndToEndBodyEncryptsOncePerDeviceAndHidesTheDetails() async throws {
        let one = Approve.Phone(), two = Approve.Phone()
        let signing = SoftwareP256SigningKey()
        let builder = ApprovalRequestBuilder(businessId: Approve.business, requestSigningKey: signing, clock: { Approve.now })
        let body = try await builder.endToEnd(requestId: "req_0123456789abcdef", subject: Approve.subject, challenge: BusinessChallenge.value, details: Approve.details,
                                              devices: [ApprovalDeviceTarget(kid: one.kid, hpkePublicKey: one.hpke.publicKey), ApprovalDeviceTarget(kid: two.kid, hpkePublicKey: two.hpke.publicKey)])
        let wire = String(decoding: try ViadereJSON.encode(body), as: UTF8.self)
        #expect(!wire.contains("Example Merchant") && !wire.contains("250000") && body.transaction == nil && body.challenge == nil)
        #expect(body.envelopes?.count == 2)
        for (phone, delivery) in zip([one, two], try #require(body.envelopes)) {
            let plaintext = try E2EE.open(delivery.envelope, using: phone.hpke, expecting: E2EEExpectation(purpose: "approve.request", requestId: "req_0123456789abcdef",
                                                                                                         sender: "biz_" + Approve.business.description, recipient: "ak_" + phone.kid), now: Approve.now)
            let content = try ApprovalRequestContent.verify(try ApprovalRequestContent.parseSigned(plaintext), signingKey: signing.publicKey, expectedBusiness: Approve.business,
                                                            expectedSubject: Approve.subject, expectedKid: phone.kid, expectedRequestId: "req_0123456789abcdef", now: Approve.now)
            #expect(content.details == Approve.details && content.challenge == BusinessChallenge.value)
        }
        // One device's envelope cannot be opened by the other.
        #expect(throws: E2EEError.self) { _ = try E2EE.open(body.envelopes![0].envelope, using: two.hpke, expecting: E2EEExpectation(purpose: "approve.request"), now: Approve.now) }
    }

    @Test func endToEndNeedsAKeyAndADevice() async throws {
        let phone = Approve.Phone()
        let withoutKey = ApprovalRequestBuilder(businessId: Approve.business)
        await #expect(throws: ApprovalRequestBuilderError.requestSigningKeyRequired) {
            _ = try await withoutKey.endToEnd(requestId: "req_0123456789abcdef", subject: Approve.subject, challenge: BusinessChallenge.value, details: Approve.details,
                                              devices: [ApprovalDeviceTarget(kid: phone.kid, hpkePublicKey: phone.hpke.publicKey)])
        }
        let builder = ApprovalRequestBuilder(businessId: Approve.business, requestSigningKey: SoftwareP256SigningKey())
        await #expect(throws: ApprovalRequestBuilderError.noDevices) {
            _ = try await builder.endToEnd(requestId: "req_0123456789abcdef", subject: Approve.subject, challenge: BusinessChallenge.value, details: Approve.details, devices: [])
        }
    }
}

@Suite("Key authority and log monitor")
struct KeyAuthorityTests {
    final class Log: @unchecked Sendable {
        let key = SoftwareP256SigningKey()
        var tree = MerkleTree()
        var entries: [KeyLogEntry] = []

        func append(_ entry: KeyLogEntry) throws { entries.append(entry); tree.append(leafData: try entry.leafData()) }

        func response(for business: BusinessID, now: Date) async throws -> KeyDirectoryResponse {
            let head = try await SignedTreeHead.sign(TreeHead(treeSize: tree.size, rootHash: tree.root(), timestamp: now), with: key)
            let items = try entries.enumerated().filter { $0.element.businessId == business }.map { index, entry in
                KeyLogEntryProof(index: index, entry: Base64URL.encode(try entry.leafData()), inclusionProof: tree.inclusionProof(index: index, size: tree.size)!.map(Hex.encode))
            }
            return KeyDirectoryResponse(sth: head, entries: items)
        }
    }

    @Test func theAuthorityProducesEntriesTheDirectoryRulesAccept() async throws {
        let log = Log()
        let root = BusinessKeyAuthority.generateRootKey()
        let authority = BusinessKeyAuthority(businessId: Approve.business, rootKey: root)
        try log.append(try await authority.registrationEntry(at: Approve.now))
        let hpke = SoftwareE2EEPrivateKey()
        try log.append(try await authority.keyEntry(purpose: .hpkeEncryption, publicKey: hpke.publicKey.x963, serial: 1, validFrom: Approve.now))
        let old = SoftwareP256SigningKey()
        try log.append(try await authority.keyEntry(purpose: .approvalRequestSigning, publicKey: old.publicKey.x963, serial: 2, validFrom: Approve.now))
        let verifier = KeyDirectoryVerifier(logKeys: [log.key.publicKey])
        var verified = try verifier.verify(try await log.response(for: Approve.business, now: Approve.now), businessId: Approve.business, lastSeen: nil, now: Approve.now)
        #expect(verified.state.lastSerial == 2)
        #expect(verified.state.currentRoot?.kid == authority.rootKid)
        let next = SoftwareP256SigningKey()
        try log.append(try await authority.keyEntry(purpose: .approvalRequestSigning, publicKey: next.publicKey.x963, serial: 3, validFrom: Approve.now))
        try log.append(try await authority.revocationEntry(kid: KeyIdentifier.make(try old.publicKey.signingKey()), serial: 4, at: Approve.now))
        verified = try verifier.verify(try await log.response(for: Approve.business, now: Approve.now), businessId: Approve.business, lastSeen: nil, now: Approve.now)
        #expect(verified.state.validKeys(for: .approvalRequestSigning, at: Approve.now).map(\.kid) == [KeyIdentifier.make(try next.publicKey.signingKey())])
        // Succession by both roots.
        let newRoot = BusinessKeyAuthority.generateRootKey()
        try log.append(try await authority.successionEntry(to: newRoot, at: Approve.now))
        verified = try verifier.verify(try await log.response(for: Approve.business, now: Approve.now), businessId: Approve.business, lastSeen: nil, now: Approve.now)
        #expect(verified.state.currentRoot?.kid == BusinessKeyAuthority(businessId: Approve.business, rootKey: newRoot).rootKid)
    }

    @Test func theMonitorFlagsEntriesYouDidNotMake() async throws {
        let log = Log()
        let root = BusinessKeyAuthority.generateRootKey()
        let authority = BusinessKeyAuthority(businessId: Approve.business, rootKey: root)
        let registration = try await authority.registrationEntry(at: Approve.now)
        try log.append(registration)
        let monitor = KeyLogMonitor(businessId: Approve.business, logKeys: [log.key.publicKey])
        var expected: Set<String> = [Hex.encode(try #require(registration.leafHash))]
        let report = try monitor.check(try await log.response(for: Approve.business, now: Approve.now), lastSeen: nil, expected: expected, now: Approve.now)
        #expect(report.newEntries.count == 1 && report.unexpected.isEmpty && report.rootKid == authority.rootKid)
        // Your own publication is expected; anything else is not.
        let mine = try await authority.keyEntry(purpose: .hpkeEncryption, publicKey: SoftwareE2EEPrivateKey().publicKey.x963, serial: 1, validFrom: Approve.now)
        try log.append(mine)
        let grown = try await log.response(for: Approve.business, now: Approve.now)
        let unexpected = try monitor.check(grown, lastSeen: nil, knownIndexes: [0], expected: expected, now: Approve.now)
        #expect(unexpected.newEntries.map(\.index) == [1] && unexpected.unexpected.count == 1, "an entry you did not record is flagged")
        expected.insert(Hex.encode(try #require(mine.leafHash)))
        let reviewed = try monitor.check(grown, lastSeen: nil, knownIndexes: [0], expected: expected, now: Approve.now)
        #expect(reviewed.unexpected.isEmpty && reviewed.newEntries.count == 1)
        // The saved head must be extended by the new one: a log that rewrote history is an alert too.
        let rewritten = Log()
        try rewritten.append(try await authority.registrationEntry(at: Approve.now.addingTimeInterval(5)))
        try rewritten.append(mine)
        let forgedHead = KeyDirectoryResponse(sth: try await SignedTreeHead.sign(TreeHead(treeSize: 2, rootHash: rewritten.tree.root(), timestamp: Approve.now), with: log.key), entries: [])
        #expect(throws: KeyDirectoryError.forkDetected) { _ = try monitor.check(forgedHead, lastSeen: report.seen.treeSize == 2 ? report.seen : SeenTreeHead(treeSize: 2, rootHash: Hex.encode(log.tree.root()), timestamp: 1), expected: expected, now: Approve.now) }
    }

    @Test func externalSigningKeysSignLikeSoftwareKeys() async throws {
        let inner = SoftwareP256SigningKey()
        let digestMode = ExternalSigningKey(publicKey: inner.publicKey, mode: .sha256Digest) { digest in
            // A KMS is handed the SHA-256 digest of the message and returns DER (here the same key signs the message, which is what a digest signature is).
            #expect(digest == Data(SHA256.hash(data: Data("statement".utf8))) || digest.count == 32)
            return try await inner.signature(for: Data("statement".utf8)).derRepresentation
        }
        let messageMode = ExternalSigningKey(publicKey: inner.publicKey, mode: .message) { message in
            try await inner.signature(for: message).rawRepresentation
        }
        let message = Data("statement".utf8)
        for key in [digestMode, messageMode] {
            let signature = try await key.signature(for: message)
            #expect(try inner.publicKey.signingKey().isValidSignature(signature, for: message))
        }
        // They work as the root of an authority.
        let authority = BusinessKeyAuthority(businessId: Approve.business, rootKey: messageMode)
        let entry = try await authority.registrationEntry(at: Approve.now)
        let statement = try entry.decodeStatement()
        #expect(throws: Never.self) { try entry.verifySignatures(of: statement, signer: inner.publicKey) }
    }
}

@Suite("Approve client")
struct ApproveClientTests {
    private func body(_ request: BusinessHTTPRequest) throws -> [String: JSONValue] {
        guard case .object(let members) = try JSONDecoder().decode(JSONValue.self, from: try #require(request.body)) else { throw ViadereSDKError.encodingFailed }
        return members
    }

    @Test func enrollmentRequestsUseTheCatalogPathsAndTheSubjectRef() async throws {
        let transport = MockTransport()
        let ticket = ApprovalEnrollmentTicket(enrollmentId: UUID(), code: "ABCDEFGH", deepLink: "https://viadere.com/a/ABCDEFGH", expiresAt: Approve.now.addingTimeInterval(600))
        try transport.enqueue(status: 201, json: ticket)
        let created = try await Fixtures.client(transport).createApprovalEnrollment(subject: Approve.subject, capability: .transactionApprove)
        #expect(created == ticket)
        let sent = try #require(transport.requests.first)
        #expect(sent.method == "POST" && sent.url.path == "/v1/business/approve/enrollments")
        let members = try body(sent)
        #expect(members["subject_ref"] == .string(Approve.subject.rawValue) && members["capability"] == .string("transaction.approve"))
        #expect(sent.headers["Idempotency-Key"] == nil, "an enrollment is not blindly retried")
    }

    @Test func confirmingVerifiesTheDeviceStatementBeforeAnythingIsSigned() async throws {
        let phone = Approve.Phone()
        let enrollmentId = UUID()
        let statement = try ApprovalEnrollmentStatement(businessId: Approve.business, subject: Approve.subject, enrollmentId: enrollmentId, publicKey: phone.key.publicKey,
                                                        hpkePublicKey: phone.hpke.publicKey, assurance: .biometric, createdAt: Approve.now)
        let signed = try await statement.sign(with: phone.key)
        func view(_ status: ApprovalEnrollmentStatus = .deviceCompleted, statement: SignedStatement? = signed) -> ApprovalEnrollmentView {
            ApprovalEnrollmentView(enrollmentId: enrollmentId, subjectRef: Approve.subject, capability: .transactionApprove, status: status, expiresAt: Approve.now, createdAt: Approve.now, deviceStatement: statement, kid: phone.kid)
        }
        let confirmationKey = SoftwareP256SigningKey()
        // Happy path: GET the view, POST the confirmation, return what to store.
        let transport = MockTransport()
        try transport.enqueue(status: 200, json: view())
        try transport.enqueue(status: 200, json: ApprovalKeyView(kid: phone.kid, subjectRef: Approve.subject, status: .active, assurance: .biometric, publicKey: phone.key.publicKey.base64URL,
                                                                 hpkeKid: phone.hpke.publicKey.kid, hpkePublicKey: phone.hpke.publicKey.base64URL, createdAt: Approve.now, activatedAt: Approve.now,
                                                                 revokedAt: nil, revokedBy: nil, deviceStatement: signed))
        let confirmed = try await Fixtures.client(transport).confirmApprovalEnrollment(id: enrollmentId, businessId: Approve.business, expectedSubject: Approve.subject, confirmationKey: confirmationKey, now: Approve.now)
        #expect(confirmed.key == phone.enrolled && confirmed.hpke == phone.hpke.publicKey && confirmed.target.kid == phone.kid)
        let post = try #require(transport.requests.last)
        #expect(post.url.path == "/v1/business/approve/enrollments/\(enrollmentId.uuidString.lowercased())/confirm")
        let confirmation = try ViadereJSON.decode(ConfirmApprovalEnrollmentRequest.self, from: try #require(post.body)).confirmation
        let parsed = try ApprovalEnrollmentConfirmation.verify(confirmation, confirmationKey: confirmationKey.publicKey)
        #expect(throws: Never.self) { try parsed.checkMatches(statement, signed: signed) }

        // Refusals happen before anything is sent: not ready, wrong customer, wrong business, forged statement, weak key.
        func refuses(_ response: ApprovalEnrollmentView, subject: SubjectRef = Approve.subject, business: BusinessID = Approve.business, minimum: ApprovalAMR = .biometric, _ expected: ApprovalEnrollmentFailure) async throws {
            let t = MockTransport()
            try t.enqueue(status: 200, json: response)
            await #expect(throws: expected) {
                _ = try await Fixtures.client(t).confirmApprovalEnrollment(id: enrollmentId, businessId: business, expectedSubject: subject, confirmationKey: confirmationKey, minimumAssurance: minimum, now: Approve.now)
            }
            #expect(t.requests.count == 1, "only the GET was sent")
        }
        try await refuses(view(.pending, statement: nil), .notReady)
        try await refuses(view(), subject: SubjectRef("sub_" + Base64URL.encode(Data(repeating: 4, count: 32)))!, .bindingMismatch(.wrongSubject))
        try await refuses(view(), business: BusinessID(), .bindingMismatch(.wrongBusiness))
        let other = SoftwareP256SigningKey()
        let otherStatement = try await ApprovalEnrollmentStatement(businessId: Approve.business, subject: Approve.subject, enrollmentId: enrollmentId, publicKey: other.publicKey,
                                                                  hpkePublicKey: phone.hpke.publicKey, assurance: .biometric, createdAt: Approve.now).sign(with: other)
        try await refuses(view(statement: SignedStatement(payload: signed.payload, signature: otherStatement.signature)), .invalidStatement(.badSignature))
        let presence = try ApprovalEnrollmentStatement(businessId: Approve.business, subject: Approve.subject, enrollmentId: enrollmentId, publicKey: phone.key.publicKey, hpkePublicKey: phone.hpke.publicKey,
                                                       assurance: .presence, createdAt: Approve.now)
        try await refuses(view(statement: try await presence.sign(with: phone.key)), .assuranceTooLow)
    }

    @Test func requestsResultsAndFreezesUseTheirEndpoints() async throws {
        let transport = MockTransport()
        let id = "req_0123456789abcdef"
        let view = ApprovalRequestView(requestId: id, subjectRef: Approve.subject, capability: .transactionApprove, status: .pending, protection: .serverVisible, expiresAt: Approve.now, createdAt: Approve.now)
        transport.enqueue(status: 503, raw: "", headers: ["Retry-After": "1"])
        try transport.enqueue(status: 201, json: view)
        try transport.enqueue(status: 200, json: view)
        try transport.enqueue(status: 200, json: ApprovalResultResponse(resultRef: "res_x", requestId: id, result: "a.b.c", kid: "k", decidedAt: Approve.now))
        try transport.enqueue(status: 200, json: [ApprovalKeyView]())
        try transport.enqueue(status: 200, json: FreezeStatus(subjectRef: Approve.subject, frozen: true))
        let client = try Fixtures.client(transport)
        let body = try ApprovalRequestBuilder(businessId: Approve.business).serverVisible(requestId: id, subject: Approve.subject, challenge: BusinessChallenge.value, details: Approve.details)
        _ = try await client.createApprovalRequest(body)
        #expect(transport.requests.count == 2, "request_id makes the create safe to retry: the 503 was retried once")
        _ = try await client.approvalRequest(requestId: id)
        let result = try await client.approvalResult(resultRef: "res_x")
        #expect(result.result == "a.b.c")
        _ = try await client.approvalKeys(subject: Approve.subject)
        #expect(transport.requests[4].url.query == "subject_ref=\(Approve.subject.rawValue)")
        _ = try await client.freezeApprovals(subject: Approve.subject, frozen: true, reason: "fraud review")
        #expect(transport.requests.map { "\($0.method) \($0.url.path)" } == [
            "POST /v1/business/approve/requests", "POST /v1/business/approve/requests", "GET /v1/business/approve/requests/\(id)", "GET /v1/business/approve/results/res_x",
            "GET /v1/business/approve/keys", "POST /v1/business/approve/freeze",
        ])
    }
}

@Suite("Webhook v2 (opaque envelope)")
struct WebhookV2Tests {
    private let secret = WebhookSignature.generateSecret()
    private let now = Approve.now

    private func delivery(_ envelope: WebhookEnvelopeV2, secret: String? = nil, at: Date? = nil) throws -> (headers: [String: String], body: Data) {
        let body = try ViadereJSON.encode(envelope)
        return (["Viadere-Signature": WebhookSignature.header(secret: secret ?? self.secret, body: body, now: at ?? now), "Viadere-Event-Id": envelope.id, "Viadere-Event-Type": envelope.type,
                 "Viadere-Webhook-Version": envelope.version, "Viadere-Delivery-Id": "0f0f0f0f-0000-4000-8000-000000000000", "Viadere-Key-Id": "whk_abcdef12_v3"], body)
    }

    private var envelope: WebhookEnvelopeV2 {
        WebhookEnvelopeV2(id: "evt_0f0f0f0f-0000-4000-8000-000000000000", type: "approve.request.decided", tenantId: "ten_abc", requestId: "req_0123456789abcdef", occurredAt: now, resultRef: "res_abc")
    }

    @Test func aGenuineDeliveryVerifiesAndExposesIdsOnly() throws {
        let verifier = WebhookVerifier(secret: secret, clock: { now })
        let d = try delivery(envelope)
        let verified = try verifier.verifyEnvelope(headers: d.headers, body: d.body)
        #expect(verified.envelope == envelope && verified.keyId == "whk_abcdef12_v3" && verified.deliveryId != nil)
    }

    @Test func tamperingHeadersTimestampsAndMembersAreRefused() throws {
        let verifier = WebhookVerifier(secret: secret, clock: { now })
        let good = try delivery(envelope)
        #expect(throws: WebhookVerificationError.noMatchingSignature) { _ = try WebhookVerifier(secret: "whsec_other", clock: { now }).verifyEnvelope(headers: good.headers, body: good.body) }
        var tampered = good.body
        tampered.append(0x20)
        #expect(throws: WebhookVerificationError.noMatchingSignature) { _ = try verifier.verifyEnvelope(headers: good.headers, body: tampered) }
        let stale = try delivery(envelope, at: now.addingTimeInterval(-1000))
        #expect(throws: WebhookVerificationError.timestampOutsideTolerance) { _ = try verifier.verifyEnvelope(headers: stale.headers, body: stale.body) }
        // A signed body with an extra member (a future format, or an injected field) is not accepted as v2.
        let extra = Data(String(decoding: good.body, as: UTF8.self).replacingOccurrences(of: "{", with: #"{"decision":"approve","#, options: [], range: nil).utf8)
        var headers = good.headers
        headers["Viadere-Signature"] = WebhookSignature.header(secret: secret, body: extra, now: now)
        #expect(throws: WebhookVerificationError.malformedBody) { _ = try verifier.verifyEnvelope(headers: headers, body: extra) }
        // Headers must agree with the signed body.
        var wrongType = good.headers
        wrongType["Viadere-Event-Type"] = "approve.key.revoked"
        #expect(throws: WebhookVerificationError.headerBodyMismatch) { _ = try verifier.verifyEnvelope(headers: wrongType, body: good.body) }
        var wrongId = good.headers
        wrongId["Viadere-Event-Id"] = "evt_other"
        #expect(throws: WebhookVerificationError.headerBodyMismatch) { _ = try verifier.verifyEnvelope(headers: wrongId, body: good.body) }
        var wrongVersion = good.headers
        wrongVersion["Viadere-Webhook-Version"] = "v1"
        #expect(throws: WebhookVerificationError.headerBodyMismatch) { _ = try verifier.verifyEnvelope(headers: wrongVersion, body: good.body) }
        #expect(throws: WebhookVerificationError.missingSignatureHeader) { _ = try verifier.verifyEnvelope(headers: [:], body: good.body) }
    }

    @Test func duplicatesAreDetectedAndTheV1VerifierRejectsAnEnvelope() throws {
        let verifier = WebhookVerifier(secret: secret, clock: { now })
        let d = try delivery(envelope)
        let dedupe = InMemoryWebhookDeduplicator()
        _ = try verifier.verifyEnvelope(headers: d.headers, body: d.body, deduplicator: dedupe)
        #expect(throws: WebhookVerificationError.duplicateEvent) { _ = try verifier.verifyEnvelope(headers: d.headers, body: d.body, deduplicator: dedupe) }
        #expect(throws: WebhookVerificationError.malformedBody) { _ = try verifier.verify(headers: d.headers, body: d.body) }
    }
}
