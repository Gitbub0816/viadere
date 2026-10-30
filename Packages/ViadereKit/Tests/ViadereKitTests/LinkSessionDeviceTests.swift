import Crypto
import Foundation
import Testing
import ViadereCore
@testable import ViadereKit

#if DEBUG

/// The relay's link-session endpoints, backed by the `FakeRelay` business (its key directory and confirmation key) and Viadere's descriptor key.
actor FakeLinkServer: LinkSessionAPI {
    let relay: FakeRelay
    let viadere = SoftwareP256SigningKey()
    let sessionId = UUID()
    var capabilities: [Capability] = [.messageSend]
    var rootKid: String?
    var signer: SoftwareP256SigningKey?
    var lyingName: String?
    var completed: CompleteLinkSessionRequest?
    var confirmation: BusinessSignedStatement?
    var status: LinkSessionStatus = .open

    init(relay: FakeRelay) { self.relay = relay }

    func set(capabilities: [Capability]) { self.capabilities = capabilities }
    func set(rootKid: String) { self.rootKid = rootKid }
    func set(signer: SoftwareP256SigningKey) { self.signer = signer }
    func set(lyingName: String) { self.lyingName = lyingName }

    func lookupLink(code: String) async throws -> LinkSessionOffer {
        let now = relay.now
        let key = signer ?? viadere
        let kid = KeyIdentifier.make(try key.publicKey.signingKey())
        let relayRoot = await relay.rootKid
        let descriptor = LinkSessionDescriptor(sessionId: sessionId, businessId: relay.businessId, businessName: "Harbor Bank", businessDomain: "harbor.example",
                                               rootKid: rootKid ?? relayRoot, capabilities: capabilities, displayHint: "Account ending 4821",
                                               subject: relay.subject, issuedAt: now, expiresAt: now.addingTimeInterval(300))
        let signed = try await SignedStatement.sign(descriptor.object(signerKid: kid), domain: LinkDomainSeparator.descriptor, with: key)
        var business = relay.summary
        if let lyingName { business.displayName = lyingName }
        return LinkSessionOffer(sessionId: sessionId, descriptor: ViadereSignedStatement(kid: kid, payload: signed.payload, signature: signed.signature),
                                business: business, subjectRef: relay.subject, capabilities: capabilities, requiredAssurance: LinkCapabilities.requiredAssurance(capabilities),
                                expiresAt: now.addingTimeInterval(300), alreadyConnected: false)
    }

    func completeLink(id: UUID, request: CompleteLinkSessionRequest) async throws -> LinkSessionDeviceView {
        completed = request
        status = .deviceCompleted
        return view()
    }

    func linkSession(id: UUID) async throws -> LinkSessionDeviceView { view() }

    /// The business confirms what it received (honest), or a statement of the relay's (substituted).
    func businessConfirms(substitute: Bool = false) async throws {
        guard var signed = completed?.statement else { return }
        if substitute {
            let key = SoftwareP256SigningKey()
            let honest = try LinkStatement.verify(signed)
            signed = try await LinkStatement(sessionId: honest.sessionId, businessId: honest.businessId, subject: honest.subject, capabilities: honest.capabilities,
                                             descriptorDigest: honest.descriptorDigest, publicKey: key.publicKey, approvalStatement: nil, createdAt: relay.now).sign(with: key)
        }
        let statement = try LinkStatement.verify(signed)
        confirmation = try await LinkConfirmation(confirming: statement, signed: signed, verification: .sasTyped, at: relay.now).sign(with: await relay.confirmationKey)
        status = .confirmed
    }

    private func view() -> LinkSessionDeviceView {
        let now = relay.now
        return LinkSessionDeviceView(sessionId: sessionId, status: status, business: relay.summary, subjectRef: relay.subject, capabilities: capabilities,
                                     expiresAt: now.addingTimeInterval(300), confirmBy: now.addingTimeInterval(600), confirmation: confirmation, connection: nil,
                                     alert: AlertDescriptor(eventId: AlertDescriptor.eventId(kind: "link_session", id: sessionId), category: .linkConfirmation,
                                                            businessId: relay.businessId, urgency: .timeSensitive, status: .pending, expiresAt: now.addingTimeInterval(600),
                                                            action: ActionRegistry.linkConnect.id, now: now))
    }
}

@Suite("Link sessions on the device (WP-C1)")
struct LinkSessionDeviceTests {
    func setUp(pinned: Bool = true) async throws -> (FakeRelay, FakeLinkServer, LinkSessionFlow, ApproveEnvironment) {
        let relay = try await makeRelay()
        let server = FakeLinkServer(relay: relay)
        let secrets = InMemorySecretStore()
        let now = relay.now
        let environment = ApproveEnvironment(api: relay, vault: SoftwareApprovalKeyVault(), store: SecretApproveLocalStore(secrets: secrets), logKeys: [await relay.logPublicKey],
                                             keys: SoftwareDeviceKeyStore(secrets: secrets), records: SecretDeviceRecordStore(secrets: secrets), clock: { now })
        let flow = environment.linkFlow(api: server, descriptorKeys: pinned ? [server.viadere.publicKey] : [], secrets: secrets, clock: { now })
        return (relay, server, flow, environment)
    }

    @Test func aDescriptorFromANonPublishedKeyIsRejectedOnTheDevice() async throws {
        let (_, server, flow, _) = try await setUp()
        await server.set(signer: SoftwareP256SigningKey())
        await #expect(throws: LinkError.descriptorInvalid(.untrustedSigner)) { _ = try await flow.lookup(code: "K7QFM2XA", secret: LinkSessionSecret()) }
    }

    @Test func withoutPinnedKeysLinkingIsClosed() async throws {
        let (_, _, flow, _) = try await setUp(pinned: false)
        #expect(!flow.isConfigured)
        await #expect(throws: LinkError.notConfigured) { _ = try await flow.lookup(code: "K7QFM2XA", secret: LinkSessionSecret()) }
    }

    @Test func withoutTheSecretOrTheCheckCodeNothingIsLooked() async throws {
        let (_, _, flow, _) = try await setUp()
        await #expect(throws: LinkError.secretRequired) { _ = try await flow.lookup(code: "K7QFM2XA") }
    }

    @Test func theDescriptorIsCrossCheckedAgainstTheDirectoryAndTheRelaysWords() async throws {
        let (_, server, flow, _) = try await setUp()
        // A root the business's log does not show (a spoofed business).
        await server.set(rootKid: KeyIdentifier.make(try SoftwareP256SigningKey().publicKey.signingKey()))
        await #expect(throws: LinkError.businessMismatch) { _ = try await flow.lookup(code: "K7QFM2XA", secret: LinkSessionSecret()) }
        // The relay's unsigned label disagreeing with the signed descriptor is not shown, it is refused.
        let (_, server2, flow2, _) = try await setUp()
        await server2.set(lyingName: "Harbour Bank Security")
        let offer = try await flow2.lookup(code: "K7QFM2XA", secret: LinkSessionSecret())
        #expect(offer.businessName == "Harbor Bank", "only the descriptor's name is shown")
        #expect(offer.warning.contains("harbor.example"))
    }

    @Test func linkingSendsTheTagShowsTheSASAndActivatesOnTheBusinessesConfirmation() async throws {
        let (_, server, flow, _) = try await setUp()
        let secret = LinkSessionSecret()
        let offer = try await flow.lookup(code: "K7QFM2XA", secret: secret)
        let completion = try await flow.link(offer)
        let sent = try #require(await server.completed)
        #expect(sent.bindingTag == secret.bindingTag(for: sent.statement))
        #expect(completion.sas == secret.expectedSAS(for: sent.statement), "the phone shows what the business computes")
        #expect(completion.pseudonym == offer.pseudonym)
        #expect(try await flow.refresh(sessionId: completion.sessionId) == .waiting)
        try await server.businessConfirms()
        #expect(try await flow.refresh(sessionId: completion.sessionId) == .linked)
        #expect(try await flow.pending().isEmpty)
    }

    @Test func aConfirmationOfAnotherStatementIsASubstitution() async throws {
        let (_, server, flow, _) = try await setUp()
        let completion = try await flow.link(try await flow.lookup(code: "K7QFM2XA", secret: LinkSessionSecret()))
        try await server.businessConfirms(substitute: true)
        #expect(try await flow.refresh(sessionId: completion.sessionId) == .substitutionDetected)
    }

    @Test func approvalCapabilitiesCreateAPendingPairwiseKeyBoundToTheSession() async throws {
        let (_, server, flow, environment) = try await setUp()
        await server.set(capabilities: [.transactionApprove, .messageSend])
        let offer = try await flow.lookup(code: "K7QFM2XA", checkCode: LinkSessionSecret().checkCode)
        #expect(offer.requiredAssurance == .biometric)
        let completion = try await flow.link(offer)
        let sent = try #require(await server.completed)
        #expect(sent.bindingTag == nil, "typed path: no secret, no tag")
        #expect(completion.sas != nil)
        let approval = try ApprovalEnrollmentStatement.verify(try #require(sent.approvalStatement))
        #expect(approval.enrollmentId == completion.sessionId)
        let statement = try LinkStatement.verify(sent.statement)
        #expect(try statement.checkApprovalStatement(sent.approvalStatement)?.kid == approval.kid)
        let key = try #require(try await environment.store.load().keys.first { $0.enrollmentId == completion.sessionId })
        #expect(key.status == .pendingConfirmation)
        #expect(try await environment.vault.approvalKey(enrollment: completion.sessionId) != nil)
    }

    @Test func theCompletionCarriesAnAppAttestAssertionOverTheStatement() async throws {
        let relay = try await makeRelay()
        let server = FakeLinkServer(relay: relay)
        let secrets = InMemorySecretStore()
        let now = relay.now
        let records = SecretDeviceRecordStore(secrets: secrets)
        try await records.save(DeviceRecord(deviceId: DeviceID(), consumerId: ConsumerID(), name: "iPhone", purposes: [.request], enrolledAt: now, appAttestKeyId: "attest-key"))
        let attest = MockAppAttest()
        let environment = ApproveEnvironment(api: relay, vault: SoftwareApprovalKeyVault(), store: SecretApproveLocalStore(secrets: secrets), logKeys: [await relay.logPublicKey],
                                             keys: SoftwareDeviceKeyStore(secrets: secrets), records: records, clock: { now })
        let flow = environment.linkFlow(api: server, descriptorKeys: [server.viadere.publicKey], secrets: secrets,
                                        assertion: DeviceAssertions(provider: attest, records: records).source, clock: { now })
        _ = try await flow.link(try await flow.lookup(code: "K7QFM2XA", secret: LinkSessionSecret()))
        let sent = try #require(await server.completed)
        let expected = Data(SHA256.hash(data: LinkAppAttest.clientData(sessionId: server.sessionId, statement: sent.statement)))
        #expect(attest.asserted.first?.keyId == "attest-key")
        #expect(attest.asserted.first?.clientDataHash == expected)
        #expect(sent.appAttestAssertion != nil)
    }
}

@Suite("Approve v2 enrollment over HTTP")
struct ApproveAPIWireTests {
    /// Exploit (before the fix): `LiveApproveAPI.completeEnrollment` dropped the binding tag, so a QR enrollment reached the business without the
    /// proof that the statement came from the phone that opened the link, and the business could not confirm it without falling back to the SAS.
    @Test func theBindingTagReachesTheRelay() async throws {
        let env = try await ClientEnv()
        let transport = FakeTransport { _, _ in
            let key = ApproveKey(kid: String(repeating: "A", count: 43), enrollmentId: UUID(), business: PreviewData.harborBank, relationshipId: RelationshipID(),
                                 subjectRef: SubjectRef("sub_" + Base64URL.encode(Data(repeating: 7, count: 32)))!, deviceId: DeviceID(), status: .pending, assurance: .biometric,
                                 createdAt: Date(), activatedAt: nil, revokedAt: nil, revokedBy: nil, statement: SignedStatement(payload: "e30", signature: "AA"), confirmation: nil)
            return HTTPResponse(status: 201, headers: [:], body: try ViadereJSON.encode(key))
        }
        let (client, _) = env.client(transport: transport)
        let api = LiveApproveAPI(client: client)
        _ = try await api.completeEnrollment(id: UUID(), statement: SignedStatement(payload: "e30", signature: "AA"), bindingTag: "tag-tag-tag")
        let body = try ViadereJSON.decode(CompleteApproveEnrollmentRequest.self, from: try #require(transport.requests.first?.body))
        #expect(body.bindingTag == "tag-tag-tag")
    }
}

@Suite("Link-session deep links")
struct LinkSessionRoutingTests {
    @Test func theLinkSessionURLIsRoutedStrictly() throws {
        let secret = LinkSessionSecret()
        #expect(DeepLinkRouter.route("https://viadere.com/k/K7QFM2XA#es=\(secret.base64URL)") == .linkSession(code: "K7QFM2XA", secret: secret))
        #expect(DeepLinkRouter.route("https://viadere.com/k/K7QFM2XA") == .linkSession(code: "K7QFM2XA", secret: nil))
        for bad in ["https://viadere.com/k/K7QFM2XA?x=1", "https://www.viadere.com/k/K7QFM2XA", "https://viadere.com/k/k7qfm2xa", "https://viadere.com/k/K7QFM2XA#es=x",
                    "https://evil.example/k/K7QFM2XA", "viadere://k/K7QFM2XA"] {
            #expect(DeepLinkRouter.route(bad) == nil, "\(bad)")
        }
    }
}

#endif
