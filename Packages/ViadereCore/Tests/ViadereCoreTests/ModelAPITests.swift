import Foundation
import Testing
@testable import ViadereCore

@Suite("Models")
struct ModelTests {
    let now = Fixtures.now

    @Test("Revoking marketing never disables essential security notices (spec §19 #10)")
    func consent() {
        let base = ConsentGrant(id: ConsentGrantID(), consumerId: ConsumerID(), businessId: BusinessID(), relationshipId: RelationshipID(),
                                purpose: .marketing, granted: true, version: 1, policyVersion: "v1", source: .app,
                                channels: [.nativePush], createdAt: now, updatedAt: now)
        var revoked = base
        revoked.version = 2
        revoked.granted = false
        let grants = [base, revoked]
        #expect(!ConsentPolicy.permits(purpose: .marketing, grants: grants))
        #expect(ConsentPolicy.permits(purpose: .security, grants: grants))
        #expect(ConsentPolicy.permits(purpose: .accountService, grants: grants))
        #expect(ConsentPolicy.permits(purpose: .transactional, grants: grants))
        #expect(!ConsentPolicy.permits(purpose: .rewards, grants: []))
        #expect(ConsentPolicy.permits(purpose: .marketing, grants: [base]))
        var revokeSecurity = base
        revokeSecurity.purpose = .security
        revokeSecurity.granted = false
        #expect(ConsentPolicy.permits(purpose: .security, grants: [revokeSecurity]))
    }

    @Test("Live Activities only for ongoing non-marketing events (spec §19 #6)")
    func liveActivity() throws {
        let delivery = LiveActivityStatus.delivery(DeliveryActivityState(trackingReference: "1Z", stage: .outForDelivery, stopsAway: 3))
        let flight = LiveActivityStatus.flight(FlightActivityState(flightNumber: "SK12", departureAirport: "PHX", arrivalAirport: "SFO",
                                                                   stage: .boarding, scheduledDeparture: now, gate: "B4"))
        #expect(LiveActivityPolicy.isEligible(purpose: .transactional, status: delivery))
        #expect(LiveActivityPolicy.isEligible(purpose: .transactional, status: flight))
        #expect(!LiveActivityPolicy.isEligible(purpose: .marketing, status: delivery))
        #expect(!LiveActivityPolicy.isEligible(purpose: .transactional, status: nil))
        let data = try ViadereJSON.encode(flight)
        #expect(String(decoding: data, as: UTF8.self).hasPrefix(#"{"flight":{"#))
        #expect(try ViadereJSON.decode(LiveActivityStatus.self, from: data) == flight)
        #expect(LiveActivityStatus.delivery(DeliveryActivityState(trackingReference: "1Z", stage: .delivered)).isTerminal)
    }

    @Test func rewardRecurrence() {
        // 2027-01-15 is a Friday; Tuesdays-only reward.
        let r = RewardRecurrence(weekdays: [2], timeZone: "America/Phoenix")
        #expect(!r.isEligible(on: now))
        #expect(r.isEligible(on: now.addingTimeInterval(4 * 86_400)))
        let reward = Reward(id: RewardID(), business: Fixtures.walmart, title: "Free coffee", status: .available, recurrence: r)
        #expect(!reward.isRedeemable(at: now))
        #expect(reward.isRedeemable(at: now.addingTimeInterval(4 * 86_400)))
    }

    @Test func deviceAssuranceFromKeys() {
        let k = SoftwareP256SigningKey().publicKey
        let keys = [DeviceKey(id: DeviceKeyID(), purpose: .request, publicKey: k, hardwareBacked: true, createdAt: now),
                    DeviceKey(id: DeviceKeyID(), purpose: .approvalBiometric, publicKey: k, hardwareBacked: true, createdAt: now)]
        let d = Device(id: DeviceID(), consumerId: ConsumerID(), name: "iPhone", platform: .iOS, keys: keys, createdAt: now)
        #expect(d.maxAssurance == .biometric)
        #expect(d.key(for: .approvalBiometric) != nil)
        #expect(!d.isRevoked)
    }

    @Test func delegation() {
        let biz = BusinessID()
        let g = DelegationGrant(id: DelegationID(), grantorId: ConsumerID(), delegateId: ConsumerID(), role: .viewer,
                                purposes: [.transactional], businessIds: [biz], createdAt: now, expiresAt: now.addingTimeInterval(86_400))
        #expect(g.isValid)
        #expect(g.permits(purpose: .transactional, businessId: biz, now: now))
        #expect(!g.permits(purpose: .security, businessId: biz, now: now))
        #expect(!g.permits(purpose: .transactional, businessId: BusinessID(), now: now))
        #expect(!g.permits(purpose: .transactional, businessId: biz, now: now.addingTimeInterval(86_401)))
    }

    @Test func primitives() throws {
        let p = try #require(PhoneNumber("+1 (480) 555-0123"))
        #expect(p.e164 == "+14805550123")
        #expect(p.masked == "+1••••••0123")
        #expect(PhoneNumber("4805550123") == nil)
        #expect(PhoneNumber("+0123456789") == nil)
        #expect(BrandColor("c9a96e")?.hex == "#C9A96E")
        #expect(BrandColor("#zzzzzz") == nil)
        let err = APIErrorResponse(code: .insufficientAssurance, message: "Use Face ID")
        let data = try ViadereJSON.encode(err)
        #expect(String(decoding: data, as: UTF8.self) == #"{"error":{"code":"insufficient_assurance","message":"Use Face ID"}}"#)
        let unknown = try ViadereJSON.decode(APIErrorResponse.self, from: Data(#"{"error":{"code":"teapot","message":"x"}}"#.utf8))
        #expect(unknown.error.code == .unknown)
    }

    @Test("Shared DTOs round-trip through ViadereJSON")
    func dtoRoundTrips() throws {
        let profile = BusinessProfile(id: BusinessID(), displayName: "Sky Air", handle: BusinessHandle(parsing: "skyair"),
                                      code: try BusinessCode("SK1234"), verificationStatus: .verified, verifiedAt: now,
                                      category: .airline, brandColor: BrandColor("#112233"))
        #expect(try ViadereJSON.decode(BusinessProfile.self, from: ViadereJSON.encode(profile)) == profile)
        let message = ConversationMessage(id: MessageID(), sessionId: SessionID(), businessId: profile.id, direction: .businessToConsumer,
                                          attribution: MessageAttribution(senderType: .business, displayName: "Sky Air"),
                                          body: "Hi", channel: .sms, createdAt: now, deliveryStatus: .delivered)
        #expect(try ViadereJSON.decode(ConversationMessage.self, from: ViadereJSON.encode(message)) == message)
        let issue = IssueInteractionRequest(relationshipId: RelationshipID(), purpose: .security,
                                            payload: .authorize(Fixtures.mesaAuthorize), sensitivity: .high, ttlSeconds: 120,
                                            idempotencyKey: "k1")
        let decoded = try ViadereJSON.decode(IssueInteractionRequest.self, from: ViadereJSON.encode(issue))
        #expect(decoded == issue)
        let interaction = decoded.makeInteraction(businessId: profile.id, consumerId: ConsumerID(), now: now)
        #expect(interaction.kind == .authorize)
        #expect(InteractionValidation.issues(in: interaction, now: now).isEmpty)
        let event = try WebhookEvent(type: .interactionDecided, createdAt: now, businessId: profile.id,
                                     payload: InteractionOutcome(interactionId: interaction.id, businessId: profile.id, status: .approved,
                                                                 decision: .approve, assurance: .biometric, decidedAt: now))
        let roundTripped = try ViadereJSON.decode(WebhookEvent.self, from: ViadereJSON.encode(event))
        #expect(try roundTripped.decodeData(InteractionOutcome.self).status == .approved)
        #expect(InteractionStatus(decision: .report) == .reported)
    }

    @Test func directoryInputClassification() {
        #expect(DirectoryInput(parsing: "@Amazon") == .handle(BusinessHandle(parsing: "amazon")!))
        #expect(DirectoryInput(parsing: "io-3456") == .code(BusinessCode(parsing: "103456")!))
        #expect(DirectoryInput(parsing: "https://viadere.com/c/AF2345") == .link(ConnectLink(code: BusinessCode(parsing: "AF2345")!)))
        #expect(DirectoryInput(parsing: "Amazon") == .name("Amazon"))
        #expect(DirectoryInput(parsing: "https://evil.com/c/AF2345") == .name("https://evil.com/c/AF2345"))
    }
}

@Suite("API routes")
struct APIRouteTests {
    @Test("No two endpoints share method + path template; names are unique")
    func unique() {
        let keys = APIRoutes.all.map { "\($0.method.rawValue) \($0.template)" }
        #expect(Set(keys).count == keys.count)
        #expect(Set(APIRoutes.all.map(\.name)).count == APIRoutes.all.count)
        #expect(APIRoutes.all.allSatisfy { $0.template.hasPrefix("/v1/") })
    }

    @Test func pathBuilding() throws {
        let id = InteractionID()
        #expect(try APIRoutes.interactionDecide.path(["interactionId": id.description]) == "/v1/interactions/\(id)/decision")
        #expect(try APIRoutes.directorySearch.path(query: [("q", "bean coffee & co"), ("limit", "5")])
                == "/v1/directory/search?q=bean%20coffee%20%26%20co&limit=5")
        #expect(try APIRoutes.directoryHandle.path(["handle": "../admin"]) == "/v1/directory/handles/..%2Fadmin")
        #expect(throws: EndpointError.missingParameter("interactionId")) { try APIRoutes.interactionGet.path() }
        #expect(APIRoutes.interactionDecide.descriptor.vaporPathComponents == ["v1", "interactions", ":interactionId", "decision"])
        #expect(APIRoutes.interactionDecide.auth == .deviceSignedBearer)
        #expect(APIRoutes.businessIssueInteraction.auth == .businessAPIKey)
        #expect(APIRoutes.providerSMSInbound.auth == .providerSignature)
        #expect(APIRoutes.registerBegin.auth == .none)
    }

    @Test("Spec-required endpoints exist", arguments: [
        "auth.register.begin", "auth.register.finish", "auth.login.begin", "auth.login.finish", "devices.enroll", "devices.list",
        "devices.revoke", "phoneLinks.start", "phoneLinks.verify", "directory.search", "directory.resolve", "directory.handle",
        "directory.code", "relationships.connect", "relationships.list", "relationships.disconnect", "consents.get",
        "consents.update", "interactions.list", "interactions.get", "interactions.decide", "conversations.list",
        "conversations.messages", "conversations.send", "rewards.list", "rewards.redeem", "wallet.pass", "liveActivities.token",
        "push.apnsToken", "sms.linkTokens.redeem", "business.interactions.issue", "business.messages.send",
        "business.statuses.update", "business.rewards.issue", "business.webhooks.create", "business.webhooks.list",
        "business.webhooks.delete", "business.interactions.outcome", "providers.sms.inbound", "delegations.create",
    ])
    func exists(name: String) {
        #expect(APIRoutes.all.contains { $0.name == name })
    }
}
