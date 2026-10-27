import Testing
import Foundation
import ViadereCore
@testable import ViadereKit

@Suite("Delegation scope policy")
struct DelegationPolicyTests {
    private let now = tuesdayNoon

    private func draft(_ purposes: Set<InteractionPurpose> = [.transactional], role: DelegationGrant.Role = .viewer,
                       businesses: Set<BusinessID> = [PreviewData.juniperCoffee.id], days: Double = 30, name: String = "Sam") -> DelegationDraft {
        DelegationDraft(delegateLabel: name, role: role, purposes: purposes, businessIds: businesses,
                        expiresAt: now.addingTimeInterval(days * 86_400))
    }

    @Test func aBlankDraftGrantsNothingAndIsInvalid() {
        let blank = DelegationDraft.blank(now: now)
        #expect(blank.purposes.isEmpty && blank.businessIds.isEmpty && blank.role == .viewer)
        #expect(DelegationScopePolicy.validate(blank, now: now) == [.missingName, .noPurposes, .noBusinesses])
        #expect(!DelegationScopePolicy.includesSensitiveScope(blank))
    }

    @Test func validationCoversNameScopeAndLifetime() {
        #expect(DelegationScopePolicy.isValid(draft(), now: now))
        #expect(DelegationScopePolicy.validate(draft(name: "   "), now: now) == [.missingName])
        #expect(DelegationScopePolicy.validate(draft(businesses: []), now: now) == [.noBusinesses])
        #expect(DelegationScopePolicy.validate(draft(days: 0.01), now: now) == [.expiresTooSoon])
        #expect(DelegationScopePolicy.validate(draft(days: -3), now: now) == [.expiresTooSoon])
        #expect(DelegationScopePolicy.validate(draft(days: 400), now: now) == [.expiresTooFar(maxDays: 365)])
        #expect(DelegationScopePolicy.isValid(draft(days: 365), now: now))
    }

    @Test func sensitiveScopesNeedStepUpAShortLifetimeAndAWarning() {
        let security = draft([.transactional, .security])
        #expect(DelegationScopePolicy.includesSensitiveScope(security) && DelegationScopePolicy.requiresStepUp(security))
        #expect(DelegationScopePolicy.validate(security, now: now).isEmpty)
        #expect(DelegationScopePolicy.validate(draft([.security], days: 90), now: now) == [.expiresTooFar(maxDays: 30)])
        #expect(DelegationScopePolicy.validate(draft([.accountService], days: 90), now: now) == [.expiresTooFar(maxDays: 30)])
        let ids = DelegationScopePolicy.warnings(security).map(\.id)
        #expect(ids.contains("security") && ids.contains("stepup"))
        let warning = DelegationScopePolicy.warnings(security).first { $0.id == "security" }
        #expect(warning?.severity == .caution)
        #expect(warning?.message.contains("can't approve sign-ins or payments") == true)
        // ordinary access: no step-up, no sensitive warning
        let plain = draft([.transactional, .rewards])
        #expect(!DelegationScopePolicy.requiresStepUp(plain))
        #expect(DelegationScopePolicy.warnings(plain).isEmpty)
    }

    @Test func managersAreWarnedTheyRespondOnYourBehalf() {
        let warnings = DelegationScopePolicy.warnings(draft(role: .manager))
        #expect(warnings.map(\.id) == ["manager"])
        #expect(warnings[0].message.contains("on behalf of you"))
    }

    @Test func marketingConsentCannotBeDelegated() {
        #expect(!DelegationScopePolicy.delegablePurposes.contains(.marketing))
        #expect(DelegationScopePolicy.delegablePurposes.contains(.security))
    }

    @Test func requestsAreCanonicalAndOrderIndependent() {
        let a = DelegationScopePolicy.request(from: draft([.rewards, .transactional], businesses: [PreviewData.juniperCoffee.id, PreviewData.harborHotel.id]))
        let b = DelegationScopePolicy.request(from: draft([.transactional, .rewards], businesses: [PreviewData.harborHotel.id, PreviewData.juniperCoffee.id]))
        #expect(a == b)
        #expect(DelegationScopePolicy.scopeDigest(of: a) == DelegationScopePolicy.scopeDigest(of: b))
        // any change to the scope changes the digest the biometric signature covers
        let wider = DelegationScopePolicy.request(from: draft([.rewards, .transactional, .security], businesses: [PreviewData.juniperCoffee.id, PreviewData.harborHotel.id]))
        #expect(DelegationScopePolicy.scopeDigest(of: wider) != DelegationScopePolicy.scopeDigest(of: a))
        #expect(a.includesSensitiveScope == false && wider.includesSensitiveScope == true)
    }

    @Test func summaryAndAuditCopy() {
        let text = DelegationScopePolicy.summary(purposes: [.rewards, .transactional], businessNames: ["Juniper Coffee", "Harbor Hotel", "Lumen Theater"], expiresAt: tuesdayNoon)
        #expect(text.hasPrefix("Orders and receipts, Rewards · Juniper Coffee and 2 more · until"))
        let entry = HouseholdAuditEntry(occurredAt: now, action: "delegation.used", actorName: "Sam Rivera", businessName: "Juniper Coffee", onBehalfOfName: "Jordan Lee")
        #expect(DelegationScopePolicy.auditTitle(entry) == "Sam Rivera responded at Juniper Coffee on behalf of Jordan Lee")
        let denied = HouseholdAuditEntry(occurredAt: now, action: "delegation.denied", actorName: "Sam Rivera", outcome: .denied)
        #expect(DelegationScopePolicy.auditTitle(denied) == "Sam Rivera was blocked")
    }

    @Test func onBehalfOfLabelsDelegatedInteractionsOnly() {
        let me = PreviewData.consumerId
        let alex = ConsumerID()
        let grant = DelegationGrant(id: DelegationID(), grantorId: alex, delegateId: me, role: .manager, purposes: [.transactional],
                                    businessIds: [PreviewData.lindenDental.id], createdAt: tuesdayNoon, expiresAt: tuesdayNoon.addingTimeInterval(86_400))
        let received = [HouseholdGrant(grant: grant, counterpartName: "Alex Morgan", businessNames: [], status: .active)]
        #expect(DelegationScopePolicy.onBehalfOfName(scopeConsumerId: me, myConsumerId: me, received: received) == nil)
        #expect(DelegationScopePolicy.onBehalfOfName(scopeConsumerId: alex, myConsumerId: me, received: received) == "Alex Morgan")
        #expect(DelegationScopePolicy.onBehalfOfName(scopeConsumerId: ConsumerID(), myConsumerId: me, received: received) == "someone in your household")
        #expect(DelegationScopePolicy.onBehalfOfName(scopeConsumerId: alex, myConsumerId: nil, received: received) == nil)
    }

    @Test func invitationCodesNormalizeWhileTyping() {
        #expect(InvitationCodeInput.normalize("k7m2 9qxp") == "K7M2-9QXP")
        #expect(InvitationCodeInput.normalize("k7m") == "K7M")
        #expect(InvitationCodeInput.normalize("K7M29QXPEXTRA") == "K7M2-9QXP")
        #expect(InvitationCodeInput.normalize("0O1I") == "")   // ambiguous characters aren't in the alphabet
        #expect(InvitationCodeInput.isComplete("K7M2-9QXP") && !InvitationCodeInput.isComplete("K7M2"))
    }
}

@Suite("Household flows")
@MainActor
struct HouseholdFlowTests {
    private func configured(_ model: HouseholdViewModel, purposes: [InteractionPurpose], role: DelegationGrant.Role = .viewer) {
        model.draft.delegateLabel = "Sam"
        model.setRole(role)
        for purpose in purposes { model.togglePurpose(purpose) }
        model.toggleBusiness(PreviewData.juniperCoffee.id)
        model.setLifetime(days: 14)
    }

    @Test func loadsGrantsGivenReceivedAndBusinesses() async throws {
        let (services, _) = await p3World()
        let model = HouseholdViewModel(services: services)
        await model.load()
        #expect(model.phase == .loaded)
        #expect(model.activeGiven.map(\.counterpartName) == ["Sam Rivera"])
        #expect(model.activeReceived.map(\.counterpartName) == ["Alex Morgan"])
        #expect(model.businesses.contains { $0.id == PreviewData.juniperCoffee.id })
    }

    @Test func ordinaryInvitationNeedsNoStepUp() async throws {
        let (services, _) = await p3World()
        let model = HouseholdViewModel(services: services)
        await model.load()
        configured(model, purposes: [.transactional, .rewards])
        #expect(!model.requiresStepUp && model.canCreate)
        await model.createInvitation()
        guard case .created(let invitation) = model.creation else { Issue.record("expected an invitation, got \(model.creation)"); return }
        #expect(invitation.code.count == 9)
        #expect(model.activeGiven.contains { $0.counterpartName == "Sam" && $0.status == .pending })
    }

    @Test func sensitiveInvitationIsSignedWithTheBiometricKeyAndServerVerifiesIt() async throws {
        let (services, _) = await p3World()
        let model = HouseholdViewModel(services: services)
        await model.load()
        configured(model, purposes: [.security])
        #expect(model.requiresStepUp && model.warnings.contains { $0.id == "security" })
        await model.createInvitation()
        guard case .created = model.creation else { Issue.record("expected created, got \(model.creation)"); return }
    }

    @Test func sensitiveInvitationFailsClosedWithoutBiometrics() async throws {
        let (services, _) = await p3World(unsupportedKeys: [.approvalBiometric])
        let model = HouseholdViewModel(services: services)
        await model.load()
        configured(model, purposes: [.security])
        await model.createInvitation()
        #expect(model.creation == .failed(StepUpError.biometricsUnavailable.userMessage))
    }

    @Test func serverRejectsSensitiveScopeWithoutOrWithTamperedProof() async throws {
        let (services, api) = await p3World()
        let draft = DelegationDraft(delegateLabel: "Sam", role: .viewer, purposes: [.security], businessIds: [PreviewData.juniperCoffee.id],
                                    expiresAt: tuesdayNoon.addingTimeInterval(7 * 86_400))
        let request = DelegationScopePolicy.request(from: draft)
        // no proof
        await #expect(throws: APIError.self) { _ = try await api.createDelegationInvitation(request) }
        // proof for a narrower scope, replayed on a wider request
        let narrow = DelegationScopePolicy.request(from: DelegationDraft(delegateLabel: "Sam", role: .viewer, purposes: [.security],
                                                                         businessIds: [PreviewData.harborHotel.id], expiresAt: draft.expiresAt))
        let proof = try await DelegationStepUp(keys: services.keys, records: services.records, clock: services.clock).prove(narrow, delegateLabel: "Sam")
        var tampered = request
        tampered.stepUp = proof
        do {
            _ = try await api.createDelegationInvitation(tampered)
            Issue.record("a proof for a different scope must not be accepted")
        } catch let error as APIError {
            #expect(error.code == .insufficientAssurance)
        }
        // the honest proof works
        var honest = request
        honest.stepUp = try await DelegationStepUp(keys: services.keys, records: services.records, clock: services.clock).prove(request, delegateLabel: "Sam")
        _ = try await api.createDelegationInvitation(honest)
    }

    @Test func staleProofsAreRejected() async throws {
        let (services, api) = await p3World()
        let draft = DelegationDraft(delegateLabel: "Sam", role: .viewer, purposes: [.security], businessIds: [PreviewData.juniperCoffee.id],
                                    expiresAt: tuesdayNoon.addingTimeInterval(7 * 86_400))
        var request = DelegationScopePolicy.request(from: draft)
        let old = DelegationStepUp(keys: services.keys, records: services.records, clock: { tuesdayNoon.addingTimeInterval(-3_600) })
        request.stepUp = try await old.prove(request, delegateLabel: "Sam")
        await #expect(throws: APIError.self) { _ = try await api.createDelegationInvitation(request) }
    }

    @Test func invalidDraftsNeverReachTheServer() async throws {
        let (services, api) = await p3World()
        let model = HouseholdViewModel(services: services)
        await model.load()
        await model.createInvitation()    // blank draft
        guard case .failed(let message) = model.creation else { Issue.record("expected failure"); return }
        #expect(message == DelegationIssue.missingName.message)
        #expect(try await api.household().given.count == 1)
    }

    @Test func sensitivePurposeShortensAnOverlongLifetime() async throws {
        let (services, _) = await p3World()
        let model = HouseholdViewModel(services: services)
        model.setLifetime(days: 365)
        #expect(model.selectedLifetimeDays == 365 && model.lifetimeChoices == [7, 14, 30, 90, 365])
        model.togglePurpose(.security)
        #expect(model.selectedLifetimeDays == 30 && model.lifetimeChoices == [7, 14, 30])
        model.togglePurpose(.marketing)   // not delegable: ignored
        #expect(!model.draft.purposes.contains(.marketing))
    }

    @Test func inviteePreviewsAndAccepts() async throws {
        let (services, _) = await p3World()
        let inviter = HouseholdViewModel(services: services)
        await inviter.load()
        configured(inviter, purposes: [.transactional], role: .manager)
        await inviter.createInvitation()
        guard case .created(let invitation) = inviter.creation else { Issue.record("expected created"); return }

        let invitee = HouseholdViewModel(services: services)
        await invitee.previewInvitation(code: "bad")
        #expect(invitee.acceptance == .failed("Enter the 8-character code."))
        await invitee.previewInvitation(code: "ZZZZ-ZZZZ")
        guard case .failed = invitee.acceptance else { Issue.record("unknown code must fail"); return }
        await invitee.previewInvitation(code: invitation.code)
        guard case .preview(let preview) = invitee.acceptance else { Issue.record("expected preview"); return }
        #expect(preview.role == .manager && preview.purposes == [.transactional] && preview.businessNames == ["Juniper Coffee"])
        await invitee.acceptInvitation(code: invitation.code)
        guard case .accepted = invitee.acceptance else { Issue.record("expected accepted"); return }
        #expect(invitee.activeReceived.count == 2)
        // single use
        await invitee.previewInvitation(code: invitation.code)
        guard case .failed = invitee.acceptance else { Issue.record("a used code must not preview again"); return }
    }

    @Test func revocationEndsAccessAndIsAudited() async throws {
        let (services, _) = await p3World()
        let model = HouseholdViewModel(services: services)
        await model.load()
        let sam = try #require(model.activeGiven.first)
        await model.revoke(sam)
        #expect(model.activeGiven.isEmpty)
        #expect(model.pastGrants.contains { $0.id == sam.id && $0.status == .revoked })
        #expect(model.statusText(try #require(model.pastGrants.first)) == "Ended")
        await model.loadAudit()
        #expect(model.audit.first?.action == "delegation.revoked")
        #expect(model.audit.contains { $0.action == "delegation.denied" && $0.outcome == .denied })
    }

    @Test func delegatedApprovalsAreLabeledOnBehalfOf() async throws {
        let (services, api) = await p3World()
        let household = try await api.household()
        let alex = try #require(household.received.first)
        var envelope = PreviewData.confirm(now: tuesdayNoon, business: PreviewData.lindenDental)
        envelope.interaction.scope.consumerId = alex.grant.grantorId
        await api.add(envelope)
        let record = try await services.records.load()
        let model = ApprovalViewModel(envelope: envelope, device: record, services: services)
        await model.load()
        #expect(model.onBehalfOf == "Alex Morgan")
        #expect(model.details.contains { $0.label == "On behalf of" && $0.value == "Alex Morgan" })
        // the Face ID reason says so too
        #expect(ApprovalPolicy.promptReason(for: envelope, decision: .confirm, onBehalfOf: "Alex Morgan").hasSuffix("on behalf of Alex Morgan"))
        // and your own requests are never labeled
        let mine = PreviewData.confirm(now: tuesdayNoon)
        let own = ApprovalViewModel(envelope: mine, device: record, services: services)
        await own.load()
        #expect(own.onBehalfOf == nil)
    }
}
