import Foundation
import Testing
import ViadereCore
@testable import ViadereKit

@Suite("Customer profiles (Kit)")
@MainActor
struct ProfileKitTests {
    let now = Date(timeIntervalSince1970: 1_800_000_000)

    func summary(_ name: String) -> BusinessSummary {
        BusinessSummary(id: BusinessID(), displayName: name, handle: nil, code: BusinessCode.generate(), verificationStatus: .verified)
    }

    @Test func publicNamePreviewFollowsTheDraftAndRejectsImpersonation() async throws {
        let api = MockProfileAPI(accountName: "Jane Doe")
        let model = ProfileEditorViewModel(api: api)
        await model.load()
        #expect(model.publicNamePreview == "Jane D.")
        model.publicNameDraft = "  Jay   D "
        #expect(model.publicNamePreview == "Jay D")
        #expect(model.publicNameIssue == nil)
        model.publicNameDraft = "Viadere Support"
        #expect(model.publicNameIssue != nil)
        #expect(await model.savePublicName() == false)
        model.publicNameDraft = "Ja\u{202E}ne"
        #expect(model.publicNameIssue != nil)
        model.publicNameDraft = "Jay D"
        #expect(await model.savePublicName())
        #expect(model.profile.publicName == "Jay D")
        model.publicNameDraft = ""
        #expect(await model.savePublicName())
        #expect(model.profile.publicName == "Jane D.")
    }

    @Test func fieldsAreValidatedLocallyAndGroupedByCategory() async throws {
        let api = MockProfileAPI(accountName: "Jane Doe")
        let model = ProfileEditorViewModel(api: api)
        #expect(!model.categories.contains { $0.category == .verified })
        #expect(model.categories.allSatisfy { $0.fields.allSatisfy { !$0.isDerived } })
        #expect(model.issue(key: "home.access_notes", entry: nil, value: .text("SSN 123-45-6789")) == ProfileRules.text(for: .forbiddenIdentifier))
        #expect(await model.set(key: "contact.email", value: .text("not an email")) == false)
        #expect(await model.set(key: "contact.email", value: .text("Jane@Example.com")))
        #expect(model.entries(for: "contact.email").first?.value == .text("jane@example.com"))
        #expect(await model.set(key: "travel.frequent_flyer", entry: "ua", value: .text("ab1234")))
        #expect(model.entries(for: "travel.frequent_flyer").first?.entry == "UA")
        #expect(await model.remove(key: "contact.email"))
        #expect(model.entries(for: "contact.email").isEmpty)
    }

    @Test func accessPageTogglesWithinAllowedCategoriesAndRevokesAll() async throws {
        let api = MockProfileAPI(accountName: "Jane Doe")
        let business = BusinessID()
        await api.connect(business, name: "Northwind Air", allowed: [.contact])
        _ = try await api.updateProfile(ProfileUpdateRequest(set: [ProfileFieldEntry(key: "contact.email", value: .text("a@b.co"))]))
        let model = BusinessProfileAccessViewModel(api: api, business: business)
        await model.load()
        #expect(model.groups.map(\.category) == [.contact])
        #expect(model.view?.publicName == "Jane D.")
        #expect(!model.canToggle("travel.frequent_flyer"))
        model.toggle("travel.frequent_flyer")
        #expect(!model.isOn("travel.frequent_flyer"))
        model.toggle("contact.email")
        #expect(model.hasChanges)
        #expect(await model.save())
        #expect(model.sharesAnything)
        #expect(!model.hasChanges)
        #expect(await model.revokeAll())
        #expect(!model.sharesAnything)
        let receipts = ProfileReceiptsViewModel(api: api)
        await receipts.load()
        #expect(receipts.receipts.map(\.action) == [.revoked, .granted])
        #expect(ProfileReceiptsViewModel.summary(receipts.receipts[0]) == "Stopped sharing Email")
    }

    @Test func requestApprovalIsFieldByFieldWithNothingPreselectedAndASanitizedPurpose() async throws {
        let api = MockProfileAPI(accountName: "Jane Doe", now: now)
        let business = summary("Northwind Air")
        await api.connect(business.id, name: business.displayName, allowed: [.contact, .travel])
        let prompt = ProfileRequestPrompt(id: ProfileRequestID(), business: business, purpose: "To credit\u{202E} your\nmiles",
                                          fields: [ProfileRequestedField(key: "contact.email", hasValue: true, alreadyGranted: false),
                                                   ProfileRequestedField(key: "travel.frequent_flyer", hasValue: true, alreadyGranted: false),
                                                   ProfileRequestedField(key: "contact.phone", hasValue: false, alreadyGranted: false)],
                                          status: .pending, approvedKeys: nil, createdAt: now, expiresAt: now.addingTimeInterval(3600))
        await api.addRequest(prompt)
        let clock = now
        let model = ProfileRequestViewModel(api: api, prompt: prompt, clock: { clock })
        #expect(model.purpose == "To credit your miles")
        #expect(model.selected.isEmpty)
        model.toggle("contact.phone")
        #expect(model.selected.isEmpty)
        model.toggle("travel.frequent_flyer")
        #expect(await model.approveSelected())
        #expect(model.prompt.status == .answered)
        #expect(model.prompt.approvedKeys == ["travel.frequent_flyer"])
        #expect(await model.decline() == false)
    }

    @Test func anExpiredRequestCannotBeAnswered() async throws {
        let api = MockProfileAPI(now: now)
        let prompt = ProfileRequestPrompt(id: ProfileRequestID(), business: summary("Old Shop"), purpose: "x", fields: [], status: .pending, approvedKeys: nil,
                                          createdAt: now.addingTimeInterval(-7200), expiresAt: now.addingTimeInterval(-1))
        let clock = now
        let model = ProfileRequestViewModel(api: api, prompt: prompt, clock: { clock })
        #expect(!model.isActionable)
        #expect(await model.decline() == false)
        #expect(model.errorMessage == "This request has expired.")
    }

    @Test func verificationEntryShowsTheBadgeOnceVerified() async throws {
        let api = MockProfileAPI(accountName: "Jane Doe")
        let verify = ProfileVerificationViewModel(api: api)
        verify.keep = []
        #expect(!verify.canBegin)
        verify.keep = [.identity, .ageOver21]
        await verify.begin(.wallet)
        guard case .started(let start) = verify.phase else { Issue.record("not started"); return }
        #expect(start.nonce != nil)
        await verify.complete(envelope: "ZW52")
        #expect(verify.phase == .finished(.verified))
        let editor = ProfileEditorViewModel(api: api)
        await editor.load()
        #expect(editor.isVerified)
        await editor.removeVerification()
        #expect(!editor.isVerified)
    }

    @Test func liveRoutesUseTheCatalog() {
        #expect(APIRoutes.profileAccessPut.template == "/v1/businesses/{businessId}/profile-access")
        #expect(APIRoutes.profileRequestAnswer.method == .POST)
    }
}
