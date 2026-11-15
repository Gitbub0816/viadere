import Foundation
import Testing
import ViadereCore
@testable import ViadereKit

/// docs/APP-IA.md §9: what a list screen shows while it loads, fails or is empty; the toast copy; and that a confirmation is only ever
/// shown for a change the server kept.
@Suite("Feedback (Kit)")
@MainActor
struct FeedbackTests {
    // MARK: Screen state

    @Test func contentAlwaysWinsOverLoadingAndErrors() {
        #expect(ScreenLoadState.resolve(isLoading: true, isEmpty: false, errorMessage: nil) == .content)
        #expect(ScreenLoadState.resolve(isLoading: false, isEmpty: false, errorMessage: "Couldn't load.") == .content)
    }

    @Test func aFirstLoadShowsThePlaceholderThenTheErrorOrTheEmptyState() {
        #expect(ScreenLoadState.resolve(isLoading: true, isEmpty: true, errorMessage: nil) == .loading)
        // A retry that is running shows the placeholder again, not the old error.
        #expect(ScreenLoadState.resolve(isLoading: true, isEmpty: true, errorMessage: "Couldn't load.") == .loading)
        #expect(ScreenLoadState.resolve(isLoading: false, isEmpty: true, errorMessage: "Couldn't load.") == .failed("Couldn't load."))
        #expect(ScreenLoadState.resolve(isLoading: false, isEmpty: true, errorMessage: nil) == .empty)
        #expect(ScreenLoadState.resolve(isLoading: false, isEmpty: true, errorMessage: "") == .empty)
    }

    // MARK: Copy

    @Test func toastCopyIsOneCalmSentence() {
        let lines = [FeedbackCopy.conversationMuted(true), FeedbackCopy.conversationMuted(false),
                     FeedbackCopy.conversationArchived(true), FeedbackCopy.conversationArchived(false),
                     FeedbackCopy.favorite(true, business: "Harbor Bank"), FeedbackCopy.favorite(false, business: "Harbor Bank"),
                     FeedbackCopy.copied, FeedbackCopy.saved]
        for line in lines {
            #expect(line.hasSuffix("."), "\(line)")
            #expect(!line.contains("!"), "\(line)")
            #expect(line.count <= 48, "\(line)")
        }
        #expect(Set(lines).count == lines.count)
        #expect(FeedbackCopy.favorite(true, business: "Harbor Bank") == "Harbor Bank is a favorite.")
    }

    @Test func noMatchTrimsAndCapsTheQuery() {
        #expect(FeedbackCopy.noMatch("  harbor ", in: "business") == "No business matches \u{201C}harbor\u{201D}.")
        #expect(FeedbackCopy.noMatch("   ", in: "conversation") == "No conversation found.")
        let long = String(repeating: "a", count: 200)
        let line = FeedbackCopy.noMatch(long, in: "setting")
        #expect(line == "No setting matches \u{201C}\(String(repeating: "a", count: FeedbackCopy.maxQueryLength))\u{2026}\u{201D}.")
    }

    // MARK: Confirm only what the server kept

    func world() async -> (AppModel, MockViadereAPI) {
        let api = MockViadereAPI(seed: true)
        let services = await ViadereServices.mock(api: api)
        let model = AppModel(services: services)
        await model.bootstrap()
        return (model, api)
    }

    @Test func mutingAndArchivingReportWhetherTheServerKeptTheChange() async throws {
        let (model, api) = await world()
        await model.messages.load()
        let thread = try #require(model.messages.visible(context: .all).first)
        #expect(await model.messages.setMuted(thread.id, true))
        #expect(model.messages.conversations.first { $0.id == thread.id }?.muted == true)

        await api.setOrganizationOffline(true)
        #expect(await model.messages.setMuted(thread.id, false) == false)
        // Rolled back: still muted, and the screen says why instead of confirming.
        #expect(model.messages.conversations.first { $0.id == thread.id }?.muted == true)
        #expect(model.messages.errorMessage != nil)
        #expect(await model.messages.setArchived(thread.id, true) == false)
        #expect(model.messages.visible(context: .all).contains { $0.id == thread.id })

        await api.setOrganizationOffline(false)
        #expect(await model.messages.setArchived(thread.id, true))
        #expect(model.messages.archived(context: .all).map(\.id) == [thread.id])
        // A thread that is not in the list changes nothing and confirms nothing.
        #expect(await model.messages.setMuted(SessionID(), true) == false)
    }

    @Test func aFavoriteIsConfirmedOnlyWhenSaved() async throws {
        let (model, api) = await world()
        let id = try #require(model.businesses.active.first { !$0.preferences.favorite }?.business.id)
        #expect(await model.businesses.setFavorite(id, true))
        #expect(model.businesses.entry(id)?.preferences.favorite == true)
        await api.setOrganizationOffline(true)
        #expect(await model.businesses.setFavorite(id, false) == false)
        #expect(model.businesses.entry(id)?.preferences.favorite == true)
        #expect(await model.businesses.setFavorite(BusinessID(), true) == false)
    }
}
