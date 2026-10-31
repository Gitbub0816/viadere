import Foundation
import Testing
import ViadereCore
@testable import ViadereKit

@Suite("Notification attachment (WP-2.7)")
struct NotificationBrandAttachmentTests {
    @Test func enrichedRequestsCarryTheApprovedLogoButSecurityRequestsNever() async throws {
        let api = MockViadereAPI(seed: false)
        let confirm = PreviewData.confirm(business: PreviewData.northfield)
        let authorize = PreviewData.authorize(business: PreviewData.northfield)
        await api.add(confirm)
        await api.add(authorize)
        let enricher = NotificationEnricher(api: api)
        let brandAPI = try await BK.served()
        let store = BK.store(api: brandAPI, assets: brandAPI)
        _ = await store.refresh(BK.business)

        let enrichedConfirm = await enricher.enrich(interactionId: confirm.interaction.id)
        #expect(enrichedConfirm.brand?.kind == .confirm)
        let attachment = try #require(enrichedConfirm.brandAttachment(from: store))
        #expect(attachment.slot == .logo)
        #expect(attachment.data == BK.logo)

        let enrichedAuthorize = await enricher.enrich(interactionId: authorize.interaction.id)
        #expect(enrichedAuthorize.brandAttachment(from: store) == nil)
        #expect(NotificationEnricher.fallback(interactionId: confirm.interaction.id).brandAttachment(from: store) == nil)
        #expect(enrichedConfirm.brandAttachment(from: nil) == nil)
    }

    @Test func theLoopCategoryIsRegisteredWithoutActions() throws {
        let loop = try #require(NotificationEnricher.registeredCategorySpecs().first { $0.identifier == "viadere.loop" })
        #expect(loop.actions.isEmpty)
    }
}
