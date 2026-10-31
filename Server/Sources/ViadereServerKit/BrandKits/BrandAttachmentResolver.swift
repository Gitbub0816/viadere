import Fluent
import Foundation
import ViadereCore

/// The server half of WP-2.7: which image a notification may attach for an interaction (`BrandSurfacePolicy.notificationAttachment`), as a
/// URL on the dedicated asset host. Only the approved `logo` (else `mark`) of the kit selected for this customer now, never business art,
/// and nothing at all for security requests, unknown kinds, a stopped or banned business, or without an asset host. The push builder may
/// call it; the notification service extension re-applies the same Core policy and checks the image hash before showing it.
struct BrandAttachmentResolver {
    let db: any Database
    let ctx: ServerContext

    func attachmentURL(businessId: UUID, consumerId: UUID, purpose: InteractionPurpose, kind: InteractionKind) async throws -> URL? {
        guard BrandSurfacePolicy.allowsBranding(purpose: purpose, kind: kind), let host = ctx.config.brandKits.assetDomain?.host else { return nil }
        let service = BrandKitService(db: db, ctx: ctx)
        guard let kitId = await service.pin(businessId: businessId, consumerId: consumerId, purpose: purpose, kind: kind),
              let kit = try await service.activeManifest(businessId: businessId)?.kit(kitId),
              let (_, asset) = BrandSurfacePolicy.notificationAttachment(kit: kit, purpose: purpose, kind: kind) else { return nil }
        return asset.url(assetHost: host)
    }
}
