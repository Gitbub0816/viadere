import Fluent
import Foundation
import ViadereCore

/// Pins the Brand Kit chosen at creation to every new interaction (WP-2.4; plan 4.6 "pinning per active interaction"). Implemented as a
/// Fluent model middleware so the interaction pipeline itself is unchanged: after the row is inserted, the kit the selector picks **now**
/// (in the business's schedule time zone, with the customer's daily pool seed) is written to `interactions.brand_kit_pin`. A later schedule
/// change never changes an interaction already in flight. Security requests are never pinned (they are never branded), and any failure is
/// swallowed: branding can never delay or fail a delivery (spec B4.4).
struct BrandPinMiddleware: AsyncModelMiddleware {
    let ctx: ServerContext

    func create(model: InteractionRecord, on db: any Database, next: any AnyAsyncModelResponder) async throws {
        try await next.create(model, on: db)
        guard let id = model.id, let purpose = InteractionPurpose(rawValue: model.purpose) else { return }
        guard let kit = await BrandKitService(db: db, ctx: ctx).pin(businessId: model.businessId, consumerId: model.consumerId, purpose: purpose,
                                                                     kind: InteractionKind(rawValue: model.kind)) else { return }
        do {
            try await InteractionBrandPinRecord.query(on: db).filter(\.$id == id).set(\.$brandKitPin, to: kit).update()
        } catch {
            ctx.logger.warning("brand pin not stored", metadata: ["type": "\(type(of: error))"])
        }
    }
}
