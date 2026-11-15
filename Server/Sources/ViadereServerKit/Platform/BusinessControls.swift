import Fluent
import Foundation
import ViadereCore

/// Restrictions applied to a business by Viadere (operators) or by the abuse thresholds. Controls only ever
/// *restrict*: they can throttle volume or lower the priority ceiling, never raise either. The billing tier
/// appears nowhere in this file — payment cannot change priority or bypass consent (Trust Engine invariant).
enum BusinessControls {
    static let allowedCeilings: [InteractionPriority] = [.low, .normal, .high]

    static func load(_ businessId: UUID, on db: any Database) async throws -> BusinessControlRecord? {
        try await BusinessControlRecord.query(on: db).filter(\.$businessId == businessId).first()
    }

    static func loadOrCreate(_ businessId: UUID, now: Date, on db: any Database) async throws -> BusinessControlRecord {
        if let existing = try await load(businessId, on: db) { return existing }
        let record = BusinessControlRecord()
        record.id = UUID()
        record.businessId = businessId
        record.throttled = false
        record.updatedAt = now
        do {
            try await record.create(on: db)
            return record
        } catch {
            if error.isConstraintViolation, let existing = try await load(businessId, on: db) { return existing }
            throw error
        }
    }

    /// Multiplier for daily quota and API rate while throttled (1 when not).
    static func throttleFactor(_ controls: BusinessControlRecord?, settings: AbuseThresholds) -> Double {
        controls?.throttled == true ? settings.throttleFactor : 1
    }

    /// Lowers (never raises) a priority to the operator ceiling.
    static func applyCeiling(_ priority: InteractionPriority, controls: BusinessControlRecord?) -> InteractionPriority {
        guard let raw = controls?.priorityCeiling, let ceiling = InteractionPriority(rawValue: raw) else { return priority }
        return min(priority, ceiling)
    }
}
