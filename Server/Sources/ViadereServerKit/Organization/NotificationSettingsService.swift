import Fluent
import Foundation
import ViadereCore

/// The account-wide notification settings and where they are enforced (SECURITY.md §2.96 "Notification level and quiet hours").
///
/// * **Default level.** A business the customer never set a level for (`business_preferences.has_own_level = false`) inherits it; a business
///   with its own level keeps that level.
/// * **Quiet hours.** A daily window in the customer's own time zone during which a push that is not security-critical is delivered
///   *quietly* (`passive`, normal priority) instead of normally.
/// * **Never a security silence.** `NotificationPolicy` (Core) decides, and sign-in and payment approvals and the `security` purpose always
///   return `normal`. Approve v2, verification and account security notices do not pass through this policy at all.
/// * **Quiet is not absent.** The item is stored and listed in Alerts exactly as before; only the push's interruption changes.
struct NotificationSettingsService {
    let db: any Database
    let ctx: ServerContext

    // MARK: Read / write

    func get(consumer: UUID) async throws -> NotificationSettings {
        guard let row = try await NotificationSettingsRecord.query(on: db).filter(\.$consumerId == consumer).first() else { return .default }
        return Self.dto(row)
    }

    static func dto(_ row: NotificationSettingsRecord) -> NotificationSettings {
        var quiet: QuietHours?
        if let start = row.quietStart, let end = row.quietEnd, let zone = row.quietZone {
            quiet = QuietHours(startMinute: start, endMinute: end, timeZone: zone)
        }
        return NotificationSettings(defaultLevel: MuteLevel(rawValue: row.defaultLevel) ?? .none, quietHours: quiet, updatedAt: row.updatedAt)
    }

    /// Replaces the settings. An invalid quiet window is `422`; the same value twice is the same result.
    func put(principal: ConsumerPrincipal, update: NotificationSettingsUpdate) async throws -> NotificationSettings {
        if let field = update.invalidField {
            throw APIError.validation("Choose a start and end that differ, and a time zone.", details: [field: "invalid"])
        }
        let consumer = principal.consumerId.uuid
        let now = ctx.now
        func apply(_ row: NotificationSettingsRecord) {
            row.consumerId = consumer
            row.defaultLevel = update.defaultLevel.rawValue
            row.quietStart = update.quietHours?.startMinute
            row.quietEnd = update.quietHours?.endMinute
            row.quietZone = update.quietHours?.timeZone
            row.updatedAt = now
        }
        var saved = try await NotificationSettingsRecord.query(on: db).filter(\.$consumerId == consumer).first()
        if let row = saved {
            apply(row)
            try await row.update(on: db)
        } else {
            let row = NotificationSettingsRecord()
            apply(row)
            do {
                try await row.create(on: db)
                saved = row
            } catch let error where error.isConstraintViolation {
                // A concurrent first save by the same account won the unique row: update that one.
                guard let winner = try await NotificationSettingsRecord.query(on: db).filter(\.$consumerId == consumer).first() else { throw error }
                apply(winner)
                try await winner.update(on: db)
                saved = winner
            }
        }
        _ = try await AuditService(db: db, ctx: ctx).record("notifications.settings_updated", principal: principal, subjectType: "notification_settings",
            subjectId: consumer.uuidString.lowercased(), metadata: ["default_level": update.defaultLevel.rawValue,
                                                                    "quiet_hours": update.quietHours == nil ? "off" : "on"])
        guard let saved else { throw APIError.internalError }
        return Self.dto(saved)
    }

    // MARK: Enforcement

    /// How a push for this item lands for this customer: the level of `business` (its own, or the account default), then quiet hours.
    /// A failure reading either setting never silences anything (best effort fails open to the sender's own level).
    func interruption(consumer: UUID, business: UUID?, kind: InteractionKind?, purpose: InteractionPurpose, actionRequired: Bool) async -> NotificationPolicy.Interruption {
        let now = ctx.now
        // Security-critical items never need the settings; skip the reads.
        if NotificationPolicy.isSecurityCritical(kind: kind, purpose: purpose) { return .normal }
        let settings = (try? await get(consumer: consumer)) ?? .default
        var preferences: BusinessPreferences?
        if let business, let row = try? await PreferenceService(db: db, ctx: ctx).record(consumer: consumer, business: business, on: db) {
            preferences = row.dto(BusinessID(business))
        }
        let level = NotificationPolicy.effectiveLevel(business: preferences, accountDefault: settings.defaultLevel, at: now)
        return NotificationPolicy.interruption(kind: kind, purpose: purpose, actionRequired: actionRequired, level: level, quietHours: settings.quietHours, at: now)
    }

    /// Account deletion: the settings go with the account.
    static func wipe(consumer: UUID, on db: any Database) async throws {
        try await NotificationSettingsRecord.query(on: db).filter(\.$consumerId == consumer).delete()
    }
}
