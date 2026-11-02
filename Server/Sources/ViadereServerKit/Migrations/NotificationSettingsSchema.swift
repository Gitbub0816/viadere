import Fluent
import Foundation

/// The account-wide notification settings (SECURITY.md §2.96 "Notification level and quiet hours"): one row per customer. The default
/// level is a `MuteLevel` raw value (`none` = Everything). Quiet hours are all-or-nothing: `quiet_start`, `quiet_end` (minutes after local
/// midnight) and `quiet_zone` (IANA identifier) are either all set or all null. No business-facing surface reads this table.
final class NotificationSettingsRecord: Model, @unchecked Sendable {
    static let schema = "notification_settings"
    @ID(key: .id) var id: UUID?
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "default_level") var defaultLevel: String
    @OptionalField(key: "quiet_start") var quietStart: Int?
    @OptionalField(key: "quiet_end") var quietEnd: Int?
    @OptionalField(key: "quiet_zone") var quietZone: String?
    @Field(key: "updated_at") var updatedAt: Date
    init() {}
}

/// `NotificationSettings.v1` (additive, forward-only): `notification_settings` and `business_preferences.has_own_level`.
///
/// `has_own_level` tells a level the customer chose for one business from the absence of a choice, so a business without its own level can
/// inherit the account-wide default. Existing rows that are muted are backfilled as their own level (they were chosen); an existing row at
/// `none` stays "inherits", which is the same as before until the customer sets a default.
struct CreateNotificationSettingsSchema: AsyncMigration {
    var name: String { "NotificationSettings.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema(NotificationSettingsRecord.schema).id()
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("default_level", .string, .required)
            .field("quiet_start", .int)
            .field("quiet_end", .int)
            .field("quiet_zone", .string)
            .field("updated_at", .datetime, .required)
            .unique(on: "consumer_id").create()
        try await db.schema(BusinessPreferenceRecord.schema).field("has_own_level", .bool, .required, .sql(.default(false))).update()
        try await BusinessPreferenceRecord.query(on: db).filter(\.$muteLevel != "none").set(\.$hasOwnLevel, to: true).update()
    }

    func revert(on db: any Database) async throws {
        try await db.schema(BusinessPreferenceRecord.schema).deleteField("has_own_level").update()
        try await db.schema(NotificationSettingsRecord.schema).delete()
    }
}

/// `LoopInstallAlerts.v1` (additive, forward-only): `loop_installs.alerts_enabled`, the customer's per-installed-Loop permission to show
/// that Loop's own alerts in Alerts (owner decision F-4). Default `false`: an install never turns it on.
struct CreateLoopInstallAlertsSchema: AsyncMigration {
    var name: String { "LoopInstallAlerts.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema(LoopInstallRecord.schema).field("alerts_enabled", .bool, .required, .sql(.default(false))).update()
    }

    func revert(on db: any Database) async throws {
        try await db.schema(LoopInstallRecord.schema).deleteField("alerts_enabled").update()
    }
}
