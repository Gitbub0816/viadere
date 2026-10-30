import Fluent
import Foundation
import ViadereCore

/// `business_preferences` (Organization.v1): one row per (consumer, business) once the customer changed anything.
final class BusinessPreferenceRecord: Model, @unchecked Sendable {
    static let schema = "business_preferences"
    @ID(key: .id) var id: UUID?
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "favorite") var favorite: Bool
    /// `MuteLevel` raw value.
    @Field(key: "mute_level") var muteLevel: String
    @OptionalField(key: "mute_until") var muteUntil: Date?
    @OptionalField(key: "blocked_at") var blockedAt: Date?
    @Field(key: "updated_at") var updatedAt: Date

    init() {}

    init(consumerId: UUID, businessId: UUID, now: Date) {
        id = UUID()
        self.consumerId = consumerId
        self.businessId = businessId
        favorite = false
        muteLevel = MuteLevel.none.rawValue
        updatedAt = now
    }

    var muteLevelValue: MuteLevel { MuteLevel(rawValue: muteLevel) ?? .none }

    func dto(_ businessId: BusinessID) -> BusinessPreferences {
        BusinessPreferences(businessId: businessId, favorite: favorite, muteLevel: muteLevelValue, muteUntil: muteUntil, blocked: blockedAt != nil,
                            updatedAt: updatedAt)
    }
}

/// `conversation_state` (Organization.v1).
final class ConversationStateRecord: Model, @unchecked Sendable {
    static let schema = "conversation_state"
    @ID(key: .id) var id: UUID?
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "session_id") var sessionId: UUID
    @OptionalField(key: "archived_at") var archivedAt: Date?
    @Field(key: "muted") var muted: Bool
    @Field(key: "updated_at") var updatedAt: Date

    init() {}

    init(consumerId: UUID, sessionId: UUID, now: Date) {
        id = UUID()
        self.consumerId = consumerId
        self.sessionId = sessionId
        muted = false
        updatedAt = now
    }
}

/// `alert_seen` (Organization.v1).
final class AlertSeenRecord: Model, @unchecked Sendable {
    static let schema = "alert_seen"
    @ID(key: .id) var id: UUID?
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "alert_id") var alertId: String
    @Field(key: "seen_at") var seenAt: Date

    init() {}

    init(consumerId: UUID, alertId: String, now: Date) {
        id = UUID()
        self.consumerId = consumerId
        self.alertId = alertId
        seenAt = now
    }
}

/// `business_surfaces` (Surfaces.v1).
final class BusinessSurfaceRecord: Model, @unchecked Sendable {
    static let schema = "business_surfaces"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "version") var version: Int
    /// `draft` or `published`.
    @Field(key: "status") var status: String
    @Field(key: "layout_json") var layoutJSON: String
    @OptionalField(key: "published_at") var publishedAt: Date?
    @OptionalField(key: "published_by") var publishedBy: String?
    @Field(key: "created_at") var createdAt: Date

    init() {}
}
