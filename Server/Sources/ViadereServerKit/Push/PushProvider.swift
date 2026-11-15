import Fluent
import Foundation
import ViadereCore

/// Where one push goes: the provider the token was **registered for**, the token, and the app it belongs to. A target is only ever handed to the
/// provider it names (`PushProviderRouter`), so a token registered for APNs is never sent through FCM and the reverse (SECURITY.md §2.114).
public struct PushTarget: Sendable, Equatable {
    public var provider: PushRegistration.Provider
    public var token: String
    /// APNs only: the token's environment.
    public var environment: APNsTokenRegistration.Environment?
    /// iOS bundle id or Android application id.
    public var appId: String

    public init(provider: PushRegistration.Provider, token: String, environment: APNsTokenRegistration.Environment? = nil, appId: String) {
        self.provider = provider
        self.token = token
        self.environment = environment
        self.appId = appId
    }
}

/// One push delivery service (APNs, FCM). `message` is the provider-neutral content built by `PushPayloadBuilder` and friends: generic text and
/// opaque ids only; each provider renders it into its own wire format and may drop what it does not carry (FCM carries no text at all).
public protocol PushProvider: Sendable {
    var kind: PushRegistration.Provider { get }
    func deliver(_ message: PushMessage, to target: PushTarget) async -> PushOutcome
}

/// The existing APNs sender, unchanged, behind `PushProvider`.
public struct APNsPushProvider: PushProvider {
    public let sender: any APNsSender
    public var kind: PushRegistration.Provider { .apns }

    public init(sender: any APNsSender) { self.sender = sender }

    public func deliver(_ message: PushMessage, to target: PushTarget) async -> PushOutcome {
        guard target.provider == .apns, let environment = target.environment else { return .failed }
        var apns = message
        apns.deviceToken = target.token
        apns.environment = environment
        if !target.appId.isEmpty { apns.topic = target.appId }
        return await sender.send(apns)
    }
}

/// Picks the provider by the target's registered provider and nothing else. A provider that is not configured (FCM while `FCM_ENABLED` is off) or
/// that claims another kind than it is filed under never receives the target.
public struct PushProviderRouter: Sendable {
    private let providers: [PushRegistration.Provider: any PushProvider]

    public init(_ providers: [any PushProvider]) {
        var byKind: [PushRegistration.Provider: any PushProvider] = [:]
        for provider in providers where provider.kind != .unknown && byKind[provider.kind] == nil { byKind[provider.kind] = provider }
        self.providers = byKind
    }

    public func supports(_ kind: PushRegistration.Provider) -> Bool { providers[kind] != nil }

    public func deliver(_ message: PushMessage, to target: PushTarget) async -> PushOutcome {
        guard let provider = providers[target.provider], provider.kind == target.provider else { return .failed }
        return await provider.deliver(message, to: target)
    }
}

/// A push token of a provider other than APNs (`push_tokens`, WP-E2). APNs tokens stay in `apns_tokens`, which every existing APNs path reads, so
/// a token stored here can never reach the APNs sender. One row per device; a device registers one provider (registering the other replaces it).
final class PushTokenRecord: Model, @unchecked Sendable {
    static let schema = "push_tokens"
    @ID(key: .id) var id: UUID?
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "device_id") var deviceId: UUID
    @Field(key: "provider") var provider: String
    @Field(key: "token") var token: String
    @OptionalField(key: "environment") var environment: String?
    @Field(key: "app_id") var appId: String
    @Field(key: "updated_at") var updatedAt: Date
    @OptionalField(key: "invalidated_at") var invalidatedAt: Date?

    init() {}

    init(consumerId: UUID, deviceId: UUID, provider: PushRegistration.Provider, token: String, appId: String, now: Date) {
        id = UUID()
        self.consumerId = consumerId
        self.deviceId = deviceId
        self.provider = provider.rawValue
        self.token = token
        self.appId = appId
        updatedAt = now
    }

    var target: PushTarget? {
        let kind = PushRegistration.Provider(rawValue: provider) ?? .unknown
        guard kind != .unknown, kind != .apns else { return nil }
        return PushTarget(provider: kind, token: token, environment: nil, appId: appId)
    }
}

/// `push_tokens` (WP-E2): additive; `apns_tokens` is untouched (dual read: APNs from `apns_tokens`, other providers from here).
struct CreatePushTokensSchema: AsyncMigration {
    var name: String { "PushTokens.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema(PushTokenRecord.schema)
            .id()
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("device_id", .uuid, .required, .references("devices", "id"))
            .field("provider", .string, .required)
            .field("token", .string, .required)
            .field("environment", .string)
            .field("app_id", .string, .required)
            .field("updated_at", .datetime, .required)
            .field("invalidated_at", .datetime)
            .unique(on: "device_id")
            .create()
    }

    func revert(on db: any Database) async throws {
        try await db.schema(PushTokenRecord.schema).delete()
    }
}

extension APNsTokenRegistrationRecord {
    /// A stand-in record for building provider-neutral content with the APNs builders: the token and topic are replaced by the provider.
    static let providerNeutral = APNsTokenRegistrationRecord(token: "", environment: .production, bundleId: "")
}

/// Sends the provider-neutral push to the **non-APNs** tokens of some devices (the APNs half stays in each caller's existing `apns_tokens` loop).
/// Does nothing, and reads nothing, while no such provider is configured.
struct PushFanout {
    let db: any Database
    let ctx: ServerContext

    /// `build(deviceId, consumerId)` returns the content for that device, or `nil` to skip it. A token the provider reports invalid is marked
    /// invalidated (that row only).
    func deliverToOtherProviders(deviceIds: [UUID], build: (UUID, UUID) -> PushMessage?) async {
        guard ctx.push.supports(.fcm), !deviceIds.isEmpty else { return }
        do {
            let tokens = try await PushTokenRecord.query(on: db).filter(\.$deviceId ~~ deviceIds).filter(\.$invalidatedAt == nil).all()
            for token in tokens {
                guard let target = token.target, let message = build(token.deviceId, token.consumerId) else { continue }
                if await ctx.push.deliver(message, to: target) == .tokenInvalid, let id = token.id {
                    try await PushTokenRecord.query(on: db).filter(\.$id == id).set(\.$invalidatedAt, to: ctx.now).update()
                }
            }
        } catch {
            // Best effort, like the APNs half: the authenticated API remains the source of truth.
        }
    }
}
