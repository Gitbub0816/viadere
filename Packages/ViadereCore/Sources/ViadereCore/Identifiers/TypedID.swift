import Foundation

/// A strongly typed UUID wrapper. `Tag` is a phantom type that prevents mixing, e.g.,
/// a `BusinessID` with a `ConsumerID` at compile time.
///
/// Wire format: lowercase canonical UUID string (`"3f2a…"`). Decoding accepts either case.
public struct TypedID<Tag>: Hashable, Comparable, Codable, CustomStringConvertible, LosslessStringConvertible {
    /// Underlying UUID.
    public let uuid: UUID

    /// Wraps an existing UUID.
    public init(_ uuid: UUID) { self.uuid = uuid }

    /// Generates a new random (v4) identifier.
    public init() { self.uuid = UUID() }

    /// Parses a UUID string (either case). Returns `nil` if malformed.
    public init?(_ description: String) {
        guard let uuid = UUID(uuidString: description) else { return nil }
        self.uuid = uuid
    }

    /// Lowercase UUID string, the canonical wire form.
    public var description: String { uuid.uuidString.lowercased() }

    /// Same as `description`.
    public var rawValue: String { description }

    public static func < (lhs: TypedID, rhs: TypedID) -> Bool { lhs.description < rhs.description }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        let string = try container.decode(String.self)
        guard let uuid = UUID(uuidString: string) else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Invalid UUID: \(string)")
        }
        self.uuid = uuid
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }
}

extension TypedID: Sendable {}

/// Phantom tags for `TypedID`.
public enum IDTag {
    public enum Business {}
    public enum Consumer {}
    public enum Device {}
    public enum DeviceKey {}
    public enum Interaction {}
    public enum Session {}
    public enum Relationship {}
    public enum ConsentGrant {}
    public enum Message {}
    public enum Reward {}
    public enum WalletPass {}
    public enum AuditEvent {}
    public enum WebhookSubscription {}
    public enum WebhookDelivery {}
    public enum Delegation {}
    public enum PhoneLink {}
    public enum APIKey {}
    public enum Ceremony {}
}

public typealias BusinessID = TypedID<IDTag.Business>
public typealias ConsumerID = TypedID<IDTag.Consumer>
public typealias DeviceID = TypedID<IDTag.Device>
public typealias DeviceKeyID = TypedID<IDTag.DeviceKey>
public typealias InteractionID = TypedID<IDTag.Interaction>
/// A business-scoped conversation session (SMS or app).
public typealias SessionID = TypedID<IDTag.Session>
public typealias RelationshipID = TypedID<IDTag.Relationship>
public typealias ConsentGrantID = TypedID<IDTag.ConsentGrant>
public typealias MessageID = TypedID<IDTag.Message>
public typealias RewardID = TypedID<IDTag.Reward>
public typealias WalletPassID = TypedID<IDTag.WalletPass>
public typealias AuditEventID = TypedID<IDTag.AuditEvent>
public typealias WebhookSubscriptionID = TypedID<IDTag.WebhookSubscription>
public typealias WebhookDeliveryID = TypedID<IDTag.WebhookDelivery>
public typealias DelegationID = TypedID<IDTag.Delegation>
public typealias PhoneLinkID = TypedID<IDTag.PhoneLink>
public typealias APIKeyID = TypedID<IDTag.APIKey>
/// Identifies a WebAuthn/passkey ceremony (begin → finish).
public typealias CeremonyID = TypedID<IDTag.Ceremony>
