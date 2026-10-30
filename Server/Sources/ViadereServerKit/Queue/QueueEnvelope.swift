import Foundation
import ViadereCore

/// The queues (ADR-0014, plan 5.7). Names match `Infra/azure/locals.tf` `queues` exactly; `maxDeliveries` matches each queue's `max_delivery_count`.
public enum QueueName: String, Sendable, CaseIterable, Codable {
    case push
    case smsOutbound = "sms-outbound"
    case channelOutbound = "channel-outbound"
    case webhookDelivery = "webhook-delivery"
    case walletPush = "wallet-push"
    case operatorNotices = "operator-notices"
    case consumerExport = "consumer-export"
    /// Scheduled messages: interaction and approval expiries, identity holds.
    case expiry

    /// Deliveries before a message is dead-lettered (the broker's `maxDeliveryCount`; the consumer dead-letters on the last one itself).
    public var maxDeliveries: Int {
        switch self {
        case .push: 5
        case .consumerExport: 3
        case .expiry: 10
        default: 8
        }
    }
}

/// A queue message envelope (SECURITY.md §2.91, normative). Canonical JSON, at most 1 KiB, exactly these members:
///
/// ```json
/// {"id":"<uuid>","not_before":"2026-10-30T12:00:00Z","ref":"<uuid>","tenant":"<uuid>","type":"sms.send","v":1}
/// ```
///
/// - `type`, `v`: the message type and its schema version; the pair selects the handler. An unknown pair is dead-lettered, never executed.
/// - `id`: the outbox row id; also the broker `MessageId` and the idempotency key (`processed_messages.message_id`).
/// - `ref`: the id of the row the work is about. Ids only: never personal data, message text, phone numbers, tokens or secrets. Consumers
///   re-read every fact from PostgreSQL; the envelope is a doorbell, not a source of truth.
/// - `tenant` (optional): the business the row belongs to, taken by the server from the row it just wrote (**trusted context only**, never from a
///   request field). The consumer refuses a message whose tenant does not match the row.
/// - `not_before` (optional): the earliest processing time (scheduled enqueue); seconds precision, UTC.
public struct QueueEnvelope: Sendable, Equatable {
    public static let maxBytes = 1024

    public var type: String
    public var version: Int
    public var id: UUID
    public var ref: UUID
    public var tenant: UUID?
    public var notBefore: Date?

    public init(type: String, version: Int, id: UUID, ref: UUID, tenant: UUID? = nil, notBefore: Date? = nil) {
        self.type = type
        self.version = version
        self.id = id
        self.ref = ref
        self.tenant = tenant
        self.notBefore = notBefore.map { Date(timeIntervalSince1970: floor($0.timeIntervalSince1970)) }
    }

    public enum DecodeError: Error, Sendable, Equatable { case malformed }

    /// Canonical JSON (sorted members, no whitespace).
    public func encoded() -> Data {
        var object: [String: JSONValue] = [
            "type": .string(type), "v": .integer(Int64(version)), "id": .string(id.uuidString.lowercased()), "ref": .string(ref.uuidString.lowercased()),
        ]
        if let tenant { object["tenant"] = .string(tenant.uuidString.lowercased()) }
        if let notBefore { object["not_before"] = .string(Self.timestamp(notBefore)) }
        // Strings and integers only: canonical serialization cannot fail.
        return (try? CanonicalJSON.serialize(.object(object))) ?? Data()
    }

    /// Strict decoding: a JSON object with exactly the members above, lowercase UUIDs, `v` an integer from 1 to 1000, a well-formed `type`.
    public static func decode(_ data: Data) throws -> QueueEnvelope {
        guard data.count <= maxBytes, let value = try? ViadereJSON.decode(JSONValue.self, from: data), case .object(let members) = value else {
            throw DecodeError.malformed
        }
        let allowed: Set<String> = ["type", "v", "id", "ref", "tenant", "not_before"]
        guard Set(members.keys).isSubset(of: allowed), Set(["type", "v", "id", "ref"]).isSubset(of: Set(members.keys)) else { throw DecodeError.malformed }
        guard case .string(let type)? = members["type"], isTypeName(type) else { throw DecodeError.malformed }
        guard case .integer(let version)? = members["v"], (1...1000).contains(version) else { throw DecodeError.malformed }
        func uuid(_ key: String) throws -> UUID? {
            guard let raw = members[key] else { return nil }
            guard case .string(let text) = raw, text == text.lowercased(), let id = UUID(uuidString: text) else { throw DecodeError.malformed }
            return id
        }
        guard let id = try uuid("id"), let ref = try uuid("ref") else { throw DecodeError.malformed }
        let tenant = try uuid("tenant")
        var notBefore: Date?
        if let raw = members["not_before"] {
            guard case .string(let text) = raw, let date = parseTimestamp(text) else { throw DecodeError.malformed }
            notBefore = date
        }
        return QueueEnvelope(type: type, version: Int(version), id: id, ref: ref, tenant: tenant, notBefore: notBefore)
    }

    /// `segment(.segment)*`, lowercase letters, digits and `_`, at most 64 characters (e.g. `sms.send`, `loop.action_event`).
    static func isTypeName(_ text: String) -> Bool {
        guard (3...64).contains(text.count) else { return false }
        return text.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { part in
            !part.isEmpty && part.unicodeScalars.allSatisfy { ("a"..."z").contains($0) || ("0"..."9").contains($0) || $0 == "_" }
        }
    }

    static func timestamp(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        formatter.timeZone = TimeZone(identifier: "UTC")
        return formatter.string(from: date)
    }

    static func parseTimestamp(_ text: String) -> Date? {
        guard text.hasSuffix("Z"), text.count == 20 else { return nil }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: text)
    }
}

