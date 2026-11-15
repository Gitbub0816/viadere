import Foundation
import NIOHTTP1
import ViadereCore

/// `QueueTransport` on the Azure Service Bus REST API with Entra bearer tokens from the worker's managed identity (ADR-0014; there is no Service Bus
/// SDK for Swift and AMQP is not needed at this volume). Operations (Microsoft Learn, Service Bus REST, 2026-10-13):
///
/// - send: `POST https://{ns}/{queue}/messages` with `BrokerProperties` `{"MessageId", "TimeToLive", "ScheduledEnqueueTimeUtc"}` → `201`;
/// - peek-lock receive: `POST https://{ns}/{queue}/messages/head?timeout={s}` → `201` with `Location` (the locked message) and `BrokerProperties`
///   (`DeliveryCount`, `LockToken`, `MessageId`), or `204` when the queue is empty;
/// - complete: `DELETE {Location}`; abandon (unlock): `PUT {Location}`; renew lock: `POST {Location}`.
///
/// The runtime REST operations carry no `api-version`. A `Location` is used only if it points into the configured namespace and the same queue,
/// so a forged response cannot redirect the token-bearing calls elsewhere.
public struct ServiceBusRESTTransport: QueueTransport {
    let fqdn: String
    let tokens: any AccessTokenSource
    let http: any OutboundHTTP

    public init(fqdn: String, tokens: any AccessTokenSource, http: any OutboundHTTP) {
        self.fqdn = fqdn.lowercased()
        self.tokens = tokens
        self.http = http
    }

    private func authorization() async throws -> String { "Bearer \(try await tokens.token(for: .serviceBus))" }

    static func rfc1123(_ date: Date) -> String { AzureBlobObjectStore.httpDate(date) }

    public func send(queue: QueueName, messageId: UUID, body: Data, scheduledAt: Date?, timeToLive: TimeInterval) async throws {
        var properties: [String: Any] = ["MessageId": messageId.uuidString.lowercased(), "TimeToLive": Int(timeToLive)]
        if let scheduledAt { properties["ScheduledEnqueueTimeUtc"] = Self.rfc1123(scheduledAt) }
        let brokerProperties = String(decoding: try JSONSerialization.data(withJSONObject: properties, options: [.sortedKeys]), as: UTF8.self)
        let response = try await http.send(method: .POST, url: "https://\(fqdn)/\(queue.rawValue)/messages", headers: [
            "Authorization": try await authorization(),
            "Content-Type": "application/json",
            "BrokerProperties": brokerProperties,
        ], body: body)
        guard response.status == 201 else { throw QueueTransportError.service(status: response.status) }
    }

    public func receive(queue: QueueName, wait: TimeInterval) async throws -> ReceivedQueueMessage? {
        let timeout = max(0, min(Int(wait), 55))
        let response = try await http.sendReturningHeaders(method: .POST, url: "https://\(fqdn)/\(queue.rawValue)/messages/head?timeout=\(timeout)",
                                                          headers: ["Authorization": try await authorization(), "Content-Length": "0"], body: nil)
        if response.status == 204 { return nil }
        guard response.status == 201 else { throw QueueTransportError.service(status: response.status) }
        guard let location = response.headers["location"], isLockLocation(location, queue: queue),
              let raw = response.headers["brokerproperties"], let properties = try? JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any],
              let delivery = (properties["DeliveryCount"] as? Int) ?? (properties["DeliveryCount"] as? Double).map(Int.init) else {
            throw QueueTransportError.service(status: 201)
        }
        let messageId = (properties["MessageId"] as? String) ?? ""
        return ReceivedQueueMessage(queue: queue, messageId: messageId, body: response.body, deliveryCount: delivery, lock: location)
    }

    /// `https://{ns}/{queue}/messages/{sequence or id}/{lock token}` in this namespace and queue, nothing else.
    func isLockLocation(_ location: String, queue: QueueName) -> Bool {
        guard let url = URL(string: location), url.scheme == "https", url.host?.lowercased() == fqdn, url.port == nil, url.user == nil, url.query == nil else { return false }
        let parts = url.path.split(separator: "/").map(String.init)
        return parts.count == 4 && parts[0].lowercased() == queue.rawValue && parts[1] == "messages"
            && parts[2].allSatisfy({ $0.isNumber || $0.isLetter || $0 == "-" }) && parts[3].allSatisfy({ $0.isHexDigit || $0 == "-" })
    }

    private func lockCall(_ method: NIOHTTP1.HTTPMethod, _ message: ReceivedQueueMessage) async throws {
        guard isLockLocation(message.lock, queue: message.queue) else { throw QueueTransportError.lockLost }
        let response = try await http.send(method: method, url: message.lock, headers: ["Authorization": try await authorization(), "Content-Length": "0"], body: nil)
        switch response.status {
        case 200: return
        case 404, 410: throw QueueTransportError.lockLost
        default: throw QueueTransportError.service(status: response.status)
        }
    }

    public func complete(_ message: ReceivedQueueMessage) async throws { try await lockCall(.DELETE, message) }
    public func abandon(_ message: ReceivedQueueMessage) async throws { try await lockCall(.PUT, message) }
    public func renewLock(_ message: ReceivedQueueMessage) async throws { try await lockCall(.POST, message) }
    /// The REST API cannot move a message to the dead-letter subqueue: the consumer recorded it in `queue_dead_letters` (and alerted); this
    /// removes it from the queue so it is never executed.
    public func deadLetter(_ message: ReceivedQueueMessage, reason: String) async throws { try await complete(message) }
}
