@preconcurrency import Crypto
import _CryptoExtras
import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import Vapor
import ViadereCore
@testable import ViadereServerKit

/// Fixed bearer tokens per audience, counting requests (no Azure).
final class FakeAccessTokens: AccessTokenSource, @unchecked Sendable {
    private let lock = NSLock()
    private var counts: [AzureResource: Int] = [:]
    var failing = false
    func token(for resource: AzureResource) async throws -> String {
        try lock.withLock {
            if failing { throw AzureIdentityError.tokenUnavailable(status: 500) }
            counts[resource, default: 0] += 1
            return "token-for-" + resource.rawValue.replacingOccurrences(of: "https://", with: "").replacingOccurrences(of: "/", with: "")
        }
    }
    func requests(_ resource: AzureResource) -> Int { lock.withLock { counts[resource] ?? 0 } }
}

/// A stub of the Azure data planes the server calls (Key Vault keys, Blob Storage, Service Bus REST), with real cryptography, so the REST clients
/// are tested end to end without a network. Records every call.
final class AzureStub: OutboundHTTP, @unchecked Sendable {
    struct Call: Sendable { var method: NIOHTTP1.HTTPMethod; var url: String; var headers: [String: String]; var body: Data? }

    static let vault = "https://kv-vdr-test.vault.azure.net"
    static let blob = "https://stviaderetestaudit.blob.core.windows.net"
    static let serviceBus = "sb-viadere-test.servicebus.windows.net"

    private let lock = NSLock()
    private var recorded: [Call] = []
    // Key Vault
    private var ecKeys: [String: [(version: String, key: P256.Signing.PrivateKey)]] = [:]
    private var rsaKeys: [String: [(version: String, key: _RSA.Encryption.PrivateKey)]] = [:]
    /// Simulates a substituted key: signatures come from a key that is not the published one.
    var signWithForeignKey = false
    // Blob
    private var blobs: [String: Data] = [:]
    var failBlobWrites = false
    // Service Bus
    struct Message { var id: String; var body: Data; var deliveryCount: Int; var lockToken: String?; var sequence: Int; var visibleAt: Date }
    private var queues: [String: [Message]] = [:]
    private var sequence = 0
    var now: @Sendable () -> Date = { Date() }

    var calls: [Call] { lock.withLock { recorded } }

    @discardableResult
    func addECKey(_ name: String) -> String {
        let version = Hex.encode(SecureToken.randomBytes(16))
        lock.withLock { ecKeys[name, default: []].append((version, P256.Signing.PrivateKey())) }
        return version
    }

    @discardableResult
    func addRSAKey(_ name: String) throws -> String {
        let version = Hex.encode(SecureToken.randomBytes(16))
        let key = try _RSA.Encryption.PrivateKey(keySize: .bits2048)
        lock.withLock { rsaKeys[name, default: []].append((version, key)) }
        return version
    }

    func publicKey(_ name: String, version: String) -> P256.Signing.PublicKey? {
        lock.withLock { ecKeys[name]?.first(where: { $0.version == version })?.key.publicKey }
    }

    func blob(_ path: String) -> Data? { lock.withLock { blobs[path] } }
    func blobNames() -> [String] { lock.withLock { blobs.keys.sorted() } }
    func messages(_ queue: String) -> [Message] { lock.withLock { queues[queue] ?? [] } }

    private static func json(_ object: [String: Any]) -> Data { (try? JSONSerialization.data(withJSONObject: object)) ?? Data() }

    func send(method: NIOHTTP1.HTTPMethod, url: String, headers: [String: String], body: Data?) async throws -> (status: Int, body: Data) {
        let response = try await sendReturningHeaders(method: method, url: url, headers: headers, body: body)
        return (response.status, response.body)
    }

    func sendReturningHeaders(method: NIOHTTP1.HTTPMethod, url: String, headers: [String: String], body: Data?) async throws -> (status: Int, headers: [String: String], body: Data) {
        lock.withLock { recorded.append(Call(method: method, url: url, headers: headers, body: body)) }
        guard headers["Authorization"]?.hasPrefix("Bearer token-for-") == true else { return (401, [:], Data()) }
        if url.hasPrefix(Self.vault) { return keyVault(method: method, url: url, body: body) }
        if url.hasPrefix(Self.blob) { return blobCall(method: method, url: url, headers: headers, body: body) }
        if url.hasPrefix("https://\(Self.serviceBus)/") { return serviceBusCall(method: method, url: url, headers: headers, body: body) }
        return (404, [:], Data())
    }

    // MARK: Key Vault

    private func keyVault(method: NIOHTTP1.HTTPMethod, url: String, body: Data?) -> (Int, [String: String], Data) {
        guard let components = URLComponents(string: url), components.queryItems?.first(where: { $0.name == "api-version" })?.value == AzureKeyVaultKMS.apiVersion else {
            return (400, [:], Data())
        }
        let parts = components.path.split(separator: "/").map(String.init)
        guard parts.count >= 2, parts[0] == "keys" else { return (404, [:], Data()) }
        let name = parts[1]
        return lock.withLock { () -> (Int, [String: String], Data) in
            if let versions = ecKeys[name] {
                let entry = parts.count >= 3 ? versions.first(where: { $0.version == parts[2] }) : versions.last
                guard let entry else { return (404, [:], Data()) }
                let kid = "\(Self.vault)/keys/\(name)/\(entry.version)"
                if method == .GET {
                    let raw = entry.key.publicKey.rawRepresentation
                    return (200, [:], Self.json(["key": ["kid": kid, "kty": "EC", "crv": "P-256", "x": Base64URL.encode(raw.prefix(32)), "y": Base64URL.encode(raw.suffix(32))]]))
                }
                guard parts.count == 4, parts[3] == "sign", let object = body.flatMap({ try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }),
                      object["alg"] as? String == "ES256", let digest = (object["value"] as? String).flatMap(Base64URL.decode), digest.count == 32 else { return (400, [:], Data()) }
                let signer = signWithForeignKey ? P256.Signing.PrivateKey() : entry.key
                let signature = try! signer.signature(for: SHA256Digest(bytes: digest))
                return (200, [:], Self.json(["kid": kid, "value": Base64URL.encode(signature.rawRepresentation)]))
            }
            if let versions = rsaKeys[name] {
                let entry = parts.count >= 3 ? versions.first(where: { $0.version == parts[2] }) : versions.last
                guard let entry else { return (404, [:], Data()) }
                let kid = "\(Self.vault)/keys/\(name)/\(entry.version)"
                if method == .GET { return (200, [:], Self.json(["key": ["kid": kid, "kty": "RSA"]])) }
                guard parts.count == 4, let object = body.flatMap({ try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }),
                      object["alg"] as? String == "RSA-OAEP-256", let value = (object["value"] as? String).flatMap(Base64URL.decode) else { return (400, [:], Data()) }
                switch parts[3] {
                case "wrapkey":
                    guard let wrapped = try? entry.key.publicKey.encrypt(value, padding: .PKCS1_OAEP_SHA256) else { return (400, [:], Data()) }
                    return (200, [:], Self.json(["kid": kid, "value": Base64URL.encode(wrapped)]))
                case "unwrapkey":
                    guard let plain = try? entry.key.decrypt(value, padding: .PKCS1_OAEP_SHA256) else { return (400, [:], Data()) }
                    return (200, [:], Self.json(["kid": kid, "value": Base64URL.encode(plain)]))
                default: return (400, [:], Data())
                }
            }
            return (404, [:], Data())
        }
    }

    // MARK: Blob

    private func blobCall(method: NIOHTTP1.HTTPMethod, url: String, headers: [String: String], body: Data?) -> (Int, [String: String], Data) {
        guard headers["x-ms-version"] == AzureBlobObjectStore.serviceVersion else { return (400, [:], Data()) }
        let path = String(url.dropFirst(Self.blob.count))
        return lock.withLock { () -> (Int, [String: String], Data) in
            switch method {
            case .PUT:
                if failBlobWrites { return (503, [:], Data()) }
                // The container is immutable (WORM): an existing blob is never replaced, with or without If-None-Match.
                if blobs[path] != nil { return (headers["If-None-Match"] == "*" ? 409 : 409, [:], Data()) }
                guard headers["x-ms-blob-type"] == "BlockBlob" else { return (400, [:], Data()) }
                blobs[path] = body ?? Data()
                return (201, [:], Data())
            case .GET:
                guard let data = blobs[path] else { return (404, [:], Data()) }
                return (200, [:], data)
            default:
                return (405, [:], Data())
            }
        }
    }

    // MARK: Service Bus

    /// Adds a message as if another sender (or a replay) had sent it.
    func inject(queue: String, id: String, body: Data) {
        lock.withLock {
            sequence += 1
            queues[queue, default: []].append(Message(id: id, body: body, deliveryCount: 0, lockToken: nil, sequence: sequence, visibleAt: .distantPast))
        }
    }

    private func serviceBusCall(method: NIOHTTP1.HTTPMethod, url: String, headers: [String: String], body: Data?) -> (Int, [String: String], Data) {
        guard let components = URLComponents(string: url) else { return (400, [:], Data()) }
        let parts = components.path.split(separator: "/").map(String.init)
        guard parts.count >= 2, parts[1] == "messages" else { return (404, [:], Data()) }
        let queue = parts[0]
        let current = now()
        return lock.withLock { () -> (Int, [String: String], Data) in
            if parts.count == 2, method == .POST {
                // Send. Basic tier: no duplicate detection, so the same MessageId twice is two messages.
                guard let raw = headers["BrokerProperties"], let properties = try? JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any],
                      let id = properties["MessageId"] as? String else { return (400, [:], Data()) }
                var visible = Date.distantPast
                if let scheduled = properties["ScheduledEnqueueTimeUtc"] as? String {
                    let formatter = DateFormatter()
                    formatter.locale = Locale(identifier: "en_US_POSIX")
                    formatter.timeZone = TimeZone(identifier: "GMT")
                    formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss 'GMT'"
                    guard let date = formatter.date(from: scheduled) else { return (400, [:], Data()) }
                    visible = date
                }
                sequence += 1
                queues[queue, default: []].append(Message(id: id, body: body ?? Data(), deliveryCount: 0, lockToken: nil, sequence: sequence, visibleAt: visible))
                return (201, [:], Data())
            }
            if parts.count == 3, parts[2] == "head", method == .POST {
                guard var list = queues[queue], let index = list.firstIndex(where: { $0.lockToken == nil && $0.visibleAt <= current }) else { return (204, [:], Data()) }
                list[index].deliveryCount += 1
                let token = UUID().uuidString.lowercased()
                list[index].lockToken = token
                queues[queue] = list
                let message = list[index]
                let properties = String(decoding: Self.json(["DeliveryCount": message.deliveryCount, "LockToken": token, "MessageId": message.id, "SequenceNumber": message.sequence]), as: UTF8.self)
                return (201, ["location": "https://\(Self.serviceBus)/\(queue)/messages/\(message.sequence)/\(token)", "brokerproperties": properties], message.body)
            }
            if parts.count == 4 {
                guard var list = queues[queue], let index = list.firstIndex(where: { String($0.sequence) == parts[2] && $0.lockToken == parts[3] }) else { return (404, [:], Data()) }
                switch method {
                case .DELETE: list.remove(at: index)
                case .PUT: list[index].lockToken = nil
                case .POST: break
                default: return (405, [:], Data())
                }
                queues[queue] = list
                return (200, [:], Data())
            }
            return (400, [:], Data())
        }
    }
}

/// A Vapor `Client` that records requests and answers 200, to prove a guarded client never reached the network.
final class RecordingClient: Client, @unchecked Sendable {
    private let lock = NSLock()
    private var urls: [String] = []
    let eventLoop: any EventLoop
    var sent: [String] { lock.withLock { urls } }

    init(eventLoop: any EventLoop = MultiThreadedEventLoopGroup.singleton.any()) { self.eventLoop = eventLoop }

    func delegating(to eventLoop: any EventLoop) -> any Client { self }
    func logging(to logger: Logger) -> any Client { self }
    func allocating(to byteBufferAllocator: ByteBufferAllocator) -> any Client { self }
    var byteBufferAllocator: ByteBufferAllocator { ByteBufferAllocator() }

    func send(_ request: ClientRequest) -> EventLoopFuture<ClientResponse> {
        lock.withLock { urls.append(request.url.string) }
        return eventLoop.makeSucceededFuture(ClientResponse(status: .ok))
    }
}

/// A resolver for the outbound guard with fixed answers (models DNS rebinding without a network).
func stubResolver(_ table: [String: String]) -> @Sendable (String, Int) async throws -> [SocketAddress] {
    { host, port in
        if let address = table[host] { return [try SocketAddress(ipAddress: address, port: port)] }
        // Literals resolve to themselves.
        if let literal = try? SocketAddress(ipAddress: host, port: port) { return [literal] }
        throw OutboundDestinationGuard.Refusal.unresolvable
    }
}
