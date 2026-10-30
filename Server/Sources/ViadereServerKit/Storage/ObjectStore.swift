import Foundation
import NIOHTTP1

/// Object storage behind one interface (WP-B2). Today it holds the exported audit-chain heads (`AuditHeadExporter`); it is deliberately general
/// (names, content types, create-only writes, reads) so later stores, such as Brand Kit assets on their own container (FEATURE-EXPANSION-v4 B2/B4),
/// are a new configuration of the same type rather than a new client. Each store is bound to exactly one container: a caller cannot name
/// another one.
public protocol ObjectStore: Sendable {
    /// Writes a new object. **Create-only**: fails with `ObjectStoreError.alreadyExists` when the name is taken, so an existing object can never be
    /// replaced through this interface (the audit container is also immutable at the storage layer).
    func create(name: String, data: Data, contentType: String) async throws
    /// Reads an object; `nil` when it does not exist.
    func read(name: String) async throws -> Data?
}

public enum ObjectStoreError: Error, Sendable, Equatable {
    case alreadyExists
    case invalidName
    case unavailable(status: Int)
}

public enum ObjectNames {
    /// `segment(/segment)*`, each segment of `[A-Za-z0-9._-]`, never `.` or `..`, at most 512 characters in total.
    public static func isValid(_ name: String) -> Bool {
        guard (1...512).contains(name.utf8.count), !name.hasPrefix("/"), !name.hasSuffix("/") else { return false }
        for segment in name.split(separator: "/", omittingEmptySubsequences: false) {
            guard !segment.isEmpty, segment != ".", segment != "..",
                  segment.unicodeScalars.allSatisfy({ $0.isASCII && ($0.properties.isAlphabetic || ("0"..."9").contains($0) || "._-".unicodeScalars.contains($0)) })
            else { return false }
        }
        return true
    }
}

/// Development and tests: a directory on disk, create-only.
public struct DirectoryObjectStore: ObjectStore {
    public let directory: String
    public init(directory: String) { self.directory = directory }

    public func create(name: String, data: Data, contentType: String) async throws {
        guard ObjectNames.isValid(name) else { throw ObjectStoreError.invalidName }
        let url = URL(fileURLWithPath: directory).appendingPathComponent(name)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        guard !FileManager.default.fileExists(atPath: url.path) else { throw ObjectStoreError.alreadyExists }
        // `withoutOverwriting` makes the write create-only (it cannot be combined with `atomic`).
        do { try data.write(to: url, options: [.withoutOverwriting]) } catch {
            if FileManager.default.fileExists(atPath: url.path) { throw ObjectStoreError.alreadyExists }
            throw error
        }
    }

    public func read(name: String) async throws -> Data? {
        guard ObjectNames.isValid(name) else { throw ObjectStoreError.invalidName }
        return FileManager.default.contents(atPath: URL(fileURLWithPath: directory).appendingPathComponent(name).path)
    }
}

/// Azure Blob Storage with the workload's managed identity (Storage Blob Data Contributor on the one container; shared keys are disabled on the
/// account). Writes are `Put Blob` with `If-None-Match: *`, so they only ever create; the audit container additionally has a version-level
/// immutability (WORM) policy, so not even a principal with delete rights can remove or replace an object during retention.
public struct AzureBlobObjectStore: ObjectStore {
    /// Pinned Blob service version: the default of the GA Storage SDKs, deployed in every region but two canary regions on 2026-10-29 (Microsoft Learn, "Versioning for Azure
    /// Storage"). Tracked in CLAUDE.md "Current versions".
    public static let serviceVersion = "2026-10-06"

    let endpoint: String
    let container: String
    let tokens: any AccessTokenSource
    let http: any OutboundHTTP
    let now: @Sendable () -> Date

    public init(endpoint: String, container: String, tokens: any AccessTokenSource, http: any OutboundHTTP, now: @escaping @Sendable () -> Date = { Date() }) throws {
        guard let normalized = Self.normalizedEndpoint(endpoint), Self.isContainerName(container) else { throw ObjectStoreError.invalidName }
        self.endpoint = normalized
        self.container = container
        self.tokens = tokens
        self.http = http
        self.now = now
    }

    /// `https://<account>.blob.core.windows.net` without path, query or port.
    public static func normalizedEndpoint(_ raw: String) -> String? {
        guard let url = URL(string: raw), url.scheme == "https", let host = url.host?.lowercased(), host.hasSuffix(".blob.core.windows.net"),
              url.user == nil, url.query == nil, url.fragment == nil, url.port == nil, url.path.isEmpty || url.path == "/" else { return nil }
        return "https://\(host)"
    }

    /// Azure container naming: 3-63 lowercase letters, digits and single hyphens, starting and ending with a letter or digit.
    public static func isContainerName(_ name: String) -> Bool {
        (3...63).contains(name.count) && name.unicodeScalars.allSatisfy({ ("a"..."z").contains($0) || ("0"..."9").contains($0) || $0 == "-" })
            && name.first != "-" && name.last != "-" && !name.contains("--")
    }

    static func httpDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "GMT")
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss 'GMT'"
        return formatter.string(from: date)
    }

    private func url(_ name: String) -> String {
        let encoded = name.split(separator: "/").map { String($0).addingPercentEncoding(withAllowedCharacters: CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")) ?? String($0) }
        return "\(endpoint)/\(container)/\(encoded.joined(separator: "/"))"
    }

    public func create(name: String, data: Data, contentType: String) async throws {
        guard ObjectNames.isValid(name) else { throw ObjectStoreError.invalidName }
        let token = try await tokens.token(for: .storage)
        let response = try await http.send(method: .PUT, url: url(name), headers: [
            "Authorization": "Bearer \(token)",
            "x-ms-version": Self.serviceVersion,
            "x-ms-date": Self.httpDate(now()),
            "x-ms-blob-type": "BlockBlob",
            "If-None-Match": "*",
            "Content-Type": contentType,
        ], body: data)
        switch response.status {
        case 201: return
        case 409, 412: throw ObjectStoreError.alreadyExists // BlobAlreadyExists / ConditionNotMet; an immutable blob also answers 409
        default: throw ObjectStoreError.unavailable(status: response.status)
        }
    }

    public func read(name: String) async throws -> Data? {
        guard ObjectNames.isValid(name) else { throw ObjectStoreError.invalidName }
        let token = try await tokens.token(for: .storage)
        let response = try await http.send(method: .GET, url: url(name), headers: [
            "Authorization": "Bearer \(token)", "x-ms-version": Self.serviceVersion, "x-ms-date": Self.httpDate(now()),
        ], body: nil)
        switch response.status {
        case 200: return response.body
        case 404: return nil
        default: throw ObjectStoreError.unavailable(status: response.status)
        }
    }
}
