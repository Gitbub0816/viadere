import Foundation
import ViadereCore

/// What the device keeps per business: the server's response exactly as received (so the manifest's signature is re-verified every time it
/// is loaded, never trusted because it is on disk), the response `ETag` for `If-None-Match`, and when it was fetched.
public struct CachedBrandRecord: Codable, Sendable, Equatable {
    public var response: BrandManifestResponse
    public var etag: String?
    public var fetchedAt: Date

    public init(response: BrandManifestResponse, etag: String?, fetchedAt: Date) {
        self.response = response
        self.etag = etag
        self.fetchedAt = fetchedAt
    }
}

/// Synchronous, small, local storage for brand manifests and verified assets (plan section 4.6 "Device cache"). Reads never touch the
/// network, so the notification service extension and any render path can use them without waiting on anything remote.
public protocol BrandKitCache: Sendable {
    func record(for business: BusinessID) -> CachedBrandRecord?
    func store(_ record: CachedBrandRecord, for business: BusinessID)
    func removeRecord(for business: BusinessID)
    /// Raw bytes previously stored under `sha256` (the caller re-verifies them against the reference before use).
    func asset(sha256: String) -> Data?
    func storeAsset(_ data: Data, sha256: String)
    func removeAsset(sha256: String)
    /// Sign-out, device revocation.
    func removeAll()
    /// Bytes currently used.
    var usedBytes: Int { get }
}

/// The on-disk cache in the app group (shared with the notification service extension): `manifests/{business}.json` and
/// `assets/{sha256}.png`, written atomically (stage, then swap; verification happens before anything is written), protected until first
/// unlock so the extension can read it, and kept under a byte budget by least-recently-used eviction (assets first, then records).
public final class FileBrandKitCache: BrandKitCache, @unchecked Sendable {
    /// Planning target (plan section 4.6, D6.3), revisited after measurement.
    public static let defaultByteBudget = 25 * 1024 * 1024

    private let root: URL
    private let byteBudget: Int
    private let lock = NSLock()
    private let files = FileManager.default

    public init(directory: URL, byteBudget: Int = FileBrandKitCache.defaultByteBudget) {
        root = directory
        self.byteBudget = byteBudget
        try? files.createDirectory(at: manifests, withIntermediateDirectories: true)
        try? files.createDirectory(at: assets, withIntermediateDirectories: true)
    }

    private var manifests: URL { root.appendingPathComponent("manifests", isDirectory: true) }
    private var assets: URL { root.appendingPathComponent("assets", isDirectory: true) }

    private func recordURL(_ business: BusinessID) -> URL { manifests.appendingPathComponent("\(business.description.lowercased()).json") }

    /// Only a lowercase 64-hex name can become a path (no traversal, no other files).
    private func assetURL(_ sha256: String) -> URL? {
        ContractHash.isLowerHex64(sha256) ? assets.appendingPathComponent("\(sha256).png") : nil
    }

    public func record(for business: BusinessID) -> CachedBrandRecord? {
        lock.lock(); defer { lock.unlock() }
        let url = recordURL(business)
        guard let data = try? Data(contentsOf: url) else { return nil }
        guard let record = try? ViadereJSON.decode(CachedBrandRecord.self, from: data), record.response.businessId == business else {
            try? files.removeItem(at: url)
            return nil
        }
        touch(url)
        return record
    }

    public func store(_ record: CachedBrandRecord, for business: BusinessID) {
        guard record.response.businessId == business, let data = try? ViadereJSON.encode(record) else { return }
        lock.lock(); defer { lock.unlock() }
        write(data, to: recordURL(business))
        evictIfNeeded(keeping: recordURL(business))
    }

    public func removeRecord(for business: BusinessID) {
        lock.lock(); defer { lock.unlock() }
        try? files.removeItem(at: recordURL(business))
    }

    public func asset(sha256: String) -> Data? {
        guard let url = assetURL(sha256) else { return nil }
        lock.lock(); defer { lock.unlock() }
        guard let data = try? Data(contentsOf: url) else { return nil }
        touch(url)
        return data
    }

    public func storeAsset(_ data: Data, sha256: String) {
        guard let url = assetURL(sha256), data.count <= byteBudget else { return }
        lock.lock(); defer { lock.unlock() }
        write(data, to: url)
        evictIfNeeded(keeping: url)
    }

    public func removeAsset(sha256: String) {
        guard let url = assetURL(sha256) else { return }
        lock.lock(); defer { lock.unlock() }
        try? files.removeItem(at: url)
    }

    public func removeAll() {
        lock.lock(); defer { lock.unlock() }
        for directory in [manifests, assets] {
            for url in (try? files.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) ?? [] { try? files.removeItem(at: url) }
        }
    }

    public var usedBytes: Int {
        lock.lock(); defer { lock.unlock() }
        return entries(assets).reduce(0) { $0 + $1.size } + entries(manifests).reduce(0) { $0 + $1.size }
    }

    // MARK: Internals (lock held)

    private func write(_ data: Data, to url: URL) {
        #if canImport(Darwin) && !os(macOS)
        try? data.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        #else
        try? data.write(to: url, options: [.atomic])
        #endif
    }

    private func touch(_ url: URL) {
        try? files.setAttributes([.modificationDate: Date()], ofItemAtPath: url.path)
    }

    private struct Entry { var url: URL; var size: Int; var used: Date }

    private func entries(_ directory: URL) -> [Entry] {
        let keys: [URLResourceKey] = [.fileSizeKey, .contentModificationDateKey]
        return ((try? files.contentsOfDirectory(at: directory, includingPropertiesForKeys: keys)) ?? []).compactMap { url in
            let values = try? url.resourceValues(forKeys: Set(keys))
            return Entry(url: url, size: values?.fileSize ?? 0, used: values?.contentModificationDate ?? .distantPast)
        }
    }

    /// Least recently used first; assets go before manifest records; the entry just written is kept.
    private func evictIfNeeded(keeping kept: URL) {
        let assetEntries = entries(assets)
        let recordEntries = entries(manifests)
        var total = assetEntries.reduce(0) { $0 + $1.size } + recordEntries.reduce(0) { $0 + $1.size }
        guard total > byteBudget else { return }
        let candidates = assetEntries.sorted { $0.used < $1.used } + recordEntries.sorted { $0.used < $1.used }
        for entry in candidates where total > byteBudget && entry.url.standardizedFileURL != kept.standardizedFileURL {
            try? files.removeItem(at: entry.url)
            total -= entry.size
        }
    }
}

/// An in-memory cache (previews, the mock world, tests that do not exercise the disk).
public final class InMemoryBrandKitCache: BrandKitCache, @unchecked Sendable {
    private let lock = NSLock()
    private var records: [BusinessID: CachedBrandRecord] = [:]
    private var blobs: [String: Data] = [:]

    public init() {}

    public func record(for business: BusinessID) -> CachedBrandRecord? { lock.lock(); defer { lock.unlock() }; return records[business] }
    public func store(_ record: CachedBrandRecord, for business: BusinessID) {
        guard record.response.businessId == business else { return }
        lock.lock(); defer { lock.unlock() }
        records[business] = record
    }
    public func removeRecord(for business: BusinessID) { lock.lock(); defer { lock.unlock() }; records[business] = nil }
    public func asset(sha256: String) -> Data? { lock.lock(); defer { lock.unlock() }; return blobs[sha256] }
    public func storeAsset(_ data: Data, sha256: String) {
        guard ContractHash.isLowerHex64(sha256) else { return }
        lock.lock(); defer { lock.unlock() }
        blobs[sha256] = data
    }
    public func removeAsset(sha256: String) { lock.lock(); defer { lock.unlock() }; blobs[sha256] = nil }
    public func removeAll() { lock.lock(); defer { lock.unlock() }; records = [:]; blobs = [:] }
    public var usedBytes: Int { lock.lock(); defer { lock.unlock() }; return blobs.values.reduce(0) { $0 + $1.count } }

    /// Test hook: replace stored bytes (tampering on disk).
    public func overwriteAsset(_ data: Data, sha256: String) { lock.lock(); defer { lock.unlock() }; blobs[sha256] = data }
}
