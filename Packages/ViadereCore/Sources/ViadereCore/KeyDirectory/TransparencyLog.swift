import Crypto
import Foundation

/// The log's identity in a tree head. Part of the signed bytes, so a head of another log never verifies.
public enum TransparencyLog {
    public static let defaultLogId = "viadere.key-directory.v1"
}

/// The decoded payload of a signed tree head (STH).
public struct TreeHead: Sendable, Hashable {
    public static let version: Int64 = 1

    public var logId: String
    public var treeSize: Int
    /// Lowercase hex of the 32-byte Merkle root.
    public var rootHash: String
    /// Unix seconds when the head was signed.
    public var timestamp: Int64

    public init(logId: String = TransparencyLog.defaultLogId, treeSize: Int, rootHash: Data, timestamp: Date) {
        self.logId = logId
        self.treeSize = treeSize
        self.rootHash = Hex.encode(rootHash)
        self.timestamp = ViadereDate.unixSeconds(timestamp)
    }

    init(logId: String, treeSize: Int, rootHash: String, timestamp: Int64) {
        self.logId = logId
        self.treeSize = treeSize
        self.rootHash = rootHash
        self.timestamp = timestamp
    }

    public var rootData: Data? { Hex.decode(rootHash).flatMap { $0.count == MerkleTree.hashLength ? $0 : nil } }
    public var date: Date { Date(timeIntervalSince1970: TimeInterval(timestamp)) }

    var object: [String: JSONValue] {
        ["v": .integer(Self.version), "log_id": .string(logId), "tree_size": .integer(Int64(treeSize)), "root_hash": .string(rootHash),
         "timestamp": .integer(timestamp)]
    }
}

/// A tree head signed by the Viadere log key: `{"payload": base64url(canonical JSON), "signature": base64url(raw r‖s)}`, signed over
/// `"VIADERE-STH-V1\n" ‖ payload`.
public struct SignedTreeHead: Sendable, Hashable, Codable {
    public var payload: String
    public var signature: String

    public init(payload: String, signature: String) {
        self.payload = payload
        self.signature = signature
    }

    public static func sign(_ head: TreeHead, with key: any DeviceSigningKey) async throws -> SignedTreeHead {
        let signed = try await SignedStatement.sign(head.object, domain: KeyDirectoryDomain.treeHead, with: key)
        return SignedTreeHead(payload: signed.payload, signature: signed.signature)
    }

    /// Verifies the signature against any of `logKeys` (several during a log-key rotation) and decodes the head strictly.
    public func verified(logKeys: [DevicePublicKey]) throws -> TreeHead {
        let statement = SignedStatement(payload: payload, signature: signature)
        guard logKeys.contains(where: { statement.isValid(domain: KeyDirectoryDomain.treeHead, publicKey: $0) }) else { throw KeyDirectoryError.treeHeadSignature }
        guard let o = statement.canonicalObject(), Set(o.keys) == ["v", "log_id", "tree_size", "root_hash", "timestamp"] else { throw KeyDirectoryError.malformed("tree head") }
        guard o["v"]?.int64Value == TreeHead.version else { throw KeyDirectoryError.unsupportedVersion(o["v"]?.int64Value ?? -1) }
        guard let logId = o["log_id"]?.stringValue, let size = o["tree_size"]?.int64Value, size >= 0, size < 1 << 40,
              let root = o["root_hash"]?.stringValue, root.utf8.count == 64, Hex.decode(root) != nil, root == root.lowercased(),
              let timestamp = o["timestamp"]?.int64Value, timestamp > 0 else { throw KeyDirectoryError.malformed("tree head members") }
        return TreeHead(logId: logId, treeSize: Int(size), rootHash: root, timestamp: timestamp)
    }
}

// MARK: Wire responses

/// An entry with its position and audit path.
public struct KeyLogEntryProof: Sendable, Hashable, Codable {
    public var index: Int
    /// base64url of the canonical entry bytes (the leaf data, preserved byte for byte).
    public var entry: String
    /// Hex hashes of the audit path.
    public var inclusionProof: [String]

    public init(index: Int, entry: String, inclusionProof: [String]) {
        self.index = index
        self.entry = entry
        self.inclusionProof = inclusionProof
    }
}

/// `GET /v1/key-directory/businesses/{businessId}` and `GET /v1/business/key-directory/entries`: the signed head, a consistency proof from
/// the head the caller last saw (`since` query), and every entry of the business with its audit path against that head.
public struct KeyDirectoryResponse: Sendable, Hashable, Codable {
    public var sth: SignedTreeHead
    /// Size the consistency proof starts from (echo of the request's `since`), when one was asked for and the log is larger.
    public var consistencyFrom: Int?
    public var consistencyProof: [String]?
    public var entries: [KeyLogEntryProof]

    public init(sth: SignedTreeHead, consistencyFrom: Int? = nil, consistencyProof: [String]? = nil, entries: [KeyLogEntryProof]) {
        self.sth = sth
        self.consistencyFrom = consistencyFrom
        self.consistencyProof = consistencyProof
        self.entries = entries
    }
}

public struct ConsistencyProofResponse: Sendable, Hashable, Codable {
    public var first: Int
    public var second: Int
    public var proof: [String]
    public init(first: Int, second: Int, proof: [String]) {
        self.first = first
        self.second = second
        self.proof = proof
    }
}

/// What a client remembers about the last log head it verified (the basis of the next consistency check).
public struct SeenTreeHead: Sendable, Hashable, Codable {
    public var treeSize: Int
    public var rootHash: String
    public var timestamp: Int64

    public init(treeSize: Int, rootHash: String, timestamp: Int64) {
        self.treeSize = treeSize
        self.rootHash = rootHash
        self.timestamp = timestamp
    }

    public init(_ head: TreeHead) {
        self.init(treeSize: head.treeSize, rootHash: head.rootHash, timestamp: head.timestamp)
    }
}
