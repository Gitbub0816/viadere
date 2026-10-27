import Crypto
import Foundation

/// One epoch of a business's root key: from its registration (or the succession that introduced it) until the next succession.
public struct RootEpoch: Sendable, Hashable {
    public var kid: String
    public var publicKey: DevicePublicKey
    /// Log index of the entry that made it the root.
    public var sinceIndex: Int
}

/// An operational key as published by the business's root.
public struct DirectoryKey: Sendable, Hashable {
    public var purpose: BusinessKeyPurpose
    public var kid: String
    /// X9.63.
    public var publicKeyBytes: Data
    public var notBefore: Int64
    public var notAfter: Int64
    public var serial: Int64
    public var revokedAt: Int64?
    public var rootKid: String

    /// Whether the key may be used at `now`: inside its validity window and not revoked.
    public func isValid(at now: Date) -> Bool {
        let t = ViadereDate.unixSeconds(now)
        return revokedAt == nil && t >= notBefore && t < notAfter
    }

    public var signingKey: DevicePublicKey? { try? DevicePublicKey(bytes: publicKeyBytes) }
    public var encryptionKey: E2EEPublicKey? { try? E2EEPublicKey(x963: publicKeyBytes) }
}

/// A business's key history replayed from its log entries.
///
/// Rules (each violation throws a `KeyDirectoryError`): the first entry is the root registration; `key` and `revoke` statements are signed
/// by the **current** root and carry `serial = previous + 1` (a missing statement is a gap); a `root-succession` is signed by both old and
/// new roots and starts a new epoch in which **no key is valid until the new root publishes it** (a root change is a clean break, never a
/// silent inheritance); a key's validity window is at most `KeyPublication.maxValidity`; `kid` values are never reused.
public struct BusinessKeyState: Sendable {
    public let businessId: BusinessID
    public private(set) var roots: [RootEpoch] = []
    public private(set) var keys: [String: DirectoryKey] = [:]
    public private(set) var lastSerial: Int64 = 0
    public private(set) var lastIndex: Int = -1
    private var seenKids: Set<String> = []

    public init(businessId: BusinessID) { self.businessId = businessId }

    public var currentRoot: RootEpoch? { roots.last }

    /// Keys of the current epoch valid at `now` for `purpose`, newest `not_before` first.
    public func validKeys(for purpose: BusinessKeyPurpose, at now: Date) -> [DirectoryKey] {
        keys.values.filter { $0.purpose == purpose && $0.isValid(at: now) }.sorted { ($0.notBefore, $0.serial) > ($1.notBefore, $1.serial) }
    }

    /// The key `kid` if it is valid at `now` for `purpose`.
    public func validKey(kid: String, purpose: BusinessKeyPurpose, at now: Date) -> DirectoryKey? {
        keys[kid].flatMap { $0.purpose == purpose && $0.isValid(at: now) ? $0 : nil }
    }

    /// Applies the next entry of the business's history (strictly in log order). Throws on any rule violation; the state is unchanged then.
    public mutating func apply(_ entry: KeyLogEntry, index: Int) throws {
        var next = self
        try next.applyUnchecked(entry, index: index)
        self = next
    }

    private mutating func applyUnchecked(_ entry: KeyLogEntry, index: Int) throws {
        guard entry.businessId == businessId else { throw KeyDirectoryError.wrongBusiness }
        let statement = try entry.decodeStatement()
        switch statement {
        case .root(let value):
            guard roots.isEmpty else { throw KeyDirectoryError.rootAlreadyRegistered }
            try entry.verifySignatures(of: statement, signer: value.publicKey)
            roots.append(RootEpoch(kid: value.rootKid, publicKey: value.publicKey, sinceIndex: index))
            seenKids.insert(value.rootKid)
        case .succession(let value):
            guard let current = currentRoot else { throw KeyDirectoryError.noRoot }
            guard value.oldRootKid == current.kid else { throw KeyDirectoryError.rootMismatch }
            guard !seenKids.contains(value.newRootKid) else { throw KeyDirectoryError.duplicateKey }
            try entry.verifySignatures(of: statement, signer: current.publicKey)
            roots.append(RootEpoch(kid: value.newRootKid, publicKey: value.newPublicKey, sinceIndex: index))
            seenKids.insert(value.newRootKid)
            keys = [:]
        case .key(let value):
            guard let current = currentRoot else { throw KeyDirectoryError.noRoot }
            guard value.rootKid == current.kid else { throw KeyDirectoryError.rootMismatch }
            try entry.verifySignatures(of: statement, signer: current.publicKey)
            guard value.serial == lastSerial + 1 else { throw KeyDirectoryError.serialOutOfOrder(expected: lastSerial + 1, got: value.serial) }
            guard value.notAfter > value.notBefore, TimeInterval(value.notAfter - value.notBefore) <= KeyPublication.maxValidity else {
                throw KeyDirectoryError.invalidValidity("window")
            }
            guard !seenKids.contains(value.kid) else { throw KeyDirectoryError.duplicateKey }
            guard let bytes = value.publicKeyBytes else { throw KeyDirectoryError.invalidKey("public_key") }
            keys[value.kid] = DirectoryKey(purpose: value.purpose, kid: value.kid, publicKeyBytes: bytes, notBefore: value.notBefore,
                                           notAfter: value.notAfter, serial: value.serial, revokedAt: nil, rootKid: value.rootKid)
            seenKids.insert(value.kid)
            lastSerial = value.serial
        case .revocation(let value):
            guard let current = currentRoot else { throw KeyDirectoryError.noRoot }
            guard value.rootKid == current.kid else { throw KeyDirectoryError.rootMismatch }
            try entry.verifySignatures(of: statement, signer: current.publicKey)
            guard value.serial == lastSerial + 1 else { throw KeyDirectoryError.serialOutOfOrder(expected: lastSerial + 1, got: value.serial) }
            guard var key = keys[value.kid] else { throw KeyDirectoryError.unknownKey }
            if key.revokedAt == nil { key.revokedAt = value.revokedAt }
            keys[value.kid] = key
            lastSerial = value.serial
        }
        lastIndex = index
    }
}

/// A key directory response whose every claim checked out.
public struct VerifiedDirectory: Sendable {
    public var head: TreeHead
    public var state: BusinessKeyState
}

/// Where a business's current root stands relative to what the client pinned.
public enum RootPinStatus: Sendable, Equatable {
    /// The business has no root in the log.
    case noRoot
    /// Nothing pinned yet: the current root is a candidate to pin (trust on first use, with the log as witness).
    case firstUse(rootKid: String)
    case unchanged
    /// The pinned root was superseded by a valid, doubly signed succession. Still **alert the person and require re-confirmation**.
    case rotated(pinnedKid: String, currentKid: String)
    /// The pinned root does not appear in this business's history: the directory is showing a different root. Refuse.
    case conflict(pinnedKid: String, currentKid: String)
}

/// A root key a device (or monitor) pinned.
public struct PinnedRoot: Sendable, Hashable, Codable {
    public var businessId: BusinessID
    public var rootKid: String
    public var publicKey: DevicePublicKey
    public var pinnedAt: Int64

    public init(businessId: BusinessID, rootKid: String, publicKey: DevicePublicKey, pinnedAt: Date) {
        self.businessId = businessId
        self.rootKid = rootKid
        self.publicKey = publicKey
        self.pinnedAt = ViadereDate.unixSeconds(pinnedAt)
    }

    public init(from epoch: RootEpoch, businessId: BusinessID, at now: Date) {
        self.init(businessId: businessId, rootKid: epoch.kid, publicKey: epoch.publicKey, pinnedAt: now)
    }
}

/// Verifies key directory responses (devices, business monitors, tests). Pure: no network, no storage.
public struct KeyDirectoryVerifier: Sendable {
    /// Public keys of the Viadere log (several during a log-key rotation). Pinned in the app build, never taken from the response.
    public var logKeys: [DevicePublicKey]
    public var logId: String
    /// A tree head older than this is refused (a relay cannot freeze the view of the log indefinitely).
    public var maxHeadAge: TimeInterval
    public var allowedFutureSkew: TimeInterval

    public init(logKeys: [DevicePublicKey], logId: String = TransparencyLog.defaultLogId, maxHeadAge: TimeInterval = 7 * 86_400,
                allowedFutureSkew: TimeInterval = 300) {
        self.logKeys = logKeys
        self.logId = logId
        self.maxHeadAge = maxHeadAge
        self.allowedFutureSkew = allowedFutureSkew
    }

    /// Verifies a response for `businessId`: tree-head signature and freshness, **consistency with the head the caller saw last** (no
    /// rollback, no fork), an inclusion proof for every entry, and the replayed key history.
    public func verify(_ response: KeyDirectoryResponse, businessId: BusinessID, lastSeen: SeenTreeHead?, now: Date) throws -> VerifiedDirectory {
        let head = try response.sth.verified(logKeys: logKeys)
        guard head.logId == logId else { throw KeyDirectoryError.wrongLog }
        guard head.date <= now.addingTimeInterval(allowedFutureSkew) else { throw KeyDirectoryError.treeHeadFromFuture }
        guard now.timeIntervalSince(head.date) <= maxHeadAge else { throw KeyDirectoryError.treeHeadStale }
        guard let root = head.rootData else { throw KeyDirectoryError.malformed("root_hash") }

        if let last = lastSeen, last.treeSize > 0 {
            guard let lastRoot = Hex.decode(last.rootHash), lastRoot.count == MerkleTree.hashLength else { throw KeyDirectoryError.malformed("last root") }
            if head.treeSize < last.treeSize { throw KeyDirectoryError.treeShrank }
            if head.treeSize == last.treeSize {
                guard ConstantTime.equals(lastRoot, root) else { throw KeyDirectoryError.forkDetected }
            } else {
                guard response.consistencyFrom == last.treeSize, let hexProof = response.consistencyProof else { throw KeyDirectoryError.consistencyProofMissing }
                let proof = try hexProof.map { try Self.hash($0) }
                guard MerkleTree.verifyConsistency(first: last.treeSize, second: head.treeSize, firstRoot: lastRoot, secondRoot: root, proof: proof) else {
                    throw KeyDirectoryError.consistencyFailed
                }
            }
        }

        // Strictly ascending positions, checked before anything is applied: history is replayed in log order only.
        guard zip(response.entries, response.entries.dropFirst()).allSatisfy({ $0.index < $1.index }), response.entries.first.map({ $0.index >= 0 }) ?? true else {
            throw KeyDirectoryError.entriesOutOfOrder
        }
        var state = BusinessKeyState(businessId: businessId)
        for item in response.entries {
            guard item.index < head.treeSize, item.inclusionProof.count <= 64, let bytes = Base64URL.decode(item.entry), bytes.count <= KeyLogEntry.maxBytes else {
                throw KeyDirectoryError.inclusionFailed(index: item.index)
            }
            let path = try item.inclusionProof.map { try Self.hash($0) }
            guard MerkleTree.verifyInclusion(leafHash: MerkleTree.leafHash(bytes), index: item.index, treeSize: head.treeSize, proof: path, root: root) else {
                throw KeyDirectoryError.inclusionFailed(index: item.index)
            }
            try state.apply(try KeyLogEntry.parse(bytes), index: item.index)
        }
        return VerifiedDirectory(head: head, state: state)
    }

    static func hash(_ hex: String) throws -> Data {
        guard hex.utf8.count == 64, let data = Hex.decode(hex) else { throw KeyDirectoryError.malformed("hash") }
        return data
    }

    /// Compares the replayed state with the pinned root.
    public static func pinStatus(pin: PinnedRoot?, state: BusinessKeyState) -> RootPinStatus {
        guard let current = state.currentRoot else { return .noRoot }
        guard let pin else { return .firstUse(rootKid: current.kid) }
        if pin.rootKid == current.kid && pin.publicKey == current.publicKey { return .unchanged }
        if state.roots.dropLast().contains(where: { $0.kid == pin.rootKid && $0.publicKey == pin.publicKey }) {
            return .rotated(pinnedKid: pin.rootKid, currentKid: current.kid)
        }
        return .conflict(pinnedKid: pin.rootKid, currentKid: current.kid)
    }
}
