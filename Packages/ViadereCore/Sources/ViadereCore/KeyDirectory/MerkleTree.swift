import Crypto
import Foundation

/// An RFC 6962 / RFC 9162 Merkle hash tree over SHA-256: leaf hash `SHA-256(0x00 ‖ data)`, node hash `SHA-256(0x01 ‖ left ‖ right)`, the
/// empty tree `SHA-256("")`. The split point of a list of `n > 1` entries is the largest power of two smaller than `n`.
///
/// This type holds the leaf **hashes** (32 bytes each) and produces roots, inclusion proofs and consistency proofs for any prefix size.
/// The verification functions are static and need no tree: devices and monitors hold only roots and proofs.
public struct MerkleTree: Sendable {
    public static let hashLength = 32

    public private(set) var leafHashes: [Data]

    public init(leafHashes: [Data] = []) {
        self.leafHashes = leafHashes
    }

    public var size: Int { leafHashes.count }

    public mutating func append(leafData: Data) { leafHashes.append(Self.leafHash(leafData)) }
    public mutating func append(leafHash: Data) { leafHashes.append(leafHash) }

    // MARK: Hashing

    public static func leafHash(_ data: Data) -> Data {
        var hasher = SHA256()
        hasher.update(data: [0x00])
        hasher.update(data: data)
        return Data(hasher.finalize())
    }

    public static func nodeHash(_ left: Data, _ right: Data) -> Data {
        var hasher = SHA256()
        hasher.update(data: [0x01])
        hasher.update(data: left)
        hasher.update(data: right)
        return Data(hasher.finalize())
    }

    public static let emptyRoot = Data(SHA256.hash(data: Data()))

    /// Largest power of two strictly smaller than `n` (`n >= 2`).
    static func split(_ n: Int) -> Int {
        var k = 1
        while k << 1 < n { k <<= 1 }
        return k
    }

    // MARK: Roots and proofs (prefix `size`)

    /// MTH of the first `size` leaves.
    public func root(size: Int? = nil) -> Data {
        let size = size ?? leafHashes.count
        precondition(size >= 0 && size <= leafHashes.count)
        return size == 0 ? Self.emptyRoot : mth(0, size)
    }

    private func mth(_ lo: Int, _ hi: Int) -> Data {
        if hi - lo == 1 { return leafHashes[lo] }
        let k = Self.split(hi - lo)
        return Self.nodeHash(mth(lo, lo + k), mth(lo + k, hi))
    }

    /// The audit path of leaf `index` in the tree of the first `size` leaves (RFC 6962 section 2.1.1).
    public func inclusionProof(index: Int, size: Int) -> [Data]? {
        guard index >= 0, index < size, size <= leafHashes.count else { return nil }
        return path(index, 0, size)
    }

    private func path(_ m: Int, _ lo: Int, _ hi: Int) -> [Data] {
        if hi - lo == 1 { return [] }
        let k = Self.split(hi - lo)
        if m < k { return path(m, lo, lo + k) + [mth(lo + k, hi)] }
        return path(m - k, lo + k, hi) + [mth(lo, lo + k)]
    }

    /// The proof that the tree of the first `first` leaves is a prefix of the tree of the first `second` leaves (RFC 6962 section 2.1.2).
    public func consistencyProof(first: Int, second: Int) -> [Data]? {
        guard first > 0, first <= second, second <= leafHashes.count else { return nil }
        if first == second { return [] }
        return subProof(first, 0, second, complete: true)
    }

    private func subProof(_ m: Int, _ lo: Int, _ hi: Int, complete: Bool) -> [Data] {
        let n = hi - lo
        if m == n { return complete ? [] : [mth(lo, hi)] }
        let k = Self.split(n)
        if m <= k { return subProof(m, lo, lo + k, complete: complete) + [mth(lo + k, hi)] }
        return subProof(m - k, lo + k, hi, complete: false) + [mth(lo, lo + k)]
    }

    // MARK: Verification (RFC 9162 section 2.1.3.2 and 2.1.4.2)

    /// Whether `leafHash` is leaf `index` of the tree of `treeSize` leaves with root `root`.
    public static func verifyInclusion(leafHash: Data, index: Int, treeSize: Int, proof: [Data], root: Data) -> Bool {
        guard index >= 0, index < treeSize, leafHash.count == hashLength, root.count == hashLength, proof.allSatisfy({ $0.count == hashLength }),
              proof.count <= 64 else { return false }
        var fn = index
        var sn = treeSize - 1
        var r = leafHash
        for p in proof {
            if sn == 0 { return false }
            if fn & 1 == 1 || fn == sn {
                r = nodeHash(p, r)
                if fn & 1 == 0 {
                    while fn & 1 == 0 && fn != 0 {
                        fn >>= 1
                        sn >>= 1
                    }
                }
            } else {
                r = nodeHash(r, p)
            }
            fn >>= 1
            sn >>= 1
        }
        return sn == 0 && ConstantTime.equals(r, root)
    }

    /// Whether the tree with root `firstRoot` and `first` leaves is a prefix of the tree with root `secondRoot` and `second` leaves.
    public static func verifyConsistency(first: Int, second: Int, firstRoot: Data, secondRoot: Data, proof: [Data]) -> Bool {
        guard first >= 0, second >= first, firstRoot.count == hashLength, secondRoot.count == hashLength,
              proof.allSatisfy({ $0.count == hashLength }), proof.count <= 128 else { return false }
        if first == second { return proof.isEmpty && ConstantTime.equals(firstRoot, secondRoot) }
        // The empty tree is a prefix of every tree.
        if first == 0 { return proof.isEmpty && ConstantTime.equals(firstRoot, emptyRoot) }
        var nodes = proof
        if first & (first - 1) == 0 { nodes.insert(firstRoot, at: 0) }
        guard !nodes.isEmpty else { return false }
        var fn = first - 1
        var sn = second - 1
        while fn & 1 == 1 {
            fn >>= 1
            sn >>= 1
        }
        var fr = nodes[0]
        var sr = nodes[0]
        for c in nodes.dropFirst() {
            if sn == 0 { return false }
            if fn & 1 == 1 || fn == sn {
                fr = nodeHash(c, fr)
                sr = nodeHash(c, sr)
                if fn & 1 == 0 {
                    while fn & 1 == 0 && fn != 0 {
                        fn >>= 1
                        sn >>= 1
                    }
                }
            } else {
                sr = nodeHash(sr, c)
            }
            fn >>= 1
            sn >>= 1
        }
        return sn == 0 && ConstantTime.equals(fr, firstRoot) && ConstantTime.equals(sr, secondRoot)
    }
}
