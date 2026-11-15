import Fluent
import FluentSQL
import Foundation
import SQLKit
import ViadereCore

/// In-memory copy of the leaf hashes of the transparency log, extended from the database as the log grows. The log is append-only, so
/// a cached prefix never becomes wrong; another instance's appends are picked up on the next `sync`.
actor KeyLogTreeCache {
    private var tree = MerkleTree()

    func sync(on db: any Database) async throws -> MerkleTree {
        let known = tree.size
        let rows = try await KDLogEntryRecord.query(on: db).filter(\.$idx >= known).sort(\.$idx, .ascending).all()
        for row in rows {
            // A gap would mean the table was altered outside the application: refuse to serve a tree that does not match the log.
            guard row.idx == tree.size, let hash = Hex.decode(row.leafHash), hash.count == MerkleTree.hashLength else { throw APIError.internalError }
            tree.append(leafHash: hash)
        }
        return tree
    }
}

/// The business key directory's transparency log: appends signed entries, signs tree heads with the Viadere log key, serves entries with
/// inclusion proofs and consistency proofs.
struct KeyLogService {
    let db: any Database
    let ctx: ServerContext

    static let maxEntriesPerBusiness = 1000

    // MARK: Tree

    func tree() async throws -> MerkleTree { try await ctx.keyLogCache.sync(on: db) }

    // MARK: Heads

    /// The head for the current tree. A new one is signed when none covers the current size or the latest is older than the refresh
    /// interval, so the head a client sees is always fresh (clients refuse heads older than a week) and always covers every entry.
    func currentHead() async throws -> SignedTreeHead {
        let tree = try await tree()
        let now = ctx.now
        if let latest = try await KDTreeHeadRecord.query(on: db).sort(\.$treeSize, .descending).sort(\.$createdAt, .descending).first(), latest.treeSize == tree.size,
           now.timeIntervalSince(latest.createdAt) < ctx.config.approve.treeHeadRefreshInterval, latest.createdAt <= now {
            return latest.signed
        }
        return try await signHead(of: tree)
    }

    @discardableResult
    func signHead(of tree: MerkleTree) async throws -> SignedTreeHead {
        let now = ctx.now
        let root = tree.root()
        let head = try await SignedTreeHead.sign(TreeHead(logId: ctx.config.approve.logId, treeSize: tree.size, rootHash: root, timestamp: now),
                                                 with: ctx.config.approve.logKey)
        try await KDTreeHeadRecord(head: head, treeSize: tree.size, rootHash: Hex.encode(root), now: now).create(on: db)
        return head
    }

    // MARK: Entries

    func state(for businessId: UUID) async throws -> BusinessKeyState {
        var state = BusinessKeyState(businessId: BusinessID(businessId))
        for row in try await KDLogEntryRecord.query(on: db).filter(\.$businessId == businessId).sort(\.$idx, .ascending).all() {
            guard let bytes = Base64URL.decode(row.entry), let entry = try? KeyLogEntry.parse(bytes) else { throw APIError.internalError }
            do { try state.apply(entry, index: row.idx) } catch {
                // The log holds only entries that passed the same rules on the way in: a failure here is corruption, not user input.
                ctx.logger.error("key log replay failed", metadata: ["type": "\(type(of: error))"])
                throw APIError.internalError
            }
        }
        return state
    }

    func count(for businessId: UUID) async throws -> Int {
        try await KDLogEntryRecord.query(on: db).filter(\.$businessId == businessId).count()
    }

    /// Appends one validated entry and returns its index and a head that covers it. The caller already checked the entry against the
    /// business's replayed state; appends are serialized (advisory lock on PostgreSQL, unique `idx` everywhere) so the log never forks.
    func append(_ entry: KeyLogEntry, bytes: Data) async throws -> (index: Int, head: SignedTreeHead) {
        let leaf = MerkleTree.leafHash(bytes)
        let now = ctx.now
        let index: Int = try await DB.retryingTransient {
            try await db.transaction { tx in
                if DB.isPostgres(tx), let sql = tx as? any SQLDatabase { try await sql.raw("SELECT pg_advisory_xact_lock(746175)").run() }
                let next = try await KDLogEntryRecord.query(on: tx).count()
                try await KDLogEntryRecord(idx: next, businessId: entry.businessId.uuid, entryType: entry.type, entry: Base64URL.encode(bytes),
                                           leafHash: Hex.encode(leaf), now: now).create(on: tx)
                return next
            }
        }
        let head = try await signHead(of: try await tree())
        return (index, head)
    }

    // MARK: Responses

    /// Every entry of `businessId` with its audit path against the current head, plus the consistency proof from `since` when asked.
    func response(for businessId: UUID, since: Int?) async throws -> KeyDirectoryResponse {
        let head = try await currentHead()
        let tree = try await tree()
        // The head covers the whole tree (`currentHead` signs a new one whenever the size changed).
        guard let size = Optional(tree.size), let proofSize = try? head.verified(logKeys: [ctx.config.approve.logKey.publicKey]).treeSize, proofSize == size else {
            throw APIError.internalError
        }
        var consistencyFrom: Int?
        var consistency: [String]?
        if let since, since > 0, since < size, let proof = tree.consistencyProof(first: since, second: size) {
            consistencyFrom = since
            consistency = proof.map(Hex.encode)
        }
        let rows = try await KDLogEntryRecord.query(on: db).filter(\.$businessId == businessId).sort(\.$idx, .ascending).all()
        let items = try rows.map { row -> KeyLogEntryProof in
            guard let path = tree.inclusionProof(index: row.idx, size: size) else { throw APIError.internalError }
            return KeyLogEntryProof(index: row.idx, entry: row.entry, inclusionProof: path.map(Hex.encode))
        }
        return KeyDirectoryResponse(sth: head, consistencyFrom: consistencyFrom, consistencyProof: consistency, entries: items)
    }

    func consistency(first: Int, second: Int) async throws -> ConsistencyProofResponse {
        let tree = try await tree()
        guard first >= 1, first <= second, second <= tree.size, let proof = tree.consistencyProof(first: first, second: second) else {
            throw APIError.validation("The tree sizes are invalid.", details: ["first": "invalid", "second": "invalid"])
        }
        return ConsistencyProofResponse(first: first, second: second, proof: proof.map(Hex.encode))
    }
}
