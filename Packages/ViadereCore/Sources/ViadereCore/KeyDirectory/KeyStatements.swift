import Crypto
import Foundation

/// What a business operational key is for (SEC-CR-008: one key, one purpose).
public enum BusinessKeyPurpose: String, Sendable, Codable, CaseIterable, Hashable {
    /// ES256 key that signs the business's confirmation of a customer's approval-key enrollment.
    case approvalEnrollmentConfirmation = "approval-enrollment-confirmation"
    /// ES256 key that signs approval requests (`ApprovalRequest`), so a device can tell the business from the relay.
    case approvalRequestSigning = "approval-request-signing"
    /// HPKE (P-256) key customers' devices encrypt to.
    case hpkeEncryption = "hpke-encryption"

    /// The algorithm identifier a statement for this purpose must carry.
    public var algorithm: String {
        switch self {
        case .approvalEnrollmentConfirmation, .approvalRequestSigning: "ES256"
        case .hpkeEncryption: E2EESuite.p256HKDFSHA256AES256GCM.rawValue
        }
    }
}

/// Domain separators of the directory's signatures.
public enum KeyDirectoryDomain {
    public static let root = "VIADERE-KD-ROOT-V1\n"
    public static let succession = "VIADERE-KD-SUCC-V1\n"
    public static let key = "VIADERE-KD-KEY-V1\n"
    public static let revoke = "VIADERE-KD-REVOKE-V1\n"
    public static let treeHead = "VIADERE-STH-V1\n"
}

/// Why a directory statement or entry was refused.
public enum KeyDirectoryError: Error, Sendable, Equatable {
    case malformed(String)
    case unsupportedVersion(Int64)
    case invalidSignature(String)
    case invalidKey(String)
    case wrongBusiness
    /// No root is registered (or a statement came before the root).
    case noRoot
    case rootAlreadyRegistered
    case rootMismatch
    case serialOutOfOrder(expected: Int64, got: Int64)
    case unknownKey
    case duplicateKey
    case invalidValidity(String)
    // Log proofs
    case treeHeadSignature
    case treeHeadStale
    case treeHeadFromFuture
    case treeShrank
    case forkDetected
    case inclusionFailed(index: Int)
    case consistencyFailed
    case consistencyProofMissing
    case entriesOutOfOrder
    case wrongLog
}

/// A parsed, signature-checked statement in a business's key history.
public enum KeyStatement: Sendable, Hashable {
    /// The business's long-term root key, proven by a self-signature.
    case root(RootRegistration)
    /// A hand-over from the old root to a new one, signed by both.
    case succession(RootSuccession)
    /// An operational key, signed by the current root.
    case key(KeyPublication)
    case revocation(KeyRevocation)

    public var kind: String {
        switch self {
        case .root: "root"
        case .succession: "root-succession"
        case .key: "key"
        case .revocation: "revoke"
        }
    }
}

public struct RootRegistration: Sendable, Hashable {
    public var businessId: BusinessID
    public var rootKid: String
    public var publicKey: DevicePublicKey
    /// Unix seconds.
    public var createdAt: Int64

    public init(businessId: BusinessID, publicKey: DevicePublicKey, createdAt: Date) {
        self.businessId = businessId
        self.publicKey = publicKey
        rootKid = KeyIdentifier.make((try? publicKey.signingKey())!)
        self.createdAt = ViadereDate.unixSeconds(createdAt)
    }

    var object: [String: JSONValue] {
        ["v": .integer(1), "type": .string("root"), "business_id": .string(businessId.description), "root_kid": .string(rootKid),
         "public_key": .string(publicKey.base64URL), "created_at": .integer(createdAt)]
    }
}

public struct RootSuccession: Sendable, Hashable {
    public var businessId: BusinessID
    public var oldRootKid: String
    public var newRootKid: String
    public var newPublicKey: DevicePublicKey
    public var createdAt: Int64

    public init(businessId: BusinessID, oldRootKid: String, newPublicKey: DevicePublicKey, createdAt: Date) {
        self.businessId = businessId
        self.oldRootKid = oldRootKid
        self.newPublicKey = newPublicKey
        newRootKid = KeyIdentifier.make((try? newPublicKey.signingKey())!)
        self.createdAt = ViadereDate.unixSeconds(createdAt)
    }

    var object: [String: JSONValue] {
        ["v": .integer(1), "type": .string("root-succession"), "business_id": .string(businessId.description),
         "old_root_kid": .string(oldRootKid), "new_root_kid": .string(newRootKid), "new_public_key": .string(newPublicKey.base64URL),
         "created_at": .integer(createdAt)]
    }
}

/// A root-signed operational key with its validity window. `serial` increases by exactly one per key or revocation statement of a
/// business, so a missing statement shows up as a gap.
public struct KeyPublication: Sendable, Hashable {
    /// Longest validity a statement may claim (rotation keeps keys short-lived; revocation covers the rest).
    public static let maxValidity: TimeInterval = 400 * 86_400

    public var businessId: BusinessID
    public var rootKid: String
    public var purpose: BusinessKeyPurpose
    public var kid: String
    /// X9.63 (65 bytes), base64url.
    public var publicKey: String
    public var notBefore: Int64
    public var notAfter: Int64
    public var serial: Int64

    /// - Throws: `KeyDirectoryError.invalidKey` unless `publicKey` is a P-256 point.
    public init(businessId: BusinessID, rootKid: String, purpose: BusinessKeyPurpose, publicKey: Data, notBefore: Date, notAfter: Date, serial: Int64) throws {
        self.businessId = businessId
        self.rootKid = rootKid
        self.purpose = purpose
        kid = try KeyIdentifier.make(p256X963: publicKey)
        self.publicKey = Base64URL.encode(publicKey)
        self.notBefore = ViadereDate.unixSeconds(notBefore)
        self.notAfter = ViadereDate.unixSeconds(notAfter)
        self.serial = serial
    }

    init(businessId: BusinessID, rootKid: String, purpose: BusinessKeyPurpose, kid: String, publicKey: String, notBefore: Int64, notAfter: Int64, serial: Int64) {
        self.businessId = businessId
        self.rootKid = rootKid
        self.purpose = purpose
        self.kid = kid
        self.publicKey = publicKey
        self.notBefore = notBefore
        self.notAfter = notAfter
        self.serial = serial
    }

    var object: [String: JSONValue] {
        ["v": .integer(1), "type": .string("key"), "business_id": .string(businessId.description), "root_kid": .string(rootKid),
         "purpose": .string(purpose.rawValue), "alg": .string(purpose.algorithm), "kid": .string(kid), "public_key": .string(publicKey),
         "not_before": .integer(notBefore), "not_after": .integer(notAfter), "serial": .integer(serial)]
    }

    /// The key's X9.63 bytes.
    public var publicKeyBytes: Data? { Base64URL.decode(publicKey) }
}

public struct KeyRevocation: Sendable, Hashable {
    public static let reasons: Set<String> = ["superseded", "compromised", "retired"]

    public var businessId: BusinessID
    public var rootKid: String
    public var kid: String
    public var reason: String
    public var revokedAt: Int64
    public var serial: Int64

    public init(businessId: BusinessID, rootKid: String, kid: String, reason: String, revokedAt: Date, serial: Int64) {
        self.businessId = businessId
        self.rootKid = rootKid
        self.kid = kid
        self.reason = reason
        self.revokedAt = ViadereDate.unixSeconds(revokedAt)
        self.serial = serial
    }

    var object: [String: JSONValue] {
        ["v": .integer(1), "type": .string("revoke"), "business_id": .string(businessId.description), "root_kid": .string(rootKid),
         "kid": .string(kid), "reason": .string(reason), "revoked_at": .integer(revokedAt), "serial": .integer(serial)]
    }
}

/// One entry of the transparency log: the canonical bytes of this object are the log leaf.
///
/// ```json
/// {"business_id":"…","sigs":["<base64url r‖s>", …],"statement":"<base64url canonical payload>","type":"key","v":1}
/// ```
public struct KeyLogEntry: Sendable, Hashable {
    public static let version: Int64 = 1
    public static let maxBytes = 16 * 1024

    public var type: String
    public var businessId: BusinessID
    public var statement: String
    public var signatures: [String]

    public init(type: String, businessId: BusinessID, statement: String, signatures: [String]) {
        self.type = type
        self.businessId = businessId
        self.statement = statement
        self.signatures = signatures
    }

    /// The leaf data: canonical JSON.
    public func leafData() throws -> Data {
        try CanonicalJSON.serialize(.object(["v": .integer(Self.version), "type": .string(type), "business_id": .string(businessId.description),
                                             "statement": .string(statement), "sigs": .array(signatures.map(JSONValue.string))]))
    }

    public var leafHash: Data? { (try? leafData()).map(MerkleTree.leafHash) }

    /// Strict parse of leaf bytes.
    public static func parse(_ data: Data) throws -> KeyLogEntry {
        guard data.count <= maxBytes, case .object(let o)? = try? JSONDecoder().decode(JSONValue.self, from: data) else { throw KeyDirectoryError.malformed("entry") }
        guard case .integer(let v)? = o["v"] else { throw KeyDirectoryError.malformed("v") }
        guard v == version else { throw KeyDirectoryError.unsupportedVersion(v) }
        guard Set(o.keys) == ["v", "type", "business_id", "statement", "sigs"], let type = o["type"]?.stringValue,
              ["root", "root-succession", "key", "revoke"].contains(type), let business = o["business_id"]?.stringValue.flatMap(BusinessID.init),
              let statement = o["statement"]?.stringValue, case .array(let sigs)? = o["sigs"], sigs.count == (type == "root-succession" ? 2 : 1),
              sigs.allSatisfy({ $0.stringValue != nil }) else { throw KeyDirectoryError.malformed("entry members") }
        let entry = KeyLogEntry(type: type, businessId: business, statement: statement, signatures: sigs.compactMap(\.stringValue))
        guard try entry.leafData() == data else { throw KeyDirectoryError.malformed("not canonical") }
        return entry
    }

    // MARK: Statement parsing and signature checks

    /// Decodes and strictly validates the statement (shape, kid derivation, algorithm/purpose pairing) **without** checking signatures.
    public func decodeStatement() throws -> KeyStatement {
        let signed = SignedStatement(payload: statement, signature: signatures.first ?? "")
        guard let o = signed.canonicalObject() else { throw KeyDirectoryError.malformed("statement") }
        guard case .integer(let v)? = o["v"] else { throw KeyDirectoryError.malformed("statement v") }
        guard v == Self.version else { throw KeyDirectoryError.unsupportedVersion(v) }
        guard o["type"]?.stringValue == type, o["business_id"]?.stringValue.flatMap(BusinessID.init) == businessId else { throw KeyDirectoryError.wrongBusiness }
        func string(_ k: String) throws -> String {
            guard let s = o[k]?.stringValue, s.utf8.count <= 256 else { throw KeyDirectoryError.malformed(k) }
            return s
        }
        func integer(_ k: String) throws -> Int64 {
            guard let i = o[k]?.int64Value, i >= 0, i < 4_102_444_800 * 2 else { throw KeyDirectoryError.malformed(k) }
            return i
        }
        func key(_ k: String) throws -> DevicePublicKey {
            guard let key = try? DevicePublicKey(base64URL: try string(k)), key.x963.count == 65, key.base64URL == (o[k]?.stringValue ?? "") else { throw KeyDirectoryError.invalidKey(k) }
            return key
        }
        switch type {
        case "root":
            guard Set(o.keys) == ["v", "type", "business_id", "root_kid", "public_key", "created_at"] else { throw KeyDirectoryError.malformed("members") }
            let publicKey = try key("public_key")
            guard try string("root_kid") == KeyIdentifier.make(try publicKey.signingKey()) else { throw KeyDirectoryError.invalidKey("root_kid") }
            return .root(RootRegistration(businessId: businessId, publicKey: publicKey, createdAt: Date(timeIntervalSince1970: TimeInterval(try integer("created_at")))))
        case "root-succession":
            guard Set(o.keys) == ["v", "type", "business_id", "old_root_kid", "new_root_kid", "new_public_key", "created_at"] else { throw KeyDirectoryError.malformed("members") }
            let publicKey = try key("new_public_key")
            guard try string("new_root_kid") == KeyIdentifier.make(try publicKey.signingKey()), KeyIdentifier.isValid(try string("old_root_kid")) else {
                throw KeyDirectoryError.invalidKey("new_root_kid")
            }
            return .succession(RootSuccession(businessId: businessId, oldRootKid: try string("old_root_kid"), newPublicKey: publicKey,
                                              createdAt: Date(timeIntervalSince1970: TimeInterval(try integer("created_at")))))
        case "key":
            guard Set(o.keys) == ["v", "type", "business_id", "root_kid", "purpose", "alg", "kid", "public_key", "not_before", "not_after", "serial"] else {
                throw KeyDirectoryError.malformed("members")
            }
            guard let purpose = BusinessKeyPurpose(rawValue: try string("purpose")), try string("alg") == purpose.algorithm else { throw KeyDirectoryError.malformed("purpose/alg") }
            let rootKid = try string("root_kid")
            guard KeyIdentifier.isValid(rootKid) else { throw KeyDirectoryError.malformed("root_kid") }
            let publicKey = try key("public_key")
            guard try string("kid") == KeyIdentifier.make(p256X963: publicKey.x963) else { throw KeyDirectoryError.invalidKey("kid") }
            return .key(KeyPublication(businessId: businessId, rootKid: rootKid, purpose: purpose, kid: try string("kid"), publicKey: publicKey.base64URL,
                                       notBefore: try integer("not_before"), notAfter: try integer("not_after"), serial: try integer("serial")))
        case "revoke":
            guard Set(o.keys) == ["v", "type", "business_id", "root_kid", "kid", "reason", "revoked_at", "serial"] else { throw KeyDirectoryError.malformed("members") }
            let reason = try string("reason")
            guard KeyRevocation.reasons.contains(reason), KeyIdentifier.isValid(try string("kid")), KeyIdentifier.isValid(try string("root_kid")) else {
                throw KeyDirectoryError.malformed("revoke")
            }
            return .revocation(KeyRevocation(businessId: businessId, rootKid: try string("root_kid"), kid: try string("kid"), reason: reason,
                                             revokedAt: Date(timeIntervalSince1970: TimeInterval(try integer("revoked_at"))), serial: try integer("serial")))
        default:
            throw KeyDirectoryError.malformed("type")
        }
    }

    // MARK: Signing (business side)

    /// Builds an entry whose single signature is made with `key` (the root key, or the new root for a succession's second signature).
    public static func sign(_ statement: KeyStatement, rootKey: any DeviceSigningKey, newRootKey: (any DeviceSigningKey)? = nil) async throws -> KeyLogEntry {
        switch statement {
        case .root(let value):
            let signed = try await SignedStatement.sign(value.object, domain: KeyDirectoryDomain.root, with: rootKey)
            return KeyLogEntry(type: "root", businessId: value.businessId, statement: signed.payload, signatures: [signed.signature])
        case .succession(let value):
            guard let newRootKey else { throw KeyDirectoryError.invalidKey("new root key required") }
            let old = try await SignedStatement.sign(value.object, domain: KeyDirectoryDomain.succession, with: rootKey)
            let new = try await SignedStatement.sign(value.object, domain: KeyDirectoryDomain.succession, with: newRootKey)
            return KeyLogEntry(type: "root-succession", businessId: value.businessId, statement: old.payload, signatures: [old.signature, new.signature])
        case .key(let value):
            let signed = try await SignedStatement.sign(value.object, domain: KeyDirectoryDomain.key, with: rootKey)
            return KeyLogEntry(type: "key", businessId: value.businessId, statement: signed.payload, signatures: [signed.signature])
        case .revocation(let value):
            let signed = try await SignedStatement.sign(value.object, domain: KeyDirectoryDomain.revoke, with: rootKey)
            return KeyLogEntry(type: "revoke", businessId: value.businessId, statement: signed.payload, signatures: [signed.signature])
        }
    }

    /// Checks the signature(s) of a decoded statement against the keys that must have made them.
    /// - Parameters:
    ///   - signer: the key that must have signed (the root for `root` and `key`/`revoke`: the **current** root; for a succession, the old root).
    public func verifySignatures(of statement: KeyStatement, signer: DevicePublicKey) throws {
        func check(_ index: Int, domain: String, key: DevicePublicKey, label: String) throws {
            guard index < signatures.count, SignedStatement(payload: self.statement, signature: signatures[index]).isValid(domain: domain, publicKey: key) else {
                throw KeyDirectoryError.invalidSignature(label)
            }
        }
        switch statement {
        case .root(let value): try check(0, domain: KeyDirectoryDomain.root, key: value.publicKey, label: "root")
        case .succession(let value):
            try check(0, domain: KeyDirectoryDomain.succession, key: signer, label: "old root")
            try check(1, domain: KeyDirectoryDomain.succession, key: value.newPublicKey, label: "new root")
        case .key: try check(0, domain: KeyDirectoryDomain.key, key: signer, label: "key")
        case .revocation: try check(0, domain: KeyDirectoryDomain.revoke, key: signer, label: "revoke")
        }
    }
}
