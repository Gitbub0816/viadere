import Crypto
import Foundation
import ViadereCore

/// A signing key held outside the process (a cloud KMS, an HSM): you give the SDK the public key and a closure that signs. The private key
/// never enters your application.
///
/// ```swift
/// let root = ExternalSigningKey(publicKey: kmsPublicKey, mode: .sha256Digest) { digest in try await kms.sign(digest: digest) }  // DER or raw r‖s
/// ```
public struct ExternalSigningKey: DeviceSigningKey {
    public enum Mode: Sendable {
        /// The closure receives the message and signs it (hashing with SHA-256 itself).
        case message
        /// The closure receives `SHA-256(message)` (what most KMS `Sign` calls take as the digest).
        case sha256Digest
    }

    public let publicKey: DevicePublicKey
    private let mode: Mode
    private let sign: @Sendable (Data) async throws -> Data

    /// `sign` returns an ECDSA P-256 signature as DER or as raw `r‖s` (64 bytes).
    public init(publicKey: DevicePublicKey, mode: Mode = .sha256Digest, sign: @escaping @Sendable (Data) async throws -> Data) {
        self.publicKey = publicKey
        self.mode = mode
        self.sign = sign
    }

    public func signature(for data: Data) async throws -> P256.Signing.ECDSASignature {
        let input = mode == .message ? data : Data(SHA256.hash(data: data))
        let bytes = try await sign(input)
        if bytes.count == 64, let raw = try? P256.Signing.ECDSASignature(rawRepresentation: bytes) { return raw }
        return try P256.Signing.ECDSASignature(derRepresentation: bytes)
    }
}

/// Your business root key and the signed statements that publish everything else (ADR-07).
///
/// Generate the **root key** yourself, once, in your KMS or HSM (P-256, signing only), register it, and use it only to sign statements: it
/// never signs an approval, a webhook or a request. Everything operational is a short-lived key the root vouches for:
///
/// * `approval-enrollment-confirmation`: confirms customers' enrollments,
/// * `approval-request-signing`: signs end-to-end approval requests so a device can tell you from the relay,
/// * `hpke-encryption`: customers' devices encrypt to it.
///
/// Rotate by publishing the new key (both are valid during the overlap) and later revoking the old one. A change of the **root** itself is a
/// succession signed by both roots; every pinned device alerts its owner and requires re-confirmation, so do it rarely.
public struct BusinessKeyAuthority: Sendable {
    public let businessId: BusinessID
    public let rootKey: any DeviceSigningKey

    public init(businessId: BusinessID, rootKey: any DeviceSigningKey) {
        self.businessId = businessId
        self.rootKey = rootKey
    }

    /// A new software root key. For production create it in your KMS and wrap it in `ExternalSigningKey`.
    public static func generateRootKey() -> SoftwareP256SigningKey { SoftwareP256SigningKey() }

    public var rootKid: String { (try? KeyIdentifier.make(rootKey.publicKey.signingKey())) ?? "" }

    /// The self-signed registration of the root key (proof of possession).
    public func registrationEntry(at now: Date = Date()) async throws -> KeyLogEntry {
        try await KeyLogEntry.sign(.root(RootRegistration(businessId: businessId, publicKey: rootKey.publicKey, createdAt: now)), rootKey: rootKey)
    }

    /// Publishes an operational key valid from `validFrom` for `lifetime` (at most 400 days; 30 to 90 days is a good rotation period).
    /// `serial` is one more than the last statement you published (`KeyDirectoryState.nextSerial`).
    public func keyEntry(purpose: BusinessKeyPurpose, publicKey: Data, serial: Int64, validFrom: Date = Date(), lifetime: TimeInterval = 90 * 86_400) async throws -> KeyLogEntry {
        let statement = try KeyPublication(businessId: businessId, rootKid: rootKid, purpose: purpose, publicKey: publicKey, notBefore: validFrom.addingTimeInterval(-60),
                                           notAfter: validFrom.addingTimeInterval(lifetime), serial: serial)
        return try await KeyLogEntry.sign(.key(statement), rootKey: rootKey)
    }

    public func revocationEntry(kid: String, reason: String = "superseded", serial: Int64, at now: Date = Date()) async throws -> KeyLogEntry {
        try await KeyLogEntry.sign(.revocation(KeyRevocation(businessId: businessId, rootKid: rootKid, kid: kid, reason: reason, revokedAt: now, serial: serial)), rootKey: rootKey)
    }

    /// A root change. Both the old and the new root sign it. After it, none of the old root's keys are valid: publish new ones with the new root.
    public func successionEntry(to newRootKey: any DeviceSigningKey, at now: Date = Date()) async throws -> KeyLogEntry {
        try await KeyLogEntry.sign(.succession(RootSuccession(businessId: businessId, oldRootKid: rootKid, newPublicKey: newRootKey.publicKey, createdAt: now)),
                                   rootKey: rootKey, newRootKey: newRootKey)
    }
}

/// What the log says about your business, replayed and verified: the basis for the next serial and for monitoring.
public struct KeyDirectoryState: Sendable {
    public var head: TreeHead
    public var state: BusinessKeyState
    /// The serial the next key or revocation statement must carry.
    public var nextSerial: Int64 { state.lastSerial + 1 }
    public var currentRootKid: String? { state.currentRoot?.kid }
}

/// Watches the transparency log for entries about your business that you did not make (a compromised root key, a rogue operational key, a
/// relay that tampers). Run it on a schedule (the `viadere-key-monitor` tool does); alert on any `unexpected` entry or a tree head that does
/// not extend what you saw last.
public struct KeyLogMonitor: Sendable {
    public struct Report: Sendable, Equatable {
        public var treeSize: Int
        public var rootHash: String
        /// Entries of your business the monitor has not seen before, in log order.
        public var newEntries: [Entry]
        /// New entries whose leaf hash is not in `expected` (your own publication records): investigate immediately.
        public var unexpected: [Entry]
        /// The root key of the business at the head.
        public var rootKid: String?
        /// The log's current head, to pass to the next run.
        public var seen: SeenTreeHead
    }

    public struct Entry: Sendable, Equatable {
        public var index: Int
        public var type: String
        /// Lowercase hex Merkle leaf hash: record this for every entry you publish and pass the set as `expected`.
        public var leafHash: String
        public var kid: String?
    }

    private let verifier: KeyDirectoryVerifier
    private let businessId: BusinessID

    public init(businessId: BusinessID, logKeys: [DevicePublicKey], logId: String = TransparencyLog.defaultLogId, maxHeadAge: TimeInterval = 7 * 86_400) {
        self.businessId = businessId
        verifier = KeyDirectoryVerifier(logKeys: logKeys, logId: logId, maxHeadAge: maxHeadAge)
    }

    /// Verifies the response (head signature, consistency with `lastSeen`, every inclusion proof, the replayed history) and reports what is new.
    /// - Parameters:
    ///   - knownIndexes: indexes you have already reviewed (from the previous report).
    ///   - expected: leaf hashes of the entries you published yourself.
    public func check(_ response: KeyDirectoryResponse, lastSeen: SeenTreeHead?, knownIndexes: Set<Int> = [], expected: Set<String>, now: Date = Date()) throws -> Report {
        let verified = try verifier.verify(response, businessId: businessId, lastSeen: lastSeen, now: now)
        var entries: [Entry] = []
        for item in response.entries where !knownIndexes.contains(item.index) {
            guard let bytes = Base64URL.decode(item.entry), let entry = try? KeyLogEntry.parse(bytes) else { continue }
            var kid: String?
            switch try? entry.decodeStatement() {
            case .key(let key)?: kid = key.kid
            case .revocation(let revocation)?: kid = revocation.kid
            case .root(let root)?: kid = root.rootKid
            case .succession(let succession)?: kid = succession.newRootKid
            case nil: break
            }
            entries.append(Entry(index: item.index, type: entry.type, leafHash: Hex.encode(MerkleTree.leafHash(bytes)), kid: kid))
        }
        return Report(treeSize: verified.head.treeSize, rootHash: verified.head.rootHash, newEntries: entries, unexpected: entries.filter { !expected.contains($0.leafHash) },
                      rootKid: verified.state.currentRoot?.kid, seen: SeenTreeHead(verified.head))
    }
}
