@preconcurrency import Crypto
import Foundation

// The key-log formats shared by the authority and the app (ADR-0023 §4, ADR-0032 §1, §3, ADR-0033 §1, §2, §4.1, §5, ADR-0034 §1, §2): proof-of-possession
// strings, the entry hash chain, the device-add comparison code, the key-log displays, the signed head and the sealed recovery envelope.

public enum AuthorityKeyLogFormat {
    /// `prev_hash` of an account's first entry: 32 zero bytes, lowercase hex.
    public static let zeroHash = String(repeating: "0", count: 64)
    public static let entryDomain = "VIADERE-KEYLOG-ENTRY-V1\n"
    public static let popDomain = "VIADERE-KEYLOG-V1"

    /// `VIADERE-KEYLOG-V1\n{env}\n{type}\n{kid}\n{nonce}` (plus `\n{extra}` for each extra member, e.g. the recovery start's `envelope_digest`).
    /// `type` is `genesis`, `device_added`, `enrollment_confirmed` (whose "nonce" is the confirmed `head_hash`) or `recovery_started`.
    public static func popMessage(environment: AuthorityEnvironment, type: String, kid: String, nonce: String, extra: [String] = []) -> Data {
        Data(([popDomain, environment.rawValue, type, kid, nonce] + extra).joined(separator: "\n").utf8)
    }

    /// A PoP is the raw low-S `r ‖ s` ES256 signature over `popMessage`, base64url (86 characters).
    public static func signPoP(_ key: any DeviceSigningKey, message: Data) async throws -> String {
        ViadereSignatureEncoding.encode(try await key.signature(for: message))
    }

    public static func verifyPoP(_ pop: String, key: P256.Signing.PublicKey, message: Data) -> Bool {
        guard Base64URL.isValid(pop, minLength: 86, maxLength: 86), let signature = ViadereSignatureEncoding.decode(pop) else { return false }
        return key.isValidSignature(signature, for: message)
    }

    /// `entry_hash = lowercase hex SHA-256("VIADERE-KEYLOG-ENTRY-V1\n" ‖ canonical(entry without entry_hash))` (ADR-0033 §5). The entry includes
    /// `prev_hash`, so the chain is bound into every hash.
    public static func entryHash(_ entry: [String: JSONValue]) throws -> String {
        precondition(entry["entry_hash"] == nil, "the hash never covers itself")
        return SecureToken.sha256Hex(Data(entryDomain.utf8) + (try CanonicalJSON.serialize(.object(entry))))
    }

    /// `acct_` + 32 lowercase hex characters (ADR-0032 §1.1).
    public static func isAccountRef(_ value: String) -> Bool {
        value.count == 37 && value.hasPrefix("acct_") && value.dropFirst(5).allSatisfy { ("0"..."9").contains($0) || ("a"..."f").contains($0) }
    }

    /// Device-reported names in a `device_added` display: 1-40 characters after NFC, no control, format (bidi, zero-width) or line characters.
    public static func reportedName(_ raw: String) -> String? {
        let name = raw.precomposedStringWithCanonicalMapping
        guard (1...40).contains(name.count), !name.unicodeScalars.contains(where: {
            [.control, .format, .lineSeparator, .paragraphSeparator, .unassigned, .privateUse, .surrogate].contains($0.properties.generalCategory)
        }) else { return nil }
        return name
    }
}

/// The 6-digit device-add comparison code (ADR-0033 §4.1 item 4): `decimal6(SHA-256("VIADERE-DEVICE-ADD-V1\n" ‖ env ‖ "\n" ‖ nonce ‖ "\n" ‖
/// join("\n", sorted kids)))`, `decimal6(h)` = big-endian unsigned integer of the first 8 bytes of `h` modulo 1 000 000, six digits.
public enum AuthorityDeviceAddCode {
    public static func code(environment: AuthorityEnvironment, nonce: String, kids: [String]) -> String {
        let sorted = kids.sorted { Array($0.utf8).lexicographicallyPrecedes(Array($1.utf8)) }
        let input = "VIADERE-DEVICE-ADD-V1\n" + environment.rawValue + "\n" + nonce + "\n" + sorted.joined(separator: "\n")
        let digest = Array(SHA256.hash(data: Data(input.utf8)))
        let value = digest.prefix(8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        let six = String(value % 1_000_000)
        return String(repeating: "0", count: 6 - six.count) + six
    }
}

extension AuthorityDisplay {
    /// `keylog_device_added`: the name the new device reported (labelled as reported text), every key of the entry, `match_digits: 6`. The code itself
    /// is never in the display (ADR-0033 §1, §4.1).
    public static func deviceAdded(reportedName: String, kids: [String]) -> JSONValue {
        .object(["v": .integer(1), "purpose": .string(AuthorityPurpose.keylogDeviceAdded.rawValue), "reported_name": .string(reportedName),
                 "reported_name_source": .string("new_device"), "kids": .array(kids.map { .string($0) }), "match_digits": .integer(6)])
    }

    /// `enrollment_confirmed`: the account, the confirming device's own keys and the head it verified (no person-facing prompt).
    public static func enrollmentConfirmed(accountRef: String, kids: [String], headHash: String, seq: Int64) -> JSONValue {
        .object(["v": .integer(1), "purpose": .string(AuthorityPurpose.enrollmentConfirmed.rawValue), "account_ref": .string(accountRef),
                 "kids": .array(kids.map { .string($0) }), "head_hash": .string(headHash), "seq": .integer(seq)])
    }

    /// `recovery_codes_set`: the device-generated set id and the code count.
    public static func recoveryCodesSet(setId: String, count: Int) -> JSONValue {
        .object(["v": .integer(1), "purpose": .string(AuthorityPurpose.recoveryCodesSet.rawValue), "set_id": .string(setId), "count": .integer(Int64(count))])
    }

    /// `recovery_cancel`: when the pending recovery started and when it would activate.
    public static func recoveryCancel(startedAt: Int64, activatesAt: Int64) -> JSONValue {
        .object(["v": .integer(1), "purpose": .string(AuthorityPurpose.recoveryCancel.rawValue), "started_at": .integer(startedAt), "activates_at": .integer(activatesAt)])
    }

    /// `recovery_started`: the hold (no person-facing prompt; the recovering device shows S-REC-01).
    public static func recoveryStarted() -> JSONValue {
        .object(["v": .integer(1), "purpose": .string(AuthorityPurpose.recoveryStarted.rawValue), "activates_after_hours": .integer(72)])
    }
}

/// The signed key-log head `viadere-keylog-head+jws` (ADR-0033 §2): what the authority will accept for one account.
public struct AuthorityKeyLogHead: Sendable, Hashable {
    public static let type = "viadere-keylog-head+jws"
    /// Heads older than this are refused by the device.
    public static let maxAge: Int64 = 15 * 60

    public struct Key: Sendable, Hashable {
        public var kid: String
        public var purpose: String
        public var usableFrom: Int64
        public var entryType: String
        public var imported: Bool
        public var grantCapable: Bool
        public init(kid: String, purpose: String, usableFrom: Int64, entryType: String, imported: Bool, grantCapable: Bool) {
            self.kid = kid
            self.purpose = purpose
            self.usableFrom = usableFrom
            self.entryType = entryType
            self.imported = imported
            self.grantCapable = grantCapable
        }
        var json: JSONValue {
            .object(["kid": .string(kid), "purpose": .string(purpose), "usable_from": .integer(usableFrom), "entry_type": .string(entryType),
                     "imported": .bool(imported), "grant_capable": .bool(grantCapable)])
        }
    }

    public struct PendingRecovery: Sendable, Hashable {
        public var recoveryId: String
        public var startedAt: Int64
        public var activatesAt: Int64
        public var legacy: Bool
        public var kids: [String]
        public init(recoveryId: String, startedAt: Int64, activatesAt: Int64, legacy: Bool, kids: [String]) {
            self.recoveryId = recoveryId
            self.startedAt = startedAt
            self.activatesAt = activatesAt
            self.legacy = legacy
            self.kids = kids
        }
        var json: JSONValue {
            .object(["recovery_id": .string(recoveryId), "started_at": .integer(startedAt), "activates_at": .integer(activatesAt), "legacy": .bool(legacy),
                     "kids": .array(kids.map { .string($0) })])
        }
    }

    /// `none`, `active`, `refresh_suggested`, `invalidated` (ADR-0034 §8).
    public static let recoverySetStates: Set<String> = ["none", "active", "refresh_suggested", "invalidated"]

    public var environment: AuthorityEnvironment
    public var accountRef: String
    public var seq: Int64
    public var headHash: String
    public var keys: [Key]
    public var pendingRecoveries: [PendingRecovery]
    public var recoverySet: String
    public var issuedAt: Int64

    public init(environment: AuthorityEnvironment, accountRef: String, seq: Int64, headHash: String, keys: [Key], pendingRecoveries: [PendingRecovery],
                recoverySet: String, issuedAt: Int64) {
        self.environment = environment
        self.accountRef = accountRef
        self.seq = seq
        self.headHash = headHash
        self.keys = keys
        self.pendingRecoveries = pendingRecoveries
        self.recoverySet = recoverySet
        self.issuedAt = issuedAt
    }

    public var payload: [String: JSONValue] {
        ["v": .integer(1), "iss": .string(environment.authorityURN), "aud": .string(AuthorityAudience.device), "env": .string(environment.rawValue),
         "account_ref": .string(accountRef), "seq": .integer(seq), "head_hash": .string(headHash), "keys": .array(keys.map(\.json)),
         "pending_recoveries": .array(pendingRecoveries.map(\.json)), "recovery_set": .string(recoverySet), "issued_at": .integer(issuedAt)]
    }

    static let members: Set<String> = ["v", "iss", "aud", "env", "account_ref", "seq", "head_hash", "keys", "pending_recoveries", "recovery_set", "issued_at"]
}

extension AuthorityStatementVerifier {
    public enum HeadError: Error, Sendable, Equatable { case stale, rollback, notMyAccount, entryMismatch, recoveryMismatch }

    /// The device check of a `viadere-keylog-head+jws` (ADR-0033 §2): pinned non-revoked key, exact `typ`, `iss`, `aud`, `env`, member set; `issued_at` at
    /// most 15 minutes old and not in the future; `seq` not below the highest accepted (`minimumSeq`); the head **contains** every key of this
    /// device (`ownKids`). The stricter enrollment and recovery checks are `requireExactEntry` and `requireExactPendingRecovery`.
    public static func verifyHead(_ compact: String, pinnedKeys: [P256.Signing.PublicKey], revokedKids: Set<String> = [], environment: AuthorityEnvironment,
                                  ownKids: [String], minimumSeq: Int64, now: Date) throws -> AuthorityKeyLogHead {
        let parts = try AuthorityJWS.parse(compact, expectedType: AuthorityKeyLogHead.type, allowedAlgorithms: ["ES256"])
        guard !revokedKids.contains(parts.kid), let key = pinnedKeys.first(where: { JWKThumbprint.p256($0) == parts.kid }) else { throw AuthorityJOSEError.unknownKey }
        try AuthorityJWS.verifyES256(parts, key: key)
        let o = parts.payload
        guard Set(o.keys) == AuthorityKeyLogHead.members else { throw AuthorityJOSEError.claims("members") }
        guard o["v"]?.authorityInteger == 1, o["iss"]?.stringValue == environment.authorityURN, o["aud"]?.stringValue == AuthorityAudience.device,
              o["env"]?.stringValue == environment.rawValue else { throw AuthorityJOSEError.claims("issuer") }
        guard let accountRef = o["account_ref"]?.stringValue, AuthorityKeyLogFormat.isAccountRef(accountRef), let seq = o["seq"]?.authorityInteger, seq >= 0,
              let headHash = o["head_hash"]?.stringValue, headHash.count == 64, let issuedAt = o["issued_at"]?.authorityInteger,
              let recoverySet = o["recovery_set"]?.stringValue, AuthorityKeyLogHead.recoverySetStates.contains(recoverySet),
              case .array(let keyItems)? = o["keys"], case .array(let recoveryItems)? = o["pending_recoveries"] else { throw AuthorityJOSEError.claims("values") }
        var keys: [AuthorityKeyLogHead.Key] = []
        for item in keyItems {
            guard let k = item.objectValue, Set(k.keys) == ["kid", "purpose", "usable_from", "entry_type", "imported", "grant_capable"],
                  let kid = k["kid"]?.stringValue, KeyIdentifier.isValid(kid), let purpose = k["purpose"]?.stringValue, let usable = k["usable_from"]?.authorityInteger,
                  let entryType = k["entry_type"]?.stringValue, case .bool(let imported)? = k["imported"], case .bool(let capable)? = k["grant_capable"] else {
                throw AuthorityJOSEError.claims("keys")
            }
            keys.append(.init(kid: kid, purpose: purpose, usableFrom: usable, entryType: entryType, imported: imported, grantCapable: capable))
        }
        var pending: [AuthorityKeyLogHead.PendingRecovery] = []
        for item in recoveryItems {
            guard let r = item.objectValue, Set(r.keys) == ["recovery_id", "started_at", "activates_at", "legacy", "kids"], let id = r["recovery_id"]?.stringValue,
                  let started = r["started_at"]?.authorityInteger, let activates = r["activates_at"]?.authorityInteger, case .bool(let legacy)? = r["legacy"],
                  case .array(let kidItems)? = r["kids"] else { throw AuthorityJOSEError.claims("pending_recoveries") }
            let kids = kidItems.compactMap(\.stringValue)
            guard kids.count == kidItems.count, kids.allSatisfy(KeyIdentifier.isValid) else { throw AuthorityJOSEError.claims("pending_recoveries") }
            pending.append(.init(recoveryId: id, startedAt: started, activatesAt: activates, legacy: legacy, kids: kids))
        }
        let t = Int64(now.timeIntervalSince1970)
        guard issuedAt <= t + skew else { throw AuthorityJOSEError.notYetValid }
        guard t - issuedAt <= AuthorityKeyLogHead.maxAge else { throw HeadError.stale }
        guard seq >= minimumSeq else { throw HeadError.rollback }
        let listed = Set(keys.map(\.kid))
        guard ownKids.allSatisfy(listed.contains) else { throw HeadError.notMyAccount }
        return AuthorityKeyLogHead(environment: environment, accountRef: accountRef, seq: seq, headHash: headHash, keys: keys, pendingRecoveries: pending,
                                   recoverySet: recoverySet, issuedAt: issuedAt)
    }

    /// Enrollment (ADR-0032 §1.4): the keys of `entryType` entries that are not yet grant-capable must be **exactly** this device's keys (no more,
    /// no fewer). An attacker key added beside the device's keys makes the device refuse to confirm. Imported accounts only need to contain them.
    public static func requireExactEntry(_ head: AuthorityKeyLogHead, ownKids: [String]) throws {
        let own = Set(ownKids)
        let candidates = head.keys.filter { own.contains($0.kid) }
        guard candidates.count == own.count else { throw HeadError.notMyAccount }
        if candidates.allSatisfy(\.imported) { return }
        let unconfirmed = Set(head.keys.filter { !$0.grantCapable && !$0.imported }.map(\.kid))
        guard unconfirmed == own else { throw HeadError.entryMismatch }
    }

    /// A recovering device continues only with a pending recovery whose `kids` are exactly its own new keys (ADR-0032 §3.2).
    public static func requireExactPendingRecovery(_ head: AuthorityKeyLogHead, newKids: [String]) throws {
        guard head.pendingRecoveries.contains(where: { Set($0.kids) == Set(newKids) && $0.kids.count == newKids.count }) else { throw HeadError.recoveryMismatch }
    }
}

/// Internal authority routes of the key log, recovery and link service (api → authority; `Authority.Evidence.Submit` and the `api` caller only).
public enum AuthorityKeyLogRoute {
    public static let nonces = "/v1/keylog/nonces"
    public static let genesis = "/v1/keylog/genesis"
    public static let head = "/v1/keylog/head"
    public static let challenges = "/v1/keylog/challenges"
    public static let deviceAdded = "/v1/keylog/device-added"
    public static let evidence = "/v1/keylog/evidence"
    public static let recoveryStart = "/v1/keylog/recovery/start"
    public static let recoveryLegacyStart = "/v1/keylog/recovery/legacy-start"
    public static let linkRedeem = "/v1/link/redeem"
}

// MARK: - Sealed recovery envelopes (ADR-0034, lean construction: HPKE P-256 / HKDF-SHA256 / AES-256-GCM, mode_base)

public enum RecoverySealError: Error, Sendable, Equatable {
    case malformed(String)
    case wrongKey
    case openFailed
    case plaintext(String)
}

public enum RecoverySealPurpose: String, Sendable, Hashable, CaseIterable {
    case codesSet = "recovery_codes_set"
    case start = "recovery_started"

    var infoLabel: String { self == .codesSet ? "VIADERE-RECOVERY-SET-V1\n" : "VIADERE-RECOVERY-START-V1\n" }
}

/// `{"v":1,"kid","enc","ct"}`, nothing else, at most 4096 bytes.
public struct RecoverySealEnvelope: Sendable, Hashable {
    public var kid: String
    public var enc: Data
    public var ct: Data

    public init(kid: String, enc: Data, ct: Data) {
        self.kid = kid
        self.enc = enc
        self.ct = ct
    }

    /// `base64url(SHA-256(enc ‖ ct))`: what the authorizing device signature commits to.
    public var digest: String { Base64URL.encode(Data(SHA256.hash(data: enc + ct))) }

    public var json: JSONValue { .object(["v": .integer(1), "kid": .string(kid), "enc": .string(Base64URL.encode(enc)), "ct": .string(Base64URL.encode(ct))]) }

    public static func parse(_ value: JSONValue) throws -> RecoverySealEnvelope {
        guard let o = value.objectValue, Set(o.keys) == ["v", "kid", "enc", "ct"], o["v"]?.authorityInteger == 1,
              let kid = o["kid"]?.stringValue, Base64URL.isValid(kid, minLength: 43, maxLength: 43),
              let encText = o["enc"]?.stringValue, let enc = Base64URL.decode(encText), enc.count == 65,
              let ctText = o["ct"]?.stringValue, let ct = Base64URL.decode(ctText), (17...3000).contains(ct.count),
              (try? CanonicalJSON.serialize(value))?.count ?? .max <= 4096 else { throw RecoverySealError.malformed("envelope") }
        return RecoverySealEnvelope(kid: kid, enc: enc, ct: ct)
    }
}

public enum RecoverySeal {
    public static let codeCount = 10

    /// The RFC 7638 thumbprint of a seal public key.
    public static func kid(_ key: P256.KeyAgreement.PublicKey) -> String {
        JWKThumbprint.p256((try? P256.Signing.PublicKey(rawRepresentation: key.rawRepresentation)) ?? P256.Signing.PrivateKey().publicKey)
    }

    static func info(_ purpose: RecoverySealPurpose, _ environment: AuthorityEnvironment) -> Data { Data((purpose.infoLabel + environment.rawValue).utf8) }
    static func aad(challengeId: String, nonce: String) -> Data { Data((challengeId + "\n" + nonce).utf8) }

    /// `rcs_` + 22 base64url (16 random bytes).
    public static func generateSetId() -> String { "rcs_" + Base64URL.encode(SecureToken.randomBytes(16)) }
    public static func isSetId(_ value: String) -> Bool {
        value.hasPrefix("rcs_") && Base64URL.isValid(String(value.dropFirst(4)), minLength: 22, maxLength: 22)
    }

    /// Ten device-generated codes, normalized (10 Crockford symbols each, pairwise distinct).
    public static func generateCodes() -> [String] {
        var codes: [String] = []
        while codes.count < codeCount {
            if let code = RecoveryCodeFormat.normalizeCode(RecoveryCodeFormat.generateCode()), !codes.contains(code) { codes.append(code) }
        }
        return codes
    }

    public static func seal(_ plaintext: JSONValue, to key: P256.KeyAgreement.PublicKey, purpose: RecoverySealPurpose, environment: AuthorityEnvironment,
                            challengeId: String, nonce: String) throws -> RecoverySealEnvelope {
        var sender = try HPKE.Sender(recipientKey: key, ciphersuite: .P256_SHA256_AES_GCM_256, info: info(purpose, environment))
        let ct = try sender.seal(try CanonicalJSON.serialize(plaintext), authenticating: aad(challengeId: challengeId, nonce: nonce))
        return RecoverySealEnvelope(kid: kid(key), enc: Data(sender.encapsulatedKey), ct: Data(ct))
    }

    /// Opens with the purpose's `info` and the challenge's `aad`. One answer for every failure (no oracle).
    public static func open(_ envelope: RecoverySealEnvelope, with key: P256.KeyAgreement.PrivateKey, purpose: RecoverySealPurpose, environment: AuthorityEnvironment,
                            challengeId: String, nonce: String) throws -> [String: JSONValue] {
        guard ConstantTime.equals(envelope.kid, kid(key.publicKey)) else { throw RecoverySealError.wrongKey }
        let bytes: Data
        do {
            var recipient = try HPKE.Recipient(privateKey: key, ciphersuite: .P256_SHA256_AES_GCM_256, info: info(purpose, environment), encapsulatedKey: envelope.enc)
            bytes = try recipient.open(envelope.ct, authenticating: aad(challengeId: challengeId, nonce: nonce))
        } catch { throw RecoverySealError.openFailed }
        guard case .object(let o)? = try? JSONDecoder().decode(JSONValue.self, from: bytes), (try? CanonicalJSON.serialize(.object(o))) == bytes else {
            throw RecoverySealError.plaintext("encoding")
        }
        return o
    }

    public static func setPlaintext(accountRef: String, setId: String, nonce: String, codes: [String]) -> JSONValue {
        .object(["v": .integer(1), "purpose": .string(RecoverySealPurpose.codesSet.rawValue), "account_ref": .string(accountRef), "set_id": .string(setId),
                 "nonce": .string(nonce), "codes": .array(codes.map { .string($0) })])
    }

    public static func startPlaintext(recoveryId: String, nonce: String, code: String, newKids: [String]) -> JSONValue {
        .object(["v": .integer(1), "purpose": .string(RecoverySealPurpose.start.rawValue), "recovery_id": .string(recoveryId), "nonce": .string(nonce),
                 "code": .string(code), "new_kids": .array(sortedKids(newKids).map { .string($0) })])
    }

    public static func sortedKids(_ kids: [String]) -> [String] { kids.sorted { Array($0.utf8).lexicographicallyPrecedes(Array($1.utf8)) } }

    /// Strict set plaintext: exact members, 10 normalized pairwise-distinct codes.
    public static func parseSet(_ o: [String: JSONValue]) throws -> (accountRef: String, setId: String, nonce: String, codes: [String]) {
        guard Set(o.keys) == ["v", "purpose", "account_ref", "set_id", "nonce", "codes"], o["v"]?.authorityInteger == 1,
              o["purpose"]?.stringValue == RecoverySealPurpose.codesSet.rawValue, let accountRef = o["account_ref"]?.stringValue,
              let setId = o["set_id"]?.stringValue, isSetId(setId), let nonce = o["nonce"]?.stringValue, case .array(let items)? = o["codes"] else {
            throw RecoverySealError.plaintext("members")
        }
        let codes = items.compactMap(\.stringValue)
        guard codes.count == codeCount, items.count == codeCount, codes.allSatisfy({ RecoveryCodeFormat.normalizeCode($0) == $0 }), Set(codes).count == codeCount else {
            throw RecoverySealError.plaintext("codes")
        }
        return (accountRef, setId, nonce, codes)
    }

    /// Strict start plaintext: exact members, one normalized code, 1-4 sorted distinct `new_kids`.
    public static func parseStart(_ o: [String: JSONValue]) throws -> (recoveryId: String, nonce: String, code: String, newKids: [String]) {
        guard Set(o.keys) == ["v", "purpose", "recovery_id", "nonce", "code", "new_kids"], o["v"]?.authorityInteger == 1,
              o["purpose"]?.stringValue == RecoverySealPurpose.start.rawValue, let recoveryId = o["recovery_id"]?.stringValue,
              let nonce = o["nonce"]?.stringValue, let code = o["code"]?.stringValue, RecoveryCodeFormat.normalizeCode(code) == code,
              case .array(let items)? = o["new_kids"] else { throw RecoverySealError.plaintext("members") }
        let kids = items.compactMap(\.stringValue)
        guard kids.count == items.count, (1...4).contains(kids.count), kids.allSatisfy(KeyIdentifier.isValid), kids == sortedKids(kids),
              Set(kids).count == kids.count else { throw RecoverySealError.plaintext("new_kids") }
        return (recoveryId, nonce, code, kids)
    }
}
