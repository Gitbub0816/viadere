import Crypto
import Foundation

/// WebAuthn Level 3 `authenticatorData` flags (§6.1).
public struct AuthenticatorFlags: OptionSet, Sendable, Equatable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }
    /// User present.
    public static let userPresent = AuthenticatorFlags(rawValue: 0x01)
    /// User verified (biometric or passcode).
    public static let userVerified = AuthenticatorFlags(rawValue: 0x04)
    /// Backup eligible: the credential may be synced (fixed for the life of the credential).
    public static let backupEligible = AuthenticatorFlags(rawValue: 0x08)
    /// Backup state: the credential is currently backed up (synced).
    public static let backupState = AuthenticatorFlags(rawValue: 0x10)
    /// Attested credential data follows.
    public static let attestedCredentialData = AuthenticatorFlags(rawValue: 0x40)
    /// Extension data follows.
    public static let extensionData = AuthenticatorFlags(rawValue: 0x80)
}

public enum WebAuthnError: Error, Equatable, Sendable {
    case invalidRelyingParty
    case invalidClientDataHash
    case userVerificationRequired
    case unsupportedAlgorithm
    case credentialExcluded
    case malformedAuthenticatorData
    case invalidCredential
    case invalidUserHandle
}

/// A discoverable passkey held by the vault. Contains the private key: it only ever exists in memory unlocked, or sealed inside a vault
/// item (`VaultItemPayload`).
public struct PasskeyCredential: Sendable, Equatable {
    public var credentialId: Data
    public var rpId: String
    public var userHandle: Data
    public var userName: String
    public var displayName: String?
    /// The 32-byte raw P-256 private scalar.
    public var privateKey: Data
    public var createdAt: Date

    public init(credentialId: Data, rpId: String, userHandle: Data, userName: String, displayName: String? = nil, privateKey: Data, createdAt: Date) {
        self.credentialId = credentialId
        self.rpId = rpId
        self.userHandle = userHandle
        self.userName = userName
        self.displayName = displayName
        self.privateKey = privateKey
        self.createdAt = createdAt
    }

    /// The public key in COSE form (what registration returns).
    public func cosePublicKey() throws -> Data {
        let key = try P256.Signing.PrivateKey(rawRepresentation: privateKey)
        return WebAuthnAuthenticator.coseES256(key.publicKey)
    }
}

/// How the authenticator attests a new credential.
public enum AttestationFormat: Sendable, Equatable {
    /// `fmt: "none"`: no attestation statement (the default, and what relying parties should expect from a synced passkey provider).
    case none
    /// `fmt: "packed"` self attestation (`alg: -7`, no certificate): signs with the credential key itself.
    case packedSelf
}

/// The result of `makeCredential`.
public struct CreatedPasskey: Sendable {
    public var credential: PasskeyCredential
    /// CBOR attestation object (`fmt`, `attStmt`, `authData`).
    public var attestationObject: Data
    /// The raw authenticator data inside the attestation object.
    public var authenticatorData: Data
}

/// The result of `getAssertion`.
public struct PasskeyAssertion: Sendable {
    public var credentialId: Data
    public var userHandle: Data
    public var authenticatorData: Data
    /// ASN.1 DER ECDSA signature over `authenticatorData || clientDataHash`.
    public var signature: Data
}

/// A platform-neutral WebAuthn authenticator (CTAP2 `authenticatorMakeCredential` / `authenticatorGetAssertion` semantics) for ES256
/// (P-256) passkeys.
///
/// The caller (the credential-provider extension) is responsible for **user verification** and passes the outcome in `userVerified`;
/// when the relying party requires it and it did not happen, nothing is created or signed. The operating system builds the client data
/// and passes its SHA-256 (`clientDataHash`), so this engine never sees an origin and cannot be tricked into signing for another one:
/// the relying-party ID it signs for is the one in the request, hashed into `authenticatorData`.
///
/// Choices, each deliberate:
/// - **signCount is always 0.** A passkey that syncs has no single counter; relying parties must treat 0 as "not supported" (WebAuthn §6.1.3).
/// - **Backup eligible (BE) is always 1**; **backup state (BS)** is 1 only while the vault is synced (`backedUp`).
/// - **AAGUID is all zeros** (no attestation, no fingerprinting of the provider).
/// - Only ES256 (`alg -7`, curve P-256) is implemented.
public enum WebAuthnAuthenticator {
    public static let aaguid = Data(repeating: 0, count: 16)
    public static let es256: Int = -7
    public static let credentialIdLength = 32
    public static let userHandleLimit = 64

    // MARK: Validation

    /// A conservative relying-party ID check: a lowercase ASCII host name (labels of letters, digits and hyphens, at least one dot or
    /// `localhost`), no scheme, port, path, user info, trailing dot or IP-literal form. Internationalised names arrive in punycode.
    public static func isValidRelyingPartyID(_ rpId: String) -> Bool {
        guard !rpId.isEmpty, rpId.utf8.count <= 253, rpId == rpId.lowercased() else { return false }
        let labels = rpId.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.allSatisfy({ label in
            !label.isEmpty && label.utf8.count <= 63 && !label.hasPrefix("-") && !label.hasSuffix("-")
                && label.utf8.allSatisfy { ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2D }
        }) else { return false }
        // Not an IPv4 address.
        if labels.count == 4, labels.allSatisfy({ $0.utf8.allSatisfy { $0 >= 0x30 && $0 <= 0x39 } }) { return false }
        return labels.count > 1 || rpId == "localhost"
    }

    public static func rpIdHash(_ rpId: String) -> Data { Data(SHA256.hash(data: Data(rpId.utf8))) }

    // MARK: Registration

    /// `authenticatorMakeCredential`.
    /// - Parameters:
    ///   - supportedAlgorithms: the COSE algorithms the relying party accepts, in preference order; `nil` or empty means "any" (ES256).
    ///   - excludedCredentialIds: IDs of credentials the account already holds *for this relying party*. If the vault holds one, no new
    ///     credential is made (§6.3.2 step 3).
    public static func makeCredential(rpId: String, userHandle: Data, userName: String, displayName: String? = nil, clientDataHash: Data,
                                      supportedAlgorithms: [Int]? = nil, excludedCredentialIds: [Data] = [], existingCredentialIds: Set<Data> = [],
                                      requireUserVerification: Bool, userVerified: Bool, backedUp: Bool,
                                      attestation: AttestationFormat = .none, now: Date) throws -> CreatedPasskey {
        guard isValidRelyingPartyID(rpId) else { throw WebAuthnError.invalidRelyingParty }
        guard clientDataHash.count == 32 else { throw WebAuthnError.invalidClientDataHash }
        guard !userHandle.isEmpty, userHandle.count <= userHandleLimit else { throw WebAuthnError.invalidUserHandle }
        if let algorithms = supportedAlgorithms, !algorithms.isEmpty, !algorithms.contains(es256) { throw WebAuthnError.unsupportedAlgorithm }
        if requireUserVerification && !userVerified { throw WebAuthnError.userVerificationRequired }
        if excludedCredentialIds.contains(where: { existingCredentialIds.contains($0) }) { throw WebAuthnError.credentialExcluded }

        let privateKey = P256.Signing.PrivateKey()
        var credentialId = SecureToken.randomBytes(credentialIdLength)
        while existingCredentialIds.contains(credentialId) { credentialId = SecureToken.randomBytes(credentialIdLength) }
        let credential = PasskeyCredential(credentialId: credentialId, rpId: rpId, userHandle: userHandle, userName: userName, displayName: displayName,
                                           privateKey: privateKey.rawRepresentation, createdAt: now)

        var flags: AuthenticatorFlags = [.userPresent, .backupEligible, .attestedCredentialData]
        if userVerified { flags.insert(.userVerified) }
        if backedUp { flags.insert(.backupState) }
        var authData = authenticatorDataPrefix(rpId: rpId, flags: flags)
        authData.append(aaguid)
        authData.append(contentsOf: [UInt8(credentialId.count >> 8), UInt8(credentialId.count & 0xFF)])
        authData.append(credentialId)
        authData.append(coseES256(privateKey.publicKey))

        let statement: CBORValue
        let format: String
        switch attestation {
        case .none:
            format = "none"
            statement = .map([])
        case .packedSelf:
            format = "packed"
            let signature = try privateKey.signature(for: authData + clientDataHash)
            statement = .textMap([("alg", .negative(Int64(es256))), ("sig", .bytes(signature.derRepresentation))])
        }
        let object = CBOR.encode(.textMap([("fmt", .text(format)), ("attStmt", statement), ("authData", .bytes(authData))]), deterministic: true)
        return CreatedPasskey(credential: credential, attestationObject: object, authenticatorData: authData)
    }

    // MARK: Assertion

    /// `authenticatorGetAssertion` for one credential the caller selected (the OS or the person chose it from the list).
    public static func getAssertion(credential: PasskeyCredential, rpId: String, clientDataHash: Data, requireUserVerification: Bool,
                                    userVerified: Bool, backedUp: Bool) throws -> PasskeyAssertion {
        guard isValidRelyingPartyID(rpId), credential.rpId == rpId else { throw WebAuthnError.invalidRelyingParty }
        guard clientDataHash.count == 32 else { throw WebAuthnError.invalidClientDataHash }
        if requireUserVerification && !userVerified { throw WebAuthnError.userVerificationRequired }
        let key: P256.Signing.PrivateKey
        do { key = try P256.Signing.PrivateKey(rawRepresentation: credential.privateKey) } catch { throw WebAuthnError.invalidCredential }
        var flags: AuthenticatorFlags = [.userPresent, .backupEligible]
        if userVerified { flags.insert(.userVerified) }
        if backedUp { flags.insert(.backupState) }
        let authData = authenticatorDataPrefix(rpId: rpId, flags: flags)
        let signature = try key.signature(for: authData + clientDataHash)
        return PasskeyAssertion(credentialId: credential.credentialId, userHandle: credential.userHandle, authenticatorData: authData,
                                signature: signature.derRepresentation)
    }

    // MARK: Encoding

    /// `rpIdHash || flags || signCount(0)`.
    static func authenticatorDataPrefix(rpId: String, flags: AuthenticatorFlags) -> Data {
        var out = rpIdHash(rpId)
        out.append(flags.rawValue)
        out.append(contentsOf: [0, 0, 0, 0])
        return out
    }

    /// COSE_Key for ES256: `{1: 2, 3: -7, -1: 1, -2: x, -3: y}`, in CTAP2 canonical order.
    public static func coseES256(_ key: P256.Signing.PublicKey) -> Data {
        let raw = key.rawRepresentation
        return CBOR.encode(.intMap([(1, .unsigned(2)), (3, .negative(Int64(es256))), (-1, .unsigned(1)),
                                    (-2, .bytes(raw.prefix(32))), (-3, .bytes(raw.suffix(32)))]), deterministic: true)
    }

    // MARK: Parsing (used by tests, the server's independent checks and diagnostics)

    public struct ParsedAuthenticatorData: Sendable, Equatable {
        public var rpIdHash: Data
        public var flags: AuthenticatorFlags
        public var signCount: UInt32
        public var aaguid: Data?
        public var credentialId: Data?
        /// The COSE key bytes (exactly the encoded map).
        public var cosePublicKey: Data?
    }

    public static func parseAuthenticatorData(_ data: Data) throws -> ParsedAuthenticatorData {
        guard data.count >= 37 else { throw WebAuthnError.malformedAuthenticatorData }
        let bytes = [UInt8](data)
        let flags = AuthenticatorFlags(rawValue: bytes[32])
        let count = bytes[33..<37].reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        var parsed = ParsedAuthenticatorData(rpIdHash: Data(bytes[0..<32]), flags: flags, signCount: count)
        var index = 37
        if flags.contains(.attestedCredentialData) {
            guard bytes.count >= index + 18 else { throw WebAuthnError.malformedAuthenticatorData }
            parsed.aaguid = Data(bytes[index..<index + 16])
            let length = Int(bytes[index + 16]) << 8 | Int(bytes[index + 17])
            index += 18
            guard length > 0, length <= 1023, bytes.count >= index + length else { throw WebAuthnError.malformedAuthenticatorData }
            parsed.credentialId = Data(bytes[index..<index + length])
            index += length
            guard let key = try? CBOR.decodePrefix(Data(bytes[index...])) else { throw WebAuthnError.malformedAuthenticatorData }
            parsed.cosePublicKey = Data(bytes[index..<index + key.length])
            index += key.length
        }
        if flags.contains(.extensionData) {
            guard (try? CBOR.decodePrefix(Data(bytes[index...]))) != nil else { throw WebAuthnError.malformedAuthenticatorData }
        } else if index != bytes.count {
            throw WebAuthnError.malformedAuthenticatorData
        }
        return parsed
    }

    /// The P-256 public key in a COSE_Key map, only if it is exactly the ES256 shape.
    public static func publicKey(fromCOSE data: Data) throws -> P256.Signing.PublicKey {
        guard let key = try? CBOR.decode(data), key[1]?.intValue == 2, key[3]?.intValue == Int64(es256), key[-1]?.intValue == 1,
              let x = key[-2]?.byteString, let y = key[-3]?.byteString, x.count == 32, y.count == 32 else { throw WebAuthnError.invalidCredential }
        return try P256.Signing.PublicKey(rawRepresentation: x + y)
    }
}
