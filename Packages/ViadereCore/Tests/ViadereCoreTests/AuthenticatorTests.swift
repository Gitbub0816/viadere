import Crypto
import Foundation
import Testing
@testable import ViadereCore

@Suite("CBOR")
struct CBORTests {
    @Test func roundTripsAndIsStrict() throws {
        let value = CBORValue.textMap([("a", .array([.unsigned(1), .negative(-5), .bytes(Data([1])), .text("é"), .bool(true), .null]))])
        #expect(try CBOR.decode(CBOR.encode(value)) == value)
        #expect(throws: CBORError.self) { try CBOR.decode(Data([0x5F, 0x41, 0x01, 0xFF])) }   // indefinite length
        #expect(throws: CBORError.duplicateKey) { try CBOR.decode(Data([0xA2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02])) }
        #expect(throws: CBORError.trailingBytes) { try CBOR.decode(Data([0x01, 0x02])) }
        #expect(throws: CBORError.truncated) { try CBOR.decode(Data([0x44, 0x01])) }
        #expect(throws: CBORError.unsupported) { try CBOR.decode(Data([0xC1, 0x01])) }          // tags
        #expect(throws: CBORError.unsupported) { try CBOR.decode(Data([0xF9, 0x3C, 0x00])) }    // floats
        #expect(throws: CBORError.tooDeep) { try CBOR.decode(Data(repeating: 0x81, count: 40) + Data([0x01])) }
        #expect(throws: CBORError.malformed) { try CBOR.decode(Data([0x62, 0xFF, 0xFE])) }     // invalid UTF-8
        #expect(throws: CBORError.tooLarge) { try CBOR.decode(Data(repeating: 0, count: 70_000)) }
    }

    @Test func deterministicEncodingSortsKeysAndRejectsOtherOrders() throws {
        let unsorted = CBORValue.textMap([("zz", .unsigned(1)), ("a", .unsigned(2)), ("mm", .unsigned(3))])
        let canonical = CBOR.encode(unsorted, deterministic: true)
        // Bytewise order of the encoded keys: "a" (0x61 ..) < "mm" (0x62 ..) < "zz" (0x62 ..).
        #expect(try CBOR.decodeDeterministic(canonical).mapEntries?.map { $0.key.textString } == ["a", "mm", "zz"])
        #expect(throws: CBORError.notCanonical) { try CBOR.decodeDeterministic(CBOR.encode(unsorted)) }
        // Non-shortest integer heads are not canonical either.
        #expect(throws: CBORError.notCanonical) { try CBOR.decodeDeterministic(Data([0x18, 0x01])) }
    }

    @Test func decodePrefixReportsLength() throws {
        let key = CBOR.encode(.intMap([(1, .unsigned(2))]))
        let (value, length) = try CBOR.decodePrefix(key + Data([0xAA, 0xBB]))
        #expect(length == key.count)
        #expect(value[1]?.intValue == 2)
    }

    @Test func negativeIntegerLookup() {
        let map = CBORValue.intMap([(-1, .unsigned(1)), (3, .negative(-7))])
        #expect(map[-1]?.unsignedValue == 1)
        #expect(map[3]?.intValue == -7)
    }
}

@Suite("TOTP (RFC 4226, RFC 6238)")
struct TOTPTests {
    @Test func hotpAppendixDVectors() {
        let secret = Data("12345678901234567890".utf8)
        let expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]
        for (counter, code) in expected.enumerated() {
            #expect(TOTP.hotp(secret: secret, counter: UInt64(counter)) == code)
        }
    }

    @Test func totpAppendixBVectors() {
        let sha1 = Data("12345678901234567890".utf8)
        let sha256 = Data("12345678901234567890123456789012".utf8)
        let sha512 = Data("1234567890123456789012345678901234567890123456789012345678901234".utf8)
        let times: [Int] = [59, 1_111_111_109, 1_111_111_111, 1_234_567_890, 2_000_000_000, 20_000_000_000]
        let vectors: [(TOTPAlgorithm, Data, [String])] = [
            (.sha1, sha1, ["94287082", "07081804", "14050471", "89005924", "69279037", "65353130"]),
            (.sha256, sha256, ["46119246", "68084774", "67062674", "91819424", "90698825", "77737706"]),
            (.sha512, sha512, ["90693936", "25091201", "99943326", "93441116", "38618901", "47863826"]),
        ]
        for (algorithm, secret, codes) in vectors {
            for (time, code) in zip(times, codes) {
                let parameters = TOTPParameters(secret: secret, algorithm: algorithm, digits: 8, period: 30, accountName: "x")
                #expect(TOTP.code(for: parameters, at: Date(timeIntervalSince1970: TimeInterval(time))) == code, "\(algorithm) at \(time)")
            }
        }
    }

    @Test func sixDigitCodesKeepLeadingZerosAndCountdownIsExact() {
        let p = TOTPParameters(secret: Data("12345678901234567890".utf8), accountName: "x")
        // RFC 6238 T=1111111109 truncates to ...07081804, whose last six digits begin with 0.
        #expect(TOTP.code(for: p, at: Date(timeIntervalSince1970: 1_111_111_109)) == "081804")
        #expect(TOTP.secondsRemaining(period: 30, at: Date(timeIntervalSince1970: 60)) == 30)
        #expect(TOTP.secondsRemaining(period: 30, at: Date(timeIntervalSince1970: 89.9)) == 1)
    }

    @Test func base32() {
        #expect(Base32.encode(Data("foobar".utf8), padded: true) == "MZXW6YTBOI======")
        #expect(Base32.decode("mzxw 6ytb-oi======") == Data("foobar".utf8))
        #expect(Base32.decode("MZXW6YTBO1") == nil)        // '1' is not in the alphabet
        #expect(Base32.decode("MZXW6YTBOJ") == nil)        // non-zero padding bits
        #expect(Base32.decode("") == nil)
        for count in 1...40 {
            let data = SecureToken.randomBytes(count)
            #expect(Base32.decode(Base32.encode(data)) == data)
        }
    }

    @Test func parsesKeyURIs() throws {
        let p = try OTPAuthURI.parse("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example")
        #expect(p.issuer == "Example")
        #expect(p.accountName == "alice@google.com")
        #expect(p.secret == Base32.decode("JBSWY3DPEHPK3PXP"))
        #expect(p.algorithm == .sha1 && p.digits == 6 && p.period == 30)
        let q = try OTPAuthURI.parse("otpauth://totp/Acme%20Co:bob%20smith?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=sha256&digits=8&period=60")
        #expect(q.issuer == "Acme Co" && q.accountName == "bob smith" && q.algorithm == .sha256 && q.digits == 8 && q.period == 60)
        #expect(try OTPAuthURI.parse(OTPAuthURI.uri(for: q)) == q)
    }

    @Test func rejectsHostileOrAmbiguousURIs() {
        let good = "secret=JBSWY3DPEHPK3PXP"
        let bad = [
            "otpauth://hotp/x?\(good)&counter=1", "https://totp/x?\(good)", "otpauth://totp/x", "otpauth://totp/x?secret=not*base32",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&secret=JBSWY3DPEHPK3PXP", "otpauth://totp/x?\(good)&digits=9",
            "otpauth://totp/x?\(good)&digits=5", "otpauth://totp/x?\(good)&period=0", "otpauth://totp/x?\(good)&period=99999",
            "otpauth://totp/x?\(good)&algorithm=MD5", "otpauth://totp/Evil:x?\(good)&issuer=Good", "otpauth://totp/?\(good)",
            "otpauth://totp/x%0Ay?\(good)", "otpauth://totp/x%E2%80%AEy?\(good)", "otpauth://user@totp/x?\(good)", "otpauth://totp/x?secret=ME",
            "otpauth://totp/x?\(good)&digits=06x", "otpauth://totp/x?\(good)#frag",
            "otpauth://totp/x?\(good)&pad=" + String(repeating: "a", count: 3000),
        ]
        for uri in bad { #expect(throws: TOTPError.self, "\(uri.prefix(60))") { try OTPAuthURI.parse(uri) } }
    }
}

/// An independent WebAuthn verifier: written from the specification (§7.1, §7.2) against CryptoKit only, sharing nothing with the engine
/// but the CBOR reader. The server's own tests additionally verify with `webauthn-swift`.
enum ReferenceWebAuthnVerifier {
    struct Registration { var credentialId: Data; var publicKey: P256.Signing.PublicKey; var flags: UInt8; var signCount: UInt32; var format: String; var authData: Data }

    static func verifyRegistration(attestationObject: Data, rpId: String, clientDataHash: Data) throws -> Registration {
        let object = try CBOR.decode(attestationObject)
        guard let fmt = object["fmt"]?.textString, let authData = object["authData"]?.byteString, let statement = object["attStmt"] else { throw WebAuthnError.invalidCredential }
        guard authData.count >= 55 else { throw WebAuthnError.malformedAuthenticatorData }
        guard Data(authData.prefix(32)) == Data(SHA256.hash(data: Data(rpId.utf8))) else { throw WebAuthnError.invalidRelyingParty }
        let flags = authData[32]
        guard flags & 0x01 != 0, flags & 0x40 != 0 else { throw WebAuthnError.malformedAuthenticatorData }
        // BS without BE is forbidden by WebAuthn L3 §6.1.3.
        if flags & 0x10 != 0, flags & 0x08 == 0 { throw WebAuthnError.malformedAuthenticatorData }
        let signCount = authData[33..<37].reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        let idLength = Int(authData[53]) << 8 | Int(authData[54])
        let id = Data(authData[55..<(55 + idLength)])
        let coseBytes = Data(authData[(55 + idLength)...])
        let cose = try CBOR.decode(coseBytes)
        guard cose[1]?.intValue == 2, cose[3]?.intValue == -7, cose[-1]?.intValue == 1, let x = cose[-2]?.byteString, let y = cose[-3]?.byteString else {
            throw WebAuthnError.invalidCredential
        }
        let key = try P256.Signing.PublicKey(rawRepresentation: x + y)
        switch fmt {
        case "none": guard statement.mapEntries?.isEmpty == true else { throw WebAuthnError.invalidCredential }
        case "packed":
            guard statement["alg"]?.intValue == -7, statement["x5c"] == nil, let sig = statement["sig"]?.byteString,
                  key.isValidSignature(try P256.Signing.ECDSASignature(derRepresentation: sig), for: authData + clientDataHash) else { throw WebAuthnError.invalidCredential }
        default: throw WebAuthnError.invalidCredential
        }
        return Registration(credentialId: id, publicKey: key, flags: flags, signCount: signCount, format: fmt, authData: authData)
    }

    static func verifyAssertion(_ assertion: PasskeyAssertion, publicKey: P256.Signing.PublicKey, rpId: String, clientDataHash: Data) throws -> UInt8 {
        let authData = assertion.authenticatorData
        guard authData.count == 37, Data(authData.prefix(32)) == Data(SHA256.hash(data: Data(rpId.utf8))), authData[32] & 0x01 != 0 else {
            throw WebAuthnError.malformedAuthenticatorData
        }
        let signature = try P256.Signing.ECDSASignature(derRepresentation: assertion.signature)
        guard publicKey.isValidSignature(signature, for: authData + clientDataHash) else { throw WebAuthnError.invalidCredential }
        return authData[32]
    }
}

@Suite("WebAuthn authenticator")
struct WebAuthnAuthenticatorTests {
    let cdh = Data(SHA256.hash(data: Data("client data".utf8)))
    let now = Date(timeIntervalSince1970: 1_800_000_000)

    func make(rpId: String = "example.com", uv: Bool = true, backedUp: Bool = false, attestation: AttestationFormat = .none,
              excluded: [Data] = [], existing: Set<Data> = []) throws -> CreatedPasskey {
        try WebAuthnAuthenticator.makeCredential(rpId: rpId, userHandle: Data([1, 2, 3]), userName: "alice", displayName: "Alice", clientDataHash: cdh,
                                                 excludedCredentialIds: excluded, existingCredentialIds: existing, requireUserVerification: true,
                                                 userVerified: uv, backedUp: backedUp, attestation: attestation, now: now)
    }

    @Test func registrationVerifiesWithTheReferenceVerifier() throws {
        for format in [AttestationFormat.none, .packedSelf] {
            let created = try make(backedUp: true, attestation: format)
            let result = try ReferenceWebAuthnVerifier.verifyRegistration(attestationObject: created.attestationObject, rpId: "example.com", clientDataHash: cdh)
            #expect(result.credentialId == created.credential.credentialId)
            #expect(result.credentialId.count == 32)
            #expect(result.signCount == 0)
            #expect(result.flags == 0x01 | 0x04 | 0x08 | 0x10 | 0x40, "UP | UV | BE | BS | AT")
            #expect(result.format == (format == .none ? "none" : "packed"))
            #expect(result.publicKey.x963Representation == (try P256.Signing.PrivateKey(rawRepresentation: created.credential.privateKey)).publicKey.x963Representation)
            #expect(Data(result.authData[37..<53]) == Data(repeating: 0, count: 16), "zero AAGUID")
        }
    }

    @Test func attestationObjectIsCanonicalCBORWithTheExpectedKeyOrder() throws {
        let created = try make()
        let object = try CBOR.decodeDeterministic(created.attestationObject)
        #expect(object.mapEntries?.map { $0.key.textString } == ["fmt", "attStmt", "authData"])
        let parsed = try WebAuthnAuthenticator.parseAuthenticatorData(created.authenticatorData)
        #expect(parsed.cosePublicKey == (try created.credential.cosePublicKey()))
        // COSE_Key order is 1, 3, -1, -2, -3.
        let cose = try CBOR.decodeDeterministic(try #require(parsed.cosePublicKey))
        #expect(cose.mapEntries?.compactMap { $0.key.intValue } == [1, 3, -1, -2, -3])
        let key = try WebAuthnAuthenticator.publicKey(fromCOSE: try #require(parsed.cosePublicKey))
        #expect(key.rawRepresentation.count == 64)
    }

    @Test func assertionVerifiesAndBindsTheRelyingParty() throws {
        let created = try make()
        let key = try P256.Signing.PrivateKey(rawRepresentation: created.credential.privateKey).publicKey
        let assertion = try WebAuthnAuthenticator.getAssertion(credential: created.credential, rpId: "example.com", clientDataHash: cdh,
                                                               requireUserVerification: true, userVerified: true, backedUp: false)
        let flags = try ReferenceWebAuthnVerifier.verifyAssertion(assertion, publicKey: key, rpId: "example.com", clientDataHash: cdh)
        #expect(flags == 0x01 | 0x04 | 0x08)
        #expect(assertion.userHandle == Data([1, 2, 3]))
        #expect(try WebAuthnAuthenticator.parseAuthenticatorData(assertion.authenticatorData).signCount == 0)
        // Wrong client data hash, wrong rpId, tampered authenticator data: all fail verification.
        #expect(throws: (any Error).self) { try ReferenceWebAuthnVerifier.verifyAssertion(assertion, publicKey: key, rpId: "example.com", clientDataHash: Data(repeating: 1, count: 32)) }
        #expect(throws: (any Error).self) { try ReferenceWebAuthnVerifier.verifyAssertion(assertion, publicKey: key, rpId: "evil.com", clientDataHash: cdh) }
        var tampered = assertion
        tampered.authenticatorData[32] ^= 0x04
        #expect(throws: (any Error).self) { try ReferenceWebAuthnVerifier.verifyAssertion(tampered, publicKey: key, rpId: "example.com", clientDataHash: cdh) }
        // The credential only signs for its own relying party.
        #expect(throws: WebAuthnError.invalidRelyingParty) {
            try WebAuthnAuthenticator.getAssertion(credential: created.credential, rpId: "evil.com", clientDataHash: cdh, requireUserVerification: true, userVerified: true, backedUp: false)
        }
    }

    @Test func userVerificationIsEnforcedAndFlagsFollowIt() throws {
        #expect(throws: WebAuthnError.userVerificationRequired) { try make(uv: false) }
        let created = try WebAuthnAuthenticator.makeCredential(rpId: "example.com", userHandle: Data([9]), userName: "a", clientDataHash: cdh,
                                                               requireUserVerification: false, userVerified: false, backedUp: false, now: now)
        let flags = try WebAuthnAuthenticator.parseAuthenticatorData(created.authenticatorData).flags
        #expect(!flags.contains(.userVerified) && flags.contains(.userPresent) && flags.contains(.backupEligible) && !flags.contains(.backupState))
        #expect(throws: WebAuthnError.userVerificationRequired) {
            try WebAuthnAuthenticator.getAssertion(credential: created.credential, rpId: "example.com", clientDataHash: cdh, requireUserVerification: true, userVerified: false, backedUp: false)
        }
    }

    @Test func inputsAreValidated() throws {
        #expect(throws: WebAuthnError.invalidClientDataHash) {
            try WebAuthnAuthenticator.makeCredential(rpId: "example.com", userHandle: Data([1]), userName: "a", clientDataHash: Data([1]), requireUserVerification: true, userVerified: true, backedUp: false, now: now)
        }
        #expect(throws: WebAuthnError.unsupportedAlgorithm) {
            try WebAuthnAuthenticator.makeCredential(rpId: "example.com", userHandle: Data([1]), userName: "a", clientDataHash: cdh, supportedAlgorithms: [-257], requireUserVerification: true, userVerified: true, backedUp: false, now: now)
        }
        #expect(throws: WebAuthnError.invalidUserHandle) {
            try WebAuthnAuthenticator.makeCredential(rpId: "example.com", userHandle: Data(), userName: "a", clientDataHash: cdh, requireUserVerification: true, userVerified: true, backedUp: false, now: now)
        }
        for bad in ["", "Example.com", "https://example.com", "example.com:443", "example.com/", "-a.com", "a..com", "1.2.3.4", "exa mple.com", "user@example.com", "com"] {
            #expect(!WebAuthnAuthenticator.isValidRelyingPartyID(bad), "\(bad)")
            #expect(throws: WebAuthnError.invalidRelyingParty) { try make(rpId: bad) }
        }
        #expect(WebAuthnAuthenticator.isValidRelyingPartyID("login.example.co.uk"))
        #expect(WebAuthnAuthenticator.isValidRelyingPartyID("xn--bcher-kva.example"))
        #expect(WebAuthnAuthenticator.isValidRelyingPartyID("localhost"))
    }

    @Test func excludedCredentialsBlockRegistrationAndIdsAreUnique() throws {
        let first = try make()
        #expect(throws: WebAuthnError.credentialExcluded) { try make(excluded: [first.credential.credentialId], existing: [first.credential.credentialId]) }
        // An exclude list naming a credential the vault does not hold does not block.
        _ = try make(excluded: [Data([9, 9])], existing: [first.credential.credentialId])
        var ids = Set<Data>()
        for _ in 0..<200 { #expect(ids.insert(try make().credential.credentialId).inserted) }
    }

    @Test func parsesAuthenticatorDataStrictly() throws {
        let created = try make()
        var truncated = created.authenticatorData
        truncated.removeLast(5)
        #expect(throws: WebAuthnError.malformedAuthenticatorData) { try WebAuthnAuthenticator.parseAuthenticatorData(truncated) }
        #expect(throws: WebAuthnError.malformedAuthenticatorData) { try WebAuthnAuthenticator.parseAuthenticatorData(Data(count: 36)) }
        var trailing = try WebAuthnAuthenticator.getAssertion(credential: created.credential, rpId: "example.com", clientDataHash: cdh, requireUserVerification: true, userVerified: true, backedUp: false).authenticatorData
        trailing.append(0)
        #expect(throws: WebAuthnError.malformedAuthenticatorData) { try WebAuthnAuthenticator.parseAuthenticatorData(trailing) }
    }
}
