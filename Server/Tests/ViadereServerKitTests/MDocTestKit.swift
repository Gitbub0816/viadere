@preconcurrency import Crypto
import Foundation
import SwiftASN1
import ViadereCore
@preconcurrency import X509
@testable import ViadereServerKit

/// Synthetic ISO 18013-5 fixtures: our own IACA and document-signer certificates, a Mobile Security Object, issuer-signed items, device
/// authentication and the Apple HPKE envelope. Nothing here is a real credential; it builds exactly the structures Apple documents so the
/// verifier is exercised end to end, and each `Flaws` field breaks exactly one rule.
struct TestMDocPKI {
    let now: Date
    let iacaKey = P256.Signing.PrivateKey()
    let dsKey = P256.Signing.PrivateKey()
    let iaca: Certificate
    let ds: Certificate
    let iacaName: DistinguishedName

    struct Options {
        var iacaNotAfter: Date?
        var iacaIsCA = true
        var iacaKeyCertSign = true
        var dsNotBefore: Date?
        var dsNotAfter: Date?
        var dsEKU = true
        var dsDigitalSignature = true
        var dsIsCA = false
    }

    init(now: Date = Date(timeIntervalSince1970: 1_800_000_000), options: Options = Options(), name: String = "Test State IACA") {
        self.now = now
        let iacaName = try! DistinguishedName { CommonName(name); CountryName("US") }
        self.iacaName = iacaName
        let iacaExtensions = try! Certificate.Extensions {
            if options.iacaIsCA { Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 0)) }
            Critical(KeyUsage(keyCertSign: options.iacaKeyCertSign, cRLSign: true))
        }
        iaca = try! Certificate(version: .v3, serialNumber: .init(), publicKey: .init(iacaKey.publicKey), notValidBefore: now.addingTimeInterval(-86_400 * 365),
                                notValidAfter: options.iacaNotAfter ?? now.addingTimeInterval(86_400 * 3000), issuer: iacaName, subject: iacaName,
                                signatureAlgorithm: .ecdsaWithSHA256, extensions: iacaExtensions, issuerPrivateKey: .init(iacaKey))
        let dsName = try! DistinguishedName { CommonName("Test Document Signer"); CountryName("US") }
        let dsExtensions = try! Certificate.Extensions {
            if options.dsIsCA { Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 0)) } else { Critical(BasicConstraints.notCertificateAuthority) }
            Critical(KeyUsage(digitalSignature: options.dsDigitalSignature))
            if options.dsEKU { try ExtendedKeyUsage([ExtendedKeyUsage.Usage(oid: IACATrustStore.documentSignerEKU)]) }
        }
        ds = try! Certificate(version: .v3, serialNumber: .init(), publicKey: .init(dsKey.publicKey), notValidBefore: options.dsNotBefore ?? now.addingTimeInterval(-86_400 * 30),
                              notValidAfter: options.dsNotAfter ?? now.addingTimeInterval(86_400 * 300), issuer: iacaName, subject: dsName,
                              signatureAlgorithm: .ecdsaWithSHA256, extensions: dsExtensions, issuerPrivateKey: .init(iacaKey))
    }

    var iacaDER: Data {
        var serializer = DER.Serializer()
        try! serializer.serialize(iaca)
        return Data(serializer.serializedBytes)
    }

    var dsDER: Data {
        var serializer = DER.Serializer()
        try! serializer.serialize(ds)
        return Data(serializer.serializedBytes)
    }

    var fingerprint: String { SecureToken.sha256Hex(iacaDER) }

    func trustStore() -> IACATrustStore {
        IACATrustStore(entries: [try! IACATrustStore.entry(der: iacaDER, now: now, pinned: nil)])
    }
}

/// Builds a `DeviceResponse` for the given elements.
struct TestMDoc {
    var pki: TestMDocPKI
    var now: Date { pki.now }
    var docType = WalletElementPlan.docType
    /// namespace → [(identifier, value)] in issuance order.
    var elements: [String: [(String, CBORValue)]]
    var deviceKey = P256.Signing.PrivateKey()

    struct Flaws {
        var tamperElement: (namespace: String, identifier: String, value: CBORValue)?
        /// Sign `issuerAuth` with a PKI the trust store does not know.
        var otherPKI: TestMDocPKI?
        var signed: Date?
        var validFrom: Date?
        var validUntil: Date?
        /// COSE `alg` placed in the issuer protected header (e.g. -8 for EdDSA).
        var issuerAlgorithm: Int64 = -7
        var deviceTranscript: Data?
        var omitDeviceSignature = false
        var useDeviceMac = false
        var omitX5Chain = false
        var msoDocType: String?
        var digestAlgorithm = "SHA-256"
        var duplicateFirstItem = false
        var deviceNameSpacesNotEmpty = false
        var shortRandom = false
        var documentErrors = false
        var algorithmInUnprotected = false
    }
    var flaws = Flaws()

    init(pki: TestMDocPKI, elements: [String: [(String, CBORValue)]]) {
        self.pki = pki
        self.elements = elements
    }

    static func ageOver(_ years: Int, _ value: Bool, extra: [(String, CBORValue)] = []) -> [String: [(String, CBORValue)]] {
        [WalletElementPlan.isoNamespace: [(WalletElementPlan.ageOverIdentifier(years), .bool(value))] + extra]
    }

    func tdate(_ date: Date) -> CBORValue {
        let formatter = ISO8601DateFormatter()
        return .tagged(0, .text(formatter.string(from: date)))
    }

    func coseKey(_ key: P256.Signing.PublicKey) -> CBORValue {
        let x963 = key.x963Representation
        return .intMap([(1, .unsigned(2)), (-1, .unsigned(1)), (-2, .bytes(x963.subdata(in: 1..<33))), (-3, .bytes(x963.subdata(in: 33..<65)))])
    }

    func sign1(protected: CBORValue, unprotected: CBORValue, payload: Data?, key: P256.Signing.PrivateKey) -> CBORValue {
        let protectedBytes = CBOR.encode(protected)
        let structure = CBOR.encode(.array([.text("Signature1"), .bytes(protectedBytes), .bytes(Data()), .bytes(payload ?? Data())]))
        let signature = try! key.signature(for: structure).rawRepresentation
        return .array([.bytes(protectedBytes), unprotected, payload.map { .bytes($0) } ?? .null, .bytes(signature)])
    }

    /// The `DeviceResponse` CBOR (one document).
    func deviceResponse(sessionTranscript: Data) -> Data {
        var digestIDs: [String: [UInt64: Data]] = [:]
        var itemBytes: [String: [Data]] = [:]
        var nextID: UInt64 = 0
        for (namespace, items) in elements {
            var list = items
            if flaws.duplicateFirstItem, let first = items.first { list.append(first) }
            for (identifier, value) in list {
                let id = nextID
                nextID += 1
                let item = CBORValue.textMap([("digestID", .unsigned(id)), ("random", .bytes(Data(repeating: UInt8(truncatingIfNeeded: id &+ 7), count: flaws.shortRandom ? 8 : 16))),
                                              ("elementIdentifier", .text(identifier)), ("elementValue", value)])
                let wrapped = CBOR.encode(.tagged(24, .bytes(CBOR.encode(item))))
                let digestInput = wrapped
                digestIDs[namespace, default: [:]][id] = flaws.digestAlgorithm == "SHA-384" ? Data(SHA384.hash(data: digestInput)) : Data(SHA256.hash(data: digestInput))
                // A tampered element keeps the digest of the original item but carries another value.
                if let tamper = flaws.tamperElement, tamper.namespace == namespace, tamper.identifier == identifier {
                    let forged = CBORValue.textMap([("digestID", .unsigned(id)), ("random", .bytes(Data(repeating: UInt8(truncatingIfNeeded: id &+ 7), count: 16))),
                                                    ("elementIdentifier", .text(identifier)), ("elementValue", tamper.value)])
                    itemBytes[namespace, default: []].append(CBOR.encode(.tagged(24, .bytes(CBOR.encode(forged)))))
                } else {
                    itemBytes[namespace, default: []].append(wrapped)
                }
            }
        }
        let mso = CBORValue.textMap([
            ("version", .text("1.0")), ("digestAlgorithm", .text(flaws.digestAlgorithm)),
            ("valueDigests", .map(digestIDs.map { namespace, ids in
                CBORValue.Entry(key: .text(namespace), value: .map(ids.sorted { $0.key < $1.key }.map { CBORValue.Entry(key: .unsigned($0.key), value: .bytes($0.value)) }))
            })),
            ("deviceKeyInfo", .textMap([("deviceKey", coseKey(deviceKey.publicKey))])),
            ("docType", .text(flaws.msoDocType ?? docType)),
            ("validityInfo", .textMap([("signed", tdate(flaws.signed ?? now.addingTimeInterval(-3600))), ("validFrom", tdate(flaws.validFrom ?? now.addingTimeInterval(-3600))),
                                       ("validUntil", tdate(flaws.validUntil ?? now.addingTimeInterval(86_400 * 30)))])),
        ])
        let msoPayload = CBOR.encode(.tagged(24, .bytes(CBOR.encode(mso))))
        let signerPKI = flaws.otherPKI ?? pki
        let protectedHeader = CBORValue.intMap([(1, flaws.issuerAlgorithm >= 0 ? .unsigned(UInt64(flaws.issuerAlgorithm)) : .negative(flaws.issuerAlgorithm))])
        var unprotected: [(Int64, CBORValue)] = []
        if !flaws.omitX5Chain { unprotected.append((33, .bytes(signerPKI.dsDER))) }
        if flaws.algorithmInUnprotected { unprotected.append((1, .negative(-7))) }
        let issuerAuth = sign1(protected: protectedHeader, unprotected: .intMap(unprotected), payload: msoPayload, key: signerPKI.dsKey)

        let namespaces = CBORValue.map(itemBytes.map { namespace, items in
            CBORValue.Entry(key: .text(namespace), value: .array(items.map { try! CBOR.decode($0, limits: RawCBOR.limits) }))
        })
        let issuerSigned = CBORValue.textMap([("nameSpaces", namespaces), ("issuerAuth", issuerAuth)])

        let deviceNameSpaces = CBOR.encode(.tagged(24, .bytes(CBOR.encode(flaws.deviceNameSpacesNotEmpty
            ? .textMap([(WalletElementPlan.isoNamespace, .textMap([("x", .bool(true))]))]) : .map([])))))
        var authentication = Data([0x84])
        authentication += CBOR.encode(.text("DeviceAuthentication"))
        authentication += flaws.deviceTranscript ?? sessionTranscript
        authentication += CBOR.encode(.text(docType))
        authentication += deviceNameSpaces
        let authenticationBytes = CBOR.encode(.tagged(24, .bytes(authentication)))
        // The device signs the detached payload (the authentication bytes), so the structure carries `nil` in its payload position.
        let signedDevice: CBORValue = {
            let protectedBytes = CBOR.encode(.intMap([(1, .negative(-7))]))
            let structure = CBOR.encode(.array([.text("Signature1"), .bytes(protectedBytes), .bytes(Data()), .bytes(authenticationBytes)]))
            return .array([.bytes(protectedBytes), .map([]), .null, .bytes(try! deviceKey.signature(for: structure).rawRepresentation)])
        }()
        var deviceAuth: [(String, CBORValue)] = []
        if flaws.useDeviceMac { deviceAuth.append(("deviceMac", .array([.bytes(Data()), .map([]), .null, .bytes(Data(repeating: 1, count: 32))]))) }
        else if !flaws.omitDeviceSignature { deviceAuth.append(("deviceSignature", signedDevice)) }
        let deviceSigned = CBORValue.textMap([("nameSpaces", try! CBOR.decode(deviceNameSpaces, limits: RawCBOR.limits)), ("deviceAuth", .textMap(deviceAuth))])
        let document = CBORValue.textMap([("docType", .text(docType)), ("issuerSigned", issuerSigned), ("deviceSigned", deviceSigned)])
        var response: [(String, CBORValue)] = [("version", .text("1.0")), ("documents", .array([document])), ("status", .unsigned(0))]
        if flaws.documentErrors { response.append(("documentErrors", .array([.textMap([(WalletElementPlan.docType, .unsigned(0))])]))) }
        return CBOR.encode(.textMap(response))
    }

    /// `{"identity": DeviceResponse}`, the HPKE plaintext.
    func plaintext(sessionTranscript: Data) -> Data {
        CBOR.encode(.textMap([("identity", try! CBOR.decode(deviceResponse(sessionTranscript: sessionTranscript), limits: RawCBOR.limits))]))
    }
}

/// What Wallet does with a request: build the transcript from the request's values and seal the plaintext to the merchant key.
enum TestWalletSealer {
    static let teamID = "TEAMID1234"
    static let merchant = "merchant.com.viadere.test"

    enum HashEncoding { case x963, spki, wrong }

    static func transcript(nonce: Data, merchant: String = merchant, team: String = teamID, key: P256.KeyAgreement.PublicKey, encoding: HashEncoding = .x963) -> (transcript: Data, keyHash: Data) {
        let hash: Data
        switch encoding {
        case .x963: hash = Data(SHA256.hash(data: key.x963Representation))
        case .spki: hash = Data(SHA256.hash(data: key.derRepresentation))
        case .wrong: hash = Data(SHA256.hash(data: Data("other".utf8)))
        }
        return (AppleIdentityEnvelope.sessionTranscript(nonce: nonce, merchantIdentifier: merchant, teamIdentifier: team, recipientKeyHash: hash), hash)
    }

    /// The CBOR HPKE envelope bytes as `PKIdentityDocument.encryptedData` would carry them.
    static func seal(_ mdoc: TestMDoc, nonce: Data, recipient: P256.KeyAgreement.PublicKey, merchant: String = merchant, team: String = teamID,
                     encoding: HashEncoding = .x963, infoOverride: Data? = nil, algorithm: String = AppleIdentityEnvelope.algorithm, mode: UInt64 = 0) throws -> Data {
        let built = transcript(nonce: nonce, merchant: merchant, team: team, key: recipient, encoding: encoding)
        var sender = try HPKE.Sender(recipientKey: recipient, ciphersuite: AppleIdentityEnvelope.ciphersuite, info: built.transcript)
        let ciphertext = try sender.seal(mdoc.plaintext(sessionTranscript: built.transcript), authenticating: Data())
        return envelope(encapsulatedKey: sender.encapsulatedKey, keyHash: built.keyHash, infoHash: Data(SHA256.hash(data: infoOverride ?? built.transcript)),
                        ciphertext: ciphertext, algorithm: algorithm, mode: mode)
    }

    static func envelope(encapsulatedKey: Data, keyHash: Data, infoHash: Data, ciphertext: Data, algorithm: String = AppleIdentityEnvelope.algorithm, mode: UInt64 = 0) -> Data {
        CBOR.encode(.textMap([
            ("algorithm", .text(algorithm)),
            ("params", .textMap([("mode", .unsigned(mode)), ("pkEm", .bytes(encapsulatedKey)), ("pkRHash", .bytes(keyHash)), ("infoHash", .bytes(infoHash))])),
            ("data", .bytes(ciphertext)),
        ]))
    }
}
