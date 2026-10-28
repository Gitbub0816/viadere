@preconcurrency import Crypto
import Foundation
import ViadereCore
@_spi(FixedExpiryValidationTime) @preconcurrency import X509

/// What a verified presentation yields: **only the requested elements**, plus validity facts. Everything else in the `DeviceResponse`
/// is dropped by the verifier and never leaves it. Not `Codable` and never persisted: the caller turns it into the capability's
/// output and lets it go out of scope.
struct MDocVerification: Sendable {
    var docType: String
    /// Lowercase hex SHA-256 prefix (16 chars) of the trust anchor.
    var issuerAnchor: String
    var signedAt: Date
    var validFrom: Date
    var validUntil: Date
    /// The requested elements that were present and digest-verified, with their values.
    var elements: [MDocElement: CBORValue]
    /// The issuing country (ISO 3166-1 alpha-2): the document signer's and the IACA's `countryName`, which agree (and agree with the
    /// `issuing_country` element when the response carries it).
    var issuerCountry: String
}

/// Verifies an ISO/IEC 18013-5 `DeviceResponse` (the plaintext Apple Wallet's identity presentment produces, no ISO session encryption):
///
/// 1. `issuerAuth` is a `COSE_Sign1` (ES256/ES384/ES512 only) whose `x5chain` validates to a configured IACA, with a document-signer
///    certificate that carries the mdoc profile (`IACATrustStore.validate`);
/// 2. the signature over the Mobile Security Object verifies, the MSO says `docType` matches, and `validityInfo` covers now **and** the
///    document-signer certificate covers `signed`;
/// 3. every `IssuerSignedItem` in the allowed namespaces hashes (over its exact bytes) to the digest the MSO lists, so a changed value,
///    a swapped item or an item the issuer never signed is refused;
/// 4. `DeviceAuth` is an ECDSA `COSE_Sign1` over `DeviceAuthentication = ["DeviceAuthentication", SessionTranscript, docType,
///    DeviceNameSpacesBytes]` made with the device key in the MSO, so the presentation is bound to the transcript (this request's
///    nonce, merchant, team and encryption key). MAC authentication and device-signed elements are refused.
struct MDocVerifier: Sendable {
    static let acceptedDocTypes: Set<String> = [WalletElementPlan.docType]
    /// Clock skew tolerated between the issuer's clock and ours for `signed` and `validFrom`.
    static let skew: TimeInterval = 300
    static let maxItemsPerNamespace = 128
    /// Read (when present) for the country consistency check; not part of any capability's output.
    static let issuingCountryElement = MDocElement(namespace: WalletElementPlan.isoNamespace, identifier: "issuing_country")

    let trust: IACATrustStore

    func verify(plaintext: Data, sessionTranscript: Data, requested: Set<MDocElement>, now: Date) async throws -> MDocVerification {
        // Topics = {"identity": DeviceResponse}: exactly one topic.
        guard let topics = try? RawCBOR.decode(plaintext), case .map(let topicEntries) = topics, topicEntries.count == 1,
              let responseRaw = try? RawCBOR.mapValue(plaintext, key: "identity") else { throw MDocFailure.malformedResponse }
        return try await verify(deviceResponse: responseRaw, sessionTranscript: sessionTranscript, requested: requested, now: now)
    }

    func verify(deviceResponse raw: Data, sessionTranscript: Data, requested: Set<MDocElement>, now: Date) async throws -> MDocVerification {
        guard let response = try? RawCBOR.decode(raw), case .map = response else { throw MDocFailure.malformedResponse }
        guard response["version"]?.textString == "1.0" else { throw MDocFailure.unsupportedVersion }
        guard response["status"]?.unsignedValue == 0 else { throw MDocFailure.malformedResponse }
        // A document-level error list means the wallet could not return what was asked: nothing to trust.
        if let errors = response["documentErrors"], errors != .array([]) { throw MDocFailure.malformedResponse }
        guard let documents = response["documents"]?.arrayValue, documents.count == 1,
              let documentsRaw = try? RawCBOR.mapValue(raw, key: "documents"), let documentRaw = try? RawCBOR.arrayElements(documentsRaw).first
        else { throw MDocFailure.malformedResponse }
        // One view of the structure: everything below is read from the raw slices (which reject duplicate keys and non-shortest heads),
        // decoded once; the decoded `response` above is used only to find them. A disagreement between the two is a refusal.
        guard let document = try? RawCBOR.decode(documentRaw), document == documents[0] else { throw MDocFailure.malformedResponse }
        guard let docType = document["docType"]?.textString, Self.acceptedDocTypes.contains(docType) else { throw MDocFailure.unsupportedDocType }
        guard let issuerSignedRaw = try? RawCBOR.mapValue(documentRaw, key: "issuerSigned"),
              let deviceSignedRaw = try? RawCBOR.mapValue(documentRaw, key: "deviceSigned"),
              let issuerSigned = try? RawCBOR.decode(issuerSignedRaw), let deviceSigned = try? RawCBOR.decode(deviceSignedRaw),
              document["issuerSigned"] == issuerSigned, document["deviceSigned"] == deviceSigned,
              let issuerAuthValue = issuerSigned["issuerAuth"] else { throw MDocFailure.malformedResponse }

        // 1 and 2: issuer authentication.
        let issuerAuth = try COSESign1(issuerAuthValue)
        let chain = try Self.certificateChain(from: issuerAuth.unprotected)
        let issuer = try await trust.validate(chain: chain, now: now)
        guard let issuerKey = COSEVerificationKey(certificateKey: issuer.leaf.publicKey), issuerKey.curve == issuerAuth.algorithm.curve else {
            throw MDocFailure.unsupportedAlgorithm
        }
        guard let msoPayload = issuerAuth.payload, issuerAuth.verify(key: issuerKey, payload: msoPayload) else { throw MDocFailure.badIssuerSignature }
        let mso = try Self.parseMSO(msoPayload, docType: docType)
        guard mso.signed <= now.addingTimeInterval(Self.skew), mso.validFrom <= now.addingTimeInterval(Self.skew), now < mso.validUntil,
              mso.validFrom < mso.validUntil else { throw MDocFailure.outsideValidity }
        guard issuer.leaf.notValidBefore <= mso.signed.addingTimeInterval(Self.skew), mso.signed <= issuer.leaf.notValidAfter else { throw MDocFailure.outsideValidity }

        // 3: digests of every item in the allowed namespaces.
        let read = try Self.verifiedElements(issuerSignedRaw: issuerSignedRaw, mso: mso, requested: requested.union([Self.issuingCountryElement]))
        var elements = read
        // The issuing country element, when the response carries it, must be the certificates' country (ISO 18013-5 Annex B: the DS and the
        // IACA name the issuing country). Apple's Wallet cannot be asked for it, so its absence is not an error.
        if let claimed = elements.removeValue(forKey: Self.issuingCountryElement) {
            guard let text = claimed.textString, CountryCodes.alpha2(text) == issuer.country, text.count == 2 else { throw MDocFailure.issuerCountryMismatch }
            if requested.contains(Self.issuingCountryElement) { elements[Self.issuingCountryElement] = claimed }
        }

        // 4: device authentication over the transcript.
        try Self.verifyDeviceAuth(deviceSigned: deviceSigned, deviceSignedRaw: deviceSignedRaw, deviceKey: mso.deviceKey, docType: docType,
                                  sessionTranscript: sessionTranscript)
        return MDocVerification(docType: docType, issuerAnchor: String(issuer.anchorFingerprint.prefix(16)), signedAt: mso.signed,
                                validFrom: mso.validFrom, validUntil: mso.validUntil, elements: elements, issuerCountry: issuer.country)
    }

    // MARK: Issuer certificate chain

    /// `x5chain` (COSE header 33) from the **unprotected** header: one certificate or an array of up to three.
    static func certificateChain(from unprotected: CBORValue) throws -> [Certificate] {
        guard let value = unprotected[33] else { throw MDocFailure.noIssuerCertificate }
        let blobs: [Data]
        if let single = value.byteString { blobs = [single] }
        else if let list = value.arrayValue, !list.isEmpty, list.count <= 3, list.allSatisfy({ $0.byteString != nil }) { blobs = list.compactMap(\.byteString) }
        else { throw MDocFailure.noIssuerCertificate }
        return try blobs.map { der in
            guard der.count <= 4096, let certificate = try? Certificate(derEncoded: Array(der)) else { throw MDocFailure.noIssuerCertificate }
            return certificate
        }
    }

    // MARK: Mobile Security Object

    struct MSO {
        var digestAlgorithm: String
        var valueDigests: [String: [UInt64: Data]]
        var deviceKey: COSEVerificationKey
        var signed: Date
        var validFrom: Date
        var validUntil: Date
    }

    static func parseMSO(_ payload: Data, docType: String) throws -> MSO {
        // MobileSecurityObjectBytes = #6.24(bstr .cbor MobileSecurityObject)
        guard let outer = try? RawCBOR.decode(payload), let inner = outer.content(taggedWith: 24)?.byteString,
              let mso = try? RawCBOR.decode(inner), case .map = mso else { throw MDocFailure.badMobileSecurityObject }
        guard mso["version"]?.textString == "1.0", let algorithm = mso["digestAlgorithm"]?.textString, ["SHA-256", "SHA-384", "SHA-512"].contains(algorithm),
              mso["docType"]?.textString == docType,
              let digestMap = mso["valueDigests"]?.mapEntries,
              let deviceKeyValue = mso["deviceKeyInfo"]?["deviceKey"], let deviceKey = COSEVerificationKey(coseKey: deviceKeyValue),
              let validity = mso["validityInfo"], let signed = date(validity["signed"]), let from = date(validity["validFrom"]),
              let until = date(validity["validUntil"]) else { throw MDocFailure.badMobileSecurityObject }
        var digests: [String: [UInt64: Data]] = [:]
        for entry in digestMap {
            guard let namespace = entry.key.textString, let byID = entry.value.mapEntries, byID.count <= 4096 else { throw MDocFailure.badMobileSecurityObject }
            var ids: [UInt64: Data] = [:]
            for pair in byID {
                guard let id = pair.key.unsignedValue, let digest = pair.value.byteString, digest.count == digestLength(algorithm) else {
                    throw MDocFailure.badMobileSecurityObject
                }
                ids[id] = digest
            }
            digests[namespace] = ids
        }
        return MSO(digestAlgorithm: algorithm, valueDigests: digests, deviceKey: deviceKey, signed: signed, validFrom: from, validUntil: until)
    }

    static func digestLength(_ algorithm: String) -> Int {
        switch algorithm {
        case "SHA-256": 32
        case "SHA-384": 48
        default: 64
        }
    }

    static func digest(_ algorithm: String, _ data: Data) -> Data {
        switch algorithm {
        case "SHA-256": Data(SHA256.hash(data: data))
        case "SHA-384": Data(SHA384.hash(data: data))
        default: Data(SHA512.hash(data: data))
        }
    }

    /// `tdate`: tag 0 with an RFC 3339 string.
    static func date(_ value: CBORValue?) -> Date? {
        guard let text = value?.content(taggedWith: 0)?.textString, text.count <= 40 else { return nil }
        return ViadereDate.parse(text) ?? ISO8601DateFormatter().date(from: text)
    }

    // MARK: Issuer-signed items

    static func verifiedElements(issuerSignedRaw: Data, mso: MSO, requested: Set<MDocElement>) throws -> [MDocElement: CBORValue] {
        // `nameSpaces` is optional in the structure; a response with none cannot satisfy a request for elements.
        guard let namespacesRaw = try? RawCBOR.mapValue(issuerSignedRaw, key: "nameSpaces"), let namespaces = try? RawCBOR.decode(namespacesRaw),
              let namespaceEntries = namespaces.mapEntries else { throw MDocFailure.noRequestedElement }
        var out: [MDocElement: CBORValue] = [:]
        for entry in namespaceEntries {
            // Namespaces outside the allow-list are dropped without being read.
            guard let namespace = entry.key.textString, WalletElementPlan.allowedNamespaces.contains(namespace),
                  let itemsValue = entry.value.arrayValue else { continue }
            guard let digests = mso.valueDigests[namespace], itemsValue.count <= maxItemsPerNamespace,
                  let itemsRaw = try? namespaceItems(namespacesRaw, namespace: namespace), itemsRaw.count == itemsValue.count else {
                throw MDocFailure.digestMismatch
            }
            var seenIDs = Set<UInt64>()
            var seenNames = Set<String>()
            for raw in itemsRaw {
                // IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem); the digest is over these exact bytes (tag and all).
                guard let wrapper = try? RawCBOR.decode(raw), let innerBytes = wrapper.content(taggedWith: 24)?.byteString,
                      let item = try? RawCBOR.decode(innerBytes), case .map = item,
                      let id = item["digestID"]?.unsignedValue, let random = item["random"]?.byteString, random.count >= 16,
                      let identifier = item["elementIdentifier"]?.textString, identifier.count <= 64, let value = item["elementValue"],
                      let expected = digests[id] else { throw MDocFailure.digestMismatch }
                guard ConstantTime.equals(digest(mso.digestAlgorithm, raw), expected), seenIDs.insert(id).inserted, seenNames.insert(identifier).inserted else {
                    throw MDocFailure.digestMismatch
                }
                let element = MDocElement(namespace: namespace, identifier: identifier)
                if requested.contains(element) { out[element] = value }
            }
        }
        return out
    }

    /// The raw `IssuerSignedItemBytes` of one namespace's array.
    private static func namespaceItems(_ namespacesRaw: Data, namespace: String) throws -> [Data] {
        guard let arrayRaw = try RawCBOR.mapValue(namespacesRaw, key: namespace) else { throw MDocFailure.malformedResponse }
        return try RawCBOR.arrayElements(arrayRaw)
    }

    // MARK: Device authentication

    static func verifyDeviceAuth(deviceSigned: CBORValue?, deviceSignedRaw: Data, deviceKey: COSEVerificationKey, docType: String,
                                 sessionTranscript: Data) throws {
        guard let deviceSigned, case .map = deviceSigned, let deviceAuth = deviceSigned["deviceAuth"], case .map = deviceAuth else {
            throw MDocFailure.missingDeviceAuthentication
        }
        // ECDSA only (the framework never uses MAC); a MAC would need the reader's ephemeral key we do not have.
        guard deviceAuth["deviceMac"] == nil, let signatureValue = deviceAuth["deviceSignature"] else { throw MDocFailure.missingDeviceAuthentication }
        let signature = try COSESign1(signatureValue)
        guard signature.payload == nil else { throw MDocFailure.badDeviceSignature }
        // DeviceNameSpacesBytes = #6.24(bstr .cbor {}): the device signs no elements of its own.
        guard let namespacesRaw = try? RawCBOR.mapValue(deviceSignedRaw, key: "nameSpaces"), let namespaces = try? RawCBOR.decode(namespacesRaw),
              let content = namespaces.content(taggedWith: 24)?.byteString, let decoded = try? RawCBOR.decode(content), decoded.mapEntries?.isEmpty == true
        else { throw MDocFailure.unexpectedDeviceNamespaces }
        // DeviceAuthenticationBytes = #6.24(bstr .cbor ["DeviceAuthentication", SessionTranscript, DocType, DeviceNameSpacesBytes]).
        var authentication = Data([0x84])
        authentication += CBOR.encode(.text("DeviceAuthentication"))
        authentication += sessionTranscript
        authentication += CBOR.encode(.text(docType))
        authentication += namespacesRaw
        let authenticationBytes = CBOR.encode(.tagged(24, .bytes(authentication)))
        guard signature.verify(key: deviceKey, payload: authenticationBytes) else { throw MDocFailure.badDeviceSignature }
    }
}
