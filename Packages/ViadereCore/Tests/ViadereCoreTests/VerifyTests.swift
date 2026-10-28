import Foundation
import Testing
@testable import ViadereCore

/// WP3 (Verify): assurance taxonomy, age arithmetic, the Wallet element plan, the wire types and the display digest.
@Suite("Verify")
struct VerifyTests {
    let now = Date(timeIntervalSince1970: 1_800_000_000) // 2027-01-15

    // MARK: Taxonomy (VER-005, VER-007, VER-009, AGE-002)

    @Test func eachMethodEstablishesOnlyItsOwnLabels() {
        #expect(VerificationMethod.walletMdoc.establishes == [.verifiedAgeThreshold, .verifiedIdentity])
        #expect(VerificationMethod.diditDocumentLiveness.establishes == [.verifiedAgeThreshold, .verifiedIdentity])
        // A selfie age estimate is an estimate: never a verified age, never an identity (AGE-002).
        #expect(VerificationMethod.diditAgeEstimation.establishes == [.estimatedAge])
        #expect(VerificationMethod.deviceAuthenticator.establishes == [.registeredAuthenticator])
        #expect(VerificationMethod.contactCode.establishes == [.reachableContact])
    }

    @Test func noLabelIsPromotedToAStrongerClaim() {
        for requirement in RequiredEvidence.allCases where requirement != .none {
            let satisfying = VerificationLabel.allCases.filter { requirement.isSatisfied(by: $0) }
            #expect(satisfying.count == 1, "\(requirement) must be satisfied by exactly one label")
        }
        #expect(!RequiredEvidence.verifiedAgeThreshold.isSatisfied(by: .verifiedIdentity))
        #expect(!RequiredEvidence.verifiedAgeThreshold.isSatisfied(by: .estimatedAge))
        #expect(!RequiredEvidence.verifiedIdentity.isSatisfied(by: .registeredAuthenticator))
        #expect(!RequiredEvidence.verifiedIdentity.isSatisfied(by: .reachableContact))
        #expect(!RequiredEvidence.verifiedIdentity.isSatisfied(by: .verifiedAgeThreshold))
        #expect(!RequiredEvidence.registeredAuthenticator.isSatisfied(by: .verifiedIdentity))
    }

    @Test func mapperKeepsEstimatesApartFromVerifiedClaims() {
        // An estimate never produces a verified label, even if the provider also "validated" something.
        let estimate = VerificationAssuranceMapper.Observation(method: .diditAgeEstimation, validatedAgeStatement: true, validatedIdentityAttributes: true, estimatedAgeOnly: true)
        #expect(VerificationAssuranceMapper.labels(for: estimate) == [.estimatedAge])
        let wallet = VerificationAssuranceMapper.Observation(method: .walletMdoc, validatedAgeStatement: true)
        #expect(VerificationAssuranceMapper.labels(for: wallet) == [.verifiedAgeThreshold])
        let walletName = VerificationAssuranceMapper.Observation(method: .walletMdoc, validatedIdentityAttributes: true)
        #expect(VerificationAssuranceMapper.labels(for: walletName) == [.verifiedIdentity])
        // A wallet credential cannot establish an authenticator or a contact.
        #expect(VerificationAssuranceMapper.labels(for: .init(method: .walletMdoc)).isEmpty)
        #expect(VerificationAssuranceMapper.labels(for: .init(method: .contactCode)) == [.reachableContact])
    }

    @Test func provenanceOfAnEstimateOrAWeakLabelNeverBecomesPolicyEvidence() {
        let dims = VerificationAssuranceMapper.providerDimensions(verifiedAt: now, validUntil: now.addingTimeInterval(900), risk: .high)
        let estimate = VerificationProvenance(method: .diditAgeEstimation, issuer: "didit:ESP", label: .estimatedAge, assurance: dims, expiresAt: now.addingTimeInterval(900), revocation: .notApplicable)
        #expect(estimate.evidenceHolding() == nil)
        // A method cannot carry a label it cannot establish: the record is inconsistent and yields no evidence.
        let forged = VerificationProvenance(method: .diditAgeEstimation, issuer: "didit:ESP", label: .verifiedAgeThreshold, assurance: dims, expiresAt: now.addingTimeInterval(900), revocation: .notApplicable)
        #expect(!forged.isConsistent)
        #expect(forged.evidenceHolding() == nil)
        let contact = VerificationProvenance(method: .contactCode, issuer: "viadere", label: .reachableContact, assurance: dims, expiresAt: now.addingTimeInterval(900), revocation: .notApplicable)
        #expect(contact.evidenceHolding() == nil)
        let age = VerificationProvenance(method: .walletMdoc, issuer: "00112233aabbccdd", label: .verifiedAgeThreshold,
                                         assurance: VerificationAssuranceMapper.walletDimensions(verifiedAt: now, validUntil: now.addingTimeInterval(900), risk: .high),
                                         expiresAt: now.addingTimeInterval(900), revocation: .notChecked)
        #expect(age.evidenceHolding()?.kind == .verifiedAgeThreshold)
        #expect(age.verifier == "viadere" && age.policyVersion == VerifyPolicy.version)
        // An age result is never identity evidence.
        #expect(age.evidenceHolding()?.kind != .verifiedIdentity)
    }

    @Test func provenanceRecordsEveryDimensionWithoutPersonalData() throws {
        let provenance = VerificationProvenance(method: .walletMdoc, issuer: "00112233aabbccdd", label: .verifiedAgeThreshold,
            assurance: VerificationAssuranceMapper.walletDimensions(verifiedAt: now, validUntil: now.addingTimeInterval(900), risk: .high),
            expiresAt: now.addingTimeInterval(900), revocation: .notChecked)
        let json = String(decoding: try ViadereJSON.encode(provenance), as: UTF8.self)
        for key in ["method", "verifier", "issuer", "label", "evidence", "authenticator", "issuerTrust", "verifiedAt", "validUntil", "presentationBinding",
                    "transactionRisk", "expiresAt", "revocation", "policyVersion"] {
            #expect(json.contains("\"\(key)\""), "missing \(key)")
        }
        for banned in CapabilityCatalog.personalDataFieldNames { #expect(!json.contains("\"\(banned)\"")) }
        #expect(provenance.assurance.level == "issuer_signed_credential_device_bound")
    }

    @Test func labelsAreDistinctAndNeverAUniversalBadge() {
        let names = Set(VerificationLabel.allCases.map(\.displayName))
        #expect(names.count == VerificationLabel.allCases.count)
        #expect(!VerificationLabel.allCases.contains { $0.displayName.lowercased() == "verified" })
        #expect(VerificationLabel.estimatedAge.displayName.contains("not verified"))
        #expect(VerificationLabel.allCases.allSatisfy { !$0.limits.isEmpty })
    }

    // MARK: Age arithmetic (AGE-001)

    @Test func ageThresholdBoundaries() {
        func meets(_ birth: String, _ years: Int, on today: String) -> Bool {
            AgeThreshold.meets(birth: AgeThreshold.Day(isoDate: birth)!, years: years, today: AgeThreshold.Day(isoDate: today)!)
        }
        #expect(meets("2005-06-15", 21, on: "2026-06-15"))
        #expect(!meets("2005-06-15", 21, on: "2026-06-14"))
        #expect(meets("2000-02-29", 18, on: "2018-03-01"))
        #expect(!meets("2000-02-29", 18, on: "2018-02-28"))
        #expect(meets("2000-02-29", 24, on: "2024-02-29"))
        #expect(!meets("2030-01-01", 0, on: "2026-01-01"), "a birth date in the future meets nothing")
        #expect(AgeThreshold.Day(isoDate: "2000-13-01") == nil)
        #expect(AgeThreshold.Day(isoDate: "2000-02-30") == nil)
        #expect(AgeThreshold.Day(isoDate: "20000101") == nil)
        #expect(AgeThreshold.Day(isoDate: "1899-01-01") == nil)
        #expect(AgeThreshold.meets(birthDate: "1990-01-01", years: 18, now: now) == true)
        #expect(AgeThreshold.meets(birthDate: "garbage", years: 18, now: now) == nil)
    }

    // MARK: Wallet element plan (AGE-001, AGE-003)

    @Test func ageRequestsNeverAskForTheBirthDate() {
        let plan = WalletElementPlan.request(for: .ageMinimum, parameters: ["years": .integer(21)])
        #expect(plan == .ageAtLeast(21))
        #expect(WalletElementPlan.requestedIdentifiers(for: plan!) == ["age_over_21"])
        let readable = WalletElementPlan.readableElements(for: plan!).map(\.identifier)
        #expect(readable.contains("age_over_21"))
        #expect(WalletElementPlan.ageOverIdentifier(8) == "age_over_08")
        #expect(WalletElementPlan.request(for: .ageMinimum, parameters: [:]) == nil)
        #expect(WalletElementPlan.request(for: .messageSend, parameters: [:]) == nil)
        #expect(WalletElementPlan.request(for: .identityName, parameters: [:]) == .givenAndFamilyName)
        #expect(WalletElementPlan.requestedIdentifiers(for: .givenAndFamilyName) == ["given_name", "family_name"])
        #expect(WalletElementPlan.allowedNamespaces == [WalletElementPlan.isoNamespace, WalletElementPlan.aamvaNamespace])
    }

    // MARK: Wire types

    @Test func idsRoundTripAndRejectLookalikes() throws {
        let id = VerificationRequestID()
        #expect(id.description.count == 26 && id.description.hasPrefix("req_"))
        #expect(VerificationRequestID(id.description) == id)
        #expect(VerificationRequestID("req_short") == nil)
        #expect(VerificationRequestID("xxx_" + id.description.dropFirst(4)) == nil)
        let ref = VerificationResultRef.generate()
        #expect(VerificationResultRef(ref.rawValue) == ref)
        #expect(VerificationResultRef("res_abc") == nil)
        let data = try ViadereJSON.encode(["id": id])
        #expect(try ViadereJSON.decode([String: VerificationRequestID].self, from: data)["id"] == id)
    }

    @Test func createRequestUsesSnakeCaseAndRefusesAnUnknownShape() throws {
        let ref = SubjectRef("sub_" + Base64URL.encode(Data(repeating: 7, count: 32)))!
        let body = CreateVerificationRequest(subjectRef: ref, capability: .ageMinimum, parameters: ["years": .integer(18)],
                                             purposeCode: "age_restricted_access", callbackId: "5d1b2a60-0000-4000-8000-000000000001", expiresInSeconds: 180)
        let text = String(decoding: try ViadereJSON.encode(body), as: UTF8.self)
        for key in ["subject_ref", "purpose_code", "callback_id", "expires_in_seconds"] { #expect(text.contains(key)) }
        #expect(try ViadereJSON.decode(CreateVerificationRequest.self, from: Data(text.utf8)) == body)
    }

    @Test func resultTopLevelFieldsAreTheEnvelopePlusReferenceAndOutcome() {
        #expect(VerificationResult.topLevelFields == Set(CapabilityCatalog.resultEnvelopeFields).union(["result_ref", "outcome", "result", "encrypted_result", "encrypted_result_kid"]))
        #expect(VerificationOutcome.allCases.count == 2, "no outcome distinguishes underage from unable or unwilling (AGE-005)")
        #expect(BusinessVerificationStatus.allCases.count == 2)
    }

    @Test func webhookCarriesOnlyOpaqueIdentifiers() throws {
        let data = VerificationCompletedEventData(requestId: VerificationRequestID(), resultRef: .generate())
        let object = try #require(try ViadereJSON.decode(JSONValue.self, from: ViadereJSON.encode(data)).objectValue)
        #expect(Set(object.keys) == ["request_id", "result_ref"])
        #expect(WebhookEventType.verificationCompleted.rawValue == "verification.completed")
    }

    @Test func displayDigestBindsEveryDisplayedField() {
        let id = VerificationRequestID()
        let business = BusinessID()
        func digest(_ name: String = "Northwind", years: Int64 = 18, purpose: String = "age_restricted_access", fields: [String] = ["meets_threshold"],
                    expires: Date? = nil, biz: BusinessID? = nil) -> String {
            VerificationPrompt.displayDigest(requestId: id, businessId: biz ?? business, recipientName: name, capability: .ageMinimum, parameters: ["years": .integer(years)],
                                             purposeCode: purpose, fields: fields, expiresAt: expires ?? now)
        }
        let base = digest()
        #expect(base == digest())
        #expect(base.hasPrefix("sha256:") && base.count == 71)
        #expect(base != digest("Northwind Air"))
        #expect(base != digest(years: 21))
        #expect(base != digest(purpose: "other_purpose"))
        #expect(base != digest(fields: ["meets_threshold", "given_name"]))
        #expect(base != digest(expires: now.addingTimeInterval(1)))
        #expect(base != digest(biz: BusinessID()))
    }

    @Test func promptContentNamesExactlyTheClaimFieldsAndWhatIsWithheld() {
        for capability in [Capability.ageMinimum, .identityName, .identityAddress, .identityVerified] {
            let definition = capability.definition!
            let shown = Set(VerificationPromptContent.disclosure(for: capability, parameters: ["years": .integer(18)]).map(\.field))
            #expect(shown == Set(definition.disclosedClaimFields), "\(capability): the prompt lists exactly the claim fields the receipt covers")
        }
        let age = VerificationPromptContent.notDisclosed(for: .ageMinimum)
        #expect(age.contains("Your date of birth") && age.contains("Your name") && age.contains("Your ID number"))
        #expect(VerificationPromptContent.purposeText("age_restricted_access").contains("age-restricted"))
    }

    @Test func routeCatalogIncludesVerifyEndpointsAndTheyAreBoundCorrectly() {
        let names = Set(APIRoutes.all.map(\.name))
        for endpoint in APIRoutes.verifyEndpoints { #expect(names.contains(endpoint.name)) }
        #expect(APIRoutes.verificationRequestCreate.auth == .businessAPIKey)
        #expect(APIRoutes.verificationConsent.auth == .deviceSignedBearer)
        #expect(APIRoutes.providerDiditWebhook.auth == .providerSignature)
    }

    // MARK: Strict CBOR with tags (mdoc)

    @Test func cborTagsAreRefusedUnlessAllowed() throws {
        let tagged = CBORValue.tagged(24, .bytes(Data([1, 2, 3])))
        let encoded = CBOR.encode(tagged)
        #expect(encoded == Data([0xD8, 0x18, 0x43, 1, 2, 3]))
        #expect(throws: CBORError.self) { try CBOR.decode(encoded) }
        let decoded = try CBOR.decode(encoded, limits: CBOR.Limits(allowedTags: [24]))
        #expect(decoded.content(taggedWith: 24)?.byteString == Data([1, 2, 3]))
        #expect(throws: CBORError.self) { try CBOR.decode(encoded, limits: CBOR.Limits(allowedTags: [0])) }
        #expect(throws: CBORError.self) { try CBOR.decode(Data([0xD8, 0x18]), limits: CBOR.Limits(allowedTags: [24])) }
    }
}

@Suite struct CBORParserDifferentialTests {
    /// {"a": 1, "a": 2} where the second key uses a non-shortest text length head (0x78 0x01 'a').
    static let twoEncodingsOfOneKey = Data([0xA2, 0x61, 0x61, 0x01, 0x78, 0x01, 0x61, 0x02])

    /// Info finding: a duplicate key hidden behind a non-shortest encoding passed the raw-bytes check, and "first match" and "last match"
    /// readers then disagreed (1 vs 2).
    @Test func aDuplicateKeyIsFoundOnTheDecodedKeyEvenWithoutStrictMode() {
        #expect(throws: CBORError.duplicateKey) { try CBOR.decode(Self.twoEncodingsOfOneKey) }
        #expect(throws: CBORError.duplicateKey) { try CBOR.decode(Self.twoEncodingsOfOneKey, limits: CBOR.Limits(strictShortestForm: false)) }
    }

    @Test func strictModeRefusesEveryNonShortestHead() {
        let strict = CBOR.Limits(strictShortestForm: true)
        let cases: [Data] = [
            Data([0x18, 0x05]),                          // 5 as a one-byte argument
            Data([0x19, 0x00, 0xFF]),                    // 255 in two bytes
            Data([0x1A, 0x00, 0x00, 0xFF, 0xFF]),        // 65535 in four bytes
            Data([0x1B, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF]),
            Data([0x78, 0x01, 0x61]),                    // text of length 1 with a one-byte length
            Data([0x98, 0x01, 0x00]),                    // array of one with a one-byte length
        ]
        for data in cases { #expect(throws: CBORError.notCanonical) { try CBOR.decode(data, limits: strict) } }
        // The same bytes are accepted when strict mode is off (formats that never required it keep working).
        #expect((try? CBOR.decode(Data([0x18, 0x05]))) == .unsigned(5))
        // Shortest forms are accepted in strict mode.
        #expect((try? CBOR.decode(Data([0x18, 0x18]), limits: strict)) == .unsigned(24))
        #expect((try? CBOR.decode(Data([0x19, 0x01, 0x00]), limits: strict)) == .unsigned(256))
        var tagged = CBOR.Limits(strictShortestForm: true)
        tagged.allowedTags = [5]
        #expect(throws: CBORError.notCanonical) { try CBOR.decode(Data([0xD8, 0x05, 0x01]), limits: tagged) }
        #expect((try? CBOR.decode(Data([0xC5, 0x01]), limits: tagged)) == .tagged(5, .unsigned(1)))
    }
}
