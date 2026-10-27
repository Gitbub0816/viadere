import Crypto
import Foundation
import Testing
@testable import ViadereCore

@Suite("Capability catalog")
struct CapabilityCatalogTests {
    @Test func stableIDsAndForwardCompatibility() throws {
        let expected = ["message.send", "contact.reachable", "consent.request", "auth.challenge", "transaction.approve",
                        "age.minimum", "identity.name", "identity.address", "identity.verified"]
        #expect(Capability.known.map(\.rawValue) == expected)
        for raw in expected { #expect(Capability(rawValue: raw).isKnown) }
        let future = try ViadereJSON.decode(Capability.self, from: Data("\"payment.initiate\"".utf8))
        #expect(future == .unknown("payment.initiate") && !future.isKnown && future.definition == nil)
        #expect(try ViadereJSON.encode(Capability.ageMinimum) == Data("\"age.minimum\"".utf8))
    }

    @Test func everyKnownCapabilityHasADefinitionAndTheCatalogInvariantsHold() {
        #expect(CapabilityCatalog.audit() == [])
        for capability in Capability.known { #expect(capability.definition?.capability == capability) }
        #expect(CapabilityCatalog.definitions.count == Capability.known.count)
    }

    @Test func tierMIsMessagingOnlyAndApprovalsNeedTierA() {
        #expect(Set(CapabilityCatalog.capabilities(minimumTier: .m)) == Set(Capability.messaging))
        #expect(Set(CapabilityCatalog.capabilities(minimumTier: .a)) == [.authChallenge, .transactionApprove])
        #expect(Set(CapabilityCatalog.capabilities(minimumTier: .v)) == [.ageMinimum, .identityName, .identityAddress, .identityVerified])
    }

    /// Acceptance 6: an age-only request discloses no birthdate, name, address or document number.
    @Test func ageMinimumDisclosesOnlyTheThresholdResult() throws {
        let age = try #require(Capability.ageMinimum.definition)
        #expect(age.output.fieldNames == ["meets_threshold", "assurance", "issued_at", "expires_at", "audience"])
        #expect(age.output.personalDataFields.isEmpty)
        for forbidden in CapabilityCatalog.personalDataFieldNames { #expect(!age.output.fieldNames.contains(forbidden)) }
        // A producer that tries to attach PII has it dropped by projection and flagged by the check.
        let attempt: [String: JSONValue] = ["meets_threshold": .bool(true), "assurance": .string("high"), "birthdate": .string("1990-01-01"),
                                            "name": .string("A B"), "document_number": .string("X123"), "age": .integer(34), "address": .string("1 Main")]
        #expect(Set(age.project(attempt).keys) == ["meets_threshold", "assurance"])
        #expect(Set(age.violations(in: attempt)) == ["birthdate", "name", "document_number", "age", "address"])
        #expect(age.requiredEvidence == .verifiedAgeThreshold && age.consent.mode == .perRequestReceipt && age.minimumTier == .v)
    }

    @Test func onlyTheIdentityCapabilitiesMayDisclosePersonalData() {
        for definition in CapabilityCatalog.definitions {
            let pii = definition.output.personalDataFields
            switch definition.capability {
            case .identityName: #expect(Set(pii) == ["given_name", "family_name"])
            case .identityAddress: #expect(pii == ["address"])
            default: #expect(pii.isEmpty, "\(definition.capability) must not disclose personal data")
            }
        }
        #expect(Capability.identityVerified.definition?.output.personalDataFields.isEmpty == true)
    }

    @Test func parametersAreTypedClosedAndStrict() throws {
        let age = try #require(Capability.ageMinimum.definition)
        for years in [13, 16, 18, 21, 25] { #expect(age.parameterIssues(["years": .integer(Int64(years))]).isEmpty) }
        #expect(age.parameterIssues(["years": .integer(17)]) == ["years": "not_allowed"])
        #expect(age.parameterIssues(["years": .string("18")]) == ["years": "wrong_type"])
        #expect(age.parameterIssues([:]) == ["years": "missing"])
        #expect(age.parameterIssues(["years": .integer(18), "birthdate": .string("1990-01-01")]) == ["birthdate": "unknown"])
        let approve = try #require(Capability.transactionApprove.definition)
        #expect(approve.parameterIssues(["currency": .string("USD"), "amount_minor": .integer(250_000), "payee_display": .string("Example Merchant"),
                                         "transaction_reference": .string("bank_tx_123"), "challenge": .string("abc")]).isEmpty)
        #expect(approve.parameterIssues(["currency": .string("USDX"), "amount_minor": .integer(0), "payee_display": .string("x"),
                                         "transaction_reference": .string("r"), "challenge": .string("c")]) == ["currency": "too_long", "amount_minor": "too_small"])
    }

    @Test func interactionKindsMapToCapabilities() {
        #expect(Capability.required(forInteractionKind: .authenticate) == .authChallenge)
        #expect(Capability.required(forInteractionKind: .authorize) == .transactionApprove)
        for kind in [InteractionKind.confirm, .choose, .acknowledge, .reply, .status, .reward, .ticket, .message] {
            #expect(Capability.required(forInteractionKind: kind) == .messageSend)
        }
        #expect(!Capability.required(forInteractionKind: .unknown("payment")).isKnown)
    }

    @Test func catalogRoundTripsThroughJSON() throws {
        let data = try ViadereJSON.encode(CapabilityCatalog.definitions)
        #expect(try ViadereJSON.decode([CapabilityDefinition].self, from: data) == CapabilityCatalog.definitions)
    }
}

@Suite("Policy engine")
struct PolicyEngineTests {
    let business = BusinessID()
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    var subject: SubjectRef { SubjectRefDeriver(key: SymmetricKey(data: Data(repeating: 7, count: 32))).subjectRef(businessId: business, consumerId: ConsumerID()) }

    func facts(entitled: Set<Capability> = Set(Capability.messaging), scopes: Set<Capability> = Set(Capability.messaging),
               tiers: Set<BusinessRiskTier> = [.m], env: PolicyEnvironment = .live, disabled: [Capability: String] = [:],
               rules: [PolicyRule] = [], unavailable: Bool = false) -> BusinessPolicyFacts {
        BusinessPolicyFacts(active: true, tiers: tiers, entitlements: entitled, keyScopes: scopes, keyEnvironment: env, disabled: disabled,
                            switchesUnavailable: unavailable, rules: rules)
    }

    func request(_ capability: Capability, env: PolicyEnvironment = .live, parameters: [String: JSONValue]? = nil, purpose: String? = nil,
                 ref: SubjectRef? = nil, requestId: String? = nil, jurisdiction: String? = nil) -> PolicyRequest {
        PolicyRequest(capability: capability, businessId: business, environment: env, subjectRef: ref, parameters: parameters, purpose: purpose,
                      jurisdiction: jurisdiction, requestId: requestId, now: now)
    }

    let active = SubjectPolicyFacts(relationshipActive: true, purposeConsentGranted: true)

    @Test func messagingKeyCannotUseApproveOrVerify() {
        let f = facts()
        for capability in [Capability.authChallenge, .transactionApprove, .ageMinimum, .identityName] {
            let decision = PolicyEngine.evaluate(request(capability, parameters: capability == .ageMinimum ? ["years": .integer(18)] : [:], purpose: "p_x"),
                                                 business: f, subject: active)
            #expect(!decision.allowed)
            #expect(decision.primaryReason == .insufficientScope)
            #expect(decision.reasons.contains(.notEntitled))
            #expect(decision.audit.action == "policy.denied" && decision.audit.outcome == .denied)
        }
        #expect(PolicyEngine.evaluate(request(.messageSend), business: f, subject: active).allowed)
    }

    @Test func entitlementIsACeilingOverTheKeyScope() {
        // The key still carries approve, but the business was not (or is no longer) entitled.
        let f = facts(entitled: Set(Capability.messaging), scopes: Set(Capability.operational), tiers: [.m, .a])
        let d = PolicyEngine.evaluate(request(.transactionApprove), business: f, subject: active)
        #expect(!d.allowed && d.primaryReason == .notEntitled)
        // Entitled but the tier was removed.
        let g = facts(entitled: Set(Capability.operational), scopes: Set(Capability.operational), tiers: [.m])
        #expect(PolicyEngine.evaluate(request(.authChallenge), business: g, subject: active).reasons.contains(.tierRequired))
    }

    @Test func environmentMustMatchTheKey() {
        let f = facts(env: .test)
        #expect(PolicyEngine.evaluate(request(.messageSend, env: .live), business: f, subject: active).primaryReason == .environmentMismatch)
        #expect(PolicyEngine.evaluate(request(.messageSend, env: .test), business: f, subject: active).allowed)
    }

    @Test func killSwitchDeniesEvenAnEntitledScopedKey() {
        let f = facts(disabled: [.messageSend: "provider incident"])
        let d = PolicyEngine.evaluate(request(.messageSend), business: f, subject: active)
        #expect(d.primaryReason == .capabilityDisabled)
        // Sensitive capabilities fail closed when the switch table cannot be read; messaging does not.
        let g = facts(entitled: Set(Capability.operational), scopes: Set(Capability.operational), tiers: [.m, .a], unavailable: true)
        #expect(PolicyEngine.evaluate(request(.transactionApprove), business: g, subject: active).primaryReason == .policyUnavailable)
        #expect(PolicyEngine.evaluate(request(.messageSend), business: g, subject: active).allowed)
    }

    @Test func consentIsCheckedAgainstThePurposeAndRelationship() {
        let f = facts()
        let off = SubjectPolicyFacts(relationshipActive: true, purposeConsentGranted: false)
        let denied = PolicyEngine.evaluate(request(.messageSend), business: f, subject: off)
        #expect(denied.primaryReason == .consentRequired)
        let gone = SubjectPolicyFacts(relationshipActive: false, purposeConsentGranted: true)
        #expect(PolicyEngine.evaluate(request(.messageSend), business: f, subject: gone).primaryReason == .consentRequired)
        #expect(PolicyEngine.evaluate(request(.contactReachable), business: f, subject: gone).primaryReason == .consentRequired)
        #expect(PolicyEngine.evaluate(request(.contactReachable), business: f, subject: SubjectPolicyFacts(relationshipActive: true)).allowed)
    }

    @Test func subjectDataIsNotEvaluatedForACredentialThatMayNotUseTheCapability() {
        // Business-level denial wins: consent and evidence are never consulted (the server does not even load them).
        let d = PolicyEngine.evaluate(request(.ageMinimum, parameters: ["years": .integer(18)], purpose: "age_restricted_access"), business: facts(), subject: nil)
        #expect(d.reasons.contains(.insufficientScope))
        #expect(!d.reasons.contains(.consentRequired) && !d.reasons.contains(.evidenceInsufficient))
        // Business stage stops before the subject.
        let b = PolicyEngine.evaluate(request(.messageSend), business: facts(), stage: .business)
        #expect(b.allowed)
    }

    @Test func unknownCapabilityIsNeverAllowed() {
        let unknown = Capability.unknown("payment.initiate")
        let f = facts(entitled: [unknown], scopes: [unknown], tiers: Set(BusinessRiskTier.allCases))
        let d = PolicyEngine.evaluate(request(unknown), business: f, subject: active)
        #expect(!d.allowed && d.primaryReason == .unknownCapability)
    }

    @Test func jurisdictionRulesAreFailClosed() {
        let block = PolicyRule(capability: .ageMinimum, kind: .jurisdictionBlock, jurisdictions: ["XX", "us-ut"], reason: "test")
        let only = PolicyRule(capability: .ageMinimum, kind: .jurisdictionAllowOnly, jurisdictions: ["US", "CA"], reason: "launch markets")
        let verify = facts(entitled: [.ageMinimum], scopes: [.ageMinimum], tiers: [.m, .v], rules: [block, only])
        func decide(_ j: String?) -> PolicyDecision {
            PolicyEngine.evaluate(request(.ageMinimum, parameters: ["years": .integer(18)], purpose: "age_restricted_access", jurisdiction: j), business: verify, stage: .business)
        }
        #expect(decide("US").allowed)
        #expect(decide("XX").primaryReason == .jurisdictionBlocked)
        #expect(decide("us-ut").primaryReason == .jurisdictionBlocked)
        #expect(decide("DE").primaryReason == .jurisdictionBlocked, "not in the allow-only list")
        #expect(decide(nil).primaryReason == .jurisdictionBlocked, "an unknown jurisdiction fails closed under an allow-only rule")
        #expect(PolicyRule(capability: .ageMinimum, kind: .jurisdictionBlock, jurisdictions: ["XX"], reason: "x").blocks(nil) == false)
    }

    @Test func parametersAndPurposeAreRequiredForVerification() {
        let verify = facts(entitled: [.ageMinimum], scopes: [.ageMinimum], tiers: [.m, .v])
        #expect(PolicyEngine.evaluate(request(.ageMinimum, parameters: ["years": .integer(17)], purpose: "age_restricted_access"), business: verify, stage: .business).reasons == [.invalidParameters])
        #expect(PolicyEngine.evaluate(request(.ageMinimum, parameters: nil, purpose: "age_restricted_access"), business: verify, stage: .business).reasons == [.invalidParameters])
        #expect(PolicyEngine.evaluate(request(.ageMinimum, parameters: ["years": .integer(18)]), business: verify, stage: .business).reasons == [.purposeRequired])
        #expect(PolicyEngine.evaluate(request(.ageMinimum, parameters: ["years": .integer(18)], purpose: "Age Restricted!"), business: verify, stage: .business).reasons == [.purposeRequired])
        #expect(PolicyEngine.evaluate(request(.ageMinimum, parameters: ["years": .integer(18)], purpose: "age_restricted_access"), business: verify, stage: .business).allowed)
    }

    // MARK: Per-request consent and evidence

    func receipt(_ capability: Capability = .identityName, requestId: String = "vr_1", fields: [String]? = nil, ref: SubjectRef, purpose: String = "kyc_check") -> DisclosureReceipt {
        DisclosureReceipt(subjectRef: ref, businessId: business, recipientName: "Northwind", capability: capability, purpose: purpose,
                          fields: fields ?? capability.definition!.disclosedClaimFields, requestId: requestId, grantedAt: now.addingTimeInterval(-5),
                          expiresAt: now.addingTimeInterval(120))
    }

    var verifyFacts: BusinessPolicyFacts { facts(entitled: [.identityName, .ageMinimum], scopes: [.identityName, .ageMinimum], tiers: [.m, .v]) }
    let identityEvidence = EvidenceHolding(kind: .verifiedIdentity, verifiedAt: Date(timeIntervalSince1970: 1_700_000_000))

    @Test func identityNeedsAPerRequestReceiptNotBlanketConsent() {
        let ref = subject
        let blanket = SubjectPolicyFacts(relationshipActive: true, purposeConsentGranted: true, evidence: [identityEvidence], receipt: nil)
        let d = PolicyEngine.evaluate(request(.identityName, purpose: "kyc_check", ref: ref, requestId: "vr_1"), business: verifyFacts, subject: blanket)
        #expect(d.primaryReason == .consentRequired && d.details["receipt"] == "missing")
        let ok = SubjectPolicyFacts(relationshipActive: true, evidence: [identityEvidence], receipt: receipt(ref: ref))
        let allowed = PolicyEngine.evaluate(request(.identityName, purpose: "kyc_check", ref: ref, requestId: "vr_1"), business: verifyFacts, subject: ok)
        #expect(allowed.allowed)
        #expect(allowed.audit.action == "policy.allowed" && allowed.audit.metadata["receipt_id"] != nil)
    }

    @Test func aReceiptCannotBeReusedElsewhere() {
        let ref = subject
        func problem(_ r: DisclosureReceipt, _ req: PolicyRequest) -> String? {
            PolicyEngine.evaluate(req, business: verifyFacts, subject: SubjectPolicyFacts(relationshipActive: true, evidence: [identityEvidence], receipt: r)).details["receipt"]
        }
        let base = request(.identityName, purpose: "kyc_check", ref: ref, requestId: "vr_1")
        #expect(problem(receipt(ref: ref), base) == nil)
        #expect(problem(receipt(ref: ref), request(.identityName, purpose: "marketing_profile", ref: ref, requestId: "vr_1")) == "wrong_purpose")
        #expect(problem(receipt(ref: ref), request(.identityName, purpose: "kyc_check", ref: ref, requestId: "vr_2")) == "wrong_request")
        #expect(problem(receipt(ref: ref), request(.identityName, purpose: "kyc_check", ref: subject, requestId: "vr_1")) == "wrong_subject")
        #expect(problem(receipt(.identityAddress, ref: ref), base) == "wrong_capability")
        var otherBusiness = receipt(ref: ref); otherBusiness.businessId = BusinessID()
        #expect(problem(otherBusiness, base) == "wrong_recipient")
        var expired = receipt(ref: ref); expired.expiresAt = now.addingTimeInterval(-1)
        #expect(problem(expired, base) == "expired")
        var tooLong = receipt(ref: ref); tooLong.expiresAt = tooLong.grantedAt.addingTimeInterval(DisclosureReceipt.maxLifetime + 1000)
        #expect(problem(tooLong, base) == "expired")
        var revoked = receipt(ref: ref); revoked.revokedAt = now
        #expect(problem(revoked, base) == "revoked")
        var used = receipt(ref: ref); used.consumedAt = now
        #expect(problem(used, base) == "already_used")
        #expect(problem(receipt(fields: [], ref: ref), base) == "fields_mismatch")
        #expect(problem(receipt(fields: ["given_name", "family_name", "birthdate"], ref: ref), base) == "fields_mismatch", "a receipt cannot widen the disclosure")
    }

    @Test func evidenceKindsAreNotInterchangeableAndMustBeFresh() {
        let ref = subject
        let age = request(.ageMinimum, parameters: ["years": .integer(21)], purpose: "age_restricted_access", ref: ref, requestId: "vr_9")
        let r = receipt(.ageMinimum, requestId: "vr_9", ref: ref, purpose: "age_restricted_access")
        func decide(_ evidence: [EvidenceHolding]) -> PolicyDecision {
            PolicyEngine.evaluate(age, business: verifyFacts, subject: SubjectPolicyFacts(relationshipActive: true, evidence: evidence, receipt: r))
        }
        #expect(decide([]).reasons == [.evidenceInsufficient])
        #expect(decide([identityEvidence]).reasons == [.evidenceInsufficient], "a verified identity is not a verified age threshold")
        #expect(decide([EvidenceHolding(kind: .registeredAuthenticator, verifiedAt: now.addingTimeInterval(-9))]).reasons == [.evidenceInsufficient])
        #expect(decide([EvidenceHolding(kind: .verifiedAgeThreshold, verifiedAt: now.addingTimeInterval(-9), expiresAt: now.addingTimeInterval(-1))]).reasons == [.evidenceInsufficient])
        #expect(decide([EvidenceHolding(kind: .verifiedAgeThreshold, verifiedAt: now.addingTimeInterval(-9), expiresAt: now.addingTimeInterval(60))]).allowed)
    }

    @Test func auditRecordsCarryNoPersonalData() {
        let ref = subject
        let d = PolicyEngine.evaluate(request(.ageMinimum, parameters: ["years": .integer(18), "birthdate": .string("1990-01-01")], purpose: "age_restricted_access", ref: ref),
                                      business: verifyFacts, subject: nil)
        #expect(!d.audit.metadata.values.contains { $0.contains("1990") })
        #expect(d.audit.metadata["capability"] == "age.minimum")
        #expect(d.audit.metadata["subject_ref"] == ref.rawValue)
    }
}

@Suite("Subject references")
struct SubjectRefTests {
    let deriver = SubjectRefDeriver(key: SymmetricKey(data: Data(repeating: 0xA5, count: 32)))

    @Test func formatAndParsing() throws {
        let ref = deriver.subjectRef(businessId: BusinessID(), consumerId: ConsumerID())
        #expect(ref.rawValue.hasPrefix("sub_") && ref.rawValue.count == 47)
        #expect(SubjectRef(ref.rawValue) == ref)
        for bad in ["", "sub_", "sub_short", String(ref.rawValue.dropLast()), ref.rawValue + "A", "SUB_" + ref.rawValue.dropFirst(4),
                    "sub_" + String(repeating: "+", count: 43), "sub_" + String(repeating: "A", count: 42) + "="] {
            #expect(SubjectRef(bad) == nil, "\(bad)")
        }
        #expect(throws: DecodingError.self) { try ViadereJSON.decode(SubjectRef.self, from: Data("\"nope\"".utf8)) }
    }

    @Test func derivationMatchesTheSpecifiedConstruction() {
        let business = BusinessID(UUID(uuidString: "11111111-2222-3333-4444-555555555555")!)
        let consumer = ConsumerID(UUID(uuidString: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")!)
        let key = SymmetricKey(data: Data(repeating: 0xA5, count: 32))
        let expected = HMAC<SHA256>.authenticationCode(for: Data("VIADERE-SUBJECT-V1\n11111111-2222-3333-4444-555555555555\naaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".utf8), using: key)
        #expect(deriver.subjectRef(businessId: business, consumerId: consumer).rawValue == "sub_" + Base64URL.encode(Data(expected)))
    }

    @Test func stablePerBusinessAndUnlinkableAcrossBusinesses() {
        let consumer = ConsumerID(), a = BusinessID(), b = BusinessID()
        #expect(deriver.subjectRef(businessId: a, consumerId: consumer) == deriver.subjectRef(businessId: a, consumerId: consumer))
        #expect(deriver.subjectRef(businessId: a, consumerId: consumer) != deriver.subjectRef(businessId: b, consumerId: consumer))
        #expect(deriver.subjectRef(businessId: a, consumerId: consumer) != deriver.subjectRef(businessId: a, consumerId: ConsumerID()))
        // A different key gives unrelated values, and no ref contains the ids it was derived from.
        let other = SubjectRefDeriver(key: SymmetricKey(data: Data(repeating: 0x5A, count: 32)))
        #expect(other.subjectRef(businessId: a, consumerId: consumer) != deriver.subjectRef(businessId: a, consumerId: consumer))
        let ref = deriver.subjectRef(businessId: a, consumerId: consumer).rawValue
        #expect(!ref.contains(consumer.description) && !ref.contains(a.description))
    }

    @Test func requestsAcceptSubjectRefAndKeepRelationshipIdWorking() throws {
        let ref = deriver.subjectRef(businessId: BusinessID(), consumerId: ConsumerID())
        let byRef = BusinessSendMessageRequest(subjectRef: ref, body: "hi", idempotencyKey: "k1")
        let wire = String(decoding: try ViadereJSON.encode(byRef), as: UTF8.self)
        #expect(wire.contains("\"subjectRef\"") && !wire.contains("relationshipId"))
        let decoded = try ViadereJSON.decode(BusinessSendMessageRequest.self, from: Data(wire.utf8))
        #expect(decoded.subjectRef == ref && decoded.relationshipId.isUnaddressed)
        let legacy = BusinessSendMessageRequest(relationshipId: RelationshipID(), body: "hi", idempotencyKey: "k2")
        let legacyWire = String(decoding: try ViadereJSON.encode(legacy), as: UTF8.self)
        #expect(legacyWire.contains("relationshipId") && !legacyWire.contains("subjectRef"))
        #expect(try ViadereJSON.decode(BusinessSendMessageRequest.self, from: Data(legacyWire.utf8)) == legacy)
        // Neither: rejected.
        #expect(throws: DecodingError.self) { try ViadereJSON.decode(BusinessSendMessageRequest.self, from: Data(#"{"body":"x","idempotencyKey":"k"}"#.utf8)) }
        // A malformed ref is rejected, never ignored.
        #expect(throws: DecodingError.self) {
            try ViadereJSON.decode(BusinessSendMessageRequest.self, from: Data(#"{"subjectRef":"sub_x","body":"x","idempotencyKey":"k"}"#.utf8))
        }
    }
}

@Suite("Catalog documentation")
struct CatalogDocumentationTests {
    /// `docs/SECURITY.md` §2.28 is the normative table: every capability and every disclosed field in the code must be in it, and
    /// `age.minimum`'s row must name exactly the five permitted fields.
    @Test func theNormativeTableMatchesTheCatalog() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let url = root.appendingPathComponent("docs/SECURITY.md")
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return }   // not available when built outside the repository
        let section = try #require(text.range(of: "### 2.28 Capability catalog").map { String(text[$0.lowerBound...]) })
        let table = section.components(separatedBy: "### 2.29").first ?? section
        let rows = table.split(separator: "\n").filter { $0.hasPrefix("| `") }
        for definition in CapabilityCatalog.definitions {
            let id = "`\(definition.capability.rawValue)`"
            let matching = rows.filter { $0.hasPrefix("| \(id) |") }
            #expect(matching.count == 2, "\(id) needs a row in each normative table")
            // The first table lists tier, evidence and consent; the second lists inputs and disclosed fields.
            let outputRow = try #require(matching.last)
            for name in definition.output.fieldNames { #expect(outputRow.contains("`\(name)`"), "\(id): documented fields must include \(name)") }
        }
        let age = try #require(rows.last { $0.hasPrefix("| `age.minimum` |") })
        for forbidden in ["birthdate", "given_name", "family_name", "document_number"] {
            // The row may say "never a birthdate ..." in prose, but must not list one as a disclosed field.
            #expect(!age.contains("`\(forbidden)`"))
        }
    }
}
