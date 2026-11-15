import Foundation
import ViadereCore

/// What a verification method established, **in memory only**. This type is deliberately not `Codable`/`Encodable` and is never stored,
/// logged or returned: `ClaimsBuilder` reduces it to the capability's output fields and the value goes out of scope. It may hold a
/// birthdate (to answer a threshold) or a name; nothing here outlives the request that created it.
struct EvidenceClaims: Sendable {
    var method: VerificationMethod
    /// Issuer identifier without personal data (see `VerificationProvenance.issuer`).
    var issuer: String
    var verifiedAt: Date
    /// The evidence stops being valid (credential or document expiry); a result never outlives it.
    var validUntil: Date
    var revocation: RevocationState
    /// The document's issuing country (ISO 3166-1 alpha-2) when the method established one: the IACA / document-signer country for
    /// Wallet, the provider's `issuing_state` for a document check. `nil` = unknown (jurisdiction rules then fail closed).
    var issuerCountry: String?

    /// Explicit issuer statements `age_over_NN` → value.
    var ageOver: [Int: Bool] = [:]
    var ageInYears: Int?
    var birthDate: AgeThreshold.Day?
    var givenName: String?
    var familyName: String?
    var address: [String: JSONValue]?
    /// A validated document was presented (for `identity.verified`).
    var documentPresented = false
}

/// Reduces `EvidenceClaims` to the capability's output (`CapabilityDefinition.output`), following the mapping of methods to labels
/// (`VerificationAssuranceMapper`). A result that cannot be built (a threshold the evidence cannot answer, a missing name) is `nil`.
enum ClaimsBuilder {
    struct Built {
        var values: [String: JSONValue]
        var label: VerificationLabel
        var provenance: VerificationProvenance
    }

    /// Whether the evidence says the person is at least `years`; `nil` when it cannot say. Monotonic: an issuer's `age_over_21 = true`
    /// answers a threshold of 18 or 21, and a `false` for a threshold at or below the one asked answers "no".
    static func meetsThreshold(_ claims: EvidenceClaims, years: Int, now: Date) -> Bool? {
        if let exact = claims.ageOver[years] { return exact }
        if claims.ageOver.contains(where: { $0.key >= years && $0.value }) { return true }
        if claims.ageOver.contains(where: { $0.key <= years && !$0.value }) { return false }
        if let birth = claims.birthDate { return AgeThreshold.meets(birth: birth, years: years, today: AgeThreshold.Day(earliestLocal: now)) }
        if let age = claims.ageInYears, (0...150).contains(age), age >= years { return true }
        return nil
    }

    private static func cleaned(_ text: String?) -> String? {
        guard let text else { return nil }
        let trimmed = text.precomposedStringWithCanonicalMapping.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (1...128).contains(trimmed.count), !trimmed.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { return nil }
        return trimmed
    }

    /// The disclosed fields for `capability`. `audience` is the business the result is bound to.
    static func build(capability: Capability, parameters: [String: JSONValue], claims: EvidenceClaims, audience: BusinessID, now: Date) -> Built? {
        guard let definition = capability.definition else { return nil }
        var values: [String: JSONValue] = [:]
        let label: VerificationLabel
        var observation = VerificationAssuranceMapper.Observation(method: claims.method)
        switch capability {
        case .ageMinimum:
            guard case .integer(let years)? = parameters["years"], let n = Int(exactly: years),
                  let meets = meetsThreshold(claims, years: n, now: now), meets else { return nil }
            values["meets_threshold"] = .bool(true)
            observation.validatedAgeStatement = true
            label = .verifiedAgeThreshold
        case .identityName:
            guard let given = cleaned(claims.givenName), let family = cleaned(claims.familyName) else { return nil }
            values["given_name"] = .string(given)
            values["family_name"] = .string(family)
            observation.validatedIdentityAttributes = true
            label = .verifiedIdentity
        case .identityAddress:
            guard let address = claims.address, !address.isEmpty else { return nil }
            values["address"] = .object(address)
            observation.validatedIdentityAttributes = true
            label = .verifiedIdentity
        case .identityVerified:
            guard claims.documentPresented else { return nil }
            values["verified"] = .bool(true)
            observation.validatedIdentityAttributes = true
            label = .verifiedIdentity
        default:
            return nil
        }
        // No promotion: the method must be able to establish the label, and the observation must have produced it.
        guard VerificationAssuranceMapper.labels(for: observation).contains(label) else { return nil }
        let issuedAt = now
        let expiresAt = min(issuedAt.addingTimeInterval(VerifyPolicy.resultValidity), claims.validUntil)
        guard expiresAt > issuedAt else { return nil }
        let risk = definition.sensitivity.transactionRisk
        let dimensions: AssuranceDimensions
        switch claims.method {
        case .walletMdoc: dimensions = VerificationAssuranceMapper.walletDimensions(verifiedAt: claims.verifiedAt, validUntil: expiresAt, risk: risk)
        case .sandbox: dimensions = VerificationAssuranceMapper.sandboxDimensions(verifiedAt: claims.verifiedAt, validUntil: expiresAt, risk: risk)
        default: dimensions = VerificationAssuranceMapper.providerDimensions(verifiedAt: claims.verifiedAt, validUntil: expiresAt, risk: risk)
        }
        values["assurance"] = .string(dimensions.level)
        values["issued_at"] = .string(ViadereDate.format(issuedAt))
        values["expires_at"] = .string(ViadereDate.format(expiresAt))
        values["audience"] = .string(audience.description)
        let provenance = VerificationProvenance(method: claims.method, issuer: claims.issuer, label: label, assurance: dimensions, expiresAt: expiresAt,
                                                revocation: claims.revocation)
        guard provenance.isConsistent else { return nil }
        // The catalog is the allow-list: whatever the producer put in, only the output schema's fields leave (acceptance 6).
        let projected = definition.project(values)
        guard definition.violations(in: projected).isEmpty, Set(definition.output.fieldNames).isSubset(of: Set(projected.keys)) else { return nil }
        return Built(values: projected, label: label, provenance: provenance)
    }
}
