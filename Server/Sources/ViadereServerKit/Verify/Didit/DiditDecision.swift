import Foundation
import ViadereCore

/// What a Didit session's terminal state means for the attempt.
enum DiditSessionState: Equatable {
    /// Not finished: the person is still in the flow (or asked to resubmit). Nothing is read and nothing is purged.
    case inProgress
    /// Finished without an approval (declined, abandoned, expired, or left in manual review). Purge only.
    case notApproved(reason: String)
    /// Finished, approved by the document, liveness and face-match checks.
    case approved
}

/// Maps a Didit decision (`GET /v3/session/{id}/decision/`, V3 plural arrays) to the assurance taxonomy.
///
/// - **Identity and age** need the full set the product promises: an approved **document check**, an approved **liveness** check and an
///   approved **face match**, on an approved session whose `vendor_data` is the attempt id this server created. Anything less is not
///   verified (VER-005): a document without a face match, a liveness without a document, or a mismatching `vendor_data`.
/// - A **selfie age estimate** (`liveness_checks[].age_estimation`) is **an estimate** (AGE-002): it is recognized and reported as
///   `.estimatedAgeOnly` so it can be recorded, and it never yields a verified-age or identity claim.
/// - The document's birthdate is read here to answer the threshold in memory; the decision, the images, scores, document numbers and
///   URLs are never stored or returned.
enum DiditDecisionMapper {
    struct Mapped {
        var state: DiditSessionState
        var claims: EvidenceClaims?
        /// An age estimate was present without an approved document (recorded as a label only; never a verified claim).
        var estimatedAgeOnly = false
    }

    static func state(of decision: [String: JSONValue]) -> DiditSessionState {
        let status = (decision["status"]?.stringValue ?? "").lowercased()
        switch status {
        case "approved": return .approved
        case "declined": return .notApproved(reason: "declined")
        case "abandoned": return .notApproved(reason: "abandoned")
        case "expired", "kyc expired": return .notApproved(reason: "expired")
        // Manual review can take longer than any request lives; the session is purged and the person may use another method.
        case "in review": return .notApproved(reason: "in_review")
        default: return .inProgress
        }
    }

    private static func array(_ decision: [String: JSONValue], _ key: String) -> [[String: JSONValue]] {
        guard case .array(let items)? = decision[key] else { return [] }
        return items.compactMap(\.objectValue)
    }

    private static func approved(_ items: [[String: JSONValue]]) -> [String: JSONValue]? {
        guard !items.isEmpty, items.allSatisfy({ ($0["status"]?.stringValue ?? "").lowercased() == "approved" }) else { return nil }
        return items[0]
    }

    /// `expectedAttempt` is the attempt id the server put in `vendor_data`; `expectedSession` the session it created.
    static func map(decision: [String: JSONValue], expectedSession: String, expectedAttempt: String, now: Date) -> Mapped {
        let state = state(of: decision)
        guard state == .approved else { return Mapped(state: state, claims: nil) }
        // Binding: this decision is for the session we created for this attempt, not another one.
        guard decision["session_id"]?.stringValue?.lowercased() == expectedSession.lowercased(),
              decision["vendor_data"]?.stringValue == expectedAttempt else {
            return Mapped(state: .notApproved(reason: "binding_mismatch"), claims: nil)
        }
        let liveness = approved(array(decision, "liveness_checks"))
        let faceMatch = approved(array(decision, "face_matches"))
        guard let document = approved(array(decision, "id_verifications")), liveness != nil, faceMatch != nil else {
            let estimate = liveness.flatMap { Self.estimate($0) } != nil
            return Mapped(state: .notApproved(reason: estimate ? "estimate_only" : "incomplete_checks"), claims: nil, estimatedAgeOnly: estimate)
        }
        var validUntil = now.addingTimeInterval(VerifyPolicy.resultValidity)
        if let expiry = document["expiration_date"]?.stringValue, !expiry.isEmpty {
            // A document past its expiry is not evidence (VER-004: validity dates).
            guard let day = AgeThreshold.Day(isoDate: expiry), day >= AgeThreshold.Day(utc: now) else {
                return Mapped(state: .notApproved(reason: "document_expired"), claims: nil)
            }
            validUntil = max(validUntil, now)
        }
        var claims = EvidenceClaims(method: .diditDocumentLiveness, issuer: "didit:" + issuerCountry(document), verifiedAt: now, validUntil: validUntil,
                                    revocation: .notApplicable)
        if let dob = document["date_of_birth"]?.stringValue { claims.birthDate = AgeThreshold.Day(isoDate: dob) }
        claims.givenName = document["first_name"]?.stringValue
        claims.familyName = document["last_name"]?.stringValue
        if let formatted = document["formatted_address"]?.stringValue ?? document["address"]?.stringValue, !formatted.isEmpty, formatted.count <= 300 {
            var address: [String: JSONValue] = ["formatted": .string(formatted)]
            if let country = document["issuing_state"]?.stringValue { address["country"] = .string(String(country.prefix(3)).uppercased()) }
            claims.address = address
        }
        claims.documentPresented = true
        // The provider reports the issuing state as alpha-3 (or alpha-2); policy rules name alpha-2. Unassigned or placeholder -> unknown.
        claims.issuerCountry = CountryCodes.alpha2((document["issuing_state"]?.stringValue ?? "").trimmingCharacters(in: .whitespaces))
        return Mapped(state: .approved, claims: claims)
    }

    private static func estimate(_ liveness: [String: JSONValue]) -> Double? {
        switch liveness["age_estimation"] {
        case .number(let d)?: d
        case .integer(let n)?: Double(n)
        default: nil
        }
    }

    /// Upper-case alphabetic country code of the issuing state (no personal data), or `unknown`.
    private static func issuerCountry(_ document: [String: JSONValue]) -> String {
        let raw = (document["issuing_state"]?.stringValue ?? "").uppercased()
        return (2...3).contains(raw.count) && raw.allSatisfy({ $0.isASCII && $0.isLetter }) ? raw : "unknown"
    }
}
