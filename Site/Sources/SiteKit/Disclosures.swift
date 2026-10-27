import Foundation

/// Draft disclosure language from docs/SECURITY-TRUST-PLATFORM-SPEC.md §11.5, verbatim. Counsel review is required
/// before any of it is treated as final. Pages cite them with `disclosures: [key]` in front matter and the lint
/// requires the exact text to be present.
public enum Disclosures {
    public static let all: [String: String] = [
        "business_verification": "A verified business has completed Viadere's business-identity checks. Verification does not constitute an endorsement, guarantee of legitimacy, or confirmation of regulatory licensing.",
        "identity_verification": "Viadere may verify selected identity attributes using supported credentials or verification providers. A verification result describes the attribute and assurance evaluated; it is not a universal guarantee of identity or eligibility.",
        "mfa": "Viadere delivers and records authentication approvals. The business remains responsible for account access decisions and for independently validating applicable approval evidence.",
        "age_verification": "Where supported, Viadere can confirm that a person meets a specified age threshold without disclosing their date of birth. Availability and legal sufficiency vary by jurisdiction and service.",
        "encryption": "Certain sensitive Viadere features may use end-to-end encryption. Ordinary SMS, operational metadata, and other features may have different protection models, as described in our Security Overview.",
        "device_custody": "Some credentials are protected on your device. Losing access to a device or recovery method may require re-enrollment or re-verification; some nonrecoverable credentials may need to be recreated with the original service.",
    ]
}
