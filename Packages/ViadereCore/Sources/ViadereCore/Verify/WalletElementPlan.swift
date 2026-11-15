import Foundation

/// One ISO 18013-5 data element: the namespace and the element identifier.
public struct MDocElement: Sendable, Hashable, Codable {
    public var namespace: String
    public var identifier: String
    public init(namespace: String, identifier: String) {
        self.namespace = namespace
        self.identifier = identifier
    }
}

/// Which Wallet (mdoc) elements a capability needs, and nothing more (AGE-001, AGE-003: never a birthdate for an age threshold).
///
/// Shared by the app (which turns it into a `PKIdentityRequest`) and the server (which extracts **only** these elements from the
/// decrypted `DeviceResponse` and discards everything else), so the request and the extraction cannot drift.
public enum WalletElementPlan {
    public static let docType = "org.iso.18013.5.1.mDL"
    public static let isoNamespace = "org.iso.18013.5.1"
    public static let aamvaNamespace = "org.iso.18013.5.1.aamva"
    /// Namespaces whose items are parsed at all. Items in any other namespace are dropped without being read.
    public static let allowedNamespaces: Set<String> = [isoNamespace, aamvaNamespace]

    /// What the app asks Wallet for, per capability.
    public enum Request: Sendable, Hashable {
        /// `PKIdentityElement.age(atLeast:)`; never the birthdate, never `age` together with `age_over`.
        case ageAtLeast(Int)
        case givenAndFamilyName
        case residentAddress
        /// A validated document with no attribute released: only the issuing authority element is requested.
        case documentPresented
    }

    public static func request(for capability: Capability, parameters: [String: JSONValue]) -> Request? {
        switch capability {
        case .ageMinimum:
            guard case .integer(let years)? = parameters["years"], let n = Int(exactly: years), (0...99).contains(n) else { return nil }
            return .ageAtLeast(n)
        case .identityName: return .givenAndFamilyName
        case .identityAddress: return .residentAddress
        case .identityVerified: return .documentPresented
        default: return nil
        }
    }

    /// The elements the server will read for `request` (the same ones the app asks for, plus the issuer's documented fallbacks for age).
    public static func readableElements(for request: Request) -> Set<MDocElement> {
        func iso(_ id: String) -> MDocElement { MDocElement(namespace: isoNamespace, identifier: id) }
        switch request {
        case .ageAtLeast(let years):
            // `age_over_NN` is what is requested. If the issuer did not include it the framework falls back to the age element
            // (`age_in_years`); `birth_date` is read only to answer the yes/no in memory when an issuer returns it that way.
            return [iso(ageOverIdentifier(years)), iso("age_in_years"), iso("birth_date")]
        case .givenAndFamilyName: return [iso("given_name"), iso("family_name")]
        case .residentAddress:
            return [iso("resident_address"), iso("resident_city"), iso("resident_state"), iso("resident_postal_code"), iso("resident_country")]
        case .documentPresented: return [iso("issuing_authority")]
        }
    }

    /// What the app declares to Wallet about keeping the data (`PKIdentityIntentToStore`). Wallet shows it to the person on the sheet, so it
    /// must be true:
    /// - an age threshold or "has a verified ID" releases a yes/no that Viadere and the business keep only as that boolean: `willNotStore`;
    /// - a name or an address is **relayed to the business, which may keep it** under its own retention terms: `mayStore`. Declaring
    ///   `willNotStore` for it would tell the person something false about data a third party then holds.
    public enum StorageIntent: Sendable, Hashable { case willNotStore, mayStore }

    public static func storageIntent(for request: Request) -> StorageIntent {
        switch request {
        case .ageAtLeast, .documentPresented: .willNotStore
        case .givenAndFamilyName, .residentAddress: .mayStore
        }
    }

    /// `age_over_NN` for a threshold (two digits, as ISO 18013-5 names them).
    public static func ageOverIdentifier(_ years: Int) -> String { "age_over_" + (years < 10 ? "0" : "") + String(years) }

    /// The identifiers (ISO namespace) the app requests from Wallet; used by the app to build `PKIdentityElement`s.
    public static func requestedIdentifiers(for request: Request) -> [String] {
        switch request {
        case .ageAtLeast(let years): [ageOverIdentifier(years)]
        case .givenAndFamilyName: ["given_name", "family_name"]
        case .residentAddress: ["resident_address", "resident_city", "resident_state", "resident_postal_code", "resident_country"]
        case .documentPresented: ["issuing_authority"]
        }
    }
}
