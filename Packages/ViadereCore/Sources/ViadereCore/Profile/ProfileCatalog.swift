import Foundation

/// The categories of the customer profile (docs/PROFILES.md). A category is the unit of **business entitlement**: a business may only ask
/// for (and only ever read) fields of categories a Viadere operator allowed it, like an Apple entitlement. No category is allowed by default.
public enum ProfileCategory: String, Sendable, Codable, CaseIterable, Hashable, Comparable {
    case contact
    case personal
    case birthdate
    case travel
    case memberships
    case vehicle
    case home
    case work
    case verified

    public var title: String {
        switch self {
        case .contact: "Contact"
        case .personal: "Personal"
        case .birthdate: "Date of birth and age"
        case .travel: "Travel"
        case .memberships: "Memberships and loyalty"
        case .vehicle: "Vehicle"
        case .home: "Home and property"
        case .work: "Work"
        case .verified: "Verified identity"
        }
    }

    public var summary: String {
        switch self {
        case .contact: "Email, phone and mailing or service addresses."
        case .personal: "Legal and preferred name, language and pronouns."
        case .birthdate: "Date of birth, shared by preference as an age check (over 18, over 21)."
        case .travel: "Frequent-flyer and known traveler numbers, seat and meal preference."
        case .memberships: "Loyalty and membership numbers per program."
        case .vehicle: "Make, model, year and plate."
        case .home: "Property type and access notes for home services."
        case .work: "Employer and job title."
        case .verified: "Facts confirmed with an ID: a verified ID, a verified legal name, verified age checks."
        }
    }

    /// Whether a business must give a written justification when it asks Viadere to allow this category (onboarding). Every category still
    /// needs an operator's approval; these are the ones whose purpose must be stated in writing.
    public var requiresJustification: Bool {
        switch self {
        case .contact, .personal, .memberships: false
        case .birthdate, .travel, .vehicle, .home, .work, .verified: true
        }
    }

    /// Whether the operator grant also needs the reference of a heightened review (the AGE-007 rule of the identity capabilities).
    public var requiresReviewReference: Bool { self == .verified || self == .birthdate }

    private var order: Int { Self.allCases.firstIndex(of: self) ?? 0 }
    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.order < rhs.order }
}

/// How a value is entered and checked.
public enum ProfileFieldType: String, Sendable, Codable, Hashable {
    /// Short single-line text (names, employer).
    case text
    /// Single-line free text with a small limit (access notes). Free text never carries numbers that look like identifiers.
    case note
    case email
    /// E.164 (`+` and 7-15 digits).
    case phone
    case address
    /// `YYYY-MM-DD`.
    case date
    /// A BCP 47-shaped language tag (`en`, `en-US`, `pt-BR`).
    case language
    /// One of `allowedValues`.
    case choice
    /// A membership-style identifier: letters, digits, spaces and dashes.
    case identifier
    /// A four-digit year.
    case year
    /// Computed by Viadere, never entered (age checks, verified facts). Read-only booleans.
    case derivedBoolean = "derived_boolean"
}

/// How much harm a disclosure could cause; drives the copy the customer sees and what an operator reviews. It does **not** relax any check.
public enum ProfileSensitivity: String, Sendable, Codable, Hashable, Comparable {
    case standard, elevated, high

    private var rank: Int { self == .standard ? 0 : (self == .elevated ? 1 : 2) }
    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.rank < rhs.rank }
}

/// One field of the catalog. Keys are `"{category}.{name}"` and stable; a key not in the catalog is rejected everywhere (closed set).
public struct ProfileFieldDefinition: Sendable, Codable, Hashable, Identifiable {
    public var id: String { key }
    public var key: String
    public var category: ProfileCategory
    public var title: String
    public var type: ProfileFieldType
    /// Grapheme limit of a text value (also bounds scalars and bytes, `DisplayTextSanitizer.isWithinLimits`).
    public var maxLength: Int
    /// Minimum grapheme length of a text value.
    public var minLength: Int
    /// Multi-entry fields are keyed by an entry label (the airline, the program); `nil` = one value.
    public var entryLabel: String?
    public var maxEntries: Int
    public var allowedValues: [String]?
    public var sensitivity: ProfileSensitivity
    public var summary: String

    public init(_ key: String, _ category: ProfileCategory, _ title: String, _ type: ProfileFieldType, maxLength: Int = 64, minLength: Int = 1,
                entryLabel: String? = nil, maxEntries: Int = 1, allowedValues: [String]? = nil, sensitivity: ProfileSensitivity = .standard, summary: String) {
        self.key = key
        self.category = category
        self.title = title
        self.type = type
        self.maxLength = maxLength
        self.minLength = minLength
        self.entryLabel = entryLabel
        self.maxEntries = maxEntries
        self.allowedValues = allowedValues
        self.sensitivity = sensitivity
        self.summary = summary
    }

    public var isMultiEntry: Bool { entryLabel != nil }
    /// Derived fields are computed (from the date of birth or from verified facts) and cannot be written.
    public var isDerived: Bool { type == .derivedBoolean }
}

/// Why a value was refused (machine codes, also the `details` of the API error).
public enum ProfileValueIssue: String, Sendable, Codable, Hashable, Error {
    case unknownField = "unknown_field"
    case readOnly = "read_only"
    case wrongType = "wrong_type"
    case empty
    case tooShort = "too_short"
    case tooLong = "too_long"
    case disallowedCharacters = "disallowed_characters"
    case impersonation
    case invalidFormat = "invalid_format"
    case notAllowed = "not_allowed"
    /// The value looks like a payment card, bank account or government ID number (never collected).
    case forbiddenIdentifier = "forbidden_identifier"
    case entryRequired = "entry_required"
    case entryNotAllowed = "entry_not_allowed"
    case invalidEntry = "invalid_entry"
    case tooManyEntries = "too_many_entries"
}

/// The versioned, closed field catalog (docs/PROFILES.md §Catalog). Shared by the server (validation before anything is stored), the app
/// (editing and copy) and the business SDK (requests).
///
/// **Never collected, by construction** (no field exists and unknown keys are rejected): health, medical, allergy or disability data
/// (healthcare is banned platform-wide), government ID numbers (SSN, passport, driver's license numbers), payment card or bank numbers,
/// biometric data, religion, sexual orientation, political views and precise live location. Meal preference offers no medical or religious
/// options for the same reason. Free-text and identifier values that look like a card, bank or national ID number are refused
/// (`ProfileCatalog.looksLikeForbiddenIdentifier`).
public enum ProfileCatalog {
    /// Bumped whenever a field is added or a rule changes; stored with each profile and returned to clients.
    public static let version = 1

    /// Meal options are deliberately non-medical and non-religious.
    public static let mealPreferences = ["standard", "vegetarian", "vegan", "no_preference"]
    public static let seatPreferences = ["window", "aisle", "no_preference"]
    public static let propertyTypes = ["house", "apartment", "condo", "townhouse", "mobile_home", "other"]

    public static let fields: [ProfileFieldDefinition] = [
        // Contact
        .init("contact.email", .contact, "Email", .email, maxLength: 254, minLength: 3, summary: "An email address you want businesses to use."),
        .init("contact.phone", .contact, "Phone", .phone, maxLength: 24, minLength: 8, summary: "A phone number in international format."),
        .init("contact.mailing_address", .contact, "Mailing address", .address, maxLength: 120, sensitivity: .elevated, summary: "Where post should go."),
        .init("contact.service_address", .contact, "Service address", .address, maxLength: 120, entryLabel: "label", maxEntries: 3,
              sensitivity: .elevated, summary: "Where a service happens (home, office, cabin)."),
        // Personal
        .init("personal.given_name", .personal, "First name", .text, maxLength: 64, summary: "Your legal first name."),
        .init("personal.family_name", .personal, "Last name", .text, maxLength: 64, summary: "Your legal last name."),
        .init("personal.preferred_name", .personal, "Preferred name", .text, maxLength: 64, summary: "What you like to be called."),
        .init("personal.preferred_language", .personal, "Preferred language", .language, maxLength: 35, minLength: 2, summary: "For example en, en-US or pt-BR."),
        .init("personal.pronouns", .personal, "Pronouns", .text, maxLength: 24, summary: "Optional."),
        // Date of birth (shared preferentially as age checks)
        .init("birthdate.date", .birthdate, "Date of birth", .date, maxLength: 10, minLength: 10, sensitivity: .high,
              summary: "Prefer sharing an age check instead: a business asking only whether you are over 18 never sees the date."),
        .init("birthdate.age_over_18", .birthdate, "Over 18", .derivedBoolean, sensitivity: .elevated, summary: "Computed from your date of birth."),
        .init("birthdate.age_over_21", .birthdate, "Over 21", .derivedBoolean, sensitivity: .elevated, summary: "Computed from your date of birth."),
        // Travel
        .init("travel.frequent_flyer", .travel, "Frequent-flyer number", .identifier, maxLength: 20, minLength: 3, entryLabel: "airline", maxEntries: 10,
              sensitivity: .elevated, summary: "One per airline (two- or three-character airline code)."),
        .init("travel.known_traveler_number", .travel, "Known traveler number", .identifier, maxLength: 15, minLength: 8, sensitivity: .high,
              summary: "A trusted-traveler program number (for example TSA PreCheck)."),
        .init("travel.seat_preference", .travel, "Seat preference", .choice, allowedValues: seatPreferences, summary: "Window or aisle."),
        .init("travel.meal_preference", .travel, "Meal preference", .choice, allowedValues: mealPreferences,
              summary: "Not for medical or dietary-health needs: tell those to the airline directly."),
        // Memberships
        .init("memberships.loyalty_number", .memberships, "Loyalty number", .identifier, maxLength: 32, minLength: 3, entryLabel: "program", maxEntries: 20,
              sensitivity: .elevated, summary: "One per program."),
        // Vehicle
        .init("vehicle.make", .vehicle, "Make", .text, maxLength: 40, summary: "For example Toyota."),
        .init("vehicle.model", .vehicle, "Model", .text, maxLength: 40, summary: "For example Corolla."),
        .init("vehicle.year", .vehicle, "Year", .year, maxLength: 4, minLength: 4, summary: "Model year."),
        .init("vehicle.plate", .vehicle, "Plate", .identifier, maxLength: 10, minLength: 2, sensitivity: .elevated, summary: "Optional."),
        // Home
        .init("home.property_type", .home, "Property type", .choice, allowedValues: propertyTypes, summary: "House, apartment, condo..."),
        .init("home.access_notes", .home, "Access notes", .note, maxLength: 200, sensitivity: .elevated,
              summary: "Short notes for a visit (gate, parking, pets). No health information."),
        // Work
        .init("work.employer", .work, "Employer", .text, maxLength: 80, summary: "Where you work."),
        .init("work.title", .work, "Job title", .text, maxLength: 80, summary: "Your role."),
        // Verified identity (read-only, from the Verify flows)
        .init("verified.identity", .verified, "Verified ID", .derivedBoolean, sensitivity: .elevated, summary: "You presented a valid ID."),
        .init("verified.legal_name", .verified, "Verified legal name", .derivedBoolean, sensitivity: .elevated,
              summary: "The name on your profile matches your ID."),
        .init("verified.age_over_18", .verified, "Verified over 18", .derivedBoolean, sensitivity: .elevated, summary: "Confirmed with your ID."),
        .init("verified.age_over_21", .verified, "Verified over 21", .derivedBoolean, sensitivity: .elevated, summary: "Confirmed with your ID."),
    ]

    private static let byKey: [String: ProfileFieldDefinition] = Dictionary(uniqueKeysWithValues: fields.map { ($0.key, $0) })

    public static func definition(for key: String) -> ProfileFieldDefinition? { byKey[key] }

    public static func fields(in category: ProfileCategory) -> [ProfileFieldDefinition] { fields.filter { $0.category == category } }

    /// The category of `key`, or `nil` when it is not in the catalog.
    public static func category(of key: String) -> ProfileCategory? { byKey[key]?.category }

    /// Terms no field key, title or summary may contain (the catalog test checks it, so a future field cannot slip a banned category in).
    public static let forbiddenTerms = ["health", "medical", "allerg", "disab", "diagnos", "medication", "prescription", "insurance id", "ssn",
                                        "social security", "passport number", "license number", "national id", "card number", "cvv", "iban",
                                        "routing", "bank account", "biometric", "fingerprint", "religio", "sexual", "orientation", "politic",
                                        "ethnic", "race", "gps", "live location", "precise location"]

    // MARK: Validation

    /// Checks one value for `key` (and `entry`, for multi-entry fields) and returns it normalized (trimmed, whitespace collapsed; e-mail
    /// lower-cased; phone in E.164). Throws `ProfileValueIssue`.
    public static func validate(key: String, entry: String?, value: ProfileValue) throws -> ProfileValue {
        guard let definition = definition(for: key) else { throw ProfileValueIssue.unknownField }
        guard !definition.isDerived else { throw ProfileValueIssue.readOnly }
        _ = try validateEntry(entry, for: definition)
        switch (definition.type, value) {
        case (.address, .address(let address)):
            return .address(try validate(address, maxLength: definition.maxLength))
        case (.address, _), (_, .address), (_, .boolean):
            throw ProfileValueIssue.wrongType
        case (_, .text(let raw)):
            return .text(try validateText(raw, definition: definition))
        }
    }

    /// The normalized entry label for a multi-entry field (`nil` for single-value fields). Airline codes are upper-cased.
    public static func validateEntry(_ entry: String?, for definition: ProfileFieldDefinition) throws -> String? {
        guard let label = definition.entryLabel else {
            if let entry, !entry.isEmpty { throw ProfileValueIssue.entryNotAllowed }
            return nil
        }
        guard let raw = entry else { throw ProfileValueIssue.entryRequired }
        let trimmed = collapse(raw)
        guard !trimmed.isEmpty else { throw ProfileValueIssue.entryRequired }
        if label == "airline" {
            let code = trimmed.uppercased()
            guard (2...3).contains(code.count), code.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber) }) else { throw ProfileValueIssue.invalidEntry }
            return code
        }
        guard DisplayTextSanitizer.violation(of: trimmed, maxCharacters: 40, identity: true) == nil, !looksLikeForbiddenIdentifier(trimmed) else {
            throw ProfileValueIssue.invalidEntry
        }
        return trimmed
    }

    private static func collapse(_ text: String) -> String {
        text.split(whereSeparator: { $0.isWhitespace }).joined(separator: " ")
    }

    static func validateText(_ raw: String, definition: ProfileFieldDefinition) throws -> String {
        // Hostile characters are refused before anything is trimmed away, so a hidden control character cannot ride along.
        if DisplayTextSanitizer.containsDisallowedScalars(raw) { throw ProfileValueIssue.disallowedCharacters }
        let value = collapse(raw)
        guard !value.isEmpty else { throw ProfileValueIssue.empty }
        guard DisplayTextSanitizer.isWithinLimits(value, maxCharacters: definition.maxLength) else { throw ProfileValueIssue.tooLong }
        guard value.count >= definition.minLength else { throw ProfileValueIssue.tooShort }
        switch definition.type {
        case .text, .note:
            if DisplayTextSanitizer.impersonatesViadere(value, anywhere: definition.type == .text) { throw ProfileValueIssue.impersonation }
            if looksLikeForbiddenIdentifier(value) { throw ProfileValueIssue.forbiddenIdentifier }
            return value
        case .email:
            let lower = value.lowercased()
            let parts = lower.split(separator: "@", omittingEmptySubsequences: false)
            guard parts.count == 2, !parts[0].isEmpty, parts[1].contains("."), !parts[1].hasPrefix("."), !parts[1].hasSuffix("."),
                  lower.allSatisfy({ $0.isASCII && !$0.isWhitespace }) else { throw ProfileValueIssue.invalidFormat }
            return lower
        case .phone:
            guard let phone = PhoneNumber(value) else { throw ProfileValueIssue.invalidFormat }
            return phone.e164
        case .date:
            guard let day = AgeThreshold.Day(isoDate: value), value.count == 10 else { throw ProfileValueIssue.invalidFormat }
            // No future dates, nobody older than 130.
            guard day.year >= 1890, day <= AgeThreshold.Day(utc: Date()) else { throw ProfileValueIssue.invalidFormat }
            return value
        case .language:
            let parts = value.split(separator: "-", omittingEmptySubsequences: false)
            guard parts.allSatisfy({ (1...8).contains($0.count) && $0.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber) } }),
                  let first = parts.first, (2...3).contains(first.count), first.allSatisfy({ $0.isLetter }) else { throw ProfileValueIssue.invalidFormat }
            return value
        case .choice:
            guard definition.allowedValues?.contains(value) == true else { throw ProfileValueIssue.notAllowed }
            return value
        case .identifier:
            guard value.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == " ") }) else { throw ProfileValueIssue.invalidFormat }
            // Membership numbers are legitimately long digit strings, so only the payment-card shape is refused here.
            if looksLikeForbiddenIdentifier(value, strict: false) { throw ProfileValueIssue.forbiddenIdentifier }
            return value.uppercased()
        case .year:
            guard let year = Int(value), value.count == 4, (1900...2100).contains(year) else { throw ProfileValueIssue.invalidFormat }
            return value
        case .address, .derivedBoolean:
            throw ProfileValueIssue.wrongType
        }
    }

    static func validate(_ address: ProfileAddress, maxLength: Int) throws -> ProfileAddress {
        var out = address
        func check(_ text: String?, required: Bool, max: Int) throws -> String? {
            guard let text else {
                if required { throw ProfileValueIssue.empty }
                return nil
            }
            if DisplayTextSanitizer.containsDisallowedScalars(text) { throw ProfileValueIssue.disallowedCharacters }
            let value = collapse(text)
            if value.isEmpty {
                if required { throw ProfileValueIssue.empty }
                return nil
            }
            guard DisplayTextSanitizer.isWithinLimits(value, maxCharacters: max) else { throw ProfileValueIssue.tooLong }
            if DisplayTextSanitizer.impersonatesViadere(value) { throw ProfileValueIssue.impersonation }
            if looksLikeForbiddenIdentifier(value) { throw ProfileValueIssue.forbiddenIdentifier }
            return value
        }
        out.line1 = try check(address.line1, required: true, max: maxLength) ?? ""
        out.line2 = try check(address.line2, required: false, max: maxLength)
        out.locality = try check(address.locality, required: true, max: 80) ?? ""
        out.region = try check(address.region, required: false, max: 80)
        out.postalCode = try check(address.postalCode, required: false, max: 16)
        let country = address.country.uppercased()
        guard country.count == 2, country.allSatisfy({ $0.isASCII && $0.isLetter }) else { throw ProfileValueIssue.invalidFormat }
        out.country = country
        return out
    }

    /// Whether `text` contains something that looks like a payment card (13-19 digits passing the Luhn check) or, when `strict`, a bank
    /// account or national ID number (any run of 9 or more digits, spaces, dashes and dots ignored; this covers a US SSN `ddd-dd-dddd`).
    /// Strict applies to every free-text, name, entry-label and address value; identifier fields (membership, frequent-flyer, known
    /// traveler numbers, plates) are not strict because such numbers are long digit strings, so only the card shape is refused there.
    /// Residual (docs/PROFILES.md §Never collected): a 9-digit government number typed into an identifier field cannot be told apart from
    /// a membership number, and a membership number with the shape of a card number is refused.
    public static func looksLikeForbiddenIdentifier(_ text: String, strict: Bool = true) -> Bool {
        var run = ""
        var longest = 0
        var runs: [String] = []
        for character in text {
            if character.isASCII, character.isNumber {
                run.append(character)
            } else if character == " " || character == "-" || character == "." {
                continue
            } else {
                if !run.isEmpty { runs.append(run) }
                longest = max(longest, run.count)
                run = ""
            }
        }
        if !run.isEmpty { runs.append(run) }
        longest = max(longest, run.count)
        if strict, longest >= 9 { return true }
        return runs.contains { (13...19).contains($0.count) && luhn($0) }
    }

    static func luhn(_ digits: String) -> Bool {
        var sum = 0
        for (index, character) in digits.reversed().enumerated() {
            guard let digit = character.wholeNumberValue else { return false }
            if index % 2 == 1 {
                let doubled = digit * 2
                sum += doubled > 9 ? doubled - 9 : doubled
            } else {
                sum += digit
            }
        }
        return sum % 10 == 0
    }
}
