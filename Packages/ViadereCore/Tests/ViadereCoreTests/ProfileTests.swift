import Foundation
import Testing
@testable import ViadereCore

@Suite("Customer profiles: catalog, public name, access policy")
struct ProfileTests {
    // MARK: Catalog

    @Test func catalogKeysAreUniqueNamespacedAndClosed() throws {
        let keys = ProfileCatalog.fields.map(\.key)
        #expect(Set(keys).count == keys.count)
        for field in ProfileCatalog.fields {
            #expect(field.key.hasPrefix(field.category.rawValue + "."), "\(field.key)")
            #expect(field.maxLength > 0 && field.maxLength <= 254)
        }
        #expect(ProfileCatalog.version >= 1)
        // Every category has at least one field.
        for category in ProfileCategory.allCases { #expect(!ProfileCatalog.fields(in: category).isEmpty, "\(category)") }
        // Unknown keys are refused, whatever they claim to be.
        for key in ["health.allergies", "medical.conditions", "identity.ssn", "contact.ssn", "payment.card_number", "personal.religion",
                    "personal.sexual_orientation", "personal.political_party", "location.live", "biometric.face", "CONTACT.EMAIL", "contact.email "] {
            #expect(throws: ProfileValueIssue.unknownField) { try ProfileCatalog.validate(key: key, entry: nil, value: .text("x")) }
        }
    }

    @Test func catalogHasNoFieldInABannedCategory() {
        for field in ProfileCatalog.fields {
            let haystack = "\(field.key) \(field.title) \(field.allowedValues?.joined(separator: " ") ?? "")".lowercased()
            for term in ProfileCatalog.forbiddenTerms {
                #expect(!haystack.contains(term), "field \(field.key) mentions \(term)")
            }
        }
        // No medical or religious meal options (gluten-free, diabetic, kosher, halal...).
        for option in ["gluten_free", "diabetic", "kosher", "halal", "low_sodium", "nut_free"] {
            #expect(!ProfileCatalog.mealPreferences.contains(option))
            #expect(throws: ProfileValueIssue.notAllowed) { try ProfileCatalog.validate(key: "travel.meal_preference", entry: nil, value: .text(option)) }
        }
    }

    @Test func derivedFieldsAreReadOnly() {
        for key in ["birthdate.age_over_18", "verified.identity", "verified.legal_name", "verified.age_over_21"] {
            #expect(throws: ProfileValueIssue.readOnly) { try ProfileCatalog.validate(key: key, entry: nil, value: .boolean(true)) }
        }
    }

    @Test func valuesAreNormalizedAndValidated() throws {
        #expect(try ProfileCatalog.validate(key: "contact.email", entry: nil, value: .text(" Jane@Example.COM ")) == .text("jane@example.com"))
        #expect(throws: ProfileValueIssue.invalidFormat) { try ProfileCatalog.validate(key: "contact.email", entry: nil, value: .text("not-an-email")) }
        #expect(try ProfileCatalog.validate(key: "contact.phone", entry: nil, value: .text("+1 (415) 555-0100")) == .text("+14155550100"))
        #expect(throws: ProfileValueIssue.invalidFormat) { try ProfileCatalog.validate(key: "birthdate.date", entry: nil, value: .text("1990-02-30")) }
        #expect(try ProfileCatalog.validate(key: "birthdate.date", entry: nil, value: .text("1990-02-28")) == .text("1990-02-28"))
        #expect(try ProfileCatalog.validate(key: "travel.frequent_flyer", entry: "ua", value: .text("ab123456")) == .text("AB123456"))
        #expect(try ProfileCatalog.validateEntry("ua", for: ProfileCatalog.definition(for: "travel.frequent_flyer")!) == "UA")
        #expect(throws: ProfileValueIssue.entryRequired) { try ProfileCatalog.validate(key: "travel.frequent_flyer", entry: nil, value: .text("AB123456")) }
        #expect(throws: ProfileValueIssue.entryNotAllowed) { try ProfileCatalog.validate(key: "contact.email", entry: "x", value: .text("a@b.co")) }
        #expect(throws: ProfileValueIssue.wrongType) { try ProfileCatalog.validate(key: "contact.email", entry: nil, value: .boolean(true)) }
        #expect(throws: ProfileValueIssue.tooLong) { try ProfileCatalog.validate(key: "home.access_notes", entry: nil, value: .text(String(repeating: "a", count: 201))) }
        let address = try ProfileCatalog.validate(key: "contact.mailing_address", entry: nil,
                                                  value: .address(ProfileAddress(line1: " 1  Main St ", locality: "Mesa", region: "AZ", postalCode: "85201", country: "us")))
        #expect(address == .address(ProfileAddress(line1: "1 Main St", locality: "Mesa", region: "AZ", postalCode: "85201", country: "US")))
        #expect(throws: ProfileValueIssue.wrongType) { try ProfileCatalog.validate(key: "contact.mailing_address", entry: nil, value: .text("1 Main St")) }
    }

    @Test func hostileTextIsRefused() {
        #expect(throws: ProfileValueIssue.disallowedCharacters) { try ProfileCatalog.validate(key: "work.employer", entry: nil, value: .text("Acme\u{202E}gnp.exe")) }
        #expect(throws: ProfileValueIssue.disallowedCharacters) { try ProfileCatalog.validate(key: "home.access_notes", entry: nil, value: .text("Gate\ncode")) }
        #expect(throws: ProfileValueIssue.impersonation) { try ProfileCatalog.validate(key: "work.employer", entry: nil, value: .text("V1ADERE Support")) }
    }

    @Test func cardBankAndGovernmentNumbersAreNeverCollected() {
        // SSN, card and bank account shapes in free text, names and addresses.
        for text in ["My SSN is 123-45-6789", "4111 1111 1111 1111", "acct 000123456789", "123456789"] {
            #expect(throws: ProfileValueIssue.forbiddenIdentifier) { try ProfileCatalog.validate(key: "home.access_notes", entry: nil, value: .text(text)) }
        }
        #expect(throws: ProfileValueIssue.forbiddenIdentifier) {
            try ProfileCatalog.validate(key: "contact.mailing_address", entry: nil, value: .address(ProfileAddress(line1: "4111111111111111", locality: "Mesa", country: "US")))
        }
        // A card number is refused as a loyalty number too; an ordinary long membership number is fine.
        #expect(throws: ProfileValueIssue.forbiddenIdentifier) { try ProfileCatalog.validate(key: "memberships.loyalty_number", entry: "Shop", value: .text("4111111111111111")) }
        #expect((try? ProfileCatalog.validate(key: "memberships.loyalty_number", entry: "Shop", value: .text("1234567890"))) == .text("1234567890"))
        #expect(!ProfileCatalog.looksLikeForbiddenIdentifier("Gate code 4821"))
        #expect(ProfileCatalog.luhn("4111111111111111"))
    }

    // MARK: Public name

    @Test func publicNameDefaultsToFirstNameAndLastInitial() {
        #expect(PublicName.derive(givenName: "John", familyName: "Doe") == "John D.")
        #expect(PublicName.derive(givenName: " john  paul ", familyName: "o'brien") == "john O.")
        #expect(PublicName.derive(fullName: "Ana María López") == "Ana L.")
        #expect(PublicName.derive(fullName: "Cher") == "Cher")
        #expect(PublicName.derive(fullName: "  ") == nil)
        #expect(PublicName.derive(givenName: nil, familyName: "Doe") == nil)
        #expect(PublicName.effective(custom: "JD", givenName: "John", familyName: "Doe", accountName: nil) == "JD")
        #expect(PublicName.effective(custom: nil, givenName: nil, familyName: nil, accountName: "Jane Roe") == "Jane R.")
    }

    @Test func publicNameImpersonationAndContactDataAreRejected() {
        #expect(PublicName.validate("Viadere") == .impersonation)
        #expect(PublicName.validate("Team V1ADERE") == .impersonation)
        #expect(PublicName.validate("Vіadere") == .impersonation) // Cyrillic і
        #expect(PublicName.validate("Support") == .impersonation)
        #expect(PublicName.validate("Official Account") == .impersonation)
        #expect(PublicName.validate("Verified") == .impersonation)
        #expect(PublicName.validate("Security Team") == .impersonation)
        #expect(PublicName.validate("Customer Care") == .impersonation)
        #expect(PublicName.validate("jane@example.com") == .contactData)
        #expect(PublicName.validate("call 4155550100") == .contactData)
        #expect(PublicName.validate("A\u{200B}na") == .disallowedCharacters)
        #expect(PublicName.validate("J") == .tooShort)
        #expect(PublicName.validate(String(repeating: "a", count: 33)) == .tooLong)
        #expect(PublicName.validate("   ") == .empty)
        #expect(PublicName.validate("Jo M.") == nil)
        #expect(PublicName.validate("Zoë") == nil)
    }

    // MARK: Access policy

    @Test func onlyCategoriesTheBusinessIsAllowedCanBeRequestedOrRead() {
        let allowed: Set<ProfileCategory> = [.contact]
        #expect(ProfileAccessPolicy.disallowed(["contact.email", "travel.frequent_flyer", "nope.field"], allowed: allowed) == ["travel.frequent_flyer", "nope.field"])
        #expect(ProfileAccessPolicy.disallowed(["contact.email"], allowed: []) == ["contact.email"])
        #expect(ProfileAccessPolicy.readable(["contact.email", "work.title"], allowed: allowed) == ["contact.email"])
        #expect(ProfileAccessPolicy.readable(["contact.email"], allowed: []).isEmpty)
    }

    @Test func justificationRulesPerCategory() {
        #expect(!ProfileCategory.contact.requiresJustification)
        #expect(!ProfileCategory.personal.requiresJustification)
        for category in [ProfileCategory.birthdate, .travel, .vehicle, .home, .work, .verified] { #expect(category.requiresJustification, "\(category)") }
        #expect(ProfileCategory.verified.requiresReviewReference)
    }

    @Test func ageChecksUseTheConservativeDay() {
        let now = ISO8601DateFormatter().date(from: "2026-06-15T13:00:00Z")!
        #expect(ProfileAccessPolicy.ageCheck(key: "birthdate.age_over_18", birthDate: "2008-06-14", now: now) == true)
        #expect(ProfileAccessPolicy.ageCheck(key: "birthdate.age_over_18", birthDate: "2008-06-16", now: now) == false)
        #expect(ProfileAccessPolicy.ageCheck(key: "birthdate.age_over_21", birthDate: nil, now: now) == nil)
    }

    // MARK: Wire

    @Test func valuesAndRoutesRoundTrip() throws {
        let values: [ProfileValue] = [.text("x"), .boolean(true), .address(ProfileAddress(line1: "1 Main", locality: "Mesa", country: "US"))]
        for value in values { #expect(try ViadereJSON.decode(ProfileValue.self, from: ViadereJSON.encode(value)) == value) }
        let names = Set(APIRoutes.all.map(\.name))
        for route in APIRoutes.profileEndpoints { #expect(names.contains(route.name)) }
        #expect(APIRoutes.profileEndpoints.filter { $0.auth == .businessAPIKey }.allSatisfy { $0.template.hasPrefix("/v1/business/") })
        #expect(APIRoutes.profileEndpoints.filter { $0.auth != .businessAPIKey }.allSatisfy { $0.auth == .deviceSignedBearer })
        let unknown = try ViadereJSON.decode(ProfileRequestStatus.self, from: Data("\"later\"".utf8))
        #expect(unknown == .unknown)
    }
}
