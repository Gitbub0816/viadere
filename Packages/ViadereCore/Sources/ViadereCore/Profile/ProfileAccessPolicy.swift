import Foundation

/// Who may see which profile field (docs/PROFILES.md §Access). Three gates, all required, evaluated at **request time and again at every read**:
///
/// 1. **Category entitlement** (like an Apple entitlement): Viadere allowed the business the field's category, after the business asked for it
///    during onboarding (with a written justification where `ProfileCategory.requiresJustification`) and an operator approved it. **No category
///    is allowed by default**, a business cannot grant one to itself, and an operator revocation takes effect on the next call.
/// 2. **Customer grant**: the customer granted this field to this business (per field, revocable at any time).
/// 3. **Environment**: a live key reads only real customers, a test key only sandbox customers.
///
/// The public name is outside this policy: every connected business receives it.
public enum ProfileAccessPolicy {
    /// Keys a business may not even ask for: unknown to the catalog, or outside its allowed categories. Empty means the request is acceptable.
    public static func disallowed(_ keys: [String], allowed categories: Set<ProfileCategory>) -> [String] {
        keys.filter { key in
            guard let category = ProfileCatalog.category(of: key) else { return true }
            return !categories.contains(category)
        }
    }

    /// The subset of `granted` keys a business may read now, given its allowed categories.
    public static func readable(_ granted: Set<String>, allowed categories: Set<ProfileCategory>) -> Set<String> {
        granted.filter { key in ProfileCatalog.category(of: key).map(categories.contains) ?? false }
    }

    /// The stored values that back a field: derived fields read the date of birth or the verified facts.
    public static func sourceKeys(for key: String) -> [String] {
        switch key {
        case "birthdate.age_over_18", "birthdate.age_over_21": ["birthdate.date"]
        default: [key]
        }
    }

    /// Value of a derived age check from a self-entered birth date (conservative day, `AgeThreshold.Day(earliestLocal:)`).
    public static func ageCheck(key: String, birthDate: String?, now: Date) -> Bool? {
        guard let birthDate else { return nil }
        switch key {
        case "birthdate.age_over_18": return AgeThreshold.meets(birthDate: birthDate, years: 18, now: now)
        case "birthdate.age_over_21": return AgeThreshold.meets(birthDate: birthDate, years: 21, now: now)
        default: return nil
        }
    }
}
