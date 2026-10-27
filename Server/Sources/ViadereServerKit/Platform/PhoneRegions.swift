import Foundation
import ViadereCore

/// Destination policy for verification-code SMS (toll-fraud defence): which countries Viadere will text a code to.
///
/// SMS pumping rings request codes to numbers in premium ranges they profit from. The default allows only the United States and
/// Canada. For the shared +1 plan the area code decides: Caribbean NANP countries (Jamaica, Dominican Republic, ...) are
/// separate regions that must be allowed explicitly, even though they dial as +1.
public enum PhoneRegions {
    /// ISO 3166 region → international calling code (regions that do not share a code).
    static let callingCodes: [String: String] = [
        "US": "1", "CA": "1",
        "GB": "44", "DE": "49", "FR": "33", "ES": "34", "IT": "39", "NL": "31", "BE": "32", "CH": "41", "AT": "43", "SE": "46",
        "NO": "47", "DK": "45", "FI": "358", "IE": "353", "PT": "351", "PL": "48", "AU": "61", "NZ": "64", "JP": "81", "KR": "82",
        "SG": "65", "IN": "91", "MX": "52", "BR": "55", "AR": "54", "CL": "56", "CO": "57", "ZA": "27", "AE": "971", "IL": "972",
        // NANP members outside the US and Canada: dialled as +1, told apart by area code.
        "BS": "1", "BB": "1", "AG": "1", "JM": "1", "DO": "1", "TT": "1", "KY": "1", "BM": "1", "GD": "1", "LC": "1", "VC": "1",
        "KN": "1", "DM": "1", "TC": "1", "AI": "1", "VG": "1", "MS": "1", "SX": "1",
    ]

    /// Area codes of the NANP regions that are neither US nor Canada.
    static let nanpAreaCodes: [String: Set<String>] = [
        "BS": ["242"], "BB": ["246"], "AI": ["264"], "AG": ["268"], "VG": ["284"], "KY": ["345"], "BM": ["441"], "GD": ["473"],
        "TC": ["649"], "MS": ["664"], "SX": ["721"], "LC": ["758"], "DM": ["767"], "VC": ["784"], "DO": ["809", "829", "849"],
        "TT": ["868"], "KN": ["869"], "JM": ["876", "658"],
    ]

    private static let nonUSCAAreaCodes: Set<String> = nanpAreaCodes.values.reduce(into: Set<String>()) { $0.formUnion($1) }

    /// Whether a code may be sent to `phone` given the allowed `regions`.
    public static func isAllowed(_ phone: PhoneNumber, regions: [String]) -> Bool {
        let digits = String(phone.e164.dropFirst())
        for region in regions {
            guard let code = callingCodes[region], digits.hasPrefix(code) else { continue }
            if code == "1" {
                guard digits.count >= 4 else { continue }
                let area = String(digits.dropFirst().prefix(3))
                if let own = nanpAreaCodes[region] {
                    if own.contains(area) { return true }
                } else if !nonUSCAAreaCodes.contains(area) {
                    return true   // US or Canada (US territories dial as +1 and are US-regulated)
                }
            } else {
                return true
            }
        }
        return false
    }

    /// `+` and the first `digits` digits: the bucket for the per-prefix budget (country code plus a slice of the national number).
    public static func budgetPrefix(of phone: PhoneNumber, digits: Int) -> String {
        "+" + String(phone.e164.dropFirst().prefix(max(2, digits)))
    }
}
