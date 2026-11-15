import Foundation

/// Decides whether a one-time code belongs to the site that asked for one. A TOTP item stores an issuer and an account name, never a
/// domain, so the match is a conservative heuristic on the site's **registrable label** (the label before the public suffix): the issuer must
/// name it, or the account must be an e-mail address at that site. A subdomain the requester chose (`bank.evil.example`) therefore matches
/// nothing but `evil`. The picker shows only matches; with no match the app tells the person plainly and offers all codes after a tap.
public enum OneTimeCodeDomainMatcher {
    private static let genericSecondLevel: Set<String> = ["co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go"]

    /// The label that identifies the site: `github` for `www.github.com`, `example` for `login.example.co.uk`.
    static func registrableLabel(_ domain: String) -> String? {
        var host = domain.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ". "))
        if let url = URL(string: host), let urlHost = url.host { host = urlHost }
        let labels = host.split(separator: ".").map(String.init)
        guard labels.count >= 2 else { return labels.first.flatMap { $0.count >= 3 ? $0 : nil } }
        var rest = Array(labels.dropLast())              // drop the TLD
        if rest.count >= 2, let last = rest.last, genericSecondLevel.contains(last) { rest.removeLast() }
        guard let label = rest.last, label.count >= 3 else { return nil }
        return label
    }

    private static func normalize(_ text: String) -> String {
        String(text.lowercased().unicodeScalars.filter { ($0.value >= 0x61 && $0.value <= 0x7A) || ($0.value >= 0x30 && $0.value <= 0x39) }.map(Character.init))
    }

    public static func matches(issuer: String?, accountName: String, domain: String) -> Bool {
        guard let label = registrableLabel(domain) else { return false }
        let name = normalize(issuer ?? "")
        if name.count >= 3, name.contains(label) || label.contains(name) { return true }
        if let at = accountName.lastIndex(of: "@") {
            let host = String(accountName[accountName.index(after: at)...])
            if registrableLabel(host) == label { return true }
        }
        return false
    }
}
