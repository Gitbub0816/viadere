import Foundation

public struct LintFinding: Sendable, CustomStringConvertible {
    public enum Severity: String, Sendable { case error, warning }
    public let rule: String
    public let page: String
    public let message: String
    public let severity: Severity
    public var description: String { "[\(severity.rawValue)] \(rule) \(page): \(message)" }
}

/// Marketing integrity lint (docs/SECURITY-TRUST-PLATFORM-SPEC.md §10.2 and acceptance criterion 10).
///
/// Rules
/// - `banned-claim`: a banned marketing claim appears un-negated and the page has no approved `claims:` entry for it.
/// - `unearned-attestation`: an attestation or certification term appears un-negated without an approved `claims:` entry.
/// - `claim-evidence`: a `claims:` entry lacks `phrase`, `feature`, `evidence` or `approved_by`, or cites a missing file.
/// - `product-status`: a product page lacks `status: live|beta|planned`, or claims availability its status does not support.
/// - `sms-not-e2ee`: a page that mentions SMS fallback does not state that SMS is not end-to-end encrypted.
/// - `fee-disclosure`: a `pricing: true` page does not disclose per-message, verification, carrier, provider and overage fees.
/// - `disclosure-verbatim`: a page citing `disclosures:` does not contain the §11.5 text verbatim.
/// - `legal-metadata`, `legal-version`, `legal-draft`: legal pages need version, effective_date, owner, counsel_review,
///   cannot be in effect without approved counsel review, and versions must be unique and ordered.
public struct IntegrityLint {
    public static let bannedClaims: [String] = [
        "unhackable", "anonymous", "zero knowledge", "government certified",
        "bank compliant", "HIPAA compliant", "end-to-end encrypted",
    ]
    public static let attestationTerms: [String] = [
        "SOC 2", "SOC2", "ISO 27001", "PCI DSS", "FedRAMP", "HITRUST", "certified", "independently audited",
        "GDPR compliant", "CCPA compliant", "SOX compliant",
    ]
    static let negation = try! NSRegularExpression(pattern: "\\b(not|never|no|isn't|aren't|don't|doesn't|cannot|can't|won't|without|nor|neither)\\b", options: .caseInsensitive)
    static let smsFallback = try! NSRegularExpression(pattern: "sms\\s+fallback|fall(?:s|ing)?\\s*back\\s+to\\s+sms|fallback\\s+to\\s+sms|text\\s+fallback", options: .caseInsensitive)

    public var repoRoot: URL?
    public init(repoRoot: URL?) { self.repoRoot = repoRoot }

    /// Lowercase, straight quotes, hyphens/dashes/underscores as spaces, collapsed whitespace: so "Zero-Knowledge" matches "zero knowledge".
    static func normalize(_ s: String) -> String {
        var t = s.lowercased()
        for (a, b) in [("\u{2019}", "'"), ("\u{2018}", "'"), ("\u{201C}", "\""), ("\u{201D}", "\""), ("\u{2011}", "-")] { t = t.replacingOccurrences(of: a, with: b) }
        t = t.replacingOccurrences(of: "[\\-\u{2010}-\u{2015}_]+", with: " ", options: .regularExpression)
        return t.replacingOccurrences(of: "[ \\t]+", with: " ", options: .regularExpression)
    }

    static func sentences(_ text: String) -> [String] {
        var out: [String] = []
        var cur = ""
        for c in text {
            if c == "." || c == "!" || c == "?" || c == "\n" || c == "|" { if !cur.trimmed.isEmpty { out.append(cur) }; cur = "" }
            else { cur.append(c) }
        }
        if !cur.trimmed.isEmpty { out.append(cur) }
        return out
    }

    /// Returns true when the term occurs at least once outside a negating context.
    static func occursUnnegated(_ term: String, in text: String) -> Bool {
        let n = normalize(term)
        let pattern = "(?<![a-z0-9])" + NSRegularExpression.escapedPattern(for: n) + (n == "anonymous" ? "" : "(?![a-z0-9])")
        guard let re = try? NSRegularExpression(pattern: pattern) else { return false }
        for sentence in sentences(text) {
            let s = normalize(sentence)
            let ns = s as NSString
            for m in re.matches(in: s, range: NSRange(location: 0, length: ns.length)) {
                let before = ns.substring(to: m.range.location)
                let negated = negation.firstMatch(in: before, range: NSRange(location: 0, length: (before as NSString).length)) != nil
                if !negated { return true }
            }
        }
        return false
    }

    public func check(_ page: Page, assembledText: String, allPages: [Page] = []) -> [LintFinding] {
        var f: [LintFinding] = []
        let id = page.url
        func err(_ rule: String, _ msg: String, _ sev: LintFinding.Severity = .error) { f.append(LintFinding(rule: rule, page: id, message: msg, severity: sev)) }

        let metaText = [page.title, page.description].joined(separator: ". ")
        let text = metaText + ".\n" + assembledText
        let claims = page.claims
        var approved = Set<String>()
        for c in claims {
            var ok = true
            if c.phrase.isEmpty || c.feature.isEmpty || c.evidence.isEmpty || c.approvedBy.isEmpty {
                err("claim-evidence", "claims entry needs phrase, feature, evidence and approved_by (got phrase=\"\(c.phrase)\")"); ok = false
            } else if let root = repoRoot, !c.evidence.contains("://") {
                let path = c.evidence.split(separator: "#").first.map(String.init) ?? c.evidence
                if !FileManager.default.fileExists(atPath: root.appendingPathComponent(path).path) {
                    err("claim-evidence", "evidence file \(c.evidence) does not exist"); ok = false
                }
            }
            if ok { approved.insert(Self.normalize(c.phrase)) }
        }

        for (rule, terms) in [("banned-claim", Self.bannedClaims), ("unearned-attestation", Self.attestationTerms)] {
            for term in terms where Self.occursUnnegated(term, in: text) && !approved.contains(Self.normalize(term)) {
                err(rule, "\"\(term)\" is used without an approved claims: entry referencing documented evidence")
            }
        }
        for c in claims where !c.phrase.isEmpty && !Self.occursUnnegated(c.phrase, in: text) {
            err("claim-evidence", "claims entry \"\(c.phrase)\" is not used on this page (remove stale approvals)", .warning)
        }

        // Product status badges and availability language.
        if page.isProductPage {
            if page.status == nil { err("product-status", "product pages must set status: live | beta | planned") }
            else if page.status != .live {
                for phrase in ["generally available", "now available", "available today", "available now", "is live", "are live"]
                where Self.occursUnnegated(phrase, in: text) {
                    err("product-status", "status is \(page.status!.rawValue) but the page says \"\(phrase)\"")
                }
            }
        }

        // SMS fallback pages must state SMS is not end-to-end encrypted.
        let mentionsSMS = page.front["sms_fallback"]?.bool == true
            || Self.smsFallback.firstMatch(in: text, range: NSRange(location: 0, length: (text as NSString).length)) != nil
        if mentionsSMS {
            let ok = Self.sentences(text).contains {
                let s = Self.normalize($0)
                return s.contains("sms") && s.contains("end to end encrypt") && Self.negation.firstMatch(in: s, range: NSRange(location: 0, length: (s as NSString).length)) != nil
            }
            if !ok { err("sms-not-e2ee", "page mentions SMS fallback but does not state that SMS is not end-to-end encrypted") }
        }

        // Pricing fee disclosure.
        if page.front["pricing"]?.bool == true {
            let n = Self.normalize(text)
            for needle in ["per message", "verification", "carrier", "provider", "overage"] where !n.contains(needle) {
                err("fee-disclosure", "pricing page must disclose \(needle) fees")
            }
        }

        // Verbatim §11.5 disclosures.
        for key in page.front["disclosures"]?.strings ?? [] {
            guard let expected = Disclosures.all[key] else { err("disclosure-verbatim", "unknown disclosure key \(key)"); continue }
            if !Self.collapse(assembledText).contains(Self.collapse(expected)) {
                err("disclosure-verbatim", "disclosure \(key) must appear verbatim (§11.5)")
            }
        }

        // Legal pages.
        if page.isLegal { f += checkLegal(page, allPages: allPages) }
        return f
    }

    static func collapse(_ s: String) -> String {
        s.replacingOccurrences(of: "[>\\s]+", with: " ", options: .regularExpression)
            .replacingOccurrences(of: "\u{2019}", with: "'")
    }

    func checkLegal(_ page: Page, allPages: [Page]) -> [LintFinding] {
        var f: [LintFinding] = []
        func err(_ rule: String, _ msg: String) { f.append(LintFinding(rule: rule, page: page.url, message: msg, severity: .error)) }
        for key in ["version", "effective_date", "owner", "counsel_review"] where page.front[key] == nil {
            err("legal-metadata", "front matter needs `\(key)` (leave effective_date empty until approved)")
        }
        let version = page.front["version"]?.string ?? ""
        if version.range(of: "^\\d+\\.\\d+\\.\\d+$", options: .regularExpression) == nil { err("legal-version", "version must look like 0.1.0 (got \"\(version)\")") }
        if (page.front["owner"]?.string ?? "").isEmpty { err("legal-metadata", "owner must not be empty") }
        let review = page.front["counsel_review"]?.string ?? ""
        if !["pending", "in-review", "approved"].contains(review) { err("legal-metadata", "counsel_review must be pending, in-review or approved") }
        let eff = page.front["effective_date"]?.string ?? ""
        if !eff.isEmpty {
            if review != "approved" { err("legal-draft", "effective_date is set but counsel_review is \(review): a document cannot take effect before counsel approval") }
            if eff.range(of: "^\\d{4}-\\d{2}-\\d{2}$", options: .regularExpression) == nil { err("legal-metadata", "effective_date must be YYYY-MM-DD") }
        }
        if page.legalIsArchive {
            if (page.front["superseded_on"]?.string ?? "").isEmpty { err("legal-metadata", "archived versions need superseded_on") }
        } else if let slug = page.legalSlug {
            let versions = allPages.filter { $0.legalSlug == slug }.map { $0.front["version"]?.string ?? "" }
            if Set(versions).count != versions.count { err("legal-version", "duplicate version numbers in \(slug)") }
            for p in allPages where p.legalSlug == slug && p.legalIsArchive {
                if LegalCatalog.compareVersions(p.front["version"]?.string ?? "0", version) >= 0 {
                    err("legal-version", "archived version \(p.front["version"]?.string ?? "?") is not older than the current \(version)")
                }
            }
        }
        return f
    }
}

/// Archived legal versions with an effective date are immutable: their SHA-256 is recorded in `legal-lock.json`.
public enum LegalLock {
    public static func entries(pages: [Page]) -> [String: String] {
        var out: [String: String] = [:]
        for p in pages where p.isLegal {
            let eff = p.front["effective_date"]?.string ?? ""
            guard !eff.isEmpty else { continue }
            out["\(p.legalSlug ?? "")@\(p.front["version"]?.string ?? "")"] = SHA256.hex(p.body + "\n" + (p.front["effective_date"]?.string ?? ""))
        }
        return out
    }

    public static func check(lock: [String: String], pages: [Page]) -> [LintFinding] {
        let now = entries(pages: pages)
        var f: [LintFinding] = []
        for (key, hash) in lock {
            if let cur = now[key] {
                if cur != hash { f.append(LintFinding(rule: "legal-lock", page: key, message: "a version that took effect was modified: publish a new version instead", severity: .error)) }
            } else {
                f.append(LintFinding(rule: "legal-lock", page: key, message: "a version that took effect was removed: archived versions must stay at their stable URL", severity: .error))
            }
        }
        return f
    }

    public static func encode(_ e: [String: String]) -> String {
        let body = e.keys.sorted().map { "  \"\($0)\": \"\(e[$0]!)\"" }.joined(separator: ",\n")
        return "{\n\(body)\n}\n"
    }

    public static func decode(_ text: String) -> [String: String] {
        guard let d = text.data(using: .utf8), let o = try? JSONSerialization.jsonObject(with: d) as? [String: String] else { return [:] }
        return o
    }
}
