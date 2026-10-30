import Foundation

/// Content rules over business-authored Loop text (titles, bodies, labels, options, parameter text). Versioned in Core; a rule change is a
/// code change with an ADR (plan section 4.12, O20).
///
/// These are a **tripwire**, never the control: the control is the closed field-type allowlist and the action registry (health data,
/// secrets and payment data have no field to live in). Word lists catch clear cases early and give the reviewer rule-coded reasons.
public enum LoopContentRules {
    public static let version = 1

    /// What a text hit means.
    public enum Topic: String, Sendable, Codable, Hashable {
        /// Health or medical information or services (FX-4: banned platform-wide). Hard gate.
        case health
        /// Requests for secrets, payment card/bank data or government identifiers. Hard gate.
        case sensitiveData = "sensitive_data"
        /// Text that claims authorship, verification or platform origin ("Built by", "Secured by", "Verified by"). Hard gate.
        case attributionClaim = "attribution_claim"
        /// Links, domains, e-mail addresses. Hard gate (INV-4: no arbitrary URLs).
        case link
        /// Ambiguous health-adjacent words ("therapy", "treatment", "wellness"). Review flag: mandatory second reviewer.
        case healthAdjacent = "health_adjacent"
        /// Government, bank or official claims. Review flag: mandatory second reviewer.
        case authorityClaim = "authority_claim"
    }

    public static func isHardGate(_ topic: Topic) -> Bool {
        switch topic {
        case .health, .sensitiveData, .attributionClaim, .link: true
        case .healthAdjacent, .authorityClaim: false
        }
    }

    /// A term: tokens to match in sequence; the last token may match as a prefix (`stem`).
    struct Term {
        let tokens: [String]
        let stem: Bool
        let topic: Topic

        init(_ phrase: String, _ topic: Topic, stem: Bool = false) {
            tokens = phrase.split(separator: " ").map(String.init)
            self.stem = stem
            self.topic = topic
        }
    }

    static let terms: [Term] = {
        var t: [Term] = []
        // Health (FX-4). Stems catch inflections ("diagnosis", "diagnosed").
        for stem in ["diagnos", "symptom", "prescri", "medic", "pharmac", "clinic", "physician", "hospital", "dentist", "dental",
                     "illness", "disease", "allerg", "pregnan", "vaccin", "surgery", "surgical", "psychiatr", "mental health",
                     "health record", "health insurance", "health condition", "telehealth", "healthcare", "hipaa", "chiropract", "optometr",
                     "orthodont", "pediatric", "disabilit", "injur"] {
            t.append(Term(stem, .health, stem: true))
        }
        for word in ["health", "doctor", "doctors", "nurse", "nurses", "nursing", "phi", "covid", "x-ray", "xray", "medicine", "rx"] {
            t.append(Term(word, .health))
        }
        for stem in ["therap", "treatment", "wellness", "insurance", "counsel", "patient"] { t.append(Term(stem, .healthAdjacent, stem: true)) }
        // Secrets, payment and government identifiers (FX-5 and the field allowlist).
        for phrase in ["password", "passcode", "pin code", "pin number", "one time code", "verification code", "security code", "otp",
                       "card number", "credit card", "debit card", "cvv", "cvc", "expiry date", "expiration date", "iban", "routing number",
                       "account number", "bank account", "ssn", "social security", "passport number", "driver license", "drivers license",
                       "license number", "tax id", "national id", "date of birth", "mother maiden name", "seed phrase", "recovery phrase"] {
            t.append(Term(phrase, .sensitiveData))
        }
        // Attribution and platform claims (A6a: authorship comes only from the signed manifest).
        for phrase in ["built by", "created by", "made by", "authored by", "secured by", "protected by", "verified by", "powered by",
                       "verified business", "official viadere", "from viadere"] {
            t.append(Term(phrase, .attributionClaim))
        }
        for phrase in ["government", "federal", "irs", "police", "official notice", "your bank", "fraud department", "bank security"] {
            t.append(Term(phrase, .authorityClaim))
        }
        return t
    }()

    /// Lower-cased, diacritic- and width-folded word tokens of `text` (letters and digits; everything else separates). Apostrophes are
    /// dropped inside words ("driver's" → "drivers").
    static func tokens(_ text: String) -> [String] {
        let folded = text.folding(options: [.caseInsensitive, .diacriticInsensitive, .widthInsensitive], locale: nil)
            .replacingOccurrences(of: "'", with: "").replacingOccurrences(of: "\u{2019}", with: "")
        var out: [String] = []
        var current = ""
        for ch in folded {
            if ch.isLetter || ch.isNumber || ch == "-" { current.append(ch) } else if !current.isEmpty { out.append(current); current = "" }
        }
        if !current.isEmpty { out.append(current) }
        // Hyphenated words are matched both whole ("x-ray") and split ("x", "ray").
        var expanded: [String] = []
        for token in out {
            let trimmed = token.trimmingCharacters(in: CharacterSet(charactersIn: "-"))
            if trimmed.isEmpty { continue }
            expanded.append(trimmed)
        }
        return expanded
    }

    /// Topics of every term found in `text`, in rule order, without duplicates.
    public static func topics(in text: String) -> [Topic] {
        var found: [Topic] = []
        let words = tokens(text)
        let split = words.flatMap { $0.split(separator: "-").map(String.init) }
        for sequence in [words, split] {
            for term in terms where !found.contains(term.topic) {
                if matches(term, in: sequence) { found.append(term.topic) }
            }
        }
        if containsLink(text), !found.contains(.link) { found.append(.link) }
        return found
    }

    static func matches(_ term: Term, in words: [String]) -> Bool {
        let n = term.tokens.count
        guard words.count >= n else { return false }
        for start in 0...(words.count - n) {
            var ok = true
            for (offset, token) in term.tokens.enumerated() {
                let word = words[start + offset]
                let isLast = offset == n - 1
                if isLast && term.stem ? !word.hasPrefix(token) : word != token { ok = false; break }
            }
            if ok { return true }
        }
        return false
    }

    static let linkTLDs: Set<String> = ["com", "net", "org", "io", "co", "app", "link", "ly", "me", "info", "biz", "xyz", "site", "online",
                                        "shop", "store", "us", "uk", "ca", "de", "fr", "page", "dev", "gl", "to", "tk", "top", "click"]

    /// Whether `text` contains a URL, a bare domain or an e-mail address.
    public static func containsLink(_ text: String) -> Bool {
        let lower = text.lowercased()
        if lower.contains("://") || lower.contains("www.") || lower.contains("mailto:") || lower.contains("tel:") { return true }
        // name.tld, name@host.tld (letters/digits/hyphen labels), with the fullwidth dot folded.
        let folded = lower.folding(options: [.widthInsensitive], locale: nil).replacingOccurrences(of: "\u{3002}", with: ".")
        let pieces = folded.split(whereSeparator: { $0.isWhitespace || "()[]<>\"',;!?".contains($0) })
        for piece in pieces {
            if piece.contains("@") && piece.contains(".") { return true }
            let labels = piece.split(separator: ".", omittingEmptySubsequences: false)
            guard labels.count >= 2 else { continue }
            let tld = labels.last.map { String($0).trimmingCharacters(in: CharacterSet(charactersIn: "/:")) } ?? ""
            let host = labels.dropLast().last.map(String.init) ?? ""
            if linkTLDs.contains(tld), !host.isEmpty, host.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "-" }) { return true }
        }
        return false
    }
}

/// Business categories and the Loop / platform decision for each (FX-4, plan section 4.13 layer 1, open decision O19).
public enum LoopCategoryPolicy {
    /// Categories refused **platform-wide** (onboarding stops with a plain reason; existing records are offboarded). The plan assumes the
    /// platform-wide reading of FX-4 (O19).
    public static let bannedPlatformWide: Set<String> = ["healthcare", "health", "medical", "pharmacy", "dental", "telehealth"]
    /// Categories that may use Viadere but never Loops (Acceptable Use Policy prohibited categories for business-authored content).
    public static let prohibitedForLoops: Set<String> = ["adult", "gambling", "weapons", "firearms", "cannabis", "tobacco", "crypto_exchange",
                                                          "debt_collection", "government"]

    public enum Decision: Sendable, Hashable, Codable {
        case eligible
        case refused(reason: String)
    }

    /// Whether a business in `category` may be onboarded at all.
    public static func onboarding(_ category: BusinessCategory) -> Decision {
        bannedPlatformWide.contains(category.rawValue.lowercased()) ? .refused(reason: "healthcare_banned") : .eligible
    }

    /// Whether a business in `category` may hold the `loops` entitlement or submit a Loop.
    public static func loops(_ category: BusinessCategory) -> Decision {
        let raw = category.rawValue.lowercased()
        if bannedPlatformWide.contains(raw) { return .refused(reason: "healthcare_banned") }
        if prohibitedForLoops.contains(raw) { return .refused(reason: "category_prohibited") }
        return .eligible
    }
}
