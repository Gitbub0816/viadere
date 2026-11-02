import Foundation

/// The Viadere-owned template catalog (UX_COPY N-02, N-05, N-06): a business picks an id, never text. Each template fixes the method, the allowed
/// purposes, the variables it declares and the lifetime bounds (ADR-0020 section 2).
public struct AuthDeliveryTemplate: Sendable, Hashable {
    public var id: String
    public var method: AuthDeliveryMethod
    public var purposes: Set<AuthDeliveryPurpose>
    /// The only variable keys the template accepts.
    public var variableKeys: Set<String>

    public static let catalog: [AuthDeliveryTemplate] = [
        AuthDeliveryTemplate(id: "auth.sign_in_link.v1", method: .magicLink, purposes: [.signIn], variableKeys: ["reference"]),
        AuthDeliveryTemplate(id: "auth.step_up_link.v1", method: .magicLink, purposes: [.stepUp], variableKeys: ["action_display", "reference"]),
        AuthDeliveryTemplate(id: "auth.verify_contact_link.v1", method: .magicLink, purposes: [.verifyContact], variableKeys: ["reference"]),
        AuthDeliveryTemplate(id: "auth.sign_in_code.v1", method: .otp, purposes: [.signIn], variableKeys: ["reference"]),
        AuthDeliveryTemplate(id: "auth.step_up_code.v1", method: .otp, purposes: [.stepUp], variableKeys: ["action_display", "reference"]),
        AuthDeliveryTemplate(id: "auth.verify_contact_code.v1", method: .otp, purposes: [.verifyContact], variableKeys: ["reference"]),
        // N-06 "{Business} sent a security notice." never takes business text (S1-A9-14).
        AuthDeliveryTemplate(id: "auth.security_notice.v1", method: .notice, purposes: [.accountNotice], variableKeys: []),
    ]

    public static func template(_ id: String) -> AuthDeliveryTemplate? { catalog.first { $0.id == id } }

    /// Lifetime bounds in seconds (`expires_in_seconds`), by method.
    public static func lifetimeBounds(for method: AuthDeliveryMethod) -> ClosedRange<Int> {
        switch method {
        case .magicLink: 120...600
        case .otp: 60...600
        case .notice: 300...86_400
        }
    }

    public static func defaultLifetime(for method: AuthDeliveryMethod) -> Int {
        switch method {
        case .magicLink, .otp: 300
        case .notice: 3600
        }
    }
}

/// A reason a create request is refused (`422 validation_failed`, `details[field] = code`).
public struct AuthDeliveryValidationIssue: Error, Sendable, Hashable {
    public var field: String
    public var code: String
    public init(_ field: String, _ code: String) {
        self.field = field
        self.code = code
    }
}

/// Validation shared by the server, the SDKs and tests.
public enum AuthDeliveryValidation {
    public static let maxVariableLength: [String: Int] = ["action_display": 60, "reference": 40]

    /// `[A-Za-z0-9_.:-]`, 1 to `max`.
    public static func isValidIdentifier(_ value: String, max: Int = 128) -> Bool {
        value.utf8.count >= 1 && value.utf8.count <= max && value.utf8.allSatisfy {
            ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x5A) || ($0 >= 0x61 && $0 <= 0x7A) || $0 == 0x5F || $0 == 0x2E || $0 == 0x3A || $0 == 0x2D
        }
    }

    /// 4 to 10 characters of `[0-9A-Z]`.
    public static func isValidCode(_ code: String) -> Bool {
        (4...10).contains(code.utf8.count) && code.utf8.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x5A) }
    }

    // MARK: Text hygiene

    /// Control, format (bidi, zero-width), line and paragraph separator characters. None may appear in a displayed string.
    public static func hasHiddenOrControlCharacters(_ text: String) -> Bool {
        text.unicodeScalars.contains { scalar in
            switch scalar.properties.generalCategory {
            case .control, .format, .lineSeparator, .paragraphSeparator, .privateUse, .surrogate, .unassigned: return true
            default: return false
            }
        }
    }

    /// Whether the string carries `otpauth:` (any case), also after **one** percent-decode: a TOTP seed must never transit Viadere in plaintext (T-TOTP-1).
    public static func containsOTPAuth(_ text: String) -> Bool {
        let lower = text.lowercased()
        if lower.contains("otpauth") { return true }
        if let decoded = text.removingPercentEncoding, decoded.lowercased().contains("otpauth") { return true }
        return false
    }

    /// Whether any string in the JSON tree (a key or a value) carries `otpauth`.
    public static func containsOTPAuth(in value: JSONValue) -> Bool {
        switch value {
        case .string(let s): containsOTPAuth(s)
        case .array(let items): items.contains { containsOTPAuth(in: $0) }
        case .object(let members): members.contains { containsOTPAuth($0.key) || containsOTPAuth(in: $0.value) }
        default: false
        }
    }

    /// A URL-looking string: a scheme (`word:` followed by `//` or a non-space), `www.`, or a dotted host-like word ending in letters.
    public static func looksLikeURL(_ text: String) -> Bool {
        let lower = text.lowercased()
        if lower.contains("://") || lower.contains("www.") { return true }
        return lower.range(of: #"(^|[\s(<])[a-z][a-z0-9+.\-]{1,15}:[^\s]"#, options: .regularExpression) != nil
            || lower.range(of: #"[a-z0-9\-]+\.[a-z]{2,}"#, options: .regularExpression) != nil
    }

    public static func looksLikeEmail(_ text: String) -> Bool {
        text.range(of: #"[^\s@]+@[^\s@]+"#, options: .regularExpression) != nil
    }

    /// Seven or more digits in a run that allows the usual separators.
    public static func looksLikePhoneNumber(_ text: String) -> Bool {
        text.range(of: #"\+?\d[\d\s().\-]{5,}\d"#, options: .regularExpression) != nil
    }

    /// Validates one displayed variable. Treated as personal data: NFC, no hidden characters, no URL, e-mail address or phone number.
    public static func validateVariable(key: String, value: String) -> AuthDeliveryValidationIssue? {
        let field = "variables.\(key)"
        guard let limit = maxVariableLength[key] else { return AuthDeliveryValidationIssue(field, "unknown_variable") }
        guard !value.isEmpty, value.count <= limit else { return AuthDeliveryValidationIssue(field, "length") }
        guard Array(value.precomposedStringWithCanonicalMapping.unicodeScalars) == Array(value.unicodeScalars) else { return AuthDeliveryValidationIssue(field, "not_nfc") }
        guard !hasHiddenOrControlCharacters(value) else { return AuthDeliveryValidationIssue(field, "hidden_characters") }
        guard !looksLikeURL(value), !looksLikeEmail(value), !looksLikePhoneNumber(value) else { return AuthDeliveryValidationIssue(field, "contact_or_link_like") }
        return nil
    }

    // MARK: Request

    /// Everything about a decoded create request that does not need the database. `nil` = valid.
    public static func validate(_ request: AuthDeliveryCreateRequest) -> AuthDeliveryValidationIssue? {
        guard isValidIdentifier(request.requestId) else { return AuthDeliveryValidationIssue("request_id", "invalid") }
        if let correlation = request.correlationId, !isValidIdentifier(correlation) { return AuthDeliveryValidationIssue("correlation_id", "invalid") }
        if let ref = request.clientTransactionRef, !isValidIdentifier(ref) { return AuthDeliveryValidationIssue("client_transaction_ref", "invalid") }
        guard let template = AuthDeliveryTemplate.template(request.template), template.method == request.method else {
            return AuthDeliveryValidationIssue("template", "unknown_or_wrong_method")
        }
        guard template.purposes.contains(request.purpose) else { return AuthDeliveryValidationIssue("purpose", "not_allowed_for_template") }
        for (key, value) in (request.variables ?? [:]).sorted(by: { $0.key < $1.key }) {
            guard template.variableKeys.contains(key) else { return AuthDeliveryValidationIssue("variables.\(key)", "unknown_variable") }
            if let issue = validateVariable(key: key, value: value) { return issue }
        }
        if let seconds = request.expiresInSeconds, !AuthDeliveryTemplate.lifetimeBounds(for: request.method).contains(seconds) {
            return AuthDeliveryValidationIssue("expires_in_seconds", "out_of_range")
        }
        switch request.method {
        case .magicLink:
            guard request.destination != nil, request.otp == nil else { return AuthDeliveryValidationIssue("destination", "required") }
        case .otp:
            guard let otp = request.otp, request.destination == nil else { return AuthDeliveryValidationIssue("otp", "required") }
            guard isValidCode(otp.code) else { return AuthDeliveryValidationIssue("otp.code", "invalid") }
        case .notice:
            guard request.destination == nil, request.otp == nil else { return AuthDeliveryValidationIssue("destination", "not_allowed") }
        }
        if let channels = request.channels {
            guard !channels.isEmpty, Set(channels).count == channels.count else { return AuthDeliveryValidationIssue("channels", "invalid") }
        }
        return nil
    }

    // MARK: Strict decoding

    /// The result of reading a create body.
    public enum DecodeResult: Sendable {
        case request(AuthDeliveryCreateRequest)
        case invalid(AuthDeliveryValidationIssue)
    }

    /// Reads a create body: at most 16 KiB; valid JSON without duplicate object members; no `otpauth` anywhere (any field, any case, once-percent-decoded);
    /// no member the contract does not define (`tenant_id` and `audience` included); then `validate`.
    public static func decodeCreate(_ body: Data) -> DecodeResult {
        guard !body.isEmpty, body.count <= AuthDeliveryCreateRequest.maxBytes else { return .invalid(AuthDeliveryValidationIssue("body", "size")) }
        guard !JSONDuplicateMemberScan.hasDuplicateMembers(body) else { return .invalid(AuthDeliveryValidationIssue("body", "duplicate_member")) }
        guard let tree = JSONValue.parseContract(body), case .object(let members) = tree else { return .invalid(AuthDeliveryValidationIssue("body", "not_an_object")) }
        if containsOTPAuth(in: tree) { return .invalid(AuthDeliveryValidationIssue("body", "otpauth_refused")) }
        for key in members.keys.sorted() where !AuthDeliveryCreateRequest.memberNames.contains(key) {
            return .invalid(AuthDeliveryValidationIssue(key, "unknown_member"))
        }
        guard let request = try? ViadereJSON.decode(AuthDeliveryCreateRequest.self, from: body) else { return .invalid(AuthDeliveryValidationIssue("body", "malformed")) }
        if let issue = validate(request) { return .invalid(issue) }
        return .request(request)
    }
}

/// Detects an object that names the same member twice (JSON parsers keep the last one silently, which lets two readers disagree about a request).
public enum JSONDuplicateMemberScan {
    public static func hasDuplicateMembers(_ data: Data) -> Bool {
        var scanner = Walker(bytes: Array(data))
        return scanner.value()
    }

    private struct Walker {
        let bytes: [UInt8]
        var index = 0
        init(bytes: [UInt8]) { self.bytes = bytes }

        mutating func skipSpace() { while index < bytes.count, [0x20, 0x09, 0x0A, 0x0D].contains(bytes[index]) { index += 1 } }

        /// Returns `true` as soon as a duplicate is found. Malformed input simply stops the scan (the parser refuses it separately).
        mutating func value() -> Bool {
            skipSpace()
            guard index < bytes.count else { return false }
            switch bytes[index] {
            case UInt8(ascii: "{"): return object()
            case UInt8(ascii: "["): return array()
            case UInt8(ascii: "\""): _ = string(); return false
            default:
                while index < bytes.count, ![0x2C, 0x7D, 0x5D, 0x20, 0x09, 0x0A, 0x0D].contains(bytes[index]) { index += 1 }
                return false
            }
        }

        mutating func string() -> String {
            var out = [UInt8]()
            index += 1
            while index < bytes.count, bytes[index] != UInt8(ascii: "\"") {
                if bytes[index] == UInt8(ascii: "\\"), index + 1 < bytes.count {
                    out.append(bytes[index]); index += 1
                }
                out.append(bytes[index]); index += 1
            }
            index += 1
            return String(decoding: out, as: UTF8.self)
        }

        mutating func object() -> Bool {
            index += 1
            var seen = Set<String>()
            while true {
                skipSpace()
                guard index < bytes.count else { return false }
                if bytes[index] == UInt8(ascii: "}") { index += 1; return false }
                if bytes[index] == UInt8(ascii: ",") { index += 1; continue }
                guard bytes[index] == UInt8(ascii: "\"") else { return false }
                let key = string()
                if !seen.insert(key).inserted { return true }
                skipSpace()
                guard index < bytes.count, bytes[index] == UInt8(ascii: ":") else { return false }
                index += 1
                if value() { return true }
            }
        }

        mutating func array() -> Bool {
            index += 1
            while true {
                skipSpace()
                guard index < bytes.count else { return false }
                if bytes[index] == UInt8(ascii: "]") { index += 1; return false }
                if bytes[index] == UInt8(ascii: ",") { index += 1; continue }
                if value() { return true }
            }
        }
    }
}
