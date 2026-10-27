import AsyncHTTPClient
import Fluent
import Foundation
import NIOCore
import Vapor
import ViadereCore

/// Looks at the outside world on behalf of domain verification. Replaceable in tests; the network implementation is `NetworkDomainChecker`.
protocol DomainChecker: Sendable {
    /// The TXT strings published at `name`. Throws when the resolver cannot answer (so "no record" and "could not look" stay different).
    func txtRecords(name: String) async throws -> [String]
    /// The first 4 KiB of `https://<domain>/.well-known/viadere-verification.txt`, or `nil` when the file is not there (non-200, redirect).
    func wellKnown(domain: String) async throws -> String?
}

enum DomainCheckError: Error { case unavailable }

/// Used when nothing is configured (an unconfigured deployment cannot verify domains; it never silently succeeds).
struct UnconfiguredDomainChecker: DomainChecker {
    func txtRecords(name: String) async throws -> [String] { throw DomainCheckError.unavailable }
    func wellKnown(domain: String) async throws -> String? { throw DomainCheckError.unavailable }
}

/// DNS TXT lookups over DNS-over-HTTPS to a fixed resolver (Cloudflare, a listed sub-processor; DNSSEC-validating) and a well-known file
/// fetched with the webhook SSRF defences: https only, no redirects, DNS resolved once and every address vetted before connecting, the
/// connection pinned to the vetted address, a 4 KiB body cap and short timeouts.
struct NetworkDomainChecker: DomainChecker {
    let client: any Client
    let allowInsecure: Bool
    static let resolverURL = "https://cloudflare-dns.com/dns-query"

    private struct DoHAnswer: Decodable {
        struct Record: Decodable {
            var type: Int
            var data: String
        }
        var Status: Int
        var Answer: [Record]?
    }

    func txtRecords(name: String) async throws -> [String] {
        guard DomainControl.isValidHostname(name) || name.hasPrefix("_") else { throw DomainCheckError.unavailable }
        var uri = URI(string: Self.resolverURL)
        uri.query = "name=\(name)&type=TXT"
        let response = try await client.get(uri, headers: ["Accept": "application/dns-json"])
        guard response.status == .ok, var body = response.body, body.readableBytes <= 64 * 1024,
              let bytes = body.readBytes(length: body.readableBytes) else { throw DomainCheckError.unavailable }
        let answer = try JSONDecoder().decode(DoHAnswer.self, from: Data(bytes))
        // NXDOMAIN (3) is a definite "no such record"; anything else but NOERROR (0) is a resolver problem.
        guard answer.Status == 0 || answer.Status == 3 else { throw DomainCheckError.unavailable }
        return (answer.Answer ?? []).filter { $0.type == 16 }.map { Self.unquote($0.data) }
    }

    /// `"abc" "def"` -> `abcdef` (TXT strings longer than 255 bytes arrive split).
    static func unquote(_ data: String) -> String {
        var out = ""
        var inside = false
        var escaped = false
        for character in data {
            if escaped { out.append(character); escaped = false; continue }
            if character == "\\" && inside { escaped = true; continue }
            if character == "\"" { inside.toggle(); continue }
            if inside { out.append(character) }
        }
        return out.isEmpty ? data : out
    }

    func wellKnown(domain: String) async throws -> String? {
        guard DomainControl.isValidHostname(domain), let url = URL(string: "https://\(domain)/.well-known/viadere-verification.txt"),
              WebhookURLPolicy.validate(url, allowInsecure: false), let host = url.host else { return nil }
        let addresses = try await VaporWebhookTransport.resolve(host: host, port: 443)
        guard !addresses.isEmpty, addresses.allSatisfy(WebhookURLPolicy.isPublic), let pinned = addresses.first?.ipAddress else { return nil }
        var configuration = HTTPClient.Configuration()
        configuration.redirectConfiguration = .disallow
        configuration.timeout = .init(connect: .seconds(5), read: .seconds(10))
        configuration.dnsOverride = [host: pinned]
        let pinnedClient = HTTPClient(eventLoopGroupProvider: .singleton, configuration: configuration)
        do {
            var request = HTTPClientRequest(url: url.absoluteString)
            request.method = .GET
            request.headers.add(name: "User-Agent", value: "Viadere-DomainVerification/1")
            let response = try await pinnedClient.execute(request, timeout: .seconds(15))
            defer { Task { try? await pinnedClient.shutdown() } }
            guard response.status == .ok else { return nil }
            var body = try await response.body.collect(upTo: 4096)
            return body.readString(length: body.readableBytes)
        } catch {
            try? await pinnedClient.shutdown()
            return nil
        }
    }
}

/// Domain verification (spec §8.1 step 2). The business publishes `viadere-verify=<token>` as a TXT record at `_viadere-verify.<domain>` (or
/// serves it at the well-known path); a check passes only if the token appears. The token is random per business and domain, so proving
/// control of one domain says nothing about another, and a verified domain belongs to exactly one tenant (unique index).
struct DomainControl {
    let db: any Database
    let ctx: ServerContext

    static let maxDomains = 5
    static let recordPrefix = "_viadere-verify."
    static let valuePrefix = "viadere-verify="
    static let wellKnownPath = "/.well-known/viadere-verification.txt"
    /// Names that can never be a business's domain.
    static let reservedSuffixes = [".local", ".localhost", ".internal", ".lan", ".home.arpa", ".test", ".invalid", ".example", ".onion", ".arpa"]

    static func recordName(for domain: String) -> String { recordPrefix + domain }
    static func expectedValue(token: String) -> String { valuePrefix + token }

    /// `https://Example.COM/path` -> `example.com`; `nil` when it is not a plain DNS name (IP literals, ports, userinfo, single labels, reserved suffixes).
    static func normalize(_ raw: String) -> String? {
        var text = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        for scheme in ["https://", "http://"] where text.hasPrefix(scheme) { text.removeFirst(scheme.count) }
        if let slash = text.firstIndex(where: { $0 == "/" || $0 == "?" || $0 == "#" }) { text = String(text[text.startIndex..<slash]) }
        if text.hasSuffix(".") { text.removeLast() }
        if text.hasPrefix("www.") && text.split(separator: ".").count > 2 { text.removeFirst(4) }
        guard isValidHostname(text) else { return nil }
        return text
    }

    static func isValidHostname(_ text: String) -> Bool {
        guard (4...253).contains(text.count), text == text.lowercased() else { return false }
        let labels = text.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2, labels.allSatisfy({ (1...63).contains($0.count) }) else { return false }
        for label in labels {
            guard label.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }), !label.hasPrefix("-"), !label.hasSuffix("-") else { return false }
        }
        guard let tld = labels.last, tld.count >= 2, tld.allSatisfy({ $0.isLetter }) || tld.hasPrefix("xn--") else { return false }
        return !reservedSuffixes.contains { text.hasSuffix($0) }
    }

    // MARK: Management

    func domains(businessId: UUID) async throws -> [BusinessDomainRecord] {
        try await BusinessDomainRecord.query(on: db).filter(\.$businessId == businessId).sort(\.$createdAt, .ascending).all()
    }

    func add(businessId: UUID, domain raw: String, by userId: UUID) async throws -> BusinessDomainRecord {
        guard let domain = Self.normalize(raw) else {
            throw APIError.validation("Enter a domain name such as example.com.", details: ["domain": "invalid"])
        }
        if let existing = try await BusinessDomainRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$domain == domain).first() { return existing }
        guard try await BusinessDomainRecord.query(on: db).filter(\.$businessId == businessId).count() < Self.maxDomains else {
            throw APIError.conflict("Remove a domain before adding another.")
        }
        let record = BusinessDomainRecord()
        record.id = UUID()
        record.businessId = businessId
        record.domain = domain
        record.token = SecureToken.generate(byteCount: 24)
        record.status = "pending"
        record.createdBy = userId.uuidString.lowercased()
        record.createdAt = ctx.now
        record.failures = 0
        try await record.create(on: db)
        _ = try await AuditService(db: db, ctx: ctx).record("domain.added", actor: AuditActor(kind: .business, id: userId.uuidString.lowercased()),
            businessId: BusinessID(businessId), subjectType: "domain", subjectId: domain)
        return record
    }

    func remove(businessId: UUID, id: UUID, by userId: UUID) async throws {
        guard let record = try await BusinessDomainRecord.query(on: db).filter(\.$id == id).filter(\.$businessId == businessId).first() else { throw APIError.notFound }
        let onboarding = try await BusinessOnboardingRecord.query(on: db).filter(\.$businessId == businessId).first()
        // The domain that established control cannot be removed while it is the only proof; add and verify another first.
        if record.status == "verified" || record.verifiedDomain != nil,
           try await BusinessDomainRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$id != id).filter(\.$verifiedDomain != nil).count() == 0,
           onboarding?.controlDomain == record.domain {
            throw APIError.conflict("Verify another domain before removing the one that proves control.")
        }
        try await record.delete(on: db)
        _ = try await AuditService(db: db, ctx: ctx).record("domain.removed", actor: AuditActor(kind: .business, id: userId.uuidString.lowercased()),
            businessId: BusinessID(businessId), subjectType: "domain", subjectId: record.domain)
    }

    // MARK: Verification

    enum Outcome: Equatable {
        case verified(method: String)
        /// The token was not found (DNS or file).
        case notFound
        /// The resolver or the site could not be reached.
        case unavailable
        /// Someone else already holds this domain.
        case claimedElsewhere
    }

    /// Looks for the token (DNS first, then the file). Pure: writes nothing.
    func probe(_ record: BusinessDomainRecord) async -> Outcome {
        let expected = Self.expectedValue(token: record.token)
        var unreachable = false
        do {
            let texts = try await ctx.domains.txtRecords(name: Self.recordName(for: record.domain))
            if texts.contains(where: { ConstantTime.equals($0.trimmingCharacters(in: .whitespaces), expected) }) { return .verified(method: "dns") }
        } catch { unreachable = true }
        do {
            if let body = try await ctx.domains.wellKnown(domain: record.domain),
               ConstantTime.equals(body.trimmingCharacters(in: .whitespacesAndNewlines), expected) { return .verified(method: "wellknown") }
        } catch { unreachable = true }
        return unreachable ? .unavailable : .notFound
    }

    /// The business's "Check now". Rate-limited per domain.
    @discardableResult
    func check(businessId: UUID, id: UUID, by userId: UUID?) async throws -> Outcome {
        guard let record = try await BusinessDomainRecord.query(on: db).filter(\.$id == id).filter(\.$businessId == businessId).first() else { throw APIError.notFound }
        guard await ctx.limiter.allow("domain-check", key: id.uuidString.lowercased(), rule: .perHour(12, burst: 6)) else {
            throw APIError.rateLimited(retryAfter: 600)
        }
        let outcome = await probe(record)
        let now = ctx.now
        record.lastCheckedAt = now
        switch outcome {
        case .verified(let method):
            record.status = "verified"
            record.method = method
            record.verifiedAt = record.verifiedAt ?? now
            record.nextCheckAt = now.addingTimeInterval(ctx.config.operations.domainRecheckInterval)
            record.failures = 0
            record.lastError = nil
            record.verifiedDomain = record.domain
            do { try await record.update(on: db) } catch {
                guard error.isConstraintViolation else { throw error }
                // Another tenant verified this domain first (the unique index decides a race).
                record.verifiedDomain = nil
                record.status = "pending"
                record.lastError = "claimed_elsewhere"
                try await record.update(on: db)
                return .claimedElsewhere
            }
            try await OnboardingService(db: db, ctx: ctx).domainVerified(businessId: businessId, domain: record.domain, method: method)
            _ = try await AuditService(db: db, ctx: ctx).record("domain.verified", actor: AuditActor(kind: userId == nil ? .system : .business, id: userId?.uuidString.lowercased()),
                businessId: BusinessID(businessId), subjectType: "domain", subjectId: record.domain, metadata: ["method": method])
        case .notFound, .unavailable:
            record.failures += 1
            record.lastError = outcome == .notFound ? "token_not_found" : "lookup_failed"
            if record.status == "verified" { record.status = "failed" }
            try await record.update(on: db)
        case .claimedElsewhere: break
        }
        return outcome
    }
}
