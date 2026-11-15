import Fluent
import Foundation
import SQLKit
import ViadereCore

/// **Email fallback for one-time codes (ADR-0020 section 7, UX_COPY C-OTP-01/-03, SECURITY §2.101 "Email fallback").**
///
/// What the specification allows, and nothing more:
/// - only behind `AUTH_EMAIL_FALLBACK_ENABLED` (default off; refused in staging and production until the owner records the email provider's storage
///   location and retention, ledger L-8) **and** the tenant policy `allow_email_fallback` (default off, set by an Owner or Security Admin);
/// - only for `otp` deliveries (`magic_link` by email is not built: the email would carry a link);
/// - only when the business asks for it on this request (`channels` contains `email` **and** `fallback.email.address` is present; one without the other
///   is `422`). There is no automatic fallback: Viadere never decides on its own to email a code;
/// - the address is the business's (the consumer account holds no address, ADR-0020 section 7). It must be one plain mailbox (`AuthEmailAddress`);
/// - the email is Viadere's fixed template with the business's verified name, the code and the expiry; **no link, no business text**;
/// - the delivery lives at most 15 minutes;
/// - budgets per tenant, per (tenant, customer) and per address (keyed hash), fail closed: over any of them, or while the delivery is silent, no email
///   is sent and the address is not stored. The delivery itself is still created and openable in the app (budgets limit alerting, not availability);
/// - the address is sealed with the code (`auth_delivery_secrets`, P class) and removed by a compare-and-swap **before** the send, so a redelivered
///   dispatch message cannot send a second email; the code stays for the app until it is opened or the delivery ends;
/// - audit and events carry ids, the channel and `assurance: email`; never the code, the address or its domain.
enum AuthEmailFallback {
    static let auditUsed = "auth_delivery.fallback_used"
    static let auditSuppressed = "auth_delivery.fallback_suppressed"
    static let auditFailed = "auth_delivery.fallback_failed"
    static let eventReason = "fallback_used:email"
    static let emailKind = "auth-otp-email"

    /// The checks of the create request that do not depend on the customer. Returns the normalized address when email is requested and allowed.
    static func validateRequest(_ request: AuthDeliveryCreateRequest, channels: [AuthDeliveryChannel], lifetime: Int, settings: AuthDeliverySettings,
                                tenantAllows: () async throws -> Bool) async throws -> String? {
        let wantsEmail = channels.contains(.email)
        guard wantsEmail || request.fallback != nil else { return nil }
        // The gate first: while it is off nothing about email is evaluated (the answer is the same as before the feature existed).
        guard settings.emailFallbackEnabled else {
            throw APIError.validation("Email delivery is not available.", details: [request.fallback == nil ? "channels" : "fallback": "email_unavailable"])
        }
        guard request.method == .otp else { throw APIError.validation("Email fallback is only for one-time codes.", details: ["channels": "email_otp_only"]) }
        guard wantsEmail, let raw = request.fallback?.email?.address else {
            throw APIError.validation("channels must contain email together with fallback.email.address.", details: [wantsEmail ? "fallback.email.address" : "channels": "email_incomplete"])
        }
        guard let address = AuthEmailAddress.normalized(raw) else {
            throw APIError.validation("fallback.email.address is not a single plain email address.", details: ["fallback.email.address": "invalid"])
        }
        guard lifetime <= AuthDeliverySettings.maxEmailLifetime else {
            throw APIError.validation("A code sent by email lives at most 15 minutes.", details: ["expires_in_seconds": "email_lifetime"])
        }
        guard try await tenantAllows() else {
            throw APIError.validation("Email fallback is off for your organization (Security, Email fallback).", details: ["channels": "email_not_allowed"])
        }
        return address
    }

    /// The fail-closed budgets (namespaces `authdl-email-*`). All are consulted, so a request over one budget still counts toward the others.
    static func withinBudget(ctx: ServerContext, settings: AuthDeliverySettings, businessId: BusinessID, consumerId: UUID, address: String) async -> Bool {
        let tenant = businessId.description
        let subject = "\(tenant)|\(consumerId.uuidString.lowercased())"
        let recipient = ctx.hasher.hmacHex("auth-email-address", address)
        let checks = [
            await ctx.limiter.allow("authdl-email-tenant", key: tenant, rule: settings.emailTenantRate),
            await ctx.limiter.allow("authdl-email-subject", key: subject, rule: settings.emailSubjectRate),
            await ctx.limiter.allow("authdl-email-subject-day", key: subject, rule: settings.emailSubjectDailyRate),
            await ctx.limiter.allow("authdl-email-address", key: recipient, rule: settings.emailAddressRate),
        ]
        return !checks.contains(false)
    }

    /// The email: UX_COPY C-OTP-01 (title, the code, lines 1 and 2, the expiry) and the C-OTP-03 footnote. Plain text, no link, no business text
    /// beyond the verified name.
    static func message(to address: String, business: String, code: String, expiresAt: Date) -> EmailMessage {
        let name = AuthEmailAddress.plainLine(business)
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        let parts = calendar.dateComponents([.year, .month, .day, .hour, .minute], from: expiresAt)
        let time = String(format: "%02d:%02d UTC on %04d-%02d-%02d", parts.hour ?? 0, parts.minute ?? 0, parts.year ?? 0, parts.month ?? 0, parts.day ?? 0)
        let text = """
        Your \(name) code

        \(code)

        Use it only on \(name).
        Never share this code. \(name) will never ask you for it by phone, text or email.
        Expires at \(time)

        \(name) sent this code by email because you asked for it there. Email is easier to intercept than the Viadere app.
        """
        return EmailMessage(to: address, subject: "Your \(name) code", text: text, kind: emailKind, sensitive: true)
    }

    /// Sends the email of a queued delivery at most once. The address is removed from the sealed secret by a compare-and-swap before the provider is
    /// called: the winner sends, a concurrent or redelivered dispatch finds no address. Returns whether the provider accepted it.
    static func dispatch(_ row: AuthDeliveryRecord, db: any Database, ctx: ServerContext) async throws -> Bool {
        let settings = ctx.config.authDelivery
        guard settings.emailFallbackEnabled, let id = row.id, let secret = try await AuthDeliverySecretRecord.find(id, on: db),
              let data = try? settings.cipher.open(secret.ciphertext, context: AuthDeliverySecretRecord.sealContext, rowId: id),
              var payload = try? ViadereJSON.decode(AuthSecretPayload.self, from: data), let address = payload.emailAddress, let code = payload.code else { return false }
        payload.emailAddress = nil
        let resealed = try settings.cipher.seal(try ViadereJSON.encode(payload), context: AuthDeliverySecretRecord.sealContext, rowId: id)
        guard let sql = db as? any SQLDatabase else { throw APIError.internalError }
        let claimed = try await sql.update(AuthDeliverySecretRecord.schema).set("ciphertext", to: resealed)
            .where("delivery_id", .equal, id).where("ciphertext", .equal, secret.ciphertext).returning("delivery_id").all()
        guard claimed.count == 1 else { return false }
        // The tenant policy is read again at send time: turning it off stops emails that are still queued.
        let policy = try await BusinessSecuritySettingsRecord.query(on: db).filter(\.$businessId == row.businessId).first()
        let audit = AuditService(db: db, ctx: ctx)
        func record(_ action: String, _ outcome: AuditEvent.Outcome, _ metadata: [String: String]) async {
            _ = try? await audit.record(action, outcome: outcome, actor: AuditActor(kind: .system), consumerId: ConsumerID(row.consumerId), businessId: BusinessID(row.businessId),
                                        subjectType: "auth_delivery", subjectId: row.wireId.description, metadata: metadata.merging(["channel": "email", "method": row.method]) { a, _ in a })
        }
        guard policy?.allowEmailFallback == true, row.expiresAt > ctx.now,
              let business = try await BusinessRecord.find(row.businessId, on: db) else {
            await record(auditSuppressed, .denied, ["reason": "not_allowed"])
            return false
        }
        do {
            try await ctx.email.send(message(to: address, business: business.displayName, code: code, expiresAt: row.expiresAt))
        } catch {
            await record(auditFailed, .failure, ["reason": "provider"])
            return false
        }
        await record(auditUsed, .success, ["assurance": "email"])
        return true
    }
}

/// One plain mailbox, as a business may supply it for a fallback email. Deliberately narrower than RFC 5322: ASCII only, a dot-atom local part of
/// `[A-Za-z0-9._%+-]` (no quoted strings, comments, display names, spaces or line breaks, so nothing can add a header or a second recipient), a DNS
/// domain of at least two labels with an alphabetic top-level label, never an IP literal or a reserved name.
enum AuthEmailAddress {
    static func normalized(_ raw: String) -> String? {
        guard raw.utf8.count <= 254, raw.unicodeScalars.allSatisfy({ $0.isASCII }) else { return nil }
        let parts = raw.split(separator: "@", omittingEmptySubsequences: false)
        guard parts.count == 2 else { return nil }
        let local = String(parts[0])
        let domain = parts[1].lowercased()
        let localAllowed = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._%+-")
        guard (1...64).contains(local.count), local.allSatisfy(localAllowed.contains), !local.hasPrefix("."), !local.hasSuffix("."), !local.contains("..") else { return nil }
        let labels = domain.split(separator: ".", omittingEmptySubsequences: false)
        let labelAllowed = Set("abcdefghijklmnopqrstuvwxyz0123456789-")
        guard labels.count >= 2, labels.allSatisfy({ (1...63).contains($0.count) && $0.allSatisfy(labelAllowed.contains) && !$0.hasPrefix("-") && !$0.hasSuffix("-") }),
              let top = labels.last, top.count >= 2, top.allSatisfy({ $0.isLetter }) else { return nil }
        guard !DomainControl.reservedSuffixes.contains(where: { ("." + domain).hasSuffix($0) }) else { return nil }
        return local + "@" + domain
    }

    /// A display string safe for one line of a plain-text email and its subject: control and format characters removed, at most 120 characters.
    static func plainLine(_ text: String) -> String {
        String(String(text.unicodeScalars.filter { scalar in
            switch scalar.properties.generalCategory {
            case .control, .format, .lineSeparator, .paragraphSeparator: false
            default: true
            }
        }).prefix(120))
    }
}
