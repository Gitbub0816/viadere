import Fluent
import Foundation
import SQLKit
import Vapor
import ViadereCore

/// RFC 9421 request signatures for business API calls (SECURITY §2.112, ADR-0020 §3): the registered keys, their console lifecycle and the
/// verification the API-key middleware runs before any handler.
///
/// A request-signing key is a P-256 **public** key a business registers in the console with a proof of possession. It is bound to **one** API
/// key (a rotation moves the binding to the successor, and the predecessor keeps it for its overlap), revocable, and every change is audited and
/// mailed to the Owners. A signed request is verified whatever the route; on the auth routes a live key needs a signature or mutual TLS
/// (`AUTH_LIVE_KEY_ASSURANCE`).
final class BusinessRequestSigningKeyRecord: Model, @unchecked Sendable {
    static let schema = "business_request_signing_keys"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "api_key_id") var apiKeyId: UUID
    /// `vsk_` + 16 lowercase hex, issued by Viadere; the `keyid` signature parameter.
    @Field(key: "keyid") var keyid: String
    /// base64url X9.63 P-256 public key.
    @Field(key: "public_key") var publicKey: String
    /// SHA-256 of the X9.63 bytes (hex): one key belongs to one registration.
    @Field(key: "fingerprint") var fingerprint: String
    @Field(key: "label") var label: String
    @Field(key: "created_by") var createdBy: UUID
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "last_used_at") var lastUsedAt: Date?
    @OptionalField(key: "revoked_at") var revokedAt: Date?
    @OptionalField(key: "revoked_by") var revokedBy: String?

    init() {}
}

/// `RequestSigningKeys.v1` (additive).
struct CreateRequestSigningKeysSchema: AsyncMigration {
    var name: String { "RequestSigningKeys.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema(BusinessRequestSigningKeyRecord.schema).id()
            .field("business_id", .uuid, .required, .references("businesses", "id", onDelete: .cascade))
            .field("api_key_id", .uuid, .required, .references("business_api_keys", "id", onDelete: .cascade))
            .field("keyid", .string, .required)
            .field("public_key", .string, .required)
            .field("fingerprint", .string, .required)
            .field("label", .string, .required)
            .field("created_by", .uuid, .required)
            .field("created_at", .datetime, .required)
            .field("last_used_at", .datetime)
            .field("revoked_at", .datetime)
            .field("revoked_by", .string)
            .unique(on: "keyid")
            .unique(on: "fingerprint")
            .create()
        guard let sql = db as? any SQLDatabase else { return }
        try await sql.raw("CREATE INDEX IF NOT EXISTS idx_request_signing_keys_api_key ON business_request_signing_keys (api_key_id)").run()
    }

    func revert(on db: any Database) async throws {
        try await db.schema(BusinessRequestSigningKeyRecord.schema).delete()
    }
}

/// `REQUEST_SIGNATURE_AUTHORITIES`: the `@authority` values a signature may cover (comma-separated `host[:port]`, lowercase, default port
/// omitted). Default: the authority of `PUBLIC_BASE_URL`. The verifier never reads `Host` (cloudflared rewrites it, SECURITY §2.74).
struct RequestSignatureSettings: Sendable {
    var authorities: [String] = []

    static func parse(_ raw: String) throws -> [String] {
        let items = raw.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        guard !items.isEmpty, items.count <= 8 else { throw ServerConfigError.invalid("REQUEST_SIGNATURE_AUTHORITIES (1 to 8 host[:port] values)") }
        for item in items {
            let parts = item.split(separator: ":", omittingEmptySubsequences: false)
            guard item == item.lowercased(), (1...2).contains(parts.count), !parts[0].isEmpty, parts[0].count <= 253,
                  parts[0].allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == ".") }),
                  parts.count == 1 || (Int(parts[1]).map { (1...65535).contains($0) && $0 != 443 } ?? false) else {
                throw ServerConfigError.invalid("REQUEST_SIGNATURE_AUTHORITIES (lowercase host[:port], default port omitted)")
            }
        }
        return items
    }
}

extension ServerConfig {
    /// The accepted `@authority` values.
    var requestSignatureAuthorities: [String] {
        if !requestSignatures.authorities.isEmpty { return requestSignatures.authorities }
        return URL(string: publicBaseURL).flatMap(HTTPSignatureProfile.authority(of:)).map { [$0] } ?? []
    }
}

struct RequestSigningKeys {
    let db: any Database
    let ctx: ServerContext

    static let maxPerAPIKey = 5
    static let challengeLifetime: TimeInterval = 900

    // MARK: Proof-of-possession challenge

    /// A challenge the console shows: `{issued}.{nonce}.{mac}`, bound to the business, the API key and the person, valid 15 minutes, single use.
    func challenge(businessId: UUID, apiKeyId: UUID, userId: UUID) -> String {
        let issued = Int64(ctx.now.timeIntervalSince1970)
        let nonce = SecureToken.generate(byteCount: 16)
        return "\(issued).\(nonce).\(mac(businessId: businessId, apiKeyId: apiKeyId, userId: userId, issued: issued, nonce: nonce))"
    }

    private func mac(businessId: UUID, apiKeyId: UUID, userId: UUID, issued: Int64, nonce: String) -> String {
        String(ctx.hasher.hmacHex("request-signing-key-pop", [businessId, apiKeyId, userId].map { $0.uuidString.lowercased() }.joined(separator: "|") + "|\(issued)|\(nonce)").prefix(32))
    }

    private func checkChallenge(_ challenge: String, businessId: UUID, apiKeyId: UUID, userId: UUID) async throws {
        let parts = challenge.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 3, let issued = Int64(parts[0]), RequestSignature.isValidNonce(parts[1]),
              ConstantTime.equals(parts[2], mac(businessId: businessId, apiKeyId: apiKeyId, userId: userId, issued: issued, nonce: parts[1])) else {
            throw APIError.validation("The challenge is not valid. Reload the page and sign the new challenge.", details: ["challenge": "invalid"])
        }
        let age = ctx.now.timeIntervalSince1970 - TimeInterval(issued)
        guard age >= -60, age <= Self.challengeLifetime else {
            throw APIError.validation("The challenge expired. Reload the page and sign the new challenge.", details: ["challenge": "expired"])
        }
        guard try await DatabaseReplayGuard(db: db).registerIfFresh(nonce: parts[1], scope: "sigkey-pop:\(businessId.uuidString.lowercased())",
                                                                    expiresAt: ctx.now.addingTimeInterval(Self.challengeLifetime * 2), now: ctx.now) else {
            throw APIError.validation("This challenge was already used. Reload the page and sign the new challenge.", details: ["challenge": "used"])
        }
    }

    // MARK: Lifecycle (the caller checks the role and the fresh passkey step-up)

    func list(businessId: UUID) async throws -> [BusinessRequestSigningKeyRecord] {
        try await BusinessRequestSigningKeyRecord.query(on: db).filter(\.$businessId == businessId).sort(\.$createdAt, .descending).all()
    }

    func add(businessId: UUID, apiKeyId: UUID, label rawLabel: String, publicKey rawKey: String, challenge: String, proof: String, by userId: UUID) async throws -> BusinessRequestSigningKeyRecord {
        let label = rawLabel.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (1...64).contains(label.count), !label.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw APIError.validation("Give the key a label of up to 64 characters.", details: ["label": "invalid"])
        }
        guard let apiKey = try await BusinessAPIKeyRecord.query(on: db).filter(\.$id == apiKeyId).filter(\.$businessId == businessId).first(),
              apiKey.isUsable(at: ctx.now), apiKey.rotatedTo == nil else {
            throw APIError.validation("Choose a working API key of your organization.", details: ["api_key": "invalid"])
        }
        let text = rawKey.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.contains("PRIVATE"), let key = Self.publicKey(text) else {
            throw APIError.validation("Paste the P-256 public key (base64url X9.63 or a PEM public key). Never paste a private key.", details: ["public_key": "invalid"])
        }
        // The challenge first (it is spent even when the proof is wrong, so a proof cannot be ground against one challenge).
        try await checkChallenge(challenge, businessId: businessId, apiKeyId: apiKeyId, userId: userId)
        guard HTTPSigningKeyProof.verify(proof: proof.trimmingCharacters(in: .whitespacesAndNewlines), challenge: challenge, publicKey: key) else {
            throw APIError.validation("The proof does not verify with this public key and challenge.", details: ["proof": "invalid"])
        }
        guard try await BusinessRequestSigningKeyRecord.query(on: db).filter(\.$apiKeyId == apiKeyId).filter(\.$revokedAt == nil).count() < Self.maxPerAPIKey else {
            throw APIError.conflict("Revoke an unused signing key of this API key before adding another.")
        }
        let record = BusinessRequestSigningKeyRecord()
        record.id = UUID()
        record.businessId = businessId
        record.apiKeyId = apiKeyId
        record.keyid = "vsk_" + Hex.encode(SecureToken.randomBytes(8))
        record.publicKey = key.base64URL
        record.fingerprint = key.fingerprint
        record.label = label
        record.createdBy = userId
        record.createdAt = ctx.now
        do { try await record.create(on: db) } catch {
            // A public key belongs to one registration (the unique index spans tenants); the answer does not say whose.
            if error.isConstraintViolation { throw APIError.conflict("That public key is already registered.") }
            throw error
        }
        _ = try await AuditService(db: db, ctx: ctx).record("request_signing_key.added", actor: AuditActor(kind: .business, id: userId.uuidString.lowercased()),
            businessId: BusinessID(businessId), subjectType: "request_signing_key", subjectId: record.keyid,
            metadata: ["api_key_kid": apiKey.kid ?? "legacy", "fingerprint_prefix": String(key.fingerprint.prefix(12)), "label": label])
        await Notifier(db: db, ctx: ctx).notifyBusiness(businessId, roles: [.owner], includeSecurityContacts: true, subject: "A request-signing key was added",
            text: "A team member registered the request-signing key \(record.keyid) (\(label)) for an API key of your organization. Requests signed with it can send live sign-in prompts. If this was not expected, revoke it under Security > Request signing and review your team's sessions.",
            kind: "security-alert")
        return record
    }

    func revoke(businessId: UUID, id: UUID, by actor: String) async throws {
        guard let record = try await BusinessRequestSigningKeyRecord.query(on: db).filter(\.$id == id).filter(\.$businessId == businessId).first() else { throw APIError.notFound }
        guard record.revokedAt == nil else { return }
        try await BusinessRequestSigningKeyRecord.query(on: db).filter(\.$id == id).filter(\.$revokedAt == nil)
            .set(\.$revokedAt, to: ctx.now).set(\.$revokedBy, to: actor).update()
        _ = try await AuditService(db: db, ctx: ctx).record("request_signing_key.revoked", actor: AuditActor(kind: .business, id: actor),
            businessId: BusinessID(businessId), subjectType: "request_signing_key", subjectId: record.keyid)
        await Notifier(db: db, ctx: ctx).notifyBusiness(businessId, roles: [.owner], includeSecurityContacts: false, subject: "A request-signing key was revoked",
            text: "The request-signing key \(record.keyid) (\(record.label)) was revoked. Requests signed with it are refused from now on.", kind: "security-alert")
    }

    /// A rotation moves every active binding of `from` to its successor `to` (the predecessor keeps accepting them during its overlap).
    func moveBindings(from: UUID, to: UUID) async throws {
        try await BusinessRequestSigningKeyRecord.query(on: db).filter(\.$apiKeyId == from).filter(\.$revokedAt == nil).set(\.$apiKeyId, to: to).update()
    }

    static func publicKey(_ text: String) -> DevicePublicKey? {
        if text.hasPrefix("-----BEGIN PUBLIC KEY-----") {
            let body = text.replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "").replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "")
                .components(separatedBy: .whitespacesAndNewlines).joined()
            // SubjectPublicKeyInfo of an uncompressed P-256 point: a fixed 26-byte header, then the 65-byte point.
            let header: [UInt8] = [0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00]
            guard let der = Data(base64Encoded: body), der.count == header.count + 65, Array(der.prefix(header.count)) == header else { return nil }
            return try? DevicePublicKey(bytes: der.suffix(65))
        }
        return try? DevicePublicKey(base64URL: text)
    }

    // MARK: Verification

    /// Verifies the request's signature for the authenticated `key` (SECURITY §2.112 steps 1-9). Returns the `keyid`. Every refusal is a `401`
    /// (`clock_skew` and `replay_detected` named, everything else `signature_invalid`), counted and audited (at most once per key per 5 minutes per reason).
    static func verify(_ request: Request, key: BusinessAPIKeyRecord, ctx: ServerContext, db: any Database) async throws -> String {
        let body = try await request.collectedBody(limit: ctx.config.maxBodyBytes(forPath: request.url.path))
        var fields: [(name: String, value: String)] = []
        for (name, value) in request.headers { fields.append((name: name, value: value)) }
        let input = HTTPSignatureRequest(method: request.method.rawValue, target: request.url.string, fields: fields, body: body)
        let now = ctx.now
        do {
            let parsed = try HTTPSignatureVerifier.parse(input, now: now)
            let record = try await BusinessRequestSigningKeyRecord.query(on: db).filter(\.$keyid == parsed.keyId).first()
            var registered: HTTPSignatureVerifier.RegisteredKey?
            if let record, let publicKey = try? DevicePublicKey(base64URL: record.publicKey) {
                var bound: Set<String> = [record.apiKeyId.uuidString]
                // During a rotation overlap the predecessor key keeps the binding its successor now holds.
                if let keyId = key.id, key.rotatedTo == record.apiKeyId { bound.insert(keyId.uuidString) }
                registered = .init(publicKey: publicKey, businessId: record.businessId.uuidString, apiKeyIds: bound, revoked: record.revokedAt != nil)
            }
            _ = try await HTTPSignatureVerifier.verify(parsed, key: registered, businessId: key.businessId.uuidString, apiKeyId: key.id?.uuidString ?? "",
                                                       authorities: ctx.config.requestSignatureAuthorities, replayGuard: DatabaseReplayGuard(db: db), now: now)
            if let record, record.lastUsedAt == nil || now.timeIntervalSince(record.lastUsedAt ?? now) > 300 {
                try await BusinessRequestSigningKeyRecord.query(on: db).filter(\.$id == record.id!).set(\.$lastUsedAt, to: now).update()
            }
            return parsed.keyId
        } catch let error as HTTPSignatureError {
            ctx.metrics.count(.apiKeySignatureDenied)
            await BusinessAPIKeyMiddleware.auditDenied("apikey.signature_denied", key: key, ctx: ctx, db: db, metadata: ["reason": error.rawValue],
                                                       bucket: error.rawValue)
            if error.isClock { throw APIError(.unauthorized, .clockSkew, "The request signature is outside its time window.") }
            if error == .replayed { throw APIError(.unauthorized, .replayDetected, "This request signature was already used.") }
            // Structural reasons help an integrator; anything about keys or the signature itself is one answer (no probing whose key a keyid is).
            let keyRelated: Set<HTTPSignatureError> = [.unknownKey, .revokedKey, .wrongBusiness, .wrongAPIKey, .badSignature]
            throw APIError(.unauthorized, .signatureInvalid, "The request signature is not valid.", details: keyRelated.contains(error) ? nil : ["reason": error.rawValue])
        }
    }
}
