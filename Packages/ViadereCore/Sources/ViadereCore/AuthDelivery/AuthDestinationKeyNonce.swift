import Foundation

/// `POST /v1/business/destination-keys/registration-nonce` (ADR-0031 §1.2 rule (a), SECURITY.md §2.110 "Registration"): the business reads the nonce
/// the authority admin job issued for one of **its own** destination keys, so it can sign `viadere-destination-key-registration+jws` with that key.
/// The tenant is the authenticated API key's business, never a member of the request. The nonce is not a secret (the proof of possession and the
/// attested domain evidence are what count) and reading it consumes nothing; the job's registration consumes it once.
public struct AuthDestinationKeyNonceRequest: Codable, Sendable, Hashable {
    /// The key's RFC 7638 thumbprint (43 base64url characters), as named in the reviewed registration change.
    public var kid: String

    public init(kid: String) { self.kid = kid }

    enum CodingKeys: String, CodingKey { case kid }

    public init(from decoder: any Decoder) throws {
        try requireOnly(decoder, ["kid"])
        kid = try decoder.container(keyedBy: CodingKeys.self).decode(String.self, forKey: .kid)
    }

    public var isWellFormed: Bool { Base64URL.isValid(kid, minLength: 43, maxLength: 43) && Base64URL.decode(kid)?.count == 32 }
}

/// Exactly what the registration proof needs (`DestinationKeyRegistration.sign`): `iss` = `tenant_id`, `aud`, `kid`, `hosts[]` and the `nonce`, plus
/// when the nonce stops being accepted. Nothing else about the tenant, its other keys or the registration change.
public struct AuthDestinationKeyNonceResponse: Codable, Sendable, Hashable {
    public var tenantId: String
    public var aud: String
    public var kid: String
    public var hosts: [String]
    public var nonce: String
    public var expiresAt: Int64

    public init(tenantId: String, aud: String, kid: String, hosts: [String], nonce: String, expiresAt: Int64) {
        self.tenantId = tenantId
        self.aud = aud
        self.kid = kid
        self.hosts = hosts
        self.nonce = nonce
        self.expiresAt = expiresAt
    }

    enum CodingKeys: String, CodingKey { case tenantId = "tenant_id", aud, kid, hosts, nonce, expiresAt = "expires_at" }
}

extension APIRoutes {
    /// Scope `auth_deliveries:write`, **live keys only**. `404` while `AUTH_DELIVERY_ENABLED` or `AUTH_DESTINATION_RECORDS_ENABLED` is off, when the
    /// authority's `AUTHORITY_TENANT_KEYS_ENABLED` is off, and when no unconsumed, unexpired nonce exists for this tenant and key (one body for all);
    /// `503` without an authority. Rate-limited per tenant (fail closed) and audited.
    public static let businessDestinationKeyNonce = Endpoint<AuthDestinationKeyNonceRequest, AuthDestinationKeyNonceResponse>(
        "business.destinationKeys.registrationNonce", .POST, "/v1/business/destination-keys/registration-nonce", auth: .businessAPIKey)
}
