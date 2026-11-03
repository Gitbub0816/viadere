import Foundation

/// `POST /v1/business/auth-links/redeem` (ADR-0021 §5.4, §6): the business backend exchanges the link code (same device, from the `#vdr_code=` fragment)
/// or, for a cross-device sign-in, the challenge reference, together with its PKCE `code_verifier`, for the authority's `viadere-grant+jwt`.
/// Exactly one of `code` and `ach`. Behind `AUTH_LINK_SERVICE_ENABLED` (default off).
public struct AuthLinkRedeemRequest: Codable, Sendable, Hashable {
    public var linkClientId: String
    public var code: String?
    public var ach: String?
    public var codeVerifier: String

    public init(linkClientId: String, code: String? = nil, ach: String? = nil, codeVerifier: String) {
        self.linkClientId = linkClientId
        self.code = code
        self.ach = ach
        self.codeVerifier = codeVerifier
    }

    enum CodingKeys: String, CodingKey { case linkClientId = "link_client_id", code, ach, codeVerifier = "code_verifier" }

    private struct AnyKey: CodingKey {
        var stringValue: String
        var intValue: Int? { nil }
        init?(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { nil }
    }

    public init(from decoder: any Decoder) throws {
        let keys = Set(try decoder.container(keyedBy: AnyKey.self).allKeys.map(\.stringValue))
        guard keys.isSubset(of: ["link_client_id", "code", "ach", "code_verifier"]) else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "unknown member"))
        }
        let c = try decoder.container(keyedBy: CodingKeys.self)
        linkClientId = try c.decode(String.self, forKey: .linkClientId)
        code = try c.decodeIfPresent(String.self, forKey: .code)
        ach = try c.decodeIfPresent(String.self, forKey: .ach)
        codeVerifier = try c.decode(String.self, forKey: .codeVerifier)
        guard (code == nil) != (ach == nil) else { throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "code or ach")) }
    }

    /// Field-level check before anything is relayed.
    public var isWellFormed: Bool {
        linkClientId.hasPrefix("lcl_") && linkClientId.count <= 64 && OIDCProfile.isValidCodeVerifier(codeVerifier)
            && (code.map { Base64URL.isValid($0, minLength: 43, maxLength: 43) } ?? true) && (ach.map(AuthorityChallengeID.isValid) ?? true)
    }
}

public struct AuthLinkRedeemResponse: Codable, Sendable, Hashable {
    /// The `viadere-grant+jwt` (verify it with `AuthorityGrantVerifier` against the static grant JWKS; consume its `jti` once).
    public var grant: String
    public var deliveryId: String

    public init(grant: String, deliveryId: String) {
        self.grant = grant
        self.deliveryId = deliveryId
    }

    enum CodingKeys: String, CodingKey { case grant, deliveryId = "delivery_id" }
}

extension APIRoutes {
    /// Scope `auth_deliveries:write`. `400 bad_request` (`invalid_grant`) for an unknown, expired, used or foreign code or a wrong verifier.
    public static let businessAuthLinkRedeem = Endpoint<AuthLinkRedeemRequest, AuthLinkRedeemResponse>(
        "business.authLinks.redeem", .POST, "/v1/business/auth-links/redeem", auth: .businessAPIKey)
}
