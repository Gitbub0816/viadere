import Foundation

// The device half of the OIDC app path (ADR-0024 §4 method 2): the Viadere app fetches the authority-signed challenge statement through the api, verifies
// it against its pinned statement keys, shows exactly its display, asks for the number shown on the website, and returns a `viadere-factor+jws` that the
// api relays unchanged to the authority. Behind `OIDC_PROVIDER_ENABLED` (`404` while off).

/// `GET /v1/oidc/challenges/{challengeId}`: the compact `viadere-challenge+jws`, relayed unchanged.
public struct OIDCDeviceChallenge: Codable, Sendable, Hashable {
    public var statement: String
    public init(statement: String) { self.statement = statement }
}

/// `POST /v1/oidc/challenges/{challengeId}/evidence`.
public struct OIDCDeviceEvidenceRequest: Codable, Sendable, Hashable {
    public var factor: String
    public init(factor: String) { self.factor = factor }

    enum CodingKeys: String, CodingKey { case factor }

    public init(from decoder: any Decoder) throws {
        let keys = try decoder.container(keyedBy: AnyCodingKey.self).allKeys.map(\.stringValue)
        guard Set(keys) == ["factor"] else { throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "unknown member")) }
        factor = try decoder.container(keyedBy: CodingKeys.self).decode(String.self, forKey: .factor)
    }

    private struct AnyCodingKey: CodingKey {
        var stringValue: String
        var intValue: Int? { nil }
        init?(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { nil }
    }
}

/// What the authority decided. The app never receives the authorization code: the api hands it only to the browser that started the request.
public struct OIDCDeviceEvidenceResponse: Codable, Sendable, Hashable {
    public var decision: FactorDecision
    public init(decision: FactorDecision) { self.decision = decision }
}

extension APIRoutes {
    public static let oidcChallengeGet = Endpoint<EmptyBody, OIDCDeviceChallenge>(
        "oidc.challenge.get", .GET, "/v1/oidc/challenges/{challengeId}", auth: .deviceSignedBearer)
    public static let oidcChallengeEvidence = Endpoint<OIDCDeviceEvidenceRequest, OIDCDeviceEvidenceResponse>(
        "oidc.challenge.evidence", .POST, "/v1/oidc/challenges/{challengeId}/evidence", auth: .deviceSignedBearer)

    public static let oidcDeviceEndpoints: [AnyEndpoint] = [oidcChallengeGet.descriptor, oidcChallengeEvidence.descriptor]
}
