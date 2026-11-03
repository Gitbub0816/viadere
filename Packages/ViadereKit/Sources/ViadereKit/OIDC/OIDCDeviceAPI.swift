import Crypto
import Foundation
import ViadereCore

// The device half of "Sign in with Viadere" (ADR-0024 §4 method 2, §8): fetch the authority-signed challenge statement through the api, verify it
// against the build-pinned statement keys, sign a `viadere-factor+jws` over its display with the device approval key the authority logged, and list
// or revoke the consents the authority keeps. The api relays every value unchanged; the app never receives the authorization code.

public enum OIDCDeviceError: Error, Sendable, Equatable {
    /// No network or the service could not be reached. Nothing was sent.
    case offline
    /// The challenge is gone (expired, used, cancelled or unknown).
    case notActive
    /// The authority refused the answer (one generic refusal: a wrong number, an unknown key, an expired challenge).
    case refused
    /// OIDC is off for this build or server.
    case unavailable
}

/// The device calls (`APIRoutes.oidcChallengeGet`, `oidcChallengeEvidence`, `oidcConsentsList`, `oidcConsentRevoke`).
public protocol OIDCDeviceAPI: Sendable {
    /// The compact `viadere-challenge+jws`, unchanged.
    func statement(challengeId: String) async throws -> String
    /// The authority's decision for a signed factor. Never a code.
    func submit(challengeId: String, factor: String) async throws -> FactorDecision
    func consents() async throws -> [OIDCConsentView]
    /// Reduce-only.
    func revokeConsent(clientId: String) async throws -> Bool
}

/// The live client over the device-signed `APIClient`.
public struct LiveOIDCDeviceAPI: OIDCDeviceAPI {
    let client: APIClient
    public init(client: APIClient) { self.client = client }

    public func statement(challengeId: String) async throws -> String {
        guard AuthorityChallengeID.isValid(challengeId) else { throw OIDCDeviceError.notActive }
        return try await map { try await client.call(APIRoutes.oidcChallengeGet, params: ["challengeId": challengeId]).statement }
    }

    public func submit(challengeId: String, factor: String) async throws -> FactorDecision {
        guard AuthorityChallengeID.isValid(challengeId) else { throw OIDCDeviceError.notActive }
        return try await map {
            try await client.call(APIRoutes.oidcChallengeEvidence, params: ["challengeId": challengeId], body: OIDCDeviceEvidenceRequest(factor: factor)).decision
        }
    }

    public func consents() async throws -> [OIDCConsentView] {
        try await map { try await client.call(APIRoutes.oidcConsentsList).consents }
    }

    public func revokeConsent(clientId: String) async throws -> Bool {
        guard OIDCClientID.isValid(clientId) else { throw OIDCDeviceError.notActive }
        return try await map { try await client.call(APIRoutes.oidcConsentRevoke, params: ["clientId": clientId]).revoked }
    }

    private func map<T>(_ body: () async throws -> T) async throws -> T {
        do { return try await body() } catch let error as APIError {
            if case .transport = error { throw OIDCDeviceError.offline }
            switch error.code {
            case .notFound?: throw OIDCDeviceError.notActive
            case .forbidden?: throw OIDCDeviceError.refused
            case .unavailable?: throw OIDCDeviceError.unavailable
            default: throw OIDCDeviceError.refused
            }
        } catch { throw OIDCDeviceError.offline }
    }
}

/// The default where the build has no client (App Clip, extensions): every call fails closed.
public struct UnavailableOIDCDeviceAPI: OIDCDeviceAPI {
    public init() {}
    public func statement(challengeId: String) async throws -> String { throw OIDCDeviceError.unavailable }
    public func submit(challengeId: String, factor: String) async throws -> FactorDecision { throw OIDCDeviceError.unavailable }
    public func consents() async throws -> [OIDCConsentView] { throw OIDCDeviceError.unavailable }
    public func revokeConsent(clientId: String) async throws -> Bool { throw OIDCDeviceError.unavailable }
}

/// A recording fake for tests and previews.
public actor MockOIDCDeviceAPI: OIDCDeviceAPI {
    public var statements: [String: String] = [:]
    public var decision: FactorDecision = .approve
    public var refuse = false
    public var submitError: OIDCDeviceError?
    public private(set) var submitted: [(challengeId: String, factor: String)] = []
    public var consentList: [OIDCConsentView] = []
    public private(set) var revoked: [String] = []

    public init() {}

    public func set(statement: String, for challengeId: String) { statements[challengeId] = statement }
    public func set(consents: [OIDCConsentView]) { consentList = consents }
    public func set(submitError: OIDCDeviceError?) { self.submitError = submitError }

    public func statement(challengeId: String) async throws -> String {
        guard let statement = statements[challengeId] else { throw OIDCDeviceError.notActive }
        return statement
    }
    public func submit(challengeId: String, factor: String) async throws -> FactorDecision {
        submitted.append((challengeId, factor))
        if let submitError { throw submitError }
        return (try? FactorAssertion.parse(factor).claims.decision) ?? decision
    }
    public func consents() async throws -> [OIDCConsentView] { consentList }
    public func revokeConsent(clientId: String) async throws -> Bool {
        revoked.append(clientId)
        let before = consentList.count
        consentList.removeAll { $0.clientId == clientId }
        return consentList.count < before
    }
}

// MARK: Signing

/// Signs a factor assertion with the device approval key the authority logged (ADR-0023 §3). `uv` follows the key: `biometric` only from the
/// `approvalBiometric` key, otherwise `user_presence`.
public protocol AuthorityFactorSigning: Sendable {
    /// The `uv` value the key that will sign can claim (`nil`: no approval key on this device).
    func userVerification() async -> FactorUserVerification?
    func sign(_ claims: FactorAssertionClaims, prompt: SigningPrompt) async throws -> String
}

public enum AuthorityFactorSigningError: Error, Sendable, Equatable {
    case noApprovalKey
    case keyMismatch
}

/// The account device's approval keys: `approvalBiometric` when present, else `approvalUserPresence`.
public struct DeviceKeyFactorSigner: AuthorityFactorSigning {
    let keys: any DeviceKeyStore
    public init(keys: any DeviceKeyStore) { self.keys = keys }

    private func key() async -> (any ManagedSigningKey)? {
        if let key = try? await keys.existingKey(for: .approvalBiometric) { return key }
        return try? await keys.existingKey(for: .approvalUserPresence)
    }

    public func userVerification() async -> FactorUserVerification? {
        guard let key = await key() else { return nil }
        return key.purpose == .approvalBiometric ? .biometric : .userPresence
    }

    public func sign(_ claims: FactorAssertionClaims, prompt: SigningPrompt) async throws -> String {
        guard let key = await key() else { throw AuthorityFactorSigningError.noApprovalKey }
        // The claimed `uv` must be the one this key can make (the authority refuses `biometric` from a user-presence key anyway).
        let expected: FactorUserVerification = key.purpose == .approvalBiometric ? .biometric : .userPresence
        guard claims.userVerification == expected else { throw AuthorityFactorSigningError.keyMismatch }
        return try await FactorAssertion.sign(claims, with: PromptBoundKey(key, prompt: prompt))
    }
}

// MARK: Pinned statement keys

/// The authority's `device-statement-signing` public keys this build trusts (ADR-0033 §3). Build setting `VIADERE_AUTHORITY_STATEMENT_KEYS`
/// (Info.plist `ViadereAuthorityStatementKeys`): base64url X9.63 P-256 keys, comma separated (active, standby). A key is used only if its RFC 7638
/// thumbprint is also one of Core's `AuthorityPinnedKeys.deviceStatementKids` for the environment, so the two pins must agree. **All-or-nothing**:
/// one malformed entry rejects the list. An empty result fails every statement closed.
public enum AuthorityStatementKeyPins {
    public static func parse(_ raw: String?) -> [P256.Signing.PublicKey] {
        guard let raw else { return [] }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.contains("$(") else { return [] }
        var keys: [P256.Signing.PublicKey] = []
        for entry in trimmed.split(separator: ",", omittingEmptySubsequences: false) {
            guard let bytes = Base64URL.decode(entry.trimmingCharacters(in: .whitespaces)), bytes.count == 65,
                  let key = try? P256.Signing.PublicKey(x963Representation: bytes) else { return [] }
            guard !keys.contains(where: { JWKThumbprint.p256($0) == JWKThumbprint.p256(key) }) else { return [] }
            keys.append(key)
        }
        return keys
    }

    /// The build keys narrowed to those whose thumbprint Core pins for `environment`.
    public static func effective(_ keys: [P256.Signing.PublicKey], pinnedKids: [String]) -> [P256.Signing.PublicKey] {
        keys.filter { pinnedKids.contains(JWKThumbprint.p256($0)) }
    }

    public static func effective(configuration: ViadereConfiguration) -> [P256.Signing.PublicKey] {
        effective(parse(configuration.authorityStatementKeys.joined(separator: ",")),
                  pinnedKids: AuthorityPinnedKeys.deviceStatementKids(configuration.authorityEnvironment))
    }
}

extension ViadereConfiguration {
    /// Staging and local builds verify `stg` statements; only a production build verifies `prod` ones.
    public var authorityEnvironment: AuthorityEnvironment { mode == .production && !stagingDiagnostics ? .production : .staging }
}
