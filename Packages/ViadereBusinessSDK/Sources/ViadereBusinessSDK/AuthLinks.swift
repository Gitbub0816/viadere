import Foundation
import ViadereCore

extension ViadereBusinessClient {
    /// Link service (ADR-0021 §5.4, §6): exchanges the `vdr_code` your page posted to your backend (same device) or the challenge reference
    /// (`ach`, cross device) and your PKCE `code_verifier` for the authority's `viadere-grant+jwt`. Verify the grant with `AuthorityGrantVerifier`
    /// against the static grant JWKS and consume its `jti` once before you sign the person in. Any refusal is a `400` (`invalid_grant`).
    public func redeemAuthLink(_ request: AuthLinkRedeemRequest) async throws -> AuthLinkRedeemResponse {
        try decode(AuthLinkRedeemResponse.self, try await perform(APIRoutes.businessAuthLinkRedeem.descriptor, body: request))
    }

    /// Destination-key registration (ADR-0031 §1.2, SECURITY §2.110): reads the nonce the authority issued for one of **your own** destination keys,
    /// with exactly what `viadere-destination-key-registration+jws` must sign. Live keys only. Reading consumes nothing (the registration
    /// consumes the nonce once), so it is retried like a read. Every "not available" case is the same `404`.
    public func readDestinationKeyRegistrationNonce(kid: String) async throws -> AuthDestinationKeyNonceResponse {
        let request = AuthDestinationKeyNonceRequest(kid: kid)
        guard request.isWellFormed else { throw ViadereSDKError.invalidPath }
        return try decode(AuthDestinationKeyNonceResponse.self,
                          try await perform(APIRoutes.businessDestinationKeyNonce.descriptor, body: request, naturallyIdempotent: true))
    }
}
