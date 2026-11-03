import Foundation
import ViadereCore

extension ViadereBusinessClient {
    /// Link service (ADR-0021 §5.4, §6): exchanges the `vdr_code` your page posted to your backend (same device) or the challenge reference
    /// (`ach`, cross device) and your PKCE `code_verifier` for the authority's `viadere-grant+jwt`. Verify the grant with `AuthorityGrantVerifier`
    /// against the static grant JWKS and consume its `jti` once before you sign the person in. Any refusal is a `400` (`invalid_grant`).
    public func redeemAuthLink(_ request: AuthLinkRedeemRequest) async throws -> AuthLinkRedeemResponse {
        try decode(AuthLinkRedeemResponse.self, try await perform(APIRoutes.businessAuthLinkRedeem.descriptor, body: request))
    }
}
