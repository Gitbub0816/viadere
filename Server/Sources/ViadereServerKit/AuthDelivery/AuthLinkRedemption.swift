import Foundation
import Vapor
import ViadereCore

/// `POST /v1/business/auth-links/redeem` (ADR-0021 §5.4, §6; ledger S6-05). The api is a relay: it names the **authenticated** business (from the API
/// key, never from the body) and forwards the code or challenge reference and the PKCE verifier to the authority, which checks the code against its
/// own records, compares the business with its link-client record, and only then signs the `viadere-grant+jwt`. The api never holds a grant before
/// the business redeems, and cannot mint one.
///
/// `404` while `AUTH_DELIVERY_ENABLED` or `AUTH_LINK_SERVICE_ENABLED` is off; `503` when on but no authority is configured (fail closed).
enum AuthLinkRedemption {
    static func register(_ routes: any RoutesBuilder) {
        routes.api(APIRoutes.businessAuthLinkRedeem, scope: BusinessAPIKeys.Scope.authDeliveriesWrite) { req in
            try AuthDeliveryGate.require(req.ctx)
            guard req.ctx.config.authDelivery.linkServiceEnabled else { throw APIError.notFound }
            let principal = try req.business
            try await AuthDeliveryService(db: req.db, ctx: req.ctx).requireLiveKeyAssurance(principal)
            let body: AuthLinkRedeemRequest
            do { body = try ViadereJSON.decode(AuthLinkRedeemRequest.self, from: req.bodyBytes) } catch {
                throw APIError.validation("link_client_id, code_verifier and exactly one of code and ach are required.")
            }
            guard body.isWellFormed else { throw APIError.validation("The request failed validation.") }
            guard let transport = req.application.authorityTransport else {
                throw APIError(.serviceUnavailable, .unavailable, "The link service is unavailable right now.")
            }
            let result = try await AuthorityClient(transport: transport).redeemLink(body, businessId: principal.businessId.uuid)
            switch result.status {
            case 200:
                guard let grant = result.response else { throw APIError(.serviceUnavailable, .unavailable, "The link service is unavailable right now.") }
                return try req.jsonResponse(grant)
            case 400..<500:
                // One answer for every refusal (unknown, expired, used, foreign code or wrong verifier); the reason is in the authority's audit.
                throw APIError(.badRequest, .badRequest, "The link code cannot be redeemed.", details: ["error": "invalid_grant"])
            default:
                throw APIError(.serviceUnavailable, .unavailable, "The link service is unavailable right now.")
            }
        }
    }
}

extension AuthorityClient {
    /// `POST /v1/link/redeem`: the body's members plus the authenticated business id; the authority's answer is decoded strictly.
    func redeemLink(_ body: AuthLinkRedeemRequest, businessId: UUID) async throws -> (status: Int, response: AuthLinkRedeemResponse?) {
        var object: [String: JSONValue] = ["link_client_id": .string(body.linkClientId), "business_id": .string(businessId.uuidString.lowercased()),
                                           "code_verifier": .string(body.codeVerifier)]
        if let code = body.code { object["code"] = .string(code) }
        if let ach = body.ach { object["ach"] = .string(ach) }
        let result: (status: Int, body: Data)
        do {
            result = try await transport.send(method: .POST, path: AuthorityKeyLogRoute.linkRedeem, contentType: "application/json", body: try CanonicalJSON.serialize(.object(object)))
        } catch { return (503, nil) }
        guard result.status == 200 else { return (result.status, nil) }
        guard case .object(let o)? = try? JSONDecoder().decode(JSONValue.self, from: result.body), Set(o.keys) == ["grant", "delivery_id"],
              let grant = o["grant"]?.stringValue, let delivery = o["delivery_id"]?.stringValue else { return (503, nil) }
        return (200, AuthLinkRedeemResponse(grant: grant, deliveryId: delivery))
    }
}
