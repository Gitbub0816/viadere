import Foundation
import Testing
@testable import ViadereCore

/// Core contract of the Stage 6 OIDC methods (ADR-0023 §3a, ADR-0024 §4, §5, §8).
struct AuthorityOIDCMethodsTests {
    let domain = LinkDomain("viadere.cksites.dev")!

    @Test func passkeyAMRNeverImpliesHardwareAndOnlyOIDCLoginHasAPasskeyOrigin() {
        #expect(OIDCProfile.passkeyAMR(hardwareBound: true) == ["hwk", "user", "mfa"])
        #expect(OIDCProfile.passkeyAMR(hardwareBound: false) == ["swk", "user", "mfa"])
        #expect(OIDCProfile.passkeyOrigins(for: .oidcLogin, issuer: "https://id.example.com") == ["https://id.example.com"])
        // ST-REC-17: no passkey origin exists for key-log, recovery-codes, enrollment or link purposes in this stage.
        for purpose in AuthorityPurpose.allCases where purpose != .oidcLogin {
            #expect(OIDCProfile.passkeyOrigins(for: purpose, issuer: "https://id.example.com").isEmpty, "\(purpose)")
        }
    }

    @Test func challengeLinkCarriesOnlyTheChallengeId() throws {
        let ach = AuthorityChallengeID.generate()
        let link = OIDCChallengeLink.build(challengeId: ach, domain: domain)
        #expect(link == "https://viadere.cksites.dev/o/\(ach)")
        #expect(OIDCChallengeLink.parse(try #require(URL(string: link)), domain: domain) == ach)
        for bad in ["https://viadere.cksites.dev/o/\(ach)?n=42", "https://viadere.cksites.dev/o/\(ach)#x", "https://www.viadere.cksites.dev/o/\(ach)",
                    "https://u@viadere.cksites.dev/o/\(ach)", "https://viadere.cksites.dev/o/ach_x", "https://viadere.cksites.dev/v/\(ach)"] {
            #expect(OIDCChallengeLink.parse(try #require(URL(string: bad)), domain: domain) == nil, "\(bad)")
        }
    }

    @Test func requestBodiesAreClosed() throws {
        let ach = AuthorityChallengeID.generate()
        let credential = #"{"id":"aaaa","rawId":"aaaa","authenticatorData":"x","clientDataJSON":"y","signature":"z"}"#
        #expect(throws: (any Error).self) { try ViadereJSON.decode(AuthorityPasskeyEvidenceRequest.self, from: Data(#"{"ach":"\#(ach)","credential":\#(credential),"account_id":"x"}"#.utf8)) }
        #expect(try ViadereJSON.decode(AuthorityPasskeyEvidenceRequest.self, from: Data(#"{"ach":"\#(ach)","credential":\#(credential)}"#.utf8)).challengeId == ach)
        #expect(throws: (any Error).self) { try ViadereJSON.decode(AuthorityConsentRevokeRequest.self, from: Data(#"{"account_id":"\#(UUID())","client_id":"ocl_x1234","all":true}"#.utf8)) }
        #expect(throws: (any Error).self) { try ViadereJSON.decode(AuthorityConsentListRequest.self, from: Data(#"{"account_id":"\#(UUID())","client_id":"ocl_x1234"}"#.utf8)) }
        #expect(throws: (any Error).self) { try ViadereJSON.decode(AuthorityPasskeyChallengeRequest.self, from: Data(#"{"oidc":{},"display":{}}"#.utf8)) }
        // The login hint members are part of the closed OIDC authorization object, nothing else is.
        let oidc = AuthorityChallengeCreateRequest.OIDCAuthorization(clientId: "ocl_x1234", redirectURI: "https://rp.example.com/cb", codeChallenge: "c",
                                                                      codeChallengeMethod: "S256", nonce: "n", loginHint: "sub_x", hintAccountId: UUID())
        let round = try ViadereJSON.decode(AuthorityChallengeCreateRequest.self, from: try ViadereJSON.encode(AuthorityChallengeCreateRequest(purpose: .oidcLogin, oidc: oidc)))
        #expect(round.oidc == oidc)
    }

    @Test func clientIdsAndPushPayloads() {
        #expect(OIDCClientID.isValid("ocl_frontend"))
        #expect(!OIDCClientID.isValid("lcl_frontend"))
        #expect(!OIDCClientID.isValid("ocl_a/b"))
        #expect(!OIDCClientID.isValid("ocl_"))
        let ach = AuthorityChallengeID.generate()
        let aps: [String: Any] = ["alert": ["title": "Viadere", "body": "Action needed."], "category": "viadere.oidc", "interruption-level": "active"]
        #expect(OIDCPushPayloadPolicy.isAllowed(["aps": aps, "ach": ach]))
        #expect(!OIDCPushPayloadPolicy.isAllowed(["aps": aps, "ach": ach, "client": "Example"]))
        #expect(!OIDCPushPayloadPolicy.isAllowed(["aps": aps.merging(["interruption-level": "time-sensitive"]) { $1 }, "ach": ach]))
        #expect(!OIDCPushPayloadPolicy.isAllowed(["aps": aps, "ach": "not-a-challenge"]))
    }
}
