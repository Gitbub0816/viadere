import Crypto
import Foundation
import Testing
@testable import ViadereCore

/// ApprovalResult v2 (ADR-0022 §3) against the independently generated vectors `docs/protocol/vectors/approval-result-v2.json` (Python), plus the
/// request v2 (`number_match` inside the business-signed request), the code sampler and the SDK key derivation. ST-MFA-02 (V), ST-MFA-03 (B).
@Suite("Approval result v2 and number matching")
struct ApprovalResultV2Tests {
    static var vectors: [String: Any] {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { url.deleteLastPathComponent() }
        let data = try! Data(contentsOf: url.appendingPathComponent("docs/protocol/vectors/approval-result-v2.json"))
        return try! JSONSerialization.jsonObject(with: data) as! [String: Any]
    }

    struct Fixture {
        let now: Date
        let key: EnrolledApprovalKey
        let context: [String: Any]
        func expectation(_ kind: String) -> ApprovalExpectation {
            let auth = context["authentication"] as! [String: Any]
            let details = ApprovalSubject.authentication(AuthenticationDetails(actionDisplay: auth["action_display"] as! String, matchDigits: auth["match_digits"] as? Int))
            return ApprovalExpectation(audience: BusinessID(context["aud"] as! String)!, subject: SubjectRef(context["sub"] as! String)!,
                                       requestId: context["request_id"] as! String, challenge: context["challenge"] as! String, subjectDetails: details,
                                       numberMatch: kind == "required" ? .required(code: context["code"] as! String) : .notRequested,
                                       requestExpiresAt: Date(timeIntervalSince1970: TimeInterval(context["request_expires_at"] as! Int)), minimumAMR: .biometric)
        }
    }

    static func fixture() throws -> Fixture {
        let v = vectors
        let device = v["device_key"] as! [String: Any]
        let context = v["context"] as! [String: Any]
        let publicKey = try DevicePublicKey(base64URL: device["public_x963_b64url"] as! String)
        let kid = device["kid"] as! String
        #expect(KeyIdentifier.make(try publicKey.signingKey()) == kid)
        return Fixture(now: Date(timeIntervalSince1970: TimeInterval(v["now"] as! Int)),
                       key: EnrolledApprovalKey(kid: kid, publicKey: publicKey, subject: SubjectRef(context["sub"] as! String)!, assurance: .biometric), context: context)
    }

    @Test func theTransactionDigestCoversTheNumberMatchLength() throws {
        let f = try Self.fixture()
        let details = ApprovalSubject.authentication(AuthenticationDetails(actionDisplay: "Sign in to Example Bank", matchDigits: 2))
        #expect(try details.digest() == f.context["txn_digest"] as! String)
        // Stripping the requirement changes the digest the business checks.
        #expect(try ApprovalSubject.authentication(AuthenticationDetails(actionDisplay: "Sign in to Example Bank")).digest() != f.context["txn_digest"] as! String)
    }

    @Test func everyVectorHasItsExpectedOutcome() throws {
        let f = try Self.fixture()
        let cases = Self.vectors["cases"] as! [[String: Any]]
        #expect(cases.count >= 20)
        for vector in cases {
            let name = vector["name"] as! String
            do {
                let verified = try ApprovalResultVerifier.verify(vector["jws"] as! String, expecting: f.expectation(vector["expectation"] as! String), keys: [f.key], now: f.now)
                #expect(verified.decision.rawValue == vector["outcome"] as? String, "\(name)")
            } catch {
                let expected = vector["error"] as? String
                #expect(expected != nil && String(describing: error).hasPrefix(expected!), "\(name): \(error)")
            }
        }
    }

    @Test func aV2ResultIsConsumedOnceByChallengeAndByJti() async throws {
        let f = try Self.fixture()
        let jws = (Self.vectors["cases"] as! [[String: Any]])[0]["jws"] as! String
        let guardian = InMemoryReplayGuard()
        let verified = try await ApprovalResultVerifier.verifyAndConsume(jws, expecting: f.expectation("required"), keys: [f.key], now: f.now, replayGuard: guardian)
        #expect(verified.claims.jti != nil && verified.claims.match == "47")
        await #expect(throws: ApprovalVerificationError.replayed) {
            _ = try await ApprovalResultVerifier.verifyAndConsume(jws, expecting: f.expectation("required"), keys: [f.key], now: f.now, replayGuard: guardian)
        }
    }

    @Test func theDeviceSignsV2WithTheTypedNumberAndTheVerifierChecksIt() async throws {
        let f = try Self.fixture()
        let signer = try SoftwareP256SigningKey(rawRepresentation: Hex.decode((Self.vectors["device_key"] as! [String: Any])["private_scalar_hex"] as! String)!)
        let exp = f.expectation("required")
        let content = ApprovalRequestContent(businessId: exp.audience, subject: exp.subject, requestId: exp.requestId, challenge: exp.challenge!,
                                             details: exp.subjectDetails!, toKid: f.key.kid, issuedAt: f.now, expiresAt: f.now.addingTimeInterval(120),
                                             numberMatch: ApprovalNumberMatch(digits: 2, code: "47"))
        let good = try await ApprovalResultFactory.sign(displayed: content, decision: .approve, amr: .biometric, key: signer, now: f.now,
                                                        numberMatch: ApprovalNumberMatchAnswer(match: "47", denyReason: nil, invalidMatchAttempts: 1))
        #expect(try ApprovalResultVerifier.verify(good, expecting: exp, keys: [f.key], now: f.now).claims.v == 2)
        // An approve of a number-matched request without the typed number is never signed.
        await #expect(throws: ApprovalRequestError.self) {
            _ = try await ApprovalResultFactory.sign(displayed: content, decision: .approve, amr: .biometric, key: signer, now: f.now)
        }
        // Downgrade: a v1 result (the legacy factory path without a number) fails a `.required` expectation.
        var v1Content = content
        v1Content.numberMatch = nil
        let v1 = try await ApprovalResultFactory.sign(displayed: v1Content, decision: .approve, amr: .biometric, key: signer, now: f.now)
        #expect(throws: ApprovalVerificationError.numberMatchRequired) { _ = try ApprovalResultVerifier.verify(v1, expecting: exp, keys: [f.key], now: f.now) }
    }

    @Test func aSignedRequestV2CarriesTheNumberAndCannotBeStripped() async throws {
        let business = SoftwareP256SigningKey()
        let f = try Self.fixture()
        let exp = f.expectation("required")
        let content = ApprovalRequestContent(businessId: exp.audience, subject: exp.subject, requestId: exp.requestId, challenge: exp.challenge!,
                                             details: exp.subjectDetails!, toKid: f.key.kid, issuedAt: f.now, expiresAt: f.now.addingTimeInterval(120),
                                             numberMatch: ApprovalNumberMatch(digits: 2, code: "47"))
        let signed = try await content.sign(with: business)
        let verified = try ApprovalRequestContent.verify(signed, signingKey: business.publicKey, expectedBusiness: exp.audience, expectedSubject: exp.subject,
                                                         expectedKid: f.key.kid, expectedRequestId: nil, now: f.now)
        #expect(verified.numberMatch == ApprovalNumberMatch(digits: 2, code: "47"))
        // `match_digits` in the details without the signed number is malformed (a business signer bug or a stripped requirement).
        var stripped = content
        stripped.numberMatch = nil
        let strippedSigned = try await stripped.sign(with: business)
        #expect(throws: ApprovalRequestError.self) {
            _ = try ApprovalRequestContent.verify(strippedSigned, signingKey: business.publicKey, expectedBusiness: exp.audience, expectedSubject: exp.subject,
                                                  expectedKid: f.key.kid, expectedRequestId: nil, now: f.now)
        }
        // A payment needs 3 digits.
        var payment = content
        payment.details = .transaction(TransactionDetails(currency: "USD", amountMinor: 100, payeeDisplay: "Shop", transactionReference: "r1"))
        await #expect(throws: ApprovalRequestError.self) { _ = try await payment.sign(with: business) }
    }

    @Test func theCodeSamplerMatchesTheVectorsAndHasNoLeadingZero() throws {
        for draw in Self.vectors["code_draws"] as! [[String: Any]] {
            var stream = Hex.decode(draw["random_hex"] as! String)!
            let code = ApprovalNumberMatch.draw(digits: draw["digits"] as! Int) { count in
                let chunk = stream.prefix(count)
                stream = stream.dropFirst(count)
                return Data(chunk)
            }
            #expect(code.code == draw["code"] as! String)
        }
        for _ in 0..<500 {
            #expect(ApprovalNumberMatch.draw(digits: 2).isValid)
            #expect(ApprovalNumberMatch.draw(digits: 3).isValid)
        }
        #expect(ApprovalNumberMatch.requiredDigits(capability: .transactionApprove, risk: .low) == 3)
        #expect(ApprovalNumberMatch.requiredDigits(capability: .authChallenge, risk: .high) == 3)
        #expect(ApprovalNumberMatch.requiredDigits(capability: .authChallenge, risk: .medium) == 2)
    }

    @Test func sdkKeysMatchTagsAndSessionHandlesMatchTheVectors() throws {
        let tags = Self.vectors["match_tags"] as! [String: Any]
        let secret = SymmetricKey(data: Hex.decode(tags["sdk_secret_hex"] as! String)!)
        let kMatch = AuthSDKKeys.derive(secret: secret, label: AuthSDKKeys.matchTagLabel)
        #expect(kMatch.withUnsafeBytes { Data($0) } == Hex.decode(tags["k_match_hex"] as! String)!)
        let subject = SubjectRef(tags["subject_ref"] as! String)!
        for entry in tags["tags"] as! [[String: Any]] {
            let computed = AuthMatchTags.tags(key: kMatch, subjectRef: subject, code: entry["code"] as! String)
            #expect(computed?.tag == entry["match_tag"] as? String)
            #expect(computed?.prefixTag == entry["match_prefix_tag"] as? String)
        }
        let handles = Self.vectors["session_handles"] as! [String: Any]
        let kSH = AuthSDKKeys.derive(secret: secret, label: AuthSDKKeys.sessionHandleLabel)
        #expect(kSH.withUnsafeBytes { Data($0) } == Hex.decode(handles["k_sh_hex"] as! String)!)
        for entry in handles["handles"] as! [[String: Any]] {
            #expect(AuthSDKKeys.sessionHandle(key: kSH, initiatingSessionId: entry["initiating_session_id"] as! String) == entry["session_handle"] as! String)
        }
    }

    @Test func authApprovalCreateIsStrictAndChecksTheShape() throws {
        let tag = Base64URL.encode(Data(repeating: 1, count: 32))
        let sub = "sub_" + Base64URL.encode(Data(repeating: 7, count: 32))
        let base = #"{"request_id":"req_0123456789abcdef","subject_ref":"\#(sub)","capability":"auth.challenge","challenge":"\#(Base64URL.encode(Data(count: 32)))","authentication":{"action_display":"Sign in","match_digits":2},"number_match":{"digits":2,"code":"47"},"match_tag":"\#(tag)"}"#
        let ok = try ViadereJSON.decode(AuthApprovalCreateRequest.self, from: Data(base.utf8))
        #expect(ok.validate() == nil)
        // Unknown members (a tenant) are refused.
        #expect(throws: (any Error).self) { _ = try ViadereJSON.decode(AuthApprovalCreateRequest.self, from: Data(base.replacingOccurrences(of: "{\"request_id\"", with: "{\"tenant_id\":\"x\",\"request_id\"").utf8)) }
        var payment = ok
        payment.capability = .transactionApprove
        #expect(payment.validate()?.code == "three_required")
        var high = ok
        high.risk = .high
        #expect(high.validate()?.code == "three_required")
        var noDigits = ok
        noDigits.authentication = AuthenticationDetails(actionDisplay: "Sign in")
        #expect(noDigits.validate()?.field == "authentication.match_digits")
        var leadingZero = ok
        leadingZero.numberMatch = AuthApprovalNumberMatch(digits: 2, code: "07")
        #expect(leadingZero.validate()?.field == "number_match.code")
        var badPrefix = ok
        badPrefix.matchPrefixTag = "nope"
        #expect(badPrefix.validate() != nil)
    }
}
