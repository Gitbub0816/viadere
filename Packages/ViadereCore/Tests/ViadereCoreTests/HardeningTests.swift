import Crypto
import Foundation
import Testing
@testable import ViadereCore

/// P-256 group order, independent of the implementation under test (used to build the malleable twin of a signature).
private let p256Order: [UInt8] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
]

/// `(r, n - s)`: the other valid encoding of the same signature.
private func malleableTwin(_ raw: Data) -> Data {
    let bytes = [UInt8](raw)
    var out = [UInt8](repeating: 0, count: 32)
    var borrow = 0
    for i in stride(from: 31, through: 0, by: -1) {
        var d = Int(p256Order[i]) - Int(bytes[32 + i]) - borrow
        if d < 0 { d += 256; borrow = 1 } else { borrow = 0 }
        out[i] = UInt8(d)
    }
    return Data(bytes[0..<32] + out)
}

@Suite("ECDSA malleability (A5)")
struct SignatureMalleabilityTests {
    let key = SoftwareP256SigningKey()
    let deviceId = DeviceID()
    let now = Fixtures.now

    @Test("both (r, s) and (r, n-s) verify with the raw crypto, and Viadere folds them to one encoding")
    func twinsCollapse() throws {
        let message = Data("message".utf8)
        let privateKey = try P256.Signing.PrivateKey(rawRepresentation: key.rawRepresentation)
        for _ in 0..<20 {
            let signature = try privateKey.signature(for: message)
            let twinRaw = malleableTwin(signature.rawRepresentation)
            let twin = try P256.Signing.ECDSASignature(rawRepresentation: twinRaw)
            // The exploit premise: the underlying primitive accepts both encodings.
            #expect(privateKey.publicKey.isValidSignature(signature, for: message))
            #expect(privateKey.publicKey.isValidSignature(twin, for: message))
            // Viadere's canonical form is identical for both, whichever was produced.
            let a = ViadereSignatureEncoding.encode(signature)
            let b = ViadereSignatureEncoding.encode(twin)
            #expect(a == b)
            #expect(ViadereSignatureEncoding.decode(Base64URL.encode(twinRaw))?.rawRepresentation == ViadereSignatureEncoding.decode(a)?.rawRepresentation)
            #expect(ViadereSignatureEncoding.canonicalString(Base64URL.encode(signature.rawRepresentation)) == ViadereSignatureEncoding.canonicalString(Base64URL.encode(twinRaw)))
            #expect(ViadereSignatureEncoding.isCanonical(try #require(ViadereSignatureEncoding.decode(a))))
        }
    }

    @Test("a delegation step-up proof cannot be replayed by re-encoding its signature")
    func delegationReplayKeyIsContentBased() async throws {
        let request = DelegationInvitationRequest(delegateLabel: "Sam", role: .manager, purposes: [.security], businessIds: [BusinessID()],
                                                  expiresAt: now.addingTimeInterval(86_400), includesSensitiveScope: true)
        let digest = DelegationScopePolicy.scopeDigest(of: request)
        let signedAt = ViadereDate.truncatedToMilliseconds(now)
        let unsigned = DelegationStepUpProof(deviceId: deviceId, signedAt: signedAt, scopeDigest: digest, signature: "")
        let raw = try await key.signature(for: unsigned.signingInput()).rawRepresentation
        // Whichever half the signer picked, build both encodings by hand.
        let canonical = ViadereSignatureEncoding.normalizedRaw(raw)
        let other = malleableTwin(canonical)
        #expect(canonical != other)
        let first = DelegationStepUpProof(deviceId: deviceId, signedAt: signedAt, scopeDigest: digest, signature: Base64URL.encode(canonical))
        let twin = DelegationStepUpProof(deviceId: deviceId, signedAt: signedAt, scopeDigest: digest, signature: Base64URL.encode(other))
        let guardian = InMemoryReplayGuard()
        let at = now.addingTimeInterval(10)
        try await DelegationStepUpVerifier.verify(first, for: request, deviceId: deviceId, publicKey: key.publicKey, now: at, replayGuard: guardian)
        // Before the fix the replay key was sha256(signature string), so this second encoding sailed through.
        await #expect(throws: DelegationStepUpVerifier.Failure.replayed) {
            try await DelegationStepUpVerifier.verify(twin, for: request, deviceId: deviceId, publicKey: key.publicKey, now: at, replayGuard: guardian)
        }
        #expect(DelegationStepUpVerifier.replayKey(for: first) == DelegationStepUpVerifier.replayKey(for: twin))
    }

    @Test("a request signature and a decision signature accept either encoding")
    func requestAndDecisionAcceptEither() async throws {
        let headers = try await RequestSigner(deviceId: deviceId, key: key).sign(method: "GET", pathAndQuery: "/v1/x", body: Data(), now: now)
        let raw = try #require(Base64URL.decode(headers.signature))
        var twinHeaders = headers
        twinHeaders.signature = Base64URL.encode(malleableTwin(raw))
        try RequestVerifier().verify(method: "GET", pathAndQuery: "/v1/x", body: Data(), headers: twinHeaders, publicKey: key.publicKey, now: now)
        try RequestVerifier().verify(method: "GET", pathAndQuery: "/v1/x", body: Data(), headers: headers, publicKey: key.publicKey, now: now)
        // A signature over other bytes still fails.
        #expect(throws: RequestVerificationError.badSignature) {
            try RequestVerifier().verify(method: "GET", pathAndQuery: "/v1/y", body: Data(), headers: twinHeaders, publicKey: key.publicKey, now: now)
        }
    }

    @Test("garbage and out-of-range scalars are not 'normalised' into validity")
    func invalidScalarsStayInvalid() {
        let zeroS = Data(repeating: 1, count: 32) + Data(repeating: 0, count: 32)
        #expect(ViadereSignatureEncoding.normalizedRaw(zeroS) == zeroS)
        let tooBig = Data(repeating: 1, count: 32) + Data(p256Order)
        #expect(ViadereSignatureEncoding.normalizedRaw(tooBig) == tooBig)
        #expect(ViadereSignatureEncoding.decode("short") == nil)
    }
}

@Suite("Display text (iOS #3)")
struct DisplayTextTests {
    @Test("every invisible or reordering character is refused")
    func hostileScalars() {
        let hostile: [UInt32] = [
            0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069, 0x200E, 0x200F, 0x061C, 0x180E,
            0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x2028, 0x2029, 0x0085, 0x0000, 0x0007, 0x001B, 0x007F, 0x00AD, 0x2062,
            0xE0041, 0x3164, 0x2800, 0x034F, 0xE000,
        ]
        for value in hostile {
            let scalar = Unicode.Scalar(value)!
            #expect(DisplayTextSanitizer.isDisallowed(scalar), "U+\(String(value, radix: 16)) must be disallowed")
            #expect(DisplayTextSanitizer.containsDisallowedScalars("Pay " + String(scalar) + "Walmart"))
        }
        #expect(!DisplayTextSanitizer.containsDisallowedScalars("Café Zoë — 285,28 € 日本 🚗 ❤️"))
        #expect(DisplayTextSanitizer.containsDisallowedScalars("a\nb"))
        #expect(!DisplayTextSanitizer.containsDisallowedScalars("a\nb", allowNewlines: true))
        #expect(DisplayTextSanitizer.containsDisallowedScalars("a\rb", allowNewlines: true))
    }

    @Test("sanitize strips, collapses and caps")
    func sanitize() {
        let nasty = "\u{202E}Pay\u{200B}   Walmart\n\n$1\u{2028}Approve\t"
        let clean = DisplayTextSanitizer.sanitize(nasty, maxCharacters: 80)
        #expect(clean == "Pay Walmart $1 Approve")
        #expect(!DisplayTextSanitizer.containsDisallowedScalars(clean))
        // Zalgo: one grapheme per letter, hundreds of scalars.
        let zalgo = "a" + String(repeating: "\u{0301}", count: 500)
        let capped = DisplayTextSanitizer.sanitize(zalgo, maxCharacters: 20)
        #expect(DisplayTextSanitizer.isWithinLimits(capped, maxCharacters: 20))
        let long = DisplayTextSanitizer.sanitize(String(repeating: "x", count: 500), maxCharacters: 40)
        #expect(long.count <= 40 && long.hasSuffix("…"))
        #expect(DisplayTextSanitizer.sanitize("line1\nline2", maxCharacters: 40, allowNewlines: true) == "line1\nline2")
    }

    @Test("limits count scalars and UTF-8 bytes, not only graphemes")
    func limits() {
        let zalgo = "a" + String(repeating: "\u{0301}", count: 500)
        #expect(zalgo.count == 1)
        #expect(!DisplayTextSanitizer.isWithinLimits(zalgo, maxCharacters: 80))
        let emoji = String(repeating: "🚗", count: 80)   // 80 graphemes, 320 bytes
        #expect(DisplayTextSanitizer.isWithinLimits(emoji, maxCharacters: 80))
        #expect(!DisplayTextSanitizer.isWithinLimits(emoji + "🚗", maxCharacters: 80))
    }

    @Test("Viadere impersonation, including width, case, homoglyph and punctuation tricks")
    func impersonation() {
        for text in ["Viadere", "viadere security", "VIADERE: your code", "[Viadere] help", "  \"Viadere\"", "V.i.a.d.e.r.e Support",
                     "V I A D E R E", "Ｖｉａｄｅｒｅ", "Vіadere" /* Cyrillic і */, "V1ADERE", "Via\u{200B}dere", "Viaderé", "vladere"] {
            #expect(DisplayTextSanitizer.impersonatesViadere(text), "\(text) should look like Viadere")
        }
        for text in ["Walmart", "Via Rail", "Diaderm", "Pay Viadere later", "Radar"] {
            #expect(!DisplayTextSanitizer.impersonatesViadere(text), "\(text) should not be flagged as a prefix")
        }
        #expect(DisplayTextSanitizer.impersonatesViadere("Pay Viadere later", anywhere: true))
        #expect(!DisplayTextSanitizer.impersonatesViadere("Walmart", anywhere: true))
    }

    private func issues(_ payload: InteractionPayload, sensitivity: Sensitivity = .standard) -> [InteractionValidation.Issue] {
        InteractionValidation.issues(in: Fixtures.interaction(payload, sensitivity: sensitivity, purpose: .security), now: Fixtures.now)
    }

    @Test("validation rejects hostile business strings on every approval screen field")
    func validationRejects() {
        var login = Fixtures.loginPayload
        #expect(issues(.authenticate(login)).isEmpty)
        for hostile in ["\u{202E}gnikna", "Bank\u{061C}", "Bank\u{180E}x", "Bank\u{2028}Amount: $0", "Bank\u{2029}", "Bank\u{200B}", "Bank\u{0007}", "Bank\nApprove"] {
            login.service = hostile
            let found = issues(.authenticate(login))
            #expect(found.contains { $0.field == "payload.service" && $0.code == .disallowedCharacters }, "\(hostile.debugDescription) must be rejected")
        }
        login = Fixtures.loginPayload
        login.service = "Viadere Security"
        #expect(issues(.authenticate(login)).contains { $0.field == "payload.service" && $0.code == .impersonation })
        login.service = "Sign in to Viadere"      // identity fields may not mention the brand at all
        #expect(issues(.authenticate(login)).contains { $0.code == .impersonation })
        login = Fixtures.loginPayload
        login.device = "Viadere Verified Device"
        #expect(issues(.authenticate(login)).contains { $0.field == "payload.device" && $0.code == .impersonation })

        var pay = Fixtures.mesaAuthorize
        pay.merchant = "V1ADERE Refunds"
        #expect(issues(.authorize(pay)).contains { $0.field == "payload.merchant" && $0.code == .impersonation })
        pay = Fixtures.mesaAuthorize
        pay.effectOfApproval = "\u{202E}Cancels the charge"
        #expect(issues(.authorize(pay)).contains { $0.field == "payload.effectOfApproval" && $0.code == .disallowedCharacters })
        pay = Fixtures.mesaAuthorize
        pay.riskIndicators = [RiskIndicator(code: "x", label: "Safe\u{200D}", severity: .info)]
        #expect(issues(.authorize(pay)).contains { $0.code == .disallowedCharacters })
    }

    @Test("validation caps unicode scalars and UTF-8 bytes")
    func validationCaps() {
        var login = Fixtures.loginPayload
        login.service = "a" + String(repeating: "\u{0301}", count: 300)
        #expect(issues(.authenticate(login)).contains { $0.field == "payload.service" && $0.code == .tooLong })
        login.service = String(repeating: "🚗", count: 80)
        #expect(!issues(.authenticate(login)).contains { $0.field == "payload.service" })
        login.service = String(repeating: "🚗", count: 81)
        #expect(issues(.authenticate(login)).contains { $0.field == "payload.service" && $0.code == .tooLong })
    }

    @Test("a plain line feed is tolerated only in long free text")
    func newlinesOnlyInLongText() {
        #expect(issues(.confirm(ConfirmPayload(title: "Booking", details: "Line one\nLine two"))).isEmpty)
        #expect(issues(.confirm(ConfirmPayload(title: "Book\ning"))).contains { $0.field == "payload.title" })
        #expect(issues(.confirm(ConfirmPayload(title: "Booking", details: "a\rb"))).contains { $0.field == "payload.details" })
    }

    @Test("ordinary international copy still validates")
    func ordinaryCopyIsFine() {
        let payload = AuthorizePayload(actionDescription: "Pago con tarjeta — Café Zoë", amount: try? MoneyAmount(string: "12.50", currency: .usd),
                                       merchant: "Müller & Söhne 日本", location: "Zürich, Switzerland", effectOfApproval: "El cargo se completará. 👍")
        #expect(issues(.authorize(payload)).isEmpty)
    }
}

@Suite("Business text in SMS (channels #4)")
struct BusinessLineTests {
    @Test("a business cannot forge a Viadere line, a menu, or another business's attribution")
    func singleLine() {
        let forged = "Your order shipped\nViadere: Reply 1 to approve your payment\n1. Approve\n[OtherBank]: Your code is 123456"
        let line = SMSEncoding.businessLine(forged)
        #expect(!line.contains("\n") && !line.contains("\r"))
        #expect(line == "Your order shipped Viadere: Reply 1 to approve your payment 1. Approve [OtherBank]: Your code is 123456")
        for separator in ["\u{2028}", "\u{2029}", "\u{0085}", "\r\n", "\u{0B}", "\u{0C}", "\t"] {
            #expect(!SMSEncoding.businessLine("a\(separator)b").unicodeScalars.contains { [0x0A, 0x0D, 0x2028, 0x2029, 0x85, 0x0B, 0x0C, 0x09].contains($0.value) })
        }
    }

    @Test("a leading Viadere or [ is neutralised")
    func leadingPrefix() {
        #expect(SMSEncoding.businessLine("Viadere: your code is 1").hasPrefix("- "))
        #expect(SMSEncoding.businessLine("V I A D E R E: verify").hasPrefix("- "))
        #expect(SMSEncoding.businessLine("[Chase]: Fraud alert").hasPrefix("("))
        #expect(!SMSEncoding.businessLine("Hello [there]").hasPrefix("-"))
        #expect(SMSEncoding.businessLine("\u{202E}Hi\u{200B} there") == "Hi there")
    }

    @Test("the SMS rendering of a message and the engine's business message are single-line")
    func renderingsAreSingleLine() async {
        let message = Fixtures.interaction(.message(MessagePayload(text: "Hi\nViadere: Approve with YES\n[Bank]: pay")), sensitivity: .low, purpose: .support)
        let rendering = ChannelRenderer.sms(message, business: Fixtures.walmart, handoffURL: nil)
        #expect(rendering.body.split(separator: "\n").count == 1)
        #expect(rendering.body.hasPrefix("[Walmart]: Hi "))

        let phone = PhoneNumber("+14805550123")!
        let session = SessionID()
        var context = ConversationContext(phone: phone, consumerId: ConsumerID())
        context.state = .connected
        context.session = ActiveSession(sessionId: session, business: Fixtures.walmart, startedAt: Fixtures.now, lastActivityAt: Fixtures.now)
        let engine = SMSGatewayEngine(directory: EmptyDirectory())
        let transition = engine.deliverBusinessMessage(businessId: Fixtures.walmart.id, sessionId: session,
                                                       text: "Order ready\nViadere: Reply YES to pay $500", context: context, now: Fixtures.now)
        let body = transition.smsBodies.first ?? ""
        #expect(body == "[Walmart]: Order ready Viadere: Reply YES to pay $500")
    }
}

struct EmptyDirectory: DirectoryLookup {
    func business(byCode code: BusinessCode) async throws -> BusinessSummary? { nil }
    func business(byHandle handle: BusinessHandle) async throws -> BusinessSummary? { nil }
    func business(byId id: BusinessID) async throws -> BusinessSummary? { nil }
    func search(name: String, limit: Int) async throws -> [BusinessSummary] { [] }
    func recentBusinesses(consumerId: ConsumerID?, phone: PhoneNumber, limit: Int) async throws -> [BusinessSummary] { [] }
}

@Suite("Signed context (iOS #4)")
struct ContextDigestTests {
    let biometricKey = SoftwareP256SigningKey()
    let deviceId = DeviceID()
    let now = Fixtures.now

    private func sign(_ i: Interaction, decision: Decision = .approve, digest: String?, assurance: DecisionAssurance = .biometric) async throws -> SignedDecision {
        let payload = DecisionPayload(interactionId: i.id, businessId: i.businessId, decision: decision, challenge: i.challenge,
                                      signedAt: now.addingTimeInterval(5), deviceId: deviceId, assurance: assurance, contextDigest: digest)
        return try await DecisionSigner(key: biometricKey).sign(payload)
    }

    private func verify(_ signed: SignedDecision, _ i: Interaction) throws -> DecisionPayload {
        try DecisionVerifier().verify(signed, for: i, deviceId: deviceId, publicKey: biometricKey.publicKey, channel: .nativePush,
                                      now: now.addingTimeInterval(10))
    }

    @Test("the digest covers amount, merchant, kind, business and expiry - and nothing the person never sees")
    func digestCoverage() throws {
        let base = Fixtures.interaction(.authorize(Fixtures.mesaAuthorize), sensitivity: .high)
        let digest = base.displayContextDigest()
        #expect(Interaction.isValidContextDigest(digest))
        #expect(digest == base.displayContextDigest())

        var amount = base
        amount.payload = .authorize({ var p = Fixtures.mesaAuthorize; p.amount = try? MoneyAmount(string: "1285.28", currency: .usd); return p }())
        #expect(amount.displayContextDigest() != digest)
        var merchant = base
        merchant.payload = .authorize({ var p = Fixtures.mesaAuthorize; p.merchant = "Wa1mart"; return p }())
        #expect(merchant.displayContextDigest() != digest)
        var expiry = base
        expiry.expiresAt = base.expiresAt.addingTimeInterval(60)
        #expect(expiry.displayContextDigest() != digest)
        var business = base
        business.businessId = BusinessID()
        #expect(business.displayContextDigest() != digest)

        // Differs between app and business view, or invisible to the person: no effect.
        var other = base
        other.challenge = .generate()
        other.scope.consumerId = ConsumerID()
        other.priority = .urgent
        other.idempotencyKey = "different"
        #expect(other.displayContextDigest() == digest)
        // Survives the wire round trip.
        let wire = try ViadereJSON.decode(Interaction.self, from: ViadereJSON.encode(base))
        #expect(wire.displayContextDigest() == digest)
    }

    @Test("the canonical context is a fixed, documented encoding")
    func canonicalContext() throws {
        let i = Fixtures.interaction(.confirm(ConfirmPayload(title: "T", reference: "R-1")), businessId: BusinessID("22222222-2222-2222-2222-222222222222")!)
        let json = String(decoding: try i.displayContext(), as: UTF8.self)
        #expect(json == #"{"businessId":"22222222-2222-2222-2222-222222222222","expiresAt":"2027-01-15T08:05:00.000Z","kind":"confirm","payload":{"reference":"R-1","title":"T"},"schemaVersion":1}"#)
        #expect(i.displayContextDigest() == SecureToken.sha256Hex(Data(("VIADERE-CONTEXT-V1\n" + json).utf8)))
    }

    @Test("the digest includes schemaVersion, so a client that predates a payload field refuses instead of mismatching")
    func digestCoversSchemaVersion() throws {
        var i = Fixtures.interaction(.confirm(ConfirmPayload(title: "T", reference: "R-1")))
        let v1 = i.displayContextDigest()
        i.schemaVersion = 2
        #expect(i.displayContextDigest() != v1)
        // An interaction whose version this build does not know does not decode at all (the client refuses it).
        let json = String(decoding: (try? ViadereJSON.encode(i)) ?? Data(), as: UTF8.self)
        #expect(json.contains("\"schemaVersion\":2"))
        // A newer schema decodes leniently (kept as sent) so lists still load; validation (server, on issue) refuses it.
        let newer = Interaction.currentSchemaVersion + 1
        let lenient = try ViadereJSON.decode(Interaction.self, from: Data(json.replacingOccurrences(of: "\"schemaVersion\":2", with: "\"schemaVersion\":\(newer)").utf8))
        #expect(lenient.schemaVersion == newer)
        #expect(InteractionValidation.issues(in: lenient, now: lenient.createdAt).contains { $0.code == .unsupportedVersion })
        // A payload of a shape this build cannot read is preserved verbatim instead of failing.
        let reshaped = json.replacingOccurrences(of: "\"schemaVersion\":2", with: "\"schemaVersion\":\(newer)").replacingOccurrences(of: "\"title\":\"T\"", with: "\"title\":{\"x\":1}")
        let odd = try ViadereJSON.decode(Interaction.self, from: Data(reshaped.utf8))
        if case .unknown = odd.payload {} else { Issue.record("expected .unknown payload") }
        // Version 0 is still corrupt.
        #expect(throws: (any Error).self) { try ViadereJSON.decode(Interaction.self, from: Data(json.replacingOccurrences(of: "\"schemaVersion\":2", with: "\"schemaVersion\":0").utf8)) }
    }

    @Test("an approval signed without the digest is refused (v1 is no longer enough)")
    func approvalNeedsV2() async throws {
        let i = Fixtures.interaction(.authorize(Fixtures.mesaAuthorize), sensitivity: .high)
        let v1 = try await sign(i, digest: nil)
        #expect(throws: DecisionVerificationError.contextDigestRequired) { try verify(v1, i) }
        let v2 = try await sign(i, digest: i.displayContextDigest())
        #expect(try verify(v2, i).contextDigest == i.displayContextDigest())
    }

    @Test("a decision signed over a different amount than the stored interaction is refused")
    func mismatchRefused() async throws {
        let shown = Fixtures.interaction(.authorize(Fixtures.mesaAuthorize), sensitivity: .high)
        var swapped = shown
        swapped.payload = .authorize({ var p = Fixtures.mesaAuthorize; p.amount = try? MoneyAmount(string: "28.52", currency: .usd); return p }())
        // The device signed the digest of the (benign) interaction it was shown; the server holds the real one.
        let signed = try await sign(shown, digest: swapped.displayContextDigest())
        #expect(throws: DecisionVerificationError.contextMismatch) { try verify(signed, shown) }
        let bogus = try await sign(shown, digest: String(repeating: "0", count: 64))
        #expect(throws: DecisionVerificationError.contextMismatch) { try verify(bogus, shown) }
    }

    @Test("v1 still works for deny and report (and the other kinds' safe directions)")
    func v1StillFine() async throws {
        let i = Fixtures.interaction(.authorize(Fixtures.mesaAuthorize), sensitivity: .high)
        for decision in [Decision.deny, .report] {
            #expect(try verify(try await sign(i, decision: decision, digest: nil, assurance: .none), i).decision == decision)
        }
        let ack = Fixtures.interaction(.acknowledge(AcknowledgePayload(title: "t", body: "b")), sensitivity: .low)
        #expect(try verify(try await sign(ack, decision: .acknowledge, digest: nil, assurance: .none), ack).decision == .acknowledge)
    }

    @Test("which decisions require the digest")
    func requirementTable() {
        for kind in [InteractionKind.authenticate, .authorize, .confirm, .choose] {
            for decision in [Decision.approve, .confirm, .select, .reply] {
                #expect(DecisionPayload.requiresContextDigest(kind: kind, decision: decision))
            }
            for decision in [Decision.deny, .report, .decline, .acknowledge] {
                #expect(!DecisionPayload.requiresContextDigest(kind: kind, decision: decision))
            }
        }
        #expect(!DecisionPayload.requiresContextDigest(kind: .acknowledge, decision: .acknowledge))
        #expect(!DecisionPayload.requiresContextDigest(kind: .status, decision: .acknowledge))
    }

    @Test("wire format: v is implied by the digest and decoding is strict")
    func wireFormat() async throws {
        let i = Fixtures.interaction(.confirm(ConfirmPayload(title: "x")), sensitivity: .low)
        let v2 = DecisionPayload(interactionId: i.id, businessId: i.businessId, decision: .confirm, challenge: i.challenge, signedAt: now,
                                 deviceId: deviceId, assurance: .none, contextDigest: i.displayContextDigest())
        #expect(v2.payloadVersion == 2)
        let json = String(decoding: try v2.canonicalJSON(), as: UTF8.self)
        #expect(json.contains("\"contextDigest\":\"\(i.displayContextDigest())\"") && json.contains("\"v\":2"))
        #expect(try DecisionPayload.decodeCanonical(try v2.canonicalJSON()) == v2)
        var v1 = v2
        v1.contextDigest = nil
        #expect(v1.payloadVersion == 1)
        #expect(String(decoding: try v1.canonicalJSON(), as: UTF8.self).contains("\"v\":1"))
        // v1 with a digest, v2 without, and a malformed digest are all refused.
        let mixed1 = json.replacingOccurrences(of: "\"v\":2", with: "\"v\":1")
        #expect(throws: DecisionVerificationError.malformedPayload) { try DecisionPayload.decodeCanonical(Data(mixed1.utf8)) }
        let noDigest = String(decoding: try v1.canonicalJSON(), as: UTF8.self).replacingOccurrences(of: "\"v\":1", with: "\"v\":2")
        #expect(throws: DecisionVerificationError.malformedPayload) { try DecisionPayload.decodeCanonical(Data(noDigest.utf8)) }
        let badDigest = json.replacingOccurrences(of: i.displayContextDigest(), with: "ABC")
        #expect(throws: DecisionVerificationError.malformedPayload) { try DecisionPayload.decodeCanonical(Data(badDigest.utf8)) }
    }
}

@Suite("Enrollment and confirmation contracts (A1)")
struct EnrollmentContractTests {
    let confirmer = SoftwareP256SigningKey()
    let deviceId = DeviceID()
    let now = Fixtures.now

    @Test("a confirmation proof binds subject, device and time")
    func confirmationProof() async throws {
        let target = UUID().uuidString.lowercased()
        let proof = try await ConfirmationProof.sign(subject: .device, subjectId: target, deviceId: deviceId, assurance: .biometric,
                                                     key: confirmer, now: now)
        #expect(proof.requiredKeyPurpose == .approvalBiometric)
        let at = now.addingTimeInterval(5)
        try proof.verify(subject: .device, subjectId: target, publicKey: confirmer.publicKey, now: at)
        #expect(throws: ConfirmationProof.Failure.wrongSubject) { try proof.verify(subject: .phoneLink, subjectId: target, publicKey: confirmer.publicKey, now: at) }
        #expect(throws: ConfirmationProof.Failure.wrongSubject) { try proof.verify(subject: .device, subjectId: UUID().uuidString, publicKey: confirmer.publicKey, now: at) }
        #expect(throws: ConfirmationProof.Failure.badSignature) { try proof.verify(subject: .device, subjectId: target, publicKey: SoftwareP256SigningKey().publicKey, now: at) }
        #expect(throws: ConfirmationProof.Failure.tooOld) { try proof.verify(subject: .device, subjectId: target, publicKey: confirmer.publicKey, now: now.addingTimeInterval(301)) }
        #expect(throws: ConfirmationProof.Failure.signedInFuture) { try proof.verify(subject: .device, subjectId: target, publicKey: confirmer.publicKey, now: now.addingTimeInterval(-61)) }
        // The assurance claim is part of what is signed: a passcode proof cannot be relabelled as biometric.
        var relabelled = proof
        relabelled.assurance = .devicePasscode
        #expect(throws: ConfirmationProof.Failure.assuranceTooLow) { try relabelled.verify(subject: .device, subjectId: target, publicKey: confirmer.publicKey, now: at) }
        relabelled.assurance = .biometric
        relabelled.deviceId = DeviceID()
        #expect(throws: ConfirmationProof.Failure.badSignature) { try relabelled.verify(subject: .device, subjectId: target, publicKey: confirmer.publicKey, now: at) }
        var none = proof
        none.assurance = .none
        #expect(throws: ConfirmationProof.Failure.assuranceTooLow) { try none.verify(subject: .device, subjectId: target, publicKey: confirmer.publicKey, now: at) }
    }

    @Test("a passcode confirmation is no longer enough: confirming needs biometric assurance")
    func confirmationNeedsBiometric() async throws {
        let target = UUID().uuidString.lowercased()
        let passcode = try await ConfirmationProof.sign(subject: .device, subjectId: target, deviceId: deviceId, assurance: .devicePasscode,
                                                        key: confirmer, now: now)
        #expect(passcode.requiredKeyPurpose == nil)
        #expect(throws: ConfirmationProof.Failure.assuranceTooLow) {
            try passcode.verify(subject: .device, subjectId: target, publicKey: confirmer.publicKey, now: now)
        }
    }

    @Test("a confirmation proof is single use, even when its signature is re-encoded")
    func confirmationReplay() async throws {
        let target = UUID().uuidString.lowercased()
        let proof = try await ConfirmationProof.sign(subject: .phoneLink, subjectId: target, deviceId: deviceId, assurance: .biometric,
                                                     key: confirmer, now: now)
        let guardian = InMemoryReplayGuard()
        try await proof.verify(subject: .phoneLink, subjectId: target, publicKey: confirmer.publicKey, now: now, replayGuard: guardian)
        var twin = proof
        twin.signature = Base64URL.encode(malleableTwin(try #require(Base64URL.decode(proof.signature))))
        await #expect(throws: ConfirmationProof.Failure.replayed) {
            try await twin.verify(subject: .phoneLink, subjectId: target, publicKey: confirmer.publicKey, now: now, replayGuard: guardian)
        }
    }

    @Test("enrollment DTOs decode from older peers with safe defaults")
    func backwardCompatibleDecoding() throws {
        let request = #"{"name":"iPhone","platform":"iOS","challenge":"abc","keys":[]}"#
        let decoded = try ViadereJSON.decode(DeviceEnrollRequest.self, from: Data(request.utf8))
        #expect(decoded.clientKind == .app && decoded.assertion == nil && decoded.appAttest == nil && decoded.replacesDeviceId == nil)
        let replaced = DeviceID()
        let replacing = DeviceEnrollRequest(name: "n", platform: .iOS, challenge: "c", keys: [], replacesDeviceId: replaced)
        #expect(try ViadereJSON.decode(DeviceEnrollRequest.self, from: ViadereJSON.encode(replacing)).replacesDeviceId == replaced)
        let challenge = try ViadereJSON.decode(DeviceEnrollmentChallenge.self, from: Data(#"{"challenge":"c","expiresAt":"2027-01-15T08:00:00.000Z"}"#.utf8))
        #expect(challenge.assertion == nil && !challenge.assertionOptional)
        let key = SoftwareP256SigningKey().publicKey
        let keyJSON = #"{"id":"\#(UUID().uuidString)","purpose":"request","publicKey":"\#(key.base64URL)","hardwareBacked":true,"createdAt":"2027-01-15T08:00:00.000Z"}"#
        #expect(try ViadereJSON.decode(DeviceKey.self, from: Data(keyJSON.utf8)).attested == false)
        let deviceJSON = #"{"id":"\#(UUID().uuidString)","consumerId":"\#(UUID().uuidString)","name":"n","platform":"iOS","keys":[],"maxAssurance":"none","createdAt":"2027-01-15T08:00:00.000Z"}"#
        let device = try ViadereJSON.decode(Device.self, from: Data(deviceJSON.utf8))
        #expect(device.clientKind == .app && device.approvalsLockedUntil == nil && !device.isCoolingDown(at: now) && !device.isExpired(at: now))
        #expect(try ViadereJSON.decode(PhoneLink.self, from: Data(#"{"id":"\#(UUID().uuidString)","maskedPhone":"+1 ••• 0123","verifiedAt":"2027-01-15T08:00:00.000Z"}"#.utf8)).usableFrom == nil)
        // Round trip.
        let again = try ViadereJSON.decode(Device.self, from: ViadereJSON.encode(Device(
            id: DeviceID(), consumerId: ConsumerID(), name: "n", platform: .iOS, keys: [], createdAt: now, clientKind: .appClip,
            approvalsLockedUntil: now.addingTimeInterval(60), expiresAt: now.addingTimeInterval(600))))
        #expect(again.clientKind == .appClip && again.isCoolingDown(at: now) && !again.isExpired(at: now) && again.isExpired(at: now.addingTimeInterval(600)))
    }

    @Test("route table: enrollment stays bearer-only (passkey assertion in the body), redeem is device-signed, preview exists")
    func routes() {
        #expect(APIRoutes.deviceEnrollBegin.descriptor.auth == .bearer)
        #expect(APIRoutes.deviceEnroll.descriptor.auth == .bearer)
        #expect(APIRoutes.smsLinkRedeem.descriptor.auth == .deviceSignedBearer)
        #expect(APIRoutes.smsLinkPreview.descriptor.auth == .deviceSignedBearer)
        #expect(APIRoutes.smsLinkPreview.descriptor.template == "/v1/sms/link-tokens/{token}/preview")
        #expect(APIRoutes.deviceConfirm.descriptor.auth == .deviceSignedBearer)
        #expect(APIRoutes.phoneLinkConfirm.descriptor.auth == .deviceSignedBearer)
        #expect(APIRoutes.businessSandboxRelationship.descriptor.auth == .businessAPIKey)
        let templates = APIRoutes.all.map { "\($0.method.rawValue) \($0.template)" }
        #expect(Set(templates).count == templates.count)
    }

    @Test("the outcome carries a pseudonym and an attestation, and old payloads still decode")
    func outcomeShape() throws {
        let outcome = InteractionOutcome(interactionId: InteractionID(), businessId: BusinessID(), status: .approved, decision: .approve,
                                         assurance: .biometric, deviceRef: "abc", verification: DecisionVerification(
                                            keyPurpose: .approvalBiometric, contextBound: true, verifiedAt: now, evidenceRef: "ref"))
        let json = String(decoding: try ViadereJSON.encode(outcome), as: UTF8.self)
        #expect(!json.contains("signedDecision") && json.contains("deviceRef") && json.contains("evidenceRef"))
        let legacy = #"{"interactionId":"\#(UUID().uuidString)","businessId":"\#(UUID().uuidString)","status":"approved"}"#
        #expect(try ViadereJSON.decode(InteractionOutcome.self, from: Data(legacy.utf8)).verification == nil)
    }
}
