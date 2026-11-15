import Crypto
import Foundation
import Testing
import ViadereCore
@testable import ViadereBusinessSDK

/// "Verify with Viadere" in the business SDK: the server-side session calls verify Viadere's signed result themselves, and the iOS button's
/// hand-off and QR-first panel (pure Swift) follow the owner's rule. The SwiftUI/UIKit views are Apple-only and compiled in Xcode.
@Suite("Verify with Viadere (business SDK)")
struct VerifyButtonSDKTests {
    static let now = Date(timeIntervalSince1970: 1_800_000_000)
    let business = BusinessID()
    let viadere = SoftwareP256SigningKey()
    let sessionId = UUID()
    let subject = SubjectRef("sub_" + Base64URL.encode(Data(repeating: 7, count: 32)))!
    let origin = "https://shop.northwind.example"

    var repo: URL { URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent() }

    // MARK: Session link

    @Test func onlyAViadereSessionLinkMakesAButtonSession() throws {
        let session = try #require(VerifyButtonSession(link: "https://viadere.com/v/K7QFM2XA", expiresAt: Self.now))
        #expect(session.code == "K7QFM2XA")
        #expect(session.displayCode == "K7QF-M2XA")
        #expect(session.spokenCode == "K 7 Q F M 2 X A")
        #expect(session.qrPayload == "https://viadere.com/v/K7QFM2XA")
        #expect(session.isExpired(at: Self.now))
        #expect(!session.isExpired(at: Self.now.addingTimeInterval(-1)))
        #expect(VerifyButtonSession(link: "https://viadere.cksites.dev/v/K7QFM2XA") != nil, "staging")
        for bad in ["https://evil.test/v/K7QFM2XA", "http://viadere.com/v/K7QFM2XA", "https://viadere.com/v/K7QFM2XA?next=evil", "https://viadere.com/v/K7QFM2XA#x",
                    "https://viadere.com/k/K7QFM2XA", "https://viadere.com/v/k7qfm2xa", "https://www.viadere.com/v/K7QFM2XA", "viadere://v/K7QFM2XA", ""] {
            #expect(VerifyButtonSession(link: bad) == nil, "\(bad)")
        }
        #expect(VerifyButtonSession(link: "https://viadere.cksites.dev/v/K7QFM2XA", allowedDomains: [.production]) == nil, "the integrator can narrow the domains")
        let ticket = VerificationSessionTicket(sessionId: sessionId, code: "K7QFM2XA", link: "https://viadere.com/v/K7QFM2XA", expiresAt: Self.now)
        #expect(VerifyButtonSession(ticket: ticket)?.expiresAt == Self.now)
        let lying = VerificationSessionTicket(sessionId: sessionId, code: "AAAAAAAA", link: "https://viadere.com/v/K7QFM2XA", expiresAt: Self.now)
        #expect(VerifyButtonSession(ticket: lying) == nil)
    }

    // MARK: Hand-off rule

    @Test func phonesHandOffAndComputersShowTheQRFirst() throws {
        let session = try #require(VerifyButtonSession(link: "https://viadere.com/v/K7QFM2XA", expiresAt: Self.now.addingTimeInterval(300)))
        #expect(VerifyHandoffPlanner.onTap(device: .handheld, session: session, now: Self.now) == .openInApp(session.link))
        #expect(VerifyHandoffPlanner.onTap(device: .computer, session: session, now: Self.now) == .showPanel)
        #expect(VerifyHandoffPlanner.afterOpenInApp(opened: true) == .handedOff)
        #expect(VerifyHandoffPlanner.afterOpenInApp(opened: false) == .showPanel, "app not installed: the QR-first panel, with Get the app")
        #expect(VerifyHandoffPlanner.onTap(device: .handheld, session: session, now: Self.now.addingTimeInterval(301)) == .expired)
    }

    @Test func thePanelStartsWithTheQRAndOffersTheOtherOptions() throws {
        let session = try #require(VerifyButtonSession(link: "https://viadere.com/v/K7QFM2XA"))
        var panel = VerifyPanelState(session: session, sendToPhone: false)
        #expect(panel.screen == .qr)
        #expect(panel.options == [.openOnThisDevice, .enterCode, .getApp])
        #expect(panel.select(.sendToPhone) == .none, "not offered, not possible")
        panel.chooseAnotherOption()
        #expect(panel.screen == .options)
        #expect(panel.select(.openOnThisDevice) == .open(session.link))
        #expect(panel.select(.getApp) == .open(session.link), "the landing page carries the store link (or opens the app once installed)")
        #expect(panel.select(.enterCode) == .none)
        #expect(panel.showsCode)
        #expect(panel.status == "Your code is K 7 Q F M 2 X A.")
        panel.backToQR()
        #expect(panel.screen == .qr && !panel.showsCode && panel.status == nil)
        #expect(panel.close() == .dismiss)

        var withPhone = VerifyPanelState(session: session, sendToPhone: true)
        #expect(withPhone.options == [.openOnThisDevice, .enterCode, .sendToPhone, .getApp])
        #expect(withPhone.select(.sendToPhone) == .sendToPhone)
        #expect(withPhone.status == "Check your phone for a notification from Viadere.")
    }

    @Test func theButtonMatchesTheBrandAndTheWebButton() throws {
        #expect(VerifyButtonFlow.verify.label == "Verify with Viadere")
        #expect(VerifyButtonSize.medium.height == 44)
        #expect(VerifyButtonSize.allCases.allSatisfy { $0.minimumHitTarget >= 44 })
        let css = try String(contentsOf: repo.appendingPathComponent("Server/Public/verify-button/v1/viadere-verify.css"), encoding: .utf8).uppercased()
        for variant in VerifyButtonVariant.allCases {
            for dark in [false, true] {
                let colors = VerifyButtonColors.of(variant, dark: dark)
                for hex in [colors.background, colors.foreground, colors.border].compactMap({ $0 }) {
                    #expect(css.contains(String(format: "#%06X", hex)), "\(variant) \(dark): \(String(format: "#%06X", hex)) is in the web stylesheet")
                }
            }
        }
        // The mark is the brand artwork, path for path.
        let svg = try String(contentsOf: repo.appendingPathComponent("Design/svg/viadere-mark-mono-dark.svg"), encoding: .utf8)
        let paths = svg.matches(of: /d="([^"]+)"/).map { String($0.output.1) }
        #expect(paths == [VerifyButtonMark.backFaces] + VerifyButtonMark.frontFaces)
        for path in paths { #expect((VerifyButtonMark.commands(path)?.count ?? 0) > 3) }
        #expect(VerifyButtonMark.commands("M0 0L1 1Q2 2 3 3") == nil, "only the subset the artwork uses")
        #expect(VerifyButtonMark.commands("M1-2L3 4Z") == [.move(1, -2), .line(3, 4), .close])
    }

    // MARK: Server side: sessions and the signed result

    func signedResult(outcome: VerificationOutcome = .verified, ref: VerificationResultRef, signer: SoftwareP256SigningKey? = nil,
                      origin: String? = nil) async throws -> ViadereSignedStatement {
        let key = signer ?? viadere
        let kid = KeyIdentifier.make(try key.publicKey.signingKey())
        let result = VerificationSessionResult(sessionId: sessionId, businessId: business, requestId: VerificationRequestID(), subject: subject, capability: .ageMinimum,
                                               parameters: ["years": .integer(21)], purposeCode: "age_restricted_purchase", origin: origin ?? self.origin,
                                               outcome: outcome, resultRef: ref, completedAt: Self.now)
        let signed = try await SignedStatement.sign(result.object(signerKid: kid), domain: VerificationSessionDomainSeparator.result, with: key)
        return ViadereSignedStatement(kid: kid, payload: signed.payload, signature: signed.signature)
    }

    func view(status: VerificationSessionStatus = .completed, result: ViadereSignedStatement?, ref: VerificationResultRef?) -> VerificationSessionView {
        VerificationSessionView(sessionId: sessionId, status: status, capability: .ageMinimum, purposeCode: "age_restricted_purchase", origin: origin, createdAt: Self.now,
                                expiresAt: Self.now.addingTimeInterval(300), requestId: VerificationRequestID(), subjectRef: subject, resultRef: ref, result: result,
                                completedAt: Self.now)
    }

    @Test func aTicketWithAnotherHostIsRefusedAndCancelled() async throws {
        let request = CreateVerificationSessionRequest(capability: .ageMinimum, parameters: ["years": .integer(21)], purposeCode: "age_restricted_purchase", origin: origin)
        let good = MockTransport()
        try good.enqueue(status: 201, json: VerificationSessionTicket(sessionId: sessionId, code: "K7QFM2XA", link: "https://viadere.com/v/K7QFM2XA", expiresAt: Self.now))
        let ticket = try await Fixtures.client(good).createVerificationSession(request)
        #expect(ticket.code == "K7QFM2XA")
        #expect(good.requests.first?.url.path == "/v1/business/verification-sessions")
        for link in ["https://evil.test/v/K7QFM2XA", "https://viadere.com/v/K7QFM2XA?x=1", "https://viadere.com/v/AAAAAAAA"] {
            let transport = MockTransport()
            try transport.enqueue(status: 201, json: VerificationSessionTicket(sessionId: sessionId, code: "K7QFM2XA", link: link, expiresAt: Self.now))
            try transport.enqueue(status: 200, json: view(status: .cancelled, result: nil, ref: nil))
            await #expect(throws: VerificationSessionFailure.ticketMismatch) { try await Fixtures.client(transport).createVerificationSession(request) }
            #expect(transport.requests.last?.url.path == "/v1/business/verification-sessions/\(sessionId.uuidString.lowercased())/cancel")
        }
    }

    @Test func theBusinessTrustsOnlyAResultItVerifiedItself() async throws {
        let ref = VerificationResultRef.generate()
        func verified(_ v: VerificationSessionView, origin: String? = nil) async throws -> VerifiedVerificationSession {
            let transport = MockTransport()
            try transport.enqueue(status: 200, json: v)
            return try await Fixtures.client(transport).verifiedVerificationSession(id: sessionId, businessId: business, origin: origin ?? self.origin, capability: .ageMinimum,
                                                                                    viadereKeys: [viadere.publicKey])
        }
        let ok = try await verified(view(result: try await signedResult(ref: ref), ref: ref))
        #expect(ok.outcome == .verified)
        #expect(ok.subjectRef == subject)
        #expect(ok.resultRef == ref)
        await #expect(throws: VerificationSessionFailure.notCompleted(.accepted)) { try await verified(view(status: .accepted, result: nil, ref: nil)) }
        // A relay (or anyone) signing its own "verified".
        await #expect(throws: VerificationSessionFailure.resultInvalid(.untrustedSigner)) {
            try await verified(view(result: try await signedResult(ref: ref, signer: SoftwareP256SigningKey()), ref: ref))
        }
        // A genuine result from another of the business's origins is not this button's.
        await #expect(throws: VerificationSessionFailure.resultInvalid(.wrongOrigin)) {
            try await verified(view(result: try await signedResult(ref: ref, origin: "https://other.northwind.example"), ref: ref))
        }
        await #expect(throws: VerificationSessionFailure.resultRefMismatch) {
            try await verified(view(result: try await signedResult(ref: ref), ref: VerificationResultRef.generate()))
        }
    }
}
