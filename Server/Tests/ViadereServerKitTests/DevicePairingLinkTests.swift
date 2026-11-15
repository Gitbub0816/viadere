import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// The pairing code's QR universal link (`/p/{code}`, SECURITY.md §2.107): the app owns `/p/*`; the browser fallback looks nothing up, starts
/// nothing and never shows the code back; a code in a log line is masked whole.
final class DevicePairingLinkTests: XCTestCase {
    func testTheWebFallbackLooksNothingUpAndTheAppOwnsThePath() async throws {
        try await withHarness { h in
            let a = try await h.deviceFirstConsumer()
            let code = try await h.pairingCode(a)
            let link = try XCTUnwrap(DevicePairingLink.build(code: code, domain: h.config.linkDomain))
            XCTAssertTrue(link.hasSuffix("/p/\(code)"))
            let landing = try await h.request(.GET, "/p/\(code)")
            XCTAssertEqual(landing.status, .ok)
            XCTAssertTrue(landing.text.contains("Nothing was added here."))
            XCTAssertFalse(landing.text.contains(code), "the code is never repeated")
            // The page read nothing: the code is still open and nothing was started or audited beyond the invitation.
            try await eq(try await h.auditActions(prefix: "device_pairing."), ["device_pairing.invited"])
            let b = try await h.startPairing(code: code)
            XCTAssertEqual(b.result.status, .created, b.result.text)

            let aasa = try await h.request(.GET, "/.well-known/apple-app-site-association")
            XCTAssertTrue(aasa.text.contains("\"/p/*\""))
        }
    }

    func testAPairingCodeIsRedactedWholeInLogs() {
        let code = DevicePairingCode.generate()
        let line = LogRedactor.redact("GET /p/\(code) 200")
        XCTAssertFalse(line.contains(String(code.suffix(4))), line)
        XCTAssertEqual(line, "GET /p/[redacted-code] 200")
        // The shorter shapes are unchanged.
        XCTAssertEqual(LogRedactor.redact("invite ABCD-EFGH"), "invite [redacted-code]")
    }
}
