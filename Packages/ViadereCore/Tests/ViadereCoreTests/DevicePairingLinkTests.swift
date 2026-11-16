import Foundation
import Testing
@testable import ViadereCore

/// The QR form of a pairing code (SECURITY.md §2.107): exactly `https://{link domain}/p/{XXXX-XXXX-XXXX}`.
@Suite("Device pairing link (/p/{code})")
struct DevicePairingLinkTests {
    let domain = LinkDomain("viadere.io")!

    @Test func buildsAndParsesOnlyTheExactForm() throws {
        for _ in 0..<50 {
            let code = DevicePairingCode.generate()
            let link = try #require(DevicePairingLink.build(code: code, domain: domain))
            #expect(link == "https://viadere.io/p/\(code)")
            #expect(DevicePairingLink.parse(link, domain: domain) == code)
            #expect(DevicePairingCode.normalize(code) != nil)
        }
    }

    @Test func refusesEverythingElse() {
        let good = "https://viadere.io/p/AB12-CD34-EF56"
        #expect(DevicePairingLink.parse(good, domain: domain) == "AB12-CD34-EF56")
        let refused = [
            // Lookalike and other hosts, the www alias, scheme, port, user info.
            "https://viadere.io.evil.example/p/AB12-CD34-EF56", "https://evil.example/p/AB12-CD34-EF56", "https://www.viadere.io/p/AB12-CD34-EF56",
            "https://viadere.co/p/AB12-CD34-EF56", "https://vladere.io/p/AB12-CD34-EF56", "https://VIADERE.io/p/AB12-CD34-EF56",
            "http://viadere.io/p/AB12-CD34-EF56", "https://viadere.io:443/p/AB12-CD34-EF56", "https://user@viadere.io/p/AB12-CD34-EF56",
            // Extra path, query, fragment.
            "https://viadere.io/p/AB12-CD34-EF56/", "https://viadere.io/p/AB12-CD34-EF56/x", "https://viadere.io/x/p/AB12-CD34-EF56",
            "https://viadere.io/P/AB12-CD34-EF56", "https://viadere.io/p/AB12-CD34-EF56?x=1", "https://viadere.io/p/AB12-CD34-EF56#x",
            "https://viadere.io/p/AB12-CD34-EF56?", "https://viadere.io/p/AB12-CD34-EF56#",
            // Case, length, dashes, letters outside the alphabet, encodings, spaces.
            "https://viadere.io/p/ab12-cd34-ef56", "https://viadere.io/p/AB12-CD34-Ef56", "https://viadere.io/p/AB12-CD34-EF5",
            "https://viadere.io/p/AB12-CD34-EF567", "https://viadere.io/p/AB12CD34EF56", "https://viadere.io/p/AB1-2CD34-EF56",
            "https://viadere.io/p/AB12-CD34-EFI6", "https://viadere.io/p/AB12-CD34-EFO6", "https://viadere.io/p/AB12-CD34-EFL6",
            "https://viadere.io/p/AB12-CD34-EFU6", "https://viadere.io/p/AB12 CD34 EF56", "https://viadere.io/p/AB12-CD34-EF5%36",
            "https://viadere.io/p/AB12-CD34-ÉF56", " https://viadere.io/p/AB12-CD34-EF56", "https://viadere.io/p/AB12-CD34-EF56 ",
            "https://viadere.io/p/", "",
        ]
        for text in refused { #expect(DevicePairingLink.parse(text, domain: domain) == nil, "\(text)") }
        #expect(DevicePairingLink.build(code: "ab12-cd34-ef56", domain: domain) == nil)
        #expect(DevicePairingLink.build(code: "AB12CD34EF56", domain: domain) == nil)
        // Another build's link domain is refused.
        #expect(DevicePairingLink.parse(good, domain: LinkDomain("viadere.cksites.dev")!) == nil)
    }
}
