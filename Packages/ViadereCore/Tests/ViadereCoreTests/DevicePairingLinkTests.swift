import Foundation
import Testing
@testable import ViadereCore

/// The QR form of a pairing code (SECURITY.md §2.107): exactly `https://{link domain}/p/{XXXX-XXXX-XXXX}`.
@Suite("Device pairing link (/p/{code})")
struct DevicePairingLinkTests {
    let domain = LinkDomain("viadere.com")!

    @Test func buildsAndParsesOnlyTheExactForm() throws {
        for _ in 0..<50 {
            let code = DevicePairingCode.generate()
            let link = try #require(DevicePairingLink.build(code: code, domain: domain))
            #expect(link == "https://viadere.com/p/\(code)")
            #expect(DevicePairingLink.parse(link, domain: domain) == code)
            #expect(DevicePairingCode.normalize(code) != nil)
        }
    }

    @Test func refusesEverythingElse() {
        let good = "https://viadere.com/p/AB12-CD34-EF56"
        #expect(DevicePairingLink.parse(good, domain: domain) == "AB12-CD34-EF56")
        let refused = [
            // Lookalike and other hosts, the www alias, scheme, port, user info.
            "https://viadere.com.evil.example/p/AB12-CD34-EF56", "https://evil.example/p/AB12-CD34-EF56", "https://www.viadere.com/p/AB12-CD34-EF56",
            "https://viadere.co/p/AB12-CD34-EF56", "https://vladere.com/p/AB12-CD34-EF56", "https://VIADERE.com/p/AB12-CD34-EF56",
            "http://viadere.com/p/AB12-CD34-EF56", "https://viadere.com:443/p/AB12-CD34-EF56", "https://user@viadere.com/p/AB12-CD34-EF56",
            // Extra path, query, fragment.
            "https://viadere.com/p/AB12-CD34-EF56/", "https://viadere.com/p/AB12-CD34-EF56/x", "https://viadere.com/x/p/AB12-CD34-EF56",
            "https://viadere.com/P/AB12-CD34-EF56", "https://viadere.com/p/AB12-CD34-EF56?x=1", "https://viadere.com/p/AB12-CD34-EF56#x",
            "https://viadere.com/p/AB12-CD34-EF56?", "https://viadere.com/p/AB12-CD34-EF56#",
            // Case, length, dashes, letters outside the alphabet, encodings, spaces.
            "https://viadere.com/p/ab12-cd34-ef56", "https://viadere.com/p/AB12-CD34-Ef56", "https://viadere.com/p/AB12-CD34-EF5",
            "https://viadere.com/p/AB12-CD34-EF567", "https://viadere.com/p/AB12CD34EF56", "https://viadere.com/p/AB1-2CD34-EF56",
            "https://viadere.com/p/AB12-CD34-EFI6", "https://viadere.com/p/AB12-CD34-EFO6", "https://viadere.com/p/AB12-CD34-EFL6",
            "https://viadere.com/p/AB12-CD34-EFU6", "https://viadere.com/p/AB12 CD34 EF56", "https://viadere.com/p/AB12-CD34-EF5%36",
            "https://viadere.com/p/AB12-CD34-ÉF56", " https://viadere.com/p/AB12-CD34-EF56", "https://viadere.com/p/AB12-CD34-EF56 ",
            "https://viadere.com/p/", "",
        ]
        for text in refused { #expect(DevicePairingLink.parse(text, domain: domain) == nil, "\(text)") }
        #expect(DevicePairingLink.build(code: "ab12-cd34-ef56", domain: domain) == nil)
        #expect(DevicePairingLink.build(code: "AB12CD34EF56", domain: domain) == nil)
        // Another build's link domain is refused.
        #expect(DevicePairingLink.parse(good, domain: LinkDomain("viadere.cksites.dev")!) == nil)
    }
}
