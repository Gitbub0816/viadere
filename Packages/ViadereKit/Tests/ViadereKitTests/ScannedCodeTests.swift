import Testing
import Foundation
import ViadereCore
@testable import ViadereKit

/// The camera reads whatever is put in front of it. `ScannedCodePolicy` is the only thing between a scan and the app, so every case here is
/// an attack or a mistake that must end in "nothing was opened".
@Suite("Scanned codes")
struct ScannedCodeTests {
    static let ach = "ach_AAECAwQFBgcICQoLDA0ODw"

    private func decide(_ payload: String, _ symbology: ScannedSymbology = .ckey) -> ScannedCodeDecision {
        ScannedCodePolicy.evaluate(payload, symbology: symbology, domain: .production)
    }

    @Test func theSignInCodeOpensTheSignInReviewFromEitherSymbology() {
        let link = OIDCChallengeLink.build(challengeId: Self.ach, domain: .production)
        #expect(decide(link, .ckey) == .open(.oidcSignIn(challengeId: Self.ach)))
        #expect(decide(link, .qr) == .open(.oidcSignIn(challengeId: Self.ach)))
    }

    @Test func everyPrintedLinkKindOpensItsReviewScreen() {
        #expect(decide("https://viadere.com/v/K7QFM2XA") == .open(.verificationSession(code: "K7QFM2XA")))
        guard case .open(.connect(let code, let link)) = decide("https://viadere.com/c/AF2345", .qr) else { Issue.record("expected connect"); return }
        #expect(code.canonical == "AF2345")
        #expect(link != nil)
    }

    @Test func otherWebsitesAndLookalikesOpenNothing() {
        for payload in [
            "https://evil.example/o/\(Self.ach)",
            "https://viadere.com.evil.example/o/\(Self.ach)",
            "https://viadere.com@evil.example/o/\(Self.ach)",
            "https://evil.example@viadere.com/o/\(Self.ach)",
            "https://viadere.com:8443/o/\(Self.ach)",
            "https://viadere.com/o/\(Self.ach)?next=https://evil.example",
            "https://viadere.com/o/\(Self.ach)#x",
            "https://viadere.com/o/\(Self.ach)/extra",
            "https://viadere.com/o/ach_short",
            "https://viadere.com/",
            "https://viadere.com/unknown/\(Self.ach)",
            "http://viadere.com/o/\(Self.ach)",
            "HTTPS://viadere.com/o/\(Self.ach)",
            " https://viadere.com/o/\(Self.ach)",
            "https://viadere.com/o/\(Self.ach) ",
            "https://viadere.cksites.dev/o/\(Self.ach)",  // staging links are not production links
            "https://viad\u{0435}re.com/o/\(Self.ach)",   // Cyrillic e
        ] {
            #expect(decide(payload, .ckey) == .rejected(.notViadere), "\(payload)")
            #expect(decide(payload, .qr) == .rejected(.notViadere), "\(payload)")
        }
    }

    @Test func noOtherSchemeIsFollowedIncludingTheAppsOwn() {
        for payload in [
            "viadere://settings", "viadere://c/AF2345", "viadere://i/00000000-0000-0000-0000-000000000000", "viadere://m/00000000-0000-0000-0000-000000000000",
            "javascript:alert(1)", "data:text/html,<script>1</script>", "file:///etc/passwd", "tel:+15551234567", "sms:+15551234567", "mailto:a@b.example",
            "otpauth://totp/x?secret=AAAA", "viadere-vault://pair?c=x", "itms-services://?action=download-manifest", "intent://x#Intent;end",
        ] {
            #expect(decide(payload, .ckey) == .rejected(.notViadere), "\(payload)")
            #expect(decide(payload, .qr) == .rejected(.notViadere), "\(payload)")
        }
    }

    @Test func aSafeActionNeverRunsHoweverItIsSpelled() {
        // A genuine envelope from the CKey vectors (valid cross-device sign-in for `com.viadere`): still refused, because a code never acts by itself here.
        let genuine = "ckey-action:1:AQELY2l0ZW9yeS5jb20LY29tLnZpYWRlcmUOc2lnbmluLnJlcXVlc3QHMjAyNi0xMRJzZXNzLTQxZmQwYTliZTJjNzQAAAAAau5EYgAAAABq7kTaAAACHa8IJgHKEekWl1IdGliWpiUHh2XxNxnxhSm2S6cTYMkSroRnqeoR2B1OOzpEervNy2wJgYYKO5vXooio3S0L"
        #expect(decide(genuine, .ckey) == .rejected(.automaticAction))
        #expect(decide(genuine, .qr) == .rejected(.automaticAction))
        #expect(decide("CKEY-ACTION:1:AAAA") == .rejected(.automaticAction))
        #expect(decide("ckey-action:2:AAAA") == .rejected(.automaticAction))
    }

    @Test func retiredTextLinksAreNamedAndNeverRedeemed() {
        let token = String(repeating: "A", count: 43)
        #expect(decide("https://viadere.com/l/\(token)") == .rejected(.retired))
        #expect(decide("https://viadere.com/h/\(token)", .qr) == .rejected(.retired))
    }

    @Test func oversizedEmptyAndControlCharacterPayloadsStopBeforeAnyParser() {
        #expect(decide("") == .rejected(.malformed))
        #expect(decide("https://viadere.com/o/" + String(repeating: "A", count: 600)) == .rejected(.malformed))
        #expect(decide(String(repeating: "é", count: 257)) == .rejected(.malformed))  // 514 bytes
        for scalar in ["\u{0}", "\n", "\r", "\t", "\u{1B}", "\u{7F}", "\u{85}"] {
            #expect(decide("https://viadere.com/o/\(Self.ach)\(scalar)") == .rejected(.malformed))
            #expect(decide("\(scalar)@northwind", .qr) == .rejected(.malformed))
        }
    }

    @Test func aPrintedHandleOrCodeIsLookedUpOnlyFromAQRCode() {
        #expect(decide("@northwind", .qr) == .lookup("@northwind"))
        #expect(decide("AF2345", .qr) == .lookup("AF2345"))
        // A Viadere code (CKey) always carries a link; bare text in one is not ours.
        #expect(decide("@northwind", .ckey) == .rejected(.notViadere))
        #expect(decide("AF2345", .ckey) == .rejected(.notViadere))
        // A business name or free text is never searched from a scan.
        #expect(decide("Northwind Traders", .qr) == .rejected(.notViadere))
        #expect(decide("WIFI:S:cafe;T:WPA;P:secret;;", .qr) == .rejected(.notViadere))
    }

    @Test func refusalMessagesNeverRepeatTheScannedText() {
        for reason in [ScanRejection.notViadere, .retired, .automaticAction, .malformed] {
            #expect(!reason.message.isEmpty)
            #expect(!reason.message.contains("http"))
        }
    }
}
