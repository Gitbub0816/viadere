import Crypto
import Testing
import Foundation
import ViadereCore
@testable import ViadereKit

/// The camera reads whatever is put in front of it. `ScannedCodePolicy` is the only thing between a scan and the app, so every case here is
/// an attack or a mistake that must end in "nothing was opened".
@Suite("Scanned codes")
struct ScannedCodeTests {
    static let ach = "ach_AAECAwQFBgcICQoLDA0ODw"
    /// A genuine envelope from the CKey vectors: a valid cross-device sign-in for `com.viadere` from `citeory.com`, under its own key.
    static let foreignSafeAction = "ckey-action:1:AQELY2l0ZW9yeS5jb20LY29tLnZpYWRlcmUOc2lnbmluLnJlcXVlc3QHMjAyNi0xMRJzZXNzLTQxZmQwYTliZTJjNzQAAAAAau5EYgAAAABq7kTaAAACHa8IJgHKEekWl1IdGliWpiUHh2XxNxnxhSm2S6cTYMkSroRnqeoR2B1OOzpEervNy2wJgYYKO5vXooio3S0L"

    private func decide(_ payload: String, _ symbology: ScannedSymbology = .ckey) -> ScannedCodeDecision {
        ScannedCodePolicy.evaluate(payload, symbology: symbology, domain: .production)
    }

    @Test func theSignInCodeOpensTheSignInReviewFromEitherSymbology() {
        let link = OIDCChallengeLink.build(challengeId: Self.ach, domain: .production)
        #expect(decide(link, .ckey) == .open(.oidcSignIn(challengeId: Self.ach)))
        #expect(decide(link, .qr) == .open(.oidcSignIn(challengeId: Self.ach)))
    }

    @Test func everyPrintedLinkKindOpensItsReviewScreen() {
        #expect(decide("https://viadere.io/v/K7QFM2XA") == .open(.verificationSession(code: "K7QFM2XA")))
        guard case .open(.connect(let code, let link)) = decide("https://viadere.io/c/AF2345", .qr) else { Issue.record("expected connect"); return }
        #expect(code.canonical == "AF2345")
        #expect(link != nil)
    }

    @Test func otherWebsitesAndLookalikesOpenNothing() {
        for payload in [
            "https://evil.example/o/\(Self.ach)",
            "https://viadere.io.evil.example/o/\(Self.ach)",
            "https://viadere.io@evil.example/o/\(Self.ach)",
            "https://evil.example@viadere.io/o/\(Self.ach)",
            "https://viadere.io:8443/o/\(Self.ach)",
            "https://viadere.io/o/\(Self.ach)?next=https://evil.example",
            "https://viadere.io/o/\(Self.ach)#x",
            "https://viadere.io/o/\(Self.ach)/extra",
            "https://viadere.io/o/ach_short",
            "https://viadere.io/",
            "https://viadere.io/unknown/\(Self.ach)",
            "http://viadere.io/o/\(Self.ach)",
            "HTTPS://viadere.io/o/\(Self.ach)",
            " https://viadere.io/o/\(Self.ach)",
            "https://viadere.io/o/\(Self.ach) ",
            "https://staging.viadere.io/o/\(Self.ach)",  // staging links are not production links
            "https://viad\u{0435}re.io/o/\(Self.ach)",   // Cyrillic e
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

    @Test func aSafeActionIsOnlyHandedOnWhenItIsAnExactWellFormedSignInSizedEnvelope() throws {
        let world = SafeActionWorld()
        let code = try world.code()
        // A well-formed envelope is handed to the reader, unverified, from either symbology. The gate decides nothing about it.
        #expect(decide(code, .ckey) == .safeAction(code))
        #expect(decide(code, .qr) == .safeAction(code))
        // Even a genuine envelope for another site and app (from the CKey vectors) is only handed on: the reader refuses it (below).
        #expect(decide(Self.foreignSafeAction) == .safeAction(Self.foreignSafeAction))
        // Every other spelling is refused on the spot and never reaches the reader or the network.
        let tail = String(code.dropFirst(14))
        for payload in ["CKEY-ACTION:1:" + tail, "Ckey-Action:1:" + tail, "ckey-action:2:" + tail, "ckey-action:1:", "ckey-action:",
                        "ckey-action:1:AAAA", "ckey-action:01:" + tail, code + "=", code + "A", String(code.dropLast()), code + "?x=1",
                        "ckey-action:1:" + String(repeating: "A", count: 200)] {
            #expect(decide(payload, .ckey) == .rejected(.unverifiedAction), "\(payload.prefix(24))")
            #expect(decide(payload, .qr) == .rejected(.unverifiedAction), "\(payload.prefix(24))")
        }
        #expect(decide(" " + code) == .rejected(.notViadere), "a leading space is not the prefix, and it is not a Viadere link either")
        #expect(decide(code + "\n") == .rejected(.malformed))
    }

    @Test func theByteCapIsRaisedOnlyForASafeActionAndOnlyToASignInEnvelopesSize() throws {
        // viadere.io: 262 bytes covers the longest sign-in envelope (a 32-character key id) and nothing longer.
        #expect(ScannedCodePolicy.maxSafeActionBytes(domain: .production) == 262)
        let world = SafeActionWorld()
        let longest = try CKeySafeAction(scope: .crossDevice, issuer: "viadere.io", app: "com.viadere.app", action: "signin.request", keyId: String(repeating: "k", count: 32),
                                         requestId: SafeActionWorld.ach, issuedAt: 1_794_000_000, expiresAt: 1_794_000_120).signed(with: world.issuerKey)
        #expect(longest.utf8.count == 262)
        #expect(decide(longest) == .safeAction(longest))
        // A well-formed, correctly signed envelope that is larger than any sign-in (it carries parameters) is refused before the reader.
        let padded = try CKeySafeAction(scope: .crossDevice, issuer: "viadere.io", app: "com.viadere.app", action: "signin.request", keyId: "2026-11",
                                        requestId: SafeActionWorld.ach, issuedAt: 1_794_000_000, expiresAt: 1_794_000_120, params: Data(repeating: 0x20, count: 40))
            .signed(with: world.issuerKey)
        #expect(padded.utf8.count > 262 && padded.utf8.count <= 512)
        #expect(decide(padded) == .rejected(.unverifiedAction))
        // A long link domain raises the cap for its own Safe Actions only; links and everything else stay at 512.
        let long = try #require(LinkDomain(String(repeating: "a", count: 63) + "." + String(repeating: "b", count: 63) + "." + String(repeating: "c", count: 63) + ".example"))
        #expect(ScannedCodePolicy.maxSafeActionBytes(domain: long) > 512)
        let big = try CKeySafeAction(scope: .crossDevice, issuer: long.host, app: "com.viadere.app", action: "signin.request", keyId: String(repeating: "k", count: 32),
                                     requestId: SafeActionWorld.ach, issuedAt: 1_794_000_000, expiresAt: 1_794_000_120).signed(with: world.issuerKey)
        #expect(big.utf8.count > 512 && big.utf8.count == ScannedCodePolicy.maxSafeActionBytes(domain: long))
        #expect(ScannedCodePolicy.evaluate(big, symbology: .ckey, domain: long) == .safeAction(big))
        #expect(ScannedCodePolicy.evaluate("https://\(long.host)/o/" + String(repeating: "A", count: 500), symbology: .ckey, domain: long) == .rejected(.malformed))
        #expect(ScannedCodePolicy.evaluate(String(repeating: "A", count: 513), symbology: .qr, domain: long) == .rejected(.malformed))
        #expect(decide(big) == .rejected(.malformed), "the production cap is unchanged by another domain's")
    }

    @Test func retiredTextLinksAreNamedAndNeverRedeemed() {
        let token = String(repeating: "A", count: 43)
        #expect(decide("https://viadere.io/l/\(token)") == .rejected(.retired))
        #expect(decide("https://viadere.io/h/\(token)", .qr) == .rejected(.retired))
    }

    @Test func oversizedEmptyAndControlCharacterPayloadsStopBeforeAnyParser() {
        #expect(decide("") == .rejected(.malformed))
        #expect(decide("https://viadere.io/o/" + String(repeating: "A", count: 600)) == .rejected(.malformed))
        #expect(decide(String(repeating: "é", count: 257)) == .rejected(.malformed))  // 514 bytes
        for scalar in ["\u{0}", "\n", "\r", "\t", "\u{1B}", "\u{7F}", "\u{85}"] {
            #expect(decide("https://viadere.io/o/\(Self.ach)\(scalar)") == .rejected(.malformed))
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
        for reason in [ScanRejection.notViadere, .retired, .unverifiedAction, .malformed] {
            #expect(!reason.message.isEmpty)
            #expect(!reason.message.contains("http"))
        }
    }
}

@Suite("Scanner hand-off")
@MainActor
struct ScannerHandOffTests {
    @Test func anAcceptedCodeClosesTheScannerAndOpensItsReviewOnlyWhenDelivered() async throws {
        let (services, _) = await p3World()
        let model = AppModel(services: services)
        await model.bootstrap()
        model.scannerPresented = true
        let link = OIDCChallengeLink.build(challengeId: ScannedCodeTests.ach, domain: .current)
        #expect(model.scanned(link, symbology: .ckey) == nil)
        #expect(!model.scannerPresented)
        #expect(model.pendingOIDCSignIn == nil, "nothing is presented over the closing camera")
        await model.deliverScanned()
        #expect(model.pendingOIDCSignIn?.challengeId == ScannedCodeTests.ach)
        // Delivered once.
        model.pendingOIDCSignIn = nil
        await model.deliverScanned()
        #expect(model.pendingOIDCSignIn == nil)
    }

    @Test func aRefusedCodeChangesNothingAndKeepsTheScannerOpen() async throws {
        let (services, _) = await p3World()
        let model = AppModel(services: services)
        await model.bootstrap()
        model.scannerPresented = true
        #expect(model.scanned("https://evil.example/o/\(ScannedCodeTests.ach)", symbology: .ckey) == .notViadere)
        #expect(model.scanned("viadere://settings", symbology: .qr) == .notViadere)
        #expect(model.scannerPresented)
        #expect(model.scannedDecision == nil)
        await model.deliverScanned()
        #expect(model.pendingOIDCSignIn == nil && model.selectedTab == .alerts && !model.addBusinessPresented)
    }

    /// A signed-in world whose reader pins `world`'s issuer key and asks `world`'s scripted issuer host.
    private func model(_ world: SafeActionWorld, keys: [PinnedSafeActionKey]? = nil) async -> AppModel {
        var (services, _) = await p3World(now: SafeActionWorld.now)
        services.safeActionReader = world.reader(keys: keys)
        let model = AppModel(services: services)
        await model.bootstrap()
        model.scannerPresented = true
        return model
    }

    @Test func aVerifiedSafeActionOpensOnlyTheSignInReviewAndApprovesNothing() async throws {
        let world = SafeActionWorld(issuer: LinkDomain.current.host)
        let model = await model(world)
        let code = try world.code()
        #expect(model.scanned(code, symbology: .ckey) == nil)
        #expect(!model.scannerPresented)
        #expect(model.pendingOIDCSignIn == nil && world.transport.requests.isEmpty, "nothing is verified, fetched or presented over the closing camera")
        await model.deliverScanned()
        let pending = try #require(model.pendingOIDCSignIn)
        #expect(pending.challengeId == SafeActionWorld.ach)
        #expect(pending.safeAction == VerifiedSafeActionRequest(issuer: world.issuer, requestId: SafeActionWorld.ach, device: "Chrome on Windows",
                                                                requestedAt: Date(timeIntervalSince1970: 1_794_082_443)))
        #expect(model.toast == nil)
        // The only request was the issuer's request information: no statement was fetched, nothing was signed, nothing was submitted.
        #expect(world.transport.requests.map(\.url.path) == ["/ckey/requests/\(SafeActionWorld.ach)"])
        // Delivered once, and the same code never opens a second review.
        model.pendingOIDCSignIn = nil
        await model.deliverScanned()
        #expect(model.pendingOIDCSignIn == nil)
        model.scannerPresented = true
        #expect(model.scanned(code, symbology: .qr) == nil)
        await model.deliverScanned()
        #expect(model.pendingOIDCSignIn == nil)
        #expect(model.toast == SafeActionRejection.alreadyUsed.message)
    }

    @Test func aSafeActionThatDoesNotVerifyOpensNothing() async throws {
        let world = SafeActionWorld(issuer: LinkDomain.current.host)
        let cases: [(String, [PinnedSafeActionKey]?, SafeActionRejection)] = [
            (try world.code(), [], .unknownKey),                                                             // unpinned
            (ScannedCodeTests.foreignSafeAction, nil, .wrongApp),                                            // a genuine code for another app and site
            (try world.code(app: "com.example.other"), nil, .wrongApp),                                      // foreign app, our key
            (try world.code(action: "signin.approve"), nil, .notAccepted),                                   // wrong action
            (try world.code(scope: .sameDevice), nil, .notAccepted),                                         // would run without a prompt
            (try world.code(issuedAt: SafeActionWorld.now.addingTimeInterval(-600)), nil, .expired),         // expired
            (try world.code(lifetime: 3600), nil, .expired),                                                 // too long-lived
            (try world.code(key: P256.Signing.PrivateKey()), nil, .signature),                         // forged
        ]
        for (code, keys, reason) in cases {
            let model = await model(world, keys: keys)
            #expect(model.scanned(code, symbology: .ckey) == nil, "\(reason)")
            await model.deliverScanned()
            #expect(model.pendingOIDCSignIn == nil, "\(reason)")
            #expect(model.toast == reason.message, "\(reason)")
            #expect(model.selectedTab == .alerts && !model.addBusinessPresented && model.presentedApproval == nil, "\(reason)")
        }
        #expect(world.transport.requests.isEmpty, "an unverified code never reaches the issuer")

        // Tampered after signing (one bit of the signature): the envelope still parses, the signature no longer matches.
        var characters = Array(try world.code())
        let index = characters.count - 20
        characters[index] = characters[index] == "A" ? "B" : "A"
        let tampered = await model(world)
        #expect(tampered.scanned(String(characters), symbology: .ckey) == nil)
        await tampered.deliverScanned()
        #expect(tampered.pendingOIDCSignIn == nil)
        #expect(tampered.toast == SafeActionRejection.signature.message)
        #expect(world.transport.requests.isEmpty)

        // Verified, but the issuer does not confirm a pending request (or cannot be reached): nothing opens.
        let adjustments: [@Sendable (SafeActionWorld) -> Void] = [{ $0.info.offline = true }, { $0.info.status = 404 },
                                                                  { $0.info.body = SafeActionWorld.infoBody(status: "approved") }]
        for adjust in adjustments {
            let unconfirmed = SafeActionWorld(issuer: LinkDomain.current.host)
            adjust(unconfirmed)
            let model = await model(unconfirmed)
            #expect(model.scanned(try unconfirmed.code(), symbology: .ckey) == nil)
            await model.deliverScanned()
            #expect(model.pendingOIDCSignIn == nil)
            #expect(model.toast?.hasPrefix(SafeActionRejection.sentence) == true)
        }
    }

    @Test func aMalformedSafeActionIsRefusedInTheScannerAndABuildWithoutAReaderOpensNothing() async throws {
        let world = SafeActionWorld(issuer: LinkDomain.current.host)
        let model = await model(world)
        #expect(model.scanned("ckey-action:1:AAAA", symbology: .ckey) == .unverifiedAction)
        #expect(model.scanned("CKEY-ACTION:1:" + (try world.code()).dropFirst(14), symbology: .qr) == .unverifiedAction)
        #expect(model.scannerPresented && model.scannedDecision == nil)
        // No reader (App Clip, extensions, a build that has none): refused with the fixed sentence.
        let (services, _) = await p3World()
        let bare = AppModel(services: services)
        await bare.bootstrap()
        #expect(bare.scanned(try world.code(), symbology: .ckey) == nil)
        await bare.deliverScanned()
        #expect(bare.pendingOIDCSignIn == nil)
        #expect(bare.toast == SafeActionRejection.notReady.message)
        #expect(world.transport.requests.isEmpty)
    }

    @Test func aSafeActionIsNeverQueuedBehindTheAppLock() async throws {
        let world = SafeActionWorld(issuer: LinkDomain.current.host)
        let model = await model(world)
        #expect(model.scanned(try world.code(), symbology: .ckey) == nil)
        model.lock()
        await model.deliverScanned()
        #expect(model.pendingOIDCSignIn == nil)
        #expect(model.toast == SafeActionRejection.notReady.message)
        #expect(world.transport.requests.isEmpty)
        // Unlocking later does not bring it back.
        await model.unlock()
        #expect(model.pendingOIDCSignIn == nil)
    }

    @Test func aPrintedHandleOpensAddBusinessWithTheLookup() async throws {
        let (services, _) = await p3World()
        let model = AppModel(services: services)
        await model.bootstrap()
        #expect(model.scanned("@northwind", symbology: .qr) == nil)
        await model.deliverScanned()
        #expect(model.scannedLookup == "@northwind" && model.addBusinessPresented && model.selectedTab == .businesses)
    }
}
