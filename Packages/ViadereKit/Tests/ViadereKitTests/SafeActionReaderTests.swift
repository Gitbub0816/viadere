import Crypto
import Foundation
import Testing
import ViadereCore
@testable import ViadereKit

/// A world for Safe Action tests: an issuer key, the pin for it, a scripted issuer host and a replay memory.
struct SafeActionWorld {
    static let now = Date(timeIntervalSince1970: 1_794_000_000)
    static let ach = "ach_AAECAwQFBgcICQoLDA0ODw"

    /// ES256, like Viadere's issuer (the authority's Key Vault key).
    let issuerKey = P256.Signing.PrivateKey()
    let issuer: String
    let keyId = "2026-11"
    let replay: any SafeActionReplayStore
    let info: Box
    let transport: FakeTransport

    /// What the issuer host answers; mutable so a test can change it between scans.
    final class Box: @unchecked Sendable {
        private let lock = NSLock()
        private var _status = 200
        private var _body = Data()
        private var _offline = false
        var status: Int { get { lock.lock(); defer { lock.unlock() }; return _status } set { lock.lock(); _status = newValue; lock.unlock() } }
        var body: Data { get { lock.lock(); defer { lock.unlock() }; return _body } set { lock.lock(); _body = newValue; lock.unlock() } }
        var offline: Bool { get { lock.lock(); defer { lock.unlock() }; return _offline } set { lock.lock(); _offline = newValue; lock.unlock() } }
    }

    init(issuer: String = "viadere.com", replay: any SafeActionReplayStore = InMemorySafeActionReplayStore()) {
        self.issuer = issuer
        self.replay = replay
        let box = Box()
        box.body = Self.infoBody()
        info = box
        transport = FakeTransport { _, _ in
            if box.offline { throw APIError.transport("offline") }
            return HTTPResponse(status: box.status, body: box.body)
        }
    }

    static func infoBody(requestId: String = ach, device: String? = "Chrome on Windows", location: String? = nil, requestedAt: String? = "2026-11-07T20:14:03Z",
                         status: String = "pending") -> Data {
        var object: [String: String] = ["request_id": requestId, "status": status]
        object["device"] = device
        object["location"] = location
        object["requested_at"] = requestedAt
        return try! JSONSerialization.data(withJSONObject: object)
    }

    var pin: PinnedSafeActionKey { PinnedSafeActionKey(issuer: issuer, keyId: keyId, publicKey: .es256(issuerKey.publicKey)) }

    func reader(appId: String = "com.viadere.app", keys: [PinnedSafeActionKey]? = nil, clock: @escaping @Sendable () -> Date = { SafeActionWorld.now }) -> SafeActionReader {
        SafeActionReader(appId: appId, issuer: issuer, keys: keys ?? [pin], replay: replay, transport: transport, clock: clock)
    }

    func code(scope: CKeySafeAction.Scope = .crossDevice, issuer: String? = nil, app: String = "com.viadere.app", action: String = "signin.request", keyId: String? = nil,
              requestId: String = ach, issuedAt: Date = now, lifetime: UInt64 = 120, params: Data = Data(), key: P256.Signing.PrivateKey? = nil) throws -> String {
        let issued = UInt64(issuedAt.timeIntervalSince1970)
        return try CKeySafeAction(scope: scope, issuer: issuer ?? self.issuer, app: app, action: action, keyId: keyId ?? self.keyId, requestId: requestId,
                                  issuedAt: issued, expiresAt: issued + lifetime, params: params).signed(with: key ?? issuerKey)
    }
}

/// The spec's "What a reader must do", step by step. Every failure must end in "nothing was opened" and no request to the issuer
/// unless the code itself verified.
@Suite("Safe Action reader")
struct SafeActionReaderTests {
    typealias World = SafeActionWorld

    @Test func aVerifiedSignInCodeYieldsOnlyAPendingConfirmationWithWhoIsAsking() async throws {
        let world = World()
        world.info.body = World.infoBody(location: "United States")
        let outcome = await world.reader().read(try world.code())
        #expect(outcome == .needsConfirmation(VerifiedSafeActionRequest(issuer: "viadere.com", requestId: World.ach, device: "Chrome on Windows", location: "United States",
                                                                        requestedAt: Date(timeIntervalSince1970: 1_794_082_443))))
        // One request, to the issuer's own host over https, naming only the challenge: no session, no device signature, no cookie.
        let requests = world.transport.requests
        #expect(requests.count == 1)
        #expect(requests.first?.url.absoluteString == "https://viadere.com/ckey/requests/\(World.ach)")
        #expect(requests.first?.method == .GET)
        #expect(requests.first?.headers == ["Accept": "application/json"])
        #expect(requests.first?.body == nil)
    }

    @Test func aPayloadWithoutThePrefixIsNotASafeAction() async throws {
        let world = World()
        #expect(await world.reader().read("https://viadere.com/o/\(World.ach)") == .notASafeAction)
        #expect(await world.reader().read("CKEY-ACTION:1:AAAA") == .notASafeAction)
        #expect(await world.reader().read("") == .notASafeAction)
        #expect(world.transport.requests.isEmpty)
    }

    @Test func onlyPinnedKeysAreTrustedAndNoneIsFetched() async throws {
        let world = World()
        let code = try world.code()
        // No pins at all (a build that has none), a pin under another key id, a pin for another issuer.
        #expect(await world.reader(keys: []).read(code) == .rejected(.unknownKey))
        #expect(await world.reader(keys: [PinnedSafeActionKey(issuer: "viadere.com", keyId: "2025-01", publicKey: world.pin.publicKey)]).read(code) == .rejected(.unknownKey))
        #expect(await world.reader(keys: [PinnedSafeActionKey(issuer: "citeory.com", keyId: world.keyId, publicKey: world.pin.publicKey)]).read(code) == .rejected(.unknownKey))
        // A genuine envelope from the CKey vectors, valid for `citeory.com` under its own key: not this app, not this issuer.
        let foreign = "ckey-action:1:AQELY2l0ZW9yeS5jb20LY29tLnZpYWRlcmUOc2lnbmluLnJlcXVlc3QHMjAyNi0xMRJzZXNzLTQxZmQwYTliZTJjNzQAAAAAau5EYgAAAABq7kTaAAACHa8IJgHKEekWl1IdGliWpiUHh2XxNxnxhSm2S6cTYMkSroRnqeoR2B1OOzpEervNy2wJgYYKO5vXooio3S0L"
        #expect(await world.reader().read(foreign) == .rejected(.wrongApp))
        // Never a key lookup on the network, and never a request for an unverified code.
        #expect(world.transport.requests.isEmpty)
    }

    @Test func aForgedOrAlteredCodeFailsTheSignature() async throws {
        let world = World()
        // Signed by someone else under the pinned key id.
        #expect(await world.reader().read(try world.code(key: P256.Signing.PrivateKey())) == .rejected(.signature))
        // The high-S twin of the genuine signature (valid ECDSA, refused by CKey readers), and the right envelope under an Ed25519 pin.
        let original = try world.code()
        var raw = [UInt8](try #require(Base64URL.decode(String(original.dropFirst(CKeySafeAction.prefix.count)))))
        let order: [UInt8] = [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                              0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51]
        let s = Array(raw.suffix(32))
        var borrow = 0
        for i in stride(from: 31, through: 0, by: -1) {
            var d = Int(order[i]) - Int(s[i]) - borrow
            if d < 0 { d += 256; borrow = 1 } else { borrow = 0 }
            raw[raw.count - 32 + i] = UInt8(d)
        }
        let highS = CKeySafeAction.prefix + Base64URL.encode(Data(raw))
        #expect(highS != original)
        #expect(await world.reader().read(highS) == .rejected(.signature))
        let edPin = PinnedSafeActionKey(issuer: world.issuer, keyId: world.keyId, publicKey: .ed25519(Curve25519.Signing.PrivateKey().publicKey.rawRepresentation))
        #expect(await world.reader(keys: [edPin]).read(try World().code()) == .rejected(.signature))
        // A genuine code with its request id swapped for another challenge after signing.
        let genuine = try world.code()
        var bytes = Array(Data(base64Encoded: String(genuine.dropFirst(14)).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/"))!)
        let marker = Array("ach_AAEC".utf8)
        let at = try #require(bytes.indices.first { bytes[$0...].starts(with: marker) })
        bytes[at + 4] = UInt8(ascii: "B")
        let altered = "ckey-action:1:" + Data(bytes).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        #expect(await world.reader().read(altered) == .rejected(.signature))
        #expect(await world.reader().read(String(genuine.dropLast(3))) == .rejected(.malformed))
        #expect(world.transport.requests.isEmpty)
    }

    @Test func theAppTheActionTheIssuerTheScopeAndTheParametersMustBeTheRegisteredOnes() async throws {
        let world = World()
        let reader = world.reader()
        #expect(await reader.read(try world.code(app: "com.viadere")) == .rejected(.wrongApp))
        #expect(await reader.read(try world.code(app: "com.viadere.app.Clip")) == .rejected(.wrongApp))
        #expect(await reader.read(try world.code(app: "COM.VIADERE.APP")) == .rejected(.wrongApp))
        #expect(await reader.read(try world.code(action: "open.library")) == .rejected(.notAccepted))
        #expect(await reader.read(try world.code(action: "signin.approve")) == .rejected(.notAccepted))
        // A correctly signed same-device sign-in would run without a prompt in a naive reader: refused.
        #expect(await reader.read(try world.code(scope: .sameDevice)) == .rejected(.notAccepted))
        // The pinned key signing for another site's name.
        #expect(await reader.read(try world.code(issuer: "citeory.com")) == .rejected(.notAccepted))
        #expect(await reader.read(try world.code(issuer: "www.viadere.com")) == .rejected(.notAccepted))
        // Not a challenge id, or carrying parameters the sign-in never has.
        #expect(await reader.read(try world.code(requestId: "sess-41fd0a9be2c74")) == .rejected(.notAccepted))
        #expect(await reader.read(try world.code(params: Data(#"{"approve":true}"#.utf8))) == .rejected(.notAccepted))
        // A reader built for another app id never accepts a code for the Viadere app either.
        #expect(await world.reader(appId: "com.example.other").read(try world.code()) == .rejected(.wrongApp))
        #expect(world.transport.requests.isEmpty)
    }

    @Test func aSignInCodeLivesAtMostTwoMinutesWithToleranceOnlyForASlowClock() async throws {
        let world = World()
        func read(at offset: TimeInterval, lifetime: UInt64 = 120, requestId: String = AuthorityChallengeID.generate()) async throws -> SafeActionOutcome {
            await world.reader(clock: { World.now.addingTimeInterval(offset) }).read(try world.code(requestId: requestId, lifetime: lifetime))
        }
        func accepted(_ outcome: SafeActionOutcome) -> Bool { if case .rejected(let reason) = outcome { return reason != .expired } else { return true } }
        #expect(accepted(try await read(at: 0)))
        #expect(accepted(try await read(at: 119)))
        #expect(try await read(at: 120) == .rejected(.expired))
        #expect(try await read(at: 3600) == .rejected(.expired))
        // The phone's clock is behind the server's by up to two minutes.
        #expect(accepted(try await read(at: -120)))
        #expect(try await read(at: -121) == .rejected(.expired))
        // Longer than a sign-in code may live, even though the spec's general default would allow ten minutes.
        #expect(try await read(at: 0, lifetime: 121) == .rejected(.expired))
        #expect(try await read(at: 0, lifetime: 600) == .rejected(.expired))
        #expect(ViadereSignInSafeAction.lifetimeSeconds == 120)
        #expect(ViadereSignInSafeAction.lifetimeSeconds <= CKeySafeAction.defaultMaxLifetimeSeconds)
    }

    @Test func aRequestIdIsAcceptedOnceEvenAcrossARestart() async throws {
        let preferences = InMemoryPreferences()
        let world = World(replay: PreferencesSafeActionReplayStore(preferences: preferences))
        let code = try world.code()
        guard case .needsConfirmation = await world.reader().read(code) else { Issue.record("expected a confirmation"); return }
        #expect(await world.reader().read(code) == .rejected(.alreadyUsed))
        // A second envelope for the same challenge (another signature, another issue time) is the same request.
        #expect(await world.reader().read(try world.code(issuedAt: World.now.addingTimeInterval(5))) == .rejected(.alreadyUsed))
        // The app restarts: a new store over the same preferences still remembers.
        let restarted = SafeActionReader(appId: "com.viadere.app", issuer: world.issuer, keys: [world.pin],
                                         replay: PreferencesSafeActionReplayStore(preferences: preferences), transport: world.transport, clock: { World.now })
        #expect(await restarted.read(code) == .rejected(.alreadyUsed))
        // The request id itself is not written to disk.
        #expect(preferences.string(.safeActionSeenRequests)?.contains(World.ach) == false)
        #expect(world.transport.requests.count == 1, "a replay never reaches the issuer")
        // A code is remembered even when the issuer could not be asked, so a failed scan cannot be retried into a second attempt.
        let other = AuthorityChallengeID.generate()
        world.info.offline = true
        #expect(await world.reader().read(try world.code(requestId: other)) == .rejected(.requestInfoUnavailable))
        world.info.offline = false
        #expect(await world.reader().read(try world.code(requestId: other)) == .rejected(.alreadyUsed))
    }

    @Test func theReplayMemoryIsBoundedLapsesAndFailsClosed() throws {
        let preferences = InMemoryPreferences()
        let store = PreferencesSafeActionReplayStore(preferences: preferences)
        let now = World.now
        let until = now.addingTimeInterval(240)
        #expect(store.claim(requestId: "a", until: until, now: now))
        #expect(!store.claim(requestId: "a", until: until, now: now))
        #expect(!store.claim(requestId: "a", until: until, now: now.addingTimeInterval(239)))
        // Remembered until expiry + 120 s, then forgotten (the code itself is long dead by then).
        #expect(store.claim(requestId: "a", until: until.addingTimeInterval(240), now: now.addingTimeInterval(240)))
        // Already lapsed: nothing to remember, nothing accepted.
        #expect(!store.claim(requestId: "late", until: now, now: now))
        // Full of live entries: a new one is refused, never an old one forgotten.
        let fresh = PreferencesSafeActionReplayStore(preferences: InMemoryPreferences())
        for index in 0..<PreferencesSafeActionReplayStore.capacity { #expect(fresh.claim(requestId: "id-\(index)", until: until, now: now)) }
        #expect(!fresh.claim(requestId: "one-more", until: until, now: now))
        #expect(!fresh.claim(requestId: "id-0", until: until, now: now))
        #expect(fresh.claim(requestId: "one-more", until: until.addingTimeInterval(300), now: until))
        // Unreadable memory refuses the claim instead of treating everything as unseen.
        preferences.setString("not json", for: .safeActionSeenRequests)
        #expect(!store.claim(requestId: "b", until: until, now: now))
        // A store that drops writes never lets a code through.
        #expect(!PreferencesSafeActionReplayStore(preferences: DroppingPreferences()).claim(requestId: "c", until: until, now: now))
        // The in-memory store used in tests follows the same rules.
        let memory = InMemorySafeActionReplayStore()
        #expect(memory.claim(requestId: "a", until: until, now: now))
        #expect(!memory.claim(requestId: "a", until: until, now: now))
        #expect(memory.claim(requestId: "a", until: until.addingTimeInterval(240), now: until))
    }

    @Test func withoutAPendingAnswerFromTheIssuerNothingOpens() async throws {
        func outcome(_ adjust: (World) -> Void) async throws -> SafeActionOutcome {
            let world = World()
            adjust(world)
            return await world.reader().read(try world.code())
        }
        #expect(try await outcome { $0.info.offline = true } == .rejected(.requestInfoUnavailable))
        #expect(try await outcome { $0.info.status = 404 } == .rejected(.requestInfoUnavailable))
        #expect(try await outcome { $0.info.status = 500 } == .rejected(.requestInfoUnavailable))
        #expect(try await outcome { $0.info.status = 204 } == .rejected(.requestInfoUnavailable))
        #expect(try await outcome { $0.info.body = Data("<html>".utf8) } == .rejected(.requestInfoUnavailable))
        #expect(try await outcome { $0.info.body = Data("{}".utf8) } == .rejected(.requestInfoUnavailable))
        // An answer about another request.
        #expect(try await outcome { $0.info.body = World.infoBody(requestId: AuthorityChallengeID.generate()) } == .rejected(.requestInfoUnavailable))
        for status in ["approved", "denied", "expired", "used", "PENDING", "pending ", ""] {
            #expect(try await outcome { $0.info.body = World.infoBody(status: status) } == .rejected(.notPending), "\(status)")
        }
        // The confirmation must say who is asking: no device line or no time means no confirmation.
        #expect(try await outcome { $0.info.body = World.infoBody(device: nil) } == .rejected(.requestInfoUnavailable))
        #expect(try await outcome { $0.info.body = World.infoBody(device: "\u{200B}\u{202E}") } == .rejected(.requestInfoUnavailable))
        #expect(try await outcome { $0.info.body = World.infoBody(requestedAt: nil) } == .rejected(.requestInfoUnavailable))
        #expect(try await outcome { $0.info.body = World.infoBody(requestedAt: "yesterday") } == .rejected(.requestInfoUnavailable))
        // Over the caps: refused, not cut.
        #expect(try await outcome { $0.info.body = World.infoBody(device: String(repeating: "a", count: 121)) } == .rejected(.requestInfoUnavailable))
        #expect(try await outcome { $0.info.body = World.infoBody(location: String(repeating: "a", count: 121)) } == .rejected(.requestInfoUnavailable))
        #expect(try await outcome { $0.info.body = World.infoBody(requestedAt: "2026-11-07T20:14:03Z" + String(repeating: " ", count: 21)) } == .rejected(.requestInfoUnavailable))
        #expect(try await outcome { $0.info.body = World.infoBody(location: String(repeating: "a", count: 3000)) } == .rejected(.requestInfoUnavailable))
    }

    @Test func requestInformationIsShownOnlyAsSanitizedText() async throws {
        let world = World()
        world.info.body = World.infoBody(device: "Chrome\u{202E} on\nWindows\u{0}", location: "  near\tLagos \u{200B} ")
        guard case .needsConfirmation(let request) = await world.reader().read(try world.code()) else { Issue.record("expected a confirmation"); return }
        #expect(request.device == "Chrome on Windows")
        #expect(request.location == "near Lagos")
        let context = OIDCSafeActionContext(request: request) { _ in "8:14 PM" }
        #expect(context.rows.map(\.label) == ["Requested by", "Device", "Location", "Requested"])
        #expect(context.rows.map(\.value) == ["viadere.com (verified code)", "Chrome on Windows", "near Lagos", "8:14 PM"])
        #expect(context.warning == "Only continue if this is the device you are using right now. Someone may be showing you a code meant for their own session.")
    }

    @Test func refusalsUseFixedWordsAndNeverEchoTheCode() throws {
        #expect(SafeActionRejection.sentence == "This code claims to be a Viadere sign-in but could not be verified. Nothing was opened.")
        for reason in SafeActionRejection.allCases {
            #expect(reason.message.hasPrefix(SafeActionRejection.sentence + " "))
            #expect(!reason.reason.isEmpty)
            #expect(!reason.message.contains("ckey-action") && !reason.message.contains("ach_") && !reason.message.contains("http"))
        }
        #expect(Set(SafeActionRejection.allCases.map(\.reason)).count == SafeActionRejection.allCases.count)
    }

    // MARK: Pins

    @Test func pinsComeFromTheBuildAllOrNothingAndAlwaysForTheBuildsOwnLinkDomain() throws {
        func hexOf(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
        let p256 = P256.Signing.PrivateKey().publicKey
        let compressed = hexOf(p256.compressedRepresentation), uncompressed = hexOf(p256.x963Representation).uppercased()
        let ed = Curve25519.Signing.PrivateKey().publicKey.rawRepresentation
        let edHex = hexOf(ed)
        let key = CKeySafeAction.PublicKey.es256(p256)
        let hex = "ES256:" + compressed
        #expect(SafeActionKeyPins.parse("2026-11:\(hex)", issuer: "viadere.com") == [PinnedSafeActionKey(issuer: "viadere.com", keyId: "2026-11", publicKey: key)])
        #expect(SafeActionKeyPins.parse("2026-11:ES256:\(uncompressed)", issuer: "viadere.com") == [PinnedSafeActionKey(issuer: "viadere.com", keyId: "2026-11", publicKey: key)])
        #expect(SafeActionKeyPins.parse("ed:Ed25519:\(edHex)", issuer: "viadere.com") == [PinnedSafeActionKey(issuer: "viadere.com", keyId: "ed", publicKey: .ed25519(ed))])
        let other = "Ed25519:" + edHex.uppercased()
        #expect(SafeActionKeyPins.parse(" 2026-11:\(hex) , 2027-11:\(other) ", issuer: "viadere.cksites.dev").map(\.keyId) == ["2026-11", "2027-11"])
        #expect(SafeActionKeyPins.parse(" 2026-11:\(hex) , 2027-11:\(other) ", issuer: "viadere.cksites.dev").allSatisfy { $0.issuer == "viadere.cksites.dev" })
        var offCurve = p256.x963Representation
        offCurve[64] ^= 1
        for bad in [nil, "", "   ", "$(VIADERE_CKEY_SAFE_ACTION_KEYS)", hex, compressed, "2026-11:", ":\(hex)", "2026-11:\(compressed)", "2026-11:\(edHex)",
                    "2026-11:\(hex.dropLast())", "2026-11:\(hex)00", "2026-11:\(hex.dropLast())g", "2026-11:ES256:\(hexOf(offCurve))",
                    "2026-11:es256:\(compressed)", "2026-11:ES384:\(compressed)", "2026-11:Ed25519:\(compressed)", "2026-11:ES256:\(edHex)",
                    "2026 11:\(hex)", "2026/11:\(hex)", String(repeating: "k", count: 33) + ":\(hex)", "a:\(hex),a:\(other)", "a:\(hex),", "a:\(hex),b:ES256:nothex",
                    "viadere.com:2026-11:\(hex)", "REPLACE_ME"] as [String?] {
            #expect(SafeActionKeyPins.parse(bad, issuer: "viadere.com").isEmpty, "\(bad ?? "nil")")
        }
        // The issuer is never taken from the setting, and must be a plain DNS name.
        #expect(SafeActionKeyPins.parse("a:\(hex)", issuer: "Viadere.com").isEmpty)
        #expect(SafeActionKeyPins.parse("a:\(hex)", issuer: "localhost").isEmpty)

        // From the Info.plist, for the build's link domain (staging), and empty when the setting is missing.
        let staging = ViadereConfiguration.resolve(info: ["ViadereAPIBaseURL": "https://viadere-api.cksites.dev", "ViadereLinkDomain": "viadere.cksites.dev",
                                                          "ViadereCKeySafeActionKeys": "stg-1:\(hex)"], allowLocalHTTP: false)
        #expect(staging.safeActionKeys == [PinnedSafeActionKey(issuer: "viadere.cksites.dev", keyId: "stg-1", publicKey: key)])
        let production = ViadereConfiguration.resolve(info: ["ViadereLinkDomain": "evil.example", "ViadereCKeySafeActionKeys": "p:\(hex)"], allowLocalHTTP: false)
        #expect(production.safeActionKeys.map(\.issuer) == ["viadere.com"], "production keeps viadere.com whatever the plist says")
        #expect(ViadereConfiguration.resolve(info: [:], allowLocalHTTP: false).safeActionKeys.isEmpty)
        #expect(ViadereConfiguration.production.safeActionKeys.isEmpty)
        // The reader built from a configuration uses its bundle id, link domain and pins.
        let world = SafeActionWorld(issuer: "viadere.cksites.dev")
        var configuration = staging
        configuration.safeActionKeys = [world.pin]
        let reader = SafeActionReader(configuration: configuration, replay: world.replay, transport: world.transport, clock: { SafeActionWorld.now })
        #expect(reader.appId == "com.viadere.app" && reader.issuer == "viadere.cksites.dev" && reader.keys == [world.pin])
    }

    @Test func aReaderIgnoresPinsForAnotherIssuer() async throws {
        let world = World()
        let foreignPin = PinnedSafeActionKey(issuer: "citeory.com", keyId: world.keyId, publicKey: world.pin.publicKey)
        #expect(world.reader(keys: [foreignPin]).keys.isEmpty)
    }
}

/// A preferences store that accepts writes and keeps nothing.
private final class DroppingPreferences: PreferencesStore, @unchecked Sendable {
    func bool(_ key: PreferenceKey) -> Bool { false }
    func setBool(_ value: Bool, for key: PreferenceKey) {}
    func string(_ key: PreferenceKey) -> String? { nil }
    func setString(_ value: String?, for key: PreferenceKey) {}
    func removeAll() {}
}
