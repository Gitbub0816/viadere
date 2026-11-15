@preconcurrency import Crypto
import _CryptoExtras
import Fluent
import Foundation
import NIOHTTP1
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Scripted outbound calls: answers by URL, records every request.
final class ScriptedOutboundHTTP: OutboundHTTP, @unchecked Sendable {
    struct Call: Sendable {
        var url: String
        var headers: [String: String]
        var body: Data?
    }

    private let lock = NSLock()
    private var recorded: [Call] = []
    private let answer: @Sendable (String, Data?) -> (Int, Data)

    init(_ answer: @escaping @Sendable (String, Data?) -> (Int, Data)) { self.answer = answer }

    var calls: [Call] { lock.withLock { recorded } }

    func send(method: NIOHTTP1.HTTPMethod, url: String, headers: [String: String], body: Data?) async throws -> (status: Int, body: Data) {
        lock.withLock { recorded.append(Call(url: url, headers: headers, body: body)) }
        return answer(url, body)
    }
}

/// An FCM provider that records what it is given.
final class RecordingFCMProvider: PushProvider, @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [(PushMessage, PushTarget)] = []
    private var outcome: PushOutcome = .delivered
    var kind: PushRegistration.Provider { .fcm }
    var sent: [(PushMessage, PushTarget)] { lock.withLock { storage } }
    func setOutcome(_ value: PushOutcome) { lock.withLock { outcome = value } }
    func deliver(_ message: PushMessage, to target: PushTarget) async -> PushOutcome {
        lock.withLock {
            storage.append((message, target))
            return outcome
        }
    }
}

/// G26 (push providers, FCM, Android integrity, assetlinks) and G28 (OTLP export). SECURITY.md §2.114.
final class PlatformSeamsTests: XCTestCase {
    static let packageName = "com.viadere.android"
    static let fingerprint = Data((0..<32).map { UInt8($0) })

    static func serviceAccountJSON(key: _RSA.Signing.PrivateKey, tokenURI: String = FCMServiceAccount.tokenURI) -> String {
        let object: [String: Any] = ["type": "service_account", "project_id": "viadere-test", "private_key_id": "kid1",
                                     "client_email": "fcm-sender@viadere-test.iam.gserviceaccount.com", "private_key": key.pemRepresentation,
                                     "token_uri": tokenURI]
        return String(decoding: try! JSONSerialization.data(withJSONObject: object), as: UTF8.self)
    }

    static func account(_ key: _RSA.Signing.PrivateKey) -> FCMServiceAccount {
        FCMServiceAccount(projectId: "viadere-test", clientEmail: "fcm-sender@viadere-test.iam.gserviceaccount.com", privateKeyId: "kid1",
                          privateKeyPEM: key.pemRepresentation)
    }

    static func interactionPush() -> PushMessage {
        PushMessage(deviceToken: String(repeating: "ab", count: 32), environment: .sandbox, topic: "com.viadere.app", title: "Viadere",
                    body: "Action needed. Open to review a security request.", category: "viadere.authorize.secure", threadID: "business.5f0c",
                    interruptionLevel: "time-sensitive", interactionId: "11111111-2222-3333-4444-555555555555", highPriority: true)
    }

    // MARK: FCM payload policy

    func testFCMPayloadIsDataOnlyAndCarriesOnlyTheOpaqueIds() throws {
        let body = try FCMMessage.from(Self.interactionPush(), token: "fcm-token").body()
        XCTAssertTrue(FCMPushPayloadPolicy.isAllowed(body))
        let root = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        let message = try XCTUnwrap(root["message"] as? [String: Any])
        XCTAssertEqual(Set(message.keys), ["token", "data", "android"], "no notification, apns or webpush block")
        XCTAssertEqual(message["data"] as? [String: String], ["v": "1", "kind": "viadere.authorize.secure", "iid": "11111111-2222-3333-4444-555555555555"])
        XCTAssertEqual(message["android"] as? [String: String], ["priority": "HIGH", "ttl": "3600s"])
        let text = String(decoding: body, as: UTF8.self)
        for leaked in ["Action needed", "Viadere\"", "business.5f0c", "time-sensitive", "title", "body"] {
            XCTAssertFalse(text.contains(leaked), "\(leaked) must never reach FCM: \(text)")
        }
        // Each opaque id the iOS pushes carry maps to the same key, and only that key.
        let id = UUID().uuidString.lowercased()
        let loop = PushMessage(deviceToken: "", environment: .production, topic: "", title: "Viadere", body: LoopRuntimeService.pushBody, category: "viadere.loop",
                               threadID: "viadere.loop", interruptionLevel: "active", interactionId: nil, highPriority: false, collapseID: "loop.\(id)",
                               loopInstanceId: id)
        let loopBody = try FCMMessage.from(loop, token: "t").body()
        XCTAssertTrue(FCMPushPayloadPolicy.isAllowed(loopBody))
        let loopMessage = try XCTUnwrap((JSONSerialization.jsonObject(with: loopBody) as? [String: Any])?["message"] as? [String: Any])
        XCTAssertEqual(loopMessage["data"] as? [String: String], ["v": "1", "kind": "viadere.loop", "loopInstanceId": id])
        XCTAssertEqual(loopMessage["android"] as? [String: String], ["priority": "NORMAL", "ttl": "3600s", "collapse_key": "loop.\(id)"])
        let approve = PushMessage(deviceToken: "", environment: .production, topic: "", title: "", body: "", category: ApprovePushPayloadPolicy.category,
                                  threadID: "", interruptionLevel: "active", interactionId: nil, highPriority: true, approveRequestId: id)
        XCTAssertEqual(((try JSONSerialization.jsonObject(with: try FCMMessage.from(approve, token: "t").body()) as? [String: Any])?["message"]
                        as? [String: Any])?["data"] as? [String: String], ["v": "1", "kind": ApprovePushPayloadPolicy.category, "req": id])
    }

    func testFCMPayloadPolicyRefusesAnythingElse() throws {
        func body(_ message: [String: Any]) -> Data { try! JSONSerialization.data(withJSONObject: ["message": message]) }
        let data = ["v": "1", "kind": "viadere.message"]
        XCTAssertTrue(FCMPushPayloadPolicy.isAllowed(body(["token": "t", "data": data])))
        XCTAssertFalse(FCMPushPayloadPolicy.isAllowed(body(["token": "t", "data": data, "notification": ["title": "Walmart", "body": "$285.28"]])),
                       "a visible notification block")
        XCTAssertFalse(FCMPushPayloadPolicy.isAllowed(body(["token": "t", "data": data.merging(["amount": "285.28"]) { $1 }])), "an extra data key")
        XCTAssertFalse(FCMPushPayloadPolicy.isAllowed(body(["token": "t", "data": data.merging(["iid": "Card purchase at Walmart"]) { $1 }])),
                       "text where an opaque id belongs")
        XCTAssertFalse(FCMPushPayloadPolicy.isAllowed(body(["token": "t", "data": data.merging(["iid": "+15551234567"]) { $1 }])))
        XCTAssertFalse(FCMPushPayloadPolicy.isAllowed(body(["token": "t", "data": ["v": "1", "kind": "marketing.promo"]])))
        XCTAssertFalse(FCMPushPayloadPolicy.isAllowed(body(["token": "t", "data": data, "apns": ["payload": [:]]])))
        XCTAssertFalse(FCMPushPayloadPolicy.isAllowed(body(["token": "t", "data": data, "android": ["notification": ["title": "x"]]])))
        XCTAssertFalse(FCMPushPayloadPolicy.isAllowed(Data(#"{"message":{"token":"t","data":{"v":"1","kind":"viadere.message"}},"validate_only":true}"#.utf8)))
    }

    // MARK: FCM sender

    func testFCMIsOffByDefaultAndRefusedWithoutCredentials() throws {
        let base = ["ENVIRONMENT": "development"]
        XCTAssertNil(try ServerConfig.fromEnvironment(base).android.fcm, "off by default")
        let key: _RSA.Signing.PrivateKey? = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let json = Self.serviceAccountJSON(key: try XCTUnwrap(key))
        // Credentials alone do nothing: the flag is off.
        XCTAssertNil(try ServerConfig.fromEnvironment(base.merging(["FCM_SERVICE_ACCOUNT_JSON": json, "ANDROID_PACKAGE_NAME": Self.packageName]) { $1 }).android.fcm)
        // The flag without credentials, or without the Android app, refuses to boot.
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(base.merging(["FCM_ENABLED": "true", "ANDROID_PACKAGE_NAME": Self.packageName]) { $1 }))
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(base.merging(["FCM_ENABLED": "true", "FCM_SERVICE_ACCOUNT_JSON": json]) { $1 }))
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(base.merging(["FCM_ENABLED": "yes", "FCM_SERVICE_ACCOUNT_JSON": json,
                                                                            "ANDROID_PACKAGE_NAME": Self.packageName]) { $1 }))
        // A key file that would send the signed assertion elsewhere, or that holds no usable key, is refused.
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(base.merging(["FCM_ENABLED": "true", "ANDROID_PACKAGE_NAME": Self.packageName,
                                                                            "FCM_SERVICE_ACCOUNT_JSON": Self.serviceAccountJSON(key: key!, tokenURI: "https://evil.example/token")]) { $1 }))
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(base.merging(["FCM_ENABLED": "true", "ANDROID_PACKAGE_NAME": Self.packageName,
                                                                            "FCM_SERVICE_ACCOUNT_JSON": #"{"type":"service_account","project_id":"viadere-test","client_email":"a@viadere-test.iam.gserviceaccount.com","private_key":"nope"}"#]) { $1 }))
        let on = try ServerConfig.fromEnvironment(base.merging(["FCM_ENABLED": "true", "FCM_SERVICE_ACCOUNT_JSON": json, "ANDROID_PACKAGE_NAME": Self.packageName]) { $1 })
        XCTAssertEqual(on.android.fcm?.projectId, "viadere-test")
    }

    func testFCMSenderUsesTheServiceAccountGrantAndReportsInvalidTokens() async throws {
        let key = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let http = ScriptedOutboundHTTP { url, _ in
            if url == FCMServiceAccount.tokenURI { return (200, Data(#"{"access_token":"ya29.test","expires_in":3599,"token_type":"Bearer"}"#.utf8)) }
            if url.hasSuffix("messages:send") { return (200, Data(#"{"name":"projects/viadere-test/messages/1"}"#.utf8)) }
            return (500, Data())
        }
        let sender = try FCMHTTPv1Sender(account: Self.account(key), packageName: Self.packageName, http: http, now: { Date(timeIntervalSince1970: 1_800_000_000) })
        let target = PushTarget(provider: .fcm, token: "fcm-registration-token-0123456789abcdef", appId: Self.packageName)
        let delivered = await sender.deliver(Self.interactionPush(), to: target)
        XCTAssertEqual(delivered, .delivered)
        let again = await sender.deliver(Self.interactionPush(), to: target)
        XCTAssertEqual(again, .delivered)
        let calls = http.calls
        XCTAssertEqual(calls.filter { $0.url == FCMServiceAccount.tokenURI }.count, 1, "the access token is cached")
        // The assertion: RS256 by the account's key, for Google's token endpoint, with the messaging scope only.
        let form = String(decoding: try XCTUnwrap(calls.first?.body), as: UTF8.self)
        XCTAssertTrue(form.hasPrefix("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion="))
        let jwt = String(form.split(separator: "=").last!)
        let parts = jwt.split(separator: ".").map(String.init)
        XCTAssertEqual(parts.count, 3)
        let claims = try XCTUnwrap(JSONSerialization.jsonObject(with: Base64URL.decode(parts[1])!) as? [String: Any])
        XCTAssertEqual(claims["aud"] as? String, "https://oauth2.googleapis.com/token")
        XCTAssertEqual(claims["scope"] as? String, "https://www.googleapis.com/auth/firebase.messaging")
        XCTAssertEqual(claims["iss"] as? String, "fcm-sender@viadere-test.iam.gserviceaccount.com")
        XCTAssertEqual(claims["exp"] as? Int, 1_800_003_600)
        let header = try XCTUnwrap(JSONSerialization.jsonObject(with: Base64URL.decode(parts[0])!) as? [String: String])
        XCTAssertEqual(header, ["alg": "RS256", "typ": "JWT", "kid": "kid1"])
        XCTAssertTrue(key.publicKey.isValidSignature(_RSA.Signing.RSASignature(rawRepresentation: Base64URL.decode(parts[2])!),
                                                     for: Data("\(parts[0]).\(parts[1])".utf8), padding: .insecurePKCS1v1_5))
        // The send: FCM HTTP v1, bearer token, a body the policy allows.
        let send = try XCTUnwrap(calls.last)
        XCTAssertEqual(send.url, "https://fcm.googleapis.com/v1/projects/viadere-test/messages:send")
        XCTAssertEqual(send.headers["Authorization"], "Bearer ya29.test")
        XCTAssertTrue(FCMPushPayloadPolicy.isAllowed(try XCTUnwrap(send.body)))

        // UNREGISTERED (404) is an invalid token; a token for another app or provider is never sent.
        let gone = ScriptedOutboundHTTP { url, _ in
            url == FCMServiceAccount.tokenURI ? (200, Data(#"{"access_token":"ya29.test","expires_in":3599}"#.utf8))
                : (404, Data(#"{"error":{"code":404,"status":"NOT_FOUND","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"UNREGISTERED"}]}}"#.utf8))
        }
        let goneSender = try FCMHTTPv1Sender(account: Self.account(key), packageName: Self.packageName, http: gone, now: { Date() })
        let invalid = await goneSender.deliver(Self.interactionPush(), to: target)
        XCTAssertEqual(invalid, .tokenInvalid)
        let otherApp = await goneSender.deliver(Self.interactionPush(), to: PushTarget(provider: .fcm, token: target.token, appId: "com.other.app"))
        XCTAssertEqual(otherApp, .failed)
        let apnsTarget = await goneSender.deliver(Self.interactionPush(), to: PushTarget(provider: .apns, token: target.token, environment: .production, appId: Self.packageName))
        XCTAssertEqual(apnsTarget, .failed)
        XCTAssertEqual(gone.calls.filter { $0.url.hasSuffix("messages:send") }.count, 1)
    }

    func testATokenIsOnlyEverSentThroughTheProviderItWasRegisteredFor() async throws {
        let apns = RecordingAPNsSender()
        let fcm = RecordingFCMProvider()
        let router = PushProviderRouter([APNsPushProvider(sender: apns), fcm])
        _ = await router.deliver(Self.interactionPush(), to: PushTarget(provider: .apns, token: String(repeating: "cd", count: 32), environment: .sandbox, appId: "com.viadere.app"))
        _ = await router.deliver(Self.interactionPush(), to: PushTarget(provider: .fcm, token: "fcm-token-abc", appId: Self.packageName))
        XCTAssertEqual(apns.sent.map(\.deviceToken), [String(repeating: "cd", count: 32)])
        XCTAssertEqual(fcm.sent.map(\.1.token), ["fcm-token-abc"])
        // Unconfigured or unknown providers receive nothing.
        let apnsOnly = PushProviderRouter([APNsPushProvider(sender: apns)])
        let dropped = await apnsOnly.deliver(Self.interactionPush(), to: PushTarget(provider: .fcm, token: "fcm-token-abc", appId: Self.packageName))
        XCTAssertEqual(dropped, .failed)
        let unknown = await router.deliver(Self.interactionPush(), to: PushTarget(provider: .unknown, token: "x", appId: "y"))
        XCTAssertEqual(unknown, .failed)
        XCTAssertEqual(apns.sent.count, 1)
        XCTAssertEqual(fcm.sent.count, 1)
        // The APNs provider refuses a target without an APNs environment.
        let noEnvironment = await APNsPushProvider(sender: apns).deliver(Self.interactionPush(), to: PushTarget(provider: .apns, token: "ab", appId: "com.viadere.app"))
        XCTAssertEqual(noEnvironment, .failed)
    }

    func testFCMRegistrationIsStoredApartAndDeliveredOnlyThroughFCM() async throws {
        let fcm = RecordingFCMProvider()
        try await withHarness(overrides: { $0.fcm = fcm }, { $0.android.packageName = Self.packageName }) { h in
            let consumer = try await h.deviceFirstConsumer()
            let other = try await h.deviceFirstConsumer()
            let apnsToken = String(repeating: "ab", count: 32)
            try await eq(try await h.signedPost(consumer, "/v1/push/apns-token", PushRegistration(provider: .apns, token: apnsToken, environment: "sandbox",
                                                                                                   appId: "com.viadere.app")).status, .ok)
            let token = "fcm:APA91b" + String(repeating: "x", count: 140)
            // Wrong app id, an APNs environment on an FCM token or a malformed token: refused.
            for bad in [PushRegistration(provider: .fcm, token: token, environment: nil, appId: "com.other.app"),
                        PushRegistration(provider: .fcm, token: token, environment: "production", appId: Self.packageName),
                        PushRegistration(provider: .fcm, token: "short", environment: nil, appId: Self.packageName),
                        PushRegistration(provider: .fcm, token: token + " <script>", environment: nil, appId: Self.packageName)] {
                try await eq(try await h.signedPost(consumer, "/v1/push/apns-token", bad).status, .unprocessableEntity)
            }
            try await eq(try await h.signedPost(consumer, "/v1/push/apns-token", PushRegistration(provider: .fcm, token: token, environment: nil,
                                                                                                   appId: Self.packageName)).status, .ok)
            let did = consumer.device!.id.uuid
            try await eq(try await APNsTokenRecord.query(on: h.db).filter(\.$deviceId == did).count(), 0, "FCM replaced this device's APNs token")
            try await eq(try await APNsTokenRecord.query(on: h.db).filter(\.$token == token).count(), 0)
            try await eq(try await PushTokenRecord.query(on: h.db).filter(\.$deviceId == did).count(), 1)
            try await eq(try await h.signedPost(other, "/v1/push/apns-token", PushRegistration(provider: .apns, token: String(repeating: "cd", count: 32),
                                                                                               environment: "sandbox", appId: "com.viadere.app")).status, .ok)

            await SecurityNotices(db: h.db, ctx: h.ctx).push(to: consumer.id.uuid, except: nil, notice: .newDevice)
            XCTAssertTrue(h.push.sent.isEmpty, "the FCM device's token never goes through APNs")
            XCTAssertEqual(fcm.sent.map(\.1), [PushTarget(provider: .fcm, token: token, environment: nil, appId: Self.packageName)])
            XCTAssertNil(fcm.sent.first?.0.interactionId)
            await SecurityNotices(db: h.db, ctx: h.ctx).push(to: other.id.uuid, except: nil, notice: .newDevice)
            XCTAssertEqual(h.push.sent.count, 1, "the APNs device's token goes through APNs only")
            XCTAssertEqual(fcm.sent.count, 1)

            // Invalid-token feedback disables only that token.
            fcm.setOutcome(.tokenInvalid)
            await SecurityNotices(db: h.db, ctx: h.ctx).push(to: consumer.id.uuid, except: nil, notice: .newDevice)
            let stored = try await XCTUnwrapAsync(try await PushTokenRecord.query(on: h.db).filter(\.$deviceId == did).first())
            XCTAssertNotNil(stored.invalidatedAt)
            try await eq(try await APNsTokenRecord.query(on: h.db).filter(\.$invalidatedAt == nil).count(), 1, "the other device's APNs token is untouched")
            await SecurityNotices(db: h.db, ctx: h.ctx).push(to: consumer.id.uuid, except: nil, notice: .newDevice)
            XCTAssertEqual(fcm.sent.count, 2, "an invalidated token is not used again")

            // Registering APNs again on that device removes the FCM token.
            try await eq(try await h.signedPost(consumer, "/v1/push/apns-token", PushRegistration(provider: .apns, token: apnsToken, environment: "sandbox",
                                                                                                   appId: "com.viadere.app")).status, .ok)
            try await eq(try await PushTokenRecord.query(on: h.db).count(), 0)
        }
    }

    func testFCMRegistrationIsRefusedWhileFCMIsOff() async throws {
        try await withHarness({ $0.android.packageName = Self.packageName }) { h in
            let consumer = try await h.deviceFirstConsumer()
            let token = "fcm:APA91b" + String(repeating: "x", count: 140)
            let refused = try await h.signedPost(consumer, "/v1/push/apns-token", PushRegistration(provider: .fcm, token: token, environment: nil, appId: Self.packageName))
            XCTAssertEqual(refused.status, .unprocessableEntity, refused.text)
            try await eq(try await PushTokenRecord.query(on: h.db).count(), 0)
            XCTAssertFalse(h.ctx.push.supports(.fcm))
        }
    }

    // MARK: Android integrity

    struct PlayFixture {
        let kek = SymmetricKey(size: .bits256)
        let signing = P256.Signing.PrivateKey()
        var keys: PlayIntegrityKeys { PlayIntegrityKeys(decryptionKey: kek, verificationKey: signing.publicKey) }

        func verdict(nonce: String, timestamp: Date, package: String = PlatformSeamsTests.packageName, recognition: String = "PLAY_RECOGNIZED",
                     digests: [String] = [Base64URL.encode(PlatformSeamsTests.fingerprint)], device: [String] = ["MEETS_DEVICE_INTEGRITY"]) -> [String: Any] {
            ["requestDetails": ["requestPackageName": package, "nonce": nonce, "timestampMillis": String(Int(timestamp.timeIntervalSince1970 * 1000))],
             "appIntegrity": ["appRecognitionVerdict": recognition, "packageName": package, "certificateSha256Digest": digests, "versionCode": "42"],
             "deviceIntegrity": ["deviceRecognitionVerdict": device],
             "accountDetails": ["appLicensingVerdict": "LICENSED"]]
        }

        /// A classic Play Integrity token: JWS (ES256) inside JWE (A256KW + A256GCM).
        func token(_ payload: [String: Any], signer: P256.Signing.PrivateKey? = nil, kek wrapKey: SymmetricKey? = nil,
                   header: [String: String] = ["alg": "A256KW", "enc": "A256GCM"]) throws -> String {
            let jwsHeader = Base64URL.encode(try JSONSerialization.data(withJSONObject: ["alg": "ES256"]))
            let jwsPayload = Base64URL.encode(try JSONSerialization.data(withJSONObject: payload))
            let signature = try (signer ?? signing).signature(for: Data("\(jwsHeader).\(jwsPayload)".utf8))
            let jws = "\(jwsHeader).\(jwsPayload).\(Base64URL.encode(signature.rawRepresentation))"
            let protected = Base64URL.encode(try JSONSerialization.data(withJSONObject: header))
            let cek = SymmetricKey(size: .bits256)
            let wrapped = try AES.KeyWrap.wrap(cek, using: wrapKey ?? kek)
            let sealed = try AES.GCM.seal(Data(jws.utf8), using: cek, authenticating: Data(protected.utf8))
            return [protected, Base64URL.encode(wrapped), Base64URL.encode(Data(sealed.nonce)), Base64URL.encode(sealed.ciphertext), Base64URL.encode(sealed.tag)]
                .joined(separator: ".")
        }
    }

    func testPlayIntegrityVerdictsAreCheckedLocallyAndFailClosed() async throws {
        let play = PlayFixture()
        let clock = ManualClock(Date(timeIntervalSince1970: 1_800_000_000))
        let verifier = AndroidKeyAttestationVerifier(playIntegrity: PlayIntegrityVerifier(keys: play.keys, packageName: Self.packageName,
                                                                                          certificateFingerprints: [Self.fingerprint], clock: clock))
        let account = ConsumerID()
        let keys = [DeviceKeyRegistration(purpose: .request, publicKey: DevicePublicKey(P256.Signing.PrivateKey().publicKey), hardwareBacked: true,
                                          proof: "p")]
        let nonce = PlayIntegrityBinding.nonce(consumerId: account, challenge: "challenge-1", keys: keys)
        func evidence(_ token: String?) -> AndroidKeyAttestationEvidence { AndroidKeyAttestationEvidence(certificateChain: [], playIntegrityToken: token) }
        func check(_ token: String?, challenge: String = "challenge-1") async -> AttestationResult {
            await verifier.verify(evidence(token), consumerId: account, challenge: challenge, keys: keys)
        }
        let good = try play.token(play.verdict(nonce: nonce, timestamp: clock.now()))
        let verified = await check(good)
        XCTAssertTrue(verified.attested, verified.reason)
        XCTAssertEqual(verified.environment, "play-integrity")
        XCTAssertNil(verified.keyId, "Play Integrity names no hardware key")

        // The same token for another ceremony (challenge) does not match its nonce.
        let replayed = await check(good, challenge: "challenge-2")
        XCTAssertEqual(replayed.reason, "play_integrity_nonce")
        let cases: [(String, String?)] = [
            ("play_integrity_missing", nil),
            ("play_integrity_malformed", "eyJhbGciOi"),
            ("play_integrity_decryption", try play.token(play.verdict(nonce: nonce, timestamp: clock.now()), kek: SymmetricKey(size: .bits256))),
            ("play_integrity_malformed", try play.token(play.verdict(nonce: nonce, timestamp: clock.now()), header: ["alg": "dir", "enc": "A256GCM"])),
            ("play_integrity_signature", try play.token(play.verdict(nonce: nonce, timestamp: clock.now()), signer: P256.Signing.PrivateKey())),
            ("play_integrity_package", try play.token(play.verdict(nonce: nonce, timestamp: clock.now(), package: "com.evil.app"))),
            ("play_integrity_nonce", try play.token(play.verdict(nonce: Base64URL.encode(Data(repeating: 7, count: 32)), timestamp: clock.now()))),
            ("play_integrity_stale", try play.token(play.verdict(nonce: nonce, timestamp: clock.now().addingTimeInterval(-301)))),
            ("play_integrity_stale", try play.token(play.verdict(nonce: nonce, timestamp: clock.now().addingTimeInterval(120)))),
            ("play_integrity_app_not_recognized", try play.token(play.verdict(nonce: nonce, timestamp: clock.now(), recognition: "UNRECOGNIZED_VERSION"))),
            ("play_integrity_certificate", try play.token(play.verdict(nonce: nonce, timestamp: clock.now(), digests: [Base64URL.encode(Data(repeating: 9, count: 32))]))),
            ("play_integrity_device", try play.token(play.verdict(nonce: nonce, timestamp: clock.now(), device: ["MEETS_BASIC_INTEGRITY"]))),
            ("play_integrity_device", try play.token(play.verdict(nonce: nonce, timestamp: clock.now(), device: []))),
        ]
        for (reason, token) in cases {
            let result = await check(token)
            XCTAssertFalse(result.attested, reason)
            XCTAssertEqual(result.reason, reason)
        }
        // Without the owner's keys the verifier is the stub: even a perfect token is never attested.
        let stub = await AndroidKeyAttestationVerifier().verify(evidence(good), consumerId: account, challenge: "challenge-1", keys: keys)
        XCTAssertFalse(stub.attested)
        XCTAssertEqual(stub.reason, "verifier_not_implemented")
        // Configuration: the flag without its keys refuses to boot; keys without the flag leave the stub in place.
        let base = ["ENVIRONMENT": "development", "ANDROID_PACKAGE_NAME": Self.packageName, "ANDROID_CERT_SHA256_FINGERPRINTS": AndroidSettings.fingerprintText(Self.fingerprint)]
        let keyEnv = ["PLAY_INTEGRITY_DECRYPTION_KEY": play.kek.withUnsafeBytes { Data($0) }.base64EncodedString(),
                      "PLAY_INTEGRITY_VERIFICATION_KEY": play.signing.publicKey.derRepresentation.base64EncodedString()]
        XCTAssertNil(try ServerConfig.fromEnvironment(base.merging(keyEnv) { $1 }).android.playIntegrity)
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(base.merging(["PLAY_INTEGRITY_ENABLED": "true"]) { $1 }))
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(["ENVIRONMENT": "development", "PLAY_INTEGRITY_ENABLED": "true"].merging(keyEnv) { $1 }))
        let configured = try ServerConfig.fromEnvironment(base.merging(keyEnv) { $1 }.merging(["PLAY_INTEGRITY_ENABLED": "true"]) { $1 })
        XCTAssertNotNil(configured.android.playIntegrity)
        XCTAssertNil(AndroidKeyAttestationVerifier.configured(ServerConfig.testing(), clock: clock).playIntegrity)
        XCTAssertNotNil(AndroidKeyAttestationVerifier.configured(configured, clock: clock).playIntegrity)
    }

    /// Never-attested Android evidence keeps a device at D0 and is refused under `require`; a verified Play Integrity verdict is the only way in.
    func testAnUnverifiableAndroidDeviceNeverReachesD1() async throws {
        let play = PlayFixture()
        struct Verifier: DeviceIntegrityVerifier {
            let android: AndroidKeyAttestationVerifier
            func assessSensitiveRequest(deviceId: DeviceID, purpose: String) async -> IntegrityVerdict { .unverified }
        }
        let harness = try await TestHarness.make(mode: .require, integrity: { clock in
            Verifier(android: AndroidKeyAttestationVerifier(playIntegrity: PlayIntegrityVerifier(keys: play.keys, packageName: Self.packageName,
                                                                                                 certificateFingerprints: [Self.fingerprint], clock: clock)))
        })
        do {
            let unsigned = try await harness.createAccount(integrity: { keys, challenge, account in
                IntegrityEvidence(androidKeyAttestation: AndroidKeyAttestationEvidence(certificateChain: ["MIIB"], playIntegrityToken: try play.token(
                    play.verdict(nonce: PlayIntegrityBinding.nonce(consumerId: account, challenge: challenge, keys: keys), timestamp: harness.clock.now()),
                    signer: P256.Signing.PrivateKey())))
            })
            XCTAssertEqual(unsigned.result.errorCode, .attestationRequired, "a token not signed by the owner's key")
            let wrongNonce = try await harness.createAccount(integrity: { _, _, _ in
                IntegrityEvidence(androidKeyAttestation: AndroidKeyAttestationEvidence(certificateChain: [], playIntegrityToken: try play.token(
                    play.verdict(nonce: Base64URL.encode(Data(repeating: 1, count: 32)), timestamp: harness.clock.now()))))
            })
            XCTAssertEqual(wrongNonce.result.errorCode, .attestationRequired, "a verdict for another enrollment")
            let chainOnly = try await harness.createAccount(integrity: { _, _, _ in
                IntegrityEvidence(androidKeyAttestation: AndroidKeyAttestationEvidence(certificateChain: ["MIIBszCCAVmgAwIBAgIBATAKBggqhkjOPQQDAjA"]))
            })
            XCTAssertEqual(chainOnly.result.errorCode, .attestationRequired, "a key attestation chain alone is not verified, so never trusted")
            let verified = try await harness.createAccount(integrity: { keys, challenge, account in
                IntegrityEvidence(androidKeyAttestation: AndroidKeyAttestationEvidence(certificateChain: [], playIntegrityToken: try play.token(
                    play.verdict(nonce: PlayIntegrityBinding.nonce(consumerId: account, challenge: challenge, keys: keys), timestamp: harness.clock.now()))))
            })
            XCTAssertEqual(verified.result.status, .created, verified.result.text)
            let device = try verified.result.json(AccountCreateResponse.self).device
            XCTAssertEqual(device.trustTier, .d1)
            let record = try await XCTUnwrapAsync(try await DeviceRecord.find(device.id.uuid, on: harness.db))
            XCTAssertEqual(record.integrityFormat, "android-key-attestation")
            XCTAssertEqual(record.attestationStatus, "attested")
        } catch {
            try? await harness.shutdown()
            throw error
        }
        try await harness.shutdown()
    }

    // MARK: assetlinks

    func testAssetLinksAreGeneratedFromConfigurationAndAbsentOtherwise() async throws {
        try await withHarness { h in
            try await eq(try await h.request(.GET, "/.well-known/assetlinks.json").status, .notFound)
        }
        try await withHarness({ $0.android.packageName = Self.packageName }) { h in
            try await eq(try await h.request(.GET, "/.well-known/assetlinks.json").status, .notFound, "a package without fingerprints publishes nothing")
        }
        let second = Data(repeating: 0xAB, count: 32)
        try await withHarness({ config in
            config.android.packageName = Self.packageName
            config.android.certificateFingerprints = [Self.fingerprint, second]
        }) { h in
            let response = try await h.request(.GET, "/.well-known/assetlinks.json")
            XCTAssertEqual(response.status, .ok)
            XCTAssertEqual(response.headers.contentType, .json)
            XCTAssertEqual(response.text, #"[{"relation":["delegate_permission/common.handle_all_urls","delegate_permission/common.get_login_creds"],"target":{"namespace":"android_app","package_name":"com.viadere.android","sha256_cert_fingerprints":["00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F","AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB:AB"]}}]"#)
        }
        // Configuration parsing.
        let env = ["ENVIRONMENT": "development", "ANDROID_PACKAGE_NAME": Self.packageName,
                   "ANDROID_CERT_SHA256_FINGERPRINTS": "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f"]
        XCTAssertEqual(try ServerConfig.fromEnvironment(env).android.certificateFingerprints, [Self.fingerprint])
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(env.merging(["ANDROID_CERT_SHA256_FINGERPRINTS": "00:01"]) { $1 }))
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(env.merging(["ANDROID_PACKAGE_NAME": "viadere"]) { $1 }))
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(["ENVIRONMENT": "development", "ANDROID_CERT_SHA256_FINGERPRINTS": env["ANDROID_CERT_SHA256_FINGERPRINTS"]!]))
    }

    // MARK: OTLP export

    func testTelemetryIsOffByDefaultAndRefusesPlainHTTPInStrictEnvironments() async throws {
        XCTAssertNil(ServerConfig.testing().telemetry.endpoint)
        XCTAssertNil(try ServerConfig.fromEnvironment(["ENVIRONMENT": "development"]).telemetry.endpoint)
        var config = ServerConfig.testing()
        XCTAssertThrowsError(try config.applyTelemetryEnvironment(["OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector.internal:4318"], strict: true))
        XCTAssertThrowsError(try config.applyTelemetryEnvironment(["OTEL_EXPORTER_OTLP_ENDPOINT": "https://user:pw@collector.example"], strict: true))
        XCTAssertThrowsError(try config.applyTelemetryEnvironment(["OTEL_EXPORTER_OTLP_ENDPOINT": "https://collector.example?token=x"], strict: false))
        XCTAssertThrowsError(try config.applyTelemetryEnvironment(["OTEL_EXPORTER_OTLP_ENDPOINT": "ftp://collector.example"], strict: false))
        try config.applyTelemetryEnvironment(["OTEL_EXPORTER_OTLP_ENDPOINT": "https://collector.example:4318/"], strict: true)
        XCTAssertEqual(config.telemetry.endpoint?.absoluteString, "https://collector.example:4318")
        try config.applyTelemetryEnvironment(["OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4318"], strict: false)
        XCTAssertEqual(config.telemetry.endpoint?.scheme, "http")
        // The strict boot path refuses it too.
        var strict = PlatformGateOpsTests.productionEnvironment("staging")
        strict["OTEL_EXPORTER_OTLP_ENDPOINT"] = "http://collector.internal:4318"
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(strict))
        // Off: nothing is recorded.
        try await withHarness { h in
            XCTAssertFalse(h.ctx.spans.enabled)
            _ = try await h.request(.GET, "/healthz")
            XCTAssertTrue(h.ctx.spans.drain().isEmpty)
        }
    }

    func testTelemetryAttributesPassOnlyTheAllowList() throws {
        let recorder = SpanRecorder(enabled: true)
        recorder.record(name: "GET /v1/devices/:deviceId", start: Date(), end: Date(), attributes: [
            "http.request.method": .string("GET"), "http.route": .string("/v1/devices/:deviceId"), "http.response.status_code": .int(200),
            "url.full": .string("https://api.viadere.com/v1/devices/3f2c"), "http.request.body": .string("{\"code\":\"123456\"}"),
            "enduser.id": .string("sub_abc"), "client.address": .string("203.0.113.7"), "http.request.header.authorization": .string("Bearer vda_x"),
        ], failed: false)
        // An allowed key with a value shaped like personal data is dropped too, and so is a span name that carries one.
        recorder.record(name: "GET /v1/phone/+15551234567", start: Date(), end: Date(), attributes: [
            "http.route": .string("/v1/phone/+15551234567"), "http.request.method": .string("GET"),
        ], failed: false)
        recorder.record(name: "GET x", start: Date(), end: Date(), attributes: [
            "http.route": .string("/v1/i/3f2c9a10-1111-2222-3333-444455556666"),
        ], failed: false)
        recorder.record(name: "GET y", start: Date(), end: Date(), attributes: ["http.route": .string("/v1/x?email=a@b.example")], failed: false)
        let spans = recorder.drain()
        XCTAssertEqual(spans[0].attributes, ["http.request.method": .string("GET"), "http.route": .string("/v1/devices/:deviceId"),
                                             "http.response.status_code": .int(200)])
        XCTAssertEqual(spans[1].attributes, ["http.request.method": .string("GET")])
        XCTAssertEqual(spans[1].name, "request")
        XCTAssertTrue(spans[2].attributes.isEmpty)
        XCTAssertTrue(spans[3].attributes.isEmpty)
        let traces = String(decoding: try OTLPEncoder.traces(spans, settings: TelemetrySettings()), as: UTF8.self)
        for leaked in ["3f2c", "123456", "sub_abc", "203.0.113.7", "vda_x", "+1555", "a@b.example", "url.full", "enduser"] {
            XCTAssertFalse(traces.contains(leaked), leaked)
        }
        XCTAssertTrue(traces.contains(#""key":"service.name","value":{"stringValue":"viadere-server"}"#))
        // Metric labels: only class, event and reason.
        let metrics = String(decoding: try OTLPEncoder.metrics([
            MetricPoint(name: "viadere_security_events_total", labels: ["event": .string("rate_limited"), "consumer": .string("c_123"), "phone": .string("+15551234567")],
                        value: 3, counter: true),
            MetricPoint(name: "viadere_webhook_pending", labels: [:], value: 2, counter: false),
        ], start: Date(timeIntervalSince1970: 1), now: Date(timeIntervalSince1970: 2), settings: TelemetrySettings()), as: UTF8.self)
        XCTAssertTrue(metrics.contains(#"{"key":"event","value":{"stringValue":"rate_limited"}}"#), metrics)
        XCTAssertTrue(metrics.contains(#""asInt":"3""#))
        XCTAssertTrue(metrics.contains(#""gauge""#))
        XCTAssertFalse(metrics.contains("c_123"))
        XCTAssertFalse(metrics.contains("+1555"))
    }

    func testRequestSpansCarryTheRoutePatternNeverThePath() async throws {
        let collector = ScriptedOutboundHTTP { _, _ in (200, Data()) }
        try await withHarness(overrides: { $0.otlpHTTP = collector }, { $0.telemetry.endpoint = URL(string: "https://collector.example:4318") }) { h in
            XCTAssertTrue(h.ctx.spans.enabled)
            let consumer = try await h.deviceFirstConsumer()
            let id = UUID().uuidString.lowercased()
            _ = try await h.signed(consumer, .DELETE, "/v1/sessions/\(id)")
            let exporter = OTLPExporter(settings: h.ctx.config.telemetry, http: collector, spans: h.ctx.spans, metrics: h.ctx.metrics) { [] }
            let statuses = await exporter.exportOnce()
            XCTAssertEqual(statuses, [200, 200])
            let traces = try XCTUnwrap(collector.calls.first { $0.url == "https://collector.example:4318/v1/traces" }?.body)
            let text = String(decoding: traces, as: UTF8.self)
            XCTAssertTrue(text.contains("/v1/sessions/:"), text)
            XCTAssertFalse(text.contains(id), "the requested path (with its id) never leaves the process")
            XCTAssertFalse(text.contains(consumer.id.description))
            XCTAssertFalse(text.contains(consumer.token))
            let metrics = try XCTUnwrap(collector.calls.first { $0.url == "https://collector.example:4318/v1/metrics" }?.body)
            XCTAssertTrue(String(decoding: metrics, as: UTF8.self).contains("viadere_http_responses_total"))
            XCTAssertTrue(h.ctx.spans.drain().isEmpty, "exported spans are not kept")
        }
    }
}
