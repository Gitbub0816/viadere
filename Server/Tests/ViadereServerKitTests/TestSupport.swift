@preconcurrency import Crypto
import Fluent
import Foundation
import NIOHTTP1
import Vapor
import ViadereCore
import enum ViadereCore.Channel
import XCTVapor
@testable import ViadereServerKit

// MARK: - Fakes (test-only: never shipped in the library)

/// Deterministic passkey verifier. Registration: `attestationObject` = base64url(public key),
/// `clientDataJSON` = base64url(challenge). Assertion: same challenge binding and `signature == "valid"`.
struct FakePasskeyVerifier: PasskeyVerifier {
    func makeChallenge() -> Data { SecureToken.randomBytes(32) }

    func verifyRegistration(_ credential: PasskeyRegistrationCredential, challenge: Data,
                            credentialAlreadyRegistered: @Sendable (String) async throws -> Bool) async throws -> VerifiedPasskeyRegistration {
        guard Base64URL.decode(credential.clientDataJSON) == challenge, let key = Base64URL.decode(credential.attestationObject),
              !key.isEmpty, try await !credentialAlreadyRegistered(credential.id) else { throw PasskeyError.invalid }
        return VerifiedPasskeyRegistration(credentialId: credential.id, publicKey: key, signCount: 0, backupEligible: true)
    }

    func verifyAssertion(_ credential: PasskeyAssertionCredential, challenge: Data, publicKey: Data,
                         signCount: UInt32) throws -> VerifiedPasskeyAssertion {
        guard Base64URL.decode(credential.clientDataJSON) == challenge, credential.signature == "valid" else { throw PasskeyError.invalid }
        return VerifiedPasskeyAssertion(newSignCount: signCount + 1)
    }
}

final class RecordingAPNsSender: APNsSender, @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [PushMessage] = []
    private var outcome: PushOutcome = .delivered
    var sent: [PushMessage] { lock.withLock { storage } }
    func setOutcome(_ value: PushOutcome) { lock.withLock { outcome = value } }
    func send(_ message: PushMessage) async -> PushOutcome {
        lock.withLock {
            storage.append(message)
            return outcome
        }
    }
}

/// Uses the real Twilio signature/parsing code, but records outbound messages instead of calling the network.
final class RecordingSMSProvider: SMSProvider, @unchecked Sendable {
    static let authToken = "test-auth-token-0123456789"
    let twilio = TwilioProvider(config: TwilioConfig(accountSID: "ACtest", authToken: RecordingSMSProvider.authToken,
                                                     fromNumber: "+15550001111", messagingServiceSID: nil), client: nil,
                                logger: Logger(label: "test"))
    struct Sent: Equatable { var to: String; var body: String }
    private let lock = NSLock()
    private var storage: [Sent] = []
    private var failuresRemaining = 0
    private var counter = 0
    var name: String { "twilio" }
    var sent: [Sent] { lock.withLock { storage } }
    func failNext(_ count: Int) { lock.withLock { failuresRemaining = count } }
    func reset() { lock.withLock { storage.removeAll() } }

    func verifyWebhook(_ request: ProviderWebhookRequest) -> Bool { twilio.verifyWebhook(request) }
    func parseInbound(_ request: ProviderWebhookRequest) throws -> InboundSMS { try twilio.parseInbound(request) }
    func parseDeliveryUpdate(_ request: ProviderWebhookRequest) throws -> SMSDeliveryUpdate? { try twilio.parseDeliveryUpdate(request) }
    func send(_ request: OutboundSMSRequest) async throws -> OutboundSMSResult {
        try lock.withLock {
            if failuresRemaining > 0 {
                failuresRemaining -= 1
                throw SMSProviderError.transient("simulated")
            }
            storage.append(Sent(to: request.to.e164, body: request.body))
            counter += 1
            return OutboundSMSResult(providerMessageId: "twilio:SMOUT\(counter)")
        }
    }
}

final class ScriptedWebhookTransport: WebhookTransport, @unchecked Sendable {
    private let lock = NSLock()
    private var requests: [WebhookHTTPRequest] = []
    private var statuses: [Int] = []
    private var fallback = 200
    var received: [WebhookHTTPRequest] { lock.withLock { requests } }
    func respond(with codes: [Int], then fallback: Int = 200) { lock.withLock { statuses = codes; self.fallback = fallback } }
    func send(_ request: WebhookHTTPRequest) async throws -> WebhookHTTPResponse {
        lock.withLock {
            requests.append(request)
            let code = statuses.isEmpty ? fallback : statuses.removeFirst()
            return WebhookHTTPResponse(statusCode: code)
        }
    }
}

// MARK: - HTTP helper

final class Box<T>: @unchecked Sendable {
    var value: T?
}

struct HTTPResult {
    var status: HTTPStatus
    var headers: HTTPHeaders
    var body: Data

    func json<T: Decodable>(_ type: T.Type = T.self) throws -> T { try ViadereJSON.decode(type, from: body) }
    var errorCode: APIErrorCode? { (try? ViadereJSON.decode(APIErrorResponse.self, from: body))?.error.code }
    var text: String { String(decoding: body, as: UTF8.self) }
}

struct TestDevice {
    var id: DeviceID
    var requestKey: SoftwareP256SigningKey
    var passcodeKey: SoftwareP256SigningKey
    var biometricKey: SoftwareP256SigningKey
}

struct TestConsumer {
    var id: ConsumerID
    var session: AuthSession
    var device: TestDevice?
    var token: String { session.accessToken }
}

struct TestBusiness {
    var record: BusinessRecord
    var id: BusinessID { BusinessID(record.id!) }
    var key: String
    var summary: BusinessSummary
}

// MARK: - Harness

final class TestHarness: @unchecked Sendable {
    let app: Application
    let clock: ManualClock
    let apns = RecordingAPNsSender()
    let sms = RecordingSMSProvider()
    let transport = ScriptedWebhookTransport()
    var config: ServerConfig

    init(app: Application, clock: ManualClock, config: ServerConfig) {
        self.app = app
        self.clock = clock
        self.config = config
    }

    static func make(_ adjust: (inout ServerConfig) -> Void = { _ in }) async throws -> TestHarness {
        var config = ServerConfig.testing()
        adjust(&config)
        let clock = ManualClock(Date(timeIntervalSince1970: 1_800_000_000))
        let apns = RecordingAPNsSender()
        let sms = RecordingSMSProvider()
        let transport = ScriptedWebhookTransport()
        let app = try await makeApplication(environment: .testing, config: config, overrides: Overrides(
            clock: clock, apns: apns, sms: sms, passkeys: FakePasskeyVerifier(), webhookTransport: transport))
        let harness = TestHarness(app: app, clock: clock, config: config)
        harness.bind(apns: apns, sms: sms, transport: transport)
        return harness
    }

    private var boundApns: RecordingAPNsSender?
    private var boundSMS: RecordingSMSProvider?
    private var boundTransport: ScriptedWebhookTransport?
    func bind(apns: RecordingAPNsSender, sms: RecordingSMSProvider, transport: ScriptedWebhookTransport) {
        boundApns = apns
        boundSMS = sms
        boundTransport = transport
    }
    var push: RecordingAPNsSender { boundApns! }
    var texts: RecordingSMSProvider { boundSMS! }
    var webhooks: ScriptedWebhookTransport { boundTransport! }
    var ctx: ServerContext { app.ctx }
    var db: any Database { app.db }

    func shutdown() async throws { try await app.asyncShutdown() }

    // MARK: Requests

    func request(_ method: NIOHTTP1.HTTPMethod, _ path: String, headers: [String: String] = [:], body: Data? = nil,
                 contentType: String? = "application/json") async throws -> HTTPResult {
        var httpHeaders = HTTPHeaders()
        for (name, value) in headers { httpHeaders.replaceOrAdd(name: name, value: value) }
        if let body, !body.isEmpty, let contentType { httpHeaders.replaceOrAdd(name: .contentType, value: contentType) }
        let box = Box<HTTPResult>()
        try await app.test(method, path, headers: httpHeaders, body: body.map { ByteBuffer(data: $0) }) { response async throws in
            box.value = HTTPResult(status: response.status, headers: response.headers, body: Data(response.body.readableBytesView))
        }
        return box.value!
    }

    func post<T: Encodable>(_ path: String, _ value: T, headers: [String: String] = [:]) async throws -> HTTPResult {
        try await request(.POST, path, headers: headers, body: try ViadereJSON.encode(value))
    }

    // MARK: Consumer helpers

    func registerConsumer(name: String = "Test User") async throws -> TestConsumer {
        let begin = try await post(APIRoutes.registerBegin.template, PasskeyRegistrationBeginRequest(displayName: name))
        XCTAssertEqual(begin.status, .ok, begin.text)
        let options = try begin.json(PasskeyRegistrationOptions.self)
        let credential = PasskeyRegistrationCredential(
            id: SecureToken.generate(byteCount: 16), rawId: SecureToken.generate(byteCount: 16),
            attestationObject: SecureToken.generate(byteCount: 32), clientDataJSON: options.challenge)
        let finish = try await post(APIRoutes.registerFinish.template, PasskeyRegistrationFinishRequest(ceremonyId: options.ceremonyId, credential: credential))
        XCTAssertEqual(finish.status, .created, finish.text)
        let session = try finish.json(AuthSession.self)
        return TestConsumer(id: session.consumerId, session: session, device: nil)
    }

    func enrollDevice(_ consumer: TestConsumer, name: String = "Test iPhone", purposes: [DeviceKeyPurpose] = DeviceKeyPurpose.allCases) async throws -> TestConsumer {
        var consumer = consumer
        let begin = try await request(.POST, APIRoutes.deviceEnrollBegin.template, headers: ["Authorization": "Bearer \(consumer.token)"])
        XCTAssertEqual(begin.status, .ok, begin.text)
        let challenge = try begin.json(DeviceEnrollmentChallenge.self).challenge
        let keys = (request: SoftwareP256SigningKey(), passcode: SoftwareP256SigningKey(), biometric: SoftwareP256SigningKey())
        var registrations: [DeviceKeyRegistration] = []
        for purpose in purposes {
            let key: SoftwareP256SigningKey
            switch purpose {
            case .request: key = keys.request
            case .approvalUserPresence: key = keys.passcode
            case .approvalBiometric: key = keys.biometric
            }
            registrations.append(try await DeviceEnrollment.register(key: key, purpose: purpose, hardwareBacked: true, consumerId: consumer.id, challenge: challenge))
        }
        let response = try await post(APIRoutes.deviceEnroll.template,
                                      DeviceEnrollRequest(name: name, platform: .iOS, challenge: challenge, keys: registrations),
                                      headers: ["Authorization": "Bearer \(consumer.token)"])
        XCTAssertEqual(response.status, .created, response.text)
        let device = try response.json(Device.self)
        consumer.device = TestDevice(id: device.id, requestKey: keys.request, passcodeKey: keys.passcode, biometricKey: keys.biometric)
        return consumer
    }

    func readyConsumer(name: String = "Test User") async throws -> TestConsumer {
        try await enrollDevice(try await registerConsumer(name: name))
    }

    /// A device-signed + bearer request.
    func signed(_ consumer: TestConsumer, _ method: NIOHTTP1.HTTPMethod, _ path: String, body: Data? = nil, at: Date? = nil,
                nonce: String? = nil, signWithKey: SoftwareP256SigningKey? = nil, signedPath: String? = nil) async throws -> HTTPResult {
        let headers = try await signedHeaders(consumer, method, path, body: body ?? Data(), at: at, nonce: nonce, key: signWithKey, signedPath: signedPath)
        return try await request(method, path, headers: headers, body: body)
    }

    func signedHeaders(_ consumer: TestConsumer, _ method: NIOHTTP1.HTTPMethod, _ path: String, body: Data, at: Date? = nil,
                       nonce: String? = nil, key: SoftwareP256SigningKey? = nil, signedPath: String? = nil) async throws -> [String: String] {
        let device = consumer.device!
        let signer = RequestSigner(deviceId: device.id, key: key ?? device.requestKey)
        let fields = try await signer.sign(method: method.rawValue, pathAndQuery: signedPath ?? path, body: body,
                                           now: at ?? clock.now(), nonce: nonce ?? SecureToken.generate(byteCount: 16)).fields
        var headers = fields
        headers["Authorization"] = "Bearer \(consumer.token)"
        return headers
    }

    func signedPost<T: Encodable>(_ consumer: TestConsumer, _ path: String, _ value: T) async throws -> HTTPResult {
        try await signed(consumer, .POST, path, body: try ViadereJSON.encode(value))
    }

    // MARK: Business helpers

    func makeBusiness(name: String, handle: String?, status: VerificationStatus = .verified, tier: String = "free", quota: Int? = nil,
                      scopes: [String] = BusinessAPIKeys.Scope.all, live: Bool = true) async throws -> TestBusiness {
        let record = try await BusinessRegistry(db: db, ctx: ctx).register(displayName: name, handle: handle, category: .other, status: status,
                                                                            tier: tier, dailyQuota: quota)
        let key = try await BusinessAPIKeys.issue(businessId: record.id!, name: "test", live: live, scopes: scopes, now: clock.now(), on: db)
        let directory = DirectoryService(db: db)
        // Pending/suspended businesses have no public summary through `verified`; build it directly.
        let summary = try await directory.summary(for: record)!
        return TestBusiness(record: record, key: key.key, summary: summary)
    }

    func business(_ b: TestBusiness, _ method: NIOHTTP1.HTTPMethod, _ path: String, body: Data? = nil, idempotencyKey: String? = nil,
                  key: String? = nil) async throws -> HTTPResult {
        var headers = ["Authorization": "Bearer \(key ?? b.key)"]
        if let idempotencyKey { headers["Idempotency-Key"] = idempotencyKey }
        return try await request(method, path, headers: headers, body: body)
    }

    func businessPost<T: Encodable>(_ b: TestBusiness, _ path: String, _ value: T, key: String? = nil, idempotencyKey: String? = nil) async throws -> HTTPResult {
        try await business(b, .POST, path, body: try ViadereJSON.encode(value), idempotencyKey: idempotencyKey, key: key)
    }

    @discardableResult
    func connect(_ consumer: TestConsumer, to business: TestBusiness, optIn: [InteractionPurpose] = []) async throws -> Relationship {
        let response = try await signedPost(consumer, APIRoutes.relationshipConnect.template,
                                            ConnectRequest(businessId: business.id, source: .code, optInPurposes: optIn))
        XCTAssertTrue([.ok, .created].contains(response.status), response.text)
        return try response.json(Relationship.self)
    }

    func issue(_ business: TestBusiness, relationship: Relationship, payload: InteractionPayload, purpose: InteractionPurpose = .security,
               priority: InteractionPriority = .normal, sensitivity: Sensitivity = .standard, key: String = UUID().uuidString,
               ttl: Int = 300, channels: [DeliveryChannel] = [.nativePush, .inApp]) async throws -> HTTPResult {
        let request = IssueInteractionRequest(relationshipId: relationship.id, purpose: purpose, payload: payload, priority: priority,
                                              sensitivity: sensitivity, allowedChannels: channels, ttlSeconds: ttl, idempotencyKey: key)
        return try await businessPost(business, APIRoutes.businessIssueInteraction.template, request)
    }

    func decision(_ consumer: TestConsumer, interaction: Interaction, decision: Decision = .approve, assurance: DecisionAssurance = .biometric,
                  signedAt: Date? = nil, signWith: SoftwareP256SigningKey? = nil, selected: [String]? = nil, reply: String? = nil,
                  challenge: ChallengeNonce? = nil) async throws -> SignedDecision {
        let device = consumer.device!
        let key: SoftwareP256SigningKey
        switch assurance {
        case .none: key = device.requestKey
        case .devicePasscode: key = device.passcodeKey
        case .biometric: key = device.biometricKey
        }
        let payload = DecisionPayload(interactionId: interaction.id, businessId: interaction.businessId, decision: decision,
                                      selectedOptionIds: selected, reply: reply, challenge: challenge ?? interaction.challenge,
                                      signedAt: signedAt ?? clock.now(), deviceId: device.id, assurance: assurance)
        return try await DecisionSigner(key: signWith ?? key).sign(payload)
    }

    /// The consumer-visible interaction (with the real device challenge).
    func consumerInteraction(_ consumer: TestConsumer, id: InteractionID) async throws -> Interaction {
        let response = try await signed(consumer, .GET, "/v1/interactions/\(id)")
        XCTAssertEqual(response.status, .ok, response.text)
        return try response.json(InteractionEnvelope.self).interaction
    }

    func decide(_ consumer: TestConsumer, id: InteractionID, signed decision: SignedDecision, channel: DeliveryChannel = .nativePush) async throws -> HTTPResult {
        try await signedPost(consumer, "/v1/interactions/\(id)/decision", DecideInteractionRequest(signedDecision: decision, channel: channel))
    }

    func runJobs() async throws { try await BackgroundJobs(app: app).runOnce() }
}

/// Runs a test body with a fresh application, always shutting it down.
func withHarness(_ adjust: (inout ServerConfig) -> Void = { _ in }, _ body: (TestHarness) async throws -> Void) async throws {
    let harness = try await TestHarness.make(adjust)
    do {
        try await body(harness)
    } catch {
        try? await harness.shutdown()
        throw error
    }
    try await harness.shutdown()
}

extension AuthorizePayload {
    static func sample(amount: String = "285.28") -> AuthorizePayload {
        AuthorizePayload(actionDescription: "Card purchase", amount: try? MoneyAmount(string: amount, currency: .usd), merchant: "Walmart",
                         location: "Mesa, Arizona", effectOfApproval: "Approves the charge")
    }
}

/// `XCTAssertEqual` for async expressions.
func eq<T: Equatable>(_ actual: @autoclosure () async throws -> T, _ expected: @autoclosure () throws -> T,
                      _ message: String = "", file: StaticString = #filePath, line: UInt = #line) async throws {
    let value = try await actual()
    XCTAssertEqual(value, try expected(), message, file: file, line: line)
}
