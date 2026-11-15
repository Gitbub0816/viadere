@preconcurrency import Crypto
import Fluent
import Foundation
import SwiftASN1
import ViadereCore
import XCTest
@preconcurrency import X509
@testable import ViadereServerKit

/// A synthetic App Attest PKI: a test root, an intermediate and (per attestation) a credential certificate. Production only ever
/// trusts Apple's root; the tests inject this one through `AppAttestVerifier(trustedRoots:)`.
struct TestAppAttestPKI {
    static let teamID = "TEAMID1234"
    static let bundleID = "com.viadere.app"
    static let clipBundleID = "com.viadere.app.Clip"

    let rootKey = P256.Signing.PrivateKey()
    let intermediateKey = P256.Signing.PrivateKey()
    let root: Certificate
    let intermediate: Certificate
    let rootName = try! DistinguishedName { CommonName("Test App Attestation Root CA") }
    let intermediateName = try! DistinguishedName { CommonName("Test App Attestation CA 1") }

    init(now: Date = Date(timeIntervalSince1970: 1_800_000_000), rootNotAfter: Date? = nil) {
        let rootName = try! DistinguishedName { CommonName("Test App Attestation Root CA") }
        let intermediateName = try! DistinguishedName { CommonName("Test App Attestation CA 1") }
        root = try! Certificate(version: .v3, serialNumber: .init(), publicKey: .init(rootKey.publicKey), notValidBefore: now.addingTimeInterval(-86_400 * 400),
                                notValidAfter: rootNotAfter ?? now.addingTimeInterval(86_400 * 4000), issuer: rootName, subject: rootName,
                                signatureAlgorithm: .ecdsaWithSHA256,
                                extensions: try! Certificate.Extensions { Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil)) },
                                issuerPrivateKey: .init(rootKey))
        intermediate = try! Certificate(version: .v3, serialNumber: .init(), publicKey: .init(intermediateKey.publicKey), notValidBefore: now.addingTimeInterval(-86_400 * 300),
                                        notValidAfter: now.addingTimeInterval(86_400 * 3000), issuer: rootName, subject: intermediateName,
                                        signatureAlgorithm: .ecdsaWithSHA256,
                                        extensions: try! Certificate.Extensions { Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 0)) },
                                        issuerPrivateKey: .init(rootKey))
    }

    func verifier(clock: any ServerClock, environment: AppAttestEnvironment = .production, roots: [Certificate]? = nil) -> AppAttestVerifier {
        AppAttestVerifier(teamID: Self.teamID, appBundleID: Self.bundleID, clipBundleID: Self.clipBundleID, environment: environment,
                          trustedRoots: roots ?? [root], clock: clock)
    }

    /// What can be made wrong in an attestation.
    struct Flaws {
        var nonceOverride: Data?
        var rpId: String?
        var counter: UInt32 = 0
        var aaguid: Data?
        var keyIdOverride: Data?
        var credentialIdOverride: Data?
        var format = "apple-appattest"
        var leafNotBefore: Date?
        var leafNotAfter: Date?
        var otherPKI: TestAppAttestPKI?
        var skipIntermediate = false
    }

    struct Made {
        var evidence: AppAttestEvidence
        var key: P256.Signing.PrivateKey
        var keyId: Data
        var authData: Data
        var attestationObject: Data
    }

    /// A genuine-looking attestation for `clientDataHash`, optionally flawed.
    func attest(clientDataHash: Data, environment: AppAttestEnvironment = .production, clientKind: DeviceClientKind = .app,
                now: Date = Date(timeIntervalSince1970: 1_800_000_000), flaws: Flaws = Flaws(), key: P256.Signing.PrivateKey = P256.Signing.PrivateKey()) throws -> Made {
        let signer = flaws.otherPKI ?? self
        let x963 = key.publicKey.x963Representation
        let keyId = Data(SHA256.hash(data: x963))
        let bundle = clientKind == .appClip ? Self.clipBundleID : Self.bundleID
        let rpHash = Data(SHA256.hash(data: Data((flaws.rpId ?? "\(Self.teamID).\(bundle)").utf8)))
        let credentialId = flaws.credentialIdOverride ?? keyId
        var authData = rpHash
        authData.append(0x40)
        authData.append(contentsOf: [UInt8(flaws.counter >> 24), UInt8((flaws.counter >> 16) & 0xFF), UInt8((flaws.counter >> 8) & 0xFF), UInt8(flaws.counter & 0xFF)])
        authData.append(flaws.aaguid ?? environment.aaguid)
        authData.append(contentsOf: [0, UInt8(credentialId.count)])
        authData.append(credentialId)
        authData.append(CBOR.encode(.map([
            .init(key: .unsigned(1), value: .unsigned(2)), .init(key: .unsigned(3), value: .negative(-7)), .init(key: .negative(-1), value: .unsigned(1)),
            .init(key: .negative(-2), value: .bytes(x963.subdata(in: 1..<33))), .init(key: .negative(-3), value: .bytes(x963.subdata(in: 33..<65))),
        ])))
        let nonce = flaws.nonceOverride ?? Data(SHA256.hash(data: authData + clientDataHash))
        // SEQUENCE { [1] EXPLICIT { OCTET STRING nonce } }
        var inner: [UInt8] = [0x04, UInt8(nonce.count)]
        inner.append(contentsOf: nonce)
        var tagged: [UInt8] = [0xA1, UInt8(inner.count)]
        tagged.append(contentsOf: inner)
        var extensionValue: [UInt8] = [0x30, UInt8(tagged.count)]
        extensionValue.append(contentsOf: tagged)
        var extensions = try Certificate.Extensions { Critical(BasicConstraints.notCertificateAuthority) }
        try extensions.append(Certificate.Extension(oid: AppAttestVerifier.nonceExtensionOID, critical: false, value: ArraySlice(extensionValue)))
        let leafName = try DistinguishedName { CommonName("0000000000000000000000000000000000000000000000000000000000000000") }
        let leaf = try Certificate(version: .v3, serialNumber: .init(), publicKey: .init(key.publicKey),
                                   notValidBefore: flaws.leafNotBefore ?? now.addingTimeInterval(-60), notValidAfter: flaws.leafNotAfter ?? now.addingTimeInterval(86_400 * 3),
                                   issuer: signer.intermediateName, subject: leafName, signatureAlgorithm: .ecdsaWithSHA256, extensions: extensions,
                                   issuerPrivateKey: .init(signer.intermediateKey))
        func der(_ certificate: Certificate) throws -> Data {
            var serializer = DER.Serializer()
            try serializer.serialize(certificate)
            return Data(serializer.serializedBytes)
        }
        var chain: [CBORValue] = [.bytes(try der(leaf))]
        if !flaws.skipIntermediate { chain.append(.bytes(try der(signer.intermediate))) }
        let object = CBOR.encode(.map([
            .init(key: .text("fmt"), value: .text(flaws.format)),
            .init(key: .text("attStmt"), value: .map([.init(key: .text("x5c"), value: .array(chain)), .init(key: .text("receipt"), value: .bytes(Data("receipt".utf8)))])),
            .init(key: .text("authData"), value: .bytes(authData)),
        ]))
        let evidence = AppAttestEvidence(keyId: (flaws.keyIdOverride ?? keyId).base64EncodedString(), attestation: Base64URL.encode(object))
        return Made(evidence: evidence, key: key, keyId: keyId, authData: authData, attestationObject: object)
    }

    /// An assertion object (`{signature, authenticatorData}`) over `clientData` made with `key`.
    static func assertion(key: P256.Signing.PrivateKey, clientData: Data, counter: UInt32, rpId: String? = nil, clientKind: DeviceClientKind = .app,
                          signWith: P256.Signing.PrivateKey? = nil, signedClientData: Data? = nil) throws -> Data {
        let bundle = clientKind == .appClip ? clipBundleID : bundleID
        var authData = Data(SHA256.hash(data: Data((rpId ?? "\(teamID).\(bundle)").utf8)))
        authData.append(0x00)
        authData.append(contentsOf: [UInt8(counter >> 24), UInt8((counter >> 16) & 0xFF), UInt8((counter >> 8) & 0xFF), UInt8(counter & 0xFF)])
        let nonce = Data(SHA256.hash(data: authData + Data(SHA256.hash(data: signedClientData ?? clientData))))
        let signature = try (signWith ?? key).signature(for: nonce)
        return CBOR.encode(.map([.init(key: .text("signature"), value: .bytes(signature.derRepresentation)),
                                 .init(key: .text("authenticatorData"), value: .bytes(authData))]))
    }
}

extension TestHarness {
    /// A harness with its own integrity verifier and App Attest mode (the production default `Overrides.integrity == nil` is Apple's root).
    static func make(mode: AppAttestMode, integrity: (ManualClock) -> any DeviceIntegrityVerifier, _ adjust: (inout ServerConfig) -> Void = { _ in }) async throws -> TestHarness {
        var config = ServerConfig.testing()
        config.appAttestMode = mode
        config.appAttestEnvironment = .production
        adjust(&config)
        let postgres = ProcessInfo.processInfo.environment["TEST_DATABASE_URL"].flatMap { $0.isEmpty ? nil : $0 }
        if let postgres { config.databaseURL = postgres }
        let clock = ManualClock(Date(timeIntervalSince1970: 1_800_000_000))
        let apns = RecordingAPNsSender()
        let sms = RecordingSMSProvider()
        let transport = ScriptedWebhookTransport()
        let signer = FakePassSigner()
        let passPush = RecordingPassPush()
        let app = try await makeApplication(environment: .testing, config: config, overrides: Overrides(
            clock: clock, apns: apns, sms: sms, passkeys: FakePasskeyVerifier(), webhookTransport: transport, autoMigrate: postgres != nil,
            passSigner: signer, passPush: passPush, integrity: integrity(clock)))
        let harness = TestHarness(app: app, clock: clock, config: config, signer: signer, passPush: passPush)
        harness.bind(apns: apns, sms: sms, transport: transport)
        return harness
    }

    /// Enrolls a device with App Attest evidence built by `evidence(keys, challenge, consumerId)` (the way the app derives it from the
    /// enrollment challenge and the key list). Returns the raw response and the keys.
    func enrollAttested(_ consumer: TestConsumer, purposes: [DeviceKeyPurpose] = DeviceKeyPurpose.allCases, clientKind: DeviceClientKind = .app,
                        replaces: DeviceID? = nil, login: Bool = true,
                        evidence: ([DeviceKeyRegistration], String, ConsumerID) throws -> AppAttestEvidence?) async throws -> (HTTPResult, TestDevice?, TestConsumer) {
        var consumer = consumer
        if consumer.device != nil, login { consumer = try await self.login(consumer) }
        let auth = ["Authorization": "Bearer \(consumer.token)"]
        let begin = try await request(.POST, APIRoutes.deviceEnrollBegin.template, headers: auth)
        XCTAssertEqual(begin.status, .ok, begin.text)
        let challenge = try begin.json(DeviceEnrollmentChallenge.self)
        let keyMap: [DeviceKeyPurpose: SoftwareP256SigningKey] = Dictionary(uniqueKeysWithValues: purposes.map { ($0, SoftwareP256SigningKey()) })
        var registrations: [DeviceKeyRegistration] = []
        for purpose in purposes {
            registrations.append(try await DeviceEnrollment.register(key: keyMap[purpose]!, purpose: purpose, hardwareBacked: true, consumerId: consumer.id,
                                                                    challenge: challenge.challenge))
        }
        let attest = try evidence(registrations, challenge.challenge, consumer.id)
        let response = try await post(APIRoutes.deviceEnroll.template, DeviceEnrollRequest(
            name: "Phone", platform: .iOS, challenge: challenge.challenge, keys: registrations,
            assertion: enrollmentAssertion(consumer, challenge: challenge.challenge), clientKind: clientKind, appAttest: attest, replacesDeviceId: replaces), headers: auth)
        guard response.status == .created, let device = try? response.json(Device.self) else { return (response, nil, consumer) }
        let enrolled = TestDevice(id: device.id, requestKey: keyMap[.request]!, passcodeKey: keyMap[.approvalUserPresence] ?? SoftwareP256SigningKey(),
                                  biometricKey: keyMap[.approvalBiometric] ?? SoftwareP256SigningKey())
        consumer.device = enrolled
        return (response, enrolled, consumer)
    }
}

/// The `evidence` closure of a genuine app: attests over the real client-data binding.
func genuineEvidence(_ pki: TestAppAttestPKI, clock: any ServerClock, clientKind: DeviceClientKind = .app, flaws: TestAppAttestPKI.Flaws = .init(),
                     key: P256.Signing.PrivateKey = P256.Signing.PrivateKey())
    -> ([DeviceKeyRegistration], String, ConsumerID) throws -> AppAttestEvidence? {
    { keys, challenge, consumer in
        try pki.attest(clientDataHash: AppAttestBinding.clientDataHash(consumerId: consumer, challenge: challenge, keys: keys), clientKind: clientKind,
                       now: clock.now(), flaws: flaws, key: key).evidence
    }
}

/// Runs a body against a harness whose integrity verifier trusts `pki` (or `roots`), in App Attest `mode`; always shuts down.
func withAttestHarness(_ pki: TestAppAttestPKI = TestAppAttestPKI(), mode: AppAttestMode, environment: AppAttestEnvironment = .production,
                       roots: [Certificate]? = nil, _ adjust: (inout ServerConfig) -> Void = { _ in },
                       _ body: (TestHarness, TestAppAttestPKI) async throws -> Void) async throws {
    let harness = try await TestHarness.make(mode: mode, integrity: { clock in pki.verifier(clock: clock, environment: environment, roots: roots) }, adjust)
    do {
        try await body(harness, pki)
    } catch {
        try? await harness.shutdown()
        throw error
    }
    try await harness.shutdown()
}
