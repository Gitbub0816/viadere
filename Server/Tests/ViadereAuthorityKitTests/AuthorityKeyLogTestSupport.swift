@preconcurrency import Crypto
import _CryptoExtras
import Fluent
import Foundation
import Vapor
import ViadereCore
import ViadereServiceSupport
import XCTest
import XCTVapor
@testable import ViadereAuthorityKit

/// Device-side helpers for the key-log, recovery and link-service routes: what the app does, with software keys.
extension AuthorityHarness {
    static func makeWith(_ options: Options = Options(), _ mutate: @escaping @Sendable (inout AuthorityConfig) -> Void) async throws -> AuthorityHarness {
        var options = options
        options.mutateConfig = mutate
        return try await make(options)
    }

    static func kid(_ key: SoftwareP256SigningKey) -> String { KeyIdentifier.make(try! key.publicKey.signingKey()) }

    func post(_ path: String, _ object: [String: JSONValue], token: String = StaticCallerVerifier.apiToken) async throws -> (status: HTTPStatus, body: [String: JSONValue]) {
        let result = try await call(.POST, path, token: token, json: try CanonicalJSON.serialize(.object(object)))
        let body = (try? JSONDecoder().decode(JSONValue.self, from: result.body))?.objectValue ?? [:]
        return (result.status, body)
    }

    func nonce(_ entryType: String) async throws -> (id: String, value: String) {
        let result = try await post(AuthorityKeyLogRoute.nonces, ["entry_type": .string(entryType)])
        XCTAssertEqual(result.status, .ok)
        return (result.body["nonce_id"]!.stringValue!, result.body["nonce"]!.stringValue!)
    }

    /// `[{public_key, key_purpose, pop}]` with each PoP over `VIADERE-KEYLOG-V1\n{env}\n{type}\n{kid}\n{nonce}[\n{extra}]`.
    func submitted(_ keys: [(SoftwareP256SigningKey, DeviceKeyPurpose)], type: String, nonce: String, extra: [String] = [], popSigner: SoftwareP256SigningKey? = nil) async throws -> JSONValue {
        var items: [JSONValue] = []
        for (key, purpose) in keys {
            let message = AuthorityKeyLogFormat.popMessage(environment: .staging, type: type, kid: Self.kid(key), nonce: nonce, extra: extra)
            let pop = try await AuthorityKeyLogFormat.signPoP(popSigner ?? key, message: message)
            items.append(.object(["public_key": .string(key.publicKey.base64URL), "key_purpose": .string(purpose.rawValue), "pop": .string(pop)]))
        }
        return .array(items)
    }

    func genesis(_ keys: [(SoftwareP256SigningKey, DeviceKeyPurpose)]) async throws -> (status: HTTPStatus, accountId: UUID?, head: String?) {
        let nonce = try await nonce("genesis")
        let result = try await post(AuthorityKeyLogRoute.genesis, ["nonce_id": .string(nonce.id), "keys": try await submitted(keys, type: "genesis", nonce: nonce.value)])
        return (result.status, result.body["account_id"]?.stringValue.flatMap(UUID.init(uuidString:)), result.body["head"]?.stringValue)
    }

    func head(_ accountId: UUID) async throws -> String {
        let result = try await post(AuthorityKeyLogRoute.head, ["account_id": .string(accountId.uuidString)])
        XCTAssertEqual(result.status, .ok)
        return result.body["head"]!.stringValue!
    }

    func keylogChallenge(_ object: [String: JSONValue]) async throws -> (status: HTTPStatus, statement: AuthorityChallengeStatement?, body: [String: JSONValue]) {
        let result = try await post(AuthorityKeyLogRoute.challenges, object)
        guard result.status == .ok, let compact = result.body["statement"]?.stringValue else { return (result.status, nil, result.body) }
        return (result.status, try AuthorityStatementVerifier.verifyChallenge(compact, pinnedKeys: [statementKey], environment: .staging, now: clock.now), result.body)
    }

    func factor(_ statement: AuthorityChallengeStatement, key: SoftwareP256SigningKey, uv: FactorUserVerification = .biometric, match: String? = nil,
                decision: FactorDecision = .approve, mutate: ((inout FactorAssertionClaims) -> Void)? = nil) async throws -> String {
        var claims = try FactorAssertionClaims.answering(statement, decision: decision, userVerification: uv, match: decision == .approve ? match : nil, now: clock.now)
        mutate?(&claims)
        return try await FactorAssertion.sign(claims, with: key)
    }

    /// The device's enrollment: verify the head (exactly its own keys for a new entry, containing them for an imported one), then confirm it with a
    /// factor JWS and a PoP by each key over `head_hash`.
    @discardableResult
    func confirmEnrollment(keys: [SoftwareP256SigningKey], accountId: UUID, signer: SoftwareP256SigningKey? = nil, uv: FactorUserVerification = .biometric) async throws -> (status: HTTPStatus, body: [String: JSONValue]) {
        let kids = keys.map(Self.kid)
        let head = try AuthorityStatementVerifier.verifyHead(try await head(accountId), pinnedKeys: [statementKey], environment: .staging, ownKids: kids, minimumSeq: 0, now: clock.now)
        try AuthorityStatementVerifier.requireExactEntry(head, ownKids: kids)
        let created = try await keylogChallenge(["purpose": .string("enrollment_confirmed"), "account_id": .string(accountId.uuidString), "kids": .array(kids.map { .string($0) })])
        let statement = try XCTUnwrap(created.statement)
        XCTAssertEqual(statement.accountRef, head.accountRef)
        XCTAssertEqual(statement.kids, kids)
        let factor = try await factor(statement, key: signer ?? keys[0], uv: uv) {
            $0.headHash = head.headHash
            $0.seq = head.seq
        }
        var pops: [JSONValue] = []
        for key in keys {
            let pop = try await AuthorityKeyLogFormat.signPoP(key, message: AuthorityKeyLogFormat.popMessage(environment: .staging, type: "enrollment_confirmed",
                                                                                                         kid: Self.kid(key), nonce: head.headHash))
            pops.append(.object(["kid": .string(Self.kid(key)), "pop": .string(pop)]))
        }
        return try await post(AuthorityKeyLogRoute.evidence, ["factor": .string(factor), "pops": .array(pops)])
    }

    /// Recovery-seal custody for the tests (ADR-0034 §5): a KEK in the LocalKMS, its reviewed inventory row verified by the authority, an admin
    /// `seal-key-create`, then the serving context reloads with the unwrapped key (the seal kid as the development pin).
    @discardableResult
    func installSealKey(role: String = "active", executionId: String = "exec-\(UUID().uuidString)") async throws -> String {
        let kekName = role == "active" ? "recovery-seal-kek" : "recovery-seal-kek-standby"
        let version = try kms.createWrappingKey(kekName)
        let rsa = try await kms.rsaPublicKey(keyRef: "\(kekName)/\(version)")
        let p = try rsa.getKeyPrimitives()
        let jwk: JSONValue = .object(JWKThumbprint.rsaJWK(modulus: p.modulus, exponent: p.publicExponent))
        try await AuthorityAdmin.run(command: "key-inventory-record", changeFile: try CanonicalJSON.serialize(.object(["keys": .array([.object([
            "name": .string(kekName), "version": .string(version), "jwk": jwk])])])), commit: Self.commit, db: app.db, config: config, now: clock.now)
        try await AuthorityKeyInventory.verifyPending(kms: app.authority.kms, db: app.db, now: clock.now)
        try await AuthorityAdmin.run(command: "seal-key-create", changeFile: try CanonicalJSON.serialize(.object(["role": .string(role), "kek": .object([
            "name": .string(kekName), "version": .string(version), "jwk": jwk])])), commit: Self.commit, db: app.db, config: config, now: clock.now, executionId: executionId)
        let row = try await AuthoritySealKey.query(on: app.db).filter(\.$role == role).filter(\.$state == "ready").first()!
        if role == "active" { try await reloadSeal(pins: [row.id!]) }
        return row.id!
    }

    func reloadSeal(pins: [String]) async throws {
        let ctx = app.authority
        let seal = try await SealKeyHolder.load(kms: ctx.kms, db: app.db, pinnedKids: pins, now: clock.now)
        app.authority = AuthorityContext(config: ctx.config, kms: ctx.kms, keys: ctx.keys, clock: ctx.clock, seal: seal)
    }

    var sealPublicKey: P256.KeyAgreement.PublicKey { app.authority.seal!.privateKey.publicKey }
}

func XCTUnwrapAsync<T>(_ expression: @autoclosure () async throws -> T?, _ message: String = "", file: StaticString = #filePath, line: UInt = #line) async throws -> T {
    let value = try await expression()
    return try XCTUnwrap(value, message, file: file, line: line)
}

func XCTAssertNilAsync<T>(_ expression: @autoclosure () async throws -> T?, _ message: String = "", file: StaticString = #filePath, line: UInt = #line) async {
    do { let value = try await expression(); XCTAssertNil(value, message, file: file, line: line) } catch { XCTFail("threw \(error)", file: file, line: line) }
}

func XCTAssertNotNilAsync<T>(_ expression: @autoclosure () async throws -> T?, _ message: String = "", file: StaticString = #filePath, line: UInt = #line) async {
    do { let value = try await expression(); XCTAssertNotNil(value, message, file: file, line: line) } catch { XCTFail("threw \(error)", file: file, line: line) }
}
