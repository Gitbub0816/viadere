import Crypto
import Foundation
import Testing
import ViadereCore
@testable import ViadereKit

@MainActor
@Suite("Authenticator view model")
struct AuthenticatorViewModelTests {
    let secret = Base32.encode(Data("12345678901234567890".utf8))

    func make(server: InMemoryVaultServer? = nil, now: @escaping @Sendable () -> Date = { Date(timeIntervalSince1970: 59) }) -> (AuthenticatorViewModel, VaultEngine) {
        let engine = VaultEngine(store: InMemoryVaultLocalStore(), keys: SoftwareVaultKeyProvider(), api: server.map { InMemoryVaultSyncAPI(server: $0) }, clock: now)
        return (AuthenticatorViewModel(engine: engine, clock: now), engine)
    }

    @Test func emptyThenCreatedThenLockedAndUnlocked() async {
        let (vm, _) = make()
        await vm.load()
        #expect(vm.phase == .empty)
        await vm.createVault()
        #expect(vm.phase == .ready)
        await vm.lock()
        #expect(vm.phase == .locked && vm.rows.isEmpty)
        await vm.unlock()
        #expect(vm.phase == .ready)
    }

    @Test func addingAScannedCodeShowsALiveCodeAndCountdown() async {
        let (vm, _) = make()
        await vm.createVault()
        #expect(await vm.addCode(uri: "otpauth://totp/Example:anna@example.com?secret=\(secret)&issuer=Example"))
        let row = try! #require(vm.rows.first)
        #expect(row.title == "Example" && row.subtitle == "anna@example.com")
        #expect(row.code == "287082" && row.spacedCode == "287 082")
        #expect(row.secondsRemaining == 1 && row.period == 30)
        #expect(vm.codeToCopy(row.id) == "287082")
        // A QR code that isn't an authenticator code is refused with a plain sentence and nothing is added.
        #expect(await vm.addCode(uri: "https://example.com") == false)
        #expect(vm.message?.contains("otpauth://") == true)
        #expect(vm.rows.count == 1)
    }

    @Test func manualEntryValidatesTheSetupKey() async {
        let (vm, _) = make()
        await vm.createVault()
        #expect(await vm.addCode(issuer: "Acme", account: "anna", secret: "not base32!!") == false)
        #expect(await vm.addCode(issuer: "Acme", account: "", secret: secret) == false)
        #expect(await vm.addCode(issuer: "Acme", account: "anna", secret: "ME") == false)
        #expect(await vm.addCode(issuer: "Acme", account: "anna", secret: secret.lowercased().inserting(" ", every: 4)))
        #expect(vm.rows.map(\.title) == ["Acme"])
        await vm.delete(vm.rows[0].id)
        #expect(vm.rows.isEmpty)
    }

    @Test func displayTextIsSanitized() async {
        let (vm, _) = make()
        await vm.createVault()
        #expect(await vm.addCode(issuer: "Bank\u{202E}", account: "x", secret: secret) == false, "bidi controls are refused outright")
        let row = AuthenticatorViewModel.row(VaultItemPayload(body: .totp(TOTPParameters(secret: Data("12345678901234567890".utf8), issuer: "Shop", accountName: "a\u{200B}b")), createdAt: Date()), codes: [:])
        #expect(row?.subtitle == "ab")
    }

    @Test func enablingSyncNeedsTheRecoveryKeyTypedBackAndNeverKeepsItAfterwards() async {
        let server = InMemoryVaultServer()
        let (vm, engine) = make(server: server)
        await vm.createVault()
        await vm.beginEnablingSync()
        let shown = try! #require(vm.recoveryKeyText)
        #expect(vm.syncStep == .showingRecoveryKey && shown.hasPrefix("VRK1-"))
        #expect(await vm.confirmRecoveryKeyAndEnableSync(typed: "VRK1-WRONG") == false)
        #expect(server.version == 0, "nothing is uploaded until the key is confirmed")
        #expect(await vm.confirmRecoveryKeyAndEnableSync(typed: shown.lowercased()))
        #expect(vm.recoveryKeyText == nil && vm.syncStep == .idle)
        #expect(vm.syncInfo?.enabled == true && vm.syncInfo?.hasRecoveryKey == true)
        #expect(try! await engine.verifyRecoveryKey(shown))
        // Cancelling releases it too.
        await vm.beginReplacingRecoveryKey()
        #expect(vm.recoveryKeyText != nil)
        vm.cancelEnablingSync()
        #expect(vm.recoveryKeyText == nil)
    }

    @Test func syncUnavailableIsReportedNotThrown() async {
        let server = InMemoryVaultServer()
        server.available = false
        let (vm, _) = make(server: server)
        await vm.createVault()
        await vm.load()
        #expect(vm.syncAvailable == false)
        await vm.beginEnablingSync()
        let shown = vm.recoveryKeyText!
        #expect(await vm.confirmRecoveryKeyAndEnableSync(typed: shown) == false)
        #expect(vm.syncFailure == "Sync isn't available yet.")
        #expect(vm.recoveryKeyText == nil)
    }

    @Test func addingADeviceEndToEnd() async {
        let server = InMemoryVaultServer()
        let (a, _) = make(server: server)
        let (b, _) = make(server: server)
        await a.createVault()
        _ = await a.addCode(uri: "otpauth://totp/Example:one?secret=\(secret)&issuer=Example")
        await a.beginEnablingSync()
        _ = await a.confirmRecoveryKeyAndEnableSync(typed: a.recoveryKeyText!)
        await a.beginAddingDevice()
        let code = try! #require(a.invite?.code)
        #expect(await b.requestJoin(code: "AAAA-AAAA") == false)
        #expect(await b.requestJoin(code: code))
        #expect(await b.completeJoin() == false, "not approved yet")
        await a.checkForJoinRequest()
        #expect(a.joinPreview != nil)
        #expect(await a.approveJoin())
        #expect(await b.completeJoin())
        #expect(b.rows.count == 1)
        await a.loadDevices()
        #expect(a.devices.filter { !$0.isRecovery }.count == 2)
        let other = a.devices.first { !$0.isThisDevice && !$0.isRecovery }!
        await a.removeDevice(other.memberId)
        #expect(a.devices.filter { !$0.isRecovery }.count == 1)
    }
}

private extension String {
    func inserting(_ separator: String, every n: Int) -> String {
        var out = ""
        for (index, char) in enumerated() {
            if index > 0, index % n == 0 { out += separator }
            out.append(char)
        }
        return out
    }
}

@Suite("Credential Exchange import")
struct CredentialExchangeTests {
    func export(passkeys: [[String: Any]] = [], totps: [[String: Any]] = [], extra: [[String: Any]] = []) throws -> Data {
        let credentials = passkeys + totps + extra
        let root: [String: Any] = ["version": ["major": 1, "minor": 0], "exporterRpId": "passwords.example", "accounts": [["id": "a", "collections": [["id": "c", "items": [
            ["id": "i", "title": "Example", "credentials": credentials]]]]]]]
        return try JSONSerialization.data(withJSONObject: root)
    }

    @Test func importsES256PasskeysAndTOTPAndReportsTheRest() async throws {
        let key = P256.Signing.PrivateKey()
        let passkey: [String: Any] = ["type": "passkey", "credentialId": Base64URL.encode(Data(repeating: 7, count: 32)), "rpId": "example.com", "username": "anna",
                                      "userDisplayName": "Anna", "userHandle": Base64URL.encode(Data([1, 2, 3])), "key": Base64URL.encode(key.derRepresentation)]
        let totp: [String: Any] = ["type": "totp", "secret": Base32.encode(Data("12345678901234567890".utf8)), "period": 30, "digits": 6, "algorithm": "sha1", "issuer": "Example", "username": "anna"]
        let rsa: [String: Any] = ["type": "passkey", "credentialId": "AAAA", "rpId": "example.com", "username": "x", "userHandle": "AQ", "key": Base64URL.encode(Data(repeating: 1, count: 100))]
        let password: [String: Any] = ["type": "basic-auth", "username": "anna"]
        let result = try CredentialExchange.parse(try export(passkeys: [passkey, rsa], totps: [totp], extra: [password]), now: Date(timeIntervalSince1970: 1_800_000_000))
        #expect(result.items.count == 2 && result.skipped.count == 2)
        guard case .passkey(let credential) = result.items[0].body else { Issue.record("no passkey"); return }
        #expect(credential.privateKey == key.rawRepresentation && credential.rpId == "example.com" && credential.userHandle == Data([1, 2, 3]))
        #expect(result.skipped.map(\.reason).contains { $0.contains("ES256") } && result.skipped.map(\.reason).contains { $0.contains("basic-auth") })

        let engine = VaultEngine(store: InMemoryVaultLocalStore(), keys: SoftwareVaultKeyProvider())
        try await engine.create()
        #expect(try await engine.importExchange(result) == 2)
        #expect(try await engine.importExchange(result) == 0, "importing twice adds nothing")
        // The imported passkey signs with the imported key.
        let hash = Data(repeating: 9, count: 32)
        let assertion = try await engine.assertPasskey(credentialId: credential.credentialId, rpId: "example.com", clientDataHash: hash, userVerified: true)
        #expect(try ReferenceCheck.verify(assertion, key: key.publicKey, rpId: "example.com", clientDataHash: hash))
    }

    @Test func rejectsMalformedOrUnsupportedExports() throws {
        #expect(throws: CredentialExchange.ImportError.malformed) { try CredentialExchange.parse(Data("nope".utf8), now: Date()) }
        #expect(throws: CredentialExchange.ImportError.malformed) { try CredentialExchange.parse(Data("{}".utf8), now: Date()) }
        #expect(throws: CredentialExchange.ImportError.unsupportedVersion) { try CredentialExchange.parse(Data(#"{"version":{"major":2},"accounts":[]}"#.utf8), now: Date()) }
        #expect(throws: CredentialExchange.ImportError.tooLarge) { try CredentialExchange.parse(Data(count: CredentialExchange.maxBytes + 1), now: Date()) }
    }
}
