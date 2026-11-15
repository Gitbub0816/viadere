@preconcurrency import Crypto
import _CryptoExtras
import Fluent
import FluentSQL
import Foundation
import NIOHTTP1
import NIOPosix
import SQLKit
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// WP-B2 (server portability to Azure): the security tests the plan lists ("Tests first") and the configuration around them.
final class AzurePlatformTests: XCTestCase {
    static let identityEndpoint = "http://127.0.0.1:42356/msi/token"

    // MARK: Managed identity: SSRF guard

    /// A request whose URL is, or resolves to, the managed-identity endpoint (or the metadata services) is refused by every outbound client, before any
    /// connection is made.
    func testEveryOutboundClientRefusesTheIdentityEndpoint() async throws {
        let resolver = stubResolver(["rebind.attacker.example": "127.0.0.1", "rebind6.attacker.example": "::1", "metadata.attacker.example": "169.254.169.254",
                                     "wire.attacker.example": "168.63.129.16", "mapped.attacker.example": "::ffff:127.0.0.1", "api.partner.example": "93.184.216.34",
                                     "localhost": "127.0.0.1"])
        let destinationGuard = OutboundDestinationGuard(identityEndpoint: Self.identityEndpoint, resolve: resolver)
        let refused = [
            Self.identityEndpoint, "http://127.0.0.1:42356/msi/token?resource=https://vault.azure.net", "http://127.0.0.1:8080/other", "http://localhost:42356/msi/token",
            "http://[::1]:42356/msi/token", "https://rebind.attacker.example/hook", "https://rebind6.attacker.example/hook", "https://mapped.attacker.example/",
            "http://169.254.169.254/metadata/identity/oauth2/token", "https://metadata.attacker.example/", "https://wire.attacker.example/", "http://127.1:42356/",
        ]
        for url in refused {
            do { try await destinationGuard.check(URL(string: url)!); XCTFail("guard allowed \(url)") } catch {}
        }
        try await destinationGuard.check(URL(string: "https://api.partner.example/v1/send")!)

        // The generic client every provider uses (SMS, email, RCS, Didit, domain checks).
        let base = RecordingClient()
        let client = GuardedClient(base: base, guard: destinationGuard)
        for url in refused {
            do { _ = try await client.post(URI(string: url)).get(); XCTFail("client sent to \(url)") } catch {}
        }
        XCTAssertTrue(base.sent.isEmpty, "nothing reached the network")
        _ = try await client.post(URI(string: "https://api.partner.example/v1/send")).get()
        XCTAssertEqual(base.sent, ["https://api.partner.example/v1/send"])

        // The webhook transport, also in its development mode that otherwise allows loopback targets.
        for allowInsecure in [true, false] {
            let webhookBase = RecordingClient()
            let transport = VaporWebhookTransport(client: webhookBase, allowInsecure: allowInsecure, guard: destinationGuard)
            for url in refused {
                do {
                    _ = try await transport.send(WebhookHTTPRequest(url: URL(string: url)!, headers: [:], body: Data("{}".utf8)))
                    XCTFail("webhook transport sent to \(url)")
                } catch let error as WebhookTransportError { XCTAssertEqual(error, .blockedDestination, url) }
            }
            XCTAssertTrue(webhookBase.sent.isEmpty)
        }

        // The cloud REST client (Key Vault, Blob, Service Bus) and the boot-time client.
        let cloudBase = RecordingClient()
        let cloud = VaporOutboundHTTP(client: cloudBase, guard: destinationGuard)
        for url in ["https://rebind.attacker.example/keys/x", "https://metadata.attacker.example/", "https://127.0.0.1:42356/msi/token", "https://localhost/x"] {
            do { _ = try await cloud.send(method: .GET, url: url, headers: [:], body: nil); XCTFail("cloud client sent to \(url)") } catch {}
        }
        XCTAssertTrue(cloudBase.sent.isEmpty)
        let standalone = StandaloneOutboundHTTP(guard: destinationGuard)
        do { _ = try await standalone.send(method: .GET, url: "https://rebind.attacker.example/", headers: [:], body: nil); XCTFail() } catch let refusal as OutboundDestinationGuard.Refusal {
            XCTAssertEqual(refusal, .identityEndpoint)
        }

        // Without a managed identity (development, tests, Fly) loopback stays usable, the metadata services never are.
        let local = OutboundDestinationGuard(identityEndpoint: nil, resolve: resolver)
        try await local.check(URL(string: "http://127.0.0.1:8080/hook")!)
        do { try await local.check(URL(string: "http://169.254.169.254/metadata/identity/oauth2/token")!); XCTFail() } catch {}
        do { try await local.check(URL(string: "https://metadata.attacker.example/")!); XCTFail() } catch {}
        // The environment is where Container Apps puts the endpoint.
        XCTAssertTrue(OutboundDestinationGuard.fromEnvironment(["IDENTITY_ENDPOINT": "http://localhost:42356/msi/token"]).refuseLoopback)
    }

    /// Only the identity client talks to the identity endpoint, and only to exactly that endpoint.
    func testTheIdentityClientSendsOnlyToTheConfiguredEndpoint() async throws {
        let client = IdentityEndpointHTTP(endpoint: Self.identityEndpoint)
        for url in ["http://127.0.0.1:42356/other", "http://127.0.0.1:42357/msi/token", "https://127.0.0.1:42356/msi/token", "http://evil.example/msi/token"] {
            do { _ = try await client.send(method: .GET, url: url, headers: [:], body: nil); XCTFail(url) } catch let error as AzureIdentityError { XCTAssertEqual(error, .notConfigured) }
        }
        do { _ = try await client.send(method: .POST, url: Self.identityEndpoint, headers: [:], body: nil); XCTFail() } catch let error as AzureIdentityError { XCTAssertEqual(error, .notConfigured) }
    }

    /// The managed-identity token request (api-version, audience, client id, secret header) and its cache.
    func testManagedIdentityTokensAreRequestedPerAudienceAndCachedUntilFiveMinutesBeforeExpiry() async throws {
        final class Endpoint: OutboundHTTP, @unchecked Sendable {
            let lock = NSLock()
            var urls: [String] = []
            var headers: [[String: String]] = []
            let expires: Date
            init(expires: Date) { self.expires = expires }
            func send(method: NIOHTTP1.HTTPMethod, url: String, headers: [String: String], body: Data?) async throws -> (status: Int, body: Data) {
                lock.withLock { urls.append(url); self.headers.append(headers) }
                let object: [String: Any] = ["access_token": "tok-\(urls.count)", "expires_on": String(Int(expires.timeIntervalSince1970)), "token_type": "Bearer"]
                return (200, try JSONSerialization.data(withJSONObject: object))
            }
        }
        let clock = ManualClock(Date(timeIntervalSince1970: 1_800_000_000))
        let endpoint = Endpoint(expires: clock.now().addingTimeInterval(3600))
        let identity = AzureManagedIdentity(endpoint: Self.identityEndpoint, identityHeader: "secret-header", clientId: "client-123", http: endpoint, now: { clock.now() })
        let first = try await identity.token(for: .keyVault)
        let again = try await identity.token(for: .keyVault)
        XCTAssertEqual(first, again, "cached")
        _ = try await identity.token(for: .storage)
        XCTAssertEqual(endpoint.urls.count, 2, "one request per audience")
        let components = try XCTUnwrap(URLComponents(string: endpoint.urls[0]))
        let query = Dictionary(uniqueKeysWithValues: (components.queryItems ?? []).map { ($0.name, $0.value ?? "") })
        XCTAssertEqual(query["api-version"], "2019-08-01")
        XCTAssertEqual(query["resource"], "https://vault.azure.net")
        XCTAssertEqual(query["client_id"], "client-123", "the user-assigned identity is always named")
        XCTAssertEqual(endpoint.headers[0]["X-IDENTITY-HEADER"], "secret-header")
        clock.advance(by: 3600 - 299)
        _ = try await identity.token(for: .keyVault)
        XCTAssertEqual(endpoint.urls.count, 3, "refreshed within five minutes of expiry")
        XCTAssertNil(AzureManagedIdentity.fromEnvironment(["IDENTITY_ENDPOINT": Self.identityEndpoint, "IDENTITY_HEADER": "h"]), "no client id: no identity")
    }

    // MARK: KMS

    /// A Key Vault signature verifies against the published public key of the version that signed it; a different version's key does not verify it,
    /// and a response signed by any other key is refused before it is used.
    func testKeyVaultSignatureVerifiesAgainstThePublishedKeyAndAWrongVersionFails() async throws {
        let stub = AzureStub()
        let v1 = stub.addECKey("audit-head-signing")
        let v2 = stub.addECKey("audit-head-signing")
        let tokens = FakeAccessTokens()
        let kms = try AzureKeyVaultKMS(vaultURL: AzureStub.vault + "/", tokens: tokens, http: stub)
        let message = Data("head message".utf8)
        let digest = Data(SHA256.hash(data: message))

        let signature = try P256.Signing.ECDSASignature(rawRepresentation: try await kms.sign(keyRef: "audit-head-signing/\(v1)", digest: digest))
        XCTAssertTrue(try XCTUnwrap(stub.publicKey("audit-head-signing", version: v1)).isValidSignature(signature, for: message))
        XCTAssertFalse(try XCTUnwrap(stub.publicKey("audit-head-signing", version: v2)).isValidSignature(signature, for: message), "another version's key must not verify it")
        XCTAssertTrue(ViadereSignatureEncoding.isCanonical(signature), "low-S, Viadere's canonical form")
        // The unversioned reference resolves to the current version, explicitly.
        let pinned = try await kms.resolveVersion(keyRef: "audit-head-signing")
        XCTAssertEqual(pinned, "audit-head-signing/\(v2)")
        let current = try P256.Signing.ECDSASignature(rawRepresentation: try await kms.sign(keyRef: "audit-head-signing", digest: digest))
        XCTAssertTrue(try XCTUnwrap(stub.publicKey("audit-head-signing", version: v2)).isValidSignature(current, for: message))
        XCTAssertTrue(stub.calls.contains { $0.url.contains("/keys/audit-head-signing/\(v2)/sign?api-version=2025-07-01") }, "every sign call names its version")
        // A version that does not exist, and a substituted key, fail closed.
        do { _ = try await kms.sign(keyRef: "audit-head-signing/" + String(repeating: "0", count: 32), digest: digest); XCTFail() } catch {}
        stub.signWithForeignKey = true
        do { _ = try await kms.sign(keyRef: "audit-head-signing/\(v1)", digest: digest); XCTFail("a signature from another key was accepted") } catch let error as KMSError {
            XCTAssertEqual(error, .signatureMismatch)
        }
        stub.signWithForeignKey = false
        do { _ = try await kms.sign(keyRef: "audit-head-signing", digest: Data(repeating: 1, count: 31)); XCTFail() } catch let error as KMSError { XCTAssertEqual(error, .invalidDigest) }
        XCTAssertGreaterThan(tokens.requests(.keyVault), 0)
        XCTAssertTrue(stub.calls.allSatisfy { $0.headers["Authorization"] == "Bearer token-for-vault.azure.net" }, "Key Vault calls carry only the Key Vault token")

        // The same contract for the local KMS of development and tests.
        let local = LocalKMS()
        let l1 = local.createSigningKey("kd-log-signing")
        let l2 = local.createSigningKey("kd-log-signing")
        let localSignature = try P256.Signing.ECDSASignature(rawRepresentation: try await local.sign(keyRef: "kd-log-signing/\(l1)", digest: digest))
        let localKey1 = try await local.publicKey(keyRef: "kd-log-signing/\(l1)")
        let localKey2 = try await local.publicKey(keyRef: "kd-log-signing/\(l2)")
        XCTAssertTrue(localKey1.isValidSignature(localSignature, for: message))
        XCTAssertFalse(localKey2.isValidSignature(localSignature, for: message))
    }

    /// RSA-OAEP-256 wrap and unwrap: the wrapped value names its exact version; another version cannot unwrap it.
    func testKeyWrappingRoundTripsAndAnotherVersionCannotUnwrap() async throws {
        let stub = AzureStub()
        let v1 = try stub.addRSAKey("kek-data")
        let v2 = try stub.addRSAKey("kek-data")
        let kms = try AzureKeyVaultKMS(vaultURL: AzureStub.vault, tokens: FakeAccessTokens(), http: stub)
        let secret = Data(SecureToken.generate().utf8)
        let wrapped = try await kms.wrap(keyRef: "kek-data/\(v1)", plaintext: secret)
        XCTAssertEqual(wrapped.keyRef, "kek-data/\(v1)")
        let unwrapped = try await kms.unwrap(keyRef: wrapped.keyRef, ciphertext: wrapped.ciphertext)
        XCTAssertEqual(unwrapped, secret)
        do { _ = try await kms.unwrap(keyRef: "kek-data/\(v2)", ciphertext: wrapped.ciphertext); XCTFail("another version unwrapped it") } catch {}
        do { _ = try await kms.unwrap(keyRef: "kek-data", ciphertext: wrapped.ciphertext); XCTFail("an unversioned unwrap is refused") } catch {}
        var tampered = wrapped.ciphertext
        tampered[tampered.count / 2] ^= 0x01
        do { _ = try await kms.unwrap(keyRef: wrapped.keyRef, ciphertext: tampered); XCTFail() } catch {}
        XCTAssertNil(AzureKeyVaultKMS.normalizedVaultURL("http://kv.vault.azure.net"))
        XCTAssertNil(AzureKeyVaultKMS.normalizedVaultURL("https://evil.example.com"))
        XCTAssertNil(AzureKeyVaultKMS.normalizedVaultURL("https://kv.vault.azure.net/keys"))
    }

    // MARK: Envelope-wrapped secrets at boot

    func testWrappedServerSecretsAreUnwrappedAtBootAndRefusedWhenAmbiguousOrForeign() async throws {
        let kms = LocalKMS()
        let version = try kms.createWrappingKey("kek-data")
        let pepper = SecureToken.generate()
        let wrapped = WrappedSecrets.encode(try await kms.wrap(keyRef: "kek-data", plaintext: Data(pepper.utf8)))
        XCTAssertTrue(wrapped.hasPrefix("kms1:kek-data/\(version):"))
        let base = ["ENVIRONMENT": "development", "AZURE_KEY_VAULT_KEK_KEY": "kek-data"]
        let resolved = try await WrappedSecrets.resolve(base.merging(["SERVER_PEPPER_WRAPPED": wrapped]) { $1 }, kms: kms)
        XCTAssertEqual(resolved["SERVER_PEPPER"], pepper)
        XCTAssertNil(resolved["SERVER_PEPPER_WRAPPED"])
        XCTAssertEqual(try ServerConfig.fromEnvironment(resolved.filter { $0.key != "AZURE_KEY_VAULT_KEK_KEY" }).pepper, Base64URL.decode(pepper))
        // Plain and wrapped together: refused (which one wins must never be a guess).
        await XCTAssertThrowsAsync(try await WrappedSecrets.resolve(base.merging(["SERVER_PEPPER_WRAPPED": wrapped, "SERVER_PEPPER": pepper]) { $1 }, kms: kms))
        // Wrapped under another key name, unversioned, tampered, unknown variable, no KEK configured, no KMS: refused.
        let other = try kms.createWrappingKey("other-key")
        let foreign = WrappedSecrets.encode(try await kms.wrap(keyRef: "other-key/\(other)", plaintext: Data(pepper.utf8)))
        await XCTAssertThrowsAsync(try await WrappedSecrets.resolve(base.merging(["SERVER_PEPPER_WRAPPED": foreign]) { $1 }, kms: kms))
        await XCTAssertThrowsAsync(try await WrappedSecrets.resolve(base.merging(["SERVER_PEPPER_WRAPPED": "kms1:kek-data:" + wrapped.split(separator: ":").last!]) { $1 }, kms: kms))
        await XCTAssertThrowsAsync(try await WrappedSecrets.resolve(base.merging(["SERVER_PEPPER_WRAPPED": String(wrapped.dropLast(4)) + "AAAA"]) { $1 }, kms: kms))
        await XCTAssertThrowsAsync(try await WrappedSecrets.resolve(base.merging(["EDGE_TOKEN_WRAPPED": wrapped]) { $1 }, kms: kms))
        await XCTAssertThrowsAsync(try await WrappedSecrets.resolve(["ENVIRONMENT": "development", "SERVER_PEPPER_WRAPPED": wrapped], kms: kms))
        await XCTAssertThrowsAsync(try await WrappedSecrets.resolve(base.merging(["SERVER_PEPPER_WRAPPED": wrapped]) { $1 }, kms: nil))
        // Without any wrapped value nothing changes (Fly staging, development, tests).
        let plain = ["ENVIRONMENT": "development", "SERVER_PEPPER": pepper]
        let untouched = try await WrappedSecrets.resolve(plain, kms: nil)
        XCTAssertEqual(untouched, plain)

        // Wallet identity-encryption keys wrapped the same way are unwrapped by their own consumer.
        let walletKey = P256.KeyAgreement.PrivateKey()
        let walletWrapped = WrappedSecrets.encode(try await kms.wrap(keyRef: "kek-data", plaintext: walletKey.derRepresentation))
        let unwrapper = KMSWalletKeyUnwrapper(kms: kms, kekName: "kek-data")
        let der = try await unwrapper.unwrap(Data(walletWrapped.utf8))
        XCTAssertEqual(try P256.KeyAgreement.PrivateKey(derRepresentation: der).publicKey.rawRepresentation, walletKey.publicKey.rawRepresentation)
        do { _ = try await KMSWalletKeyUnwrapper(kms: kms, kekName: "other-key").unwrap(Data(walletWrapped.utf8)); XCTFail() } catch {}
    }

    // MARK: Audit-head export to Azure Blob

    /// The export writes a create-only blob, signed with the Key Vault key; a second write of the same name is a conflict and never replaces it.
    func testAuditHeadExportToBlobIsCreateOnlyAndSignedWithTheKeyVaultKey() async throws {
        let stub = AzureStub()
        let version = stub.addECKey("audit-head-signing")
        let tokens = FakeAccessTokens()
        let kms = try AzureKeyVaultKMS(vaultURL: AzureStub.vault, tokens: tokens, http: stub)
        let store = try AzureBlobObjectStore(endpoint: AzureStub.blob + "/", container: "audit-heads", tokens: tokens, http: stub)
        try await withHarness(overrides: { $0.kms = kms; $0.auditObjectStore = store }, {
            $0.operations.auditExport = AuditHeadExportSettings(kind: .azureBlob, target: "audit-heads", endpoint: AzureStub.blob, interval: 3_600, signingKey: "audit-head-signing")
        }) { h in
            for index in 0..<3 { _ = try await AuditService(db: h.db, ctx: h.ctx).record("seed.\(index)", actor: AuditActor(kind: .system)) }
            let wrote = try await AuditHeadExporter(db: h.db, ctx: h.ctx).runIfDue(force: true)
            XCTAssertTrue(wrote)
            let put = try XCTUnwrap(stub.calls.last { $0.method == .PUT })
            XCTAssertTrue(put.url.hasPrefix(AzureStub.blob + "/audit-heads/audit-heads/"))
            XCTAssertEqual(put.headers["If-None-Match"], "*", "create-only")
            XCTAssertEqual(put.headers["Authorization"], "Bearer token-for-storage.azure.com", "the storage token, not the Key Vault one")
            let name = try XCTUnwrap(stub.blobNames().first)
            let exported = try JSONDecoder().decode(AuditHeadExporter.Exported.self, from: try XCTUnwrap(stub.blob(name)))
            XCTAssertEqual(exported.kmsKey, "audit-head-signing/\(version)", "the exact signing version is recorded")
            let signature = try P256.Signing.ECDSASignature(rawRepresentation: try XCTUnwrap(exported.kmsSignature.flatMap(Base64URL.decode)))
            XCTAssertTrue(try XCTUnwrap(stub.publicKey("audit-head-signing", version: version)).isValidSignature(signature, for: exported.head.message()))
            let ring = AuditKeyring(config: h.ctx.config)
            let headOK = try await AuditService.verify(head: exported.head, on: h.db, keyring: ring)
            XCTAssertTrue(headOK)
            // Overwrite: the store refuses with a conflict, and the stored object is unchanged.
            let objectName = String(name.dropFirst("/audit-heads/".count))
            do { try await store.create(name: objectName, data: Data("{}".utf8), contentType: "application/json"); XCTFail("overwrite must be refused") } catch let error as ObjectStoreError {
                XCTAssertEqual(error, .alreadyExists)
            }
            XCTAssertNotEqual(stub.blob(name), Data("{}".utf8))
            // Names cannot escape the container.
            for bad in ["../other/x.json", "/abs.json", "a//b", "a/./b", ""] {
                do { try await store.create(name: bad, data: Data(), contentType: "application/json"); XCTFail(bad) } catch let error as ObjectStoreError { XCTAssertEqual(error, .invalidName) }
            }
            // The stored object holds no credential.
            let text = String(decoding: try XCTUnwrap(stub.blob(name)), as: UTF8.self)
            XCTAssertFalse(text.contains("token-for"))
        }
    }

    func testAFailedBlobUploadIsNotRecordedAsExportedAndIsRetried() async throws {
        let stub = AzureStub()
        let store = try AzureBlobObjectStore(endpoint: AzureStub.blob, container: "audit-heads", tokens: FakeAccessTokens(), http: stub)
        try await withHarness(overrides: { $0.auditObjectStore = store }, {
            $0.operations.auditExport = AuditHeadExportSettings(kind: .azureBlob, target: "audit-heads", endpoint: AzureStub.blob, interval: 3_600)
        }) { h in
            for index in 0..<3 { _ = try await AuditService(db: h.db, ctx: h.ctx).record("seed.\(index)", actor: AuditActor(kind: .system)) }
            stub.failBlobWrites = true
            do { _ = try await AuditHeadExporter(db: h.db, ctx: h.ctx).runIfDue(force: true); XCTFail("a failed upload must surface") } catch {}
            let mark = try await PlatformFlagRecord.query(on: h.db).filter(\.$flag == PlatformFlag.auditExportMark.rawValue).first()
            XCTAssertNil(mark, "nothing may claim the head is anchored")
            h.clock.advance(by: 3_000 * 86_400)
            let report = await RetentionPurger(db: h.db, ctx: h.ctx).run()
            XCTAssertEqual(report.skipped["audit_events"], "not_exported")
            stub.failBlobWrites = false
            let retried = try await AuditHeadExporter(db: h.db, ctx: h.ctx).runIfDue(force: true)
            XCTAssertTrue(retried)
        }
    }

    /// A signing key configured without a KMS fails the export (never an unsigned head where a signed one is required).
    func testAConfiguredSigningKeyWithoutAKMSFailsTheExport() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("heads-" + UUID().uuidString).path
        defer { try? FileManager.default.removeItem(atPath: directory) }
        try await withHarness({ $0.operations.auditExport = AuditHeadExportSettings(kind: .directory, target: directory, interval: 3_600, signingKey: "audit-head-signing") }) { h in
            _ = try await AuditService(db: h.db, ctx: h.ctx).record("seed", actor: AuditActor(kind: .system))
            do { _ = try await AuditHeadExporter(db: h.db, ctx: h.ctx).runIfDue(force: true); XCTFail() } catch {}
            XCTAssertNil(FileManager.default.subpaths(atPath: directory)?.first { $0.hasSuffix(".json") })
        }
    }

    // MARK: Key-directory log key in the KMS

    func testTheKeyDirectoryLogSignsTreeHeadsWithTheKMSKey() async throws {
        let kms = LocalKMS()
        kms.createSigningKey("kd-log-signing")
        let expected = DevicePublicKey(try await kms.publicKey(keyRef: "kd-log-signing"))
        try await withHarness(overrides: { $0.kms = kms }, { config in
            config.azure.keyVaultURL = AzureStub.vault
            config.azure.kdLogKey = "kd-log-signing"
        }) { h in
            XCTAssertEqual(h.ctx.config.approve.logKey.publicKey, expected, "the public key came from the KMS at boot")
            XCTAssertTrue(h.ctx.config.approve.logKey is KMSSigningKey)
            let head = try await KeyLogService(db: h.db, ctx: h.ctx).currentHead()
            XCTAssertNoThrow(try head.verified(logKeys: [expected]))
            XCTAssertThrowsError(try head.verified(logKeys: [SoftwareP256SigningKey().publicKey]))
        }
        // Both a software key and the Key Vault key: refused.
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(["ENVIRONMENT": "development", "KEY_DIRECTORY_LOG_KEY": Base64URL.encode(P256.Signing.PrivateKey().rawRepresentation),
                                                               "AZURE_KEY_VAULT_URL": AzureStub.vault, "AZURE_KEY_VAULT_KD_LOG_KEY": "kd-log-signing", "AZURE_CLIENT_ID": "c",
                                                               "IDENTITY_ENDPOINT": Self.identityEndpoint, "IDENTITY_HEADER": "h"]))
    }

    // MARK: Link-descriptor key in the KMS

    /// On Azure the link-descriptor key is the Key Vault key `link-descriptor`, loaded at boot like the log key; it never coexists with the
    /// environment secret, and it may never be the log key.
    func testTheLinkDescriptorKeyComesFromTheKMS() async throws {
        let kms = LocalKMS()
        kms.createSigningKey("link-descriptor")
        kms.createSigningKey("kd-log-signing")
        let expected = DevicePublicKey(try await kms.publicKey(keyRef: "link-descriptor"))
        try await withHarness(overrides: { $0.kms = kms }, { config in
            config.azure.keyVaultURL = AzureStub.vault
            config.azure.kdLogKey = "kd-log-signing"
            config.azure.linkDescriptorKey = "link-descriptor"
        }) { h in
            XCTAssertEqual(h.ctx.config.approve.linkDescriptorKey.publicKey, expected, "the public key came from the KMS at boot")
            XCTAssertTrue(h.ctx.config.approve.linkDescriptorKey is KMSSigningKey)
            let signed = try await KMSStatementSigner(key: h.ctx.config.approve.linkDescriptorKey).sign(payload: Data("{}".utf8), domain: LinkDomainSeparator.descriptor)
            XCTAssertTrue(SignedStatement(payload: signed.payload, signature: signed.signature).isValid(domain: LinkDomainSeparator.descriptor, publicKey: expected))
        }
        // Both a software key and the Key Vault key: refused.
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(["ENVIRONMENT": "development", "LINK_DESCRIPTOR_SIGNING_KEY": Base64URL.encode(P256.Signing.PrivateKey().rawRepresentation),
                                                               "AZURE_KEY_VAULT_URL": AzureStub.vault, "AZURE_KEY_VAULT_LINK_DESCRIPTOR_KEY": "link-descriptor", "AZURE_CLIENT_ID": "c",
                                                               "IDENTITY_ENDPOINT": Self.identityEndpoint, "IDENTITY_HEADER": "h"]))
        // The same Key Vault key in both roles: refused by name in the configuration ...
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(["ENVIRONMENT": "development", "AZURE_KEY_VAULT_URL": AzureStub.vault, "AZURE_CLIENT_ID": "c",
                                                               "AZURE_KEY_VAULT_KD_LOG_KEY": "kd-log-signing", "AZURE_KEY_VAULT_LINK_DESCRIPTOR_KEY": "kd-log-signing",
                                                               "IDENTITY_ENDPOINT": Self.identityEndpoint, "IDENTITY_HEADER": "h"]))
        // ... and by public key at boot (a pinned version of the log key under another reference).
        let version = try await kms.resolveVersion(keyRef: "kd-log-signing")
        do {
            try await withHarness(overrides: { $0.kms = kms }, { config in
                config.azure.keyVaultURL = AzureStub.vault
                config.azure.kdLogKey = "kd-log-signing"
                config.azure.linkDescriptorKey = version
            }) { _ in XCTFail("the log key in the link-descriptor role must not boot") }
            XCTFail("must refuse")
        } catch {}
    }

    // MARK: Database roles

    /// The runtime-role check passes for the application role and fails for the schema owner (the migrator principal).
    func testTheRuntimeRoleCheckPassesForTheAppRoleAndFailsForTheMigrator() async throws {
        guard ProcessInfo.processInfo.environment["TEST_DATABASE_URL"].map({ !$0.isEmpty }) == true else {
            throw XCTSkip("needs PostgreSQL (TEST_DATABASE_URL)")
        }
        try await withHarness { h in
            let sql = try XCTUnwrap(h.db as? any SQLDatabase)
            let role = "viadere_app_rt_" + String(UUID().uuidString.lowercased().prefix(8)).filter(\.isLetter)
            try await sql.raw(SQLQueryString("CREATE ROLE \(unsafeRaw: role) NOLOGIN")).run()
            do {
                // The same grants `GrantRuntimeRolePrivileges` gives the runtime role.
                for statement in ["GRANT USAGE ON SCHEMA public TO \(role)", "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \(role)",
                                  "REVOKE CREATE ON SCHEMA public FROM \(role)", "REVOKE CREATE ON SCHEMA public FROM PUBLIC"] {
                    try await sql.raw(SQLQueryString(statement)).run()
                }
                // The test login owns the schema: exactly what the migrator is.
                let migratorCan = try await DatabaseRoles.runtimeCanChangeSchema(h.db)
                XCTAssertTrue(migratorCan, "the schema owner must be detected")
                let appCan = try await h.db.transaction { tx -> Bool in
                    try await (tx as! any SQLDatabase).raw(SQLQueryString("SET LOCAL ROLE \(unsafeRaw: role)")).run()
                    return try await DatabaseRoles.runtimeCanChangeSchema(tx)
                }
                XCTAssertFalse(appCan, "the data-only role passes")
            } catch {
                _ = try? await sql.raw(SQLQueryString("DROP OWNED BY \(unsafeRaw: role)")).run()
                _ = try? await sql.raw(SQLQueryString("DROP ROLE \(unsafeRaw: role)")).run()
                throw error
            }
            try await sql.raw(SQLQueryString("DROP OWNED BY \(unsafeRaw: role)")).run()
            try await sql.raw(SQLQueryString("DROP ROLE \(unsafeRaw: role)")).run()
        }
    }

    /// With Entra authentication the migration job connects as its own principal; the runtime role can never be the one that migrates.
    func testEntraMigrationsRefuseTheRuntimeRole() throws {
        var config = ServerConfig.testing()
        config.environment = .production
        config.databaseEntra = EntraDatabaseSettings(host: "psql.example.postgres.database.azure.com", port: 5432, database: "viadere", user: "viadere_migrator", caFile: nil)
        XCTAssertNoThrow(try DatabaseRoles.requireMigrationURL(config: config, migrating: true))
        XCTAssertTrue(DatabaseRoles.mustVerifyRuntimeRole(config: config, migrating: false), "Entra-connected serving processes are checked too")
        config.databaseEntra = nil
        XCTAssertThrowsError(try DatabaseRoles.requireMigrationURL(config: config, migrating: true))
    }

    // MARK: PostgreSQL Entra token connection source

    /// Every new connection asks for a fresh password (the Entra token); a failing token source refuses the connection: there is no fallback.
    func testTheTokenConnectionSourceFetchesAPasswordPerNewConnectionAndNeverFallsBack() async throws {
        guard let raw = ProcessInfo.processInfo.environment["TEST_DATABASE_URL"], !raw.isEmpty, let url = URL(string: raw), let host = url.host,
              let user = url.user, let password = url.password else { throw XCTSkip("needs PostgreSQL (TEST_DATABASE_URL)") }
        final class CountingPassword: PostgresPasswordSource, @unchecked Sendable {
            let lock = NSLock()
            var count = 0
            var failing = false
            let value: String
            init(_ value: String) { self.value = value }
            func password() async throws -> String {
                try lock.withLock {
                    if failing { throw AzureIdentityError.tokenUnavailable(status: 503) }
                    count += 1
                    return value
                }
            }
        }
        let source = CountingPassword(password)
        let app = try await Application.make(.testing)
        do {
            let connectionSource = TokenAuthPostgresConnectionSource(host: host, port: url.port ?? 5432, username: user, database: String(url.path.dropFirst()),
                                                                     tls: .disable, passwordSource: source)
            app.databases.use(.postgresTokenAuth(connectionSource), as: .psql)
            let sql = try XCTUnwrap(app.db as? any SQLDatabase)
            struct One: Decodable { var one: Int }
            let row = try await sql.raw("SELECT 1 AS one").first(decoding: One.self)
            XCTAssertEqual(row?.one, 1)
            XCTAssertEqual(source.count, 1, "one password for the one new connection")
            _ = try await sql.raw("SELECT 1 AS one").first(decoding: One.self)
            XCTAssertEqual(source.count, 1, "a pooled connection is reused without a new token")
            XCTAssertTrue(DB.isPostgres(app.db), "the dialect is PostgreSQL")
            // Transactions work through it (BEGIN/COMMIT on one pooled connection).
            let inTransaction = try await app.db.transaction { tx -> Int in
                try await (tx as! any SQLDatabase).raw("SELECT 1 AS one").first(decoding: One.self)?.one ?? 0
            }
            XCTAssertEqual(inTransaction, 1)
        } catch {
            try? await app.asyncShutdown()
            throw error
        }
        try await app.asyncShutdown()

        // A fresh pool whose token source fails: the connection is refused.
        source.failing = true
        let refusing = try await Application.make(.testing)
        do {
            let connectionSource = TokenAuthPostgresConnectionSource(host: host, port: url.port ?? 5432, username: user, database: String(url.path.dropFirst()),
                                                                     tls: .disable, passwordSource: source)
            refusing.databases.use(.postgresTokenAuth(connectionSource), as: .psql)
            let sql = try XCTUnwrap(refusing.db as? any SQLDatabase)
            do { _ = try await sql.raw("SELECT 1").run(); XCTFail("a connection without a token must not exist") } catch {}
        } catch {
            try? await refusing.asyncShutdown()
            throw error
        }
        try await refusing.asyncShutdown()
    }

    func testEntraDatabaseConfiguration() throws {
        let identity = ["AZURE_CLIENT_ID": "client", "IDENTITY_ENDPOINT": Self.identityEndpoint, "IDENTITY_HEADER": "h"]
        let entra = ["ENVIRONMENT": "development", "DATABASE_AUTH": "entra", "DATABASE_HOST": "psql-viadere-stgl.postgres.database.azure.com", "DATABASE_USER": "viadere_app",
                     "DATABASE_NAME": "viadere"]
        // A database is configured, so every secret is required (no ephemeral secrets with a real database).
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(entra.merging(identity) { $1 }))
        let secrets = ["CONNECT_LINK_SIGNING_KEY", "SERVER_PEPPER", "DATA_ENCRYPTION_KEY", "AUDIT_CHAIN_KEY", "SUBJECT_REF_KEY"].reduce(into: [String: String]()) { $0[$1] = SecureToken.generate() }
            .merging(["KEY_DIRECTORY_LOG_KEY": Base64URL.encode(P256.Signing.PrivateKey().rawRepresentation),
                      "LINK_DESCRIPTOR_SIGNING_KEY": Base64URL.encode(P256.Signing.PrivateKey().rawRepresentation)]) { $1 }
        let config = try ServerConfig.fromEnvironment(entra.merging(identity) { $1 }.merging(secrets) { $1 })
        XCTAssertEqual(config.databaseEntra, EntraDatabaseSettings(host: "psql-viadere-stgl.postgres.database.azure.com", port: 5432, database: "viadere", user: "viadere_app", caFile: nil))
        XCTAssertTrue(config.hasDatabase)
        XCTAssertNil(config.databaseURL)
        // Entra without a managed identity, with a password URL as well, or with an unsafe role name: refused.
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(entra.merging(secrets) { $1 }))
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(entra.merging(identity) { $1 }.merging(secrets) { $1 }.merging(["DATABASE_URL": "postgres://u:p@h/db"]) { $1 }))
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(entra.merging(identity) { $1 }.merging(secrets) { $1 }.merging(["DATABASE_USER": "app; DROP"]) { $1 }))
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(entra.merging(identity) { $1 }.merging(secrets) { $1 }.merging(["DATABASE_AUTH": "kerberos"]) { $1 }))
    }

    // MARK: Process roles and the migrate-only configuration

    /// `ROLE=migrate` gets a database-only configuration: no service secret from the environment reaches it, and it cannot serve.
    func testTheMigrateRoleHoldsNoServiceSecretAndCannotServe() async throws {
        let pepper = SecureToken.generate()
        let env = ["ENVIRONMENT": "production", "ROLE": "migrate", "DATABASE_MIGRATION_URL": "postgres://migrator:pw@db/viadere", "SERVER_PEPPER": pepper,
                   "DATA_ENCRYPTION_KEY": SecureToken.generate()]
        let config = try ServerConfig.fromEnvironment(env)
        XCTAssertEqual(config.role, .migrate)
        XCTAssertNotEqual(config.pepper, Base64URL.decode(pepper), "service secrets are not loaded")
        XCTAssertNil(config.apns)
        XCTAssertNil(config.email)
        XCTAssertEqual(config.operations.migrationDatabaseURL, "postgres://migrator:pw@db/viadere")
        // Production `migrate` needs nothing but its database settings (the job no longer references every server secret).
        XCTAssertNoThrow(try ServerConfig.fromEnvironment(["ENVIRONMENT": "production", "ROLE": "migrate", "DATABASE_AUTH": "entra", "DATABASE_HOST": "psql.example.com",
                                                           "DATABASE_USER": "viadere_migrator", "AZURE_CLIENT_ID": "c", "IDENTITY_ENDPOINT": Self.identityEndpoint, "IDENTITY_HEADER": "h"]))
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(["ENVIRONMENT": "production", "ROLE": "migrate"]), "a database is required")
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(["ENVIRONMENT": "development", "ROLE": "scheduler"]))
        // The migrate configuration refuses to serve.
        var migrateConfig = ServerConfig.testing()
        migrateConfig.role = .migrate
        do {
            let app = try await makeApplication(environment: .testing, config: migrateConfig)
            try? await app.asyncShutdown()
            XCTFail("ROLE=migrate must not start a server")
        } catch {}
    }

    /// The worker holds no grant on the log key (plan 5.3), so it does not need one, and what it holds refuses to sign: a code path that reached it
    /// would fail rather than publish a tree head nobody can verify.
    func testTheWorkerNeverSignsTreeHeads() async throws {
        let secrets = ["CONNECT_LINK_SIGNING_KEY", "SERVER_PEPPER", "DATA_ENCRYPTION_KEY", "AUDIT_CHAIN_KEY", "SUBJECT_REF_KEY"].reduce(into: [String: String]()) { $0[$1] = SecureToken.generate() }
        var env = secrets.merging(["ENVIRONMENT": "development", "DATABASE_URL": "postgres://u:p@db/viadere", "APPROVE_V2_ENABLED": "true"]) { $1 }
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(env), "the api needs the log key")
        env["ROLE"] = "worker"
        let config = try ServerConfig.fromEnvironment(env)
        XCTAssertTrue(config.approve.logKey is UnavailableSigningKey)
        await XCTAssertThrowsAsync(try await config.approve.logKey.signature(for: Data("tree head".utf8)))
        // Nor link descriptors or results (only the api signs them).
        XCTAssertTrue(config.approve.linkDescriptorKey is UnavailableSigningKey)
        await XCTAssertThrowsAsync(try await config.approve.linkDescriptorKey.signature(for: Data("link result".utf8)))
    }

    /// The worker serves health checks only.
    func testTheWorkerServesOnlyHealthChecks() async throws {
        try await withHarness({ $0.role = .worker }) { h in
            try await eq(try await h.request(.GET, "/healthz").status, .ok)
            try await eq(try await h.request(.GET, "/readyz").status, .ok)
            try await eq(try await h.request(.GET, "/v1/directory/businesses").status, .notFound)
            try await eq(try await h.request(.POST, "/v1/accounts/enroll/begin").status, .notFound)
        }
    }

    // MARK: Origin: health peers, metrics bind host, Host header

    /// A health request from outside `HEALTH_PEER_NETWORKS` without the edge token gets 421; from inside (no proxy headers) it is served.
    func testHealthChecksOnlyFromTheConfiguredPeerNetworks() async throws {
        let token = SecureToken.generate()
        var env = ["ENVIRONMENT": "development", "EDGE_TOKEN": token, "HEALTH_PEER_NETWORKS": "10.40.0.0/23"]
        let settings = try ServerConfig.fromEnvironment(env).operations
        XCTAssertEqual(settings.healthPeerNetworks.count, 1)
        XCTAssertEqual(EdgeLockMiddleware.decide(settings: settings, token: nil, path: "/healthz", method: .GET, headerNames: [], peer: "10.40.1.17"), .allow(viaEdge: false))
        XCTAssertEqual(EdgeLockMiddleware.decide(settings: settings, token: nil, path: "/healthz", method: .GET, headerNames: [], peer: "10.40.2.1"), .rejectMissingToken)
        XCTAssertEqual(EdgeLockMiddleware.decide(settings: settings, token: nil, path: "/readyz", method: .GET, headerNames: [], peer: "fdaa::1"), .rejectMissingToken,
                       "Fly's network is no longer exempt once the subnet is configured")
        XCTAssertEqual(EdgeLockMiddleware.decide(settings: settings, token: nil, path: "/healthz", method: .GET, headerNames: ["X-Forwarded-For"], peer: "10.40.1.17"), .rejectMissingToken)
        XCTAssertEqual(EdgeLockMiddleware.decide(settings: settings, token: nil, path: "/v1/directory/businesses", method: .GET, headerNames: [], peer: "10.40.1.17"), .rejectMissingToken)
        for bad in ["10.40.0.1", "0.0.0.0/0", "::/0", "not-a-cidr", " , "] {
            env["HEALTH_PEER_NETWORKS"] = bad
            XCTAssertThrowsError(try ServerConfig.fromEnvironment(env), bad)
        }
        // Through the server: the in-process test client is not in the configured subnet, so it gets 421.
        try await withHarness({ config in
            config.operations.edgeTokens = [Data(token.utf8)]
            config.operations.healthPeerNetworks = [IPNetwork("10.40.0.0/23")!]
        }) { h in
            try await eq(try await h.request(.GET, "/healthz").status, .misdirectedRequest)
            try await eq(try await h.request(.GET, "/healthz", headers: ["X-Viadere-Edge-Token": token]).status, .ok)
        }
    }

    func testTheMetricsListenerBindHostReplacesFlysPrivateAddress() throws {
        let base = ["ENVIRONMENT": "development", "METRICS_PORT": "9091", "METRICS_TOKEN": SecureToken.generate()]
        XCTAssertEqual(try ServerConfig.fromEnvironment(base.merging(["METRICS_BIND_HOST": "10.40.0.12"]) { $1 }).operations.metricsHost, "10.40.0.12")
        XCTAssertEqual(try ServerConfig.fromEnvironment(base.merging(["METRICS_BIND_HOST": "10.40.0.12", "FLY_PRIVATE_IP": "fdaa::2"]) { $1 }).operations.metricsHost, "10.40.0.12",
                       "METRICS_BIND_HOST wins")
        XCTAssertEqual(try ServerConfig.fromEnvironment(base.merging(["FLY_PRIVATE_IP": "fdaa::2"]) { $1 }).operations.metricsHost, "fdaa::2", "Fly keeps working until cutover")
        for bad in ["0.0.0.0", "::", "10.0.0.0/8", "host.example"] {
            XCTAssertThrowsError(try ServerConfig.fromEnvironment(base.merging(["METRICS_BIND_HOST": bad]) { $1 }), bad)
        }
    }

    /// cloudflared sends `Host: ca-viadere-api` (Container Apps routes internal traffic by app name). Nothing the server builds or verifies may depend on
    /// it: provider signatures are checked against `PUBLIC_BASE_URL`, and no code reads the Host header.
    func testTheServerNeverDerivesURLsFromTheHostHeader() async throws {
        try await withHarness { h in
            let path = "/v1/providers/sms/inbound"
            let params: [(String, String)] = [("MessageSid", "SMhost0001"), ("From", "+14805550199"), ("To", "+15550001111"), ("Body", "HELP")]
            // Signed for the public URL, delivered with the internal Host: accepted.
            let publicSignature = TwilioProvider.signature(authToken: RecordingSMSProvider.authToken, url: h.config.publicBaseURL + path, params: params)
            let accepted = try await h.request(.POST, path, headers: ["Host": "ca-viadere-api", "X-Twilio-Signature": publicSignature], body: smsForm(params),
                                               contentType: "application/x-www-form-urlencoded")
            XCTAssertEqual(accepted.status, .ok)
            // Signed for the Host-derived URL: refused.
            let hostParams: [(String, String)] = [("MessageSid", "SMhost0002"), ("From", "+14805550199"), ("To", "+15550001111"), ("Body", "HELP")]
            for hostURL in ["http://ca-viadere-api" + path, "https://ca-viadere-api" + path] {
                let hostSignature = TwilioProvider.signature(authToken: RecordingSMSProvider.authToken, url: hostURL, params: hostParams)
                let refused = try await h.request(.POST, path, headers: ["Host": "ca-viadere-api", "X-Twilio-Signature": hostSignature], body: smsForm(hostParams),
                                                  contentType: "application/x-www-form-urlencoded")
                XCTAssertEqual(refused.status, .forbidden, hostURL)
            }
        }
        // No source file reads the Host header or derives a URL from the request's host.
        let sources = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Sources")
        let forbidden = ["name: .host", "headers[.host]", "first(name: \"Host\")", "first(name: \"host\")", "req.url.host", "req.headers.host", "X-Forwarded-Host", "x-forwarded-host"]
        let enumerator = try XCTUnwrap(FileManager.default.enumerator(at: sources, includingPropertiesForKeys: nil))
        var scanned = 0
        for case let file as URL in enumerator where file.pathExtension == "swift" {
            let text = try String(contentsOf: file, encoding: .utf8)
            scanned += 1
            for pattern in forbidden { XCTAssertFalse(text.contains(pattern), "\(file.lastPathComponent) uses \(pattern)") }
        }
        XCTAssertGreaterThan(scanned, 100)
    }
}

/// `XCTAssertThrowsError` for async expressions.
func XCTAssertThrowsAsync<T>(_ expression: @autoclosure () async throws -> T, _ message: String = "", file: StaticString = #filePath, line: UInt = #line) async {
    do {
        _ = try await expression()
        XCTFail("expected an error. \(message)", file: file, line: line)
    } catch {}
}
