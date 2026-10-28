@preconcurrency import Crypto
import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// The scheduled audit-head export to write-once storage (OPS-004): create-only writes, signed heads, KMS signature, and no credential leaking
/// into storage calls or logs.
final class WP6AuditExportTests: XCTestCase {
    private func settings(_ kind: AuditHeadExportSettings.Kind, target: String, subjectFile: String? = nil, kms: String? = nil) -> AuditHeadExportSettings {
        var s = AuditHeadExportSettings(kind: kind, target: target, prefix: "audit-heads/", endpoint: kind == .r2 ? "https://acct.r2.cloudflarestorage.com" : nil, interval: 3_600, kmsKey: kms)
        s.googleAudience = "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/fly"
        s.googleServiceAccount = "viadere-server-kms@proj.iam.gserviceaccount.com"
        s.subjectTokenFile = subjectFile
        s.r2AccessKeyId = "AKIAEXAMPLE0000"
        s.r2SecretAccessKey = "r2-secret-access-key-value-0123456789"
        return s
    }

    private func seedEvents(_ h: TestHarness, count: Int = 3) async throws {
        for index in 0..<count { _ = try await AuditService(db: h.db, ctx: h.ctx).record("seed.\(index)", actor: AuditActor(kind: .system)) }
    }

    // MARK: Directory (development)

    func testHeadsAreWrittenOnTheScheduleOnlyWhenSomethingChangedAndAreCreateOnly() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("heads-" + UUID().uuidString).path
        defer { try? FileManager.default.removeItem(atPath: directory) }
        try await withHarness({ $0.operations.auditExport = self.settings(.directory, target: directory) }) { h in
            let exporter = AuditHeadExporter(db: h.db, ctx: h.ctx)
            let nothing = try await exporter.runIfDue()
            XCTAssertFalse(nothing, "an empty chain has no head")
            try await seedEvents(h)
            let first = try await exporter.runIfDue()
            XCTAssertTrue(first)
            // Within the interval nothing is written; after it, with no new event, the mark is refreshed but nothing is written.
            let early = try await exporter.runIfDue()
            XCTAssertFalse(early)
            h.clock.advance(by: 3_700)
            let unchanged = try await exporter.runIfDue()
            XCTAssertFalse(unchanged)
            let mark = try await XCTUnwrapAsync(await PlatformFlagRecord.query(on: h.db).filter(\.$flag == PlatformFlag.auditExportMark.rawValue).first())
            XCTAssertEqual(mark.updatedAt, h.clock.now(), "the age gauge stays honest")
            // A new event: a new object. The object is a signed head that verifies with the chain key and matches the chain.
            _ = try await AuditService(db: h.db, ctx: h.ctx).record("new.event", actor: AuditActor(kind: .system))
            h.clock.advance(by: 3_700)
            let second = try await exporter.runIfDue()
            XCTAssertTrue(second)
            let files = try FileManager.default.subpathsOfDirectory(atPath: directory).filter { $0.hasSuffix(".json") }.sorted()
            XCTAssertEqual(files.count, 2)
            let exported = try JSONDecoder().decode(AuditHeadExporter.Exported.self, from: Data(contentsOf: URL(fileURLWithPath: directory + "/" + files[1])))
            XCTAssertEqual(exported.head.seq, 4)
            let ring = AuditKeyring(config: h.ctx.config)
            let ok = try await AuditService.verify(head: exported.head, on: h.db, keyring: ring)
            XCTAssertTrue(ok)
            // Create-only: the same object name can never be written twice.
            let sink = DirectoryHeadSink(directory: directory)
            do { try await sink.store(name: files[0], data: Data("{}".utf8)); XCTFail("overwrite must be refused") } catch {}
            let untouched = try Data(contentsOf: URL(fileURLWithPath: directory + "/" + files[0]))
            XCTAssertNotEqual(untouched, Data("{}".utf8))
            // A head whose event was rewritten no longer verifies against the chain.
            var forged = exported.head
            forged.hash = String(repeating: "a", count: 64)
            let forgedOK = try await AuditService.verify(head: forged, on: h.db, keyring: ring)
            XCTAssertFalse(forgedOK)
        }
    }

    // MARK: Google Cloud Storage and KMS

    func testGCSExportUsesWorkloadIdentityCreateOnlyUploadsAndTheKMSSignature() async throws {
        let subjectFile = FileManager.default.temporaryDirectory.appendingPathComponent("subject-" + UUID().uuidString).path
        try "subject-token-from-fly-oidc\n".write(toFile: subjectFile, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: subjectFile) }
        let http = RecordingOutboundHTTP()
        let kmsKey = "projects/p/locations/us-east1/keyRings/viadere-production/cryptoKeys/audit-head/cryptoKeyVersions/1"
        try await withHarness(outbound: http, { $0.operations.auditExport = self.settings(.gcs, target: "viadere-audit-heads-production", subjectFile: subjectFile, kms: kmsKey) }) { h in
            try await seedEvents(h)
            let wrote = try await AuditHeadExporter(db: h.db, ctx: h.ctx).runIfDue(force: true)
            XCTAssertTrue(wrote)
            let calls = http.calls
            // Token exchange -> service-account impersonation -> KMS sign (for the head), token again -> upload.
            XCTAssertTrue(calls.first?.url.hasPrefix("https://sts.googleapis.com/") ?? false)
            XCTAssertTrue(calls.contains { $0.url.contains("iamcredentials.googleapis.com") && $0.url.contains("viadere-server-kms@proj.iam.gserviceaccount.com:generateAccessToken") })
            let sign = try XCTUnwrap(calls.first { $0.url.contains("cloudkms.googleapis.com") })
            XCTAssertTrue(sign.url.hasSuffix("\(kmsKey):asymmetricSign"))
            XCTAssertEqual(sign.headers["Authorization"], "Bearer service-account-token")
            let upload = try XCTUnwrap(calls.last { $0.url.contains("storage.googleapis.com") })
            XCTAssertTrue(upload.url.contains("/b/viadere-audit-heads-production/o?"))
            XCTAssertTrue(upload.url.contains("ifGenerationMatch=0"), "create-only: an existing object is never replaced")
            XCTAssertTrue(upload.url.contains("audit-heads%2F"), "the object name is URL-encoded")
            let object = try JSONDecoder().decode(AuditHeadExporter.Exported.self, from: try XCTUnwrap(upload.body))
            XCTAssertEqual(object.kmsKey, kmsKey)
            XCTAssertEqual(object.kmsSignature, Data("kms-signature".utf8).base64EncodedString())
            // The KMS signs the SHA-256 of exactly the head message, so anyone with the public key can verify it.
            let signBody = try XCTUnwrap(try JSONSerialization.jsonObject(with: try XCTUnwrap(sign.body)) as? [String: Any])
            let digest = (signBody["digest"] as? [String: String])?["sha256"]
            XCTAssertEqual(digest, Data(SHA256.hash(data: object.head.message())).base64EncodedString())
            // No long-lived credential is involved: the only secret on the wire is the short-lived token, and the stored object holds none.
            let objectText = String(decoding: try XCTUnwrap(upload.body), as: UTF8.self)
            for secret in ["subject-token-from-fly-oidc", "federated-token", "service-account-token"] { XCTAssertFalse(objectText.contains(secret)) }
        }
    }

    func testAFailedUploadIsNotRecordedAsExportedAndIsRetried() async throws {
        let subjectFile = FileManager.default.temporaryDirectory.appendingPathComponent("subject-" + UUID().uuidString).path
        try "subject".write(toFile: subjectFile, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: subjectFile) }
        let http = RecordingOutboundHTTP()
        try await withHarness(outbound: http, { $0.operations.auditExport = self.settings(.gcs, target: "bucket", subjectFile: subjectFile) }) { h in
            try await seedEvents(h)
            http.failStorageWrites(true)
            do { _ = try await AuditHeadExporter(db: h.db, ctx: h.ctx).runIfDue(force: true); XCTFail("a failed upload must surface") } catch {}
            let mark = try await PlatformFlagRecord.query(on: h.db).filter(\.$flag == PlatformFlag.auditExportMark.rawValue).first()
            XCTAssertNil(mark, "nothing may claim the head is anchored")
            // Retention therefore refuses to purge anything.
            h.clock.advance(by: 3_000 * 86_400)
            let report = await RetentionPurger(db: h.db, ctx: h.ctx).run()
            XCTAssertEqual(report.skipped["audit_events"], "not_exported")
            http.failStorageWrites(false)
            let retried = try await AuditHeadExporter(db: h.db, ctx: h.ctx).runIfDue(force: true)
            XCTAssertTrue(retried)
        }
    }

    // MARK: R2

    func testR2ExportSignsWithSigV4AndNeverSendsTheSecretKey() async throws {
        let http = RecordingOutboundHTTP()
        try await withHarness(outbound: http, { $0.operations.auditExport = self.settings(.r2, target: "viadere-audit") }) { h in
            try await seedEvents(h)
            let wrote = try await AuditHeadExporter(db: h.db, ctx: h.ctx).runIfDue(force: true)
            XCTAssertTrue(wrote)
            let put = try XCTUnwrap(http.calls.first { $0.url.contains("r2.cloudflarestorage.com") })
            XCTAssertEqual(put.method, .PUT)
            XCTAssertTrue(put.url.hasPrefix("https://acct.r2.cloudflarestorage.com/viadere-audit/audit-heads/"))
            XCTAssertEqual(put.headers["if-none-match"], "*", "create-only")
            let authorization = try XCTUnwrap(put.headers["authorization"])
            XCTAssertTrue(authorization.hasPrefix("AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE0000/"))
            XCTAssertTrue(authorization.contains("SignedHeaders="))
            XCTAssertEqual(put.headers["x-amz-content-sha256"], SecureToken.sha256Hex(try XCTUnwrap(put.body)))
            let everything = put.headers.values.joined() + String(decoding: try XCTUnwrap(put.body), as: UTF8.self) + put.url
            XCTAssertFalse(everything.contains("r2-secret-access-key-value"))
            // Without a KMS key there is no Google call at all.
            XCTAssertFalse(http.calls.contains { $0.url.contains("googleapis.com") })
        }
    }

    func testConfigurationRefusesIncompleteOrUnsafeExportSettings() throws {
        func parse(_ extra: [String: String], environment: String = "development") throws -> ServerConfig {
            try ServerConfig.fromEnvironment(["ENVIRONMENT": environment].merging(extra) { $1 })
        }
        XCTAssertNoThrow(try parse(["AUDIT_HEAD_EXPORT": "directory", "AUDIT_HEAD_EXPORT_TARGET": "/tmp/heads"]))
        XCTAssertThrowsError(try parse(["AUDIT_HEAD_EXPORT": "directory"]), "a target is required")
        XCTAssertThrowsError(try parse(["AUDIT_HEAD_EXPORT": "tape", "AUDIT_HEAD_EXPORT_TARGET": "x"]))
        XCTAssertThrowsError(try parse(["AUDIT_HEAD_EXPORT": "gcs", "AUDIT_HEAD_EXPORT_TARGET": "bucket"]), "gcs needs workload identity settings")
        XCTAssertNoThrow(try parse(["AUDIT_HEAD_EXPORT": "gcs", "AUDIT_HEAD_EXPORT_TARGET": "bucket", "GCP_WORKLOAD_IDENTITY_AUDIENCE": "//iam.googleapis.com/x",
                                    "GCP_SERVICE_ACCOUNT_EMAIL": "sa@p.iam.gserviceaccount.com", "GCP_SUBJECT_TOKEN_FILE": "/run/secrets/oidc"]))
        XCTAssertThrowsError(try parse(["AUDIT_HEAD_EXPORT": "r2", "AUDIT_HEAD_EXPORT_TARGET": "b", "AUDIT_HEAD_EXPORT_ENDPOINT": "http://insecure.example.com",
                                        "AUDIT_HEAD_EXPORT_ACCESS_KEY_ID": "a", "AUDIT_HEAD_EXPORT_SECRET_ACCESS_KEY": "b"]), "https only")
        XCTAssertThrowsError(try parse(["AUDIT_HEAD_EXPORT": "r2", "AUDIT_HEAD_EXPORT_TARGET": "b", "AUDIT_HEAD_EXPORT_ENDPOINT": "https://x.r2.cloudflarestorage.com"]), "keys required")
        XCTAssertThrowsError(try parse(["AUDIT_HEAD_EXPORT": "directory", "AUDIT_HEAD_EXPORT_TARGET": "/tmp", "AUDIT_HEAD_EXPORT_INTERVAL_HOURS": "0"]))
        XCTAssertThrowsError(try parse(["DATABASE_MIGRATION_URL": "mysql://nope"]))
        XCTAssertEqual(try parse(["DATABASE_MIGRATION_URL": "postgres://migrator:pw@db/viadere"]).operations.migrationDatabaseURL, "postgres://migrator:pw@db/viadere")
    }

    func testRuntimeRoleHelpersRefuseUnsafeNames() {
        for good in ["viadere_app", "app1", "_x"] { XCTAssertTrue(GrantRuntimeRolePrivileges.isSafeRoleName(good), good) }
        for bad in ["", "1app", "app;DROP TABLE x", "app role", "a\"b", String(repeating: "a", count: 64), "app-role", "ünï"] { XCTAssertFalse(GrantRuntimeRolePrivileges.isSafeRoleName(bad), bad) }
    }
}
