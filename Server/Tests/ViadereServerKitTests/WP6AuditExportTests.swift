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
    private func settings(_ kind: AuditHeadExportSettings.Kind, target: String) -> AuditHeadExportSettings {
        AuditHeadExportSettings(kind: kind, target: target, prefix: "audit-heads/", endpoint: kind == .azureBlob ? "https://stviaderetestaudit.blob.core.windows.net" : nil,
                                interval: 3_600)
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
            let sink = DirectoryObjectStore(directory: directory)
            do { try await sink.create(name: "audit-heads/" + files[0].replacingOccurrences(of: "audit-heads/", with: ""), data: Data("{}".utf8), contentType: "application/json")
                XCTFail("overwrite must be refused") } catch let error as ObjectStoreError { XCTAssertEqual(error, .alreadyExists) }
            let untouched = try Data(contentsOf: URL(fileURLWithPath: directory + "/" + files[0]))
            XCTAssertNotEqual(untouched, Data("{}".utf8))
            // A head whose event was rewritten no longer verifies against the chain.
            var forged = exported.head
            forged.hash = String(repeating: "a", count: 64)
            let forgedOK = try await AuditService.verify(head: forged, on: h.db, keyring: ring)
            XCTAssertFalse(forgedOK)
        }
    }

    // The Azure Blob export, its Key Vault signature and the failed-upload retry are in AzurePlatformTests (WP-B2).

    func testConfigurationRefusesIncompleteOrUnsafeExportSettings() throws {
        func parse(_ extra: [String: String], environment: String = "development") throws -> ServerConfig {
            try ServerConfig.fromEnvironment(["ENVIRONMENT": environment].merging(extra) { $1 })
        }
        XCTAssertNoThrow(try parse(["AUDIT_HEAD_EXPORT": "directory", "AUDIT_HEAD_EXPORT_TARGET": "/tmp/heads"]))
        XCTAssertThrowsError(try parse(["AUDIT_HEAD_EXPORT": "directory"]), "a target is required")
        XCTAssertThrowsError(try parse(["AUDIT_HEAD_EXPORT": "tape", "AUDIT_HEAD_EXPORT_TARGET": "x"]))
        // Azure Blob: inferred from the container settings, which must be complete and point at Blob Storage over https.
        let identity = ["AZURE_CLIENT_ID": "c", "IDENTITY_ENDPOINT": "http://localhost:42356/msi/token", "IDENTITY_HEADER": "h"]
        let blob = try parse(identity.merging(["AZURE_AUDIT_BLOB_ENDPOINT": "https://stviaderetestaudit.blob.core.windows.net/", "AZURE_AUDIT_BLOB_CONTAINER": "audit-heads"]) { $1 })
        XCTAssertEqual(blob.operations.auditExport?.kind, .azureBlob)
        XCTAssertEqual(blob.operations.auditExport?.endpoint, "https://stviaderetestaudit.blob.core.windows.net")
        XCTAssertThrowsError(try parse(identity.merging(["AZURE_AUDIT_BLOB_ENDPOINT": "https://stviaderetestaudit.blob.core.windows.net/"]) { $1 }), "a container is required")
        XCTAssertThrowsError(try parse(identity.merging(["AZURE_AUDIT_BLOB_ENDPOINT": "http://stviaderetestaudit.blob.core.windows.net/", "AZURE_AUDIT_BLOB_CONTAINER": "audit-heads"]) { $1 }))
        XCTAssertThrowsError(try parse(identity.merging(["AZURE_AUDIT_BLOB_ENDPOINT": "https://evil.example.com/", "AZURE_AUDIT_BLOB_CONTAINER": "audit-heads"]) { $1 }))
        XCTAssertThrowsError(try parse(identity.merging(["AZURE_AUDIT_BLOB_ENDPOINT": "https://stviaderetestaudit.blob.core.windows.net/", "AZURE_AUDIT_BLOB_CONTAINER": "Audit_Heads"]) { $1 }))
        XCTAssertThrowsError(try parse(["AZURE_AUDIT_BLOB_ENDPOINT": "https://stviaderetestaudit.blob.core.windows.net/", "AZURE_AUDIT_BLOB_CONTAINER": "audit-heads"]), "needs the managed identity")
        XCTAssertThrowsError(try parse(["AUDIT_HEAD_EXPORT": "azure-blob"]), "azure-blob needs the container settings")
        // The retired Google Cloud and R2 settings are refused, not ignored.
        for retired in ["gcs", "r2"] { XCTAssertThrowsError(try parse(["AUDIT_HEAD_EXPORT": retired, "AUDIT_HEAD_EXPORT_TARGET": "bucket"])) }
        for name in ["GCP_WORKLOAD_IDENTITY_AUDIENCE", "AUDIT_HEAD_EXPORT_ACCESS_KEY_ID", "AUDIT_HEAD_KMS_KEY"] { XCTAssertThrowsError(try parse([name: "x"]), name) }
        XCTAssertThrowsError(try parse(["AUDIT_HEAD_EXPORT": "directory", "AUDIT_HEAD_EXPORT_TARGET": "/tmp", "AUDIT_HEAD_EXPORT_PREFIX": "../escape/"]))
        XCTAssertThrowsError(try parse(["AUDIT_HEAD_EXPORT": "directory", "AUDIT_HEAD_EXPORT_TARGET": "/tmp", "AUDIT_HEAD_EXPORT_INTERVAL_HOURS": "0"]))
        XCTAssertThrowsError(try parse(["DATABASE_MIGRATION_URL": "mysql://nope"]))
        XCTAssertEqual(try parse(["DATABASE_MIGRATION_URL": "postgres://migrator:pw@db/viadere"]).operations.migrationDatabaseURL, "postgres://migrator:pw@db/viadere")
    }

    func testRuntimeRoleHelpersRefuseUnsafeNames() {
        for good in ["viadere_app", "app1", "_x"] { XCTAssertTrue(GrantRuntimeRolePrivileges.isSafeRoleName(good), good) }
        for bad in ["", "1app", "app;DROP TABLE x", "app role", "a\"b", String(repeating: "a", count: 64), "app-role", "ünï"] { XCTAssertFalse(GrantRuntimeRolePrivileges.isSafeRoleName(bad), bad) }
    }
}
