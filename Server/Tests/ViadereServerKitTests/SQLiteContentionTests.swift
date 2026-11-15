import FluentKit
import FluentSQLiteDriver
import Foundation
import Logging
import NIOCore
import NIOPosix
import SQLKit
import XCTest
@testable import ViadereServerKit

/// Two transactions that each read and then write the same SQLite file, at the same time (the shape of a request transaction and the background job
/// runner). With fluent-sqlite-driver's connection per event loop the second writer gets `SQLITE_BUSY` at once: SQLite refuses to wait in this
/// deadlock case whatever busy handler or busy timeout is set. With the server's single-connection configuration both commit.
final class SQLiteContentionTests: XCTestCase {
    /// One flag per milestone; `wait` polls for at most `limit` and then goes on (a serialized database never lets the other side get there).
    actor Milestones {
        private var reached: Set<String> = []
        func mark(_ name: String) { reached.insert(name) }
        func wait(_ name: String, limit: Duration = .milliseconds(800)) async {
            let clock = ContinuousClock()
            let deadline = clock.now + limit
            while !reached.contains(name), clock.now < deadline { try? await Task.sleep(for: .milliseconds(5)) }
        }
    }

    /// Runs the two interleaved transactions on two event loops and returns the errors they threw (empty when both committed).
    private func race(_ configuration: any DatabaseConfiguration, path: String, busyTimeout: Bool = false) async throws -> [any Error] {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 2)
        let databases = Databases(threadPool: NIOThreadPool.singleton, on: group)
        databases.use(configuration, as: .sqlite)
        let logger = Logger(label: "sqlite-contention")
        let loops = Array(group.makeIterator())
        XCTAssertEqual(loops.count, 2)
        guard let first = databases.database(.sqlite, logger: logger, on: loops[0]),
              let second = databases.database(.sqlite, logger: logger, on: loops[1]) else {
            XCTFail("no database")
            return []
        }
        try await (first as! any SQLDatabase).raw("CREATE TABLE IF NOT EXISTS contention (id INTEGER PRIMARY KEY, writer TEXT NOT NULL)").run()
        let milestones = Milestones()
        func writer(_ db: any Database, name: String, other: String, writesSecond: Bool) async -> (any Error)? {
            do {
                try await db.transaction { tx in
                    let sql = tx as! any SQLDatabase
                    // `sqlite3_busy_timeout` through its pragma, on this very connection (it replaces sqlite-nio's retry-forever handler).
                    if busyTimeout { _ = try await sql.raw("PRAGMA busy_timeout = 5000").all() }
                    _ = try await sql.raw("SELECT COUNT(*) AS n FROM contention").all()
                    await milestones.mark("\(name).read")
                    await milestones.wait("\(other).read")
                    if writesSecond { await milestones.wait("\(other).wrote") }
                    try await sql.raw("INSERT INTO contention (writer) VALUES (\(bind: name))").run()
                    await milestones.mark("\(name).wrote")
                }
                return nil
            } catch {
                await milestones.mark("\(name).wrote")
                return error
            }
        }
        async let a = writer(first, name: "a", other: "b", writesSecond: false)
        async let b = writer(second, name: "b", other: "a", writesSecond: true)
        let errors = await [a, b].compactMap { $0 }
        await databases.shutdownAsync()
        try await group.shutdownGracefully()
        for suffix in ["", "-wal", "-shm", "-journal"] { try? FileManager.default.removeItem(atPath: path + suffix) }
        return errors
    }

    private func temporaryPath() -> String {
        FileManager.default.temporaryDirectory.appendingPathComponent("viadere-contention-\(UUID().uuidString).sqlite3").path
    }

    /// The hazard, reproduced: one connection per event loop. A busy timeout would not change this (the busy handler is never asked).
    func testConnectionPerEventLoopRefusesTheSecondWriterAtOnce() async throws {
        let path = temporaryPath()
        let errors = try await race(DatabaseConfigurationFactory.sqlite(.file(path)).make(), path: path)
        XCTAssertEqual(errors.count, 1, "exactly one writer should be refused")
        XCTAssertTrue(errors.allSatisfy { String(describing: $0).lowercased().contains("locked") || String(describing: $0).lowercased().contains("busy") },
                      "\(errors)")
    }

    /// The fix that looks obvious does not work: with a five-second busy timeout on both connections the second writer is still refused at once.
    func testABusyTimeoutDoesNotPreventTheRefusal() async throws {
        let path = temporaryPath()
        let started = Date()
        let errors = try await race(DatabaseConfigurationFactory.sqlite(.file(path)).make(), path: path, busyTimeout: true)
        XCTAssertEqual(errors.count, 1, "exactly one writer should be refused")
        XCTAssertLessThan(Date().timeIntervalSince(started), 4, "SQLite did not wait for the timeout")
    }

    /// The server's configuration: the same two writers both commit.
    func testSerializedConfigurationLetsBothWritersCommit() async throws {
        let path = temporaryPath()
        let errors = try await race(SerializedSQLiteConfiguration.file(path), path: path)
        XCTAssertTrue(errors.isEmpty, "\(errors)")
    }
}
