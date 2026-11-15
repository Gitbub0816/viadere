import FluentKit
import FluentSQLiteDriver
import Foundation
import NIOCore

/// SQLite (development and tests only; strict environments require PostgreSQL) on **one connection** for the whole process.
///
/// fluent-sqlite-driver opens one connection per event loop, and every Fluent transaction starts with a deferred `BEGIN TRANSACTION`. Two such
/// connections deadlock as soon as both have read inside a transaction and one tries to write: SQLite returns `SQLITE_BUSY` to the one that would
/// have to wait for the other, at once, without calling any busy handler or busy timeout (the documented deadlock case of `sqlite3_busy_handler`).
/// That is why a busy timeout cannot help here: sqlite-nio already installs a busy handler that retries forever, and a background job writing while
/// a request transaction writes still failed (`ProviderAndJobTests.testBackgroundRunnerDeliversWebhooksAndSMSWithoutManualTicks`). One connection
/// makes the transactions of the process take turns instead, which is what SQLite does with writers anyway.
///
/// Every database handle is bound to the single event loop that owns the pool; results still reach `async` callers on whatever executor they run on.
/// Nothing changes for PostgreSQL.
struct SerializedSQLiteConfiguration: DatabaseConfiguration {
    var base: any DatabaseConfiguration
    var middleware: [any AnyModelMiddleware] {
        get { base.middleware }
        set { base.middleware = newValue }
    }

    static func file(_ path: String) -> SerializedSQLiteConfiguration {
        SerializedSQLiteConfiguration(base: DatabaseConfigurationFactory.sqlite(.file(path)).make())
    }

    func makeDriver(for databases: Databases) -> any DatabaseDriver {
        let loop = databases.eventLoopGroup.next()
        // The driver's pool is built over a group of exactly this loop: one connection.
        let single = Databases(threadPool: databases.threadPool, on: loop)
        return SerializedSQLiteDriver(base: base.makeDriver(for: single), loop: loop)
    }
}

struct SerializedSQLiteDriver: DatabaseDriver {
    let base: any DatabaseDriver
    let loop: any EventLoop

    func makeDatabase(with context: DatabaseContext) -> any Database {
        base.makeDatabase(with: DatabaseContext(configuration: context.configuration, logger: context.logger, eventLoop: loop, history: context.history,
                                                pageSizeLimit: context.pageSizeLimit, shouldTrace: context.shouldTrace))
    }

    func shutdown() { base.shutdown() }
    func shutdownAsync() async { await base.shutdownAsync() }
}
