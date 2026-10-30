@preconcurrency import AsyncKit
import FluentKit
import FluentPostgresDriver
import FluentSQL
import Foundation
import Logging
import NIOConcurrencyHelpers
import NIOCore
import NIOSSL
import PostgresKit
import PostgresNIO
import SQLKit

/// Where a new PostgreSQL connection gets its password from. With Microsoft Entra authentication the "password" is an access token for
/// `https://ossrdbms-aad.database.windows.net`, valid 5 to 60 minutes and checked by the server **only at authentication**, so a pooled connection
/// stays valid after its token expires and only new connections need a fresh one (ADR-0011).
public protocol PostgresPasswordSource: Sendable {
    func password() async throws -> String
}

/// The managed identity's Entra token (cached by `AzureManagedIdentity` until five minutes before it expires).
public struct EntraPostgresPassword: PostgresPasswordSource {
    let tokens: any AccessTokenSource
    public init(tokens: any AccessTokenSource) { self.tokens = tokens }
    public func password() async throws -> String { try await tokens.token(for: .postgres) }
}

/// A connection source that asks `passwordSource` for a password **for every new connection** (PostgresNIO 1.33.2, the current release, takes only
/// a static `password` in `PostgresConnection.Configuration`, so the stock `PostgresConnectionSource` cannot do this). If the password source fails,
/// the connection fails: there is no fallback to any other credential.
public struct TokenAuthPostgresConnectionSource: ConnectionPoolSource, @unchecked Sendable {
    public let host: String
    public let port: Int
    public let username: String
    public let database: String
    public let tls: PostgresConnection.Configuration.TLS
    public let passwordSource: any PostgresPasswordSource

    private static let ids = NIOLockedValueBox<Int>(0)

    public init(host: String, port: Int, username: String, database: String, tls: PostgresConnection.Configuration.TLS, passwordSource: any PostgresPasswordSource) {
        self.host = host
        self.port = port
        self.username = username
        self.database = database
        self.tls = tls
        self.passwordSource = passwordSource
    }

    /// `verify-full`: TLS required, the certificate chain verified against `caFile` (or the system trust store) and the host name checked.
    public static func verifyFullTLS(caFile: String?) throws -> PostgresConnection.Configuration.TLS {
        var configuration = TLSConfiguration.makeClientConfiguration()
        configuration.certificateVerification = .fullVerification
        configuration.minimumTLSVersion = .tlsv12
        if let caFile { configuration.trustRoots = .file(caFile) }
        return .require(try NIOSSLContext(configuration: configuration))
    }

    public func makeConnection(logger: Logger, on eventLoop: any EventLoop) -> EventLoopFuture<PostgresConnection> {
        let id = Self.ids.withLockedValue { $0 += 1; return $0 }
        let host = self.host, port = self.port, username = self.username, database = self.database, tls = self.tls, source = passwordSource
        return eventLoop.makeFutureWithTask {
            let password = try await source.password()
            let configuration = PostgresConnection.Configuration(host: host, port: port, username: username, password: password, database: database, tls: tls)
            return try await PostgresConnection.connect(on: eventLoop, configuration: configuration, id: id, logger: logger).get()
        }
    }
}

/// The Fluent configuration for `TokenAuthPostgresConnectionSource` (selected by `DATABASE_AUTH=entra`). The database it vends behaves like the
/// stock Fluent PostgreSQL database (same dialect, transactions, `SQLDatabase` and `PostgresDatabase` conformances), adapted from
/// fluent-postgres-driver 2.14.0 (MIT), whose driver type is internal and fixed to the static-password source.
struct TokenAuthPostgresConfiguration: DatabaseConfiguration {
    var middleware: [any AnyModelMiddleware] = []
    let source: TokenAuthPostgresConnectionSource
    var maxConnectionsPerEventLoop = 1
    var connectionPoolTimeout: TimeAmount = .seconds(10)

    func makeDriver(for databases: Databases) -> any DatabaseDriver {
        TokenAuthPostgresDriver(pool: EventLoopGroupConnectionPool(source: source, maxConnectionsPerEventLoop: maxConnectionsPerEventLoop,
                                                                   requestTimeout: connectionPoolTimeout, on: databases.eventLoopGroup))
    }
}

extension DatabaseConfigurationFactory {
    /// PostgreSQL whose connections authenticate with a fresh password (an Entra token) each.
    static func postgresTokenAuth(_ source: TokenAuthPostgresConnectionSource) -> DatabaseConfigurationFactory {
        .init { TokenAuthPostgresConfiguration(source: source) }
    }
}

struct TokenAuthPostgresDriver: DatabaseDriver, @unchecked Sendable {
    let pool: EventLoopGroupConnectionPool<TokenAuthPostgresConnectionSource>

    func makeDatabase(with context: DatabaseContext) -> any Database {
        TokenAuthFluentPostgresDatabase(database: PooledPostgresDatabase(pool: pool.pool(for: context.eventLoop), logger: context.logger).sql(),
                                        context: context, inTransaction: false)
    }

    func shutdown() { try? pool.syncShutdownGracefully() }
    func shutdownAsync() async { try? await pool.shutdownAsync() }
}

private struct PooledPostgresDatabase: PostgresDatabase {
    let pool: EventLoopConnectionPool<TokenAuthPostgresConnectionSource>
    let logger: Logger

    var eventLoop: any EventLoop { pool.eventLoop }

    func send(_ request: any PostgresRequest, logger: Logger) -> EventLoopFuture<Void> {
        pool.withConnection(logger: logger) { $0.send(request, logger: logger) }
    }

    func withConnection<T>(_ closure: @escaping (PostgresConnection) -> EventLoopFuture<T>) -> EventLoopFuture<T> {
        pool.withConnection(logger: logger, closure)
    }
}

struct TokenAuthFluentPostgresDatabase {
    let database: any SQLDatabase
    let context: DatabaseContext
    let inTransaction: Bool
}

extension TokenAuthFluentPostgresDatabase: Database {
    func execute(query: DatabaseQuery, onOutput: @escaping @Sendable (any DatabaseOutput) -> ()) -> EventLoopFuture<Void> {
        var expression = SQLQueryConverter(delegate: TokenAuthConverterDelegate()).convert(query)
        // `.create` returns the generated id, unless the custom id key is the empty string (composite ids), as in the stock driver.
        if case .create = query.action, query.customIDKey != .some(.string("")) {
            expression = SQLKit.SQLList([expression, SQLReturning(.init((query.customIDKey ?? .id).description))], separator: SQLRaw(" "))
        }
        return execute(sql: expression, { onOutput(TokenAuthDatabaseOutput(row: $0, schema: nil)) })
    }

    func execute(schema: DatabaseSchema) -> EventLoopFuture<Void> {
        let expression = SQLSchemaConverter(delegate: TokenAuthConverterDelegate()).convert(schema)
        return execute(sql: expression, { _ in })
    }

    func execute(enum e: DatabaseEnum) -> EventLoopFuture<Void> {
        switch e.action {
        case .create:
            return e.createCases.reduce(create(enum: e.name)) { $0.value($1) }.run()
        case .update:
            guard !e.createCases.isEmpty else { return eventLoop.makeSucceededFuture(()) }
            return eventLoop.flatten(e.createCases.map { alter(enum: e.name).add(value: $0).run() })
        case .delete:
            return drop(enum: e.name).run()
        }
    }

    func transaction<T: Sendable>(_ closure: @escaping @Sendable (any Database) -> EventLoopFuture<T>) -> EventLoopFuture<T> {
        guard !inTransaction else { return closure(self) }
        return withConnection { conn in
            let sql = conn as! any SQLDatabase
            return sql.raw("BEGIN").run().flatMap {
                closure(conn).flatMap { result in sql.raw("COMMIT").run().map { result } }
                    .flatMapError { error in sql.raw("ROLLBACK").run().flatMapThrowing { throw error } }
            }
        }
    }

    func withConnection<T>(_ closure: @escaping @Sendable (any Database) -> EventLoopFuture<T>) -> EventLoopFuture<T> {
        withConnection { (underlying: any PostgresDatabase) in
            closure(TokenAuthFluentPostgresDatabase(database: underlying.logging(to: self.logger).sql(queryLogLevel: self.database.queryLogLevel),
                                                    context: self.context, inTransaction: true))
        }
    }
}

extension TokenAuthFluentPostgresDatabase: TransactionControlDatabase {
    func beginTransaction() -> EventLoopFuture<Void> { raw("BEGIN").run() }
    func commitTransaction() -> EventLoopFuture<Void> { raw("COMMIT").run() }
    func rollbackTransaction() -> EventLoopFuture<Void> { raw("ROLLBACK").run() }
}

extension TokenAuthFluentPostgresDatabase: SQLDatabase {
    var version: (any SQLDatabaseReportedVersion)? { database.version }
    var dialect: any SQLDialect { database.dialect }
    var queryLogLevel: Logger.Level? { database.queryLogLevel }

    func execute(sql query: any SQLExpression, _ onRow: @escaping @Sendable (any SQLRow) -> Void) -> EventLoopFuture<Void> {
        database.execute(sql: query, onRow)
    }

    func execute(sql query: any SQLExpression, _ onRow: @escaping @Sendable (any SQLRow) -> Void) async throws {
        try await database.execute(sql: query, onRow)
    }

    func withSession<R>(_ closure: @escaping @Sendable (any SQLDatabase) async throws -> R) async throws -> R {
        try await database.withSession(closure)
    }
}

extension TokenAuthFluentPostgresDatabase: PostgresDatabase {
    func send(_ request: any PostgresRequest, logger: Logger) -> EventLoopFuture<Void> {
        withConnection { $0.send(request, logger: logger) }
    }

    func withConnection<T>(_ closure: @escaping (PostgresConnection) -> EventLoopFuture<T>) -> EventLoopFuture<T> {
        guard let postgres = database as? any PostgresDatabase else { return eventLoop.makeFailedFuture(FluentError.invalidField(name: "database", valueType: Any.self, error: PostgresDatabaseUnavailable())) }
        return postgres.withConnection(closure)
    }
}

private struct PostgresDatabaseUnavailable: Error {}

/// PostgreSQL column types for Fluent schemas (adapted from fluent-postgres-driver's `PostgresConverterDelegate`, MIT).
private struct TokenAuthConverterDelegate: SQLConverterDelegate {
    func customDataType(_ dataType: DatabaseSchema.DataType) -> (any SQLExpression)? {
        switch dataType {
        case .uuid: SQLRaw("UUID")
        case .bool: SQLRaw("BOOL")
        case .data: SQLRaw("BYTEA")
        case .date: SQLRaw("DATE")
        case .datetime: SQLRaw("TIMESTAMPTZ")
        case .double: SQLRaw("DOUBLE PRECISION")
        case .dictionary: SQLRaw("JSONB")
        case .array(of: let type):
            if let type, let element = customDataType(type) { TokenAuthArrayDataType(dataType: element) } else { SQLRaw("JSONB") }
        case .enum(let value): SQLIdentifier(value.name)
        case .int8, .uint8: SQLIdentifier("char")
        case .int16, .uint16: SQLRaw("SMALLINT")
        case .int32, .uint32: SQLRaw("INT")
        case .int64, .uint64: SQLRaw("BIGINT")
        case .string: SQLRaw("TEXT")
        case .time: SQLRaw("TIME")
        case .float: SQLRaw("FLOAT")
        case .custom: nil
        }
    }
}

private struct TokenAuthArrayDataType: SQLExpression {
    let dataType: any SQLExpression
    func serialize(to serializer: inout SQLSerializer) {
        dataType.serialize(to: &serializer)
        serializer.write("[]")
    }
}

/// A row as Fluent output (adapted from fluent-postgres-driver's `_PostgresDatabaseOutput`, MIT).
private struct TokenAuthDatabaseOutput: DatabaseOutput {
    let row: any SQLRow
    let schema: String?

    var description: String { String(describing: row) }
    private func adjust(key: FieldKey) -> FieldKey { schema.map { .prefix(.prefix(.string($0), "_"), key) } ?? key }
    func schema(_ schema: String) -> any DatabaseOutput { TokenAuthDatabaseOutput(row: row, schema: schema) }
    func contains(_ key: FieldKey) -> Bool { row.contains(column: adjust(key: key).description) }
    func decodeNil(_ key: FieldKey) throws -> Bool { try row.decodeNil(column: adjust(key: key).description) }
    func decode<T: Decodable>(_ key: FieldKey, as: T.Type) throws -> T { try row.decode(column: adjust(key: key).description, as: T.self) }
}
