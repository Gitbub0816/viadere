import Foundation
import Logging
import Vapor
import ViadereServerKit

// Structured JSON logs with redaction of tokens, secrets and phone numbers.
let level = Logger.Level(rawValue: (ProcessInfo.processInfo.environment["LOG_LEVEL"] ?? "info").lowercased()) ?? .info
LoggingSystem.bootstrap { label in StructuredLogHandler(label: label, level: level) }

var environment = try Environment.detect()
let app: Application
do {
    let config = try ServerConfig.fromEnvironment()
    app = try await makeApplication(environment: environment, config: config)
    app.asyncCommands.use(SeedCommand(), as: "seed")
} catch {
    // Configuration errors are safe to print (they name variables, never values).
    FileHandle.standardError.write(Data("Startup failed: \(error)\n".utf8))
    exit(1)
}
do {
    try await app.execute()
    try await app.asyncShutdown()
} catch {
    try? await app.asyncShutdown()
    FileHandle.standardError.write(Data("Fatal: \(type(of: error))\n".utf8))
    exit(1)
}
