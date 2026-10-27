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
    app.asyncCommands.use(CreateOperatorCommand(), as: "create-operator")
    app.asyncCommands.use(AuditHeadCommand(), as: "audit-head")
    app.asyncCommands.use(KeyDirectoryLogKeyCommand(), as: "key-directory-log-key")
    app.asyncCommands.use(AuditVerifyCommand(), as: "audit-verify")
    app.asyncCommands.use(ExportDisputeCommand(), as: "export-dispute")
    app.asyncCommands.use(ReencryptFieldsCommand(), as: "reencrypt-fields")
    app.asyncCommands.use(RotateDataKeyCommand(), as: "rotate-data-key")
    app.asyncCommands.use(VerifyDataKeyCommand(), as: "verify-data-key")
    app.asyncCommands.use(AuditExportCommand(), as: "audit-export")
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
