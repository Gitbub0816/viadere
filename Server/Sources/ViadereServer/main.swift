import Foundation
import Logging
import Vapor
import ViadereServerKit

// Structured JSON logs with redaction of tokens, secrets and phone numbers; never below info in staging/production.
let level = LogLevelPolicy.effective(logLevel: ProcessInfo.processInfo.environment["LOG_LEVEL"],
                                     environment: ProcessInfo.processInfo.environment["ENVIRONMENT"])
LoggingSystem.bootstrap { label in StructuredLogHandler(label: label, level: level) }

var environment = try Environment.detect()
let app: Application
do {
    // Envelope-wrapped secrets (`*_WRAPPED`) are unwrapped with the Key Vault key-encryption key before the configuration is read (WP-B2).
    let config = try ServerConfig.fromEnvironment(try await WrappedSecrets.resolveFromEnvironment())
    app = try await makeApplication(environment: environment, config: config)
    app.asyncCommands.use(MaintenanceCommand(), as: "maintenance")
    app.asyncCommands.use(SeedCommand(), as: "seed")
    app.asyncCommands.use(CreateOperatorCommand(), as: "create-operator")
    app.asyncCommands.use(GrantOperatorPermissionCommand(), as: "grant-operator-permission")
    app.asyncCommands.use(StagingDemoCommand(), as: "staging-demo")
    app.asyncCommands.use(AuditHeadCommand(), as: "audit-head")
    app.asyncCommands.use(KeyDirectoryLogKeyCommand(), as: "key-directory-log-key")
    app.asyncCommands.use(LinkDescriptorKeyCommand(), as: "link-descriptor-key")
    app.asyncCommands.use(BrandManifestKeyCommand(), as: "brand-manifest-key")
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
