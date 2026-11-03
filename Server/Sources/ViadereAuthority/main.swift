import Foundation
import Logging
import Vapor
import ViadereAuthorityKit

// The private grant / OIDC authority (ADR-0019 §2). Internal ingress only; its own identity, vault, database and image.
//
//   ViadereAuthority serve                                  (the app; keys load only with AUTHORITY_ENABLED=true)
//   ViadereAuthority migrate --yes                          (job-viadere-authority-migrate)
//   ViadereAuthority admin <command> --change-file <path> --commit <sha>   (job-viadere-authority-admin)
//   ViadereAuthority reconcile                              (job-viadere-authority-reconcile: Key Vault AuditEvent reconciliation)

// Process hardening (L-14, C-15): no core dumps and not dumpable, so key material, the pairwise key and HMAC keys in memory cannot be read from a dump
// or by a same-user ptrace.
guard AuthorityProcessHardening.apply() else {
    FileHandle.standardError.write(Data("Authority startup failed: process hardening (RLIMIT_CORE, PR_SET_DUMPABLE) could not be applied\n".utf8))
    exit(1)
}

LoggingSystem.bootstrap { label in
    var handler = StreamLogHandler.standardOutput(label: label)
    handler.logLevel = .info
    return handler
}

let arguments = CommandLine.arguments
let mode = arguments.dropFirst().first ?? "serve"
var environment = try Environment.detect()
let app: Application
do {
    let config = try AuthorityConfig.fromEnvironment()
    app = try await Application.make(environment)
    // Only `serve` loads keys; `migrate` and `admin` run as identities without any Key Vault role (AUTH-ADMIN-NO-KV).
    try await AuthorityApplication.configure(app, config: config, loadKeys: mode == "serve")
    app.asyncCommands.use(AuthorityAdminCommand(), as: "admin")
    app.asyncCommands.use(AuthorityReconcileCommand(), as: "reconcile")
} catch {
    // Configuration errors name variables, never values.
    FileHandle.standardError.write(Data("Authority startup failed: \(error)\n".utf8))
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
