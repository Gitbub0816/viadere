import Vapor
import ViadereCore

/// `ViadereServer key-directory-log-key` prints the **public** key (and log id) of the key-directory transparency log, the value that goes into
/// the app's `VIADERE_KEY_DIRECTORY_LOG_KEYS` and into every business monitor's pinned configuration. It never prints the private scalar.
public struct KeyDirectoryLogKeyCommand: AsyncCommand {
    public struct Signature: CommandSignature { public init() {} }
    public let signature = Signature()
    public let help = "Prints the public key of the key-directory transparency log (for the app build and business monitors)."
    public init() {}

    public func run(using context: CommandContext, signature: Signature) async throws {
        let settings = context.application.ctx.config.approve
        context.console.print("log_id=\(settings.logId)")
        context.console.print("public_key=\(settings.logKey.publicKey.base64URL)")
    }
}
