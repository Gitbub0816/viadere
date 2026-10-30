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

/// `ViadereServer link-descriptor-key` prints the **public** `link-descriptor` key (and its key id) from the configured key management service:
/// the value of the app's `VIADERE_LINK_DESCRIPTOR_KEYS` and of a business SDK's pinned Viadere keys. It never prints a private key.
public struct LinkDescriptorKeyCommand: AsyncCommand {
    public struct Signature: CommandSignature { public init() {} }
    public let signature = Signature()
    public let help = "Prints the public link-descriptor key (for the app build and business SDKs)."
    public init() {}

    public func run(using context: CommandContext, signature: Signature) async throws {
        let key = try await context.application.ctx.kms.publicKey(keyRef: .linkDescriptor)
        context.console.print("kid=\(KeyIdentifier.make(try key.signingKey()))")
        context.console.print("public_key=\(key.base64URL)")
    }
}
