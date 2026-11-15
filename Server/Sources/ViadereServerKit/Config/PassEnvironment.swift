import Foundation

extension ServerConfig {
    /// Wallet pass signing configuration. All three PEMs and the identifier, or none (pass issuance off). Never committed:
    /// supply them from the secret store, either inline (`…_PEM`, `\n` escapes allowed) or as a file path (`…_PATH`).
    mutating func applyPassEnvironment(_ env: [String: String]) throws {
        func pem(_ inline: String, _ path: String) -> String? {
            if let value = env[inline], !value.isEmpty { return value.replacingOccurrences(of: "\\n", with: "\n") }
            if let file = env[path], !file.isEmpty, let text = try? String(contentsOfFile: file, encoding: .utf8) { return text }
            return nil
        }
        // The beta note on the back of every pass: on unless explicitly turned off (owner decision, docs/WALLET.md).
        if let beta = env["WALLET_BETA_LABEL"]?.lowercased(), !beta.isEmpty {
            guard ["true", "false", "1", "0"].contains(beta) else { throw ServerConfigError.invalid("WALLET_BETA_LABEL (true or false)") }
            walletBetaLabel = beta == "true" || beta == "1"
        }
        let identifier = env["PASS_TYPE_IDENTIFIER"].flatMap { $0.isEmpty ? nil : $0 }
        let certificate = pem("PASS_CERTIFICATE_PEM", "PASS_CERTIFICATE_PATH")
        let key = pem("PASS_PRIVATE_KEY_PEM", "PASS_PRIVATE_KEY_PATH")
        let wwdr = pem("PASS_WWDR_CERTIFICATE_PEM", "PASS_WWDR_CERTIFICATE_PATH")
        guard identifier != nil || certificate != nil || key != nil || wwdr != nil else { return }
        guard let identifier else { throw ServerConfigError.missing("PASS_TYPE_IDENTIFIER") }
        guard identifier.count <= 128, identifier.hasPrefix("pass."),
              identifier.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "." || $0 == "-") }) else {
            throw ServerConfigError.invalid("PASS_TYPE_IDENTIFIER (reverse-DNS, starts with pass.)")
        }
        guard let certificate else { throw ServerConfigError.missing("PASS_CERTIFICATE_PEM or PASS_CERTIFICATE_PATH") }
        guard let key else { throw ServerConfigError.missing("PASS_PRIVATE_KEY_PEM or PASS_PRIVATE_KEY_PATH") }
        guard let wwdr else { throw ServerConfigError.missing("PASS_WWDR_CERTIFICATE_PEM or PASS_WWDR_CERTIFICATE_PATH") }
        passes = PassConfig(passTypeIdentifier: identifier, certificatePEM: certificate, privateKeyPEM: key, wwdrCertificatePEM: wwdr)
    }
}
