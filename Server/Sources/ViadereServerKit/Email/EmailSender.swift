import Foundation
import Logging
import Vapor

/// A transactional email. Bodies are plain text: they carry a one-time code or a link, nothing else.
public struct EmailMessage: Sendable, Equatable {
    public var to: String
    public var subject: String
    public var text: String
    /// What the message is for (`signup-code`, `invite`, `invite-code`); logged, never the content.
    public var kind: String

    public init(to: String, subject: String, text: String, kind: String) {
        self.to = to
        self.subject = subject
        self.text = text
        self.kind = kind
    }
}

public enum EmailError: Error, Sendable, Equatable {
    case rejected(Int)
    case transport
}

/// Sends transactional email (dashboard verification codes and invitations).
public protocol EmailSender: Sendable {
    func send(_ message: EmailMessage) async throws
}

/// Generic transactional-email HTTP API: `POST <EMAIL_API_URL>` with `Content-Type: application/json`, the API key in `EMAIL_API_AUTH_HEADER`
/// (default `Authorization: Bearer <key>`) and the body `{"from": …, "to": …, "subject": …, "text": …}`. Any 2xx is success. This is the
/// request shape of Resend, Mailgun-compatible relays and most "send one email" APIs; a provider with another body shape needs a small
/// adapter in front (see Server/README.md). Redirects are not followed and nothing from the response is logged.
public struct HTTPEmailSender: EmailSender {
    public let config: EmailConfig
    let client: any Client

    public init(config: EmailConfig, client: any Client) {
        self.config = config
        self.client = client
    }

    struct Body: Encodable {
        var from: String
        var to: String
        var subject: String
        var text: String
    }

    public func send(_ message: EmailMessage) async throws {
        let response: ClientResponse
        do {
            response = try await client.post(URI(string: config.apiURL.absoluteString)) { request in
                let value = config.authScheme.isEmpty ? config.apiKey : config.authScheme + " " + config.apiKey
                request.headers.replaceOrAdd(name: config.authHeader, value: value)
                request.headers.replaceOrAdd(name: .accept, value: "application/json")
                try request.content.encode(Body(from: config.fromAddress, to: message.to, subject: message.subject, text: message.text), as: .json)
            }
        } catch {
            throw EmailError.transport
        }
        guard (200..<300).contains(Int(response.status.code)) else { throw EmailError.rejected(Int(response.status.code)) }
    }
}

/// Development sender: writes the message to the log so a developer can follow a link or read a code. **In staging and production the
/// content is never logged** (only the kind and the recipient's domain), whatever the log level.
public struct LoggingEmailSender: EmailSender {
    let logBodies: Bool
    private let logger: Logger

    public init(environment: DeploymentEnvironment, logger: Logger = Logger(label: "viadere.email")) {
        logBodies = !environment.isStrict
        self.logger = logger
    }

    public func send(_ message: EmailMessage) async throws {
        if logBodies {
            logger.notice("email (development, not sent)", metadata: ["to": "\(message.to)", "subject": "\(message.subject)", "body": "\(message.text)"])
        } else {
            let domain = message.to.split(separator: "@").last.map(String.init) ?? "?"
            logger.warning("email provider not configured; message dropped", metadata: ["kind": "\(message.kind)", "toDomain": "\(domain)"])
        }
    }
}

/// Used when a delivery must be suppressed entirely.
public struct DisabledEmailSender: EmailSender {
    public init() {}
    public func send(_ message: EmailMessage) async throws {}
}
