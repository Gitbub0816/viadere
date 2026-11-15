import Foundation
import ViadereCore

/// RFC 9421 request signing for the business API (SECURITY §2.112). `ViadereBusinessClient(requestSigner:)` calls this for every attempt; it is
/// public so a custom transport or proxy can sign the same way.
///
/// Register the public key first (console: Security > Request signing): the console shows a challenge per API key; prove possession with
/// `HTTPSigningKeyProof.prove(challenge:key:)` and paste the public key (`key.publicKey.base64URL`) and the proof. The console then shows the
/// `vsk_…` key id to construct the signer with.
public enum ViadereRequestSigning {
    /// Adds `Content-Digest` (when there is a body), `Signature-Input` and `Signature` to `request`. `@authority`, `@path` and `@query` are those of
    /// `request.url` exactly as it will be sent.
    public static func sign(_ request: BusinessHTTPRequest, with signer: HTTPRequestSigner, now: Date = Date(),
                            nonce: String = SecureToken.generate(byteCount: 16)) async throws -> BusinessHTTPRequest {
        guard let authority = HTTPSignatureProfile.authority(of: request.url), let scheme = request.url.scheme, let host = request.url.host else {
            throw ViadereSDKError.invalidPath
        }
        let origin = "\(scheme)://\(host)" + (request.url.port.map { ":\($0)" } ?? "")
        let absolute = request.url.absoluteString
        guard absolute.lowercased().hasPrefix(origin.lowercased()) else { throw ViadereSDKError.invalidPath }
        var target = String(absolute.dropFirst(origin.count))
        if target.isEmpty { target = "/" }
        guard target.hasPrefix("/"), !target.contains("#") else { throw ViadereSDKError.invalidPath }
        var copy = request
        let typeKey = request.headers.keys.first { $0.caseInsensitiveCompare("Content-Type") == .orderedSame }
        var contentType = typeKey.flatMap { request.headers[$0] }
        if contentType == nil, let body = request.body, !body.isEmpty {
            // A body is always typed, and the type is covered.
            contentType = "application/json"
            copy.headers["Content-Type"] = "application/json"
        }
        let fields: [(name: String, value: String)]
        do {
            fields = try await signer.sign(method: request.method, authority: authority, target: target, body: request.body, contentType: contentType, now: now, nonce: nonce)
        } catch { throw ViadereSDKError.signingFailed }
        for field in fields { copy.headers[field.name] = field.value }
        return copy
    }
}
