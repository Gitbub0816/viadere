import Foundation
import NIOCore
import Vapor
import ViadereCore

enum DiditError: Error, Equatable {
    /// The provider is unreachable, slow or failing (5xx, 429, network). Nothing was disclosed; the caller fails cleanly.
    case unavailable
    case notFound
    /// The provider refused the request (4xx other than 404): misconfiguration, not a user error.
    case rejected(Int)
    case malformedResponse
    case notConfigured
}

/// What creating a session returns. The hosted `url` is deliberately dropped: the app uses the SDK with the short-lived `session_token`.
struct DiditSession: Sendable, Equatable {
    var sessionId: String
    var sessionToken: String
}

/// The provider operations Verify uses (Didit API v3, `https://verification.didit.me/v3/`). Replaceable in tests.
protocol DiditAPI: Sendable {
    /// `POST /v3/session/`. `vendorData` is an opaque internal id (the attempt id), never personal data.
    func createSession(workflowId: String, vendorData: String) async throws -> DiditSession
    /// `GET /v3/session/{id}/decision/`: the full decision, **with personal data**. Read it in memory and let it go.
    func decision(sessionId: String) async throws -> [String: JSONValue]
    /// `DELETE /v3/session/{id}/delete/` with `deletion_instruction: privacy_erasure` (purges the session, its files and any biometric
    /// template). A session that is already gone (`404`) counts as deleted.
    func deleteSession(sessionId: String, instructionId: String) async throws
    /// `POST /v3/users/delete/` for the vendor user created from `vendor_data`.
    func deleteUser(vendorData: String) async throws
}

struct VaporDiditAPI: DiditAPI {
    let client: any Client
    let apiKey: String
    let base: String
    static let maxResponseBytes = 8 * 1024 * 1024

    private func headers(json: Bool) -> HTTPHeaders {
        var headers: HTTPHeaders = ["x-api-key": apiKey, "accept": "application/json"]
        if json { headers.add(name: .contentType, value: "application/json") }
        return headers
    }

    private func send(_ method: HTTPMethod, _ path: String, body: [String: JSONValue]? = nil) async throws -> (status: HTTPStatus, body: Data) {
        let response: ClientResponse
        do {
            let uri = URI(string: base + path)
            let encoded = try body.map { try ViadereJSON.encode($0) }
            response = try await client.send(ClientRequest(method: method, url: uri, headers: headers(json: encoded != nil),
                                                           body: encoded.map { ByteBuffer(data: $0) }))
        } catch {
            throw DiditError.unavailable
        }
        guard var buffer = response.body, buffer.readableBytes <= Self.maxResponseBytes else {
            return (response.status, Data())
        }
        let data = buffer.readData(length: buffer.readableBytes) ?? Data()
        return (response.status, data)
    }

    private static func fail(_ status: HTTPStatus) -> DiditError {
        switch status.code {
        case 404: .notFound
        case 408, 425, 429, 500...599: .unavailable
        default: .rejected(Int(status.code))
        }
    }

    func createSession(workflowId: String, vendorData: String) async throws -> DiditSession {
        let (status, data) = try await send(.POST, "/v3/session/", body: ["workflow_id": .string(workflowId), "vendor_data": .string(vendorData)])
        guard (200..<300).contains(Int(status.code)) else { throw Self.fail(status) }
        guard case .object(let object)? = try? JSONDecoder().decode(JSONValue.self, from: data), let id = object["session_id"]?.stringValue,
              let token = object["session_token"]?.stringValue, !id.isEmpty, !token.isEmpty, id.count <= 64, token.count <= 512 else { throw DiditError.malformedResponse }
        return DiditSession(sessionId: id, sessionToken: token)
    }

    func decision(sessionId: String) async throws -> [String: JSONValue] {
        let (status, data) = try await send(.GET, "/v3/session/\(sessionId)/decision/")
        guard (200..<300).contains(Int(status.code)) else { throw Self.fail(status) }
        guard case .object(let object)? = try? JSONDecoder().decode(JSONValue.self, from: data) else { throw DiditError.malformedResponse }
        return object
    }

    func deleteSession(sessionId: String, instructionId: String) async throws {
        let (status, _) = try await send(.DELETE, "/v3/session/\(sessionId)/delete/",
                                         body: ["deletion_instruction": .string("privacy_erasure"), "instruction_id": .string(instructionId)])
        if (200..<300).contains(Int(status.code)) || status.code == 404 { return }
        throw Self.fail(status)
    }

    func deleteUser(vendorData: String) async throws {
        let (status, _) = try await send(.POST, "/v3/users/delete/", body: ["vendor_data_list": .array([.string(vendorData)])])
        if (200..<300).contains(Int(status.code)) || status.code == 404 { return }
        throw Self.fail(status)
    }
}
