import Fluent
import Vapor

/// The only routes of `ROLE=worker` (it has no ingress; the platform probes these). Same answers as the API's `/healthz` and `/readyz`.
enum HealthRoutes {
    static func register(_ routes: any RoutesBuilder) {
        routes.get("healthz") { _ -> Response in
            let response = Response(status: .ok, body: .init(string: "{\"status\":\"ok\"}"))
            response.headers.contentType = .json
            return response
        }
        routes.get("readyz") { req -> Response in
            let ready = (try? await OutboxMessageRecord.query(on: req.db).limit(1).all()) != nil
            let response = Response(status: ready ? .ok : .serviceUnavailable, body: .init(string: ready ? "{\"status\":\"ok\"}" : "{\"status\":\"unavailable\"}"))
            response.headers.contentType = .json
            return response
        }
    }
}
