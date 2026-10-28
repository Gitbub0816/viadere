import Fluent
import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import Vapor
import ViadereCore

/// Prometheus-style counters (G-13). **No PII and no unbounded labels**: every label value comes from a fixed vocabulary in this file
/// (status classes, event names), never from a request (no paths with ids, no addresses, no business or consumer ids).
final class MetricsRegistry: @unchecked Sendable {
    /// Security-relevant events counted for alerting. Adding one is a code change, which keeps label cardinality bounded.
    enum Event: String, CaseIterable, Sendable {
        case edgeRejected = "edge_rejected"
        case apiKeyRejected = "api_key_rejected"
        case apiKeyIPDenied = "api_key_ip_denied"
        case apiKeyMTLSDenied = "api_key_mtls_denied"
        case apiKeyCreated = "api_key_created"
        case apiKeyRevoked = "api_key_revoked"
        case apiKeyRotated = "api_key_rotated"
        case apiKeyAutoRevoked = "api_key_auto_revoked"
        case dashboardLoginFailed = "dashboard_login_failed"
        case dashboardIPDenied = "dashboard_ip_denied"
        case suspiciousLogin = "suspicious_login"
        case sessionRevoked = "session_revoked"
        case replayRejected = "replay_rejected"
        case rateLimited = "rate_limited"
        case limiterFailClosed = "limiter_fail_closed"
        case maintenanceRejected = "maintenance_rejected"
        case signupStopped = "signup_stopped"
        case webhookPaused = "webhook_paused"
        case webhookVerifyFailed = "webhook_verify_failed"
        case webhookDeadLettered = "webhook_dead_lettered"
        case messagingRestricted = "messaging_restricted"
        case businessSuspended = "business_suspended"
        case accountFrozen = "account_frozen"
        case twoPersonRequested = "two_person_requested"
        case assuranceFailed = "assurance_failed"
        case privilegedDenied = "privileged_denied"
        case verifyPurgeFailed = "verify_purge_failed"
    }

    private let lock = NSLock()
    private var events: [Event: Int] = [:]
    private var statusClasses: [String: Int] = [:]
    private var lastJobRun: Date?
    private var jobFailures = 0

    func count(_ event: Event, by amount: Int = 1) { lock.withLock { events[event, default: 0] += amount } }

    func countResponse(status: UInt) {
        let bucket: String
        switch status {
        case 100..<200: bucket = "1xx"
        case 200..<300: bucket = "2xx"
        case 300..<400: bucket = "3xx"
        case 400..<500: bucket = "4xx"
        default: bucket = "5xx"
        }
        lock.withLock { statusClasses[bucket, default: 0] += 1 }
    }

    func jobRan(at date: Date, failed: Bool) {
        lock.withLock {
            lastJobRun = date
            if failed { jobFailures += 1 }
        }
    }

    func value(_ event: Event) -> Int { lock.withLock { events[event] ?? 0 } }

    /// The exposition text. `gauges` are computed from the database at scrape time by `MetricsService`.
    func render(gauges: [(name: String, help: String, value: Double)]) -> String {
        let (e, s, job, failures) = lock.withLock { (events, statusClasses, lastJobRun, jobFailures) }
        var out = "# HELP viadere_http_responses_total HTTP responses by status class.\n# TYPE viadere_http_responses_total counter\n"
        for key in ["1xx", "2xx", "3xx", "4xx", "5xx"] { out += "viadere_http_responses_total{class=\"\(key)\"} \(s[key] ?? 0)\n" }
        out += "# HELP viadere_security_events_total Security-relevant events (bounded vocabulary, no identifiers).\n# TYPE viadere_security_events_total counter\n"
        for event in Event.allCases { out += "viadere_security_events_total{event=\"\(event.rawValue)\"} \(e[event] ?? 0)\n" }
        out += "# HELP viadere_job_failures_total Background job runs that threw.\n# TYPE viadere_job_failures_total counter\nviadere_job_failures_total \(failures)\n"
        if let job {
            out += "# HELP viadere_job_last_run_timestamp_seconds Last background job run.\n# TYPE viadere_job_last_run_timestamp_seconds gauge\n"
            out += "viadere_job_last_run_timestamp_seconds \(Int(job.timeIntervalSince1970))\n"
        }
        for gauge in gauges {
            out += "# HELP \(gauge.name) \(gauge.help)\n# TYPE \(gauge.name) gauge\n\(gauge.name) \(Self.format(gauge.value))\n"
        }
        return out
    }

    private static func format(_ value: Double) -> String { value == value.rounded() ? String(Int(value)) : String(value) }
}

/// Database-derived gauges: dead letters, audit-head age, pending deliveries. Aggregates only.
struct MetricsService {
    let db: any Database
    let ctx: ServerContext

    func gauges() async -> [(name: String, help: String, value: Double)] {
        var out: [(name: String, help: String, value: Double)] = []
        func gauge(_ name: String, _ help: String, _ compute: () async throws -> Double) async {
            if let value = try? await compute() { out.append((name, help, value)) }
        }
        let now = ctx.now
        await gauge("viadere_webhook_dead_letters", "Dead-lettered webhook deliveries still retained.") {
            Double(try await WebhookDeliveryRecord.query(on: db).filter(\.$status == "dead").count())
        }
        await gauge("viadere_webhook_pending", "Webhook deliveries waiting to be sent.") {
            Double(try await WebhookDeliveryRecord.query(on: db).filter(\.$status == "pending").count())
        }
        await gauge("viadere_audit_head_age_seconds", "Seconds since the newest audit event.") {
            guard let head = try await AuditEventRecord.query(on: db).sort(\.$seq, .descending).first() else { return 0 }
            return max(0, now.timeIntervalSince(head.occurredAt))
        }
        await gauge("viadere_audit_head_export_age_seconds", "Seconds since the last successful audit-head export (-1 = never).") {
            guard let last = try await PlatformFlagRecord.query(on: db).filter(\.$flag == PlatformFlag.auditExportMark.rawValue).first() else { return -1 }
            return max(0, now.timeIntervalSince(last.updatedAt))
        }
        await gauge("viadere_sms_queued", "Outbound SMS rows waiting to be sent.") {
            Double(try await SMSOutboundRecord.query(on: db).filter(\.$status == "queued").count())
        }
        let purgeable = { VerificationAttemptRecord.query(on: db).filter(\.$providerSessionId != nil).filter(\.$purgeStatus ~~ ["pending", "failed"])
            .filter(\.$status !~ ["issued", "processing"]) }
        await gauge("viadere_verify_provider_purge_pending", "Didit sessions finished or abandoned whose deletion at the provider is still outstanding.") {
            Double(try await purgeable().count())
        }
        await gauge("viadere_verify_provider_purge_overdue", "Didit sessions still not deleted at the provider more than an hour after they ended. Alert above 0 for 10 minutes.") {
            Double(try await purgeable().filter(\.$finishedAt < now.addingTimeInterval(-VerifyService.purgeAlertAfter)).count())
        }
        await gauge("viadere_verify_provider_purge_oldest_seconds", "Age of the oldest outstanding Didit deletion (0 = none).") {
            guard let oldest = try await purgeable().filter(\.$finishedAt != nil).sort(\.$finishedAt, .ascending).first()?.finishedAt else { return 0 }
            return max(0, now.timeIntervalSince(oldest))
        }
        await gauge("viadere_businesses_suspended", "Suspended businesses.") {
            Double(try await BusinessRecord.query(on: db).filter(\.$verificationStatus == VerificationStatus.suspended.rawValue).count())
        }
        await gauge("viadere_maintenance_mode", "1 while maintenance (read-only) mode is on.") {
            try await PlatformFlags(db: db, ctx: ctx).maintenance() == nil ? 0 : 1
        }
        return out
    }

    func render() async -> String { ctx.metrics.render(gauges: await gauges()) }
}

/// Counts every response by status class (outermost application middleware).
struct MetricsMiddleware: AsyncMiddleware {
    func respond(to request: Request, chainingTo next: any AsyncResponder) async throws -> Response {
        do {
            let response = try await next.respond(to: request)
            request.application.ctx.metrics.countResponse(status: response.status.code)
            return response
        } catch {
            request.application.ctx.metrics.countResponse(status: 500)
            throw error
        }
    }
}

enum MetricsRoutes {
    /// `GET /metrics` on the main port: 404 unless `METRICS_TOKEN` is set, 401 for a missing or wrong bearer token (constant-time compare).
    /// Never edge-exempt: it is served only to requests that pass the origin lock.
    static func register(_ app: Application) {
        app.get("metrics") { req -> Response in
            let ctx = req.ctx
            guard let expected = ctx.config.operations.metricsToken else { throw APIError.notFound }
            guard let presented = req.bearerToken, ConstantTime.equals(Data(presented.utf8), expected) else {
                ctx.metrics.count(.apiKeyRejected)
                throw APIError.unauthorized
            }
            let response = Response(status: .ok, body: .init(string: await MetricsService(db: req.db, ctx: ctx).render()))
            response.headers.contentType = HTTPMediaType(type: "text", subType: "plain", parameters: ["version": "0.0.4", "charset": "utf-8"])
            return response
        }
    }
}

/// A second, minimal HTTP listener for Prometheus on `METRICS_PORT` (bind to the machine's private address only; Fly's proxy never routes it
/// because the port is not in any `[[services]]` or `[http_service]`). `GET /metrics` only; no authentication because nothing outside the
/// private network can reach it, which is why it carries nothing but the same PII-free counters.
final class InternalMetricsServer: LifecycleHandler, @unchecked Sendable {
    private let port: Int
    private let render: @Sendable () async -> String
    private let lock = NSLock()
    private var channel: (any Channel)?

    init(port: Int, render: @escaping @Sendable () async -> String) {
        self.port = port
        self.render = render
    }

    func didBootAsync(_ application: Application) async throws {
        let render = self.render
        let bootstrap = ServerBootstrap(group: application.eventLoopGroup)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.pipeline.configureHTTPServerPipeline().flatMap {
                    channel.pipeline.addHandler(MetricsHTTPHandler(render: render))
                }
            }
        let bound = try await bootstrap.bind(host: application.http.server.configuration.hostname, port: port).get()
        lock.withLock { channel = bound }
    }

    func shutdownAsync(_ application: Application) async {
        let current = lock.withLock { () -> (any Channel)? in
            let c = channel
            channel = nil
            return c
        }
        try? await current?.close().get()
    }

    func shutdown(_ application: Application) {}
}

private final class MetricsHTTPHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private let render: @Sendable () async -> String
    private var head: HTTPRequestHead?

    init(render: @escaping @Sendable () async -> String) { self.render = render }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let value): head = value
        case .body: break
        case .end:
            guard let request = head else { return }
            head = nil
            let ok = request.method == .GET && request.uri.split(separator: "?").first == "/metrics"
            let render = self.render
            let loop = context.eventLoop
            let handler = NIOLoopBound(self, eventLoop: loop)
            let ctx = NIOLoopBound(context, eventLoop: loop)
            Task {
                let body = ok ? await render() : "not found\n"
                loop.execute {
                    handler.value.write(ctx.value, status: ok ? .ok : .notFound, body: body)
                }
            }
        }
    }

    private func write(_ context: ChannelHandlerContext, status: HTTPResponseStatus, body: String) {
        var headers = HTTPHeaders()
        headers.add(name: "Content-Type", value: "text/plain; version=0.0.4; charset=utf-8")
        headers.add(name: "Content-Length", value: String(body.utf8.count))
        headers.add(name: "Cache-Control", value: "no-store")
        headers.add(name: "Connection", value: "close")
        context.write(wrapOutboundOut(.head(HTTPResponseHead(version: .http1_1, status: status, headers: headers))), promise: nil)
        var buffer = context.channel.allocator.buffer(capacity: body.utf8.count)
        buffer.writeString(body)
        context.write(wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)
        context.writeAndFlush(wrapOutboundOut(.end(nil))).whenComplete { _ in context.close(promise: nil) }
    }
}
