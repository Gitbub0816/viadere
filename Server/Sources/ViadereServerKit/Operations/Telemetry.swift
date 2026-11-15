@preconcurrency import Crypto
import Fluent
import Foundation
import NIOHTTP1
import Vapor
import ViadereCore

/// OTLP/HTTP export (WP-F2, SECURITY.md §2.114): request spans and the `/metrics` counters, as OTLP JSON (`/v1/traces`, `/v1/metrics`), to
/// `OTEL_EXPORTER_OTLP_ENDPOINT`. Off when unset. `https` is required in staging and production; no export headers are read (nothing secret
/// rides on this path). `OTEL_SERVICE_NAME` names the resource (default `viadere-server`).
public struct TelemetrySettings: Sendable {
    /// The OTLP base URL; the signal paths are appended. `nil` = export off.
    public var endpoint: URL?
    public var serviceName = "viadere-server"
    /// Seconds between exports.
    public var interval: TimeInterval = 60

    public init() {}
}

extension ServerConfig {
    /// `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME`.
    mutating func applyTelemetryEnvironment(_ env: [String: String], strict: Bool) throws {
        var settings = TelemetrySettings()
        if let raw = env["OTEL_EXPORTER_OTLP_ENDPOINT"].flatMap({ $0.isEmpty ? nil : $0 }) {
            guard let url = URL(string: raw.hasSuffix("/") ? String(raw.dropLast()) : raw), let scheme = url.scheme?.lowercased(), url.host != nil,
                  url.user == nil, url.password == nil, url.query == nil, url.fragment == nil else {
                throw ServerConfigError.invalid("OTEL_EXPORTER_OTLP_ENDPOINT (an OTLP/HTTP base URL such as https://collector.example:4318)")
            }
            guard scheme == "https" || (scheme == "http" && !strict) else {
                throw ServerConfigError.invalid("OTEL_EXPORTER_OTLP_ENDPOINT (https is required in staging and production)")
            }
            settings.endpoint = url
        }
        if let name = env["OTEL_SERVICE_NAME"].flatMap({ $0.isEmpty ? nil : $0 }) {
            guard (1...64).contains(name.count), name.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" || $0 == ".") }) else {
                throw ServerConfigError.invalid("OTEL_SERVICE_NAME (1 to 64 letters, digits, '-', '_' or '.')")
            }
            settings.serviceName = name
        }
        telemetry = settings
    }
}

/// A telemetry attribute value.
public enum TelemetryValue: Sendable, Equatable {
    case string(String)
    case int(Int)
}

/// The **only** attribute keys that leave the process (SECURITY.md §2.114). Everything else is dropped, whatever its value; an allowed key whose
/// string value could be personal or secret (anything `LogRedactor` would change, an address, a long digit run, a UUID, a query string, more
/// than 128 characters) is dropped too. Request bodies, tokens, codes, addresses, phone numbers, subject refs and identifiers are therefore never
/// exported: no key admits them and no value shaped like them passes.
public enum TelemetryRedactor {
    public static let spanKeys: Set<String> = ["http.request.method", "http.route", "http.response.status_code"]
    public static let metricLabelKeys: Set<String> = ["class", "event", "reason"]
    public static let resourceKeys: Set<String> = ["service.name"]
    static let methods: Set<String> = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]

    private static let uuid = try! NSRegularExpression(pattern: #"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"#)
    private static let digits = try! NSRegularExpression(pattern: #"\d{7,}"#)

    public static func isSafe(_ value: String) -> Bool {
        let range = NSRange(value.startIndex..., in: value)
        return (1...128).contains(value.count) && value.allSatisfy({ $0.isASCII && !$0.isNewline }) && !value.contains("@") && !value.contains("?")
            && !value.contains("=") && LogRedactor.redact(value) == value && uuid.firstMatch(in: value, range: range) == nil
            && digits.firstMatch(in: value, range: range) == nil
    }

    public static func filter(_ attributes: [String: TelemetryValue], allowed: Set<String>) -> [String: TelemetryValue] {
        attributes.filter { key, value in
            guard allowed.contains(key) else { return false }
            switch value {
            case .int: return true
            case .string(let text): return isSafe(text)
            }
        }
    }

    /// The route **pattern** (`/v1/devices/:deviceId`), never the requested path; `unmatched` when no route matched.
    static func routePattern(_ route: Route?) -> String {
        guard let route else { return "unmatched" }
        let parts = route.path.map { component -> String in
            switch component {
            case .constant(let value): return value
            case .parameter(let name): return ":" + name
            case .anything: return "*"
            case .catchall: return "**"
            }
        }
        return "/" + parts.joined(separator: "/")
    }
}

/// One finished server span.
struct TelemetrySpan: Sendable, Equatable {
    var traceId: Data
    var spanId: Data
    var name: String
    var start: Date
    var end: Date
    var attributes: [String: TelemetryValue]
    var failed: Bool
}

/// The spans waiting for the next export (bounded: beyond `capacity` new spans are dropped and counted). Disabled = records nothing.
final class SpanRecorder: @unchecked Sendable {
    static let capacity = 2048
    let enabled: Bool
    private let lock = NSLock()
    private var spans: [TelemetrySpan] = []
    private(set) var dropped = 0

    init(enabled: Bool) { self.enabled = enabled }

    /// Records a span after filtering its attributes through the allow-list.
    func record(name: String, start: Date, end: Date, attributes: [String: TelemetryValue], failed: Bool) {
        guard enabled else { return }
        let filtered = TelemetryRedactor.filter(attributes, allowed: TelemetryRedactor.spanKeys)
        let safeName = TelemetryRedactor.isSafe(name) ? name : "request"
        let span = TelemetrySpan(traceId: Data(SecureToken.randomBytes(16)), spanId: Data(SecureToken.randomBytes(8)), name: safeName, start: start, end: end,
                                 attributes: filtered, failed: failed)
        lock.withLock {
            if spans.count < Self.capacity { spans.append(span) } else { dropped += 1 }
        }
    }

    func drain() -> [TelemetrySpan] {
        lock.withLock {
            let out = spans
            spans = []
            return out
        }
    }
}

/// Records one span per request: method, route pattern and status only. Incoming trace context is ignored (a caller cannot steer our traces).
struct TelemetryMiddleware: AsyncMiddleware {
    func respond(to request: Request, chainingTo next: any AsyncResponder) async throws -> Response {
        let recorder = request.application.ctx.spans
        guard recorder.enabled else { return try await next.respond(to: request) }
        let start = Date()
        let method = TelemetryRedactor.methods.contains(request.method.rawValue) ? request.method.rawValue : "OTHER"
        let route = TelemetryRedactor.routePattern(request.route)
        func finish(_ status: Int) {
            recorder.record(name: "\(method) \(route)", start: start, end: Date(),
                            attributes: ["http.request.method": .string(method), "http.route": .string(route), "http.response.status_code": .int(status)],
                            failed: status >= 500)
        }
        do {
            let response = try await next.respond(to: request)
            finish(Int(response.status.code))
            return response
        } catch {
            finish((error as? any AbortError).map { Int($0.status.code) } ?? 500)
            throw error
        }
    }
}

/// OTLP JSON encoding (the protobuf JSON mapping of OTLP 1.x: hex trace and span ids, 64-bit integers as decimal strings).
enum OTLPEncoder {
    static func attributes(_ values: [String: TelemetryValue]) -> [[String: Any]] {
        values.keys.sorted().map { key in
            switch values[key]! {
            case .string(let text): return ["key": key, "value": ["stringValue": text]]
            case .int(let number): return ["key": key, "value": ["intValue": String(number)]]
            }
        }
    }

    static func nanos(_ date: Date) -> String { String(UInt64(max(0, date.timeIntervalSince1970) * 1_000_000_000)) }

    static func resource(_ settings: TelemetrySettings) -> [String: Any] {
        ["attributes": attributes(TelemetryRedactor.filter(["service.name": .string(settings.serviceName)], allowed: TelemetryRedactor.resourceKeys))]
    }

    static func traces(_ spans: [TelemetrySpan], settings: TelemetrySettings) throws -> Data {
        let encoded: [[String: Any]] = spans.map { span in
            ["traceId": Hex.encode(span.traceId), "spanId": Hex.encode(span.spanId), "name": span.name, "kind": 2,
             "startTimeUnixNano": nanos(span.start), "endTimeUnixNano": nanos(span.end), "attributes": attributes(span.attributes),
             "status": ["code": span.failed ? 2 : 1]]
        }
        let body: [String: Any] = ["resourceSpans": [["resource": resource(settings), "scopeSpans": [["scope": ["name": "viadere"], "spans": encoded]]]]]
        return try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys, .withoutEscapingSlashes])
    }

    /// Counters as cumulative monotonic sums, gauges as gauges. Labels pass the metric-label allow-list.
    static func metrics(_ points: [MetricPoint], start: Date, now: Date, settings: TelemetrySettings) throws -> Data {
        var byName: [String: [MetricPoint]] = [:]
        for point in points where TelemetryRedactor.isSafe(point.name) { byName[point.name, default: []].append(point) }
        let metrics: [[String: Any]] = byName.keys.sorted().map { name in
            let points = byName[name]!
            let dataPoints: [[String: Any]] = points.map { point in
                var out: [String: Any] = ["attributes": attributes(TelemetryRedactor.filter(point.labels, allowed: TelemetryRedactor.metricLabelKeys)),
                                          "timeUnixNano": nanos(now)]
                if point.counter { out["startTimeUnixNano"] = nanos(start) }
                if point.value == point.value.rounded(), abs(point.value) < 9e15 { out["asInt"] = String(Int(point.value)) } else { out["asDouble"] = point.value }
                return out
            }
            if points.first?.counter == true {
                return ["name": name, "sum": ["aggregationTemporality": 2, "isMonotonic": true, "dataPoints": dataPoints]]
            }
            return ["name": name, "gauge": ["dataPoints": dataPoints]]
        }
        let body: [String: Any] = ["resourceMetrics": [["resource": resource(settings), "scopeMetrics": [["scope": ["name": "viadere"], "metrics": metrics]]]]]
        return try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys, .withoutEscapingSlashes])
    }
}

/// One metric value with its labels (bounded vocabularies from `MetricsRegistry`).
struct MetricPoint: Sendable, Equatable {
    var name: String
    var labels: [String: TelemetryValue]
    var value: Double
    var counter: Bool
}

extension MetricsRegistry {
    /// The counters of `render`, as points (no gauges: those come from the database at export time).
    func points() -> [MetricPoint] {
        let (e, s, failures, rejections) = lockedSnapshot()
        var out: [MetricPoint] = []
        for key in ["1xx", "2xx", "3xx", "4xx", "5xx"] {
            out.append(MetricPoint(name: "viadere_http_responses_total", labels: ["class": .string(key)], value: Double(s[key] ?? 0), counter: true))
        }
        for event in Event.allCases {
            out.append(MetricPoint(name: "viadere_security_events_total", labels: ["event": .string(event.rawValue)], value: Double(e[event] ?? 0), counter: true))
        }
        for (reason, value) in rejections.sorted(by: { $0.key.rawValue < $1.key.rawValue }) {
            out.append(MetricPoint(name: "viadere_brand_asset_rejections_total", labels: ["reason": .string(reason.rawValue)], value: Double(value), counter: true))
        }
        out.append(MetricPoint(name: "viadere_job_failures_total", labels: [:], value: Double(failures), counter: true))
        return out
    }
}

/// Exports on a timer (and once at shutdown). A failed export is dropped, never retried with older data, and never blocks a request.
final class OTLPExporter: LifecycleHandler, @unchecked Sendable {
    private let settings: TelemetrySettings
    private let http: any OutboundHTTP
    private let spans: SpanRecorder
    private let metrics: MetricsRegistry
    private let gauges: @Sendable () async -> [(name: String, help: String, value: Double)]
    private let started = Date()
    private let lock = NSLock()
    private var task: Task<Void, Never>?

    init(settings: TelemetrySettings, http: any OutboundHTTP, spans: SpanRecorder, metrics: MetricsRegistry,
         gauges: @escaping @Sendable () async -> [(name: String, help: String, value: Double)]) {
        self.settings = settings
        self.http = http
        self.spans = spans
        self.metrics = metrics
        self.gauges = gauges
    }

    /// One export of both signals; returns the HTTP statuses (tests).
    @discardableResult
    func exportOnce(now: Date = Date()) async -> [Int] {
        guard let base = settings.endpoint?.absoluteString else { return [] }
        var statuses: [Int] = []
        let pending = spans.drain()
        if !pending.isEmpty, let body = try? OTLPEncoder.traces(pending, settings: settings) {
            statuses.append((try? await http.send(method: .POST, url: base + "/v1/traces", headers: ["Content-Type": "application/json"], body: body))?.status ?? 0)
        }
        var points = metrics.points()
        for gauge in await gauges() { points.append(MetricPoint(name: gauge.name, labels: [:], value: gauge.value, counter: false)) }
        if let body = try? OTLPEncoder.metrics(points, start: started, now: now, settings: settings) {
            statuses.append((try? await http.send(method: .POST, url: base + "/v1/metrics", headers: ["Content-Type": "application/json"], body: body))?.status ?? 0)
        }
        return statuses
    }

    func didBootAsync(_ application: Application) async throws {
        let interval = UInt64(max(settings.interval, 5) * 1_000_000_000)
        let started = Task { [self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: interval)
                if Task.isCancelled { break }
                await exportOnce()
            }
        }
        lock.withLock { task = started }
    }

    func shutdownAsync(_ application: Application) async {
        let current = lock.withLock { () -> Task<Void, Never>? in
            let t = task
            task = nil
            return t
        }
        current?.cancel()
        await exportOnce()
    }

    func shutdown(_ application: Application) {}
}

/// The OTLP transport: Vapor's client behind the identity-endpoint guard; plain `http` only when the configuration allowed it (development).
struct OTLPHTTPTransport: OutboundHTTP {
    let client: any Client
    let destinationGuard: OutboundDestinationGuard
    let allowPlainHTTP: Bool

    func send(method: NIOHTTP1.HTTPMethod, url: String, headers: [String: String], body: Data?) async throws -> (status: Int, body: Data) {
        guard url.hasPrefix("https://") || (allowPlainHTTP && url.hasPrefix("http://")), let parsed = URL(string: url) else { throw Abort(.badRequest) }
        try await destinationGuard.check(parsed)
        var request = ClientRequest(method: method, url: URI(string: url))
        for (name, value) in headers { request.headers.replaceOrAdd(name: name, value: value) }
        if let body { request.body = ByteBuffer(data: body) }
        let response = try await client.send(request)
        var buffer = response.body ?? ByteBuffer()
        return (Int(response.status.code), Data(buffer.readBytes(length: min(buffer.readableBytes, 64 * 1024)) ?? []))
    }
}
