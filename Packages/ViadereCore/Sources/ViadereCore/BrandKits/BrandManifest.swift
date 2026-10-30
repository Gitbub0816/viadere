import Crypto
import Foundation

/// A wall-clock date-time in the schedule's time zone, `YYYY-MM-DDTHH:MM` (no seconds, no offset).
public struct LocalDateTime: Sendable, Hashable, Comparable, CustomStringConvertible {
    public var year: Int, month: Int, day: Int, hour: Int, minute: Int

    public init?(year: Int, month: Int, day: Int, hour: Int, minute: Int) {
        guard (1970...9999).contains(year), LoopInputValidator.isCalendarDate(String(format: "%04d-%02d-%02d", year, month, day)),
              (0...23).contains(hour), (0...59).contains(minute) else { return nil }
        (self.year, self.month, self.day, self.hour, self.minute) = (year, month, day, hour, minute)
    }

    public init?(_ string: String) {
        let parts = string.split(separator: "T", omittingEmptySubsequences: false)
        guard parts.count == 2, parts[1].count == 5, LoopInputValidator.isCalendarDate(String(parts[0])) else { return nil }
        let date = parts[0].split(separator: "-").compactMap { Int($0) }
        let time = parts[1].split(separator: ":", omittingEmptySubsequences: false)
        guard date.count == 3, time.count == 2, time.allSatisfy({ $0.count == 2 && $0.allSatisfy { $0.isASCII && $0.isNumber } }),
              let h = Int(time[0]), let m = Int(time[1]) else { return nil }
        self.init(year: date[0], month: date[1], day: date[2], hour: h, minute: m)
    }

    public var description: String { String(format: "%04d-%02d-%02dT%02d:%02d", year, month, day, hour, minute) }

    /// Seconds since 1970-01-01T00:00 of this wall-clock reading as if it were UTC (days from civil, proleptic Gregorian).
    var naiveEpochSeconds: Int64 {
        var y = Int64(year)
        let m = Int64(month), d = Int64(day)
        y -= m <= 2 ? 1 : 0
        let era = (y >= 0 ? y : y - 399) / 400
        let yoe = y - era * 400
        let doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        let days = era * 146_097 + doe - 719_468
        return days * 86400 + Int64(hour) * 3600 + Int64(minute) * 60
    }

    /// The instant this wall-clock time denotes in `zone`. Normative DST rule (`SECURITY.md` §2.93):
    /// * a time that occurs twice (fall back) means the **earlier** instant;
    /// * a time that does not exist (spring forward) is shifted forward by the gap (it uses the offset in force before the transition).
    public func instant(in zone: TimeZone) -> Int64 {
        let t0 = naiveEpochSeconds
        let before = Int64(zone.secondsFromGMT(for: Date(timeIntervalSince1970: TimeInterval(t0 - 86400))))
        let after = Int64(zone.secondsFromGMT(for: Date(timeIntervalSince1970: TimeInterval(t0 + 86400))))
        var candidates: [Int64] = []
        for offset in Set([before, after]) {
            let u = t0 - offset
            if Int64(zone.secondsFromGMT(for: Date(timeIntervalSince1970: TimeInterval(u)))) == offset { candidates.append(u) }
        }
        return candidates.min() ?? (t0 - before)
    }

    public static func < (lhs: LocalDateTime, rhs: LocalDateTime) -> Bool { lhs.naiveEpochSeconds < rhs.naiveEpochSeconds }

    /// The local calendar day of `instant` in `zone`, `YYYY-MM-DD`.
    public static func localDay(of instant: Date, in zone: TimeZone) -> String {
        let shifted = Int64(instant.timeIntervalSince1970.rounded(.down)) + Int64(zone.secondsFromGMT(for: instant))
        var days = shifted >= 0 ? shifted / 86400 : (shifted - 86399) / 86400
        // civil from days
        days += 719_468
        let era = (days >= 0 ? days : days - 146_096) / 146_097
        let doe = days - era * 146_097
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
        let mp = (5 * doy + 2) / 153
        let d = doy - (153 * mp + 2) / 5 + 1
        let m = mp < 10 ? mp + 3 : mp - 9
        let y = yoe + era * 400 + (m <= 2 ? 1 : 0)
        return String(format: "%04d-%02d-%02d", Int(y), Int(m), Int(d))
    }
}

public struct BrandKit: Sendable, Hashable {
    public var kitId: String
    /// Studio name (never shown to customers as a claim; sanitized).
    public var name: String
    public var tokens: BrandTokens
    public var frameId: String?
    public var assets: [BrandAssetSlot: BrandAssetRef]

    public init(kitId: String, name: String, tokens: BrandTokens, frameId: String? = nil, assets: [BrandAssetSlot: BrandAssetRef] = [:]) {
        self.kitId = kitId
        self.name = name
        self.tokens = tokens
        self.frameId = frameId
        self.assets = assets
    }
}

public struct BrandScheduleWindow: Sendable, Hashable {
    public var kit: String
    public var startsAt: LocalDateTime
    /// `nil` = open-ended.
    public var endsAt: LocalDateTime?
    public var priority: Int

    public init(kit: String, startsAt: LocalDateTime, endsAt: LocalDateTime?, priority: Int) {
        self.kit = kit
        self.startsAt = startsAt
        self.endsAt = endsAt
        self.priority = priority
    }
}

public struct BrandPoolEntry: Sendable, Hashable {
    public var kit: String
    public var weight: Int

    public init(kit: String, weight: Int) {
        self.kit = kit
        self.weight = weight
    }
}

public struct BrandSchedule: Sendable, Hashable {
    /// IANA time zone identifier (`America/Phoenix`).
    public var timezone: String
    public var defaultKit: String?
    public var windows: [BrandScheduleWindow]
    /// Optional randomization among kits when no window is active (spec B3.2).
    public var randomPool: [BrandPoolEntry]

    public init(timezone: String, defaultKit: String? = nil, windows: [BrandScheduleWindow] = [], randomPool: [BrandPoolEntry] = []) {
        self.timezone = timezone
        self.defaultKit = defaultKit
        self.windows = windows
        self.randomPool = randomPool
    }
}

/// What a device downloads per connected business (plan section 4.6; schema `docs/protocol/schemas/brand-manifest-v1.schema.json`):
/// small, versioned, signed with the KMS key `brand-manifest` (JWS `typ` `viadere-brand-manifest+jws`), `ETag` = `manifestHash`.
public struct BrandManifest: Sendable, Hashable {
    public static let version: Int64 = 1
    public static let jwsType = "viadere-brand-manifest+jws"
    public static let maxBytes = 48 * 1024
    public static let maxKits = 8
    public static let maxWindows = 32
    public static let maxPool = 8
    /// Longest `not_after - issued_at`.
    public static let maxLifetime: Int64 = 30 * 24 * 3600

    public var businessId: BusinessID
    /// Monotonic per business.
    public var manifestVersion: Int64
    public var kits: [BrandKit]
    public var schedule: BrandSchedule
    public var issuedAt: Int64
    public var notAfter: Int64
    public var kid: String

    public init(businessId: BusinessID, manifestVersion: Int64, kits: [BrandKit], schedule: BrandSchedule, issuedAt: Int64, notAfter: Int64, kid: String) {
        self.businessId = businessId
        self.manifestVersion = manifestVersion
        self.kits = kits
        self.schedule = schedule
        self.issuedAt = issuedAt
        self.notAfter = notAfter
        self.kid = kid
    }

    public func kit(_ id: String) -> BrandKit? { kits.first { $0.kitId == id } }

    // MARK: Canonical form

    public var jsonValue: JSONValue {
        let kitValues: [JSONValue] = kits.map { kit in
            var o: [String: JSONValue] = ["kit_id": .string(kit.kitId), "name": .string(kit.name), "tokens": kit.tokens.jsonValue]
            if let frame = kit.frameId { o["frame_id"] = .string(frame) }
            if !kit.assets.isEmpty {
                var assets: [String: JSONValue] = [:]
                for (slot, ref) in kit.assets { assets[slot.rawValue] = ref.jsonValue }
                o["assets"] = .object(assets)
            }
            return .object(o)
        }
        var schedule: [String: JSONValue] = [
            "timezone": .string(self.schedule.timezone),
            "windows": .array(self.schedule.windows.map { w in
                var o: [String: JSONValue] = ["kit": .string(w.kit), "starts_at": .string(w.startsAt.description), "priority": .integer(Int64(w.priority))]
                if let end = w.endsAt { o["ends_at"] = .string(end.description) }
                return .object(o)
            }),
            "random_pool": .array(self.schedule.randomPool.map { .object(["kit": .string($0.kit), "weight": .integer(Int64($0.weight))]) }),
        ]
        if let d = self.schedule.defaultKit { schedule["default_kit"] = .string(d) }
        return .object(["v": .integer(Self.version), "business_id": .string(businessId.description), "version": .integer(manifestVersion),
                        "kits": .array(kitValues), "schedule": .object(schedule), "issued_at": .integer(issuedAt), "not_after": .integer(notAfter),
                        "kid": .string(kid)])
    }

    /// `ETag` and cache key: `sha256:<hex>` of the canonical payload.
    public func manifestHash() throws -> String { try ContractHash.sha256(jsonValue) }

    // MARK: Strict parse

    public static func parse(_ value: JSONValue) -> (manifest: BrandManifest?, issues: [ContractIssue]) {
        let sink = ContractIssueSink()
        guard let root = StrictObject(value, path: "", allowed: ["v", "business_id", "version", "kits", "schedule", "issued_at", "not_after", "kid"],
                                      required: ["v", "business_id", "version", "kits", "schedule", "issued_at", "not_after", "kid"], sink: sink) else {
            return (nil, sink.issues)
        }
        if let v = root.int("v"), v != version { sink.add("unsupported_version", "v") }
        let business = root.string("business_id").flatMap(BusinessID.init)
        if business == nil { sink.add(ContractIssue.invalidValue, "business_id") }
        var kits: [BrandKit] = []
        for (i, item) in (root.array("kits") ?? []).enumerated() {
            let path = "kits[\(i)]"
            guard let k = StrictObject(item, path: path, allowed: ["kit_id", "name", "tokens", "frame_id", "assets"], required: ["kit_id", "name", "tokens"], sink: sink),
                  let tokens = BrandTokens.parse(k.members["tokens"], path: "\(path).tokens", sink: sink) else { continue }
            var kit = BrandKit(kitId: k.string("kit_id") ?? "", name: k.string("name") ?? "", tokens: tokens, frameId: k.string("frame_id"))
            if let a = k.object("assets", allowed: Set(BrandAssetSlot.allCases.map(\.rawValue))) {
                for slot in BrandAssetSlot.allCases {
                    guard let r = a.object(slot.rawValue, allowed: ["sha256", "w", "h", "bytes"], required: ["sha256", "w", "h", "bytes"]) else { continue }
                    guard let sha = r.string("sha256"), let w = r.int("w"), let h = r.int("h"), let bytes = r.int("bytes") else { continue }
                    kit.assets[slot] = BrandAssetRef(sha256: sha, width: Int(clamping: w), height: Int(clamping: h), bytes: Int(clamping: bytes))
                }
            }
            kits.append(kit)
        }
        var schedule = BrandSchedule(timezone: "")
        if let s = root.object("schedule", allowed: ["timezone", "default_kit", "windows", "random_pool"], required: ["timezone", "windows", "random_pool"]) {
            schedule.timezone = s.string("timezone") ?? ""
            schedule.defaultKit = s.string("default_kit")
            for (i, item) in (s.array("windows") ?? []).enumerated() {
                let path = "schedule.windows[\(i)]"
                guard let w = StrictObject(item, path: path, allowed: ["kit", "starts_at", "ends_at", "priority"], required: ["kit", "starts_at", "priority"], sink: sink) else { continue }
                guard let start = w.string("starts_at").flatMap(LocalDateTime.init) else { sink.add(ContractIssue.invalidValue, "\(path).starts_at"); continue }
                var end: LocalDateTime?
                if w.has("ends_at") {
                    guard let e = w.string("ends_at").flatMap(LocalDateTime.init) else { sink.add(ContractIssue.invalidValue, "\(path).ends_at"); continue }
                    end = e
                }
                schedule.windows.append(BrandScheduleWindow(kit: w.string("kit") ?? "", startsAt: start, endsAt: end, priority: Int(clamping: w.int("priority") ?? -1)))
            }
            for (i, item) in (s.array("random_pool") ?? []).enumerated() {
                guard let p = StrictObject(item, path: "schedule.random_pool[\(i)]", allowed: ["kit", "weight"], required: ["kit", "weight"], sink: sink) else { continue }
                schedule.randomPool.append(BrandPoolEntry(kit: p.string("kit") ?? "", weight: Int(clamping: p.int("weight") ?? 0)))
            }
        }
        guard let businessId = business else { return (nil, sink.issues) }
        let manifest = BrandManifest(businessId: businessId, manifestVersion: root.int("version") ?? 0, kits: kits, schedule: schedule,
                                     issuedAt: root.int("issued_at") ?? 0, notAfter: root.int("not_after") ?? 0, kid: root.string("kid") ?? "")
        return (manifest, sink.issues)
    }

    // MARK: Publish-time validation (Studio and server)

    /// Every rule a manifest must satisfy before it is signed: ids, names, kit and frame references, asset refs per slot, time zone,
    /// window order, the **overlap rule** (two windows with equal priority may not overlap: the choice would be ambiguous), pool weights,
    /// lifetime. Returns `[]` when publishable.
    public func validationIssues(frames: FrameRegistry = .v1) -> [ContractIssue] {
        var issues: [ContractIssue] = []
        func add(_ code: String, _ path: String) { issues.append(ContractIssue(code: code, path: path)) }
        if kits.isEmpty || kits.count > Self.maxKits { add("invalid_count", "kits") }
        var ids = Set<String>()
        for (i, kit) in kits.enumerated() {
            if !ContractIdentifier.isValid(kit.kitId) { add("invalid_identifier", "kits[\(i)].kit_id") }
            if !ids.insert(kit.kitId).inserted { add("duplicate_id", "kits[\(i)].kit_id") }
            if kit.name.trimmingCharacters(in: .whitespaces).isEmpty || DisplayTextSanitizer.violation(of: kit.name, maxCharacters: 40, identity: true) != nil
                || !LoopContentRules.topics(in: kit.name).isEmpty {
                add("invalid_text", "kits[\(i)].name")
            }
            if let frame = kit.frameId, frames.definition(frame) == nil { add("unknown_frame", "kits[\(i)].frame_id") }
            for (slot, ref) in kit.assets where !ref.fits(slot) { add("invalid_asset", "kits[\(i)].assets.\(slot.rawValue)") }
        }
        guard let zone = TimeZone(identifier: schedule.timezone), !schedule.timezone.isEmpty else {
            add(ContractIssue.invalidValue, "schedule.timezone")
            return issues
        }
        if let d = schedule.defaultKit, !ids.contains(d) { add("unknown_kit", "schedule.default_kit") }
        if schedule.windows.count > Self.maxWindows { add("invalid_count", "schedule.windows") }
        for (i, w) in schedule.windows.enumerated() {
            if !ids.contains(w.kit) { add("unknown_kit", "schedule.windows[\(i)].kit") }
            if !(0...1000).contains(w.priority) { add(ContractIssue.invalidValue, "schedule.windows[\(i)].priority") }
            if let end = w.endsAt, end.instant(in: zone) <= w.startsAt.instant(in: zone) { add("empty_window", "schedule.windows[\(i)]") }
        }
        for (i, a) in schedule.windows.enumerated() {
            for j in (i + 1)..<max(i + 1, schedule.windows.count) {
                let b = schedule.windows[j]
                guard a.priority == b.priority else { continue }
                let (aStart, bStart) = (a.startsAt.instant(in: zone), b.startsAt.instant(in: zone))
                let aEnd = a.endsAt.map { $0.instant(in: zone) } ?? .max
                let bEnd = b.endsAt.map { $0.instant(in: zone) } ?? .max
                if aStart < bEnd && bStart < aEnd { add("ambiguous_overlap", "schedule.windows[\(i)],schedule.windows[\(j)]") }
            }
        }
        if schedule.randomPool.count > Self.maxPool { add("invalid_count", "schedule.random_pool") }
        var poolIds = Set<String>()
        for (i, p) in schedule.randomPool.enumerated() {
            if !ids.contains(p.kit) { add("unknown_kit", "schedule.random_pool[\(i)].kit") }
            if !poolIds.insert(p.kit).inserted { add("duplicate_id", "schedule.random_pool[\(i)].kit") }
            if !(1...100).contains(p.weight) { add(ContractIssue.invalidValue, "schedule.random_pool[\(i)].weight") }
        }
        if notAfter <= issuedAt || notAfter - issuedAt > Self.maxLifetime { add("invalid_lifetime", "not_after") }
        if manifestVersion < 1 { add(ContractIssue.invalidValue, "version") }
        if !ManifestJWS.isValidKid(kid) { add(ContractIssue.invalidValue, "kid") }
        return issues
    }

    // MARK: Signing and verification

    /// Signs the canonical payload (server, KMS key `brand-manifest`; tests use a software key).
    public func sign(with key: any DeviceSigningKey) async throws -> String {
        guard case .object(let payload) = jsonValue else { throw ManifestVerificationError.malformed("payload") }
        return try await ManifestJWS.sign(payload: payload, type: Self.jwsType, kid: kid, with: key)
    }

    /// Device-side verification: pinned key, `typ`, canonical payload, strict schema, `business_id` equal to the business being shown,
    /// within `issued_at - skew ... not_after`. Any failure means **neutral styling** (never an error that blocks a flow, spec B4.4).
    public static func verify(_ compact: String?, expectedBusiness: BusinessID, keys: [PinnedManifestKey], now: Date,
                              maxClockSkew: Int64 = 300) throws(ManifestVerificationError) -> BrandManifest {
        let payload = try ManifestJWS.verify(compact, type: jwsType, maxBytes: maxBytes, keys: keys)
        guard case .integer(let v)? = payload["v"], v == version else { throw .unsupportedVersion }
        let (manifest, issues) = parse(.object(payload))
        guard let manifest, issues.isEmpty, manifest.validationIssues().isEmpty else { throw .malformed("schema") }
        guard manifest.businessId == expectedBusiness else { throw .headerPayloadMismatch }
        let t = Int64(now.timeIntervalSince1970.rounded(.down))
        guard manifest.notAfter - manifest.issuedAt <= maxLifetime else { throw .lifetimeTooLong }
        guard t + maxClockSkew >= manifest.issuedAt else { throw .notYetValid }
        guard t < manifest.notAfter else { throw .expired }
        return manifest
    }
}
