import Crypto
import Foundation

/// The kit chosen for a surface, and why.
public struct BrandKitSelection: Sendable, Hashable, Codable {
    public enum Reason: String, Sendable, Codable, Hashable {
        /// The kit pinned to an active interaction or Loop instance at creation (no mid-flow appearance change).
        case pinned
        /// The highest-priority window active now.
        case window
        /// Stable daily randomization among pool kits.
        case randomPool = "random_pool"
        case defaultKit = "default_kit"
        /// No manifest, an invalid or stale one, a pinned kit that no longer exists, or nothing configured.
        case neutral
    }

    /// `nil` = neutral Viadere styling.
    public var kitId: String?
    public var reason: Reason

    public init(kitId: String?, reason: Reason) {
        self.kitId = kitId
        self.reason = reason
    }

    public static let neutral = BrandKitSelection(kitId: nil, reason: .neutral)
}

/// Deterministic kit selection (plan section 4.6, WP-2.4). Pure: the same inputs give the same kit on every device and on the server.
///
/// Order: pinned kit → highest-priority active window (in the schedule's time zone) → random pool → default → neutral. Equal-priority
/// active windows cannot pass `BrandManifest.validationIssues`; if a manifest has them anyway, the choice falls through to the default
/// (an ambiguity never resolves to an arbitrary brand).
public enum BrandKitSelector {
    public static func select(manifest: BrandManifest?, now: Date, pinnedKit: String? = nil, selectionSeed: Data? = nil) -> BrandKitSelection {
        guard let manifest, let zone = TimeZone(identifier: manifest.schedule.timezone) else { return .neutral }
        let t = Int64(now.timeIntervalSince1970.rounded(.down))
        guard t < manifest.notAfter else { return .neutral }
        if let pinnedKit {
            return manifest.kit(pinnedKit) != nil ? BrandKitSelection(kitId: pinnedKit, reason: .pinned) : .neutral
        }
        let active = manifest.schedule.windows.filter { w in
            w.startsAt.instant(in: zone) <= t && (w.endsAt.map { t < $0.instant(in: zone) } ?? true) && manifest.kit(w.kit) != nil
        }
        if let top = active.map(\.priority).max() {
            let winners = active.filter { $0.priority == top }
            if winners.count == 1 { return BrandKitSelection(kitId: winners[0].kit, reason: .window) }
        }
        let pool = manifest.schedule.randomPool.filter { manifest.kit($0.kit) != nil && $0.weight > 0 }
        if !pool.isEmpty, let seed = selectionSeed {
            let day = LocalDateTime.localDay(of: now, in: zone)
            let total = pool.reduce(0) { $0 + UInt64($1.weight) }
            var pick = poolValue(seed: seed, day: day) % total
            for entry in pool {
                if pick < UInt64(entry.weight) { return BrandKitSelection(kitId: entry.kit, reason: .randomPool) }
                pick -= UInt64(entry.weight)
            }
        }
        if let d = manifest.schedule.defaultKit, manifest.kit(d) != nil { return BrandKitSelection(kitId: d, reason: .defaultKit) }
        return .neutral
    }

    /// First 8 bytes (big-endian) of `SHA-256("viadere-brand-pool-v1|" ‖ seed ‖ "|" ‖ day)`.
    static func poolValue(seed: Data, day: String) -> UInt64 {
        let digest = SHA256.hash(data: Data("viadere-brand-pool-v1|".utf8) + seed + Data("|\(day)".utf8))
        return digest.prefix(8).reduce(0) { ($0 << 8) | UInt64($1) }
    }
}

/// The per-(customer, business) seed of the random pool, computed by the **server** with a dedicated key (`BRAND_SELECTION_KEY`) and
/// delivered beside the manifest. It makes the choice stable across a day and across the customer's devices, and, because each business
/// gets an unrelated seed from a key the business never sees, the pick cannot be used to link a customer across businesses.
public enum BrandSelectionSeed {
    public static func derive(key: SymmetricKey, consumer: ConsumerID, business: BusinessID) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: Data("viadere-brand-seed-v1|\(consumer)|\(business)".utf8), using: key))
    }
}
