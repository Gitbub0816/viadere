import Foundation
import ViadereCore

/// Where a business's Brand Kit is being asked to appear (WP-2.6, WP-2.7; spec B2.4, B4.4, B5; SECURITY.md §2.93 "Surfaces").
public enum BrandSurface: Sendable, Hashable {
    /// Approval and transaction-authorization sheets, sign-in approvals, security notices, verification and profile requests: **never
    /// branded** (a look-alike brand must never be able to dress up a security prompt). Checked before any lookup.
    case approval, signIn, security, verification, profileRequest
    /// The business home (Businesses → a business) and its settings header.
    case businessHome
    /// Decoration of a message card from this business (an accent line; never the sender's name or verified badge).
    case messageCard
    /// The in-app Wallet pass card (accent only).
    case walletPass
    /// Anything tied to one interaction (notification, Live Activity, alert card): branding only if `BrandSurfacePolicy.allowsBranding`.
    case interaction(purpose: InteractionPurpose, kind: InteractionKind)

    /// Surfaces that are neutral whatever the business publishes.
    public var isProtected: Bool {
        switch self {
        case .approval, .signIn, .security, .verification, .profileRequest: true
        case .interaction(let purpose, let kind): !BrandSurfacePolicy.allowsBranding(purpose: purpose, kind: kind)
        case .businessHome, .messageCard, .walletPass: false
        }
    }
}

/// The concrete style a renderer applies: clamped palettes (`ContrastPolicy`), a registered frame and the enumerated shape tokens. Built
/// only from a verified manifest, or `neutral`.
public struct BrandAppearanceStyle: Sendable, Hashable {
    public enum Source: String, Sendable, Hashable { case neutral, brandKit }

    public var source: Source
    public var kitId: String?
    public var palette: BrandStyleResolution
    public var frameId: String?
    public var radius: BrandRadius
    public var border: BrandBorder
    public var typeScale: BrandTypeScale

    public init(source: Source, kitId: String?, palette: BrandStyleResolution, frameId: String?, radius: BrandRadius, border: BrandBorder,
                typeScale: BrandTypeScale) {
        self.source = source
        self.kitId = kitId
        self.palette = palette
        self.frameId = frameId
        self.radius = radius
        self.border = border
        self.typeScale = typeScale
    }

    public static let neutral = BrandAppearanceStyle(source: .neutral, kitId: nil, palette: .neutral, frameId: nil, radius: .medium,
                                                     border: .hairline, typeScale: .standard)

    /// A kit's style: tokens clamped for contrast, frame only if registered and available `now`.
    public init(kit: BrandKit, now: Date, frames: FrameRegistry = .v1) {
        self.init(source: .brandKit, kitId: kit.kitId, palette: ContrastPolicy.resolve(kit.tokens), frameId: frames.resolve(kit.frameId, at: now),
                  radius: kit.tokens.radius ?? .medium, border: kit.tokens.border ?? .hairline, typeScale: kit.tokens.typeScale ?? .standard)
    }

    /// The style of a built Loop tree (`PresentationTree.style`).
    public init(_ style: PresentationStyle) {
        self.init(source: style.source == .brandKit ? .brandKit : .neutral, kitId: style.kitId, palette: style.palette, frameId: style.frameId,
                  radius: style.radius, border: style.border, typeScale: style.typeScale)
    }

    public var isNeutral: Bool { source == .neutral }

    /// Colors for protected elements (verified badge, risk chips, attribution, confirmation, outcome): always neutral, whatever the kit.
    public var protectedPalette: BrandStyleResolution { .neutral }
}

/// The kit (if any) for one business on one surface.
public struct BrandResolution: Sendable, Hashable {
    public var businessId: BusinessID
    /// `nil` = neutral Viadere styling.
    public var kit: BrandKit?
    public var selection: BrandKitSelection
    public var style: BrandAppearanceStyle

    public static func neutral(_ business: BusinessID) -> BrandResolution {
        BrandResolution(businessId: business, kit: nil, selection: .neutral, style: .neutral)
    }

    public var isBranded: Bool { kit != nil }
}

/// The device side of Brand Kits (WP-2.6; plan section 4.6 "Device cache"; SECURITY.md §2.93).
///
/// * **Never awaited by a security flow.** `resolution(…)` is synchronous and answers from memory (or the local cache) at once; protected
///   surfaces answer `neutral` before any lookup. Fetching happens only in `refresh`, which nothing on an approval, sign-in, verification
///   or alert path calls or waits for, and which gives up after `fetchTimeout`.
/// * **Verified, every time.** A manifest is used only after `BrandManifest.verify` against the build-pinned `brand-manifest` keys, for
///   the business being shown, inside its validity window, and is re-verified whenever it is loaded from disk. An expired, withdrawn,
///   tampered or unverifiable manifest renders neutral and is dropped from the cache.
/// * **Assets by hash.** Images come only from the dedicated asset host (`BrandAssetRef.url`, never the API host), and are stored and
///   shown only after their size, PNG signature and SHA-256 match the manifest; cached bytes are re-hashed on every read.
/// * **Per business.** Records are keyed by business and verified against it; a kit of one business can never style another.
public final class BrandKitStore: @unchecked Sendable {
    struct Entry: Sendable {
        var manifest: BrandManifest
        var pins: [String: String]
        var seed: Data?
        var assetHost: String?
    }

    private let api: (any BrandKitAPI)?
    private let assets: (any BrandAssetFetcher)?
    private let cache: any BrandKitCache
    private let keys: [PinnedManifestKey]
    private let apiHost: String?
    private let clock: @Sendable () -> Date
    private let fetchTimeout: Duration
    private let frames: FrameRegistry

    private let lock = NSLock()
    private var entries: [BusinessID: Entry] = [:]
    /// Businesses whose cache was consulted (so a miss is not re-read from disk on every render).
    private var loaded: Set<BusinessID> = []
    private var inFlight: [BusinessID: Task<BrandResolution, Never>] = [:]

    public init(api: (any BrandKitAPI)?, assets: (any BrandAssetFetcher)?, cache: any BrandKitCache, keys: [PinnedManifestKey],
                apiHost: String? = nil, clock: @escaping @Sendable () -> Date = { Date() }, fetchTimeout: Duration = .seconds(10),
                frames: FrameRegistry = .v1) {
        self.api = api
        self.assets = assets
        self.cache = cache
        self.keys = keys
        self.apiHost = apiHost?.lowercased()
        self.clock = clock
        self.fetchTimeout = fetchTimeout
        self.frames = frames
    }

    // MARK: Reading (synchronous; never waits on the network)

    /// The kit for `business` on `surface` now. Protected surfaces are neutral before anything is looked up.
    public func resolution(for business: BusinessID, surface: BrandSurface = .businessHome, interactionId: InteractionID? = nil) -> BrandResolution {
        guard !surface.isProtected, let entry = entry(for: business) else { return .neutral(business) }
        let now = clock()
        let pinned = interactionId.flatMap { entry.pins[$0.description.lowercased()] }
        let selection = BrandKitSelector.select(manifest: entry.manifest, now: now, pinnedKit: pinned, selectionSeed: entry.seed)
        guard let kitId = selection.kitId, let kit = entry.manifest.kit(kitId) else { return .neutral(business) }
        return BrandResolution(businessId: business, kit: kit, selection: selection, style: BrandAppearanceStyle(kit: kit, now: now, frames: frames))
    }

    /// The kit a Loop definition names (`appearance: brand_kit`), for `PresentationBuilder` (which applies it only to a business tree of the
    /// same business that asked for that kit). `nil` when the manifest is missing, invalid, expired or has no such kit.
    public func loopBrand(for business: BusinessID, kitKey: String) -> BrandKitPresentation? {
        guard let entry = entry(for: business), clock() < Date(timeIntervalSince1970: TimeInterval(entry.manifest.notAfter)),
              let kit = entry.manifest.kit(kitKey) else { return nil }
        return BrandKitPresentation(businessId: business, kitId: kit.kitId, tokens: kit.tokens, frameId: kit.frameId)
    }

    /// Verified bytes of `ref`, from the local cache only. Bytes that no longer hash to the reference are deleted and not returned.
    public func verifiedAsset(_ ref: BrandAssetRef) -> Data? {
        guard let data = cache.asset(sha256: ref.sha256) else { return nil }
        guard BrandAssetVerifier.isValid(data, for: ref) else {
            cache.removeAsset(sha256: ref.sha256)
            return nil
        }
        return data
    }

    /// The image a notification may attach (`BrandSurfacePolicy.notificationAttachment`: logo, else mark; never on security requests),
    /// with its verified bytes from the cache. `nil` = no attachment (the system shows the app icon).
    public func notificationAttachment(business: BusinessID, interactionId: InteractionID?, purpose: InteractionPurpose,
                                       kind: InteractionKind) -> (slot: BrandAssetSlot, asset: BrandAssetRef, data: Data)? {
        let resolved = resolution(for: business, surface: .interaction(purpose: purpose, kind: kind), interactionId: interactionId)
        guard let (slot, ref) = BrandSurfacePolicy.notificationAttachment(kit: resolved.kit, purpose: purpose, kind: kind),
              let data = verifiedAsset(ref) else { return nil }
        return (slot, ref, data)
    }

    /// The Live Activity accent per appearance (`BrandSurfacePolicy.liveActivityAccent`: the `accent` token only, only if the clamp kept
    /// it); `nil` members mean Viadere's own accent.
    public func liveActivityAccent(business: BusinessID, interactionId: InteractionID?, purpose: InteractionPurpose,
                                   kind: InteractionKind) -> (light: BrandColor?, dark: BrandColor?) {
        let resolved = resolution(for: business, surface: .interaction(purpose: purpose, kind: kind), interactionId: interactionId)
        return (BrandSurfacePolicy.liveActivityAccent(kit: resolved.kit, purpose: purpose, kind: kind, appearance: .light),
                BrandSurfacePolicy.liveActivityAccent(kit: resolved.kit, purpose: purpose, kind: kind, appearance: .dark))
    }

    // MARK: Fetching (never awaited by security flows)

    /// Fetches (conditionally), verifies and caches the manifest of `business`, then the assets the current selection needs. Concurrent
    /// calls for one business share one fetch. Any failure leaves the business neutral or on its still-valid verified manifest.
    @discardableResult
    public func refresh(_ business: BusinessID) async -> BrandResolution {
        let task: Task<BrandResolution, Never> = lock.withLock {
            if let running = inFlight[business] { return running }
            let task = Task { await self.performRefresh(business) }
            inFlight[business] = task
            return task
        }
        let result = await task.value
        lock.withLock { inFlight[business] = nil }
        return result
    }

    /// Refreshes several businesses (opening Businesses, at connect, before a scheduled window).
    public func refresh(_ businesses: [BusinessID]) async {
        await withTaskGroup(of: Void.self) { group in
            for business in Set(businesses) { group.addTask { _ = await self.refresh(business) } }
        }
    }

    /// Forgets one business (disconnected, blocked, `404`).
    public func forget(_ business: BusinessID) {
        lock.withLock {
            entries[business] = nil
            loaded.insert(business)
        }
        cache.removeRecord(for: business)
    }

    /// Sign-out and device revocation: memory and disk.
    public func removeAll() {
        lock.withLock {
            entries = [:]
            loaded = []
        }
        cache.removeAll()
    }

    private func performRefresh(_ business: BusinessID) async -> BrandResolution {
        guard let api else { return resolution(for: business) }
        let cached = cache.record(for: business)
        let fetched: BrandManifestFetch
        do {
            fetched = try await withTimeout(fetchTimeout) { try await api.brandManifest(business: business, ifNoneMatch: cached?.etag) }
        } catch let error as APIError where Self.status(error) == 404 {
            forget(business)
            return .neutral(business)
        } catch {
            // Offline, timed out, server error: keep whatever verified manifest is still valid (checked again at read time).
            return resolution(for: business)
        }
        let now = clock()
        switch fetched {
        case .notModified:
            guard let cached, let entry = verify(cached.response, now: now) else {
                forget(business)
                return .neutral(business)
            }
            install(entry, for: business)
        case .fetched(let response, let etag):
            guard response.businessId == business, let entry = verify(response, now: now) else {
                // Neutral, withdrawn, unverifiable or for another business: neutral now, nothing kept.
                forget(business)
                return .neutral(business)
            }
            cache.store(CachedBrandRecord(response: response, etag: etag, fetchedAt: now), for: business)
            install(entry, for: business)
        }
        await downloadAssets(for: business)
        return resolution(for: business)
    }

    private static func status(_ error: APIError) -> Int? {
        if case .server(let status, _, _) = error { return status }
        return nil
    }

    private func downloadAssets(for business: BusinessID) async {
        guard let assets, let entry = lock.withLock({ entries[business] }), let host = entry.assetHost else { return }
        let now = clock()
        var wanted: [(BrandAssetSlot, BrandAssetRef)] = []
        if let selected = BrandKitSelector.select(manifest: entry.manifest, now: now, selectionSeed: entry.seed).kitId.flatMap(entry.manifest.kit) {
            wanted += selected.assets.map { ($0.key, $0.value) }
        }
        for kitId in Array(Set(entry.pins.values)) + [entry.manifest.schedule.defaultKit].compactMap({ $0 }) {
            guard let kit = entry.manifest.kit(kitId) else { continue }
            for slot in [BrandAssetSlot.logo, .mark] { if let ref = kit.assets[slot] { wanted.append((slot, ref)) } }
        }
        var seen = Set<String>()
        for (slot, ref) in wanted where ref.fits(slot) && seen.insert(ref.sha256).inserted {
            if verifiedAsset(ref) != nil { continue }
            guard let url = ref.url(assetHost: host) else { continue }
            guard let data = try? await withTimeout(fetchTimeout, { try await assets.fetch(url, maxBytes: min(ref.bytes, slot.maxStoredBytes)) }),
                  BrandAssetVerifier.isValid(data, for: ref) else {
                ViadereLog.storage.error("brandkit.asset_rejected")
                continue
            }
            cache.storeAsset(data, sha256: ref.sha256)
        }
    }

    // MARK: Verification

    /// A usable entry, or `nil`: `branded` status, a manifest that verifies against the pinned keys for exactly this business inside its
    /// validity window, pins with well-formed ids, an asset host that is a plain DNS name and not the API host.
    func verify(_ response: BrandManifestResponse, now: Date) -> Entry? {
        guard response.status == .branded, !keys.isEmpty,
              let manifest = try? BrandManifest.verify(response.manifest, expectedBusiness: response.businessId, keys: keys, now: now) else { return nil }
        var pins: [String: String] = [:]
        for pin in response.pins.prefix(50) {
            guard let id = UUID(uuidString: pin.interactionId) else { continue }
            pins[id.uuidString.lowercased()] = pin.kitId
        }
        var host: String?
        if let raw = response.assetHost, let domain = LinkDomain(raw), domain.host != apiHost { host = domain.host }
        return Entry(manifest: manifest, pins: pins, seed: response.selectionSeedData, assetHost: host)
    }

    private func install(_ entry: Entry, for business: BusinessID) {
        lock.withLock {
            entries[business] = entry
            loaded.insert(business)
        }
    }

    /// The in-memory entry, loading (and re-verifying) the cached record once. An entry past `not_after` is dropped.
    private func entry(for business: BusinessID) -> Entry? {
        let now = clock()
        let (current, consulted) = lock.withLock { (entries[business], loaded.contains(business)) }
        if let current {
            if now < Date(timeIntervalSince1970: TimeInterval(current.manifest.notAfter)) { return current }
            forget(business)
            return nil
        }
        guard !consulted else { return nil }
        lock.withLock { _ = loaded.insert(business) }
        guard let record = cache.record(for: business) else { return nil }
        guard let entry = verify(record.response, now: now) else {
            cache.removeRecord(for: business)
            return nil
        }
        lock.withLock { entries[business] = entry }
        return entry
    }
}

/// Runs `operation`, giving up with `BrandKitError.timedOut` after `limit`. The caller is released at the deadline even if the operation
/// ignores cancellation (it is cancelled and left to finish on its own), so a hung server can never hold anything up.
func withTimeout<T: Sendable>(_ limit: Duration, _ operation: @escaping @Sendable () async throws -> T) async throws -> T {
    let once = ResumeOnce<T>()
    return try await withCheckedThrowingContinuation { continuation in
        once.install(continuation)
        let work = Task {
            do { once.resume(.success(try await operation())) } catch { once.resume(.failure(error)) }
        }
        Task {
            try? await Task.sleep(for: limit)
            work.cancel()
            once.resume(.failure(BrandKitError.timedOut))
        }
    }
}

/// Resumes a continuation exactly once, whichever side finishes first.
final class ResumeOnce<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<T, any Error>?
    private var pending: Result<T, any Error>?

    func install(_ continuation: CheckedContinuation<T, any Error>) {
        lock.lock()
        if let pending {
            self.pending = nil
            lock.unlock()
            continuation.resume(with: pending)
            return
        }
        self.continuation = continuation
        lock.unlock()
    }

    func resume(_ result: Result<T, any Error>) {
        lock.lock()
        guard let continuation else {
            if pending == nil { pending = result }
            lock.unlock()
            return
        }
        self.continuation = nil
        lock.unlock()
        continuation.resume(with: result)
    }
}
