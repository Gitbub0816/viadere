import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

public enum AppTab: String, CaseIterable, Sendable, Hashable { case home, activity, connect, messages, settings }

/// A request to start the connect flow with a code that arrived by link, QR, NFC or App Clip.
public struct PendingConnect: Equatable, Sendable {
    public var code: BusinessCode
    public var link: ConnectLink?
    public var source: ConnectSource
}

/// Root state: which top-level phase the app is in, where the user is, and what to present.
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class AppModel {
    public enum Phase: Equatable, Sendable { case launching, onboarding(OnboardingStep), needsReenrollment, ready }

    public private(set) var phase: Phase = .launching
    public var selectedTab: AppTab = .home
    public var presentedApproval: ApprovalViewModel?
    public var pendingConnect: PendingConnect?
    public var pendingAccountLinkToken: String?
    public var conversationToOpen: SessionID?
    public var businessToOpen: BusinessHandle?
    public var toast: String?
    /// Set to open Settings → Trusted devices (the security notice banner's "Review"); Settings clears it once it has navigated.
    public var reviewDevicesRequested = false
    public private(set) var isLocked = false
    /// Bumped every time the app locks. The UI keys its content on this so every presented sheet, alert and
    /// pushed screen is torn down with the lock, and nothing underneath can stay visible or interactive.
    public private(set) var lockEpoch = 0
    /// True when the keychain could not be read at launch (locked, early boot): keys are re-checked on the next
    /// foreground instead of forcing a re-enrollment.
    public private(set) var keysNeedRecheck = false

    public let services: ViadereServices
    /// The explanation shown before the passkey sheet when setting this iPhone up again.
    public let passkeyGate = PasskeyExplanationGate()
    public let home: HomeViewModel
    public let activity: ActivityViewModel
    public let rewards: RewardsViewModel
    public let wallet: WalletPassCoordinator
    public let messages: MessagesViewModel
    public let securityNotices: SecurityNoticesViewModel
    private var queuedLink: DeepLink?
    /// Links and notification opens that arrived while the app was locked, replayed in order after unlock.
    private var lockedQueue: [DeepLink] = []
    /// How many opens are waiting for an unlock (tests and the lock screen).
    public var queuedWhileLockedCount: Int { lockedQueue.count }
    static let maxQueuedWhileLocked = 5
    private var backgroundedAt: Date?
    private var isColdLaunch = true

    /// - Parameter walletLibrary: `PassKitWalletLibrary()` in the app; the default reports Wallet as unavailable.
    public init(services: ViadereServices, walletLibrary: any WalletLibrary = UnavailableWalletLibrary()) {
        self.services = services
        home = HomeViewModel(services: services)
        activity = ActivityViewModel(services: services)
        rewards = RewardsViewModel(services: services)
        wallet = WalletPassCoordinator(services: services, library: walletLibrary)
        messages = MessagesViewModel(services: services)
        securityNotices = SecurityNoticesViewModel(services: services)
        // The API client reports "the server no longer trusts this device" through this notifier.
        services.revocation.setHandler { [weak self] in
            Task { @MainActor in await self?.deviceWasRevoked() }
        }
    }

    // MARK: Launch

    public func bootstrap() async {
        let hasSession = await services.sessions.isSignedIn
        let record = try? await services.records.load()
        let complete = services.preferences.bool(.onboardingComplete)
        guard hasSession, complete else {
            phase = .onboarding(OnboardingFlow.resume(hasSession: hasSession, hasDevice: record != nil,
                                                      primingShown: services.preferences.bool(.notificationPrimingShown), complete: complete,
                                                      recoveryPending: RecoveryHoldStore(secrets: services.secrets).load() != nil))
            return
        }
        switch await services.account.health() {
        case .healthy:
            phase = .ready
        case .needsReenrollment, .notEnrolled:
            phase = .needsReenrollment
        case .unavailable:
            // The keychain can't answer yet (-25308 and friends): not an invalidation. Stay usable, re-check later.
            phase = .ready
            keysNeedRecheck = true
        }
        if AppLockPolicy(enabled: services.preferences.bool(.appLockEnabled)).shouldLock(backgroundedAt: nil, now: services.clock(), isColdLaunch: isColdLaunch) {
            lock()
        }
        isColdLaunch = false
        if phase == .ready {
            await home.load()
            await activity.load()
            await securityNotices.load()
            if let link = queuedLink { queuedLink = nil; await handle(link) }
        }
    }

    public func completeOnboarding() async {
        phase = .ready
        await home.load()
        await activity.load()
        await securityNotices.load()
        if let link = queuedLink { queuedLink = nil; await handle(link) }
    }

    // MARK: App lock & scene phases

    public func reviewDevices() { reviewDevicesRequested = true; selectedTab = .settings }

    public func sceneDidEnterBackground() { backgroundedAt = services.clock() }

    public func sceneWillEnterForeground() async {
        let policy = AppLockPolicy(enabled: services.preferences.bool(.appLockEnabled))
        if phase == .ready, policy.shouldLock(backgroundedAt: backgroundedAt, now: services.clock(), isColdLaunch: false) { lock() }
        backgroundedAt = nil
        if keysNeedRecheck {
            switch await services.account.health() {
            case .healthy: keysNeedRecheck = false
            case .needsReenrollment, .notEnrolled: keysNeedRecheck = false; phase = .needsReenrollment
            case .unavailable: break
            }
        }
        if phase == .ready, !isLocked { await home.load(); await activity.load(); await securityNotices.load() }
    }

    /// Locks the app: dismisses every presented sheet and discards pending presentations, so nothing stays on
    /// screen behind or above the lock. Links and notification opens that arrive meanwhile are queued.
    public func lock() {
        guard !isLocked else { return }
        isLocked = true
        lockEpoch += 1
        presentedApproval = nil
        pendingConnect = nil
        pendingAccountLinkToken = nil
        conversationToOpen = nil
        businessToOpen = nil
        toast = nil
    }

    public func unlock() async {
        let ok = await services.appLock.authenticate(reason: "Unlock Viadere")
        if ok { await unlocked() }
    }

    /// Opens the app after a successful authentication and replays what arrived while it was locked.
    func unlocked() async {
        isLocked = false
        let replay = lockedQueue
        lockedQueue.removeAll()
        for link in replay { await handle(link) }
    }

    private func enqueueWhileLocked(_ link: DeepLink) {
        lockedQueue.append(link)
        if lockedQueue.count > Self.maxQueuedWhileLocked { lockedQueue.removeFirst(lockedQueue.count - Self.maxQueuedWhileLocked) }
    }

    // MARK: Deep links & notifications

    public func open(url: URL) async {
        guard let link = DeepLinkRouter.route(url) else { return }
        await handle(link)
    }

    public func handle(_ link: DeepLink) async {
        // Nothing is routed, fetched or presented while locked: it waits for the unlock.
        guard !isLocked else { enqueueWhileLocked(link); return }
        guard phase == .ready else { queuedLink = link; return }
        switch link {
        case .connect(let code, let link):
            selectedTab = .connect
            pendingConnect = PendingConnect(code: code, link: link, source: link == nil ? .code : .qr)
        case .business(let handle):
            businessToOpen = handle
            selectedTab = .home
        case .accountLink(let token):
            pendingAccountLinkToken = token
            selectedTab = .settings
        case .handoff(let token):
            selectedTab = .home
            guard let redeemed = try? await services.api.redeemHandoff(token: token) else {
                toast = "That link has expired. Open Viadere to see your requests."
                await home.load()
                return
            }
            switch redeemed.purpose {
            case .interaction:
                if let id = redeemed.interactionId { await openInteraction(id) } else { await home.load() }
            case .manageBusinesses:
                selectedTab = .connect
            case .accountHelp:
                selectedTab = .settings
            }
        case .interaction(let id):
            await openInteraction(id)
        case .conversation(let id):
            conversationToOpen = id
            selectedTab = .messages
        case .settings:
            selectedTab = .settings
        }
    }

    /// Presents the secure approval sheet for an interaction.
    public func openInteraction(_ id: InteractionID) async {
        guard !isLocked else { enqueueWhileLocked(.interaction(id)); return }
        guard phase == .ready || phase == .needsReenrollment else { queuedLink = .interaction(id); return }
        guard let envelope = try? await services.api.interaction(id) else {
            toast = "We couldn't load that request."
            return
        }
        let record = try? await services.records.load()
        let model = ApprovalViewModel(envelope: envelope, device: record, services: services)
        model.onFinished = { [weak self] outcome in
            guard let self else { return }
            self.home.didDecide(outcome.interactionId)
            Task {
                await self.home.load()
                await self.activity.load()
            }
        }
        model.onKeyInvalidated = { [weak self] in self?.phase = .needsReenrollment }
        presentedApproval = model
    }

    /// Applies the result of an action performed from a notification.
    public func apply(_ outcome: NotificationOutcome) async {
        if isLocked {
            // Opens wait for the unlock; refreshes and toasts would only touch hidden state, so they wait too.
            switch outcome {
            case .requiresApp(let id), .open(let id?): enqueueWhileLocked(.interaction(id))
            default: break
            }
            return
        }
        switch outcome {
        case .requiresApp(let id): await openInteraction(id)
        case .open(let id?): await openInteraction(id)
        case .open(nil):
            // A security push ("Review") carries no subject: the notices are fetched when the app opens.
            selectedTab = .home
            await securityNotices.load()
        case .submitted: await home.load()
        case .stale: toast = "That was already handled."; await home.load()
        case .expired: toast = "That request expired."; await home.load()
        case .failed(_, let message): toast = message
        case .ignored: break
        }
    }

    // MARK: Account

    public func signOut() async {
        await services.account.signOut()
        reset()
    }

    /// The server no longer trusts this device: erase everything and start over.
    public func deviceWasRevoked() async {
        guard !wiping else { return }
        wiping = true
        defer { wiping = false }
        await services.account.wipeLocalState()
        reset()
        toast = "This device was removed from your account."
        // Re-arm so a later enrollment can report a revocation again.
        services.revocation.setHandler { [weak self] in
            Task { @MainActor in await self?.deviceWasRevoked() }
        }
    }

    public func deleteAccount() async throws {
        try await services.account.deleteAccount()
        reset()
    }

    public func reenroll(deviceName: String) async throws {
        _ = try await services.account.reenrollThisDevice(name: deviceName, explain: passkeyGate.explainer)
        phase = .ready
        await home.load()
    }

    private var wiping = false

    private func reset() {
        presentedApproval = nil
        pendingConnect = nil
        pendingAccountLinkToken = nil
        conversationToOpen = nil
        businessToOpen = nil
        lockedQueue.removeAll()
        queuedLink = nil
        keysNeedRecheck = false
        selectedTab = .home
        isLocked = false
        phase = .onboarding(.welcome)
    }
}
