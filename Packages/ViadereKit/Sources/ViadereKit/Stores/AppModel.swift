import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

public enum AppTab: String, CaseIterable, Sendable, Hashable { case home, connect, messages, settings }

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
    public private(set) var isLocked = false

    public let services: ViadereServices
    public let home: HomeViewModel
    public let messages: MessagesViewModel
    private var queuedLink: DeepLink?
    private var backgroundedAt: Date?
    private var isColdLaunch = true

    public init(services: ViadereServices) {
        self.services = services
        home = HomeViewModel(services: services)
        messages = MessagesViewModel(services: services)
    }

    // MARK: Launch

    public func bootstrap() async {
        let hasSession = await services.sessions.isSignedIn
        let record = try? await services.records.load()
        let complete = services.preferences.bool(.onboardingComplete)
        guard hasSession, complete else {
            phase = .onboarding(OnboardingFlow.resume(hasSession: hasSession, hasDevice: record != nil,
                                                      primingShown: services.preferences.bool(.notificationPrimingShown), complete: complete))
            return
        }
        switch await services.account.health() {
        case .healthy:
            phase = .ready
        case .needsReenrollment, .notEnrolled:
            phase = .needsReenrollment
        }
        if AppLockPolicy(enabled: services.preferences.bool(.appLockEnabled)).shouldLock(backgroundedAt: nil, now: services.clock(), isColdLaunch: isColdLaunch) {
            isLocked = true
        }
        isColdLaunch = false
        if phase == .ready {
            await home.load()
            if let link = queuedLink { queuedLink = nil; await handle(link) }
        }
    }

    public func completeOnboarding() async {
        phase = .ready
        await home.load()
        if let link = queuedLink { queuedLink = nil; await handle(link) }
    }

    // MARK: App lock & scene phases

    public func sceneDidEnterBackground() { backgroundedAt = services.clock() }

    public func sceneWillEnterForeground() async {
        let policy = AppLockPolicy(enabled: services.preferences.bool(.appLockEnabled))
        if phase == .ready, policy.shouldLock(backgroundedAt: backgroundedAt, now: services.clock(), isColdLaunch: false) { isLocked = true }
        backgroundedAt = nil
        if phase == .ready { await home.load() }
    }

    public func unlock() async {
        let ok = await services.appLock.authenticate(reason: "Unlock Viadere")
        if ok { isLocked = false }
    }

    // MARK: Deep links & notifications

    public func open(url: URL) async {
        guard let link = DeepLinkRouter.route(url) else { return }
        await handle(link)
    }

    public func handle(_ link: DeepLink) async {
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
            Task { await self.home.load() }
        }
        model.onKeyInvalidated = { [weak self] in self?.phase = .needsReenrollment }
        presentedApproval = model
    }

    /// Applies the result of an action performed from a notification.
    public func apply(_ outcome: NotificationOutcome) async {
        switch outcome {
        case .requiresApp(let id): await openInteraction(id)
        case .open(let id?): await openInteraction(id)
        case .open(nil): selectedTab = .home
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
        await services.account.wipeLocalState()
        reset()
        toast = "This device was removed from your account."
    }

    public func deleteAccount() async throws {
        try await services.account.deleteAccount()
        reset()
    }

    public func reenroll(deviceName: String) async throws {
        _ = try await services.account.reenrollThisDevice(name: deviceName)
        phase = .ready
        await home.load()
    }

    private func reset() {
        presentedApproval = nil
        pendingConnect = nil
        selectedTab = .home
        isLocked = false
        phase = .onboarding(.welcome)
    }
}
