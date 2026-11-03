import SwiftUI
import UIKit
import ViadereCore
import ViadereKit

/// Where the You tab can go: a settings screen, or a business's settings (from Notifications → Business by business).
enum YouRoute: Hashable {
    case settings(SettingsDestination)
    case business(BusinessID)
}

/// The You tab (docs/APP-IA.md): the account in one place. A security summary first, then searchable groups (Account, Security,
/// Notifications, Privacy and sharing, Records, Appearance), then sign out and delete. Each row says its current state, so most questions
/// are answered without opening anything; the screens behind the rows hold the controls. Rows for features the server does not offer
/// are hidden, never shown broken.
struct SettingsView: View {
    @Bindable var model: AppModel
    @State private var vm: SecuritySettingsViewModel
    @State private var household: HouseholdViewModel
    @State private var acknowledgments: AcknowledgmentsViewModel
    @State private var path: [YouRoute] = []
    @State private var query = ""
    @State private var confirmingSignOut = false
    @State private var confirmingDelete = false
    @State private var deleteError: String?
    @State private var device: DeviceRecord?

    init(model: AppModel) {
        self.model = model
        _vm = State(initialValue: SecuritySettingsViewModel(services: model.services))
        _household = State(initialValue: HouseholdViewModel(services: model.services))
        _acknowledgments = State(initialValue: AcknowledgmentsViewModel(services: model.services))
    }

    private var approve: ApproveController { AppEnvironment.shared.approve }

    private var availability: SettingsAvailability {
        SettingsAvailability(recovery: vm.recoveryAvailable, phones: vm.phonesAvailable, sessions: vm.sessionsAvailable,
                             household: household.phase != .unavailable, acknowledgments: acknowledgments.phase != .unavailable,
                             loops: model.services.loopsAPI != nil)
    }

    var body: some View {
        NavigationStack(path: $path) {
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    ViadereHeader("You", subtitle: device?.name ?? "Your account, security and preferences")
                    ViadereSearchField("Search settings", text: $query)
                        .padding(.bottom, ViadereSpace.s)
                    if query.trimmingCharacters(in: .whitespaces).isEmpty {
                        overview
                    } else {
                        searchResults
                    }
                }
                .padding(.horizontal, ViadereSpace.screen)
                .padding(.bottom, ViadereSpace.xl)
                .animation(ViadereMotion.quick, value: query.isEmpty)
            }
            .scrollIndicators(.hidden)
            .scrollDismissesKeyboard(.interactively)
            .viadereScreenBackground()
            .toolbar(.hidden, for: .navigationBar)
            .refreshable { await reload() }
            .navigationDestination(for: YouRoute.self) { route in
                switch route {
                case .settings(let destination): screen(destination)
                case .business(let id): businessSettings(id)
                }
            }
            .task {
                if model.pendingApproveEnrollment != nil { path = [.settings(.approvals)] }
                openDevicesIfRequested()
                await reload()
            }
        }
        .onChange(of: model.reviewDevicesRequested) { _, _ in openDevicesIfRequested() }
        .onChange(of: model.pendingApproveEnrollment) { _, pending in
            if pending != nil, path.last != .settings(.approvals) { path = [.settings(.approvals)] }
        }
    }

    private func reload() async {
        await vm.load()
        device = try? await model.services.records.load()
        await household.load()
        await acknowledgments.load()
    }

    /// "Review" on a security notice lands on the device list, where anything unfamiliar can be removed.
    private func openDevicesIfRequested() {
        guard model.reviewDevicesRequested else { return }
        model.reviewDevicesRequested = false
        path = [.settings(.devices)]
    }

    // MARK: Destinations

    @ViewBuilder private func screen(_ destination: SettingsDestination) -> some View {
        switch destination {
        case .profile: ProfileView(api: AppEnvironment.shared.profileAPI)
        case .household: HouseholdView(vm: household)
        case .phones: PhonesView(vm: vm)
        case .sessions: SessionsView(vm: vm)
        case .approvals: ApproveSettingsView(controller: approve, model: model)
        case .devices: DevicesView(vm: vm)
        case .authenticator: AuthenticatorView(backTitle: "You")
        case .recovery: RecoveryCodesSettingsView(vm: vm)
        case .notifications, .lockScreenDetails, .businessNotifications:
            NotificationSettingsView(model: model, vm: vm) { id in path.append(.business(id)) }
        case .loops: LoopSettingsView(model: model)
        case .profileReceipts: ProfileReceiptsView(api: AppEnvironment.shared.profileAPI)
        case .consents: ConsentHistoryView(vm: vm)
        case .verifications: VerificationHistoryView(api: AppEnvironment.shared.verifyAPI, center: AppEnvironment.shared.verification)
        case .acknowledgments: AcknowledgmentsView(vm: acknowledgments)
        case .dataExport: DataExportView(services: model.services)
        case .appearance: AppearanceSettingsSlot(model: model)
        case .appLock: SubScreen(title: "App lock", subtitle: nil) { appLockRow }
        }
    }

    @ViewBuilder private func businessSettings(_ id: BusinessID) -> some View {
        if let entry = model.businesses.entry(id), entry.isActive {
            BusinessDetailView(relationship: entry.relationship, model: model)
        } else {
            SubScreen(title: "Not available", subtitle: "You're no longer connected to this business.") { EmptyView() }
        }
    }

    // MARK: Overview

    @ViewBuilder private var overview: some View {
        securitySummary
        ForEach(SettingsGroup.allCases, id: \.self) { group in
            let rows = SettingsCatalog.rows(in: group, available: availability)
            if !rows.isEmpty {
                VStack(alignment: .leading, spacing: 0) {
                    ViadereSectionHeader(group.title)
                    ViadereRowGroup {
                        ForEach(Array(rows.enumerated()), id: \.element) { index, destination in
                            row(destination)
                            if index < rows.count - 1 { ViadereHairline(inset: 50) }
                        }
                    }
                    if group == .notifications {
                        Text("Viadere only interrupts when action is required. Security requests can break through Focus; everything else stays quiet.")
                            .font(ViadereType.footnote)
                            .foregroundStyle(ViadereColor.textTertiary)
                            .padding(.top, ViadereSpace.s)
                    }
                }
            }
        }
        accountSection
        footer
    }

    /// How well the account is protected, in one line (the weakest fact wins), with any account notice under it.
    private var securitySummary: some View {
        let posture = SecurityPosture.summarize(assurance: device?.maxAssurance, appLock: vm.appLockEnabled,
                                                activeDevices: vm.devices.filter { !$0.isRevoked }.count,
                                                recoveryRemaining: vm.recoveryAvailable ? vm.recoveryInfo?.remainingCodes : nil,
                                                approvalsFrozen: approve.isAvailable && approve.accountFrozen)
        return VStack(alignment: .leading, spacing: ViadereSpace.s) {
            Button {
                path.append(.settings(posture.headline == "Create recovery codes" ? .recovery : (posture.headline == "Approvals are frozen" ? .approvals : .devices)))
            } label: {
                ViadereSummaryCard(symbol: "lock", headline: posture.headline, detail: posture.detail, status: status(posture.level), showsChevron: true)
            }
            .buttonStyle(.plain)
            .accessibilityHint(Text("Opens the setting this summary is about"))
            if let notice = model.securityNotices.current {
                SecurityNoticeBanner(vm: model.securityNotices, notice: notice) { path = [.settings(.devices)] }
            }
            if let notice = vm.thisDeviceTrustNotice {
                ViadereNotice("\(notice) \(CoolDownPolicy.stillAvailable)", kind: .info)
            }
        }
        .padding(.top, ViadereSpace.xs)
    }

    private func status(_ level: SecurityPosture.Level) -> ViadereSummaryCard.Status {
        switch level {
        case .strong: .positive
        case .good: .neutral
        case .needsAttention: .attention
        }
    }

    @ViewBuilder private func row(_ destination: SettingsDestination) -> some View {
        if destination == .appLock {
            appLockRow
        } else {
            Button { path.append(.settings(destination.screen ?? destination)) } label: {
                ViadereRow(destination.title, subtitle: summary(destination)) { ViadereIconTile(systemName: destination.symbol) }
            }
            .buttonStyle(.plain)
        }
    }

    /// App lock stays a switch: one binary, and the switch is the clearest way to show it.
    private var appLockRow: some View {
        HStack(spacing: 14) {
            ViadereIconTile(systemName: SettingsDestination.appLock.symbol)
            Toggle(isOn: Binding(get: { vm.appLockEnabled }, set: { newValue in Task { await vm.setAppLock(newValue) } })) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("App lock").font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
                    Text("Require \(vm.appLockMethod) to open Viadere").font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
                }
            }
            .toggleStyle(.viadere)
        }
        .padding(.vertical, ViadereSpace.s)
        .frame(minHeight: 56)
    }

    /// The row's live second line: the state, not a description, wherever the state is known.
    private func summary(_ destination: SettingsDestination) -> String {
        switch destination {
        case .household:
            let shared = household.activeGiven.count + household.activeReceived.count
            return shared == 0 ? destination.detail : "\(shared) active"
        case .phones: return vm.phones.isEmpty ? "None linked" : (vm.phones.count == 1 ? "1 linked" : "\(vm.phones.count) linked")
        case .sessions: return vm.sessions.count == 1 ? "1 active" : "\(vm.sessions.count) active"
        case .approvals:
            guard approve.isAvailable else { return destination.detail }
            return approve.accountFrozen ? "Frozen: no business can ask" : destination.detail
        case .devices:
            let count = vm.devices.filter { !$0.isRevoked }.count
            return count == 1 ? "1 active" : "\(count) active"
        case .recovery: return vm.recoveryStatusLine
        case .notifications:
            let now = model.services.clock()
            let quieted = model.businesses.quietedCount(at: now, accountDefault: model.notificationSettings.settings.defaultLevel)
            let lock = vm.richPreviewsEnabled ? "Full details on the lock screen" : "Name only on the lock screen"
            let base = quieted == 0 ? lock : "\(lock) · \(quieted) quieted"
            return model.notificationSettings.quietHoursEnabled ? "\(base) · Quiet hours" : base
        case .loops: return model.loopConsent.isEnabled ? "On" : "Off"
        default: return destination.detail
        }
    }

    // MARK: Search

    @ViewBuilder private var searchResults: some View {
        let results = SettingsCatalog.search(query, available: availability)
        if results.isEmpty {
            Text("No setting matches \u{201C}\(query)\u{201D}.")
                .font(ViadereType.body)
                .foregroundStyle(ViadereColor.textSecondary)
                .padding(.top, ViadereSpace.m)
        } else {
            ViadereRowGroup {
                ForEach(Array(results.enumerated()), id: \.element) { index, destination in
                    if destination == .appLock {
                        appLockRow
                    } else {
                        Button { path.append(.settings(destination.screen ?? destination)) } label: {
                            ViadereRow(destination.title, subtitle: "\(destination.group.title) · \(destination.detail)") {
                                ViadereIconTile(systemName: destination.symbol)
                            }
                        }
                        .buttonStyle(.plain)
                    }
                    if index < results.count - 1 { ViadereHairline(inset: 50) }
                }
            }
            .padding(.top, ViadereSpace.xs)
        }
    }

    // MARK: Account

    private var accountSection: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.s) {
            ViadereSectionHeader("Sign out or leave")
            if confirmingSignOut {
                confirmCard(title: "Sign out of Viadere?",
                            message: "This erases Viadere's keys and sign-in from this iPhone. Your account and connections stay.",
                            action: "Sign out", destructive: false) { Task { await model.signOut() } } cancel: { confirmingSignOut = false }
            } else {
                Button("Sign out") { withAnimation(ViadereMotion.standard) { confirmingSignOut = true } }.buttonStyle(.viadere(.secondary))
            }
            if confirmingDelete {
                confirmCard(title: "Delete your account?",
                            message: "This permanently removes your account, connections and history, and erases this iPhone. It can't be undone.",
                            action: "Delete account", destructive: true) {
                    Task {
                        do { try await model.deleteAccount() } catch {
                            deleteError = (error as? APIError)?.userMessage ?? "We couldn't delete your account. Please try again."
                        }
                    }
                } cancel: { confirmingDelete = false }
                if let deleteError { ViadereNotice(deleteError, kind: .danger) }
            } else {
                Button("Delete account") { withAnimation(ViadereMotion.standard) { confirmingDelete = true } }.buttonStyle(.viadere(.destructive))
            }
        }
    }

    private func confirmCard(title: String, message: String, action: String, destructive: Bool,
                             onConfirm: @escaping () -> Void, cancel: @escaping () -> Void) -> some View {
        ViadereCard(padding: ViadereSpace.m) {
            VStack(alignment: .leading, spacing: ViadereSpace.s) {
                Text(title).font(ViadereType.headline).foregroundStyle(ViadereColor.textPrimary)
                Text(message).font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
                HStack(spacing: ViadereSpace.s) {
                    Button("Cancel", action: cancel).buttonStyle(.viadere(.secondary))
                    Button(action, action: onConfirm).buttonStyle(.viadere(destructive ? .destructive : .primary))
                }
            }
        }
    }

    private var footer: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.xs) {
            Text("Viadere never asks you to approve anything by text message.")
                .font(ViadereType.footnote).foregroundStyle(ViadereColor.textTertiary)
            Text("Version \(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0")")
                .font(ViadereType.footnote).foregroundStyle(ViadereColor.textTertiary)
        }
        .padding(.top, ViadereSpace.xl)
    }
}

// MARK: - Notifications

/// You → Notifications: what approval notifications show on the lock screen (two choice cards instead of a switch), how loudly each
/// business may interrupt (a level per business, opened in place), requests built by businesses, and the iOS settings for sounds and
/// Focus. Security checks and requests that need an answer always come through, whatever is chosen here.
struct NotificationSettingsView: View {
    let model: AppModel
    let vm: SecuritySettingsViewModel
    let openBusiness: (BusinessID) -> Void
    @State private var expanded: BusinessID? = nil

    var body: some View {
        SubScreen(title: "Notifications", subtitle: "Viadere only interrupts when action is required.") {
            VStack(alignment: .leading, spacing: 0) {
                ViadereSectionHeader("On the lock screen")
                ViadereChoiceCards("Approval notifications on the lock screen",
                                   selection: Binding(get: { vm.richPreviewsEnabled }, set: { value in Task { await vm.setRichPreviews(value) } }),
                                   options: [
                                       .init(false, "Who's asking", detail: "Approval notifications name only the business. Open them to see the amount and place.",
                                             symbol: "eye.slash"),
                                       .init(true, "Who, amount and place", detail: "Decide faster from the notification. Anyone who can see your phone sees the details too.",
                                             symbol: "text.viewfinder"),
                                   ])
            }
            accountLevel
            quietHours
            businessLevels
            VStack(alignment: .leading, spacing: 0) {
                ViadereSectionHeader("More")
                ViadereRowGroup {
                    if model.services.loopsAPI != nil {
                        NavigationLink(value: YouRoute.settings(.loops)) {
                            ViadereRow(SettingsDestination.loops.title, subtitle: model.loopConsent.isEnabled ? "On" : "Off") {
                                ViadereIconTile(systemName: SettingsDestination.loops.symbol)
                            }
                        }
                        .buttonStyle(.plain)
                        ViadereHairline(inset: 50)
                    }
                    Button {
                        if let url = URL(string: UIApplication.openNotificationSettingsURLString) { UIApplication.shared.open(url) }
                    } label: {
                        ViadereRow("Sounds, banners and Focus", subtitle: "In the iPhone's Settings app") {
                            ViadereIconTile(systemName: "gear")
                        } trailing: {
                            Image(systemName: "arrow.up.right")
                                .font(.system(size: 13, weight: .semibold))
                                .foregroundStyle(ViadereColor.textTertiary)
                                .accessibilityHidden(true)
                        }
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }

    /// The level every business without its own setting follows: the same three named levels as a business, in one card.
    @ViewBuilder private var accountLevel: some View {
        let settings = model.notificationSettings
        VStack(alignment: .leading, spacing: 0) {
            ViadereSectionHeader("For all businesses")
            ViadereCard(padding: ViadereSpace.m) {
                ViadereLevelPicker("Default level for all businesses",
                                   selection: Binding(get: { settings.preset }, set: { value in Task { await settings.setPreset(value) } }),
                                   levels: InterruptionPreset.levels,
                                   caption: settings.levelCaption)
                    .disabled(settings.isSaving)
            }
            if let error = settings.errorMessage { ViadereNotice(error, kind: .warning).padding(.top, ViadereSpace.s) }
        }
    }

    /// Quiet hours: two named choices (not a switch), then the two times. Only security interrupts inside the window.
    @ViewBuilder private var quietHours: some View {
        let settings = model.notificationSettings
        VStack(alignment: .leading, spacing: 0) {
            ViadereSectionHeader("Quiet hours")
            ViadereChoiceCards("Quiet hours",
                               selection: Binding(get: { settings.quietHoursEnabled }, set: { value in Task { await settings.setQuietHours(enabled: value) } }),
                               options: [
                                   .init(false, "Off", detail: "Notifications follow your levels at every hour.", symbol: "sun.max"),
                                   .init(true, "Every day", detail: "Between two times only security interrupts you.", symbol: "moon"),
                               ])
                .disabled(settings.isSaving)
            if settings.quietHoursEnabled {
                ViadereCard(padding: ViadereSpace.m) {
                    VStack(alignment: .leading, spacing: ViadereSpace.xs) {
                        DatePicker("From", selection: Binding(get: { NotificationSettingsViewModel.date(minute: settings.startMinute) },
                                                              set: { value in Task { await settings.setQuietHours(startMinute: NotificationSettingsViewModel.minute(of: value), endMinute: settings.endMinute) } }),
                                   displayedComponents: .hourAndMinute)
                            .font(ViadereType.body)
                            .foregroundStyle(ViadereColor.textPrimary)
                        ViadereHairline()
                        DatePicker("Until", selection: Binding(get: { NotificationSettingsViewModel.date(minute: settings.endMinute) },
                                                               set: { value in Task { await settings.setQuietHours(startMinute: settings.startMinute, endMinute: NotificationSettingsViewModel.minute(of: value)) } }),
                                   displayedComponents: .hourAndMinute)
                            .font(ViadereType.body)
                            .foregroundStyle(ViadereColor.textPrimary)
                    }
                    .disabled(settings.isSaving)
                }
                .padding(.top, ViadereSpace.xs)
            }
            Text(settings.quietHoursCaption + " " + NotificationSettingsViewModel.securityNote)
                .font(ViadereType.footnote)
                .foregroundStyle(ViadereColor.textTertiary)
                .padding(.top, ViadereSpace.s)
        }
        .task { await settings.syncTimeZone() }
    }

    /// Every connected business with its level; tapping one opens its level picker in place (one at a time).
    @ViewBuilder private var businessLevels: some View {
        let entries = model.businesses.active
        VStack(alignment: .leading, spacing: 0) {
            ViadereSectionHeader("Business by business")
            if entries.isEmpty {
                Text("Businesses you connect to appear here.").font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
            } else {
                ViadereRowGroup {
                    ForEach(Array(entries.enumerated()), id: \.element.id) { index, entry in
                        businessRow(entry)
                        if index < entries.count - 1 { ViadereHairline(inset: 50) }
                    }
                }
                if let error = model.businesses.errorMessage { ViadereNotice(error, kind: .warning).padding(.top, ViadereSpace.s) }
                Text("Security checks and requests that need your answer always come through. Everything still appears in Alerts.")
                    .font(ViadereType.footnote)
                    .foregroundStyle(ViadereColor.textTertiary)
                    .padding(.top, ViadereSpace.s)
            }
        }
    }

    @ViewBuilder private func businessRow(_ entry: ConnectedBusiness) -> some View {
        let now = model.services.clock()
        let accountDefault = model.notificationSettings.settings.defaultLevel
        let preset = entry.preferences.preset(accountDefault: accountDefault, at: now)
        let isOpen = expanded == entry.business.id
        VStack(alignment: .leading, spacing: ViadereSpace.s) {
            Button {
                withAnimation(ViadereMotion.standard) { expanded = isOpen ? nil : entry.business.id }
            } label: {
                ViadereRow(entry.business.safeName, subtitle: entry.preferences.levelSummary(accountDefault: accountDefault, at: now)) {
                    ViadereAvatar(name: entry.business.safeName, size: 36, isVerified: entry.business.isVerified)
                } trailing: {
                    HStack(spacing: ViadereSpace.xs) {
                        ViadereLevelMeter(filled: preset.intensity, total: 3, emphasized: preset != .everything)
                        Image(systemName: isOpen ? "chevron.up" : "chevron.down")
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundStyle(ViadereColor.textTertiary)
                            .accessibilityHidden(true)
                    }
                }
            }
            .buttonStyle(.plain)
            .accessibilityHint(Text(isOpen ? "Hides the levels" : "Shows the levels"))
            if isOpen {
                ViadereLevelPicker("Interruptions from \(entry.business.safeName)",
                                   selection: Binding(get: { preset },
                                                      set: { value in Task { await model.businesses.setMute(entry.business.id, value.muteLevel) } }),
                                   levels: InterruptionPreset.levels,
                                   caption: preset.explanation(business: entry.business.safeName),
                                   customizeTitle: "More for \(entry.business.safeName)") { openBusiness(entry.business.id) }
                    .padding(.bottom, ViadereSpace.s)
                    .transition(.opacity)
                if !entry.preferences.followsDefault(at: now) {
                    Button("Follow my default level") { Task { await model.businesses.followDefault(entry.business.id) } }
                        .buttonStyle(.viadere(.quiet))
                        .accessibilityHint(Text("Uses \(InterruptionPreset(accountDefault).title) for \(entry.business.safeName), like every business without its own setting"))
                }
            }
        }
    }
}

// MARK: - Sub screens

/// A pushed screen: back button, large header, scrolling content. Shared by You, Rewards, Activity and Household. The back button keeps
/// the edge swipe back working although the navigation bar is hidden.
struct SubScreen<Content: View>: View {
    let title: String
    let subtitle: String?
    var backTitle: String = "You"
    @ViewBuilder var content: Content
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: ViadereSpace.m) {
                ViadereBackButton(backTitle) { dismiss() }
                ViadereHeader(title, subtitle: subtitle)
                content
            }
            .padding(.horizontal, ViadereSpace.screen)
            .padding(.bottom, ViadereSpace.xl)
        }
        .scrollIndicators(.hidden)
        .viadereScreenBackground()
        .toolbar(.hidden, for: .navigationBar)
    }
}

struct DevicesView: View {
    let vm: SecuritySettingsViewModel
    @State private var confirming: DeviceID?

    var body: some View {
        SubScreen(title: "Trusted devices", subtitle: "Each approval is signed by a key inside one of these.") {
            if let error = vm.errorMessage { ViadereNotice(error, kind: .danger) }
            ViadereRowGroup {
                ForEach(Array(vm.devices.enumerated()), id: \.element.id) { index, device in
                    VStack(alignment: .leading, spacing: ViadereSpace.xs) {
                        ViadereRow(device.name, subtitle: subtitle(device),
                                   leading: { ViadereIconTile(systemName: device.platform == .watchOS ? "applewatch" : "iphone") },
                                   trailing: { badge(device) })
                        if let note = vm.coolDownNote(for: device) {
                            Text(note).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        if let state = vm.replacementState(for: device) {
                            Text(vm.replacementNote(for: state)).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                                .fixedSize(horizontal: false, vertical: true)
                            if vm.canCancelReplacement(device) {
                                Button("Not you? Cancel") { Task { await vm.cancelReplacement(device) } }
                                    .buttonStyle(.viadere(.secondary, fullWidth: false))
                            }
                        }
                        if vm.canConfirm(device) {
                            Button(vm.confirmingId == device.id.description ? "Approving…" : "Approve this device") { Task { await vm.confirm(device) } }
                                .buttonStyle(.viadere(.secondary, fullWidth: false))
                                .disabled(vm.confirmingId != nil)
                        }
                        if device.id != vm.currentDeviceId, !device.isRevoked {
                            if confirming == device.id {
                                HStack(spacing: ViadereSpace.s) {
                                    Button("Cancel") { confirming = nil }.buttonStyle(.viadere(.secondary))
                                    Button("Remove") { Task { await vm.revoke(device); confirming = nil } }.buttonStyle(.viadere(.destructive))
                                }
                                .padding(.bottom, ViadereSpace.s)
                            } else {
                                Button("Remove this device") { confirming = device.id }
                                    .buttonStyle(.viadere(.quiet, fullWidth: false))
                            }
                        }
                    }
                    if index < vm.devices.count - 1 { ViadereHairline() }
                }
            }
            Text("A new device can't approve high-risk requests until you approve it here with Face ID on a device you already trust. Waiting doesn't change that. Removing a device stops it from approving requests immediately.")
                .font(ViadereType.footnote).foregroundStyle(ViadereColor.textTertiary)
        }
    }

    private func subtitle(_ device: Device) -> String {
        let level: String
        switch device.maxAssurance {
        case .biometric: level = "Face ID"
        case .devicePasscode: level = "Passcode"
        case .none: level = "Basic"
        }
        let seen = (device.lastSeenAt ?? device.createdAt).formatted(date: .abbreviated, time: .omitted)
        return "\(device.platform.rawValue) · \(level) · seen \(seen)"
    }

    @ViewBuilder private func badge(_ device: Device) -> some View {
        if device.isRevoked { ViadereBadge("Removed", kind: .danger) }
        else if let state = vm.replacementState(for: device) { ViadereBadge(vm.replacementTitle(for: state), kind: .pending) }
        else if device.id == vm.currentDeviceId { ViadereBadge("This iPhone", kind: .success) }
        else { EmptyView() }
    }
}

/// Settings → Security → Recovery codes: how many are left, and "Generate new codes" (a trusted device and a fresh passkey assertion).
/// New codes are shown once, in the same screen as onboarding, and never stored.
struct RecoveryCodesSettingsView: View {
    @Bindable var vm: SecuritySettingsViewModel
    @State private var confirming = false

    var body: some View {
        SubScreen(title: "Recovery codes", subtitle: "The way back in if you lose every device.") {
            if let message = vm.recoveryMessage { ViadereNotice(message, kind: .danger) }
            ViadereRowGroup {
                ViadereValueRow("Unused codes", vm.recoveryInfo.map { "\($0.remainingCodes) of \(RecoveryPolicy.codeCount)" } ?? "…")
            }
            if vm.recoveryInfo?.remainingCodes == 0 {
                ViadereNotice("You have no unused codes. Generate a set so you can recover your account if you lose your devices.", kind: .warning)
            }
            if let pending = vm.pendingRecoveries.first {
                // Driven by `RecoveryInfo`, not by the Home notice: the way to stop a recovery you did not start is always here.
                ViadereNotice("Recovery in progress. It finishes \(CoolDownPolicy.timeText(pending.activatesAt, now: Date())) and would sign out every device. If it wasn't you, cancel it now.", kind: .warning)
                Button(vm.isCancellingRecovery ? "Cancelling…" : "Recovery in progress — Cancel") { Task { await vm.cancelPendingRecoveries() } }
                    .buttonStyle(.viadere(.primary))
                    .disabled(vm.isCancellingRecovery || !vm.isTrustedDevice)
                    .accessibilityHint("Stops the account recovery that was started and makes its recovery codes stop working")
            }
            Text("Each code works once, together with your recovery ID. Generating new codes makes the old ones stop working. You'll confirm with Face ID or your passcode on this iPhone, and the new codes are shown only once.")
                .font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
            if !vm.canRegenerateRecoveryCodes {
                ViadereNotice(SecurityNoticesViewModel.coolDownActionMessage, kind: .info)
            }
            Button(vm.isRegeneratingCodes ? "Working…" : "Generate new codes") { confirming = true }
                .buttonStyle(.viadere(.primary))
                .disabled(vm.isRegeneratingCodes || !vm.canRegenerateRecoveryCodes)
            if let note = vm.passkeyNote { ViadereNotice(note, kind: .warning) }
            if vm.canAddPasskey {
                Text("A passkey saved to iCloud Keychain lets a new iPhone find your account. It never approves anything on its own.")
                    .font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
                Button(vm.isAddingPasskey ? "Adding…" : "Add a passkey") { Task { await vm.addRecoveryPasskey() } }
                    .buttonStyle(.viadere(.secondary))
                    .disabled(vm.isAddingPasskey)
            }
        }
        .task { await vm.loadRecovery() }
        .confirmationDialog("Generate new codes?", isPresented: $confirming, titleVisibility: .visible) {
            Button("Generate new codes") { Task { await vm.regenerateRecoveryCodes() } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Your current codes will stop working.")
        }
        .fullScreenCover(isPresented: Binding(get: { vm.newRecoveryCodes != nil }, set: { if !$0 { vm.finishRecoveryCodes() } })) {
            if let codes = vm.newRecoveryCodes {
                RecoveryCodesView(model: codes, title: "Save your new recovery codes", continueTitle: "Done") {
                    if codes.finish() { vm.finishRecoveryCodes() }
                }
            }
        }
    }
}

struct PhonesView: View {
    @Bindable var vm: SecuritySettingsViewModel

    var body: some View {
        SubScreen(title: "Linked phones", subtitle: "Numbers that can reach your businesses by text.") {
            if let error = vm.errorMessage { ViadereNotice(error, kind: .danger) }
            if !vm.phones.isEmpty {
                ViadereRowGroup {
                    ForEach(Array(vm.phones.enumerated()), id: \.element.id) { index, phone in
                        VStack(alignment: .leading, spacing: ViadereSpace.xs) {
                            HStack {
                                ViadereRow(phone.maskedPhone, subtitle: vm.coolDownNote(for: phone) ?? "Verified \(phone.verifiedAt.formatted(date: .abbreviated, time: .omitted))",
                                           leading: { ViadereIconTile(systemName: "phone") }, trailing: { EmptyView() })
                                Button("Unlink") { Task { await vm.removePhone(phone) } }.buttonStyle(.viadere(.quiet, fullWidth: false))
                            }
                            if vm.canConfirm(phone) {
                                Button(vm.confirmingId == phone.id.description ? "Confirming…" : "Confirm this phone now") { Task { await vm.confirm(phone) } }
                                    .buttonStyle(.viadere(.secondary, fullWidth: false))
                                    .disabled(vm.confirmingId != nil)
                            }
                        }
                        if index < vm.phones.count - 1 { ViadereHairline() }
                    }
                }
            }
            addPhone
            Text("A number you link this way proves you control it, nothing more. Texting never approves anything: sign-ins and purchases are always approved in the app with this iPhone.")
                .font(ViadereType.footnote).foregroundStyle(ViadereColor.textTertiary)
        }
    }

    /// One text sent from the phone (ADR-0027): the app shows a nonce and opens the compose sheet; nothing is texted to the phone.
    @ViewBuilder private var addPhone: some View {
        PhoneLinkFlowView(vm: vm.addPhone)
    }
}

struct ConsentHistoryView: View {
    let vm: SecuritySettingsViewModel

    var body: some View {
        SubScreen(title: "Consent history", subtitle: "Every change, with the version of the wording you saw.") {
            if vm.consentHistory.isEmpty {
                ViadereEmptyState("Nothing yet", message: "Permissions you grant or change will be listed here.")
            } else {
                ViadereRowGroup {
                    ForEach(Array(vm.consentHistory.enumerated()), id: \.element.id) { index, item in
                        ViadereRow("\(item.businessName) · \(PermissionCopy.title(item.grant.purpose))",
                                   subtitle: "\(item.grant.granted ? "Allowed" : "Not allowed") · v\(item.grant.version) · \(item.grant.updatedAt.formatted(date: .abbreviated, time: .shortened)) · \(source(item.grant.source))",
                                   leading: { EmptyView() }, trailing: { EmptyView() })
                        if index < vm.consentHistory.count - 1 { ViadereHairline() }
                    }
                }
            }
        }
    }

    private func source(_ source: ConsentSource) -> String {
        switch source {
        case .app: "Viadere app"
        case .web: "Web"
        case .sms, .smsKeyword: "Text message"
        case .businessAPI: "Business"
        case .system: "System"
        }
    }
}

struct SessionsView: View {
    let vm: SecuritySettingsViewModel

    var body: some View {
        SubScreen(title: "Signed-in sessions", subtitle: "Where your Viadere account is signed in.") {
            ViadereRowGroup {
                ForEach(Array(vm.sessions.enumerated()), id: \.element.id) { index, session in
                    HStack {
                        ViadereRow(session.deviceName,
                                   subtitle: "Since \(session.createdAt.formatted(date: .abbreviated, time: .omitted))",
                                   leading: { ViadereIconTile(systemName: "person.crop.circle") },
                                   trailing: { session.isCurrent ? AnyView(ViadereBadge("This session", kind: .success)) : AnyView(EmptyView()) })
                        if !session.isCurrent {
                            Button("Sign out") { Task { await vm.revokeSession(session) } }.buttonStyle(.viadere(.quiet, fullWidth: false))
                        }
                    }
                    if index < vm.sessions.count - 1 { ViadereHairline() }
                }
            }
            // ADR-0024 §8: the consents the authority keeps for "Sign in with Viadere" (OIDC-09).
            ViadereRowGroup {
                NavigationLink {
                    OIDCConsentsView(api: AppEnvironment.services.oidc)
                } label: {
                    ViadereRow(OIDCCopy.listTitle) { ViadereIconTile(systemName: "person.crop.square") }
                }
                .buttonStyle(.plain)
            }
        }
    }
}

#if DEBUG
#Preview("Settings") {
    PreviewHost { services in SettingsView(model: AppModel(services: services)) }
}
#endif
