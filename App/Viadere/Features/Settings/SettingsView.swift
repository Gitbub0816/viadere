import SwiftUI
import UIKit
import ViadereCore
import ViadereKit

enum SettingsRoute: Hashable {
    case devices, phones, consents, sessions, household, acknowledgments, recovery, authenticator, verifications, approvals
}

/// Security and account: devices, app lock, linked phones, consent history, sessions, sign out, delete.
struct SettingsView: View {
    @Bindable var model: AppModel
    @State private var vm: SecuritySettingsViewModel
    @State private var household: HouseholdViewModel
    @State private var acknowledgments: AcknowledgmentsViewModel
    @State private var path: [SettingsRoute] = []
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

    var body: some View {
        NavigationStack(path: $path) {
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    ViadereHeader("Settings")
                    thisDevice
                    securitySection
                    trustSection
                    notificationsSection
                    accountSection
                    footer
                }
                .padding(.horizontal, ViadereSpace.screen)
                .padding(.bottom, ViadereSpace.xl)
            }
            .scrollIndicators(.hidden)
            .viadereScreenBackground()
            .toolbar(.hidden, for: .navigationBar)
            .navigationDestination(for: SettingsRoute.self) { route in
                switch route {
                case .devices: DevicesView(vm: vm)
                case .phones: PhonesView(vm: vm)
                case .consents: ConsentHistoryView(vm: vm)
                case .sessions: SessionsView(vm: vm)
                case .household: HouseholdView(vm: household)
                case .acknowledgments: AcknowledgmentsView(vm: acknowledgments)
                case .recovery: RecoveryCodesSettingsView(vm: vm)
                case .authenticator: AuthenticatorView(backTitle: "Settings")
                case .approvals: ApproveSettingsView(controller: AppEnvironment.shared.approve, model: model)
                case .verifications: VerificationHistoryView(api: AppEnvironment.shared.verifyAPI, center: AppEnvironment.shared.verification)
                }
            }
            .task {
                if model.pendingApproveEnrollment != nil { path = [.approvals] }
                openDevicesIfRequested()
                await vm.load()
                device = try? await model.services.records.load()
                await household.load()
                await acknowledgments.load()
            }
        }
        .onChange(of: model.reviewDevicesRequested) { _, _ in openDevicesIfRequested() }
        .onChange(of: model.pendingApproveEnrollment) { _, pending in
            if pending != nil, path.last != .approvals { path = [.approvals] }
        }
        .sheet(isPresented: Binding(get: { model.pendingAccountLinkToken != nil }, set: { if !$0 { model.pendingAccountLinkToken = nil } })) {
            if let token = model.pendingAccountLinkToken {
                AccountLinkSheet(vm: vm, token: token) { model.pendingAccountLinkToken = nil }
                    .presentationDetents([.medium])
                    .presentationBackground(ViadereColor.background)
            }
        }
    }

    /// "Review" on the Home security banner lands here, on the device list where anything unfamiliar can be removed.
    private func openDevicesIfRequested() {
        guard model.reviewDevicesRequested else { return }
        model.reviewDevicesRequested = false
        path = [.devices]
    }

    // MARK: Sections

    private var thisDevice: some View {
        VStack(alignment: .leading, spacing: 0) {
            ViadereSectionHeader("This iPhone")
            ViadereCard(padding: ViadereSpace.m) {
                HStack(spacing: ViadereSpace.m) {
                    ViadereIconTile(systemName: "iphone")
                    VStack(alignment: .leading, spacing: 2) {
                        Text(device?.name ?? "This iPhone").font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
                        Text(assuranceText).font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
                    }
                    Spacer()
                }
            }
            if let until = vm.thisDeviceLockedUntil {
                ViadereNotice("\(CoolDownPolicy.message(until: until, now: Date())) \(CoolDownPolicy.stillAvailable)", kind: .info)
                    .padding(.top, ViadereSpace.s)
            }
        }
    }

    private var assuranceText: String {
        switch device?.maxAssurance {
        case .biometric?: "Approves with Face ID or Touch ID"
        case .devicePasscode?: "Approves with your passcode"
        case .none?: "Basic approvals only"
        case nil: "Checking…"
        }
    }

    private var securitySection: some View {
        VStack(alignment: .leading, spacing: 0) {
            ViadereSectionHeader("Security")
            ViadereRowGroup {
                Toggle(isOn: Binding(get: { vm.appLockEnabled }, set: { newValue in Task { await vm.setAppLock(newValue) } })) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("App lock").font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
                        Text("Require \(vm.appLockMethod) to open Viadere").font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                    }
                }
                .toggleStyle(.viadere)
                .padding(.vertical, ViadereSpace.xxs)
                ViadereHairline()
                Toggle(isOn: Binding(get: { vm.richPreviewsEnabled }, set: { newValue in Task { await vm.setRichPreviews(newValue) } })) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Details on the lock screen").font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
                        Text("Off: approval notifications say only who is asking. On: they also show the amount and place.")
                            .font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                    }
                }
                .toggleStyle(.viadere)
                .padding(.vertical, ViadereSpace.xxs)
                ViadereHairline()
                if vm.recoveryAvailable {
                    navRow("Recovery codes", subtitle: vm.recoveryStatusLine, symbol: "list.number", route: .recovery)
                    ViadereHairline(inset: 50)
                }
                navRow("Authenticator", subtitle: "Passkeys and one-time codes", symbol: "key.viewfinder", route: .authenticator)
                ViadereHairline(inset: 50)
                navRow("Approvals", subtitle: AppEnvironment.shared.approve.accountFrozen ? "Frozen" : "Payments and sign-ins you confirm", symbol: "checkmark.shield", route: .approvals)
                ViadereHairline(inset: 50)
                navRow("Trusted devices", subtitle: "\(vm.devices.filter { !$0.isRevoked }.count) active", symbol: "iphone.gen3", route: .devices)
                ViadereHairline(inset: 50)
                if vm.phonesAvailable {
                    navRow("Linked phones", subtitle: vm.phones.isEmpty ? "None" : "\(vm.phones.count) linked", symbol: "phone", route: .phones)
                    ViadereHairline(inset: 50)
                }
                navRow("Consent history", subtitle: "What you've allowed, and when", symbol: "checklist", route: .consents)
                ViadereHairline(inset: 50)
                navRow("Verification history", subtitle: "Age and ID checks, and what was shared", symbol: "person.badge.shield.checkmark", route: .verifications)
                if vm.sessionsAvailable {
                    ViadereHairline(inset: 50)
                    navRow("Signed-in sessions", subtitle: "\(vm.sessions.count) active", symbol: "person.crop.circle", route: .sessions)
                }
            }
        }
    }

    /// Household access and acknowledgment records. Each row hides itself if the server doesn't offer the feature yet.
    @ViewBuilder private var trustSection: some View {
        let showHousehold = household.phase != .unavailable
        let showRecords = acknowledgments.phase != .unavailable
        if showHousehold || showRecords {
            VStack(alignment: .leading, spacing: 0) {
                ViadereSectionHeader("Trust and records")
                ViadereRowGroup {
                    if showHousehold {
                        navRow("Household", subtitle: householdSubtitle, symbol: "person.2", route: .household)
                    }
                    if showHousehold, showRecords { ViadereHairline(inset: 50) }
                    if showRecords {
                        navRow("Acknowledgments", subtitle: "Policies and estimates you've read", symbol: "doc.text", route: .acknowledgments)
                    }
                }
            }
        }
    }

    private var householdSubtitle: String {
        let shared = household.activeGiven.count + household.activeReceived.count
        return shared == 0 ? "Share limited access with people you trust" : "\(shared) active"
    }

    private func navRow(_ title: String, subtitle: String, symbol: String, route: SettingsRoute) -> some View {
        Button { path.append(route) } label: {
            ViadereRow(title, subtitle: subtitle) { ViadereIconTile(systemName: symbol) }
        }
        .buttonStyle(.plain)
    }

    private var notificationsSection: some View {
        VStack(alignment: .leading, spacing: 0) {
            ViadereSectionHeader("Notifications")
            ViadereRowGroup {
                Button {
                    if let url = URL(string: UIApplication.openNotificationSettingsURLString) { UIApplication.shared.open(url) }
                } label: {
                    ViadereRow("Notification settings", subtitle: "Alerts, previews and Focus") { ViadereIconTile(systemName: "bell") }
                }
                .buttonStyle(.plain)
            }
            Text("Viadere only interrupts when action is required. Security requests can break through Focus; everything else stays quiet.")
                .font(ViadereType.footnote)
                .foregroundStyle(ViadereColor.textTertiary)
                .padding(.top, ViadereSpace.s)
        }
    }

    private var accountSection: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.s) {
            ViadereSectionHeader("Account")
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
        .padding(.top, ViadereSpace.s)
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

// MARK: - Sub screens

/// A pushed screen: back button, large header, scrolling content. Shared by Settings, Rewards, Activity and Household.
struct SubScreen<Content: View>: View {
    let title: String
    let subtitle: String?
    var backTitle: String = "Settings"
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
                            Button(vm.confirmingId == device.id.description ? "Confirming…" : "Confirm this device") { Task { await vm.confirm(device) } }
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
            Text("A device added recently can't approve high-risk requests for 24 hours, unless you confirm it here with Face ID on a device you already trust. Removing a device stops it from approving requests immediately.")
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
                ViadereNotice("Recovery in progress. It finishes \(CoolDownPolicy.timeText(pending.activatesAt, now: Date())) and would replace your passkey and sign out every device. If it wasn't you, cancel it now.", kind: .warning)
                Button(vm.isCancellingRecovery ? "Cancelling…" : "Recovery in progress — Cancel") { Task { await vm.cancelPendingRecoveries() } }
                    .buttonStyle(.viadere(.primary))
                    .disabled(vm.isCancellingRecovery || !vm.isTrustedDevice)
                    .accessibilityHint("Stops the account recovery that was started and makes its recovery codes stop working")
            }
            Text("Each code works once, together with your recovery ID. Generating new codes makes the old ones stop working. You'll confirm with your passkey, and the new codes are shown only once.")
                .font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
            if !vm.canRegenerateRecoveryCodes {
                ViadereNotice(SecurityNoticesViewModel.coolDownActionMessage, kind: .info)
            }
            Button(vm.isRegeneratingCodes ? "Working…" : "Generate new codes") { confirming = true }
                .buttonStyle(.viadere(.primary))
                .disabled(vm.isRegeneratingCodes || !vm.canRegenerateRecoveryCodes)
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
    @State private var raw = ""
    @State private var code = ""

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
            Text("Texting never approves anything. Sign-ins and purchases are always approved in the app with this iPhone.")
                .font(ViadereType.footnote).foregroundStyle(ViadereColor.textTertiary)
        }
    }

    @ViewBuilder private var addPhone: some View {
        switch vm.addPhoneStage {
        case .idle, .failed:
            if case .failed(let message) = vm.addPhoneStage { ViadereNotice(message, kind: .danger) }
            ViadereTextField("Add a mobile number", text: $raw, prompt: "(480) 555-0123")
                .keyboardType(.phonePad)
                .textContentType(.telephoneNumber)
                .onChange(of: raw) { _, new in raw = PhoneInput.displayFormat(new) }
            Button("Send code") { Task { await vm.startAddPhone(raw) } }
                .buttonStyle(.viadere(.primary))
                .disabled(PhoneInput.normalize(raw) == nil)
        case .awaitingCode:
            Text("Enter the code we texted you").font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
            ViadereOTPField(code: $code)
                .onChange(of: code) { _, new in code = OTPInput.normalize(new) }
            HStack(spacing: ViadereSpace.s) {
                Button("Cancel") { vm.cancelAddPhone(); code = "" }.buttonStyle(.viadere(.secondary))
                Button("Verify") { Task { await vm.verifyAddPhone(code: code); code = ""; raw = "" } }
                    .buttonStyle(.viadere(.primary))
                    .disabled(!OTPInput.isComplete(code))
            }
        }
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
        }
    }
}

/// `https://viadere.com/l/{token}`: finish linking a phone that texted Viadere.
///
/// Anyone can send you such a link, and opening it while signed in used to link their number to *your* account.
/// So this screen first asks the server what the link would link, shows the masked number, spells out the risk,
/// and links only after an explicit "This is my phone". The token itself is never shown.
struct AccountLinkSheet: View {
    let vm: SecuritySettingsViewModel
    let token: String
    let onDone: () -> Void
    @State private var confirmedOwnPhone = false
    @State private var failed = false
    @State private var working = false
    /// Set after a successful link: says when the number starts working.
    @State private var linkedMessage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.l) {
            ViadereGrabber()
            Text(linkedMessage == nil ? "Link this phone" : "Phone linked").font(ViadereType.display).foregroundStyle(ViadereColor.textPrimary)
            content
            Spacer()
            footer
        }
        .padding(.horizontal, ViadereSpace.screen)
        .padding(.bottom, ViadereSpace.m)
        .task { await vm.loadAccountLinkPreview(token: token) }
        .onDisappear { vm.resetAccountLink() }
    }

    @ViewBuilder private var content: some View {
        if let linkedMessage {
            Text(linkedMessage).font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
            if let phone = vm.lastLinkedPhone, let until = phone.usableFrom {
                ViadereRowGroup { ViadereValueRow("Starts working", CoolDownPolicy.timeText(until, now: Date()), emphasized: true) }
            }
        } else {
        switch vm.accountLinkPhase {
        case .idle, .loading:
            HStack { Spacer(); ViadereLoading(); Spacer() }.padding(.vertical, ViadereSpace.xl)
        case .failed(let message):
            ViadereNotice(message, kind: .danger)
        case .ready(let preview):
            Text("A text from this number asked to link it to your Viadere account.")
                .font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
            ViadereRowGroup {
                ViadereValueRow("Phone number", preview.maskedPhone, emphasized: true)
                ViadereHairline()
                ViadereValueRow("Link expires", preview.expiresAt.formatted(date: .omitted, time: .shortened))
            }
            ViadereNotice(SecuritySettingsViewModel.accountLinkWarning, kind: .warning)
            ViadereRowGroup {
                Toggle(isOn: $confirmedOwnPhone) {
                    Text("This is my phone").font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
                }
                .toggleStyle(.viadere)
                .padding(.vertical, ViadereSpace.xxs)
            }
            if failed { ViadereNotice(vm.errorMessage ?? "We couldn't link that number.", kind: .danger) }
        }
        }
    }

    @ViewBuilder private var footer: some View {
        if linkedMessage != nil {
            if let phone = vm.lastLinkedPhone, vm.canConfirm(phone) {
                Button("Confirm now with Face ID") {
                    Task {
                        await vm.confirm(phone)
                        if vm.lastLinkedPhone.map({ !vm.canConfirm($0) }) ?? true, vm.errorMessage == nil { onDone() }
                    }
                }
                .buttonStyle(.viadere(.primary))
            }
            Button("Done", action: onDone).buttonStyle(.viadere(.quiet))
        } else if case .ready = vm.accountLinkPhase {
            Button(working ? "Linking…" : "Link phone") {
                Task {
                    working = true
                    failed = !(await vm.redeemAccountLink(token: token, confirmedOwnPhone: confirmedOwnPhone))
                    working = false
                    if !failed { linkedMessage = vm.accountLinkResultMessage ?? "Your phone is linked." }
                }
            }
            .buttonStyle(.viadere(.primary))
            .disabled(!confirmedOwnPhone || working)
            Button("This isn't my phone", action: onDone).buttonStyle(.viadere(.quiet))
        } else {
            Button("Close", action: onDone).buttonStyle(.viadere(.quiet))
        }
    }
}

#if DEBUG
#Preview("Settings") {
    PreviewHost { services in SettingsView(model: AppModel(services: services)) }
}
#endif
