import SwiftUI
import StoreKit
import ViadereCore
import ViadereKit

struct ClipRootView: View {
    @Bindable var flow: ClipFlowModel
    @State private var showOverlay = false

    var body: some View {
        Group {
            ScrollView {
                VStack(alignment: .leading, spacing: ViadereSpace.l) {
                    ViadereLockup(.horizontal, ribbonHeight: 26).padding(.top, ViadereSpace.l)
                    content
                }
                .padding(.horizontal, ViadereSpace.screen)
                .padding(.bottom, ViadereSpace.xl)
            }
            .scrollIndicators(.hidden)
        }
        .viadereScreenBackground()
        .passkeyExplanation(flow.passkeyGate)
        .animation(ViadereMotion.gentle, value: flow.step)
        .animation(ViadereMotion.gentle, value: flow.connect.phase)
        .appStoreOverlay(isPresented: $showOverlay) { SKOverlay.AppClipConfiguration(position: .bottom) }
        .onChange(of: flow.step) { _, step in
            if case .done = step { showOverlay = true }
        }
    }

    @ViewBuilder private var content: some View {
        switch flow.step {
        case .account:
            accountStep
        case .working:
            ViadereLoading(height: 36).frame(maxWidth: .infinity).padding(.top, ViadereSpace.xxl)
        case .done(let name):
            VStack(alignment: .leading, spacing: ViadereSpace.m) {
                Image(systemName: "checkmark.circle").font(.system(size: 44, weight: .light)).foregroundStyle(ViadereColor.success)
                Text("Connected to \(name)").font(ViadereType.display).foregroundStyle(ViadereColor.textPrimary)
                Text("Get the Viadere app to approve sign-ins and purchases right from your notifications.")
                    .font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
            }
        case .idle:
            switch flow.connect.phase {
            case .review(let profile):
                ConnectReview(vm: flow.connect, profile: profile, onConnect: { Task { await flow.continueTapped() } })
            case .resolving, .connecting:
                ViadereLoading(height: 36).frame(maxWidth: .infinity).padding(.top, ViadereSpace.xxl)
            case .failed(let message):
                ViadereNotice(message, kind: .danger)
            default:
                VStack(alignment: .leading, spacing: ViadereSpace.s) {
                    Text("A trusted way to connect.").font(ViadereType.display).foregroundStyle(ViadereColor.textPrimary)
                    Text("Scan a Viadere QR code or open a Viadere link to connect to a verified business.")
                        .font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
                }
            }
        }
    }

    private var accountStep: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.m) {
            Text("Set up this iPhone").font(ViadereType.display).foregroundStyle(ViadereColor.textPrimary)
            Text("No name, email or phone number. This iPhone gets a key that lets it connect and receive messages for 7 days. It can't approve anything; the Viadere app does that.")
                .font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
            Text("Viadere stores this iPhone's public key, the kind of device, and Apple's check that this is the genuine App Clip. Never your face, passcode or contacts.")
                .font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
            Text("By continuing you agree to the Consumer Terms and confirm you've read the Privacy Notice.")
                .font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: ViadereSpace.m) {
                if let terms = URL(string: "https://\(ViadereCore.defaultDomain)/legal/consumer-terms/") { Link("Consumer Terms", destination: terms) }
                if let privacy = URL(string: "https://\(ViadereCore.defaultDomain)/legal/privacy-notice/") { Link("Privacy Notice", destination: privacy) }
            }
            .font(ViadereType.subhead)
            .tint(ViadereColor.textPrimary)
            if let error = flow.accountError { ViadereNotice(error, kind: .danger) }
            Button("Agree and connect") { Task { await flow.createAccountAndConnect() } }
                .buttonStyle(.viadere(.primary))
        }
    }
}
