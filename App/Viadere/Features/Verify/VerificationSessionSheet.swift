import SwiftUI
import ViadereCore
import ViadereKit

/// A business's "Verify with Viadere" button, QR or typed code (`/v/{CODE}`, `docs/VERIFY-BUTTON.md`): review the **verified** business, the site
/// the request was started on and exactly what it would learn; accept; then the ordinary verification (consent, Wallet or document) in the same
/// sheet; then, when the business gave one, a way back to its site. Nothing here comes from the link itself: everything shown is from the
/// descriptor Viadere signed (`VerificationSessionFlow`).
struct VerificationSessionSheet: View {
    let pending: PendingVerificationSession
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL

    private enum Phase {
        case loading
        case review(VerificationSessionReview)
        case accepting(VerificationSessionReview)
        case verifying(VerificationViewModel, returnURL: URL?, host: String)
        case failed(String)
    }

    @State private var phase: Phase = .loading
    @State private var finished = false

    private var flow: VerificationSessionFlow {
        VerificationSessionFlow(api: AppEnvironment.shared.verificationSessionAPI, descriptorKeys: ViadereRuntime.configuration.parsedLinkDescriptorKeys)
    }

    var body: some View {
        Group {
            switch phase {
            case .loading:
                ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
            case .review(let review), .accepting(let review):
                reviewView(review)
            case .verifying(let model, let returnURL, let host):
                VerificationRequestSheet(model: model)
                    .safeAreaInset(edge: .bottom) {
                        if finished, let returnURL {
                            Button("Return to \(host)") { openURL(returnURL); dismiss() }
                                .buttonStyle(.viadere(.secondary))
                                .padding(.horizontal, ViadereSpace.screen)
                                .padding(.bottom, ViadereSpace.m)
                        }
                    }
            case .failed(let message):
                VStack(spacing: ViadereSpace.l) {
                    Text("Can't continue").font(ViadereType.title)
                    Text(message).font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary).multilineTextAlignment(.center)
                    Button("Close") { dismiss() }.buttonStyle(.viadere(.secondary))
                }
                .padding(ViadereSpace.screen)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .background(ViadereColor.background)
        .privacySensitive()
        .task(id: pending) { await load() }
    }

    private func reviewView(_ review: VerificationSessionReview) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: ViadereSpace.l) {
                VStack(alignment: .leading, spacing: ViadereSpace.xs) {
                    Text(review.businessName).font(ViadereType.title)
                    Text("Verified business · \(review.businessDomain)").font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
                    Text("Asked on \(review.originHost)").font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
                }
                ViadereCard {
                    VStack(alignment: .leading, spacing: ViadereSpace.s) {
                        Text("They would learn").font(ViadereType.headline)
                        ForEach(review.disclosure) { item in
                            VStack(alignment: .leading, spacing: ViadereSpace.xxs) {
                                Text(item.title).font(ViadereType.body)
                                Text(item.detail).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                            }
                        }
                        Text("Purpose: \(review.purpose)").font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                    }
                }
                if !review.notDisclosed.isEmpty {
                    Text("Not shared: " + review.notDisclosed.joined(separator: ", ") + ".").font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                }
                if review.connects {
                    Text("Continuing also connects you with \(review.businessName). You choose what it may send you, and you can disconnect at any time.")
                        .font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                }
                Text(review.warning).font(ViadereType.footnote).foregroundStyle(ViadereColor.accent)
                VStack(spacing: ViadereSpace.s) {
                    Button("Continue") { Task { await accept(review) } }
                        .buttonStyle(.viadere(.primary))
                        .disabled(isAccepting)
                    Button("Not now") { dismiss() }.buttonStyle(.viadere(.quiet))
                }
            }
            .padding(ViadereSpace.screen)
        }
    }

    private var isAccepting: Bool { if case .accepting = phase { true } else { false } }

    @MainActor private func load() async {
        do { phase = .review(try await flow.review(code: pending.code)) } catch { phase = .failed(Self.message(error)) }
    }

    @MainActor private func accept(_ review: VerificationSessionReview) async {
        phase = .accepting(review)
        do {
            let (prompt, returnURL) = try await flow.accept(review)
            let environment = AppEnvironment.shared
            let model = VerificationViewModel(id: prompt.id, api: environment.verifyAPI, wallet: PassKitWalletIdentity(), document: DocumentVerificationLauncher.shared,
                                              lock: AppEnvironment.services.appLock)
            model.onFinished = { _ in finished = true }
            phase = .verifying(model, returnURL: returnURL, host: review.originHost)
        } catch {
            phase = .failed(Self.message(error))
        }
    }

    private static func message(_ error: any Error) -> String {
        switch error as? VerificationSessionFlowError {
        case .expired?: return "This code has expired. Go back to the business's page and start again."
        case .notConfigured?: return "This version of Viadere can't verify with businesses yet."
        case .descriptorInvalid?, .mismatch?, .promptMismatch?: return "This request could not be confirmed as coming from a verified business, so nothing was shared."
        case nil: return "This code isn't valid or was already used. Go back to the business's page and start again."
        }
    }
}
