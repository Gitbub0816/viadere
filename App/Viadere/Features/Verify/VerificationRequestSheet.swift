import SwiftUI
import ViadereCore
import ViadereKit

/// A business asks to verify something: who is asking, why, exactly what is shared, who gets it and until when. Consent is for exactly
/// this; the person can say no, and there is always a second way to verify.
struct VerificationRequestSheet: View {
    @Bindable var model: VerificationViewModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 0) {
            ViadereGrabber()
            ScrollView {
                VStack(alignment: .leading, spacing: ViadereSpace.l) {
                    content
                }
                .padding(.horizontal, ViadereSpace.screen)
                .padding(.top, ViadereSpace.m)
                .padding(.bottom, ViadereSpace.l)
            }
            .scrollIndicators(.hidden)
        }
        .background(ViadereColor.background)
        .privacySensitive()
        .interactiveDismissDisabled(isBusy)
        .task {
            await model.load()
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                model.tick()
            }
        }
    }

    private var isBusy: Bool { if case .verifying = model.phase { true } else { false } }

    @ViewBuilder private var content: some View {
        switch model.phase {
        case .loading:
            ViadereLoading()
        case .failed(let message):
            StateBlock(symbol: "exclamationmark.circle", title: "This request isn't available", message: message)
            Button("Close") { dismiss() }.buttonStyle(.viadere(.secondary))
        case .reviewing:
            if let prompt = model.prompt { review(prompt) }
        case .choosingMethod:
            if let prompt = model.prompt { methodChoice(prompt) }
        case .verifying(let method):
            VStack(spacing: ViadereSpace.m) {
                ViadereLoading()
                Text(method == .wallet ? "Waiting for Apple Wallet…" : "Continue in the verification screens…")
                    .font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
            }
            .frame(maxWidth: .infinity)
            .padding(.top, ViadereSpace.xl)
        case .finished(let outcome):
            result(outcome)
        }
    }

    // MARK: Review

    private func review(_ prompt: VerificationPrompt) -> some View {
        VStack(alignment: .leading, spacing: ViadereSpace.l) {
            HStack(spacing: ViadereSpace.s) {
                ViadereAvatar(name: prompt.recipientName, size: 48, isVerified: prompt.recipientVerified)
                VStack(alignment: .leading, spacing: 4) {
                    Text(prompt.recipientName).font(ViadereType.headline).foregroundStyle(ViadereColor.textPrimary)
                    HStack(spacing: ViadereSpace.xs) {
                        if prompt.recipientVerified { ViadereBadge("Verified business", kind: .verified) }
                        if let handle = prompt.recipientHandle { Text(handle).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary) }
                    }
                }
                Spacer(minLength: 0)
                Text(countdown).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary).accessibilityLabel("Expires in \(countdown)")
            }
            Text("\(prompt.recipientName) is asking you to verify something")
                .font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary)
            ViadereCard(padding: ViadereSpace.m) {
                VStack(alignment: .leading, spacing: ViadereSpace.s) {
                    Text("Why").font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                    Text(model.purposeText).font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
                    ViadereHairline()
                    Text("What will be shared").font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                    ForEach(model.disclosure) { item in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(item.title).font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
                            Text(item.detail).font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
                        }
                    }
                    ViadereHairline()
                    Text("Not shared").font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                    Text(prompt.notDisclosed.joined(separator: " · ")).font(ViadereType.subhead).foregroundStyle(ViadereColor.textPrimary)
                    ViadereHairline()
                    Text("Who gets it, and for how long").font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                    Text("Only \(prompt.recipientName), for this request only. It also includes \(prompt.includedMetadata.map { $0.lowercased() }.joined(separator: "; ")). This request expires \(prompt.expiresAt.formatted(date: .omitted, time: .shortened)).")
                        .font(ViadereType.subhead).foregroundStyle(ViadereColor.textPrimary)
                }
            }
            ViadereNotice(model.note, kind: .info)
            ViadereNotice(VerificationCopy.verifiedBusinessNote, kind: .info)
            ViadereNotice(VerificationCopy.localAuthNote, kind: .info)
            VStack(spacing: ViadereSpace.s) {
                Button(VerificationCopy.consentButton) { Task { await model.consent() } }
                    .buttonStyle(.viadere(.primary))
                    .disabled(model.isExpired)
                Button(VerificationCopy.declineButton) { Task { await model.decline() } }
                    .buttonStyle(.viadere(.secondary))
            }
        }
    }

    private var countdown: String {
        let seconds = Int(model.remaining)
        return String(format: "%d:%02d", seconds / 60, seconds % 60)
    }

    // MARK: Method choice

    private func methodChoice(_ prompt: VerificationPrompt) -> some View {
        VStack(alignment: .leading, spacing: ViadereSpace.l) {
            Text("How would you like to verify?").font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary)
            if let notice = model.notice { ViadereNotice(notice, kind: .warning) }
            if model.orderedMethods.isEmpty {
                ViadereNotice(VerificationCopy.noMethodAvailable, kind: .info)
            }
            ForEach(model.orderedMethods, id: \.self) { method in
                switch method {
                case .wallet:
                    methodCard(symbol: "wallet.pass", title: VerificationCopy.walletTitle, detail: VerificationCopy.walletDetail,
                               primary: model.orderedMethods.first == .wallet) { Task { await model.verifyWithWallet() } }
                case .document:
                    methodCard(symbol: "person.text.rectangle", title: VerificationCopy.documentTitle, detail: VerificationCopy.documentDetail,
                               primary: model.orderedMethods.first == .document) { Task { await model.verifyWithDocument() } }
                }
            }
            if model.walletAvailability == .unavailable {
                Text(VerificationCopy.walletUnavailableReason).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
            }
            Text(VerificationCopy.alternativePath).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
            Button(VerificationCopy.declineButton) { Task { await model.decline() } }.buttonStyle(.viadere(.secondary))
        }
    }

    private func methodCard(symbol: String, title: String, detail: String, primary: Bool, action: @escaping () -> Void) -> some View {
        ViadereCard(padding: ViadereSpace.m) {
            VStack(alignment: .leading, spacing: ViadereSpace.s) {
                HStack(spacing: ViadereSpace.s) {
                    ViadereIconTile(systemName: symbol)
                    Text(title).font(ViadereType.headline).foregroundStyle(ViadereColor.textPrimary)
                }
                Text(detail).font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
                Button(primary ? "Continue" : "Use this instead", action: action).buttonStyle(.viadere(primary ? .primary : .secondary))
            }
        }
    }

    // MARK: Result

    private func result(_ outcome: VerificationAttemptOutcome) -> some View {
        VStack(alignment: .leading, spacing: ViadereSpace.l) {
            StateBlock(symbol: outcome.status == .released ? "checkmark.circle" : "minus.circle",
                       title: outcome.status == .released ? "Done" : "Nothing was shared", message: model.resultText)
            if outcome.status == .released, let label = outcome.label {
                ViadereCard(padding: ViadereSpace.m) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(label.displayName).font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
                        Text(label.limits).font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
                        Text("You can find this receipt in Settings, under Verification history.")
                            .font(ViadereType.footnote).foregroundStyle(ViadereColor.textTertiary)
                    }
                }
            }
            Button("Done") { dismiss() }.buttonStyle(.viadere(.primary))
        }
        .sensoryFeedback(.success, trigger: outcome.status == .released)
    }
}

/// An icon, a title and a sentence.
private struct StateBlock: View {
    let symbol: String
    let title: String
    let message: String

    var body: some View {
        VStack(spacing: ViadereSpace.s) {
            Image(systemName: symbol).font(.system(size: 40, weight: .light)).foregroundStyle(ViadereColor.accent).accessibilityHidden(true)
            Text(title).font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary)
            Text(message).font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary).multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.top, ViadereSpace.xl)
        .accessibilityElement(children: .combine)
    }
}
