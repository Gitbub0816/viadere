import SwiftUI
import ViadereCore
import ViadereKit

/// "Add business" from a business's own page (WP-C1): the business just signed its customer in and shows a QR. We show who it really is (Viadere's
/// signed descriptor, checked against the business's published keys), what it asks for, and the account it will see; then the six digits to compare
/// in the business's page. Nothing is connected until the business confirms.
struct LinkSessionSheet: View {
    @Bindable var controller: LinkController
    let pending: PendingLinkSession
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 0) {
            ViadereGrabber()
            ScrollView {
                VStack(alignment: .leading, spacing: ViadereSpace.l) {
                    Text("Add business").font(ViadereType.display).foregroundStyle(ViadereColor.textPrimary)
                    if let completion = controller.completion {
                        compare(completion)
                    } else if let offer = controller.offer {
                        offerContent(offer)
                    } else if controller.phase == .working {
                        ViadereLoading()
                    } else {
                        failure
                    }
                }
                .padding(.horizontal, ViadereSpace.screen)
                .padding(.top, ViadereSpace.m)
                .padding(.bottom, ViadereSpace.l)
            }
            .scrollIndicators(.hidden)
        }
        .background(ViadereColor.background)
        .task { await controller.lookup(code: pending.code, secret: pending.secret, checkCode: pending.checkCode) }
        .onDisappear { controller.reset() }
    }

    // MARK: Before linking

    @ViewBuilder private func offerContent(_ offer: LinkOffer) -> some View {
        HStack(spacing: ViadereSpace.s) {
            ViadereAvatar(name: offer.businessName, size: 48, isVerified: true)
            VStack(alignment: .leading, spacing: 2) {
                Text(offer.businessName).font(ViadereType.headline).foregroundStyle(ViadereColor.textPrimary)
                if !offer.businessDomain.isEmpty {
                    Text(offer.businessDomain).font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
                }
            }
        }
        ViadereNotice(offer.warning, kind: .warning)
        ViadereRowGroup {
            ViadereValueRow("Your account here", offer.pseudonym)
            if !offer.displayHint.isEmpty {
                ViadereHairline()
                ViadereValueRow("At \(offer.businessName)", UntrustedText.line(offer.displayHint, max: 40))
            }
            ViadereHairline()
            ViadereValueRow("Business key", offer.rootFingerprint)
        }
        VStack(alignment: .leading, spacing: ViadereSpace.xs) {
            Text("\(offer.businessName) will be able to").font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
            ViadereRowGroup {
                ForEach(Array(offer.capabilities.enumerated()), id: \.offset) { index, capability in
                    ViadereRow(LinkText.capability(capability))
                    if index < offer.capabilities.count - 1 { ViadereHairline() }
                }
            }
        }
        Text("\(offer.businessName) sees only an account reference made for it. It never sees your other businesses or your devices.")
            .font(ViadereType.footnote)
            .foregroundStyle(ViadereColor.textTertiary)
        if let message = controller.message { ViadereNotice(message, kind: .danger) }
        VStack(spacing: ViadereSpace.xs) {
            Button(offer.requiredAssurance == .biometric ? "Link with Face ID" : "Link") {
                Task { await controller.confirm() }
            }
            .buttonStyle(.viadere(.primary))
            .disabled(controller.phase == .working)
            Button("Not now") { dismiss() }.buttonStyle(.viadere(.quiet))
        }
    }

    // MARK: After linking: compare, then wait for the business

    @ViewBuilder private func compare(_ completion: LinkCompletion) -> some View {
        switch controller.outcome {
        case .linked?:
            VStack(alignment: .leading, spacing: ViadereSpace.m) {
                Image(systemName: "checkmark.circle").font(.system(size: 44, weight: .light)).foregroundStyle(ViadereColor.success).accessibilityHidden(true)
                Text("Linked to \(completion.businessName)").font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary)
                Text("\(completion.businessName) confirmed the link. You'll find it under Businesses.").font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
                Button("Done") { dismiss() }.buttonStyle(.viadere(.primary))
            }
            .sensoryFeedback(.success, trigger: completion.sessionId)
        case .expired?, .substitutionDetected?:
            ViadereNotice(controller.message ?? LinkText.expired(completion.businessName), kind: .danger)
            Button("Close") { dismiss() }.buttonStyle(.viadere(.secondary))
        case .waiting?, nil:
            VStack(alignment: .leading, spacing: ViadereSpace.m) {
                ViadereNotice("Check these on \(completion.businessName)'s page, where you're signed in. Don't read them to anyone who calls or messages you.", kind: .info)
                if let sas = completion.sas {
                    Text(LinkSAS.display(sas))
                        .font(ViadereType.display)
                        .monospacedDigit()
                        .foregroundStyle(ViadereColor.textPrimary)
                        .accessibilityLabel("Verification number \(sas.map(String.init).joined(separator: " "))")
                }
                ViadereRowGroup { ViadereValueRow("Your account here", completion.pseudonym) }
                Text("Nothing is connected until \(completion.businessName) confirms.").font(ViadereType.footnote).foregroundStyle(ViadereColor.textTertiary)
                Button("Close") { dismiss() }.buttonStyle(.viadere(.quiet))
            }
            .task(id: completion.sessionId) {
                // The business confirms within minutes; ask a few times while the digits are on screen (the server is the source of truth).
                for _ in 0..<60 {
                    try? await Task.sleep(for: .seconds(3))
                    guard !Task.isCancelled else { return }
                    await controller.refresh()
                    if controller.outcome != .waiting { return }
                }
            }
        }
    }

    private var failure: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.m) {
            ViadereNotice(controller.message ?? "We couldn't open this code. Ask the business for a new one.", kind: .danger)
            Button("Close") { dismiss() }.buttonStyle(.viadere(.secondary))
        }
    }
}

/// The typed path: the business's link code and its check code, both from the business's own signed-in page.
struct LinkCodeEntrySheet: View {
    let onSubmit: (PendingLinkSession) -> Void
    @State private var code = ""
    @State private var checkCode = ""
    @Environment(\.dismiss) private var dismiss

    private var canonicalCode: String? { LinkSessionCode.canonical(code) }
    private var canonicalCheck: String? { LinkSessionCode.canonical(checkCode) }

    var body: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.l) {
            ViadereGrabber()
            Text("Link with a code").font(ViadereType.display).foregroundStyle(ViadereColor.textPrimary)
            Text("Type both codes the business shows on its page, where you're signed in.").font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
            ViadereEntryField(placeholder: "Link code (ABCD-EFGH)", text: $code, status: code.isEmpty ? .none : (canonicalCode == nil ? .invalid : .valid), hint: nil,
                              monospaced: true, onSubmit: {})
            ViadereEntryField(placeholder: "Check code (ABCD-EFGH)", text: $checkCode, status: checkCode.isEmpty ? .none : (canonicalCheck == nil ? .invalid : .valid),
                              hint: nil, monospaced: true, onSubmit: {})
            Button("Continue") {
                guard let canonicalCode, let canonicalCheck else { return }
                onSubmit(PendingLinkSession(code: canonicalCode, checkCode: canonicalCheck))
                dismiss()
            }
            .buttonStyle(.viadere(.primary))
            .disabled(canonicalCode == nil || canonicalCheck == nil)
            Spacer()
        }
        .padding(.horizontal, ViadereSpace.screen)
        .background(ViadereColor.background)
    }
}

extension PendingLinkSession: Identifiable {
    public var id: String { code }
}
