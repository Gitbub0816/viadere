import SwiftUI
import ViadereKit

/// "Sign in to {Client}?" (UX_COPY OIDC-08, OIDC-05 on first use; FLOW_MATRIX F13). Opened from the QR universal link on the authorize page or a
/// `login_hint` push. Everything shown comes from the authority-signed statement (`OIDCSignInViewModel`); the number is typed, never displayed.
/// Deny and Approve are one component with Deny first; "This wasn't me" is the full-width footer. Nothing is signed until a tap, and
/// "Approved" appears only after the authority accepted the answer.
struct OIDCSignInSheet: View {
    @State private var model: OIDCSignInViewModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    init(pending: PendingOIDCSignIn) {
        let services = AppEnvironment.services
        _model = State(initialValue: OIDCSignInViewModel(
            challengeId: pending.challengeId, api: services.oidc, signer: DeviceKeyFactorSigner(keys: services.keys),
            pinnedKeys: AuthorityStatementKeyPins.effective(configuration: services.configuration), environment: services.configuration.authorityEnvironment,
            safeAction: pending.safeAction))
    }

    var body: some View {
        VStack(spacing: 0) {
            ViadereSheetHandle(onClose: { dismiss() })
            ScrollView {
                VStack(alignment: .leading, spacing: ViadereSpace.l) {
                    switch model.phase {
                    case .loading:
                        ViadereLoadingState("Checking this sign-in request…")
                    case .reviewing, .submitting:
                        question
                    default:
                        outcome
                    }
                }
                .padding(.horizontal, ViadereSpace.screen)
                .padding(.top, ViadereSpace.m)
                .animation(reduceMotion ? nil : ViadereMotion.gentle, value: model.phase)
            }
            .scrollIndicators(.hidden)
            footer
                .padding(.horizontal, ViadereSpace.screen)
                .padding(.vertical, ViadereSpace.m)
        }
        .background(ViadereColor.background)
        .viadereProtectedSurface()
        .privacySensitive()
        .sensoryFeedback(.warning, trigger: model.notice) { _, notice in notice != nil }
        .task { await model.load() }
    }

    private var question: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.s) {
            safeActionContext
            Text(model.title).font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary).accessibilityAddTraits(.isHeader)
            if let consent = model.consentText { Text(consent).font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary) }
            websiteRow
            Text(OIDCCopy.subtitle).font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
            Text(OIDCCopy.numberLabel).font(ViadereType.subhead.weight(.semibold)).foregroundStyle(ViadereColor.textPrimary)
            NumberEntryField(text: model.entry, accessibilityLabel: OIDCCopy.numberLabel) { model.setEntry($0) }
                .frame(height: 56)
                .padding(.horizontal, ViadereSpace.s)
                .viadereSurface(radius: ViadereRadius.control)
            Text(model.numberHelp).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
            if let notice = model.notice { ViadereNotice(notice, kind: .warning) }
        }
    }

    /// Shown only when a verified Viadere code (CKey Safe Action) opened this review (UX_COPY OIDC-12): who signed the code, which browser
    /// asked, and the warning about someone else's code. Text and rows come from the view model; the statement check, the number and the
    /// device-key signature below are unchanged.
    @ViewBuilder private var safeActionContext: some View {
        if let context = model.safeActionContext(formatTime: { $0.formatted(date: .omitted, time: .shortened) }) {
            VStack(alignment: .leading, spacing: ViadereSpace.s) {
                ForEach(context.rows) { row in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(row.label).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                        Text(row.value).font(ViadereType.subhead).foregroundStyle(ViadereColor.textPrimary).fixedSize(horizontal: false, vertical: true)
                    }
                    .accessibilityElement(children: .combine)
                }
                ViadereNotice(context.warning, kind: .warning)
            }
        }
    }

    /// "Website {redirect host}": the full host, wrapping and never truncated, with its registrable domain in strong type.
    @ViewBuilder private var websiteRow: some View {
        if let host = model.host {
            VStack(alignment: .leading, spacing: 2) {
                Text(OIDCCopy.websiteLabel).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                (Text(host.prefix).foregroundStyle(ViadereColor.textSecondary) + Text(host.strong).fontWeight(.bold).foregroundStyle(ViadereColor.textPrimary))
                    .font(ViadereType.headline)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel("\(OIDCCopy.websiteLabel) \(host.full)")
        }
    }

    /// The end of the request, in the view model's own copy, with a drawn mark and one haptic. Success only for an accepted approval; a
    /// refusal the person chose is neutral; everything that stopped the request is a caution.
    @ViewBuilder private var outcome: some View {
        if let message = model.message {
            ViadereOutcome(outcomeKind, message)
                .transition(.opacity)
        }
    }

    private var outcomeKind: ViadereOutcome.Kind {
        switch model.phase {
        case .approved: .success
        case .denied, .reported: .neutral
        default: .caution
        }
    }

    @ViewBuilder private var footer: some View {
        switch model.phase {
        case .reviewing, .submitting:
            VStack(spacing: ViadereSpace.s) {
                ViewThatFits(in: .horizontal) {
                    HStack(spacing: ViadereSpace.s) { denyButton; approveButton }
                    VStack(spacing: ViadereSpace.s) { denyButton; approveButton }
                }
                Button(OIDCCopy.notMe) { Task { await model.thisWasntMe() } }
                    .buttonStyle(.viadere(.quiet))
                    .frame(minHeight: 44)
                    .disabled(!model.canRefuse)
            }
        default:
            Button("Close") { dismiss() }.buttonStyle(.viadere(.quiet))
        }
    }

    private var denyButton: some View {
        Button(OIDCCopy.deny) { Task { await model.deny() } }
            .buttonStyle(.viadere(.secondary))
            .frame(minHeight: 44)
            .disabled(!model.canRefuse)
    }

    private var approveButton: some View {
        Button(OIDCCopy.approve) { Task { await model.approve() } }
            .buttonStyle(.viadere(.secondary))
            .frame(minHeight: 44)
            .disabled(!model.canApprove)
            .accessibilityHint(model.numberHelp)
    }
}
