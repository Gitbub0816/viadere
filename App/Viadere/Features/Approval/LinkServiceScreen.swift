import SwiftUI
import ViadereKit

/// "Sign in to {Business}?" for a Viadere link-service delivery (`link_mode: "viadere"`; UX_COPY LS-01 to LS-08, SECURITY.md §2.110). Shown by
/// `LinkConfirmationSheet` when the delivery is one. Everything on it comes from the authority-signed `link_open` statement (`LinkServiceViewModel`);
/// the number field appears only when the challenge asks for one. This wasn't me, Deny and Approve are one component of equal buttons with the
/// safe actions first. Nothing is signed until a tap, "Approved" appears only after the authority accepted, and this screen never opens a URL.
struct LinkServiceScreen: View {
    @State private var model: LinkServiceViewModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    init(deliveryId: UUID) {
        let services = AppEnvironment.services
        // Signed only with the biometric approval key (`biometricOnly`), against the build-pinned statement keys (empty pins: fails closed).
        _model = State(initialValue: LinkServiceViewModel(
            deliveryId: deliveryId, api: services.linkService, signer: DeviceKeyFactorSigner(keys: services.keys, biometricOnly: true),
            pinnedKeys: AuthorityStatementKeyPins.effective(configuration: services.configuration), environment: services.configuration.authorityEnvironment))
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
            Text(model.title).font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary).accessibilityAddTraits(.isHeader)
            websiteRow
            if let service = model.service {
                VStack(alignment: .leading, spacing: 2) {
                    Text(LinkServiceCopy.serviceLabel).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                    Text(service).font(ViadereType.subhead).foregroundStyle(ViadereColor.textPrimary).fixedSize(horizontal: false, vertical: true)
                }
                .accessibilityElement(children: .combine)
            }
            if let subtitle = model.subtitle { Text(subtitle).font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary) }
            if let label = model.numberLabel {
                Text(label).font(ViadereType.subhead.weight(.semibold)).foregroundStyle(ViadereColor.textPrimary)
                NumberEntryField(text: model.entry, accessibilityLabel: label) { model.setEntry($0) }
                    .frame(height: 56)
                    .padding(.horizontal, ViadereSpace.s)
                    .viadereSurface(radius: ViadereRadius.control)
                if let help = model.numberHelp { Text(help).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary) }
            }
            if let notice = model.notice { ViadereNotice(notice, kind: .warning) }
        }
    }

    /// "Website {return host}": the full host, wrapping and never truncated, with its registrable domain in strong type.
    @ViewBuilder private var websiteRow: some View {
        if let host = model.host {
            VStack(alignment: .leading, spacing: 2) {
                Text(LinkServiceCopy.websiteLabel).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                (Text(host.prefix).foregroundStyle(ViadereColor.textSecondary) + Text(host.strong).fontWeight(.bold).foregroundStyle(ViadereColor.textPrimary))
                    .font(ViadereType.headline)
                    .fixedSize(horizontal: false, vertical: true)
                if host.hasUnusualCharacters { ViadereNotice(AuthDeliveryCopy.unusualHost, kind: .warning) }
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel("\(LinkServiceCopy.websiteLabel) \(host.full)")
        }
    }

    @ViewBuilder private var outcome: some View {
        if let message = model.message {
            ViadereOutcome(outcomeKind, message)
                .transition(.opacity)
        }
    }

    /// Success only for an accepted approval; a refusal the person chose is neutral; everything that stopped the request is a caution.
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
            // One component: This wasn't me, Deny, Approve, identical look, side by side until they would truncate, then stacked.
            ViewThatFits(in: .horizontal) {
                HStack(spacing: ViadereSpace.s) { ForEach(model.buttons) { button($0) } }
                VStack(spacing: ViadereSpace.s) { ForEach(model.buttons) { button($0) } }
            }
        default:
            VStack(spacing: ViadereSpace.s) {
                if model.offersTryAgain { Button(AuthDeliveryCopy.tryAgain) { Task { await model.tryAgain() } }.buttonStyle(.viadere(.secondary)) }
                Button("Close") { dismiss() }.buttonStyle(.viadere(.quiet))
            }
        }
    }

    private func button(_ spec: SafeActionButton) -> some View {
        Button(spec.title) {
            Task {
                switch spec.role {
                case .notMe: await model.thisWasntMe()
                case .deny: await model.deny()
                default: await model.approve()
                }
            }
        }
        .buttonStyle(.viadere(.secondary))
        .frame(minHeight: 44)
        .disabled(!spec.isEnabled)
        .accessibilityHint(spec.role == .approve ? (model.numberHelp ?? "") : "")
    }
}
