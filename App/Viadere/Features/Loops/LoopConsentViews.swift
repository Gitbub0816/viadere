import SwiftUI
import ViadereCore
import ViadereKit

/// Turning on Loops (WP-3.5): the counsel-approved explanation one part at a time (no skip, no timer), the comprehension questions after
/// the last part, then an explicit agreement. Works with VoiceOver and Switch Control: every step is a plain button or a selectable row,
/// nothing moves on its own, and the answers stay until the customer changes them.
struct LoopConsentFlowView: View {
    @Bindable var consent: LoopConsentViewModel
    var onFinished: (Bool) -> Void = { _ in }
    @Environment(\.dismiss) private var dismiss
    @AccessibilityFocusState private var paragraphFocused: Bool

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: ViadereSpace.l) {
                if let text = consent.text {
                    ViadereHeader(text.title, subtitle: consent.hasReadAll ? "A few questions" : consent.progressLabel)
                    if !consent.hasReadAll {
                        reading(text)
                    } else {
                        questions(text)
                        agreement(text)
                    }
                } else if consent.isLoading {
                    ViadereLoading()
                } else {
                    ViadereEmptyState("Not available", message: "Requests built by businesses aren't available right now.")
                }
                if let error = consent.errorMessage { ViadereNotice(error, kind: .warning) }
                Button("Not now") {
                    onFinished(false)
                    dismiss()
                }
                .buttonStyle(.viadere(.quiet))
            }
            .padding(ViadereSpace.screen)
        }
        .scrollIndicators(.hidden)
        .viadereScreenBackground()
        .task { if consent.status == nil { await consent.load() } }
    }

    @ViewBuilder private func reading(_ text: LoopConsentText) -> some View {
        ViadereProgressBar(progress: Double(consent.paragraphIndex + 1) / Double(max(consent.paragraphCount, 1)), label: consent.progressLabel)
        if let paragraph = consent.currentParagraph {
            ViadereCard {
                Text(paragraph)
                    .font(ViadereType.body)
                    .foregroundStyle(ViadereColor.textPrimary)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityFocused($paragraphFocused)
            }
        }
        HStack(spacing: ViadereSpace.s) {
            if consent.paragraphIndex > 0 {
                Button("Back") { consent.back(); paragraphFocused = true }
                    .buttonStyle(.viadere(.secondary))
            }
            Button("Continue") { consent.advance(); paragraphFocused = true }
                .buttonStyle(.viadere(.primary))
                .accessibilityHint(Text("Shows the next part. There are \(consent.paragraphCount) parts."))
        }
    }

    @ViewBuilder private func questions(_ text: LoopConsentText) -> some View {
        ForEach(text.checks, id: \.id) { check in
            VStack(alignment: .leading, spacing: ViadereSpace.xs) {
                Text(check.question).font(ViadereType.headline).foregroundStyle(ViadereColor.textPrimary).accessibilityAddTraits(.isHeader)
                ViadereRowGroup {
                    ForEach(Array(check.options.enumerated()), id: \.element.id) { index, option in
                        let selected = consent.answers[check.id] == option.id
                        Button {
                            consent.select(option: option.id, for: check.id)
                        } label: {
                            HStack(spacing: ViadereSpace.s) {
                                Image(systemName: selected ? "largecircle.fill.circle" : "circle")
                                    .foregroundStyle(selected ? ViadereColor.textPrimary : ViadereColor.textTertiary)
                                    .accessibilityHidden(true)
                                Text(option.label).font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
                                Spacer()
                            }
                            .padding(.vertical, ViadereSpace.s)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
                        if index < check.options.count - 1 { ViadereHairline() }
                    }
                }
            }
        }
        Button("Back to the explanation") {
            consent.back()
        }
        .buttonStyle(.viadere(.quiet))
    }

    @ViewBuilder private func agreement(_ text: LoopConsentText) -> some View {
        // An explicit agreement: a checkbox, not a switch.
        ViadereCheckbox(isOn: $consent.agreed) {
            Text("I understand how these requests work and want to turn them on.")
        }
        .disabled(!consent.allChecksAnswered)
        Button(text.agreeLabel) {
            Task {
                if await consent.enable() {
                    onFinished(true)
                    dismiss()
                }
            }
        }
        .buttonStyle(.viadere(.primary))
        .disabled(!consent.canEnable)
    }
}

/// Allowing one business to send Loops (WP-3.5): its verified name in Viadere's sentence, Allow or Not now.
struct LoopBusinessAuthorizationSheet: View {
    @Bindable var consent: LoopConsentViewModel
    let business: BusinessSummary
    var onFinished: (Bool) -> Void = { _ in }
    @Environment(\.dismiss) private var dismiss
    @State private var showingEducation = false

    var body: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.l) {
            HStack(spacing: ViadereSpace.s) {
                ViadereAvatar(name: business.safeName, size: 44, isVerified: business.isVerified)
                VStack(alignment: .leading, spacing: 2) {
                    Text(business.safeName).font(ViadereType.headline).foregroundStyle(ViadereColor.textPrimary)
                    ViadereBadge(business.isVerified ? "Verified business" : "Not verified", kind: business.isVerified ? .verified : .danger)
                }
            }
            .accessibilityElement(children: .combine)
            if !consent.isEnabled {
                ViadereNotice("Turn on requests built by businesses first.", kind: .info)
                Button("Learn how they work") { showingEducation = true }
                    .buttonStyle(.viadere(.primary))
            } else if let sentence = consent.authorizationText(for: business) {
                Text(sentence).font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary).fixedSize(horizontal: false, vertical: true)
                Button("Allow") {
                    Task {
                        let ok = await consent.authorize(business)
                        onFinished(ok)
                        if ok { dismiss() }
                    }
                }
                .buttonStyle(.viadere(.primary))
                .disabled(consent.isSubmitting)
            } else {
                ViadereNotice("Viadere hasn't verified this business, so it can't send these requests.", kind: .warning)
            }
            if let error = consent.errorMessage { ViadereNotice(error, kind: .warning) }
            Button("Not now") {
                onFinished(false)
                dismiss()
            }
            .buttonStyle(.viadere(.quiet))
            Spacer(minLength: 0)
        }
        .padding(ViadereSpace.screen)
        .viadereScreenBackground()
        .sheet(isPresented: $showingEducation) {
            LoopConsentFlowView(consent: consent)
                .presentationDetents([.large])
                .presentationBackground(ViadereColor.background)
        }
    }
}

/// You → Requests built by businesses (WP-3.5): the global state (turning on runs the education; turning off revokes everything and cancels
/// open requests, history kept) as a state card, and the allowed businesses as one group of chips (allowing one opens its authorization
/// sheet; removing one revokes it and cancels its open requests).
struct LoopSettingsView: View {
    let model: AppModel
    @State private var showingEducation = false
    @State private var confirmingOff = false
    @State private var authorizing: BusinessSummary?
    @Environment(\.dismiss) private var dismiss

    private var consent: LoopConsentViewModel { model.loopConsent }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: ViadereSpace.l) {
                ViadereBackButton("You") { dismiss() }
                ViadereHeader("Requests built by businesses",
                              subtitle: "Short requests a business builds, like choosing a pickup time. Each one says who built it.")
                if !consent.isAvailable {
                    ViadereNotice("These requests aren't available right now. Everything else in Viadere works as usual.", kind: .info)
                } else {
                    ViadereStateCard("Requests built by businesses",
                                     detail: consent.isEnabled
                                         ? "Businesses you allow can send you short requests they built. Turning this off cancels every open one."
                                         : "Off. Turning it on starts a short explanation of how these requests work, then asks you to agree.",
                                     state: consent.isEnabled ? "On" : "Off",
                                     stateKind: consent.isEnabled ? .success : .neutral,
                                     actionTitle: consent.isEnabled ? "Turn off" : "Learn and turn on",
                                     actionKind: consent.isEnabled ? .destructive : .primary) {
                        if consent.isEnabled { confirmingOff = true } else { showingEducation = true }
                    }
                    if consent.isEnabled { businesses }
                    yourLoops
                }
                if let error = consent.errorMessage { ViadereNotice(error, kind: .warning) }
            }
            .padding(.horizontal, ViadereSpace.screen)
            .padding(.bottom, ViadereSpace.xl)
        }
        .scrollIndicators(.hidden)
        .viadereScreenBackground()
        .toolbar(.hidden, for: .navigationBar)
        .task { await consent.load() }
        .task { await model.loopLibrary.load() }
        .sheet(isPresented: $showingEducation) {
            LoopConsentFlowView(consent: consent)
                .presentationDetents([.large])
                .presentationBackground(ViadereColor.background)
        }
        .sheet(item: Binding(get: { authorizing.map(IdentifiedBusiness.init) }, set: { authorizing = $0?.business })) { item in
            LoopBusinessAuthorizationSheet(consent: consent, business: item.business)
                .presentationDetents([.medium])
                .presentationBackground(ViadereColor.background)
        }
        .confirmationDialog("Turn off requests built by businesses?", isPresented: $confirmingOff, titleVisibility: .visible) {
            Button("Turn off", role: .destructive) { Task { await consent.disable() } }
            Button("Keep on", role: .cancel) {}
        } message: {
            Text("Open requests are cancelled and no business can send new ones. Your history stays.")
        }
    }

    /// Installed Loops (§2.98 "Installed Loops"): each one opens its page, where it can be removed; and the directory.
    private var yourLoops: some View {
        VStack(alignment: .leading, spacing: 0) {
            ViadereSectionHeader("Your Loops")
            if model.loopLibrary.loops.isEmpty {
                Text("Loops you add appear here, whether or not you're connected to the business.")
                    .font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
            } else {
                InstalledLoopsList(model: model, showsEmptyState: false)
            }
            ViadereRowGroup {
                NavigationLink {
                    LoopDirectoryView(model: model, backTitle: "Back")
                } label: {
                    ViadereRow("Browse Loops", subtitle: "Reviewed by Viadere", leading: { ViadereIconTile(systemName: "square.grid.2x2") })
                }
                .buttonStyle(.plain)
            }
            .padding(.top, ViadereSpace.xs)
        }
    }

    private var businesses: some View {
        VStack(alignment: .leading, spacing: 0) {
            ViadereSectionHeader("Businesses")
            let verified = model.businesses.active.filter { $0.business.isVerified }
            if verified.isEmpty {
                Text("Businesses you connect to appear here.").font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
            } else {
                ViadereCard(padding: ViadereSpace.m) {
                    VStack(alignment: .leading, spacing: ViadereSpace.s) {
                        ViadereChipSet("Businesses allowed to send requests they built",
                                       chips: verified.map { entry in
                                           ViadereChipSet<BusinessID>.Chip(entry.business.id, entry.business.safeName,
                                                                           hint: consent.isAuthorized(entry.business.id)
                                                                               ? "Double-tap to stop \(entry.business.safeName) and cancel its open requests."
                                                                               : "Double-tap to review what allowing \(entry.business.safeName) means.")
                                       },
                                       isSelected: { consent.isAuthorized($0) },
                                       toggle: { id in
                                           if consent.isAuthorized(id) { Task { await consent.revoke(id) } }
                                           else { authorizing = verified.first { $0.business.id == id }?.business }
                                       })
                        Text(allowedSummary(verified))
                            .font(ViadereType.footnote)
                            .foregroundStyle(ViadereColor.textSecondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        }
    }
}

extension LoopSettingsView {
    func allowedSummary(_ verified: [ConnectedBusiness]) -> String {
        let allowed = verified.filter { consent.isAuthorized($0.business.id) }.count
        switch allowed {
        case 0: return "No business is allowed yet. Tap one to review and allow it."
        case 1: return "1 business allowed. Tap it to stop it; its open requests are cancelled."
        default: return "\(allowed) businesses allowed. Tap one to stop it; its open requests are cancelled."
        }
    }
}

/// Business settings → whether this business may send Loops (shown only while Loops are on). Removing it revokes and cancels its open
/// requests; allowing it opens the authorization sheet.
struct BusinessLoopAuthorizationRow: View {
    let business: BusinessSummary
    let model: AppModel
    @State private var authorizing = false

    private var consent: LoopConsentViewModel { model.loopConsent }

    var body: some View {
        if model.services.loopsAPI != nil, consent.isEnabled, business.isVerified {
            let allowed = consent.isAuthorized(business.id)
            VStack(alignment: .leading, spacing: 0) {
                ViadereSectionHeader("Requests")
                ViadereStateCard("Requests built by \(business.safeName)",
                                 detail: allowed ? "\(business.safeName) can send you short requests it built. Stopping cancels its open requests."
                                                 : "\(business.safeName) can't send you requests it built.",
                                 state: allowed ? "Allowed" : "Not allowed",
                                 stateKind: allowed ? .success : .neutral,
                                 actionTitle: allowed ? "Stop" : "Allow…",
                                 actionKind: allowed ? .destructive : .secondary) {
                    if allowed { Task { await consent.revoke(business.id) } } else { authorizing = true }
                }
            }
            .sheet(isPresented: $authorizing) {
                LoopBusinessAuthorizationSheet(consent: consent, business: business)
                    .presentationDetents([.medium])
                    .presentationBackground(ViadereColor.background)
            }
        }
    }
}

private struct IdentifiedBusiness: Identifiable {
    let business: BusinessSummary
    var id: BusinessID { business.id }
}

/// The Loops a business offers on its page (entry point `business_page`), each under "Built by {verified name}". Hidden while Loops
/// are unavailable or turned off.
struct BusinessLoopsSection: View {
    let business: BusinessSummary
    let model: AppModel
    /// Owned and loaded by the page (`BusinessHomeView`): a `.task` here would never run, because this view is empty until the list has
    /// loaded and SwiftUI does not start tasks on a view with no content.
    let catalog: LoopCatalogViewModel

    static func makeCatalog(business: BusinessSummary, model: AppModel) -> LoopCatalogViewModel {
        let consent = model.loopConsent
        return LoopCatalogViewModel(business: business.id, api: model.services.loopsAPI, consent: { consent.status })
    }

    var body: some View {
        Group {
            if catalog.isVisible {
                VStack(alignment: .leading, spacing: 0) {
                    ViadereSectionHeader("Requests")
                    ViadereRowGroup {
                        ForEach(Array(catalog.loops.enumerated()), id: \.element.publicationId) { index, summary in
                            Button {
                                Task { await AppEnvironment.shared.loops.start(summary, business: business, catalog: catalog, model: model) }
                            } label: {
                                ViadereRow(LoopCatalogViewModel.title(summary), subtitle: "Built by \(business.safeName)",
                                           leading: { ViadereIconTile(systemName: "square.stack") })
                            }
                            .buttonStyle(.plain)
                            .accessibilityLabel(Text("\(LoopCatalogViewModel.title(summary)). Built by \(business.safeName), a business on Viadere"))
                            if index < catalog.loops.count - 1 { ViadereHairline(inset: 50) }
                        }
                    }
                }
            }
        }
    }
}
