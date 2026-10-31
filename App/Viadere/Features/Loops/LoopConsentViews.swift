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
        Toggle(isOn: $consent.agreed) {
            Text("I understand how these requests work and want to turn them on.")
                .font(ViadereType.body)
                .foregroundStyle(ViadereColor.textPrimary)
        }
        .toggleStyle(.viadere)
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

/// Settings → Requests built by businesses (WP-3.5): the global switch (on runs the education; off revokes everything and cancels open
/// requests, history kept) and one switch per connected, verified business.
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
                ViadereBackButton("Settings") { dismiss() }
                ViadereHeader("Requests built by businesses",
                              subtitle: "Short requests a business builds, like choosing a pickup time. Each one says who built it.")
                if !consent.isAvailable {
                    ViadereNotice("These requests aren't available right now. Everything else in Viadere works as usual.", kind: .info)
                } else {
                    ViadereRowGroup {
                        Toggle(isOn: Binding(get: { consent.isEnabled }, set: { on in
                            if on { showingEducation = true } else { confirmingOff = true }
                        })) {
                            Text("Allow requests built by businesses").font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
                        }
                        .toggleStyle(.viadere)
                        .padding(.vertical, ViadereSpace.s)
                    }
                    if consent.isEnabled { businesses }
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

    private var businesses: some View {
        VStack(alignment: .leading, spacing: 0) {
            ViadereSectionHeader("Businesses")
            let verified = model.businesses.active.filter { $0.business.isVerified }
            if verified.isEmpty {
                Text("Businesses you connect to appear here.").font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
            } else {
                ViadereRowGroup {
                    ForEach(Array(verified.enumerated()), id: \.element.id) { index, entry in
                        Toggle(isOn: Binding(get: { consent.isAuthorized(entry.business.id) }, set: { on in
                            if on { authorizing = entry.business } else { Task { await consent.revoke(entry.business.id) } }
                        })) {
                            Text(entry.business.safeName).font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
                        }
                        .toggleStyle(.viadere)
                        .padding(.vertical, ViadereSpace.s)
                        .accessibilityHint(Text("Allows \(entry.business.safeName) to send you requests it built"))
                        if index < verified.count - 1 { ViadereHairline() }
                    }
                }
            }
        }
    }
}

/// Business settings → whether this business may send Loops (shown only while Loops are on). Off revokes and cancels its open requests.
struct BusinessLoopAuthorizationRow: View {
    let business: BusinessSummary
    let model: AppModel
    @State private var authorizing = false

    private var consent: LoopConsentViewModel { model.loopConsent }

    var body: some View {
        if model.services.loopsAPI != nil, consent.isEnabled, business.isVerified {
            VStack(alignment: .leading, spacing: 0) {
                ViadereSectionHeader("Requests")
                ViadereRowGroup {
                    Toggle(isOn: Binding(get: { consent.isAuthorized(business.id) }, set: { on in
                        if on { authorizing = true } else { Task { await consent.revoke(business.id) } }
                    })) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Requests built by \(business.safeName)").font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
                            Text("Turning this off cancels its open requests.").font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                        }
                    }
                    .toggleStyle(.viadere)
                    .padding(.vertical, ViadereSpace.s)
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
    @State private var catalog: LoopCatalogViewModel

    init(business: BusinessSummary, model: AppModel) {
        self.business = business
        self.model = model
        let consent = model.loopConsent
        _catalog = State(initialValue: LoopCatalogViewModel(business: business.id, api: model.services.loopsAPI, consent: { consent.status }))
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
        .task(id: model.loopConsent.status) { await catalog.load() }
    }
}
