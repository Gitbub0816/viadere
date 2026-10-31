import SwiftUI
import ViadereCore
import ViadereKit

/// The context bar wired to the model, plus the "Showing {business}" banner when a push or link put another business on screen (C9.7).
/// Every primary destination starts with it, so the selector, Add business and Settings are always in the same place.
struct OrganizationContextHeader: View {
    @Bindable var model: AppModel
    @State private var choosing = false

    private var store: OrganizationContextStore { model.organization }

    var body: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.s) {
            ViadereContextBar(
                title: store.title, accessibilityValue: store.accessibilityValue, isFiltered: store.effective != .all,
                openSelector: { choosing = true },
                adjust: { delta in _ = store.adjust(by: delta) },
                add: { model.addBusinessPresented = true },
                account: { model.settingsPresented = true })
            if let temporary = store.temporaryBusiness {
                ViadereContextBanner(businessName: temporary.safeName) { _ = store.returnToSaved() }
                    .transition(.opacity)
            }
        }
        .animation(ViadereMotion.quick, value: store.effective)
        .sheet(isPresented: $choosing) {
            ContextSelectorSheet(model: model) { choosing = false }
                .presentationDetents([.medium, .large])
                .presentationCornerRadius(ViadereRadius.sheet)
                .presentationBackground(ViadereColor.background)
        }
    }
}

/// The full selector: All, then every connected business (favorites first), searchable; Add business at the end. Selecting changes the
/// saved context; while an approval or verification is open nothing changes (the sheet says why).
struct ContextSelectorSheet: View {
    @Bindable var model: AppModel
    let close: () -> Void
    @State private var query = ""
    @State private var refusal: String?

    private var store: OrganizationContextStore { model.organization }

    private var matches: [BusinessSummary] {
        store.order.compactMap { store.summary(for: $0) }.filter { BusinessDirectoryRules.matches($0, query: query) }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: ViadereSpace.s) {
                ViadereGrabber().frame(maxWidth: .infinity)
                ViadereHeader("Show", subtitle: "Choose which business Messages, Alerts and Benefits show.")
                if store.options.count > 8 { ViadereSearchField("Search your businesses", text: $query) }
                if let refusal { ViadereNotice(refusal, kind: .info) }
                ViadereRowGroup {
                    option(.all, title: "All businesses", subtitle: "Everything, from every business you're connected to") {
                        ViadereIconTile(systemName: "square.grid.2x2")
                    }
                    ForEach(matches) { business in
                        ViadereHairline(inset: 50)
                        option(.business(business.id), title: business.safeName, subtitle: business.handle?.display ?? business.code.display) {
                            ViadereAvatar(name: business.safeName, size: 36, isVerified: business.isVerified)
                        }
                    }
                }
                Button {
                    close()
                    model.addBusinessPresented = true
                } label: {
                    HStack(spacing: ViadereSpace.xs) {
                        Image(systemName: "plus")
                        Text("Add business")
                    }
                }
                .buttonStyle(.viadere(.secondary))
                .padding(.top, ViadereSpace.s)
            }
            .padding(.horizontal, ViadereSpace.screen)
            .padding(.bottom, ViadereSpace.xl)
        }
        .scrollIndicators(.hidden)
        .viadereScreenBackground()
    }

    private func option<Leading: View>(_ context: OrganizationContext, title: String, subtitle: String, @ViewBuilder leading: () -> Leading) -> some View {
        let selected = store.saved == context
        return Button {
            switch store.select(context) {
            case .changed, .unchanged: close()
            case .deferredSensitiveFlow: refusal = "Finish or close the open request first. The view doesn't change while you're answering it."
            case .notConnected: refusal = "You're not connected to that business."
            }
        } label: {
            ViadereRow(title, subtitle: subtitle, leading: leading) {
                if selected {
                    Image(systemName: "checkmark")
                        .font(.system(size: 15, weight: .semibold))
                        .foregroundStyle(ViadereColor.accent)
                        .accessibilityHidden(true)
                }
            }
        }
        .buttonStyle(.plain)
        .accessibilityValue(Text(selected ? "Selected" : ""))
        .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
    }
}

/// Opens whatever owns an alert: the approval sheet, the Approve v2 sheet, the verification sheet or the account notice. The list never
/// acts by itself; the owning flow re-reads the item from the server and always names its own issuer.
@MainActor
enum AlertOpener {
    static func open(_ entry: AlertEntry, model: AppModel) async {
        guard let target = entry.target else { return }
        switch target.kind {
        case .interaction:
            if let id = InteractionID(target.id) { await model.openInteraction(id) }
        case .approveDelivery:
            let approve = AppEnvironment.shared.approve
            await approve.refresh()
            guard let prompt = approve.prompts.first(where: { $0.id.uuidString.lowercased() == target.id }) else {
                model.toast = "That request is no longer waiting."
                await model.alerts.refresh()
                return
            }
            model.organization.open(itemFrom: prompt.business.id)
            model.organization.beginSensitiveFlow()
            approve.present(prompt)
        case .verification:
            guard let id = VerificationRequestID(target.id) else { return }
            if let business = entry.business?.id { model.organization.open(itemFrom: business) }
            model.organization.beginSensitiveFlow()
            AppEnvironment.shared.verification.presented = id
        case .profileRequest:
            guard let id = ProfileRequestID(target.id) else { return }
            if let business = entry.business?.id { model.organization.open(itemFrom: business) }
            model.organization.beginSensitiveFlow()
            AppEnvironment.shared.profile.presentedRequest = id
        case .securityNotice:
            await model.securityNotices.load()
        case .unknown:
            break
        }
    }
}
