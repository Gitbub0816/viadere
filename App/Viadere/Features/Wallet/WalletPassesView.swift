import SwiftUI
import ViadereCore
import ViadereKit

/// Every Wallet pass the server issued to this person (loyalty cards, offers, tickets, reservations), current first. Each opens a
/// detail with Apple's add button or the "In Wallet" state, and the pass's code for showing it from the app. Logic and wording live
/// in `WalletPassesViewModel` / `WalletPassPresentation` (ViadereKit, tested); this file only lays them out.
struct WalletPassesView: View {
    @Bindable var model: AppModel
    @State private var passes: WalletPassesViewModel?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                ViadereHeader("Wallet passes", subtitle: "Cards, offers, tickets and reservations from your businesses") {
                    if passes?.showsBetaLabel ?? model.services.configuration.walletBetaLabel { ViadereBadge("Beta", kind: .pending) }
                }
                content
            }
            .padding(.horizontal, ViadereSpace.screen)
            .padding(.bottom, ViadereSpace.xl)
        }
        .scrollIndicators(.hidden)
        .viadereScreenBackground()
        .task {
            if passes == nil { passes = WalletPassesViewModel(services: model.services, wallet: model.wallet) }
            await passes?.load()
        }
        .refreshable { await passes?.load() }
    }

    private var names: [BusinessID: String] {
        Dictionary(model.businesses.directory.map { ($0.business.id, $0.business.safeName) }, uniquingKeysWith: { first, _ in first })
    }

    @ViewBuilder private var content: some View {
        if let vm = passes {
            if vm.isLoading && !vm.hasLoaded {
                ViadereLoading().frame(maxWidth: .infinity).padding(.top, ViadereSpace.xxl)
            } else if vm.hasLoaded && vm.passes.isEmpty {
                ViadereEmptyState("No passes yet", message: "When you add a loyalty card, an offer or a ticket to Wallet, or a business sends you one, it appears here.")
                    .padding(.top, ViadereSpace.xl)
            } else {
                section("Current", vm.current, vm)
                section("Used or ended", vm.past, vm)
            }
            if let error = vm.errorMessage { ViadereNotice(error, kind: .warning).padding(.top, ViadereSpace.m) }
        } else {
            ViadereLoading().frame(maxWidth: .infinity).padding(.top, ViadereSpace.xxl)
        }
    }

    @ViewBuilder private func section(_ title: String, _ list: [WalletPassMetadata], _ vm: WalletPassesViewModel) -> some View {
        if !list.isEmpty {
            ViadereSectionHeader(title)
            ViadereRowGroup {
                ForEach(Array(list.enumerated()), id: \.element.id) { index, pass in
                    let presentation = vm.presentation(for: pass, businessName: names[pass.businessId])
                    NavigationLink {
                        WalletPassDetailView(passId: pass.id, passes: vm, wallet: model.wallet, businessName: names[pass.businessId])
                    } label: {
                        ViadereRow(presentation.businessName, subtitle: "\(presentation.kindTitle) · \(presentation.statusText)") {
                            ViadereIconTile(systemName: presentation.symbol)
                        }
                        .accessibilityLabel(Text(presentation.accessibilityLabel))
                    }
                    .buttonStyle(.plain)
                    if index < list.count - 1 { ViadereHairline(inset: 50) }
                }
            }
        }
    }
}

/// One pass: a charcoal card in the brand's colors, the Wallet action (Apple's add button, or "In Wallet"), and the code to show
/// when it is still valid. The code is the same signed code the pass carries; it identifies the pass, never the person.
struct WalletPassDetailView: View {
    let passId: WalletPassID
    let passes: WalletPassesViewModel
    let wallet: WalletPassCoordinator
    let businessName: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: ViadereSpace.l) {
                if let pass = passes.pass(passId) {
                    let presentation = passes.presentation(for: pass, businessName: businessName)
                    passCard(presentation)
                    WalletPassAction(pass: pass, wallet: wallet)
                    if let code = presentation.scanCode {
                        VStack(spacing: ViadereSpace.s) {
                            QRCodeView(payload: code, size: 220)
                                .accessibilityLabel(Text("Code for \(presentation.businessName) to scan"))
                            if let instructions = presentation.codeInstructions {
                                Text(instructions)
                                    .font(ViadereType.subhead)
                                    .foregroundStyle(ViadereColor.textSecondary)
                                    .multilineTextAlignment(.center)
                            }
                        }
                        .frame(maxWidth: .infinity)
                    }
                    Text("Viadere never puts your name, phone number or e-mail on a pass. Updates to it come from \(presentation.businessName) and are never ads.")
                        .font(ViadereType.footnote)
                        .foregroundStyle(ViadereColor.textTertiary)
                } else {
                    ViadereEmptyState("Pass not found", message: "It may have been removed. Pull to refresh the list.")
                }
            }
            .padding(.horizontal, ViadereSpace.screen)
            .padding(.vertical, ViadereSpace.l)
        }
        .scrollIndicators(.hidden)
        .viadereScreenBackground()
    }

    private func passCard(_ presentation: WalletPassPresentation) -> some View {
        let shape = RoundedRectangle(cornerRadius: ViadereRadius.card, style: .continuous)
        return VStack(alignment: .leading, spacing: ViadereSpace.s) {
            HStack {
                Image(systemName: presentation.symbol)
                    .font(.system(size: 17, weight: .medium))
                    .foregroundStyle(Color(red: 0.788, green: 0.663, blue: 0.431))
                    .accessibilityHidden(true)
                Text(presentation.kindTitle.uppercased())
                    .font(ViadereType.caption)
                    .foregroundStyle(Color(red: 0.788, green: 0.663, blue: 0.431))
                Spacer()
                if passes.showsBetaLabel {
                    Text("BETA").font(ViadereType.caption).foregroundStyle(Color(red: 0.788, green: 0.663, blue: 0.431).opacity(0.8))
                }
            }
            Text(presentation.businessName)
                .font(ViadereType.title)
                .foregroundStyle(Color(red: 0.969, green: 0.953, blue: 0.922))
            Text(presentation.statusText)
                .font(ViadereType.subhead)
                .foregroundStyle(Color(red: 0.969, green: 0.953, blue: 0.922).opacity(0.75))
        }
        .padding(ViadereSpace.l)
        .frame(maxWidth: .infinity, alignment: .leading)
        // Charcoal, ivory and champagne: the same colors the server puts on the pass itself.
        .background(shape.fill(Color(red: 0.122, green: 0.122, blue: 0.122)))
        .overlay(shape.strokeBorder(ViadereColor.hairline, lineWidth: 1))
        .accessibilityElement(children: .combine)
        .accessibilityLabel(Text(presentation.accessibilityLabel))
    }
}

#if DEBUG
#Preview("Wallet passes") {
    PreviewHost { services in
        NavigationStack {
            WalletPassesView(model: AppModel(services: services, walletLibrary: MockWalletLibrary()))
        }
    }
}
#endif
