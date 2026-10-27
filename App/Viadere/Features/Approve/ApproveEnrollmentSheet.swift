import SwiftUI
import ViadereCore
import ViadereKit

/// Setting up approvals with a business (APP-002): the person typed or scanned the business's code; we show who it is, what the key is for,
/// and the fingerprint of the business's root key to compare with what the business shows on its own screen.
struct ApproveEnrollmentSheet: View {
    @Bindable var controller: ApproveController
    let code: String
    let rootKid: String?
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 0) {
            ViadereGrabber()
            ScrollView {
                VStack(alignment: .leading, spacing: ViadereSpace.l) {
                    Text("Set up approvals").font(ViadereType.display).foregroundStyle(ViadereColor.textPrimary)
                    if let offer = controller.offer { offerContent(offer) } else if controller.phase == .working { ViadereLoading() } else { failure }
                }
                .padding(.horizontal, ViadereSpace.screen)
                .padding(.top, ViadereSpace.m)
                .padding(.bottom, ViadereSpace.l)
            }
            .scrollIndicators(.hidden)
        }
        .background(ViadereColor.background)
        .task { await controller.lookup(code: code, expectedRootKid: rootKid) }
        .onDisappear { controller.cancelOffer() }
    }

    @ViewBuilder private func offerContent(_ offer: EnrollmentOffer) -> some View {
        let business = offer.preview.business
        HStack(spacing: ViadereSpace.s) {
            ViadereAvatar(name: business.safeName, size: 48, isVerified: business.isVerified)
            VStack(alignment: .leading, spacing: 2) {
                Text(business.safeName).font(ViadereType.headline).foregroundStyle(ViadereColor.textPrimary)
                Text(offer.preview.capability == .transactionApprove ? "Payments and transfers" : "Sign-ins").font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
            }
        }
        ViadereNotice("This creates a key just for \(business.safeName), kept in this phone's secure hardware. No other business can use it or see that it exists.", kind: .info)
        ViadereRowGroup {
            ViadereValueRow("Protected by", offer.preview.requiredAssurance == .biometric ? "Face ID or Touch ID" : "Face ID, Touch ID or passcode")
            ViadereHairline()
            ViadereValueRow("Business key", offer.rootFingerprint)
            ViadereHairline()
            ViadereValueRow("Checked against", offer.trust == .verifiedOutOfBand ? "The link you opened" : "Viadere's public log")
        }
        if offer.trust == .firstUse {
            ViadereNotice("Compare the business key above with the one \(business.safeName) shows on its own screen. If they differ, stop.", kind: .warning)
        }
        if let message = controller.message { ViadereNotice(message, kind: .danger) }
        VStack(spacing: ViadereSpace.xs) {
            Button(offer.preview.requiredAssurance == .biometric ? "Set up with Face ID" : "Set up") {
                Task { if await controller.confirmEnrollment() { dismiss() } }
            }
            .buttonStyle(.viadere(.primary))
            .disabled(controller.phase == .working)
            Button("Not now") { dismiss() }.buttonStyle(.viadere(.quiet))
        }
    }

    private var failure: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.m) {
            ViadereNotice(controller.message ?? "We couldn't open this setup link. Ask the business for a new one.", kind: .danger)
            Button("Close") { dismiss() }.buttonStyle(.viadere(.secondary))
        }
    }
}
