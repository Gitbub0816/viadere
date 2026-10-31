import Foundation
import ViadereCore

/// How a message card from a business is decorated (WP-2.6, spec C4.4): an accent line from the kit at most. The sender's identity, the
/// name from Viadere's verified directory and the verified badge, never comes from the kit and is always drawn with the protected palette,
/// so a brand can decorate a card but never obscure or imitate who sent it.
public struct MessageCardDecoration: Sendable, Hashable {
    /// Sanitized verified display name (`BusinessSummary.safeName`).
    public var senderName: String
    public var isVerified: Bool
    /// The accent line per appearance after the contrast clamp; `nil` = no line (neutral).
    public var accentLight: BrandColor?
    public var accentDark: BrandColor?
    /// The palette the name and verified badge use: always the protected (neutral) one.
    public var identityPalette: BrandStyleResolution

    public static func make(business: BusinessSummary, brand: BrandKitStore?) -> MessageCardDecoration {
        let resolved = brand?.resolution(for: business.id, surface: .messageCard) ?? .neutral(business.id)
        var light: BrandColor?
        var dark: BrandColor?
        if let kit = resolved.kit {
            // The kit's accent if it set one and the clamp kept it, else its primary if kept; a replaced role draws no line.
            let palette = resolved.style.palette
            let role: BrandTokenRole = kit.tokens.accent != nil ? .accent : .primary
            func color(_ p: ResolvedPalette) -> BrandColor { role == .accent ? p.accent : p.primary }
            light = palette.overriddenLight.contains(role) ? nil : color(palette.light)
            dark = palette.overriddenDark.contains(role) ? nil : color(palette.dark)
        }
        return MessageCardDecoration(senderName: business.safeName, isVerified: business.isVerified, accentLight: light, accentDark: dark,
                                     identityPalette: .neutral)
    }
}

/// The branded business home (WP-2.6): the kit's clamped style, a registered frame and the verified logo, around Viadere's own modules.
/// The verified profile block (name, verified badge, handle), every action, wording and navigation stay neutral and come from Viadere.
public struct BusinessHomeDecoration: Sendable, Hashable {
    public var style: BrandAppearanceStyle
    /// Verified logo bytes (`logo`, else `mark`) from the cache; `nil` = Viadere's monogram avatar.
    public var logo: Data?
    public var logoSlot: BrandAssetSlot?
    /// Name and verified badge: from the verified directory, protected palette.
    public var name: String
    public var isVerified: Bool
    /// For VoiceOver: the logo is decorative when present ("Logo of {name}") and never replaces the name.
    public var logoAccessibilityLabel: String?

    public static func make(business: BusinessSummary, brand: BrandKitStore?) -> BusinessHomeDecoration {
        let resolved = brand?.resolution(for: business.id, surface: .businessHome) ?? .neutral(business.id)
        var logo: Data?
        var slot: BrandAssetSlot?
        if let kit = resolved.kit, let brand {
            for candidate in [BrandAssetSlot.logo, .mark] {
                if let ref = kit.assets[candidate], ref.fits(candidate), let data = brand.verifiedAsset(ref) {
                    logo = data
                    slot = candidate
                    break
                }
            }
        }
        return BusinessHomeDecoration(style: resolved.style, logo: logo, logoSlot: slot, name: business.safeName, isVerified: business.isVerified,
                                      logoAccessibilityLabel: logo == nil ? nil : "Logo of \(business.safeName)")
    }
}

/// The in-app Wallet pass card accent (docs/WALLET.md "Brand kits on passes"): the kit's clamped `primary` (else Viadere's) as the card's
/// accent strip. The pass's own fields, barcode, Beta label and the "In Wallet" state are unaffected; server-signed pass colors are
/// unchanged (out of scope).
public struct WalletPassBrandAccent: Sendable, Hashable {
    public var light: BrandColor?
    public var dark: BrandColor?

    public init(light: BrandColor?, dark: BrandColor?) {
        self.light = light
        self.dark = dark
    }

    /// Viadere's own card (no strip).
    public static let none = WalletPassBrandAccent(light: nil, dark: nil)

    public static func make(business: BusinessID?, brand: BrandKitStore?) -> WalletPassBrandAccent {
        guard let business, let resolved = brand?.resolution(for: business, surface: .walletPass), resolved.isBranded else {
            return WalletPassBrandAccent(light: nil, dark: nil)
        }
        let palette = resolved.style.palette
        return WalletPassBrandAccent(light: palette.overriddenLight.contains(.primary) ? nil : palette.light.primary,
                                     dark: palette.overriddenDark.contains(.primary) ? nil : palette.dark.primary)
    }
}

/// What the approval sheet shows, as plain data (the "snapshot" the hostile-token tests compare). It is built from the approval view model
/// and the decoration of the `.approval` surface, which is neutral by construction: no Brand Kit input reaches the sheet's text, buttons,
/// risk chips, verified badge or colors (spec B2.4, D3 "Misleading branded approvals").
public struct ApprovalSheetSnapshot: Sendable, Hashable {
    public var businessName: String
    public var isVerified: Bool
    public var title: String
    public var headline: String
    public var details: [PresentedDetail]
    public var riskLabels: [String]
    public var approveTitle: String
    public var denyTitle: String
    public var effect: String?
    public var style: BrandAppearanceStyle

    @MainActor
    public static func make(_ model: ApprovalViewModel, brand: BrandKitStore?) -> ApprovalSheetSnapshot {
        let interaction = model.interaction
        let surface: BrandSurface = interaction.kind == .authenticate ? .signIn : .approval
        let style = brand?.resolution(for: model.envelope.business.id, surface: surface, interactionId: interaction.id).style ?? .neutral
        let isAuth = interaction.kind == .authenticate || interaction.kind == .authorize
        return ApprovalSheetSnapshot(businessName: model.envelope.business.safeName, isVerified: model.envelope.business.isVerified,
                                     title: model.title, headline: model.headline, details: model.details,
                                     riskLabels: model.risks.map(\.label), approveTitle: isAuth ? "Approve" : "Confirm",
                                     denyTitle: isAuth ? "Deny" : "Decline", effect: model.effect, style: style)
    }
}
