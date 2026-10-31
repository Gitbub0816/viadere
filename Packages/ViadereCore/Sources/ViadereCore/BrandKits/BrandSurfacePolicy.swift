import Foundation

/// Where a Brand Kit may show beyond the app's business home (WP-2.7; spec B2.4, B5; SECURITY.md §2.93 "Surfaces"). Pure and shared:
/// the server applies it when it builds a notification, the app and its extensions apply it again when they render.
///
/// * **Security requests are never branded.** Sign-in approvals, payment authorizations and anything of purpose `security` or
///   `accountService`, and any interaction kind this build does not know, render in Viadere's neutral style with no business art. A
///   look-alike brand must never be able to dress up an approval prompt.
/// * **Notification attachment:** only the kit's approved `logo` (else `mark`), only a reference that fits its slot, never `background`
///   or `art`.
/// * **Live Activity accent:** only the kit's `accent` token, and only after the contrast clamp kept it; otherwise Viadere's accent.
public enum BrandSurfacePolicy {
    /// Whether any branding may apply to an interaction of this purpose and kind.
    public static func allowsBranding(purpose: InteractionPurpose, kind: InteractionKind) -> Bool {
        switch purpose {
        case .security, .accountService: return false
        case .transactional, .support, .marketing, .rewards: break
        }
        switch kind {
        case .authenticate, .authorize, .unknown: return false
        case .confirm, .choose, .acknowledge, .reply, .status, .reward, .ticket, .message: return true
        }
    }

    /// The image a notification may attach for this interaction, or `nil` (no attachment: the system shows the app icon).
    public static func notificationAttachment(kit: BrandKit?, purpose: InteractionPurpose, kind: InteractionKind) -> (slot: BrandAssetSlot, asset: BrandAssetRef)? {
        guard let kit, allowsBranding(purpose: purpose, kind: kind) else { return nil }
        for slot in [BrandAssetSlot.logo, .mark] {
            if let ref = kit.assets[slot], ref.fits(slot) { return (slot, ref) }
        }
        return nil
    }

    /// The accent color a Live Activity may use, or `nil` for Viadere's own accent. Only the `accent` role, only when it survived the
    /// contrast clamp in `appearance`; every other part of the activity (title, status, actions) stays neutral.
    public static func liveActivityAccent(kit: BrandKit?, purpose: InteractionPurpose, kind: InteractionKind, appearance: BrandAppearance) -> BrandColor? {
        guard let kit, allowsBranding(purpose: purpose, kind: kind), let accent = kit.tokens.accent else { return nil }
        let resolution = ContrastPolicy.resolve(kit.tokens)
        let overridden = appearance == .light ? resolution.overriddenLight : resolution.overriddenDark
        guard !overridden.contains(.accent) else { return nil }
        return resolution.palette(appearance).accent == accent ? accent : nil
    }
}

extension BrandKit {
    /// The per-kit rules of `BrandManifest.validationIssues` (identifier, sanitized name without banned topics, a registered frame, assets
    /// that fit their slots), for the Studio and the server when a kit is saved. `frameAt` additionally requires the frame to be available
    /// at that time.
    public func validationIssues(frames: FrameRegistry = .v1, frameAt: Date? = nil) -> [ContractIssue] {
        var issues: [ContractIssue] = []
        if !ContractIdentifier.isValid(kitId) { issues.append(ContractIssue(code: "invalid_identifier", path: "kit_id")) }
        if name.trimmingCharacters(in: .whitespaces).isEmpty || DisplayTextSanitizer.violation(of: name, maxCharacters: 40, identity: true) != nil
            || !LoopContentRules.topics(in: name).isEmpty {
            issues.append(ContractIssue(code: "invalid_text", path: "name"))
        }
        if let frame = frameId {
            if frames.definition(frame) == nil {
                issues.append(ContractIssue(code: "unknown_frame", path: "frame_id"))
            } else if let at = frameAt, frames.resolve(frame, at: at) == nil {
                issues.append(ContractIssue(code: "frame_unavailable", path: "frame_id"))
            }
        }
        for slot in BrandAssetSlot.allCases {
            if let ref = assets[slot], !ref.fits(slot) { issues.append(ContractIssue(code: "invalid_asset", path: "assets.\(slot.rawValue)")) }
        }
        return issues
    }
}
