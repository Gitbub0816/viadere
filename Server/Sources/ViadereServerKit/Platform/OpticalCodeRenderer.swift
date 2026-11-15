import Foundation
import ViadereCore

/// The one place the server turns a link into an optical code (docs/SECURITY.md §2.105).
///
/// The entry points take different style types on purpose. `viadere` draws Viadere's own surfaces and accepts `ViadereCodeStyle` only;
/// `business` draws a business's connect and install codes and accepts `BusinessCodeStyle` only. Neither type converts into the other,
/// so a business style cannot reach a sign-in, approval or verification page by a mistake in a caller.
///
/// The payload is encoded before any style is looked at: styling changes how marks are painted, never which marks exist.
enum OpticalCodeRenderer {
    struct Rendered: Sendable {
        var svg: String
        var symbology: BusinessCodeStyle.Symbology
    }

    /// A code on one of Viadere's own surfaces.
    static func viadere(_ text: String, style: ViadereCodeStyle = .concept, label: String) throws -> String {
        try CKeySymbol.encode(text, level: .medium).svg(style: style.ckey, label: label)
    }

    /// A business's own code in the style it stored. `label` is the accessible name; it is escaped by the encoders.
    static func business(_ text: String, style: BusinessCodeStyle, label: String) throws -> Rendered {
        if let ckey = style.ckeyStyle {
            return Rendered(svg: try CKeySymbol.encode(text, level: .medium).svg(style: ckey, label: label), symbology: .ckey)
        }
        // A QR style, or (never expected) a custom CKey style that stopped validating: fall back to QR, which every phone reads.
        let colors = style.qrColors ?? (QRCodeColorPolicy.defaultDark, QRCodeColorPolicy.defaultLight)
        let qr = try QRCode.encode(text, errorCorrection: .medium)
        return Rendered(svg: qr.svg(border: QRCodeColorPolicy.quietZoneModules, dark: colors.dark.hex, light: colors.light.hex, title: label), symbology: .qr)
    }

    /// The plain QR code that always accompanies a business's code: a phone camera cannot read a CKey.
    static func plainQR(_ text: String, label: String) throws -> String {
        try QRCode.encode(text, errorCorrection: .medium).svg(border: QRCodeColorPolicy.quietZoneModules, title: label)
    }
}
