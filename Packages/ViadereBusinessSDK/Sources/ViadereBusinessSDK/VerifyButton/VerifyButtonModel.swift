import Foundation
import ViadereCore

// The platform-neutral part of the "Verify with Viadere" button for iOS (`VerifyWithViadereButton`, `VerifyWithViadereUIButton`): what the button
// shows, how it hands off, and the QR-first panel as a state machine. Pure Swift, tested on Linux. The web component
// (`Server/Public/verify-button/v1/viadere-verify.js`) and the Android library (`Packages/android/viadere-verify`) implement the same table
// (`docs/VERIFY-BUTTON.md`, "Hand-off").
//
// The button runs in your app; it never holds an API key. Your app gets the session's `link` from **your** server (which created it with
// `createVerificationSession`), and your server learns the outcome from Viadere's signed result, never from the app.

/// The session the button opens: a Viadere session link (`https://viadere.com/v/{CODE}`) checked against the allowed link domains.
public struct VerifyButtonSession: Sendable, Hashable {
    /// Production and the staging web domain.
    public static let defaultDomains: [LinkDomain] = [.production, LinkDomain("viadere.cksites.dev")!]

    public let link: URL
    /// Canonical code (eight characters).
    public let code: String
    public let expiresAt: Date?

    /// `nil` unless `link` is exactly a session link on one of `allowedDomains` (https, `/v/{CODE}`, no query, no fragment).
    public init?(link: String, expiresAt: Date? = nil, allowedDomains: [LinkDomain] = Self.defaultDomains) {
        guard let url = URL(string: link), let code = allowedDomains.lazy.compactMap({ VerificationSessionLink.parse(url, domain: $0) }).first else { return nil }
        self.link = url
        self.code = code
        self.expiresAt = expiresAt
    }

    public init?(ticket: VerificationSessionTicket, allowedDomains: [LinkDomain] = Self.defaultDomains) {
        guard let session = VerifyButtonSession(link: ticket.link, expiresAt: ticket.expiresAt, allowedDomains: allowedDomains), session.code == ticket.code else { return nil }
        self = session
    }

    /// `ABCD-EFGH`, what the person types into the app.
    public var displayCode: String { VerificationSessionCode.display(code) }
    /// `A B C D E F G H`, for VoiceOver.
    public var spokenCode: String { code.map(String.init).joined(separator: " ") }
    /// The QR content: the link itself.
    public var qrPayload: String { link.absoluteString }

    public func isExpired(at now: Date) -> Bool { expiresAt.map { $0 <= now } ?? false }
}

/// The flow a button starts. Only `verify` exists; a sign-in flow adds a case and its copy here (the button and panel are generic).
public enum VerifyButtonFlow: String, Sendable, CaseIterable {
    case verify

    public var label: String { "Verify with Viadere" }
    public var title: String { "Verify with Viadere" }
    public var scanPrompt: String { "Scan with your phone\u{2019}s camera" }
    public var explanation: String {
        "Viadere opens and shows you which verified business is asking and exactly what it would learn. Nothing is shared until you approve."
    }
}

public enum VerifyButtonVariant: String, Sendable, CaseIterable {
    /// Charcoal (ivory in dark mode): the default.
    case filled
    /// Ivory with a silver hairline: for dark or photographic backgrounds.
    case ivory
    /// Transparent with a charcoal (dark mode: ivory) border.
    case outline
}

public enum VerifyButtonSize: String, Sendable, CaseIterable {
    case small, medium, large

    /// Height in points; never below 44 except `small`, which is for dense layouts with its own hit-area padding.
    public var height: Double {
        switch self {
        case .small: 36
        case .medium: 44
        case .large: 52
        }
    }

    public var fontSize: Double {
        switch self {
        case .small: 13
        case .medium: 15
        case .large: 17
        }
    }

    /// The minimum tappable area the button reserves (Apple HIG: 44 × 44 pt).
    public var minimumHitTarget: Double { 44 }
}

public enum VerifyButtonDisplay: String, Sendable, CaseIterable {
    case label
    /// The mark only; the accessibility label is still the flow's label.
    case iconOnly
}

/// The button's colours (sRGB hex), the same as `viadere-verify.css` and the asset kit (`Design/embeds/`).
public struct VerifyButtonColors: Sendable, Hashable {
    public let background: UInt32?
    public let foreground: UInt32
    public let border: UInt32

    public static func of(_ variant: VerifyButtonVariant, dark: Bool) -> VerifyButtonColors {
        switch (variant, dark) {
        case (.filled, false): VerifyButtonColors(background: 0x1F1E1C, foreground: 0xF5F2EC, border: 0x1F1E1C)
        case (.filled, true): VerifyButtonColors(background: 0xF3F0EA, foreground: 0x1F1E1C, border: 0xF3F0EA)
        case (.ivory, _): VerifyButtonColors(background: 0xF5F2EC, foreground: 0x1F1E1C, border: 0xC9C4BB)
        case (.outline, false): VerifyButtonColors(background: nil, foreground: 0x1F1E1C, border: 0x1F1E1C)
        case (.outline, true): VerifyButtonColors(background: nil, foreground: 0xF3F0EA, border: 0xF3F0EA)
        }
    }
}

// MARK: - Hand-off

/// Where the button runs.
public enum VerifyHandoffDevice: Sendable, Hashable {
    /// iPhone, iPad, Android phone or tablet: the operating system can hand a universal link / App Link to the Viadere app.
    case handheld
    /// A Mac or PC: no app to hand off to, so the QR-first panel (scan with your phone).
    case computer
}

public enum VerifyHandoffAction: Sendable, Hashable {
    /// Open the link **only if the Viadere app claims it** (iOS `universalLinksOnly`, Android `FLAG_ACTIVITY_REQUIRE_NON_BROWSER`).
    case openInApp(URL)
    /// Show the QR-first panel.
    case showPanel
    /// The app took over; nothing more to do here.
    case handedOff
    /// The code expired: ask your server for a new session.
    case expired
}

/// The owner's rule: hand off automatically when the app can take the link; otherwise show the QR first, with a button for the other options.
public enum VerifyHandoffPlanner {
    public static func onTap(device: VerifyHandoffDevice, session: VerifyButtonSession, now: Date = Date()) -> VerifyHandoffAction {
        if session.isExpired(at: now) { return .expired }
        switch device {
        case .handheld: return .openInApp(session.link)
        case .computer: return .showPanel
        }
    }

    /// After `openInApp`: the app opened the link, or it is not installed (then the panel, whose options include getting the app).
    public static func afterOpenInApp(opened: Bool) -> VerifyHandoffAction { opened ? .handedOff : .showPanel }
}

// MARK: - Panel

public enum VerifyPanelOption: String, Sendable, CaseIterable {
    case openOnThisDevice
    case enterCode
    /// Only when your app can reach this customer's phone through your server (an existing connection: your server creates an ordinary
    /// verification request for their `subject_ref`, which Viadere delivers as a push). The button never sends anything itself.
    case sendToPhone
    case getApp

    public var title: String {
        switch self {
        case .openOnThisDevice: "Open Viadere on this device"
        case .enterCode: "Enter a code in the app"
        case .sendToPhone: "Send to my phone"
        case .getApp: "Get the Viadere app"
        }
    }

    public var detail: String {
        switch self {
        case .openOnThisDevice: "If the Viadere app is installed here."
        case .enterCode: "Type a short code into Viadere on your phone."
        case .sendToPhone: "Get a Viadere notification on the phone linked to your account."
        case .getApp: "Free on the App Store. Then scan the code again."
        }
    }
}

/// The QR-first panel as a state machine (the SwiftUI and UIKit panels render it; tests drive it).
public struct VerifyPanelState: Sendable, Hashable {
    public enum Screen: Sendable, Hashable { case qr, options }

    public enum Effect: Sendable, Hashable {
        case none
        /// Open the session link in the system (the app if it claims it, otherwise the landing page with the store link).
        case open(URL)
        /// Your `onSendToPhone` handler: ask your server to send the request to this customer's phone.
        case sendToPhone
        case dismiss
    }

    public private(set) var screen: Screen = .qr
    public private(set) var showsCode = false
    /// An announcement for VoiceOver / the status line.
    public private(set) var status: String?
    public let options: [VerifyPanelOption]
    public let session: VerifyButtonSession

    public init(session: VerifyButtonSession, sendToPhone: Bool) {
        self.session = session
        options = VerifyPanelOption.allCases.filter { $0 != .sendToPhone || sendToPhone }
    }

    public mutating func chooseAnotherOption() { screen = .options }

    public mutating func backToQR() {
        screen = .qr
        showsCode = false
        status = nil
    }

    public mutating func select(_ option: VerifyPanelOption) -> Effect {
        guard options.contains(option) else { return .none }
        switch option {
        case .openOnThisDevice, .getApp:
            return .open(session.link)
        case .enterCode:
            showsCode = true
            status = "Your code is \(session.spokenCode)."
            return .none
        case .sendToPhone:
            status = "Check your phone for a notification from Viadere."
            return .sendToPhone
        }
    }

    public func close() -> Effect { .dismiss }
}

// MARK: - The mark

/// The Viadere mark as path commands (absolute `M`, `L`, `C`, `Z` in the 321.71 × 146 view box), the monochrome artwork of
/// `Design/svg/viadere-mark-mono-dark.svg`: the back faces at 62 % opacity, the three front faces and the dot.
public enum VerifyButtonMark {
    public static let viewBox = (width: 321.71, height: 146.0)
    public static let dot = (x: 155.21, y: 20.5, radius: 20.5)
    public static let backFacesOpacity = 0.62

    public static let backFaces = "M0 46C31.34 46 52.61 53.08 58.62 61.38L88.74 102.99L115.22 66.49C130.87 44.9 156.4 45.68 170.7 68.18L189.31 97.44L215.59 61.52C231.34 40 256.71 40.99 270.74 63.66L321.71 146C290.37 146 271.7 141.91 268.73 137.12L240.79 91.98L213.57 129.17C198.67 149.53 174.45 148.74 160.91 127.45L141.09 96.28L116.14 130.69C101.32 151.11 76.1 151.1 61.31 130.67L0 46Z"
    public static let frontFaces = [
        "M0 46C31.34 46 52.61 53.08 58.62 61.38L88.74 102.99C101.18 120.16 102.65 139.14 118.23 127.81L116.14 130.69C101.32 151.11 76.1 151.1 61.31 130.67L0 46Z",
        "M113.12 69.37L115.22 66.49C130.87 44.9 156.4 45.68 170.7 68.18L189.31 97.44C200.84 115.58 199.82 137.73 215.67 126.3L213.57 129.17C198.67 149.53 174.45 148.74 160.91 127.45L141.09 96.28C129.64 78.27 128.81 57.95 113.12 69.37Z",
        "M213.49 64.4L215.59 61.52C231.34 40 256.71 40.99 270.74 63.66L321.71 146C290.37 146 271.7 141.91 268.73 137.12L240.79 91.98C229.56 73.83 229.23 53.05 213.49 64.4Z",
    ]

    public enum Command: Sendable, Hashable {
        case move(Double, Double)
        case line(Double, Double)
        case curve(Double, Double, Double, Double, Double, Double)
        case close
    }

    /// Parses the absolute `M L C Z` subset used by the artwork; `nil` for anything else.
    public static func commands(_ path: String) -> [Command]? {
        var tokens: [String] = []
        var current = ""
        for character in path {
            if "MLCZ".contains(character) {
                if !current.isEmpty { tokens.append(current) }
                tokens.append(String(character))
                current = ""
            } else if character == " " || character == "," {
                if !current.isEmpty { tokens.append(current) }
                current = ""
            } else if character == "-" {
                if !current.isEmpty { tokens.append(current) }
                current = "-"
            } else if character.isNumber || character == "." {
                current.append(character)
            } else {
                return nil
            }
        }
        if !current.isEmpty { tokens.append(current) }
        var out: [Command] = []
        var index = 0
        func numbers(_ count: Int) -> [Double]? {
            guard index + count <= tokens.count else { return nil }
            let values = tokens[index..<index + count].compactMap(Double.init)
            guard values.count == count else { return nil }
            index += count
            return values
        }
        while index < tokens.count {
            let op = tokens[index]
            index += 1
            switch op {
            case "M": guard let n = numbers(2) else { return nil }; out.append(.move(n[0], n[1]))
            case "L": guard let n = numbers(2) else { return nil }; out.append(.line(n[0], n[1]))
            case "C": guard let n = numbers(6) else { return nil }; out.append(.curve(n[0], n[1], n[2], n[3], n[4], n[5]))
            case "Z": out.append(.close)
            default: return nil
            }
        }
        return out
    }
}
