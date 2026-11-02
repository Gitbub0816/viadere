#if canImport(SwiftUI) && canImport(CoreImage) && !os(watchOS)
import CoreImage
import CoreImage.CIFilterBuiltins
import SwiftUI
import ViadereCore
#if canImport(UIKit)
import UIKit
#endif

// SwiftUI "Verify with Viadere" button and its QR-first panel (Apple platforms only; the logic is `VerifyButtonModel.swift`, tested on Linux).
//
//     VerifyWithViadereButton(session: session) { await myServer.sendVerificationToPhone() }
//
// `session` comes from your server (`VerifyButtonSession(ticket:)` or `VerifyButtonSession(link:expiresAt:)`); the button opens it in the Viadere
// app when it is installed (universal links only) and otherwise shows the panel: a QR code to scan with a phone, and "Choose another option".

extension Color {
    init(viadereVerifyHex hex: UInt32) {
        self.init(.sRGB, red: Double((hex >> 16) & 0xFF) / 255, green: Double((hex >> 8) & 0xFF) / 255, blue: Double(hex & 0xFF) / 255, opacity: 1)
    }
}

/// One layer of the mark, scaled into the rect with its aspect ratio kept.
struct VerifyMarkShape: Shape {
    let paths: [String]
    let includeDot: Bool

    func path(in rect: CGRect) -> Path {
        let width = VerifyButtonMark.viewBox.width, height = VerifyButtonMark.viewBox.height
        let scale = min(rect.width / width, rect.height / height)
        let ox = rect.minX + (rect.width - width * scale) / 2, oy = rect.minY + (rect.height - height * scale) / 2
        func point(_ x: Double, _ y: Double) -> CGPoint { CGPoint(x: ox + x * scale, y: oy + y * scale) }
        var path = Path()
        for d in paths {
            for command in VerifyButtonMark.commands(d) ?? [] {
                switch command {
                case .move(let x, let y): path.move(to: point(x, y))
                case .line(let x, let y): path.addLine(to: point(x, y))
                case .curve(let x1, let y1, let x2, let y2, let x, let y): path.addCurve(to: point(x, y), control1: point(x1, y1), control2: point(x2, y2))
                case .close: path.closeSubpath()
                }
            }
        }
        if includeDot {
            let r = VerifyButtonMark.dot.radius * scale
            let c = point(VerifyButtonMark.dot.x, VerifyButtonMark.dot.y)
            path.addEllipse(in: CGRect(x: c.x - r, y: c.y - r, width: r * 2, height: r * 2))
        }
        return path
    }
}

/// The monochrome Viadere mark in the current foreground style (decorative: hidden from VoiceOver).
public struct VerifyWithViadereMark: View {
    public init() {}

    public var body: some View {
        ZStack {
            VerifyMarkShape(paths: [VerifyButtonMark.backFaces], includeDot: false).opacity(VerifyButtonMark.backFacesOpacity)
            VerifyMarkShape(paths: VerifyButtonMark.frontFaces, includeDot: true)
        }
        .aspectRatio(VerifyButtonMark.viewBox.width / VerifyButtonMark.viewBox.height, contentMode: .fit)
        .accessibilityHidden(true)
    }
}

/// Renders a QR code (level M) for the panel with Core Image.
enum VerifyQRCode {
    static func image(for text: String) -> CGImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 12, y: 12)) else { return nil }
        return CIContext(options: [.useSoftwareRenderer: false]).createCGImage(output, from: output.extent)
    }
}

/// Where this app runs, for the hand-off rule.
enum VerifyDevice {
    static var current: VerifyHandoffDevice {
        #if os(iOS) || os(visionOS)
        if ProcessInfo.processInfo.isiOSAppOnMac || ProcessInfo.processInfo.isMacCatalystApp { return .computer }
        return .handheld
        #else
        return .computer
        #endif
    }
}

/// Opens a link only if an installed app claims it as a universal link (never Safari).
enum VerifyAppOpener {
    @MainActor static func openInApp(_ url: URL) async -> Bool {
        #if canImport(UIKit) && !os(watchOS)
        return await UIApplication.shared.open(url, options: [.universalLinksOnly: true])
        #else
        return false
        #endif
    }

    @MainActor static func open(_ url: URL) {
        #if canImport(UIKit) && !os(watchOS)
        UIApplication.shared.open(url)
        #elseif canImport(AppKit)
        NSWorkspace.shared.open(url)
        #endif
    }
}

struct VerifyButtonStyle: ButtonStyle {
    let colors: VerifyButtonColors
    let size: VerifyButtonSize
    let iconOnly: Bool

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: size.fontSize, weight: .semibold))
            .lineLimit(1)
            .foregroundStyle(Color(viadereVerifyHex: colors.foreground))
            .padding(.horizontal, iconOnly ? 0 : size.height * 0.45)
            .frame(minWidth: size.height, minHeight: size.height)
            .frame(width: iconOnly ? size.height : nil)
            .background(Capsule().fill(colors.background.map { Color(viadereVerifyHex: $0) } ?? Color.clear))
            .overlay(Capsule().strokeBorder(Color(viadereVerifyHex: colors.border), lineWidth: 1))
            .opacity(configuration.isPressed ? 0.82 : 1)
            .contentShape(Capsule())
            .frame(minWidth: size.minimumHitTarget, minHeight: size.minimumHitTarget)
            .contentShape(Rectangle())
    }
}

/// The "Verify with Viadere" button.
public struct VerifyWithViadereButton: View {
    private let session: VerifyButtonSession
    private let flow: VerifyButtonFlow
    private let variant: VerifyButtonVariant
    private let size: VerifyButtonSize
    private let display: VerifyButtonDisplay
    private let onSendToPhone: (@MainActor () async -> Void)?
    private let onExpired: (@MainActor () -> Void)?

    @Environment(\.colorScheme) private var colorScheme
    @State private var panel: VerifyPanelState?

    /// - Parameters:
    ///   - onSendToPhone: offer "Send to my phone" (your server creates an ordinary verification request for this connected customer's
    ///     `subject_ref`; Viadere pushes it). Leave `nil` when your server cannot reach this person's phone.
    ///   - onExpired: the session's code expired; fetch a new one from your server.
    public init(session: VerifyButtonSession, flow: VerifyButtonFlow = .verify, variant: VerifyButtonVariant = .filled, size: VerifyButtonSize = .medium,
                display: VerifyButtonDisplay = .label, onSendToPhone: (@MainActor () async -> Void)? = nil, onExpired: (@MainActor () -> Void)? = nil) {
        self.session = session
        self.flow = flow
        self.variant = variant
        self.size = size
        self.display = display
        self.onSendToPhone = onSendToPhone
        self.onExpired = onExpired
    }

    public var body: some View {
        Button(action: tap) {
            HStack(spacing: size.fontSize * 0.55) {
                VerifyWithViadereMark().frame(width: size.fontSize * (display == .iconOnly ? 1.75 : 2))
                if display == .label { Text(flow.label) }
            }
        }
        .buttonStyle(VerifyButtonStyle(colors: VerifyButtonColors.of(variant, dark: colorScheme == .dark), size: size, iconOnly: display == .iconOnly))
        .accessibilityLabel(Text(flow.label))
        .accessibilityAddTraits(.isButton)
        .sheet(isPresented: Binding(get: { panel != nil }, set: { if !$0 { panel = nil } })) {
            if let state = panel {
                VerifyPanelView(state: state, flow: flow, onSendToPhone: onSendToPhone) { panel = nil }
                    .presentationDetents([.large])
            }
        }
    }

    @MainActor private func tap() {
        switch VerifyHandoffPlanner.onTap(device: VerifyDevice.current, session: session) {
        case .openInApp(let url):
            Task { @MainActor in
                let opened = await VerifyAppOpener.openInApp(url)
                if VerifyHandoffPlanner.afterOpenInApp(opened: opened) == .showPanel { present() }
            }
        case .showPanel: present()
        case .expired: onExpired?()
        case .handedOff: break
        }
    }

    @MainActor private func present() { panel = VerifyPanelState(session: session, sendToPhone: onSendToPhone != nil) }
}

/// The QR-first panel: the QR code, a short explanation, and "Choose another option".
public struct VerifyPanelView: View {
    @State private var state: VerifyPanelState
    private let flow: VerifyButtonFlow
    private let onSendToPhone: (@MainActor () async -> Void)?
    private let onDismiss: @MainActor () -> Void
    @Environment(\.colorScheme) private var colorScheme

    public init(state: VerifyPanelState, flow: VerifyButtonFlow = .verify, onSendToPhone: (@MainActor () async -> Void)? = nil, onDismiss: @escaping @MainActor () -> Void) {
        _state = State(initialValue: state)
        self.flow = flow
        self.onSendToPhone = onSendToPhone
        self.onDismiss = onDismiss
    }

    private var dark: Bool { colorScheme == .dark }
    private var surface: Color { Color(viadereVerifyHex: dark ? 0x1C1B1A : 0xFCFBF8) }
    private var text: Color { Color(viadereVerifyHex: dark ? 0xF3F0EA : 0x1F1E1C) }
    private var secondary: Color { Color(viadereVerifyHex: dark ? 0xA29D94 : 0x6B675F) }
    private var hairline: Color { Color(viadereVerifyHex: dark ? 0x4A4844 : 0xC9C4BB) }

    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack(spacing: 10) {
                    VerifyWithViadereMark().frame(width: 34)
                    Text(flow.title).font(.headline).accessibilityAddTraits(.isHeader)
                    Spacer()
                    Button { onDismiss() } label: { Image(systemName: "xmark").font(.body.weight(.semibold)).frame(width: 44, height: 44) }
                        .accessibilityLabel(Text("Close"))
                }
                switch state.screen {
                case .qr: qrScreen
                case .options: optionsScreen
                }
                if let status = state.status {
                    Text(status).font(.footnote).foregroundStyle(secondary).accessibilityAddTraits(.updatesFrequently)
                }
            }
            .padding(22)
        }
        .foregroundStyle(text)
        .background(surface.ignoresSafeArea())
    }

    private var qrScreen: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(flow.scanPrompt).font(.body.weight(.semibold))
            if let image = VerifyQRCode.image(for: state.session.qrPayload) {
                Image(decorative: image, scale: 1)
                    .interpolation(.none)
                    .resizable()
                    .scaledToFit()
                    .padding(8)
                    .background(RoundedRectangle(cornerRadius: 14).fill(Color.white))
                    .overlay(RoundedRectangle(cornerRadius: 14).strokeBorder(hairline))
                    .frame(maxWidth: 248)
                    .frame(maxWidth: .infinity)
                    .accessibilityElement()
                    .accessibilityLabel(Text("QR code to continue in the Viadere app"))
            }
            Text(flow.explanation).font(.subheadline).foregroundStyle(secondary)
            if let expires = state.session.expiresAt {
                Text("This code works until \(expires.formatted(date: .omitted, time: .shortened)).").font(.footnote).foregroundStyle(secondary)
            }
            secondaryButton("Choose another option") { state.chooseAnotherOption() }
        }
    }

    private var optionsScreen: some View {
        VStack(alignment: .leading, spacing: 8) {
            ForEach(state.options, id: \.self) { option in
                Button { handle(state.select(option)) } label: {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(option.title).font(.body.weight(.semibold))
                        Text(option.detail).font(.footnote).foregroundStyle(secondary)
                    }
                    .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 10)
                    .background(RoundedRectangle(cornerRadius: 14).fill(Color(viadereVerifyHex: dark ? 0x262523 : 0xFFFFFF)))
                    .overlay(RoundedRectangle(cornerRadius: 14).strokeBorder(hairline))
                }
                .buttonStyle(.plain)
            }
            if state.showsCode {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Open Viadere, choose Enter code and type")
                    Text(state.session.displayCode).font(.system(.title2, design: .monospaced).weight(.semibold)).kerning(2)
                        .accessibilityLabel(Text(state.session.spokenCode))
                }
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 14).fill(Color(viadereVerifyHex: dark ? 0x262523 : 0xF3F0EA)))
            }
            secondaryButton("Back to the QR code") { state.backToQR() }
        }
    }

    private func secondaryButton(_ title: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(title).font(.body.weight(.semibold)).frame(maxWidth: .infinity, minHeight: 44)
                .overlay(Capsule().strokeBorder(text, lineWidth: 1))
        }
        .buttonStyle(.plain)
    }

    @MainActor private func handle(_ effect: VerifyPanelState.Effect) {
        switch effect {
        case .none: break
        case .open(let url): VerifyAppOpener.open(url)
        case .sendToPhone:
            if let onSendToPhone { Task { @MainActor in await onSendToPhone() } }
        case .dismiss: onDismiss()
        }
    }
}
#endif
