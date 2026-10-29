import AVFoundation
import SwiftUI
import UIKit
import ViadereCore
import ViadereKit

/// Adds a one-time code: scan the QR code a site shows, paste an otpauth:// link, or type the setup key. Only valid authenticator codes are
/// accepted; anything else a QR code might carry (a link, text) is refused without being opened or shown as if it were trusted.
struct AddCodeSheet: View {
    let model: AuthenticatorViewModel
    let onClose: () -> Void
    enum Mode { case choose, scan, manual }
    @State private var mode: Mode = .choose
    @State private var issuer = ""
    @State private var account = ""
    @State private var secret = ""
    @State private var link = ""

    var body: some View {
        ZStack(alignment: .topTrailing) {
            switch mode {
            case .choose: choose
            case .scan: scanner
            case .manual: manual
            }
            if mode != .scan {
                ViadereIconButton(systemName: "xmark", label: "Close", action: onClose).padding(ViadereSpace.m)
            }
        }
        .viadereScreenBackground()
    }

    private var choose: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.m) {
            ViadereGrabber().frame(maxWidth: .infinity)
            Text("Add a code").font(ViadereType.display).foregroundStyle(ViadereColor.textPrimary).padding(.top, ViadereSpace.m)
            Text("On the site's two-step setup page, choose “authenticator app”. It shows a QR code and a setup key.")
                .font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
            Button { mode = .scan } label: { Label("Scan the QR code", systemImage: "qrcode.viewfinder") }.buttonStyle(.viadere(.primary))
            Button { mode = .manual } label: { Label("Enter the setup key", systemImage: "keyboard") }.buttonStyle(.viadere(.secondary))
            #if DEBUG
            // The file-based stand-in encourages exporting a plaintext credential file to Files. It is not shipped: release builds get the
            // system import (`ASCredentialImportManager`) once that is wired (see CredentialExchangeImport.swift).
            if #available(iOS 26.0, *) {
                CredentialExchangeImportButton(model: model, onDone: onClose)
            }
            #endif
            if let message = model.message { ViadereNotice(message, kind: .warning) }
            Spacer()
        }
        .padding(ViadereSpace.screen)
    }

    private var scanner: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            AuthenticatorQRScanner { text in
                Task {
                    if await model.addCode(uri: text) { onClose() } else { mode = .choose }
                }
            }
            .ignoresSafeArea()
            VStack {
                HStack { Spacer(); ViadereIconButton(systemName: "xmark", label: "Cancel scanning") { mode = .choose } }.padding(ViadereSpace.m)
                Spacer()
                Text("Point at the QR code on the site's setup page")
                    .font(ViadereType.subhead.weight(.medium)).foregroundStyle(.white)
                    .padding(.horizontal, ViadereSpace.l).padding(.vertical, ViadereSpace.s)
                    .background(Capsule().fill(.black.opacity(0.55))).padding(.bottom, ViadereSpace.xl)
            }
        }
    }

    private var manual: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: ViadereSpace.m) {
                ViadereGrabber().frame(maxWidth: .infinity)
                Text("Enter the setup key").font(ViadereType.display).foregroundStyle(ViadereColor.textPrimary).padding(.top, ViadereSpace.m)
                field("Site or service", text: $issuer, hint: "For example, Example Bank")
                field("Account", text: $account, hint: "Your username or email on that site")
                field("Setup key", text: $secret, hint: "Letters and numbers shown under the QR code", monospaced: true)
                Text("Or paste the otpauth:// link").font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                field("otpauth://…", text: $link, hint: nil, monospaced: true)
                if let message = model.message { ViadereNotice(message, kind: .warning) }
                Button("Add code") {
                    Task {
                        let added = link.isEmpty ? await model.addCode(issuer: issuer, account: account, secret: secret) : await model.addCode(uri: link)
                        if added { onClose() }
                    }
                }
                .buttonStyle(.viadere(.primary))
                .disabled(link.isEmpty && (account.isEmpty || secret.isEmpty))
                Button("Back") { mode = .choose }.buttonStyle(.viadere(.quiet))
            }
            .padding(ViadereSpace.screen)
        }
        .scrollDismissesKeyboard(.interactively)
    }

    private func field(_ placeholder: String, text: Binding<String>, hint: String?, monospaced: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: ViadereSpace.xxs) {
            TextField(placeholder, text: text)
                .font(monospaced ? ViadereType.code : ViadereType.body)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .padding(ViadereSpace.m)
                .background(RoundedRectangle(cornerRadius: ViadereRadius.card, style: .continuous).fill(ViadereColor.surface))
                .overlay(RoundedRectangle(cornerRadius: ViadereRadius.card, style: .continuous).strokeBorder(ViadereColor.hairline, lineWidth: 1))
            if let hint { Text(hint).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary) }
        }
    }
}

/// Camera scanner for authenticator QR codes. The payload is handed on as text and validated strictly by `OTPAuthURI`; it is never opened.
struct AuthenticatorQRScanner: UIViewControllerRepresentable {
    let onCode: (String) -> Void

    func makeUIViewController(context: Context) -> ScannerController {
        let controller = ScannerController()
        controller.onCode = onCode
        return controller
    }

    func updateUIViewController(_ uiViewController: ScannerController, context: Context) {}

    final class ScannerController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
        nonisolated(unsafe) var onCode: ((String) -> Void)?
        nonisolated(unsafe) private let session = AVCaptureSession()
        nonisolated(unsafe) private var delivered = false

        override func viewDidLoad() {
            super.viewDidLoad()
            Task { @MainActor in
                let granted: Bool
                switch AVCaptureDevice.authorizationStatus(for: .video) {
                case .authorized: granted = true
                case .notDetermined: granted = await AVCaptureDevice.requestAccess(for: .video)
                default: granted = false
                }
                guard granted, let device = AVCaptureDevice.default(for: .video), let input = try? AVCaptureDeviceInput(device: device),
                      session.canAddInput(input) else { return }
                session.addInput(input)
                let output = AVCaptureMetadataOutput()
                guard session.canAddOutput(output) else { return }
                session.addOutput(output)
                output.setMetadataObjectsDelegate(self, queue: .main)
                output.metadataObjectTypes = [.qr]
                let preview = AVCaptureVideoPreviewLayer(session: session)
                preview.videoGravity = .resizeAspectFill
                preview.frame = view.bounds
                view.layer.addSublayer(preview)
                Task.detached { [session] in session.startRunning() }
            }
        }

        override func viewDidLayoutSubviews() {
            super.viewDidLayoutSubviews()
            view.layer.sublayers?.forEach { $0.frame = view.bounds }
        }

        override func viewWillDisappear(_ animated: Bool) {
            super.viewWillDisappear(animated)
            let session = session
            Task.detached { session.stopRunning() }
        }

        nonisolated func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
            guard !delivered, let text = (metadataObjects.first as? AVMetadataMachineReadableCodeObject)?.stringValue else { return }
            delivered = true
            onCode?(text)
        }
    }
}
