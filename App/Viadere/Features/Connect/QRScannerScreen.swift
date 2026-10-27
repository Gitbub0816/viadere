import AVFoundation
import SwiftUI
import UIKit

/// Full-screen camera scanner for Viadere QR codes (`https://viadere.com/c/AF2345`). The camera is the OS's;
/// the payload is only ever handed to `ConnectViewModel.handleScanned`, which validates it strictly.
struct QRScannerScreen: View {
    let onCode: (String) -> Void
    let onClose: () -> Void
    @State private var status = AVCaptureDevice.authorizationStatus(for: .video)

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            switch status {
            case .authorized:
                QRScannerRepresentable(onCode: onCode).ignoresSafeArea()
                reticle
            case .notDetermined:
                ViadereLoading().task {
                    _ = await AVCaptureDevice.requestAccess(for: .video)
                    status = AVCaptureDevice.authorizationStatus(for: .video)
                }
            default:
                deniedState
            }
            VStack {
                HStack {
                    Spacer()
                    ViadereIconButton(systemName: "xmark", label: "Close scanner", action: onClose)
                }
                .padding(ViadereSpace.m)
                Spacer()
                if status == .authorized {
                    Text("Point at a Viadere QR code")
                        .font(ViadereType.subhead.weight(.medium))
                        .foregroundStyle(.white)
                        .padding(.horizontal, ViadereSpace.l)
                        .padding(.vertical, ViadereSpace.s)
                        .background(Capsule().fill(.black.opacity(0.55)))
                        .padding(.bottom, ViadereSpace.xl)
                }
            }
        }
    }

    private var reticle: some View {
        RoundedRectangle(cornerRadius: 28, style: .continuous)
            .strokeBorder(.white.opacity(0.85), style: StrokeStyle(lineWidth: 2, dash: [14, 10]))
            .frame(width: 250, height: 250)
            .accessibilityHidden(true)
    }

    private var deniedState: some View {
        VStack(spacing: ViadereSpace.m) {
            Text("Camera access is off")
                .font(ViadereType.title).foregroundStyle(.white)
            Text("Allow the camera in Settings to scan QR codes, or type a handle or code instead.")
                .font(ViadereType.body).foregroundStyle(.white.opacity(0.75)).multilineTextAlignment(.center)
            Button("Open Settings") {
                if let url = URL(string: UIApplication.openSettingsURLString) { UIApplication.shared.open(url) }
            }
            .buttonStyle(.viadere(.secondary, fullWidth: false))
        }
        .padding(ViadereSpace.xl)
    }
}

private struct QRScannerRepresentable: UIViewControllerRepresentable {
    let onCode: (String) -> Void

    func makeUIViewController(context: Context) -> QRScannerViewController {
        let controller = QRScannerViewController()
        controller.onCode = onCode
        return controller
    }

    func updateUIViewController(_ uiViewController: QRScannerViewController, context: Context) {}
}

/// `AVCaptureSession` isn't `Sendable`; this box lets start/stop run off the main thread.
private final class SessionBox: @unchecked Sendable {
    let session = AVCaptureSession()
}

final class QRScannerViewController: UIViewController {
    var onCode: ((String) -> Void)?
    private let box = SessionBox()
    private var previewLayer: AVCaptureVideoPreviewLayer?
    private var handled = false

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        configure()
    }

    private func configure() {
        let session = box.session
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device), session.canAddInput(input) else { return }
        session.addInput(input)
        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else { return }
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]

        let layer = AVCaptureVideoPreviewLayer(session: session)
        layer.videoGravity = .resizeAspectFill
        layer.frame = view.bounds
        view.layer.addSublayer(layer)
        previewLayer = layer
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = view.bounds
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        handled = false
        let box = self.box
        DispatchQueue.global(qos: .userInitiated).async { if !box.session.isRunning { box.session.startRunning() } }
    }

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        let box = self.box
        DispatchQueue.global(qos: .userInitiated).async { if box.session.isRunning { box.session.stopRunning() } }
    }
}

extension QRScannerViewController: @preconcurrency AVCaptureMetadataOutputObjectsDelegate {
    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
        guard !handled, let object = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              let value = object.stringValue, value.count <= 2_048 else { return }
        handled = true
        UINotificationFeedbackGenerator().notificationOccurred(.success)
        onCode?(value)
    }
}
