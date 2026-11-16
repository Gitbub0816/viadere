import AVFoundation
import CKeyScanKit
import SwiftUI
import UIKit
import ViadereKit

/// Full-screen camera scanner for Viadere codes: the CKey on "Sign in with Viadere" and the QR codes businesses show or print.
///
/// The camera reads whatever is in front of it, so this screen decides nothing. Every payload goes to `onCode`, whose answer comes from
/// `ScannedCodePolicy` (ViadereKit): an accepted code closes the scanner and opens a review screen; a refused one stays here with the
/// reason and nothing else happens. The screen never shows, copies, logs or opens the scanned text.
///
/// QR codes are read by the system (`AVCaptureMetadataOutput`). CKeys are read by the scan-only CKey package (`CKeyScanKit`: decoder only, no
/// renderer and no telemetry code) from the same camera session's frames. See docs/SECURITY.md §2.104.
struct CodeScannerScreen: View {
    /// Returns `nil` when the code was accepted (the caller closes the scanner), or why it was refused.
    let onCode: @MainActor (String, ScannedSymbology) -> ScanRejection?
    let onClose: () -> Void

    @State private var status = AVCaptureDevice.authorizationStatus(for: .video)
    @State private var torchOn = false
    @State private var torchAvailable = false
    @State private var found = false
    @State private var refusal: ScanRefusal?
    @State private var sweep = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    /// A refusal on screen; `id` restarts the dismissal timer when the same reason repeats.
    private struct ScanRefusal: Equatable {
        let id = UUID()
        let reason: ScanRejection
    }

    private let windowSide: CGFloat = 264

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            switch status {
            case .authorized:
                CodeScannerRepresentable(torchOn: torchOn, onTorchAvailability: { torchAvailable = $0 }, onPayload: handle)
                    .ignoresSafeArea()
                    .accessibilityHidden(true)
                viewfinder
            case .notDetermined:
                ViadereLoading().task {
                    _ = await AVCaptureDevice.requestAccess(for: .video)
                    status = AVCaptureDevice.authorizationStatus(for: .video)
                }
            default:
                deniedState
            }
            chrome
        }
        .sensoryFeedback(.success, trigger: found) { _, now in now }
        .sensoryFeedback(.warning, trigger: refusal)
        .task(id: refusal) {
            // A refusal clears itself; the camera keeps reading meanwhile.
            guard refusal != nil else { return }
            try? await Task.sleep(for: .seconds(4))
            if !Task.isCancelled { withAnimation(ViadereMotion.gentle) { refusal = nil } }
        }
    }

    private func handle(_ payload: String, _ symbology: ScannedSymbology) -> Bool {
        guard !found else { return true }
        if let reason = onCode(payload, symbology) {
            withAnimation(ViadereMotion.standard) { refusal = ScanRefusal(reason: reason) }
            AccessibilityNotification.Announcement(reason.message).post()
            return false
        }
        withAnimation(ViadereMotion.standard) { found = true; refusal = nil }
        return true
    }

    // MARK: Viewfinder

    /// A dimmed field with a clear rounded window, champagne corner brackets that close in when a code is accepted, and a slow sweep line
    /// (still when Reduce Motion is on).
    private var viewfinder: some View {
        ZStack {
            ScannerMask(side: windowSide, radius: 32)
                .fill(.black.opacity(0.55), style: FillStyle(eoFill: true))
            ScannerBrackets(radius: 32, arm: found ? 132 : 30)
                .stroke(found ? ViadereBrand.champagne : .white.opacity(0.92), style: StrokeStyle(lineWidth: 3, lineCap: .round))
                .frame(width: windowSide, height: windowSide)
                .scaleEffect(found ? 0.96 : 1)
            if !found && !reduceMotion {
                LinearGradient(colors: [.clear, ViadereBrand.champagne.opacity(0.7), .clear], startPoint: .leading, endPoint: .trailing)
                    .frame(width: windowSide - 56, height: 2)
                    .offset(y: sweep ? windowSide / 2 - 30 : -(windowSide / 2 - 30))
                    .onAppear { withAnimation(.easeInOut(duration: 2.2).repeatForever(autoreverses: true)) { sweep = true } }
            }
            if found {
                Image(systemName: "checkmark")
                    .font(.system(size: 44, weight: .semibold))
                    .foregroundStyle(ViadereBrand.champagne)
                    .transition(.scale(scale: 0.6).combined(with: .opacity))
            }
        }
        // One coordinate space for the hole, the brackets, the sweep and the check: all full screen. (With only the mask ignoring the safe
        // area, its hole was centred on the screen and the brackets on the safe area, so they sat apart.)
        .ignoresSafeArea()
        .accessibilityHidden(true)
    }

    // MARK: Chrome

    private var chrome: some View {
        VStack(spacing: ViadereSpace.m) {
            HStack {
                if status == .authorized && torchAvailable {
                    ScannerRoundButton(systemName: torchOn ? "flashlight.on.fill" : "flashlight.off.fill",
                                       label: torchOn ? "Turn the light off" : "Turn the light on", isOn: torchOn) { torchOn.toggle() }
                }
                Spacer()
                ScannerRoundButton(systemName: "xmark", label: "Close scanner", isOn: false, action: onClose)
            }
            .padding(.horizontal, ViadereSpace.m)
            .padding(.top, ViadereSpace.m)
            Spacer()
            if status == .authorized {
                if let refusal {
                    Text(refusal.reason.message)
                        .font(ViadereType.subhead.weight(.medium))
                        .foregroundStyle(.white)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, ViadereSpace.l)
                        .padding(.vertical, ViadereSpace.s)
                        .background(RoundedRectangle(cornerRadius: ViadereRadius.card, style: .continuous).fill(.black.opacity(0.72)))
                        .overlay(RoundedRectangle(cornerRadius: ViadereRadius.card, style: .continuous).strokeBorder(.white.opacity(0.18), lineWidth: 1))
                        .padding(.horizontal, ViadereSpace.l)
                        .transition(.move(edge: .bottom).combined(with: .opacity))
                } else {
                    VStack(spacing: ViadereSpace.xxs) {
                        Text(found ? "Code read" : "Point at a Viadere code or QR code")
                            .font(ViadereType.subhead.weight(.semibold))
                            .foregroundStyle(.white)
                        if !found {
                            Text("Only scan a code on a page you opened yourself.")
                                .font(ViadereType.footnote)
                                .foregroundStyle(.white.opacity(0.75))
                        }
                    }
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, ViadereSpace.l)
                    .padding(.vertical, ViadereSpace.s)
                    .background(Capsule().fill(.black.opacity(0.6)))
                    .transition(.opacity)
                    .accessibilityElement(children: .combine)
                }
            }
        }
        .padding(.bottom, ViadereSpace.xl)
    }

    private var deniedState: some View {
        VStack(spacing: ViadereSpace.m) {
            Image(systemName: "camera")
                .font(.system(size: 34, weight: .light))
                .foregroundStyle(.white.opacity(0.75))
                .accessibilityHidden(true)
            Text("Camera access is off")
                .font(ViadereType.title).foregroundStyle(.white)
            Text("Allow the camera in Settings to scan codes, or type a handle or code instead.")
                .font(ViadereType.body).foregroundStyle(.white.opacity(0.75)).multilineTextAlignment(.center)
            Button("Open Settings") {
                if let url = URL(string: UIApplication.openSettingsURLString) { UIApplication.shared.open(url) }
            }
            .buttonStyle(.viadere(.secondary, fullWidth: false))
        }
        .padding(ViadereSpace.xl)
    }
}

/// A 44-pt round control that stays legible over any camera image.
private struct ScannerRoundButton: View {
    let systemName: String
    let label: String
    let isOn: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Image(systemName: systemName)
                .font(.system(size: 17, weight: .medium))
                .foregroundStyle(isOn ? Color.black : Color.white)
                .frame(width: 44, height: 44)
                .background(Circle().fill(isOn ? Color.white : Color.black.opacity(0.55)))
                .overlay(Circle().strokeBorder(.white.opacity(0.25), lineWidth: 1))
                .contentShape(Circle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(Text(label))
        .sensoryFeedback(.selection, trigger: isOn)
    }
}

/// The whole screen with a centered rounded-square hole (even-odd fill).
private struct ScannerMask: Shape {
    let side: CGFloat
    let radius: CGFloat

    func path(in rect: CGRect) -> Path {
        var path = Path(rect)
        let window = CGRect(x: rect.midX - side / 2, y: rect.midY - side / 2, width: side, height: side)
        path.addRoundedRect(in: window, cornerSize: CGSize(width: radius, height: radius), style: .continuous)
        return path
    }
}

/// Four corner brackets. `arm` is how far each reaches along its edges; at half the side they join into a full outline.
private struct ScannerBrackets: Shape {
    let radius: CGFloat
    var arm: CGFloat

    var animatableData: CGFloat {
        get { arm }
        set { arm = newValue }
    }

    func path(in rect: CGRect) -> Path {
        let reach = min(max(arm, radius), rect.width / 2)
        var path = Path()
        // Top-left, then mirrored into the other three corners.
        var corner = Path()
        corner.move(to: CGPoint(x: rect.minX, y: rect.minY + reach))
        corner.addLine(to: CGPoint(x: rect.minX, y: rect.minY + radius))
        corner.addArc(center: CGPoint(x: rect.minX + radius, y: rect.minY + radius), radius: radius,
                      startAngle: .degrees(180), endAngle: .degrees(270), clockwise: false)
        corner.addLine(to: CGPoint(x: rect.minX + reach, y: rect.minY))
        for (sx, sy) in [(1.0, 1.0), (-1.0, 1.0), (1.0, -1.0), (-1.0, -1.0)] {
            let flip = CGAffineTransform(translationX: rect.midX, y: rect.midY).scaledBy(x: sx, y: sy).translatedBy(x: -rect.midX, y: -rect.midY)
            path.addPath(corner, transform: flip)
        }
        return path
    }
}

// MARK: Camera

private struct CodeScannerRepresentable: UIViewControllerRepresentable {
    let torchOn: Bool
    let onTorchAvailability: (Bool) -> Void
    /// Returns `true` when the payload was accepted and reading should stop.
    let onPayload: (String, ScannedSymbology) -> Bool

    func makeUIViewController(context: Context) -> CodeScannerViewController {
        let controller = CodeScannerViewController()
        controller.onPayload = onPayload
        controller.onTorchAvailability = onTorchAvailability
        return controller
    }

    func updateUIViewController(_ controller: CodeScannerViewController, context: Context) {
        controller.onPayload = onPayload
        controller.setTorch(torchOn)
    }
}

/// `AVCaptureSession` isn't `Sendable`; this box lets start/stop run off the main thread.
private final class SessionBox: @unchecked Sendable {
    let session = AVCaptureSession()
}

/// Reads CKeys from camera frames, off the main thread.
///
/// The decoder is C++ working on camera pixels, so its reach is kept small: it sees only the luma of frames this app's own camera session
/// produced, at most `maxFramesPerSecond`, one frame at a time (late frames are dropped by AVFoundation), and only while the scanner is on
/// screen. What it returns is treated as hostile text: Profile 0 in any layout the pinned decoder verifies (Reed-Solomon and CRC-32C decide;
/// the layout is only how the modules are drawn), valid UTF-8 text only, at most `ScannedCodePolicy.maxPayloadBytes`,
/// and a payload refused once is not offered again for `repeatInterval`, so a hostile code in view cannot flood the main thread.
private final class CKeyFrameReader: NSObject, AVCaptureVideoDataOutputSampleBufferDelegate, @unchecked Sendable {
    static let maxFramesPerSecond = 12.0
    static let repeatInterval: CFTimeInterval = 2.5

    let queue = DispatchQueue(label: "com.viadere.scanner.frames", qos: .userInitiated)
    private let deliver: @Sendable (String) -> Void
    // Frame-queue state.
    private var stopped = false
    private var lastFrame: CFTimeInterval = 0
    private var lastPayload: String?
    private var lastPayloadTime: CFTimeInterval = 0

    init(deliver: @escaping @Sendable (String) -> Void) {
        self.deliver = deliver
    }

    func stop() { queue.async { self.stopped = true } }
    func resume() { queue.async { self.stopped = false; self.lastPayload = nil } }

    func captureOutput(_ output: AVCaptureOutput, didOutput sampleBuffer: CMSampleBuffer, from connection: AVCaptureConnection) {
        guard !stopped else { return }
        let now = CACurrentMediaTime()
        guard now - lastFrame >= 1.0 / Self.maxFramesPerSecond, let pixels = CMSampleBufferGetImageBuffer(sampleBuffer) else { return }
        lastFrame = now
        guard let result = CKeyDecoder.decode(pixelBuffer: pixels), result.profile == .scalable, let text = result.text,
              !text.isEmpty, text.utf8.count <= ScannedCodePolicy.maxPayloadBytes else { return }
        if text == lastPayload, now - lastPayloadTime < Self.repeatInterval { return }
        lastPayload = text
        lastPayloadTime = now
        deliver(text)
    }
}

final class CodeScannerViewController: UIViewController {
    var onPayload: ((String, ScannedSymbology) -> Bool)?
    var onTorchAvailability: ((Bool) -> Void)?

    private let box = SessionBox()
    private var device: AVCaptureDevice?
    private var previewLayer: AVCaptureVideoPreviewLayer?
    private var frameReader: CKeyFrameReader?
    private var accepted = false
    private var lastQR: (payload: String, time: CFTimeInterval)?

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        configure()
    }

    private func configure() {
        let session = box.session
        guard let device = AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: .back) ?? AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device), session.canAddInput(input) else { return }
        self.device = device
        session.beginConfiguration()
        // 1080p is plenty for a code on a screen at arm's length and keeps each decoded frame small.
        if session.canSetSessionPreset(.hd1920x1080) { session.sessionPreset = .hd1920x1080 }
        session.addInput(input)

        // QR codes: the system's detector.
        let metadata = AVCaptureMetadataOutput()
        if session.canAddOutput(metadata) {
            session.addOutput(metadata)
            metadata.setMetadataObjectsDelegate(self, queue: .main)
            if metadata.availableMetadataObjectTypes.contains(.qr) { metadata.metadataObjectTypes = [.qr] }
        }

        // CKeys: luma frames to the CKey decoder, on its own queue; a frame that arrives while one is being read is dropped.
        let reader = CKeyFrameReader { [weak self] text in
            Task { @MainActor in self?.offer(text, .ckey) }
        }
        let video = AVCaptureVideoDataOutput()
        video.alwaysDiscardsLateVideoFrames = true
        video.videoSettings = [kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_420YpCbCr8BiPlanarFullRange]
        if session.canAddOutput(video) {
            session.addOutput(video)
            video.setSampleBufferDelegate(reader, queue: reader.queue)
            frameReader = reader
        }
        session.commitConfiguration()

        if (try? device.lockForConfiguration()) != nil {
            if device.isFocusModeSupported(.continuousAutoFocus) { device.focusMode = .continuousAutoFocus }
            if device.isAutoFocusRangeRestrictionSupported { device.autoFocusRangeRestriction = .near }
            device.unlockForConfiguration()
        }

        let layer = AVCaptureVideoPreviewLayer(session: session)
        layer.videoGravity = .resizeAspectFill
        layer.frame = view.bounds
        view.layer.addSublayer(layer)
        previewLayer = layer
        // After this layout pass: the answer changes SwiftUI state.
        let hasTorch = device.hasTorch && device.isTorchAvailable
        Task { @MainActor [weak self] in self?.onTorchAvailability?(hasTorch) }
    }

    /// One place for both symbologies, on the main thread. After an accepted code nothing more is offered.
    private func offer(_ payload: String, _ symbology: ScannedSymbology) {
        guard !accepted, viewIfLoaded?.window != nil else { return }
        if onPayload?(payload, symbology) == true {
            accepted = true
            frameReader?.stop()
            setTorch(false)
        }
    }

    func setTorch(_ on: Bool) {
        guard let device, device.hasTorch, device.isTorchAvailable, (device.torchMode == .on) != on,
              (try? device.lockForConfiguration()) != nil else { return }
        device.torchMode = on ? .on : .off
        device.unlockForConfiguration()
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = view.bounds
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        accepted = false
        lastQR = nil
        frameReader?.resume()
        let box = self.box
        DispatchQueue.global(qos: .userInitiated).async { if !box.session.isRunning { box.session.startRunning() } }
    }

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        frameReader?.stop()
        setTorch(false)
        let box = self.box
        DispatchQueue.global(qos: .userInitiated).async { if box.session.isRunning { box.session.stopRunning() } }
    }
}

extension CodeScannerViewController: @preconcurrency AVCaptureMetadataOutputObjectsDelegate {
    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
        guard !accepted, let object = metadataObjects.first as? AVMetadataMachineReadableCodeObject, object.type == .qr,
              let value = object.stringValue, !value.isEmpty, value.utf8.count <= ScannedCodePolicy.maxPayloadBytes else { return }
        // The detector reports a code in view many times a second; a refused one is offered again only after a pause.
        let now = CACurrentMediaTime()
        if let last = lastQR, last.payload == value, now - last.time < CKeyFrameReader.repeatInterval { return }
        lastQR = (value, now)
        offer(value, .qr)
    }
}
