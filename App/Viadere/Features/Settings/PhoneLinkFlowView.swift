import SwiftUI
import UIKit
import ViadereCore
import ViadereKit
#if canImport(MessageUI)
import MessageUI
#endif

/// Linking a phone number by sending one text from it (ADR-0027, UX_COPY S-PH-01 to S-PH-06). Used by onboarding and by Settings.
///
/// Viadere never texts the phone a code or a link. The person writes **one** text from the phone with that number: the system compose sheet
/// opens pre-filled ("Link my number to my Viadere app VDR-…") and the person taps Send themselves. The sheet reports only that the text was
/// queued, cancelled or failed, so this screen never decides the text was not sent: it waits for the server and says "We didn't receive your
/// text" only when the ten minutes end. Without a compose sheet (iPad without cellular or relay, Mac, no SIM) the text and number are shown to copy.
struct PhoneLinkFlowView: View {
    let vm: PhoneLinkViewModel
    @State private var composing = false

    var body: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.m) {
            switch vm.stage {
            case .entry:
                Text(PhoneLinkViewModel.introText)
                    .font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
                ViadereTextField("Mobile number", text: Binding(get: { vm.raw }, set: { vm.setPhone($0) }), prompt: "(480) 555-0123")
                    .keyboardType(.phonePad)
                    .textContentType(.telephoneNumber)
                Button(vm.isWorking ? "Working…" : PhoneLinkViewModel.writeTextTitle) { Task { await begin() } }
                    .buttonStyle(.viadere(.primary))
                    .disabled(!vm.canBegin)
            case .waiting:
                HStack(spacing: ViadereSpace.s) {
                    ViadereLoading()
                    Text(vm.statusText ?? "").font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if vm.showCopyInstead, let instructions = vm.manualInstructions {
                    Text(instructions).font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .textSelection(.enabled)
                    Button(PhoneLinkViewModel.copyTextTitle) {
                        if let body = vm.composeRequest?.body { UIPasteboard.general.string = body }
                    }
                    .buttonStyle(.viadere(.secondary))
                } else {
                    Button(PhoneLinkViewModel.writeTextTitle) { openCompose() }
                        .buttonStyle(.viadere(.secondary))
                }
                Button("Use a different number") { vm.startOver() }
                    .buttonStyle(.viadere(.quiet, fullWidth: false))
            case .linked:
                ViadereNotice(vm.statusText ?? "", kind: .info)
            case .notReceived:
                ViadereNotice(vm.statusText ?? "", kind: .warning)
                Button("Try again") { vm.startOver() }
                    .buttonStyle(.viadere(.primary))
            }
            if let message = vm.errorMessage { ViadereNotice(message, kind: .danger) }
        }
        // Poll the server while a challenge is live; the task ends when the stage changes or the view goes away.
        .task(id: vm.stage) {
            if case .waiting = vm.stage { await vm.waitForText() }
        }
        #if canImport(MessageUI)
        .sheet(isPresented: $composing) {
            if let request = vm.composeRequest {
                MessageComposeSheet(recipient: request.recipient, body: request.body) { sent in
                    composing = false
                    vm.composeDismissed(sent: sent)
                }
                .ignoresSafeArea()
            }
        }
        #endif
    }

    private func begin() async {
        await vm.begin()
        if case .waiting = vm.stage { openCompose() }
    }

    private func openCompose() {
        #if canImport(MessageUI)
        if MFMessageComposeViewController.canSendText() { composing = true } else { vm.composeUnavailable() }
        #else
        vm.composeUnavailable()
        #endif
    }
}

#if canImport(MessageUI)
/// The system compose sheet with one recipient and the pre-filled text. Nothing can be sent without the person tapping Send, and the sheet
/// reports only `.sent` (queued), `.cancelled` or `.failed`.
struct MessageComposeSheet: UIViewControllerRepresentable {
    let recipient: String
    let body: String
    let onFinished: (Bool) -> Void

    func makeUIViewController(context: Context) -> MFMessageComposeViewController {
        let controller = MFMessageComposeViewController()
        controller.recipients = [recipient]
        controller.body = body
        controller.messageComposeDelegate = context.coordinator
        return controller
    }

    func updateUIViewController(_ controller: MFMessageComposeViewController, context: Context) {}

    func makeCoordinator() -> Coordinator { Coordinator(onFinished: onFinished) }

    final class Coordinator: NSObject, MFMessageComposeViewControllerDelegate {
        let onFinished: (Bool) -> Void
        init(onFinished: @escaping (Bool) -> Void) { self.onFinished = onFinished }

        func messageComposeViewController(_ controller: MFMessageComposeViewController, didFinishWith result: MessageComposeResult) {
            onFinished(result == .sent)
        }
    }
}
#endif
