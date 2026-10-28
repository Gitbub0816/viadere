import SwiftUI
import UniformTypeIdentifiers
import ViadereCore
import ViadereKit

/// "Import from another app" (Credential Exchange). The mapping of exported data onto vault items is `CredentialExchange` in ViadereKit (tested).
///
/// The system half is iOS 26's `ASCredentialImportManager`. It is deliberately NOT wired up here:
///
/// TODO(device, Xcode 27 / iOS 26): receive the export token the system passes when the person chooses "Authenticator" in Passwords' export
/// flow (the app is opened with a Credential Exchange `NSUserActivity`), call `ASCredentialImportManager().importCredentials(token:)`, serialize
/// the returned `ASExportedCredentialData` to the CXF JSON `CredentialExchange.parse` reads, and call `model.importExchange(_:)`. The API
/// surface is new and was not available to build against in this change, so the parser is covered by tests against CXF-shaped JSON but the
/// glue below is a file picker for a CXF `.json` export as a stand-in that can be exercised today. Verify the CXF field names against a real
/// export before release.
///
/// DEBUG builds only: a plaintext export sitting in Files is exactly what a credential manager should not encourage, so release builds do not
/// offer the file picker at all (gate review, Info).
#if DEBUG
@available(iOS 26.0, *)
struct CredentialExchangeImportButton: View {
    let model: AuthenticatorViewModel
    let onDone: () -> Void
    @State private var picking = false
    @State private var report: String?

    var body: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.s) {
            Button { picking = true } label: { Label("Import from another app", systemImage: "square.and.arrow.down") }.buttonStyle(.viadere(.secondary))
            if let report { ViadereNotice(report, kind: .info) }
        }
        .fileImporter(isPresented: $picking, allowedContentTypes: [.json]) { result in
            guard case .success(let url) = result else { return }
            Task { report = await importFile(url) }
        }
    }

    private func importFile(_ url: URL) async -> String {
        guard url.startAccessingSecurityScopedResource() else { return "Couldn't open that file." }
        defer { url.stopAccessingSecurityScopedResource() }
        guard let data = try? Data(contentsOf: url) else { return "Couldn't read that file." }
        do {
            let result = try CredentialExchange.parse(data, now: Date())
            let added = try await AuthenticatorHub.shared.engine?.importExchange(result) ?? 0
            await model.load()
            let skipped = result.skipped.count
            return "Imported \(added) item\(added == 1 ? "" : "s")." + (skipped > 0 ? " \(skipped) couldn't be imported (for example passwords, which Authenticator doesn't store)." : "")
        } catch {
            return "That file isn't a supported credential export."
        }
    }
}
#endif
