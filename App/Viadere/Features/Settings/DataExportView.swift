import SwiftUI
import UniformTypeIdentifiers
import ViadereCore
import ViadereKit

/// "Download my data": asks for the export, waits while the server prepares it, opens it here (it is sealed to a key only this iPhone holds) and
/// lets the person save the file. Nothing goes by email and the server keeps nothing it can read.
struct DataExportView: View {
    @State private var vm: AccountExportViewModel
    @State private var exporting = false
    @State private var document: ExportDocument?

    init(services: ViadereServices) {
        let api = LiveAccountExportAPI.make(services: services)
        _vm = State(initialValue: AccountExportViewModel(service: AccountExportService(api: api, secrets: services.secrets, records: services.records, clock: services.clock)))
    }

    var body: some View {
        SubScreen(title: "Download my data", subtitle: "A copy of what Viadere holds about your account.") {
            VStack(alignment: .leading, spacing: ViadereSpace.m) {
                ViadereNotice("The export is prepared on our servers and locked to this iPhone, so only this iPhone can open it. It is never sent by email or text.", kind: .info)
                switch vm.phase {
                case .idle:
                    Button("Request my data") { Task { await vm.start() } }.buttonStyle(.viadere(.primary))
                case .requesting:
                    ProgressView("Asking Viadere…")
                case .waiting:
                    ProgressView("Preparing your export. This can take a few minutes; you can leave this screen and come back.")
                case .ready(let data):
                    Text("Your export is ready. Save it somewhere only you can reach: the file is not encrypted once it is saved.")
                        .font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
                    Button("Save to Files") { document = ExportDocument(data: data); exporting = true }.buttonStyle(.viadere(.primary))
                    Button("Done") { vm.reset() }.buttonStyle(.viadere(.quiet, fullWidth: false))
                case .failed(let message):
                    ViadereNotice(message, kind: .warning)
                    Button("Try again") { Task { await vm.start() } }.buttonStyle(.viadere(.secondary))
                }
            }
        }
        .fileExporter(isPresented: $exporting, document: document, contentType: .json, defaultFilename: "viadere-export") { _ in
            document = nil
        }
    }
}

private struct ExportDocument: FileDocument {
    static let readableContentTypes: [UTType] = [.json]
    var data: Data
    init(data: Data) { self.data = data }
    init(configuration: ReadConfiguration) throws { data = configuration.file.regularFileContents ?? Data() }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper { FileWrapper(regularFileWithContents: data) }
}
