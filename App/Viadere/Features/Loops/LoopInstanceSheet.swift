import SwiftUI
import ViadereCore
import ViadereKit

/// A Loop instance (WP-3.6): Viadere's chrome (Close, Report) around the verified presentation tree. The chrome is not part of the tree,
/// so no definition can remove it; nothing here waits for branding.
struct LoopInstanceSheet: View {
    @State private var vm: LoopInstanceViewModel?
    @Environment(\.dismiss) private var dismiss
    let model: AppModel

    init(presented: LoopCenter.Presented, model: AppModel) {
        self.model = model
        if let api = model.services.loopsAPI {
            _vm = State(initialValue: LoopInstanceViewModel(instanceId: presented.id, api: api, context: model.loopRenderContext(),
                                                            initial: presented.initial))
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            chrome
            if let vm {
                ScrollView {
                    VStack(alignment: .leading, spacing: ViadereSpace.l) {
                        if let notice = vm.endedNotice { ViadereNotice(notice, kind: .info) }
                        if case .failed(let message) = vm.status { ViadereNotice(message, kind: .warning) }
                        PresentationView(tree: vm.tree, model: vm)
                        if let error = vm.errorMessage { ViadereNotice(error, kind: .warning) }
                        if vm.reportSent { ViadereNotice("Thanks. Viadere will review this request.", kind: .info) }
                    }
                    .padding(.horizontal, ViadereSpace.screen)
                    .padding(.bottom, ViadereSpace.xl)
                }
                .scrollIndicators(.hidden)
                .task { await vm.load() }
                .onChange(of: vm.isClosed) { _, closed in if closed { dismiss() } }
                .sheet(isPresented: Binding(get: { vm.isReporting }, set: { vm.isReporting = $0 })) {
                    LoopReportSheet(vm: vm)
                        .presentationDetents([.medium, .large])
                        .presentationBackground(ViadereColor.background)
                }
            } else {
                ViadereEmptyState("Not available", message: "Requests built by businesses aren't available here.")
                Spacer()
            }
        }
        .viadereScreenBackground()
        .onDisappear { Task { await model.alerts.refresh() } }
    }

    private var chrome: some View {
        HStack {
            Button("Close") {
                if let vm { vm.close() } else { dismiss() }
            }
                .buttonStyle(.viadere(.quiet, fullWidth: false))
                .accessibilityLabel(Text("Close this request"))
            Spacer()
            if vm != nil {
                Button("Report") { vm?.requestReport() }
                    .buttonStyle(.viadere(.quiet, fullWidth: false))
                    .accessibilityLabel(Text("Report this request to Viadere"))
            }
        }
        .padding(.horizontal, ViadereSpace.m)
        .padding(.top, ViadereSpace.s)
    }
}

/// Why the customer reports a Loop. One report per account and publication counts toward suspension.
private struct LoopReportSheet: View {
    @Bindable var vm: LoopInstanceViewModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: ViadereSpace.l) {
                ViadereHeader("Report this request", subtitle: "Viadere reviews every report. The business isn't told who reported it.")
                ViadereRowGroup {
                    ForEach(Array(LoopReportReason.allCases.enumerated()), id: \.element) { index, reason in
                        Button {
                            Task {
                                await vm.report(reason)
                                if vm.reportSent { dismiss() }
                            }
                        } label: {
                            ViadereRow(LoopInstanceViewModel.label(for: reason))
                        }
                        .buttonStyle(.plain)
                        if index < LoopReportReason.allCases.count - 1 { ViadereHairline() }
                    }
                }
                if let error = vm.errorMessage { ViadereNotice(error, kind: .warning) }
                Button("Cancel") { vm.isReporting = false; dismiss() }
                    .buttonStyle(.viadere(.secondary))
            }
            .padding(ViadereSpace.screen)
        }
    }
}

#if DEBUG
/// A started pickup-time Loop from Northfield Market in the mock world (consent given, manifest signed with the mock key the mock
/// configuration pins).
private struct LoopPreview: View {
    let services: ViadereServices
    @State private var model: AppModel?
    @State private var presented: LoopCenter.Presented?

    var body: some View {
        Group {
            if let model, let presented {
                LoopInstanceSheet(presented: presented, model: model)
            } else {
                ViadereLoading()
            }
        }
        .task {
            guard let api = services.loopsAPI as? MockLoopsAPI else { return }
            let text = LoopConsentCatalog.current
            let answers = Dictionary(uniqueKeysWithValues: text.checks.map { ($0.id, $0.correctOptionId) })
            _ = try? await api.enableLoops(LoopGlobalConsentRequest(textVersion: text.version, textDigest: text.digest, answers: answers, agree: true))
            _ = try? await api.authorizeBusiness(PreviewData.northfield.id,
                                                 LoopBusinessConsentRequest(textVersion: text.version, textDigest: text.digest, agree: true))
            let summary = await api.publish(MockLoopsAPI.pickupDefinition, business: PreviewData.northfield.id)
            let appModel = AppModel(services: services)
            await appModel.refreshOrganization()
            guard let view = try? await api.startInstance(LoopInstanceCreateRequest(publicationId: summary.publicationId, entryPoint: .businessPage))
            else { return }
            model = appModel
            presented = LoopCenter.Presented(id: view.id, initial: view)
        }
    }
}

#Preview("Loop instance") {
    PreviewHost { services in LoopPreview(services: services) }
}

#Preview("Loops consent") {
    PreviewHost { services in LoopConsentFlowView(consent: LoopConsentViewModel(api: services.loopsAPI)) }
}
#endif
