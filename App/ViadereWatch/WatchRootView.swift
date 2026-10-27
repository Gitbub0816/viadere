import SwiftUI
import ViadereKit

/// Compact approvals list. Approving sensitive requests happens on the iPhone (Face ID); notification actions
/// on the watch work as on the phone.
struct WatchRootView: View {
    let model: WatchModel

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: ViadereSpace.xs) {
                    HStack {
                        ViadereMark().frame(height: 22)
                        Spacer()
                    }
                    if model.items.isEmpty {
                        Text("Nothing needs you")
                            .font(ViadereType.headline).foregroundStyle(ViadereColor.textPrimary)
                            .padding(.top, ViadereSpace.s)
                        Text("Requests appear here and as notifications.")
                            .font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                    } else {
                        ForEach(model.items) { item in
                            NavigationLink(value: item) { WatchRow(item: item) }.buttonStyle(.plain)
                        }
                    }
                    if let message = model.statusMessage {
                        Text(message).font(ViadereType.footnote).foregroundStyle(ViadereColor.accent)
                    }
                }
                .padding(.horizontal, ViadereSpace.xs)
            }
            .navigationDestination(for: WatchPendingItem.self) { item in
                WatchDetail(item: item, model: model)
            }
        }
        .viadereScreenBackground()
        // The watch is always dark; keep the dynamic brand colours on their dark variants.
        .environment(\.colorScheme, .dark)
    }
}

private struct WatchRow: View {
    let item: WatchPendingItem

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(item.business).font(ViadereType.caption).foregroundStyle(ViadereColor.textSecondary)
            Text(item.headline).font(ViadereType.subhead.weight(.semibold)).foregroundStyle(ViadereColor.textPrimary)
            TimelineView(.periodic(from: .now, by: 1)) { context in
                Text(InteractionPresentation.countdown(until: item.expiresAt, now: context.date))
                    .font(ViadereType.caption).monospacedDigit().foregroundStyle(ViadereColor.accent)
            }
        }
        .padding(ViadereSpace.s)
        .frame(maxWidth: .infinity, alignment: .leading)
        .viadereSurface(radius: ViadereRadius.control)
    }
}

private struct WatchDetail: View {
    let item: WatchPendingItem
    let model: WatchModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: ViadereSpace.s) {
                Text(item.business).font(ViadereType.caption).foregroundStyle(ViadereColor.textSecondary)
                Text(item.headline).font(ViadereType.headline).foregroundStyle(ViadereColor.textPrimary)
                if item.requiresPhone {
                    Label("Approve on your iPhone with Face ID", systemImage: "iphone")
                        .font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                } else if item.options.isEmpty {
                    Button("Confirm") { model.send(WatchActionRequest(interactionId: item.id, decision: .confirm)) }
                        .buttonStyle(.viadere(.primary))
                } else {
                    ForEach(item.options, id: \.id) { option in
                        Button(option.label) {
                            model.send(WatchActionRequest(interactionId: item.id, decision: .select, optionId: option.id))
                        }
                        .buttonStyle(.viadere(.secondary))
                    }
                }
                if item.isSecurity {
                    Button("No, it isn't me") { model.send(WatchActionRequest(interactionId: item.id, decision: .deny)) }
                        .buttonStyle(.viadere(.destructive))
                }
                if let message = model.statusMessage {
                    Text(message).font(ViadereType.footnote).foregroundStyle(ViadereColor.accent)
                }
            }
            .padding(.horizontal, ViadereSpace.xs)
        }
    }
}
