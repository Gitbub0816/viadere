import SwiftUI
import ViadereCore
import ViadereKit

/// Conversations with verified businesses. Every thread is attributed to exactly one business.
struct MessagesView: View {
    @Bindable var model: AppModel
    @State private var path: [ConversationSummary] = []

    private var messages: MessagesViewModel { model.messages }

    var body: some View {
        NavigationStack(path: $path) {
            ScrollView {
                VStack(alignment: .leading, spacing: ViadereSpace.s) {
                    ViadereHeader("Messages", subtitle: messages.unreadTotal > 0 ? "\(messages.unreadTotal) unread" : nil)
                    if messages.conversations.isEmpty {
                        if messages.isLoading {
                            ViadereLoading(height: 30).frame(maxWidth: .infinity).padding(.top, ViadereSpace.xxl)
                        } else {
                            ViadereEmptyState("No conversations",
                                              message: "Message a business you're connected to from its page. Replies arrive here and as notifications.",
                                              actionTitle: "See your businesses") { model.selectedTab = .home }
                                .padding(.top, ViadereSpace.xl)
                        }
                    } else {
                        ViadereRowGroup {
                            ForEach(Array(messages.conversations.enumerated()), id: \.element.id) { index, conversation in
                                Button { path.append(conversation) } label: { ConversationRow(conversation: conversation) }
                                    .buttonStyle(.plain)
                                if index < messages.conversations.count - 1 { ViadereHairline(inset: 56) }
                            }
                        }
                    }
                    if let error = messages.errorMessage {
                        ViadereNotice(error, kind: .warning).padding(.top, ViadereSpace.m)
                    }
                }
                .padding(.horizontal, ViadereSpace.screen)
                .padding(.bottom, ViadereSpace.xl)
            }
            .scrollIndicators(.hidden)
            .refreshable { await messages.load() }
            .viadereScreenBackground()
            .toolbar(.hidden, for: .navigationBar)
            .navigationDestination(for: ConversationSummary.self) { conversation in
                ConversationView(conversation: conversation, model: model)
            }
            .task { await messages.load() }
            .task(id: model.conversationToOpen) {
                guard let id = model.conversationToOpen else { return }
                await messages.load()
                if let match = messages.conversations.first(where: { $0.id == id }) { path = [match] }
                model.conversationToOpen = nil
            }
        }
    }
}

private struct ConversationRow: View {
    let conversation: ConversationSummary

    var body: some View {
        HStack(spacing: 14) {
            ViadereAvatar(name: conversation.business.safeName, size: 40, isVerified: conversation.business.isVerified)
            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    Text(conversation.business.safeName)
                        .font(ViadereType.body.weight(conversation.unreadCount > 0 ? .semibold : .regular))
                        .foregroundStyle(ViadereColor.textPrimary)
                    Spacer(minLength: ViadereSpace.xs)
                    if let at = conversation.lastMessageAt {
                        Text(InteractionPresentation.relative(at, now: Date()))
                            .font(ViadereType.footnote)
                            .foregroundStyle(ViadereColor.textTertiary)
                    }
                }
                HStack {
                    Text(conversation.lastMessagePreview ?? "No messages yet")
                        .font(ViadereType.subhead)
                        .foregroundStyle(ViadereColor.textSecondary)
                        .lineLimit(1)
                    Spacer(minLength: ViadereSpace.xs)
                    if conversation.unreadCount > 0 {
                        Circle().fill(ViadereColor.accent).frame(width: 8, height: 8).accessibilityLabel(Text("Unread"))
                    }
                }
            }
        }
        .padding(.vertical, ViadereSpace.s)
        .frame(minHeight: 60)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
    }
}

// MARK: - Thread

struct ConversationView: View {
    let conversation: ConversationSummary
    let model: AppModel
    @State private var vm: ConversationViewModel
    @Environment(\.dismiss) private var dismiss

    init(conversation: ConversationSummary, model: AppModel) {
        self.conversation = conversation
        self.model = model
        _vm = State(initialValue: ConversationViewModel(conversation: conversation, services: model.services))
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            ViadereHairline()
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(spacing: ViadereSpace.s) {
                        ForEach(vm.rows) { row in
                            MessageBubble(row: row, now: Date()) { option in
                                Task { await vm.choose(option, in: row) }
                            }
                            .id(row.id)
                        }
                    }
                    .padding(.horizontal, ViadereSpace.screen)
                    .padding(.vertical, ViadereSpace.m)
                }
                .scrollDismissesKeyboard(.interactively)
                .onChange(of: vm.rows.count) { _, _ in
                    if let last = vm.rows.last?.id { withAnimation(ViadereMotion.gentle) { proxy.scrollTo(last, anchor: .bottom) } }
                }
            }
            if let error = vm.errorMessage {
                ViadereNotice(error, kind: .warning)
                    .padding(.horizontal, ViadereSpace.screen)
                    .padding(.bottom, ViadereSpace.xs)
            }
            composer
        }
        .viadereScreenBackground()
        .toolbar(.hidden, for: .navigationBar)
        .task { await vm.load() }
    }

    private var header: some View {
        HStack(spacing: ViadereSpace.s) {
            ViadereBackButton("") { dismiss() }
            ViadereAvatar(name: conversation.business.safeName, size: 36, isVerified: conversation.business.isVerified)
            VStack(alignment: .leading, spacing: 0) {
                Text(conversation.business.safeName).font(ViadereType.headline).foregroundStyle(ViadereColor.textPrimary)
                Text("Verified business · replies are from \(conversation.business.safeName)")
                    .font(ViadereType.caption).foregroundStyle(ViadereColor.textSecondary).lineLimit(1)
            }
            Spacer()
        }
        .padding(.horizontal, ViadereSpace.m)
        .padding(.vertical, ViadereSpace.xs)
    }

    private var composer: some View {
        VStack(spacing: 0) {
            ViadereHairline()
            HStack(alignment: .bottom, spacing: ViadereSpace.xs) {
                TextField("Message", text: $vm.draft, axis: .vertical)
                    .lineLimit(1...5)
                    .font(ViadereType.body)
                    .padding(.horizontal, ViadereSpace.m)
                    .padding(.vertical, 12)
                    .background(RoundedRectangle(cornerRadius: 22, style: .continuous).fill(ViadereColor.surface))
                    .overlay(RoundedRectangle(cornerRadius: 22, style: .continuous).strokeBorder(ViadereColor.hairline, lineWidth: 1))
                    .accessibilityLabel(Text("Message"))
                Button {
                    Task { await vm.send() }
                } label: {
                    Image(systemName: "arrow.up")
                        .font(.system(size: 17, weight: .semibold))
                        .foregroundStyle(ViadereColor.onPrimary)
                        .frame(width: 44, height: 44)
                        .background(Circle().fill(vm.canSend ? ViadereColor.primaryFill : ViadereColor.textTertiary.opacity(0.4)))
                }
                .buttonStyle(.plain)
                .disabled(!vm.canSend)
                .accessibilityLabel(Text("Send"))
            }
            .padding(.horizontal, ViadereSpace.m)
            .padding(.vertical, ViadereSpace.xs)
            if vm.remainingCharacters < 100 {
                Text("\(vm.remainingCharacters) characters left")
                    .font(ViadereType.footnote)
                    .foregroundStyle(vm.remainingCharacters < 0 ? ViadereColor.danger : ViadereColor.textTertiary)
                    .padding(.bottom, ViadereSpace.xxs)
            }
        }
        .background(ViadereColor.background)
    }
}

struct MessageBubble: View {
    let row: MessageRow
    let now: Date
    let onChoose: (ChoiceOption) -> Void

    var body: some View {
        let mine = row.isFromConsumer
        VStack(alignment: mine ? .trailing : .leading, spacing: 6) {
            if !mine {
                HStack(spacing: 4) {
                    Text(attribution).font(ViadereType.caption).foregroundStyle(ViadereColor.textSecondary)
                    Image(systemName: "checkmark.seal.fill").font(.system(size: 10)).foregroundStyle(ViadereColor.accent).accessibilityHidden(true)
                }
            }
            Text(UntrustedText.paragraphs(row.message.body, max: 4_000))
                .font(ViadereType.body)
                .foregroundStyle(mine ? ViadereColor.onPrimary : ViadereColor.textPrimary)
                .padding(.horizontal, 14)
                .padding(.vertical, 10)
                .background(RoundedRectangle(cornerRadius: 20, style: .continuous).fill(mine ? ViadereColor.primaryFill : ViadereColor.surface))
                .overlay(RoundedRectangle(cornerRadius: 20, style: .continuous).strokeBorder(mine ? .clear : ViadereColor.hairline, lineWidth: 1))
                .frame(maxWidth: 300, alignment: mine ? .trailing : .leading)
            let options = row.openOptions(now: now)
            if !options.isEmpty {
                ViadereFlowLayout {
                    ForEach(options, id: \.id) { option in
                        ViadereChip(option.label) { onChoose(option) }
                    }
                }
                .frame(maxWidth: 320, alignment: .leading)
            } else if let choice = row.choice, choice.status != .pending {
                Text("Answered").font(ViadereType.caption).foregroundStyle(ViadereColor.textTertiary)
            }
            Text(row.message.createdAt.formatted(date: .omitted, time: .shortened) + (mine ? " · \(delivery)" : ""))
                .font(ViadereType.caption)
                .foregroundStyle(ViadereColor.textTertiary)
        }
        .frame(maxWidth: .infinity, alignment: mine ? .trailing : .leading)
        .accessibilityElement(children: .contain)
    }

    private var attribution: String {
        var text = UntrustedText.line(row.message.attribution.displayName, max: 40)
        if let agent = UntrustedText.optionalLine(row.message.attribution.agentName, max: 40) { text += " · \(agent)" }
        return text
    }

    private var delivery: String {
        switch row.message.deliveryStatus {
        case .queued: "Sending"
        case .sent: "Sent"
        case .delivered: "Delivered"
        case .read: "Read"
        case .failed: "Failed"
        }
    }
}

#if DEBUG
#Preview("Messages") {
    PreviewHost { services in MessagesView(model: AppModel(services: services)) }
}
#endif
