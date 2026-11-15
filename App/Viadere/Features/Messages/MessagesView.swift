import PhotosUI
import SwiftUI
import ViadereCore
import ViadereKit
#if canImport(UIKit)
import UIKit
#endif

/// Conversations with verified businesses (spec C4). Every thread is attributed to exactly one business; histories are never merged. In
/// All, threads are grouped by business; the selector narrows to one business. Search runs on this device over the cached list (message
/// bodies are encrypted at rest on the server, so there is no server-side search).
struct MessagesView: View {
    @Bindable var model: AppModel
    @State private var path: [ConversationSummary] = []

    private var messages: MessagesViewModel { model.messages }
    private var context: OrganizationContext { model.organization.effective }

    var body: some View {
        NavigationStack(path: $path) {
            ScrollView {
                VStack(alignment: .leading, spacing: ViadereSpace.s) {
                    OrganizationContextHeader(model: model)
                    ViadereHeader("Messages", subtitle: subtitle)
                    if messages.conversations.count > 3 {
                        ViadereSearchField("Search conversations", text: Binding(get: { messages.searchQuery }, set: { messages.searchQuery = $0 }))
                    }
                    content
                    archivedEntry
                    // A first load that failed has its own state (with a retry); the notice is for a failed refresh or change.
                    if let error = messages.errorMessage, !messages.conversations.isEmpty {
                        ViadereNotice(error, kind: .warning).padding(.top, ViadereSpace.m)
                    }
                }
                .padding(.horizontal, ViadereSpace.screen)
                .padding(.bottom, ViadereSpace.xl)
            }
            .scrollIndicators(.hidden)
            .scrollDismissesKeyboard(.interactively)
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
                if let match = messages.conversations.first(where: { $0.id == id }) {
                    // A thread opened from a push or link for another business shows that business; the saved choice stays.
                    model.organization.open(itemFrom: match.business.id)
                    path = [match]
                }
                model.conversationToOpen = nil
            }
        }
    }

    private var subtitle: String? {
        let unread = messages.unread(context: context)
        return unread > 0 ? "\(unread) unread" : model.organization.selectedBusiness.map { "With \($0.safeName)" }
    }

    @ViewBuilder private var content: some View {
        let groups = messages.groups(context: context)
        let state = ScreenLoadState.resolve(isLoading: messages.isLoading, isEmpty: messages.conversations.isEmpty,
                                            errorMessage: messages.errorMessage)
        if state == .loading {
            ViadereSkeleton(.rows(4), label: "Loading conversations").padding(.top, ViadereSpace.s)
        } else if case .failed(let message) = state {
            ViadereErrorState("Couldn't load messages", message: message) { await messages.load() }
                .padding(.top, ViadereSpace.m)
        } else if groups.isEmpty {
            if !messages.searchQuery.isEmpty {
                ViadereNoResults(FeedbackCopy.noMatch(messages.searchQuery, in: "conversation")) { messages.searchQuery = "" }
            } else if let business = model.organization.selectedBusiness {
                ViadereEmptyState("No messages with \(business.safeName)",
                                  message: "Start a conversation from \(business.safeName)'s page. Replies arrive here and as notifications.",
                                  actionTitle: "Message \(business.safeName)") {
                    Task {
                        if let started = await messages.start(with: business.id) { path = [started] }
                    }
                }
                .padding(.top, ViadereSpace.xl)
            } else {
                ViadereEmptyState("No conversations",
                                  message: "Message a business you're connected to from its page. Replies arrive here and as notifications.",
                                  actionTitle: "See your businesses") { model.selectedTab = .businesses }
                    .padding(.top, ViadereSpace.xl)
            }
        } else if context == .all {
            ForEach(Array(groups.enumerated()), id: \.element.id) { index, group in
                VStack(alignment: .leading, spacing: 0) {
                    ViadereSectionHeader(group.business.safeName)
                    threadList(group.threads)
                }
                .viadereEntrance(index)
            }
        } else {
            threadList(groups.flatMap(\.threads))
        }
    }

    /// Archived threads were hidden for good before: this is the way back to them.
    @ViewBuilder private var archivedEntry: some View {
        let archived = messages.archived(context: context)
        if !archived.isEmpty, messages.searchQuery.isEmpty {
            ViadereRowGroup {
                NavigationLink {
                    ArchivedConversationsView(model: model)
                } label: {
                    ViadereRow("Archived", subtitle: archived.count == 1 ? "1 conversation" : "\(archived.count) conversations") {
                        ViadereIconTile(systemName: "archivebox")
                    }
                }
                .buttonStyle(.viaderePressable)
            }
            .padding(.top, ViadereSpace.m)
        }
    }

    private func threadList(_ threads: [ConversationSummary]) -> some View {
        ViadereRowGroup {
            ForEach(Array(threads.enumerated()), id: \.element.id) { index, conversation in
                Button { path.append(conversation) } label: { ConversationRow(conversation: conversation) }
                    .buttonStyle(.viaderePressable)
                    .contextMenu {
                        Button { toggleMuted(conversation) } label: {
                            Label(conversation.muted == true ? "Unmute" : "Mute", systemImage: conversation.muted == true ? "bell" : "bell.slash")
                        }
                        Button { archive(conversation) } label: { Label("Archive", systemImage: "archivebox") }
                    }
                    .accessibilityAction(named: Text(conversation.muted == true ? "Unmute" : "Mute")) { toggleMuted(conversation) }
                    .accessibilityAction(named: Text("Archive")) { archive(conversation) }
                if index < threads.count - 1 { ViadereHairline(inset: 56) }
            }
        }
    }

    /// Mute and Archive confirm with a toast only when the server kept the change; a refusal shows the reason in the notice instead.
    private func toggleMuted(_ conversation: ConversationSummary) {
        let muted = !(conversation.muted ?? false)
        Task {
            if await messages.setMuted(conversation.id, muted) { model.toast = FeedbackCopy.conversationMuted(muted) }
        }
    }

    private func archive(_ conversation: ConversationSummary) {
        Task {
            if await messages.setArchived(conversation.id, true) { model.toast = FeedbackCopy.conversationArchived(true) }
        }
    }
}

/// Messages → Archived: threads hidden from the list (for this account only; the business is never told). Restore puts one back.
private struct ArchivedConversationsView: View {
    let model: AppModel

    private var messages: MessagesViewModel { model.messages }

    var body: some View {
        let threads = messages.archived(context: model.organization.effective)
        SubScreen(title: "Archived", subtitle: "Hidden from Messages. The business isn't told.", backTitle: "Messages") {
            if let error = messages.errorMessage { ViadereNotice(error, kind: .warning) }
            if threads.isEmpty {
                ViadereEmptyState("Nothing archived", message: "Conversations you archive appear here.")
            } else {
                ViadereRowGroup {
                    ForEach(Array(threads.enumerated()), id: \.element.id) { index, conversation in
                        HStack(spacing: ViadereSpace.xs) {
                            ConversationRow(conversation: conversation)
                            Button("Restore") {
                                Task {
                                    if await messages.setArchived(conversation.id, false) { model.toast = FeedbackCopy.conversationArchived(false) }
                                }
                            }
                                .buttonStyle(.viadere(.quiet, fullWidth: false))
                                .accessibilityLabel(Text("Restore the conversation with \(conversation.business.safeName)"))
                        }
                        if index < threads.count - 1 { ViadereHairline(inset: 56) }
                    }
                }
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
                    if conversation.muted == true {
                        Image(systemName: "bell.slash")
                            .font(.system(size: 12, weight: .medium))
                            .foregroundStyle(ViadereColor.textTertiary)
                            .accessibilityLabel(Text("Muted"))
                    }
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
    /// The business's card decoration (an accent line at most; never its name or badge). From the verified local cache.
    @State private var decoration: MessageCardDecoration
    @Environment(\.dismiss) private var dismiss
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    /// PhotosPicker selection (iOS 17); emptied once each item is handed to the view model.
    @State private var pickedItems: [PhotosPickerItem] = []

    init(conversation: ConversationSummary, model: AppModel) {
        self.conversation = conversation
        self.model = model
        _vm = State(initialValue: ConversationViewModel(conversation: conversation, services: model.services))
        _decoration = State(initialValue: MessageCardDecoration.make(business: conversation.business, brand: model.services.brandKits))
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            ViadereHairline()
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(spacing: ViadereSpace.s) {
                        ForEach(vm.rows) { row in
                            MessageBubble(row: row, now: Date(), decoration: decoration, images: vm.loadedImages, failedImages: vm.imageErrors,
                                          onLoadImage: { attachment in Task { await vm.loadImage(attachment) } }) { option in
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
                    if let last = vm.rows.last?.id {
                        withViadereAnimation(ViadereMotion.gentle, reduceMotion: reduceMotion) { proxy.scrollTo(last, anchor: .bottom) }
                    }
                }
            }
            if let error = vm.errorMessage {
                ViadereNotice(error, kind: .warning)
                    .padding(.horizontal, ViadereSpace.screen)
                    .padding(.bottom, ViadereSpace.xs)
                    .transition(.opacity)
            }
            composer
        }
        .viadereAnimation(ViadereMotion.quick, value: vm.errorMessage)
        // One light tap when a message leaves, a warning when it could not be sent.
        .sensoryFeedback(.impact(weight: .light), trigger: vm.isSending) { was, now in was && !now && vm.errorMessage == nil }
        .sensoryFeedback(.warning, trigger: vm.errorMessage) { _, now in now != nil }
        .viadereScreenBackground()
        // The business's space: its kit tints the thread and its bubbles (re-resolved per theme); the sender line stays protected.
        .environment(\.brandStyle, BrandStyle(decoration.style))
        .toolbar(.hidden, for: .navigationBar)
        .task { await vm.load() }
        .task {
            // Separate task: branding never delays the thread.
            guard let store = model.services.brandKits, conversation.business.isVerified else { return }
            await store.refresh(conversation.business.id)
            decoration = MessageCardDecoration.make(business: conversation.business, brand: store)
        }
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
            if !vm.images.isEmpty { pendingImages }
            HStack(alignment: .bottom, spacing: ViadereSpace.xs) {
                if vm.canAddImage {
                    PhotosPicker(selection: $pickedItems, maxSelectionCount: MessageAttachmentPolicy.maxPerMessage - vm.images.count,
                                 matching: .images, preferredItemEncoding: .compatible) {
                        Image(systemName: "photo")
                            .font(.system(size: 17, weight: .regular))
                            .foregroundStyle(ViadereColor.textSecondary)
                            .frame(width: 44, height: 44)
                    }
                    .buttonStyle(.viaderePressable)
                    .accessibilityLabel(Text("Add a photo"))
                    .onChange(of: pickedItems) { _, items in
                        guard !items.isEmpty else { return }
                        pickedItems = []
                        Task { await addPicked(items) }
                    }
                }
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
                        .viadereAnimation(ViadereMotion.quick, value: vm.canSend)
                }
                .buttonStyle(.viaderePressable)
                .disabled(!vm.canSend)
                .accessibilityLabel(Text("Send"))
                .accessibilityHint(Text(vm.canSend ? "" : (vm.remainingCharacters < 0 ? "The message is too long" : "Write a message or add a photo first")))
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
        .background(BrandStyle(decoration.style).canvas)
    }

    /// Images waiting to be sent: a thumbnail each, its state, and Remove (MSG-ATT-03..06).
    private var pendingImages: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: ViadereSpace.xs) {
                ForEach(vm.images) { item in
                    ZStack(alignment: .topTrailing) {
                        ComposerThumbnail(data: item.data)
                            .overlay {
                                if item.isUploading {
                                    ProgressView().accessibilityLabel(Text("Adding image"))
                                } else if item.failure != nil {
                                    Button { Task { await vm.retryImage(item.id) } } label: {
                                        Image(systemName: "arrow.clockwise").font(.system(size: 15, weight: .semibold))
                                            .foregroundStyle(ViadereColor.textPrimary)
                                            .frame(width: 44, height: 44)
                                            .background(Circle().fill(ViadereColor.surface.opacity(0.9)))
                                    }
                                    .accessibilityLabel(Text("Try again"))
                                }
                            }
                        Button { vm.removeImage(item.id) } label: {
                            Image(systemName: "xmark").font(.system(size: 11, weight: .bold))
                                .foregroundStyle(ViadereColor.textPrimary)
                                .frame(width: 24, height: 24)
                                .background(Circle().fill(ViadereColor.surface))
                                .overlay(Circle().strokeBorder(ViadereColor.hairline, lineWidth: 1))
                        }
                        .frame(width: 44, height: 44, alignment: .topTrailing)
                        .accessibilityLabel(Text("Remove image"))
                    }
                    .accessibilityElement(children: .contain)
                    .accessibilityLabel(Text(item.failure ?? (item.isUploading ? "Image, adding" : "Image, ready to send")))
                }
            }
            .padding(.horizontal, ViadereSpace.m)
            .padding(.top, ViadereSpace.xs)
        }
    }

    /// Loads each picked photo, re-encodes it on the device (orientation applied, longest side 2048 px, JPEG, no metadata) and hands it to
    /// the view model, which checks it again before uploading.
    private func addPicked(_ items: [PhotosPickerItem]) async {
        for item in items {
            guard let raw = try? await item.loadTransferable(type: Data.self) else { continue }
            if let encoded = ComposerImageEncoder.jpeg(from: raw) {
                await vm.addImage(encoded, mediaType: "image/jpeg")
            } else {
                await vm.addImage(raw, mediaType: raw.starts(with: [0x89, 0x50, 0x4E, 0x47]) ? "image/png" : "image/jpeg")
            }
        }
    }
}

/// Re-encodes a picked photo before upload: redrawn (so EXIF orientation is applied and nothing but pixels survives), at most
/// `MessageAttachmentPolicy.maxStoredDimension` on the longest side, JPEG. The server re-encodes again; this only keeps uploads small.
enum ComposerImageEncoder {
    static func jpeg(from data: Data) -> Data? {
        #if canImport(UIKit)
        guard let image = UIImage(data: data), image.size.width > 0, image.size.height > 0 else { return nil }
        let longest = max(image.size.width, image.size.height)
        let scale = min(1, CGFloat(MessageAttachmentPolicy.maxStoredDimension) / longest)
        let size = CGSize(width: (image.size.width * scale).rounded(.down), height: (image.size.height * scale).rounded(.down))
        let format = UIGraphicsImageRendererFormat.default()
        format.scale = 1
        format.opaque = true
        let redrawn = UIGraphicsImageRenderer(size: size, format: format).image { _ in image.draw(in: CGRect(origin: .zero, size: size)) }
        guard let out = redrawn.jpegData(compressionQuality: 0.8), out.count <= MessageAttachmentPolicy.maxUploadBytes else { return nil }
        return out
        #else
        return nil
        #endif
    }
}

/// A square thumbnail of image bytes held in memory.
private struct ComposerThumbnail: View {
    let data: Data
    var body: some View {
        Group {
            #if canImport(UIKit)
            if let image = UIImage(data: data) {
                Image(uiImage: image).resizable().scaledToFill()
            } else {
                ViadereColor.surface
            }
            #else
            ViadereColor.surface
            #endif
        }
        .frame(width: 64, height: 64)
        .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(ViadereColor.hairline, lineWidth: 1))
        .accessibilityHidden(true)
    }
}

/// One image in a message: loaded through the conversation's attachment route, shown only once its bytes match the reference.
private struct MessageImage: View {
    let attachment: MessageAttachment
    let data: Data?
    let failed: Bool
    let fromCustomer: Bool
    let onLoad: (MessageAttachment) -> Void

    var body: some View {
        let ratio = CGFloat(max(1, attachment.width)) / CGFloat(max(1, attachment.height))
        Group {
            #if canImport(UIKit)
            if let data, let image = UIImage(data: data) {
                Image(uiImage: image).resizable().scaledToFit()
            } else {
                placeholder
            }
            #else
            placeholder
            #endif
        }
        .aspectRatio(ratio, contentMode: .fit)
        .frame(maxWidth: 240, maxHeight: 320)
        .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).strokeBorder(ViadereColor.hairline, lineWidth: 1))
        .accessibilityElement()
        .accessibilityLabel(Text(fromCustomer ? "Image you sent" : "Image"))
        .accessibilityAddTraits(.isImage)
        .task { if data == nil && !failed { onLoad(attachment) } }
    }

    private var placeholder: some View {
        ZStack {
            ViadereColor.surface
            if failed {
                VStack(spacing: 4) {
                    Image(systemName: "photo").foregroundStyle(ViadereColor.textTertiary).accessibilityHidden(true)
                    Text("Couldn't load this image.").font(ViadereType.caption).foregroundStyle(ViadereColor.textSecondary)
                        .multilineTextAlignment(.center)
                }
                .padding(ViadereSpace.s)
            } else {
                ProgressView()
            }
        }
    }
}

struct MessageBubble: View {
    let row: MessageRow
    let now: Date
    /// Brand decoration of business messages: an accent line beside the bubble. The sender line (name, verified mark) stays neutral.
    var decoration: MessageCardDecoration? = nil
    /// Verified bytes of this thread's images by id, the ones that could not be shown, and the loader (SECURITY.md §2.113).
    var images: [AttachmentID: Data] = [:]
    var failedImages: Set<AttachmentID> = []
    var onLoadImage: (MessageAttachment) -> Void = { _ in }
    let onChoose: (ChoiceOption) -> Void
    @Environment(\.brandStyle) private var brand

    var body: some View {
        let mine = row.isFromConsumer
        VStack(alignment: mine ? .trailing : .leading, spacing: 6) {
            if !mine {
                HStack(spacing: 4) {
                    Text(attribution).font(ViadereType.caption).foregroundStyle(ViadereColor.textSecondary)
                    Image(systemName: "checkmark.seal.fill").font(.system(size: 10)).foregroundStyle(ViadereColor.accent).accessibilityHidden(true)
                }
            }
            ForEach(row.message.attachments ?? []) { attachment in
                MessageImage(attachment: attachment, data: images[attachment.id], failed: failedImages.contains(attachment.id), fromCustomer: mine,
                             onLoad: onLoadImage)
                    .frame(maxWidth: 300, alignment: mine ? .trailing : .leading)
            }
            if !row.message.body.isEmpty || (row.message.attachments ?? []).isEmpty {
            HStack(alignment: .top, spacing: 6) {
                if !mine { BrandAccentLine(decoration) }
                Text(UntrustedText.paragraphs(row.message.body, max: 4_000))
                    .font(ViadereType.body)
                    .foregroundStyle(mine ? ViadereColor.onPrimary : ViadereColor.textPrimary)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 10)
                    .background(RoundedRectangle(cornerRadius: 20, style: .continuous).fill(mine ? ViadereColor.primaryFill : (brand.isBranded ? brand.card : ViadereColor.surface)))
                    .overlay(RoundedRectangle(cornerRadius: 20, style: .continuous).strokeBorder(mine ? .clear : ViadereColor.hairline, lineWidth: 1))
            }
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: 300, alignment: mine ? .trailing : .leading)
            }
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
