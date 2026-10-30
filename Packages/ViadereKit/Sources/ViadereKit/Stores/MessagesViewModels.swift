import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class MessagesViewModel {
    public private(set) var conversations: [ConversationSummary] = []
    public private(set) var isLoading = false
    public private(set) var errorMessage: String?
    private let services: ViadereServices

    public init(services: ViadereServices, initial: [ConversationSummary] = []) {
        self.services = services
        self.conversations = initial
    }

    public var unreadTotal: Int { conversations.reduce(0) { $0 + $1.unreadCount } }

    public func load() async {
        isLoading = conversations.isEmpty
        defer { isLoading = false }
        do {
            conversations = try await services.api.conversations()
                .sorted { ($0.lastMessageAt ?? .distantPast) > ($1.lastMessageAt ?? .distantPast) }
            errorMessage = nil
        } catch {
            errorMessage = (error as? APIError)?.userMessage ?? "Couldn't load messages."
        }
    }

    // MARK: Organization (spec C4; WP-1.2)

    /// On-device search over the cached thread list (business name, handle, last preview). Message bodies are encrypted at rest on the
    /// server, so there is no server-side search; nothing here crosses into another tenant's data.
    public var searchQuery = ""

    /// Threads for the business context and the search, newest first. One business's history is never merged with another's.
    public func visible(context: OrganizationContext) -> [ConversationSummary] {
        let needle = searchQuery.trimmingCharacters(in: .whitespacesAndNewlines)
        return conversations.filter { thread in
            if let business = context.businessFilter, thread.business.id != business { return false }
            if thread.archived == true { return false }
            guard !needle.isEmpty else { return true }
            if BusinessDirectoryRules.matches(thread.business, query: needle) { return true }
            return thread.lastMessagePreview?.range(of: needle, options: [.caseInsensitive, .diacriticInsensitive]) != nil
        }
    }

    /// The All view groups threads by business (spec C2 "unified thread list grouped by business"), groups ordered by their newest thread.
    public func groups(context: OrganizationContext) -> [(business: BusinessSummary, threads: [ConversationSummary])] {
        var order: [BusinessID] = []
        var byBusiness: [BusinessID: (BusinessSummary, [ConversationSummary])] = [:]
        for thread in visible(context: context) {
            if byBusiness[thread.business.id] == nil {
                order.append(thread.business.id)
                byBusiness[thread.business.id] = (thread.business, [])
            }
            byBusiness[thread.business.id]?.1.append(thread)
        }
        return order.compactMap { byBusiness[$0].map { (business: $0.0, threads: $0.1) } }
    }

    public func unread(context: OrganizationContext) -> Int {
        conversations.filter { context.businessFilter == nil || $0.business.id == context.businessFilter }.reduce(0) { $0 + $1.unreadCount }
    }

    /// Archives (or restores) a thread for this account only; the business is never told.
    public func setArchived(_ id: SessionID, _ archived: Bool) async {
        guard let api = services.organizationAPI, let index = conversations.firstIndex(where: { $0.id == id }) else { return }
        let previous = conversations[index].archived
        conversations[index].archived = archived
        do { _ = try await api.updateConversation(id, ConversationStateUpdate(archived: archived)) } catch {
            if let i = conversations.firstIndex(where: { $0.id == id }) { conversations[i].archived = previous }
            errorMessage = (error as? APIError)?.userMessage ?? "Couldn't save that change."
        }
    }

    public func setMuted(_ id: SessionID, _ muted: Bool) async {
        guard let api = services.organizationAPI, let index = conversations.firstIndex(where: { $0.id == id }) else { return }
        let previous = conversations[index].muted
        conversations[index].muted = muted
        do { _ = try await api.updateConversation(id, ConversationStateUpdate(muted: muted)) } catch {
            if let i = conversations.firstIndex(where: { $0.id == id }) { conversations[i].muted = previous }
            errorMessage = (error as? APIError)?.userMessage ?? "Couldn't save that change."
        }
    }

    public func start(with business: BusinessID) async -> ConversationSummary? {
        do {
            let conversation = try await services.api.startConversation(with: business)
            if !conversations.contains(where: { $0.id == conversation.id }) { conversations.insert(conversation, at: 0) }
            return conversation
        } catch {
            errorMessage = (error as? APIError)?.userMessage ?? "Couldn't start a conversation."
            return nil
        }
    }
}

/// A message plus the structured `choose` request it carries, if still open.
public struct MessageRow: Identifiable, Equatable, Sendable {
    public var message: ConversationMessage
    public var choice: InteractionEnvelope?
    public var id: MessageID { message.id }
    public var isFromConsumer: Bool { message.direction == .consumerToBusiness }

    /// Structured options shown as chips, only while the choice is pending and unexpired.
    public func openOptions(now: Date) -> [ChoiceOption] {
        guard let choice, choice.status == .pending, !choice.interaction.isExpired(at: now),
              case .choose(let payload) = choice.interaction.payload else { return [] }
        return payload.options
    }
}

@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class ConversationViewModel {
    public private(set) var rows: [MessageRow] = []
    public var draft = ""
    public private(set) var isSending = false
    public private(set) var errorMessage: String?
    public let conversation: ConversationSummary
    private let services: ViadereServices
    public static let maxLength = 1600

    public init(conversation: ConversationSummary, services: ViadereServices) {
        self.conversation = conversation
        self.services = services
    }

    public var canSend: Bool {
        let text = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        return !text.isEmpty && text.count <= Self.maxLength && !isSending
    }

    public var remainingCharacters: Int { Self.maxLength - draft.count }

    public func load() async {
        do {
            let page = try await services.api.messages(in: conversation.id)
            var built: [MessageRow] = []
            for message in page.items.sorted(by: { $0.createdAt < $1.createdAt }) {
                var envelope: InteractionEnvelope?
                if let interactionId = message.interactionId { envelope = try? await services.api.interaction(interactionId) }
                built.append(MessageRow(message: message, choice: envelope))
            }
            rows = built
            errorMessage = nil
        } catch {
            errorMessage = (error as? APIError)?.userMessage ?? "Couldn't load this conversation."
        }
    }

    public func send() async {
        let text = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard canSend else { return }
        isSending = true
        defer { isSending = false }
        do {
            let message = try await services.api.sendMessage(in: conversation.id,
                                                             SendMessageRequest(body: text, clientMessageId: UUID().uuidString.lowercased()))
            rows.append(MessageRow(message: message, choice: nil))
            draft = ""
            errorMessage = nil
        } catch {
            errorMessage = (error as? APIError)?.userMessage ?? "Couldn't send that."
        }
    }

    /// Tapping a chip answers the structured `choose` interaction with a device-signed `select` decision.
    public func choose(_ option: ChoiceOption, in row: MessageRow) async {
        guard let envelope = row.choice else { return }
        do {
            let outcome = try await services.approvals.submit(envelope, decision: .select, selectedOptionIds: [option.id], channel: .inApp)
            if let index = rows.firstIndex(where: { $0.id == row.id }) { rows[index].choice?.status = outcome.status }
            errorMessage = nil
        } catch let error as ApprovalError {
            errorMessage = error.userMessage
        } catch {
            errorMessage = "Couldn't send that choice."
        }
    }
}
