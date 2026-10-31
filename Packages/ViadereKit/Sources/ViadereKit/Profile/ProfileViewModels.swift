import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

private func message(for error: any Error, _ fallback: String) -> String { (error as? APIError)?.userMessage ?? fallback }

/// Platform-neutral profile rules the screens share.
public enum ProfileRules {
    /// Whether the profile can supply `key` (derived fields: whether they can be computed).
    public static func hasValue(_ key: String, in profile: CustomerProfile) -> Bool {
        if key.hasPrefix("verified.") { return profile.verified.contains { $0.fact.fieldKey == key } }
        let sources = ProfileAccessPolicy.sourceKeys(for: key)
        return profile.fields.contains { sources.contains($0.key) }
    }

    /// The user-facing text for a validation issue.
    public static func text(for issue: ProfileValueIssue) -> String {
        switch issue {
        case .unknownField, .readOnly, .wrongType: "This field can't be edited."
        case .empty: "Enter a value or remove the field."
        case .tooShort: "This is too short."
        case .tooLong: "This is too long."
        case .disallowedCharacters: "Remove hidden or special characters."
        case .impersonation: "This can't mention Viadere."
        case .invalidFormat: "Check the format."
        case .notAllowed: "Choose one of the options."
        case .forbiddenIdentifier: "Viadere never stores card, bank or government ID numbers."
        case .entryRequired: "Add a label (for example the airline or program)."
        case .entryNotAllowed, .invalidEntry: "Check the label."
        case .tooManyEntries: "You've reached the limit for this field."
        }
    }

    public static func text(for issue: PublicName.Issue) -> String {
        switch issue {
        case .empty: "Enter a name."
        case .tooShort: "Use at least 2 characters."
        case .tooLong: "Use at most \(PublicName.maxCharacters) characters."
        case .disallowedCharacters: "Remove hidden or special characters."
        case .impersonation: "This name could look official. Choose another."
        case .contactData: "Don't put an email, link or number in your public name."
        }
    }

    /// Display title of a field key (falls back to the key for a newer catalog).
    public static func title(_ key: String) -> String { ProfileCatalog.definition(for: key)?.title ?? key }
}

// MARK: - Profile editor

/// The Profile screen: public name with a live preview, optional fields by category, and the Verified badge.
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class ProfileEditorViewModel {
    public private(set) var profile: CustomerProfile
    public private(set) var isLoading = false
    public private(set) var isSaving = false
    public private(set) var errorMessage: String?
    /// The custom public name being typed (`""` = use the default).
    public var publicNameDraft = ""
    private let api: (any ProfileAPI)?

    public init(api: (any ProfileAPI)?, initial: CustomerProfile = CustomerProfile(publicName: nil, customPublicName: nil, derivedPublicName: nil, fields: [], verified: [])) {
        self.api = api
        profile = initial
        publicNameDraft = initial.customPublicName ?? ""
    }

    /// What businesses will see if the draft is saved: the cleaned custom name, or the default.
    public var publicNamePreview: String? {
        let cleaned = PublicName.clean(publicNameDraft)
        return cleaned.isEmpty ? profile.derivedPublicName : cleaned
    }

    /// Why the draft can't be saved (`nil` = fine or empty).
    public var publicNameIssue: String? {
        guard !PublicName.clean(publicNameDraft).isEmpty || DisplayTextSanitizer.containsDisallowedScalars(publicNameDraft) else { return nil }
        return PublicName.validate(publicNameDraft).map(ProfileRules.text(for:))
    }

    public var isVerified: Bool { profile.isVerified }

    /// Categories in catalog order with the editable fields of each (derived fields are not edited).
    public var categories: [(category: ProfileCategory, fields: [ProfileFieldDefinition])] {
        ProfileCategory.allCases.filter { $0 != .verified }.map { ($0, ProfileCatalog.fields(in: $0).filter { !$0.isDerived }) }
    }

    public func entries(for key: String) -> [ProfileFieldEntry] { profile.fields.filter { $0.key == key } }

    /// Local validation before sending (the server validates again).
    public func issue(key: String, entry: String?, value: ProfileValue) -> String? {
        do {
            _ = try ProfileCatalog.validate(key: key, entry: entry, value: value)
            return nil
        } catch let issue as ProfileValueIssue {
            return ProfileRules.text(for: issue)
        } catch {
            return "Check this value."
        }
    }

    public func load() async {
        guard let api else { return }
        isLoading = true
        defer { isLoading = false }
        do {
            apply(try await api.profile())
            errorMessage = nil
        } catch {
            errorMessage = message(for: error, "Couldn't load your profile.")
        }
    }

    private func apply(_ updated: CustomerProfile) {
        profile = updated
        publicNameDraft = updated.customPublicName ?? ""
    }

    /// Saves the public name choice. Returns `false` (with `errorMessage`) when it is not valid.
    @discardableResult
    public func savePublicName() async -> Bool {
        if let issue = publicNameIssue { errorMessage = issue; return false }
        let cleaned = PublicName.clean(publicNameDraft)
        let update = cleaned.isEmpty ? ProfileUpdateRequest(useDerivedPublicName: true) : ProfileUpdateRequest(customPublicName: cleaned)
        return await send(update)
    }

    @discardableResult
    public func set(key: String, entry: String? = nil, value: ProfileValue) async -> Bool {
        if let issue = issue(key: key, entry: entry, value: value) { errorMessage = issue; return false }
        return await send(ProfileUpdateRequest(set: [ProfileFieldEntry(key: key, entry: entry, value: value)]))
    }

    @discardableResult
    public func remove(key: String, entry: String? = nil) async -> Bool {
        await send(ProfileUpdateRequest(remove: [ProfileFieldRef(key: key, entry: entry)]))
    }

    private func send(_ update: ProfileUpdateRequest) async -> Bool {
        guard let api else { return false }
        isSaving = true
        defer { isSaving = false }
        do {
            apply(try await api.updateProfile(update))
            errorMessage = nil
            return true
        } catch {
            errorMessage = message(for: error, "Couldn't save your profile.")
            return false
        }
    }

    /// Forgets verified facts (empty = all).
    public func removeVerification(_ facts: [ProfileVerifiedFactKind] = []) async {
        guard let api else { return }
        do {
            apply(try await api.removeVerifiedFacts(facts))
        } catch {
            errorMessage = message(for: error, "Couldn't update your verification.")
        }
    }
}

// MARK: - What this business can see

/// The per-business page: the public name (always shared), toggles per field within the categories Viadere allows the business, and revoke-all.
/// Changes are staged locally and saved together.
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class BusinessProfileAccessViewModel {
    public let business: BusinessID
    public private(set) var view: ProfileAccessView?
    public private(set) var staged: Set<String> = []
    public private(set) var isLoading = false
    public private(set) var isSaving = false
    public private(set) var errorMessage: String?
    private let api: (any ProfileAPI)?

    public init(api: (any ProfileAPI)?, business: BusinessID) {
        self.api = api
        self.business = business
    }

    public var hasChanges: Bool { staged != Set(view?.grantedKeys ?? []) }
    public var sharesAnything: Bool { !(view?.grantedKeys.isEmpty ?? true) }

    /// Fields grouped by category, in catalog order.
    public var groups: [(category: ProfileCategory, fields: [ProfileAccessField])] {
        guard let view else { return [] }
        return ProfileCategory.allCases.compactMap { category in
            let fields = view.fields.filter { ProfileCatalog.category(of: $0.key) == category }
            return fields.isEmpty ? nil : (category, fields)
        }
    }

    public func isOn(_ key: String) -> Bool { staged.contains(key) }

    /// A field outside the business's allowed categories can only be switched off.
    public func canToggle(_ key: String) -> Bool {
        guard let view else { return false }
        if staged.contains(key) { return true }
        return ProfileCatalog.category(of: key).map { view.allowedCategories.contains($0) } ?? false
    }

    public func toggle(_ key: String) {
        guard canToggle(key) else { return }
        if staged.contains(key) { staged.remove(key) } else { staged.insert(key) }
    }

    public func load() async {
        guard let api else { return }
        isLoading = true
        defer { isLoading = false }
        do {
            let loaded = try await api.access(business: business)
            view = loaded
            staged = Set(loaded.grantedKeys)
            errorMessage = nil
        } catch {
            errorMessage = message(for: error, "Couldn't load what this business can see.")
        }
    }

    @discardableResult
    public func save() async -> Bool { await commit(Array(staged)) }

    /// Stops sharing everything beyond the public name, immediately.
    @discardableResult
    public func revokeAll() async -> Bool {
        staged = []
        return await commit([])
    }

    private func commit(_ keys: [String]) async -> Bool {
        guard let api else { return false }
        isSaving = true
        defer { isSaving = false }
        do {
            let saved = try await api.setAccess(business: business, grantedKeys: keys.sorted())
            view = saved
            staged = Set(saved.grantedKeys)
            errorMessage = nil
            return true
        } catch {
            errorMessage = message(for: error, "Couldn't save your choices.")
            staged = Set(view?.grantedKeys ?? [])
            return false
        }
    }
}

// MARK: - Incoming request

/// A business's profile request (from Alerts): the business, its stated purpose (sanitized again here), and field-by-field approval. Nothing is
/// pre-selected: the customer opts in to each field.
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class ProfileRequestViewModel {
    public private(set) var prompt: ProfileRequestPrompt
    public private(set) var selected: Set<String> = []
    public private(set) var isSubmitting = false
    public private(set) var errorMessage: String?
    private let api: (any ProfileAPI)?
    private let clock: @Sendable () -> Date

    public init(api: (any ProfileAPI)?, prompt: ProfileRequestPrompt, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.api = api
        self.prompt = prompt
        self.clock = clock
    }

    /// The business's purpose, cleaned for display whatever the server sent.
    public var purpose: String { DisplayTextSanitizer.sanitize(prompt.purpose, maxCharacters: CreateProfileRequest.maxPurposeCharacters) }
    public var businessName: String { DisplayTextSanitizer.sanitize(prompt.business.displayName, maxCharacters: 64) }
    public var isActionable: Bool { prompt.isActionable(at: clock()) }

    /// A field the customer has no value for cannot be shared (they can add it in Profile first).
    public func canSelect(_ field: ProfileRequestedField) -> Bool { isActionable && field.hasValue && !field.alreadyGranted }

    public func toggle(_ key: String) {
        guard let field = prompt.fields.first(where: { $0.key == key }), canSelect(field) else { return }
        if selected.contains(key) { selected.remove(key) } else { selected.insert(key) }
    }

    @discardableResult
    public func approveSelected() async -> Bool { await submit(Array(selected)) }

    @discardableResult
    public func decline() async -> Bool { await submit([]) }

    private func submit(_ keys: [String]) async -> Bool {
        guard let api, isActionable else { errorMessage = "This request has expired."; return false }
        isSubmitting = true
        defer { isSubmitting = false }
        do {
            prompt = try await api.answer(prompt.id, approvedKeys: keys.sorted())
            errorMessage = nil
            return true
        } catch {
            errorMessage = message(for: error, "Couldn't send your answer.")
            return false
        }
    }
}

// MARK: - Receipts

@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class ProfileReceiptsViewModel {
    public private(set) var receipts: [ProfileDisclosureReceipt] = []
    public private(set) var errorMessage: String?
    private let api: (any ProfileAPI)?

    public init(api: (any ProfileAPI)?) { self.api = api }

    /// One line per receipt: "Shared Email, Phone" / "Stopped sharing Email".
    public static func summary(_ receipt: ProfileDisclosureReceipt) -> String {
        let fields = receipt.fieldKeys.map(ProfileRules.title).joined(separator: ", ")
        switch receipt.action {
        case .granted: return "Shared \(fields)"
        case .revoked: return "Stopped sharing \(fields)"
        case .unknown: return fields
        }
    }

    public func load() async {
        guard let api else { return }
        do {
            receipts = try await api.receipts()
            errorMessage = nil
        } catch {
            errorMessage = message(for: error, "Couldn't load your sharing history.")
        }
    }
}

// MARK: - Verification entry point

/// Starts a profile verification with the existing Verify methods. The app performs the Wallet presentment (or the provider SDK) with what
/// `begin` returns and hands the encrypted envelope to `complete`.
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class ProfileVerificationViewModel {
    public enum Phase: Equatable, Sendable { case choosing, started(ProfileVerificationStart), finished(ProfileVerificationStatus), failed(String) }
    public var keep: Set<ProfileVerifiedFactKind> = [.identity]
    public private(set) var phase: Phase = .choosing
    private let api: (any ProfileAPI)?

    public init(api: (any ProfileAPI)?) { self.api = api }

    public var canBegin: Bool { !keep.isEmpty }

    public func begin(_ method: ProfileVerificationMethod) async {
        guard let api, canBegin else { return }
        do {
            phase = .started(try await api.beginVerification(ProfileVerificationBegin(method: method, keep: keep.sorted { $0.rawValue < $1.rawValue })))
        } catch {
            phase = .failed(message(for: error, "Verification isn't available right now."))
        }
    }

    public func complete(envelope: String?) async {
        guard let api, case .started(let start) = phase else { return }
        do {
            phase = .finished(try await api.completeVerification(start.attemptId, envelope: envelope).status)
        } catch {
            phase = .failed(message(for: error, "We couldn't verify your ID."))
        }
    }

    public func reset() { phase = .choosing }

    func failVerification(_ text: String) { phase = .failed(text) }
}
