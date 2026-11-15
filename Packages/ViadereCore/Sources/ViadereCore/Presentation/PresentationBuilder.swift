import Foundation

/// A business identity from Viadere's **verified directory** (server record, or the device's copy of it). Never from the definition, the
/// manifest's free text or the client.
public struct VerifiedBusinessRecord: Sendable, Hashable {
    public var id: BusinessID
    public var displayName: String
    public var verificationStatus: VerificationStatus
    public var category: BusinessCategory

    public init(id: BusinessID, displayName: String, verificationStatus: VerificationStatus, category: BusinessCategory = .retail) {
        self.id = id
        self.displayName = displayName
        self.verificationStatus = verificationStatus
        self.category = category
    }
}

/// A Brand Kit already selected (`BrandKitSelector`) from a verified brand manifest.
public struct BrandKitPresentation: Sendable, Hashable {
    public var businessId: BusinessID
    public var kitId: String
    public var tokens: BrandTokens
    public var frameId: String?

    public init(businessId: BusinessID, kitId: String, tokens: BrandTokens, frameId: String? = nil) {
        self.businessId = businessId
        self.kitId = kitId
        self.tokens = tokens
        self.frameId = frameId
    }
}

/// Inputs of `PresentationBuilder.build` for a Loop.
public struct LoopPresentationContext: Sendable {
    /// The compact publication manifest JWS delivered with the instance.
    public var manifest: String?
    public var pinnedKeys: [PinnedManifestKey]
    public var definition: LoopDefinition
    /// The business the **instance** belongs to (server record).
    public var instanceBusinessId: BusinessID
    /// The verified directory record of the publisher; `nil` when the device cannot resolve it.
    public var publisher: VerifiedBusinessRecord?
    public var publicationStatus: LoopPublicationStatus
    public var brand: BrandKitPresentation?
    public var now: Date
    public var registry: LoopActionRegistry
    public var phase: LoopPlatformPhase
    public var frames: FrameRegistry

    public init(manifest: String?, pinnedKeys: [PinnedManifestKey], definition: LoopDefinition, instanceBusinessId: BusinessID,
                publisher: VerifiedBusinessRecord?, publicationStatus: LoopPublicationStatus = .active, brand: BrandKitPresentation? = nil,
                now: Date, registry: LoopActionRegistry = .v1, phase: LoopPlatformPhase = .hosted, frames: FrameRegistry = .v1) {
        self.manifest = manifest
        self.pinnedKeys = pinnedKeys
        self.definition = definition
        self.instanceBusinessId = instanceBusinessId
        self.publisher = publisher
        self.publicationStatus = publicationStatus
        self.brand = brand
        self.now = now
        self.registry = registry
        self.phase = phase
        self.frames = frames
    }
}

/// Which view of a Loop to build.
public enum PresentationPhase: Sendable, Hashable {
    /// A step; for `result` steps, `outcome` is the server's current outcome of the submitted event.
    case step(String, outcome: LoopActionOutcome? = nil)
    /// The confirmation of `actionId` on `stepId` (consequential actions only).
    case confirm(stepId: String, actionId: String)
}

/// Why the builder produced the safe fallback.
public enum PresentationFallbackReason: String, Sendable, Codable, CaseIterable, Hashable {
    case manifestMissing = "manifest_missing"
    case manifestInvalid = "manifest_invalid"
    case attributionPolicyUnknown = "attribution_policy_unknown"
    case definitionHashMismatch = "definition_hash_mismatch"
    case publisherMismatch = "publisher_mismatch"
    case publisherUnknown = "publisher_unknown"
    case publisherNotVerified = "publisher_not_verified"
    case publisherNameInvalid = "publisher_name_invalid"
    case definitionRejected = "definition_rejected"
    case publicationNotActive = "publication_not_active"
    case unknownStep = "unknown_step"
    case unknownAction = "unknown_action"
}

/// Builds the `PresentationTree` (plan section 4.4). Pure; the **only** producer of trees, so the attribution and confirmation invariants
/// live here and not in renderers or business data:
///
/// 1. A business Loop's first node is the protected `attribution_bar` ("Built by {verified name}"), derived from the verified manifest
///    and the verified directory record. The definition has no member that can remove, move or restyle it.
/// 2. Missing, unsigned, unverifiable, expired or mismatched publisher metadata (or an unknown `attribution_policy_version`) yields the
///    neutral fallback ("This request can't be shown", Close and Report only). The body is never rendered.
/// 3. Consequential actions get a protected confirmation panel from the action registry naming the responsible business and the effect.
/// 4. Accessibility: the attribution bar is first in reading order with an explicit label; `compactOrigin` serves compact surfaces.
/// 5. Brand tokens are clamped by `ContrastPolicy` and never reach protected nodes; a kit of another business is ignored.
/// 6. The definition is re-validated on the device (`LoopPolicyValidator`): a definition that fails the hard gate is not rendered.
public enum PresentationBuilder {
    public static let compactOriginMaxCharacters = 24
    static let businessNameMaxCharacters = 40

    public static func build(_ context: LoopPresentationContext, phase: PresentationPhase) -> PresentationTree {
        // 1. Publisher metadata.
        let manifest: LoopPublicationManifest
        do {
            manifest = try LoopPublicationManifest.verify(context.manifest, keys: context.pinnedKeys, now: context.now)
        } catch {
            return fallback(error == .missing ? .manifestMissing : .manifestInvalid)
        }
        guard LoopStringCatalog.supportedAttributionPolicyVersions.contains(manifest.attributionPolicyVersion) else { return fallback(.attributionPolicyUnknown) }
        guard let hash = try? context.definition.definitionHash(), ConstantTime.equals(hash, manifest.definitionHash) else {
            return fallback(.definitionHashMismatch)
        }
        guard context.publicationStatus == .active else {
            return context.publicationStatus == .suspended ? paused() : fallback(.publicationNotActive)
        }

        var origin = PresentationOrigin.viadere
        var attribution: AttributionNode?
        var publisherName = "Viadere"
        var compact: String?
        var publisherIdentity: LoopPublisherIdentity?
        switch manifest.publisherType {
        case .business:
            guard let business = manifest.publisherBusinessId, business == context.instanceBusinessId else { return fallback(.publisherMismatch) }
            guard let record = context.publisher else { return fallback(.publisherUnknown) }
            guard record.id == business else { return fallback(.publisherMismatch) }
            guard record.verificationStatus == .verified else { return fallback(.publisherNotVerified) }
            guard let name = verifiedName(record.displayName) else { return fallback(.publisherNameInvalid) }
            origin = .business
            publisherName = name
            compact = compactOrigin(name)
            attribution = AttributionNode(text: LoopStringCatalog.builtBy(name), accessibilityLabel: LoopStringCatalog.builtByAccessibility(name),
                                          businessId: business, businessName: name, verified: true, verifiedLabel: LoopStringCatalog.verifiedBadge,
                                          role: .primary, protected: true)
            publisherIdentity = LoopPublisherIdentity(publisherType: .business, businessId: business, verificationStatus: record.verificationStatus,
                                                      category: record.category)
        case .viadere:
            // First-party: never labeled "Built by". A business instance can never be shown as first-party.
            guard manifest.publisherBusinessId == nil else { return fallback(.publisherMismatch) }
        }

        // 6. Device-side re-validation (defense in depth: a compromised or outdated server cannot ship a hard-gate failure).
        var validation = LoopValidationContext(submittingBusinessId: context.instanceBusinessId, publisher: publisherIdentity, phase: context.phase,
                                               registry: context.registry)
        validation.skipsPublisherRules = manifest.publisherType == .viadere
        guard LoopPolicyValidator.validate(context.definition, context: validation).gate.passed else { return fallback(.definitionRejected) }

        let style = style(for: context, origin: origin)
        let definition = context.definition
        let screenTitle = DisplayTextSanitizer.sanitize(definition.title, maxCharacters: LoopLimits.titleLength)
        var children: [PresentationNode] = []
        if let attribution { children.append(.attributionBar(attribution)) }

        switch phase {
        case .step(let stepId, let outcome):
            guard let step = definition.step(stepId) else { return fallback(.unknownStep) }
            children.append(.header(HeaderNode(text: DisplayTextSanitizer.sanitize(step.title ?? definition.title, maxCharacters: LoopLimits.stepTitleLength), role: .primary)))
            if let body = step.body { children.append(.text(TextNode(text: DisplayTextSanitizer.sanitize(body, maxCharacters: LoopLimits.bodyLength), role: .secondary))) }
            if !step.fields.isEmpty {
                children.append(.fieldGroup(FieldGroupNode(id: step.id, children: step.fields.map(fieldNode))))
                if step.fields.contains(where: { $0.type == .shortText }) {
                    children.append(.notice(NoticeNode(kind: .healthPrivacy, title: nil, text: LoopStringCatalog.noHealthDetails, protected: true)))
                }
            }
            if step.type == .result, step.showOutcome == true, let outcome {
                children.append(.outcomeStatus(OutcomeStatusNode(outcome: outcome, text: LoopStringCatalog.outcomeText(outcome, business: publisherName), protected: true)))
            }
            if !step.actions.isEmpty {
                let actions = step.actions.enumerated().compactMap { index, binding -> ActionNode? in
                    guard case .registered(let def) = context.registry.resolve(binding.action) else { return nil }
                    let label = binding.customLabel.map { DisplayTextSanitizer.sanitize($0, maxCharacters: LoopLimits.customLabelLength) }
                        ?? LoopStringCatalog.actionLabels[binding.label] ?? def.title
                    return ActionNode(id: binding.id, actionType: def.actionType, label: label, role: index == 0 ? .primary : .secondary,
                                      requiresConfirmation: def.confirmation != nil, system: false)
                }
                children.append(.actionBar(ActionBarNode(actions: actions, protected: false)))
            }
        case .confirm(let stepId, let actionId):
            guard let step = definition.step(stepId) else { return fallback(.unknownStep) }
            guard let binding = step.actions.first(where: { $0.id == actionId }), case .registered(let def) = context.registry.resolve(binding.action),
                  let template = def.confirmation else { return fallback(.unknownAction) }
            let amount = LoopParameterValue.money(binding.params?["amount"])?.formatted
            let title = LoopStringCatalog.fill(template.title, business: publisherName, amount: amount)
            let statement = LoopStringCatalog.fill(template.statement, business: publisherName, amount: amount)
            let effect = LoopStringCatalog.fill(template.effect, business: publisherName, amount: amount)
            let responsible = manifest.publisherBusinessId ?? context.instanceBusinessId
            children.append(.confirmationPanel(ConfirmationPanelNode(
                actionId: binding.id, title: title, statement: statement, effect: effect, amount: amount, responsibleBusinessId: responsible,
                responsibleBusinessName: publisherName,
                accessibilityLabel: "\(title). \(statement) \(effect) Responsible business: \(publisherName).", protected: true)))
            if def.parameters.contains(where: { $0.name == "terms" }), let terms = binding.params?["terms"]?.stringValue {
                children.append(.text(TextNode(text: DisplayTextSanitizer.sanitize(terms, maxCharacters: 300), role: .secondary)))
            }
            children.append(.actionBar(ActionBarNode(actions: [
                ActionNode(id: binding.id, actionType: def.actionType, label: LoopStringCatalog.actionLabels[template.confirmLabel] ?? def.title,
                           role: .primary, requiresConfirmation: false, system: false),
                ActionNode(id: "cancel", actionType: "viadere.cancel", label: LoopStringCatalog.cancel, role: .secondary, requiresConfirmation: false, system: true),
            ], protected: true)))
        }

        return PresentationTree(v: PresentationTree.version, origin: origin,
                                root: .screen(ScreenNode(id: definition.key, title: screenTitle, children: children)),
                                style: style, fallbackReason: nil, compactOrigin: compact)
    }

    /// A first-party Viadere screen composed of modules (business home, Alerts, ...): never carries a "Built by" label (A6a.3, A6a.T3).
    public static func firstPartyScreen(id: String, title: String, modules: [ModulePlacement]) -> PresentationTree {
        PresentationTree(v: PresentationTree.version, origin: .viadere,
                         root: .screen(ScreenNode(id: id, title: title, children: modules.map { .moduleSlot(ModuleSlotNode(module: $0.module, size: $0.size)) })),
                         style: .neutral, fallbackReason: nil, compactOrigin: nil)
    }

    /// The concise business-origin indicator for notification titles, Live Activities and widgets (A6a.T6): "By {name}", sanitized and
    /// shortened to fit. `nil` when the name cannot be shown safely (then the compact surface uses the generic Viadere title instead).
    public static func compactOrigin(_ verifiedName: String, maxCharacters: Int = compactOriginMaxCharacters) -> String? {
        guard let name = self.verifiedName(verifiedName) else { return nil }
        let room = max(4, maxCharacters - 3)
        return LoopStringCatalog.compactOrigin(DisplayTextSanitizer.sanitize(name, maxCharacters: room))
    }

    /// A display name fit for attribution: sanitized, non-empty, never mentioning Viadere.
    static func verifiedName(_ raw: String) -> String? {
        let name = DisplayTextSanitizer.sanitize(raw, maxCharacters: businessNameMaxCharacters)
        guard !name.isEmpty, !DisplayTextSanitizer.impersonatesViadere(name, anywhere: true) else { return nil }
        return name
    }

    static func fieldNode(_ field: LoopField) -> PresentationNode {
        let label = DisplayTextSanitizer.sanitize(field.label, maxCharacters: LoopLimits.fieldLabelLength)
        let options = (field.options ?? []).map { ChoiceOptionNode(id: $0.id, label: DisplayTextSanitizer.sanitize($0.label, maxCharacters: LoopLimits.optionLabelLength)) }
        switch field.type {
        case .singleChoice, .multiChoice, .timeSlot:
            return .choice(ChoiceNode(fieldId: field.id, label: label, multiple: field.type == .multiChoice,
                                      control: field.type == .timeSlot ? "time_slot" : "list", required: field.required ?? false, options: options))
        case .shortText:
            return .input(InputNode(fieldId: field.id, label: label, input: "short_text", required: field.required ?? false,
                                    maxLength: min(field.maxLength ?? LoopLimits.maxShortTextLength, LoopLimits.maxShortTextLength)))
        case .date, .yesNo, .acknowledgement:
            return .input(InputNode(fieldId: field.id, label: label, input: field.type.rawValue, required: field.required ?? false, maxLength: nil))
        }
    }

    static func style(for context: LoopPresentationContext, origin: PresentationOrigin) -> PresentationStyle {
        // A kit applies only to a business Loop that asked for that kit, and only if it belongs to the same business.
        guard origin == .business, case .brandKit(let key) = context.definition.appearance, let brand = context.brand,
              brand.kitId == key, brand.businessId == context.instanceBusinessId else { return .neutral }
        return PresentationStyle(source: .brandKit, kitId: brand.kitId, palette: ContrastPolicy.resolve(brand.tokens),
                                 frameId: context.frames.resolve(brand.frameId, at: context.now), radius: brand.tokens.radius ?? .medium,
                                 border: brand.tokens.border ?? .hairline, typeScale: brand.tokens.typeScale ?? .standard)
    }

    /// The safe fallback: no business content, neutral style, Close and Report only.
    public static func fallback(_ reason: PresentationFallbackReason) -> PresentationTree {
        PresentationTree(v: PresentationTree.version, origin: .unavailable, root: .screen(ScreenNode(id: "unavailable", title: LoopStringCatalog.unavailableTitle, children: [
            .notice(NoticeNode(kind: .unavailable, title: LoopStringCatalog.unavailableTitle, text: LoopStringCatalog.unavailableBody, protected: true)),
            .actionBar(ActionBarNode(actions: [
                ActionNode(id: "close", actionType: "viadere.close", label: LoopStringCatalog.close, role: .primary, requiresConfirmation: false, system: true),
                ActionNode(id: "report", actionType: "viadere.report", label: LoopStringCatalog.report, role: .secondary, requiresConfirmation: false, system: true),
            ], protected: true)),
        ])), style: .neutral, fallbackReason: reason.rawValue, compactOrigin: nil)
    }

    static func paused() -> PresentationTree {
        PresentationTree(v: PresentationTree.version, origin: .unavailable, root: .screen(ScreenNode(id: "paused", title: LoopStringCatalog.pausedTitle, children: [
            .notice(NoticeNode(kind: .paused, title: LoopStringCatalog.pausedTitle, text: "Nothing here can be sent right now.", protected: true)),
            .actionBar(ActionBarNode(actions: [
                ActionNode(id: "close", actionType: "viadere.close", label: LoopStringCatalog.close, role: .primary, requiresConfirmation: false, system: true),
            ], protected: true)),
        ])), style: .neutral, fallbackReason: "publication_suspended", compactOrigin: nil)
    }
}
