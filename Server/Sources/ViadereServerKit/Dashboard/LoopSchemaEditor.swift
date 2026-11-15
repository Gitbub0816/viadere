import Foundation
import ViadereCore

/// Advanced Studio mode (feature expansion v4 Phase 4, WP-4.7; SECURITY.md §2.115 "Advanced Studio mode"): the draft edited as JSON.
///
/// Still data only and still the full pipeline: the text is parsed by the strict `LoopDefinition.parse` (every unknown member, floating
/// point, wrong type or size is refused), then held to the **same closed schema as the form editor** before anything is stored: actions
/// registered and available in the server's phase (reserved names refused with their reason), labels from each action's allowed set,
/// custom labels only where allowed, `next` among the draft's own steps, routing only for delivering actions and only to a mode the action
/// and the phase offer, parameters only the registered ones, no handoff step (no handoff module has shipped), appearance `standard` or one
/// of the business's own **approved** Brand Kits. The Loop key is the draft's, whatever the text says. Saving stores the canonical form;
/// `LoopPolicyValidator` reports on it like on any draft, and submission is `LoopPublicationService.submit` (hard gate, human review,
/// signing). Nothing here publishes.
enum LoopSchemaEditor {
    /// Largest accepted text (the canonical form is capped again by `LoopStudioService.save`).
    static let maxBytes = 64 * 1024

    static func parse(_ text: String, base: LoopDefinition, approvedKits: Set<String>, phase: LoopPlatformPhase) throws -> LoopDefinition {
        guard !text.isEmpty, text.utf8.count <= maxBytes else {
            throw APIError.validation("Paste a Loop definition of at most 64 KB.", details: ["schema": "size"])
        }
        let parsed = LoopDefinition.parse(Data(text.utf8))
        // `parse` returns a best-effort definition next to its issues; any issue at all refuses the text (nothing best-effort is stored).
        guard parsed.issues.isEmpty, var d = parsed.definition else {
            let first = parsed.issues.prefix(5).map { "\($0.code) at \($0.path.isEmpty ? "definition" : $0.path)" }.joined(separator: "; ")
            throw APIError.validation("The JSON isn't a valid Loop definition: \(first.isEmpty ? "unreadable" : first).", details: ["schema": parsed.issues.first?.code ?? "malformed"])
        }
        d.key = base.key
        func refuse(_ message: String, _ code: String, _ path: String) -> APIError {
            APIError.validation("\(message) (\(path)).", details: ["schema": code])
        }
        if case .brandKit(let key) = d.appearance, !approvedKits.contains(key), base.appearance != .brandKit(key) {
            throw refuse("Choose one of your approved Brand Kits", "unknown_brand_kit", "appearance")
        }
        let available = Set(ConsoleLoopStudio.availableActions(phase).map(\.actionType))
        let stepIds = Set(d.steps.map(\.id))
        for (i, step) in d.steps.enumerated() {
            if step.type == .handoff { throw refuse("Handoff steps aren't available", "handoff_not_available", "steps[\(i)]") }
            for (k, binding) in step.actions.enumerated() {
                let path = "steps[\(i)].actions[\(k)]"
                let definition: LoopActionDefinition
                switch LoopActionRegistry.v1.resolve(binding.action) {
                case .reserved(let reason): throw refuse("This action can never be used (\(reason.rawValue))", "reserved_action", path)
                case .unregistered: throw refuse("Choose a registered action", "unregistered_action", path)
                case .registered(let def): definition = def
                }
                guard available.contains(definition.actionType) else { throw refuse("This action isn't available yet", "action_not_available", path) }
                guard definition.allowedLabelKeys.contains(binding.label) else { throw refuse("Choose a label the action allows", "label_not_allowed", path) }
                if binding.customLabel != nil, !definition.customLabelAllowed { throw refuse("This button can't have custom text", "custom_label_not_allowed", path) }
                if let next = binding.next, !stepIds.contains(next) { throw refuse("Lead to one of this Loop's steps", "unknown_next_step", path) }
                if let routing = binding.routing {
                    guard definition.deliversToBusiness, definition.routing.contains(routing.mode), routing.mode != .connected || phase >= .connected else {
                        throw refuse("This routing isn't available for this action", "routing_mode_not_available", path)
                    }
                }
                let registered = Set(definition.parameters.map(\.name))
                if let params = binding.params, !Set(params.keys).isSubset(of: registered) {
                    throw refuse("Only the action's own parameters are allowed", "unknown_parameter", path)
                }
            }
        }
        return d
    }
}
