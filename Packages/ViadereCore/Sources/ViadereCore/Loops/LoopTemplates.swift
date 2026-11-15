import Foundation

/// A locked starting definition for Loop Studio (WP-3.7; plan section 4.12 "locked templates are the fast path").
///
/// Templates are Viadere-written constants: a business never edits a template, it edits a **draft** that starts as a copy. A revision whose
/// structure still matches the template it came from (`matches`) is flagged as a template revision so the reviewer's checklist is pre-filled;
/// it still passes every stage of the review pipeline. The server decides the flag from the submitted document, never from a client claim.
public struct LoopTemplate: Sendable, Hashable {
    /// Stable identifier (`ContractIdentifier` grammar), stored as `loop_revisions.template_key`.
    public var key: String
    /// Gallery name.
    public var name: String
    /// One-sentence gallery description.
    public var summary: String
    /// Starting definition. Passes the hard gate for a verified, eligible business publisher.
    public var definition: LoopDefinition

    public init(key: String, name: String, summary: String, definition: LoopDefinition) {
        self.key = key
        self.name = name
        self.summary = summary
        self.definition = definition
    }

    /// The structural skeleton of `definition`: step ids, types and order; field ids and types; action ids, registered types, targets,
    /// routing mode and parameter names. Text (titles, bodies, labels, options, custom labels), label choices, queues, `required`,
    /// `max_length`, entry points, appearance and expiry are **not** structure: a business may change them and stay on the fast path.
    public static func skeleton(of definition: LoopDefinition) -> JSONValue {
        .array(definition.steps.map { step in
            var o: [String: JSONValue] = ["id": .string(step.id), "type": .string(step.type.rawValue)]
            if let handoff = step.handoff { o["handoff"] = .string(handoff.rawValue) }
            o["fields"] = .array(step.fields.map { .object(["id": .string($0.id), "type": .string($0.type.rawValue)]) })
            o["actions"] = .array(step.actions.map { action in
                var a: [String: JSONValue] = ["id": .string(action.id), "action": .string(action.action)]
                if let next = action.next { a["next"] = .string(next) }
                if let routing = action.routing { a["routing"] = .string(routing.mode.rawValue) }
                a["params"] = .array((action.params ?? [:]).keys.sorted().map(JSONValue.string))
                return .object(a)
            })
            return .object(o)
        })
    }

    /// Whether `definition` keeps this template's structure (see `skeleton(of:)`).
    public func matches(_ definition: LoopDefinition) -> Bool { Self.skeleton(of: definition) == Self.skeleton(of: self.definition) }
}

/// The Loop Studio template gallery (WP-3.7): acknowledge, callback request, salon and repair-shop check-in, pickup time. Versioned with
/// the rule set: a template change is a code change, reviewed like the content rules (no healthcare use cases, examples or wording, FX-4
/// layer 5).
public enum LoopTemplateCatalog {
    public static let version = 1

    public static func template(_ key: String) -> LoopTemplate? { v1.first { $0.key == key } }

    /// The template `definition` was started from, if its structure still matches it.
    public static func matching(_ definition: LoopDefinition, startedFrom key: String?) -> LoopTemplate? {
        guard let key, let template = template(key), template.matches(definition) else { return nil }
        return template
    }

    private static let day: Int64 = 86_400

    private static func result(_ title: String) -> LoopStep { LoopStep(id: "done", type: .result, title: title, showOutcome: true) }

    public static let v1: [LoopTemplate] = [
        LoopTemplate(
            key: "acknowledge", name: "Acknowledge an update",
            summary: "Share a short update and let customers tell you they've seen it.",
            definition: LoopDefinition(
                key: "acknowledge-update", title: "Please read this update", entryPoints: [.message, .businessPage],
                steps: [
                    LoopStep(id: "s1", type: .summary, title: "An update from us",
                             body: "Our opening hours change next week. Tap below so we know you saw this.",
                             actions: [LoopActionBinding(id: "ack", action: "acknowledge", label: "got_it", next: "done",
                                                         routing: LoopRouting(mode: .hosted, queue: "general"))]),
                    result("Thanks for letting us know"),
                ], limits: LoopLimits(expiresInSeconds: 7 * day))),
        LoopTemplate(
            key: "callback_request", name: "Callback request",
            summary: "Customers pick a topic and a good time, and you call them back.",
            definition: LoopDefinition(
                key: "callback-request", title: "Request a callback", entryPoints: [.businessPage, .message],
                steps: [
                    LoopStep(id: "s1", type: .form, title: "How can we help?", fields: [
                        LoopField(id: "topic", type: .singleChoice, label: "What is it about?", required: true,
                                  options: [LoopOption(id: "order", label: "An order"), LoopOption(id: "booking", label: "A booking"),
                                            LoopOption(id: "other", label: "Something else")]),
                        LoopField(id: "when", type: .timeSlot, label: "Best time to call", required: true,
                                  options: [LoopOption(id: "morning", label: "Morning"), LoopOption(id: "afternoon", label: "Afternoon"),
                                            LoopOption(id: "evening", label: "Evening")]),
                    ], actions: [LoopActionBinding(id: "next", action: "select_option", label: "continue", next: "s2")]),
                    LoopStep(id: "s2", type: .summary, title: "Send your request", body: "We'll get back to you at the time you picked.",
                             actions: [LoopActionBinding(id: "send", action: "request_callback", label: "call_me_back", next: "done",
                                                         routing: LoopRouting(mode: .hosted, queue: "callbacks"))]),
                    result("Request sent"),
                ], limits: LoopLimits(expiresInSeconds: 2 * day))),
        LoopTemplate(
            key: "salon_check_in", name: "Salon check-in",
            summary: "Guests tell the front desk they've arrived for their appointment.",
            definition: LoopDefinition(
                key: "salon-check-in", title: "Check in for your visit", entryPoints: [.alert, .message, .businessPage],
                steps: [
                    LoopStep(id: "s1", type: .form, title: "Welcome", fields: [
                        LoopField(id: "where", type: .singleChoice, label: "Where are you?", required: true,
                                  options: [LoopOption(id: "inside", label: "Inside the salon"), LoopOption(id: "parking", label: "In the parking lot")]),
                    ], actions: [LoopActionBinding(id: "next", action: "select_option", label: "continue", next: "s2")]),
                    LoopStep(id: "s2", type: .summary, title: "Here for your appointment?", body: "Let us know you've arrived and we'll be right with you.",
                             actions: [LoopActionBinding(id: "arrive", action: "check_in", label: "i_have_arrived", next: "done",
                                                         routing: LoopRouting(mode: .hosted, queue: "front-desk"))]),
                    result("You're checked in"),
                ], limits: LoopLimits(expiresInSeconds: day))),
        LoopTemplate(
            key: "repair_check_in", name: "Repair shop drop-off",
            summary: "Customers check in when they drop off a vehicle or an item for service.",
            definition: LoopDefinition(
                key: "repair-check-in", title: "Drop-off check-in", entryPoints: [.alert, .message, .businessPage],
                steps: [
                    LoopStep(id: "s1", type: .form, title: "Your drop-off", fields: [
                        LoopField(id: "item", type: .shortText, label: "Vehicle or item", required: true, maxLength: 40),
                        LoopField(id: "keys", type: .yesNo, label: "Leaving keys at the counter?", required: true),
                    ], actions: [LoopActionBinding(id: "next", action: "select_option", label: "continue", next: "s2")]),
                    LoopStep(id: "s2", type: .summary, title: "Ready to check in?", body: "Tell the service desk you've arrived for your drop-off.",
                             actions: [LoopActionBinding(id: "arrive", action: "check_in", label: "check_in", next: "done",
                                                         routing: LoopRouting(mode: .hosted, queue: "service-desk"))]),
                    result("You're checked in"),
                ], limits: LoopLimits(expiresInSeconds: day))),
        LoopTemplate(
            key: "pickup_time", name: "Pickup time",
            summary: "Customers choose when they'll pick up an order.",
            definition: LoopDefinition(
                key: "pickup-time", title: "Choose a pickup time", entryPoints: [.businessPage, .message, .alert],
                steps: [
                    LoopStep(id: "s1", type: .form, title: "Pick a time", fields: [
                        LoopField(id: "slot", type: .timeSlot, label: "Pickup time", required: true,
                                  options: [LoopOption(id: "am", label: "Morning (9 to 12)"), LoopOption(id: "pm", label: "Afternoon (12 to 5)")]),
                    ], actions: [LoopActionBinding(id: "next", action: "select_pickup_time", label: "choose_time", next: "s2")]),
                    LoopStep(id: "s2", type: .summary, title: "Send your choice",
                             actions: [LoopActionBinding(id: "send", action: "acknowledge", label: "send_request", next: "done",
                                                         routing: LoopRouting(mode: .hosted, queue: "pickups"))]),
                    result("Choice sent"),
                ], limits: LoopLimits(expiresInSeconds: 3 * day))),
    ]
}

extension LoopFieldType {
    /// Why a field type outside the allowlist is refused (`secret`, `payment`, `government_id`, `health`, `free_text`, `upload`, `markup`,
    /// `link`), for clear editor messages; `nil` when the name is merely unknown. The control is the closed enum, not this list.
    public static func prohibitionReason(_ raw: String) -> String? { prohibited[raw.lowercased()] }
}
