import Foundation
import Testing
@testable import ViadereCore

/// WP-3.1 "Tests first" and the FX-3/FX-4/FX-5 hard-gate rules of `LoopPolicyValidator`.
@Suite("Loop definition and policy validator")
struct LoopPolicyValidatorTests {
    func report(_ value: JSONValue, _ context: LoopValidationContext = FX.context()) -> LoopValidationReport {
        LoopPolicyValidator.validate(value, context: context)
    }

    func rules(_ value: JSONValue, _ context: LoopValidationContext = FX.context()) -> Set<LoopRule> { report(value, context).rules }

    func hard(_ value: JSONValue, _ context: LoopValidationContext = FX.context()) -> Set<LoopRule> {
        Set(report(value, context).hardGateHits.map(\.rule))
    }

    // MARK: Schema and canonical form

    @Test func validDefinitionPassesAndRoundTrips() throws {
        let r = report(FX.pickupValue)
        #expect(r.hits.isEmpty, "\(r.hits)")
        #expect(r.gate.passed)
        #expect(r.derivedRiskClass == .medium)
        #expect(r.requiredReview == .single)
        // Parse → canonical JSON → parse is lossless, and the hash is over the canonical bytes.
        let parsed = FX.pickup
        #expect(parsed.jsonValue == FX.pickupValue)
        #expect(LoopDefinition.parse(parsed.jsonValue).definition == parsed)
        #expect(try parsed.definitionHash() == ContractHash.sha256(FX.pickupValue))
        #expect(r.definitionHash == (try parsed.definitionHash()))
        #expect(ContractHash.isValid(try parsed.definitionHash()))
    }

    @Test func typedDefinitionIsValidatedLikeBytes() throws {
        let bytes = try FX.pickup.canonicalJSON()
        #expect(LoopPolicyValidator.validate(bytes, context: FX.context()).hits.isEmpty)
        #expect(LoopPolicyValidator.validate(FX.pickup, context: FX.context()).hits.isEmpty)
        #expect(LoopPolicyValidator.validate(Data("{not json".utf8), context: FX.context()).rules == [.malformedJSON])
        #expect(LoopPolicyValidator.validate(Data("[1.5]".utf8), context: FX.context()).rules == [.malformedJSON])
    }

    @Test func unknownMembersAreRejectedEverywhere() {
        // Root, step, field, option, action, routing, limits, appearance: an extra member is never ignored.
        let paths: [[Any]] = [["extra"], ["steps", 0, "skip_confirmation"], ["steps", 0, "fields", 0, "html"],
                              ["steps", 0, "fields", 0, "options", 0, "url"], ["steps", 1, "actions", 0, "operation"],
                              ["steps", 1, "actions", 0, "routing", "endpoint"], ["limits", "max_steps"], ["appearance", "colors"]]
        for path in paths {
            let value = FX.modify(FX.pickupValue, path, .string("x"))
            #expect(hard(value).contains(.unknownMember), "\(path)")
            #expect(!report(value).gate.passed)
        }
        // A definition cannot carry its own confirmation or attribution members.
        #expect(hard(FX.modify(FX.pickupValue, ["attribution"], .string("Built by Viadere"))).contains(.unknownMember))
        #expect(hard(FX.modify(FX.pickupValue, ["steps", 1, "actions", 0, "confirmation"], .bool(false))).contains(.unknownMember))
    }

    @Test func structuralErrors() {
        #expect(hard(FX.modify(FX.pickupValue, ["schema_version"], .integer(2))).contains(.unsupportedSchemaVersion))
        #expect(hard(FX.modify(FX.pickupValue, ["title"], nil)).contains(.missingMember))
        #expect(hard(FX.modify(FX.pickupValue, ["title"], .integer(1))).contains(.wrongType))
        #expect(hard(FX.modify(FX.pickupValue, ["key"], .string("Pickup Scheduling!"))).contains(.invalidIdentifier))
        #expect(hard(FX.modify(FX.pickupValue, ["entry_points"], .array([]))).contains(.missingEntryPoint))
        #expect(hard(FX.modify(FX.pickupValue, ["entry_points"], .array([.string("lock_screen")]))).contains(.invalidValue))
        #expect(hard(FX.modify(FX.pickupValue, ["steps", 0, "type"], .string("script"))).contains(.unknownStepType))
        #expect(hard(FX.modify(FX.pickupValue, ["limits", "expires_in_seconds"], .integer(60))).contains(.invalidLimit))
        #expect(hard(FX.modify(FX.pickupValue, ["limits", "expires_in_seconds"], .integer(90 * 86400))).contains(.invalidLimit))
        #expect(hard(FX.modify(FX.pickupValue, ["steps", 1, "id"], .string("s1"))).contains(.duplicateId))
        #expect(hard(.array([])) == [.wrongType])
        // Members that do not belong to the step type.
        #expect(hard(FX.modify(FX.pickupValue, ["steps", 2, "actions"], .array([])), FX.context()).contains(.memberNotAllowedForStepType))
        #expect(hard(FX.modify(FX.pickupValue, ["steps", 1, "fields"], .array([]))).contains(.memberNotAllowedForStepType))
    }

    @Test func sizeLimits() {
        var d = FX.pickup
        d.steps = (0..<9).map { i in LoopStep(id: "s\(i)", type: .summary, actions: [LoopActionBinding(id: "a\(i)", action: "acknowledge", label: "got_it", next: "s\(i + 1)", routing: LoopRouting(mode: .hosted))]) }
        d.steps.append(LoopStep(id: "s9", type: .result))
        #expect(LoopPolicyValidator.validate(d, context: FX.context()).rules.contains(.tooManySteps))

        var f = FX.pickup
        f.steps[0].fields = (0..<7).map { LoopField(id: "f\($0)", type: .yesNo, label: "Question \($0)") }
        #expect(LoopPolicyValidator.validate(f, context: FX.context()).rules.contains(.tooManyFields))

        var a = FX.pickup
        a.steps[1].actions = (0..<4).map { LoopActionBinding(id: "x\($0)", action: "acknowledge", label: "got_it", next: "done", routing: LoopRouting(mode: .hosted)) }
        #expect(LoopPolicyValidator.validate(a, context: FX.context()).rules.contains(.tooManyActions))

        var o = FX.pickup
        o.steps[0].fields[0].options = [LoopOption(id: "only", label: "Only")]
        #expect(LoopPolicyValidator.validate(o, context: FX.context()).rules.contains(.invalidOptions))

        var big = FX.pickup
        big.description = String(repeating: "a", count: 150)
        big.steps[0].fields = (0..<6).map { i in
            LoopField(id: "f\(i)", type: .singleChoice, label: "Choice \(i)", options: (0..<10).map { LoopOption(id: "o\($0)", label: String(repeating: "x", count: 100)) })
        }
        let many = (0..<6).map { s in LoopStep(id: "p\(s)", type: .form, fields: big.steps[0].fields, actions: [LoopActionBinding(id: "n\(s)", action: "select_option", label: "next", next: s == 5 ? "s2" : "p\(s + 1)")]) }
        big.steps = many + [big.steps[1], big.steps[2]]
        #expect(LoopPolicyValidator.validate(big, context: FX.context()).rules.contains(.definitionTooLarge))
    }

    // MARK: Graph sanity

    @Test func cyclesAndUnreachableStepsAreRejected() {
        #expect(hard(FX.modify(FX.pickupValue, ["steps", 1, "actions", 0, "next"], .string("s1"))).contains(.cycle))
        #expect(hard(FX.modify(FX.pickupValue, ["steps", 0, "actions", 0, "next"], .string("s1"))).contains(.cycle))
        #expect(hard(FX.modify(FX.pickupValue, ["steps", 0, "actions", 0, "next"], .string("nowhere"))).contains(.unknownNextStep))
        #expect(hard(FX.modify(FX.pickupValue, ["steps", 0, "actions", 0, "next"], nil)).contains(.missingNext))
        // s2 skipped: unreachable.
        #expect(hard(FX.modify(FX.pickupValue, ["steps", 0, "actions", 0, "next"], .string("done"))).contains(.unreachableStep))
        // No terminal step.
        var d = FX.pickup
        d.steps.removeLast()
        d.steps[1].actions[0].next = "s1"
        let r = LoopPolicyValidator.validate(d, context: FX.context()).rules
        #expect(r.contains(.noTerminalStep) && r.contains(.cycle))
        // Entry cannot be terminal; non-terminal steps need actions.
        var t = FX.pickup
        t.steps.insert(LoopStep(id: "start", type: .result), at: 0)
        #expect(LoopPolicyValidator.validate(t, context: FX.context()).rules.contains(.entryIsTerminal))
        var e = FX.pickup
        e.steps[1].actions = []
        #expect(LoopPolicyValidator.validate(e, context: FX.context()).rules.contains(.deadEnd))
    }

    // MARK: Action registry

    @Test func onlyRegisteredActionsWithAllowedLabels() {
        #expect(hard(FX.modify(FX.pickupValue, ["steps", 1, "actions", 0, "action"], .string("delete_account"))).contains(.unregisteredAction))
        #expect(hard(FX.modify(FX.pickupValue, ["steps", 1, "actions", 0, "label"], .string("approve_estimate"))).contains(.labelNotAllowed))
        #expect(hard(FX.modify(FX.pickupValue, ["steps", 1, "actions", 0, "label"], .string("Pay now"))).contains(.labelNotAllowed))
        // Custom labels only for low risk; select_option is medium.
        #expect(hard(FX.modify(FX.pickupValue, ["steps", 0, "actions", 0, "custom_label"], .string("Go"))).contains(.customLabelNotAllowed))
        #expect(hard(FX.modify(FX.pickupValue, ["steps", 1, "actions", 0, "custom_label"], .string("Send it"))).isEmpty)
        #expect(hard(FX.modify(FX.pickupValue, ["steps", 1, "actions", 0, "custom_label"], .string("Viadere approved"))).contains(.impersonation))
    }

    @Test func paymentsVerificationAndHealthActionsAreReserved() {
        for action in ["payment.capture", "payment_intent", "order.create", "checkout", "pay", "refund", "verify_age", "verify_identity",
                       "identity.name", "age.minimum", "shop.checkout", "health_record", "medical_intake"] {
            let value = FX.modify(FX.pickupValue, ["steps", 1, "actions", 0, "action"], .string(action))
            let r = report(value)
            #expect(r.rules.contains(.reservedAction), "\(action)")
            #expect(!r.gate.passed)
        }
        #expect(LoopActionRegistry.reservedReason("verify_age") == .firstPartyVerificationOnly)
        #expect(LoopActionRegistry.reservedReason("payment.refund") == .noPayments)
        #expect(LoopActionRegistry.reservedReason("acknowledge") == nil)
    }

    @Test func registryInvariantsHold() {
        #expect(LoopActionRegistry.v1.selfCheck().isEmpty, "\(LoopActionRegistry.v1.selfCheck())")
        for d in LoopActionRegistry.v1.definitions where d.riskClass == .high { #expect(d.confirmation != nil) }
        let approve = LoopActionRegistry.v1.definitions.first { $0.actionType == "approve_estimate" }!
        #expect(approve.confirmation!.effect.contains("does not charge you"))
        #expect(approve.capabilityId == "transaction.approve")
        #expect(!approve.isAvailable(in: .hosted) && approve.isAvailable(in: .connected))
        // A registry entry that breaks the rules is caught by the self-check.
        var broken = approve
        broken.actionType = "approve_quote"
        broken.confirmation = nil
        broken.customLabelAllowed = true
        #expect(LoopActionRegistry(version: 99, definitions: [broken]).selfCheck().count >= 2)
    }

    @Test func highRiskDefinitionCannotOmitTheConfirmationPanel() {
        // Even a (mis)configured registry without a confirmation for a high-risk action fails the gate.
        var entry = LoopActionRegistry.v1.definitions.first { $0.actionType == "review_estimate" }!
        entry.confirmation = nil
        var context = FX.context()
        context.registry = LoopActionRegistry(version: 1, definitions: LoopActionRegistry.v1.definitions.filter { $0.actionType != "review_estimate" } + [entry])
        #expect(LoopPolicyValidator.validate(FX.estimate, context: context).rules.contains(.missingConfirmation))
        // With the real registry the estimate passes, is high risk and needs two reviewers.
        let r = LoopPolicyValidator.validate(FX.estimate, context: FX.context(kits: ["spring"]))
        #expect(r.gate.passed, "\(r.hits)")
        #expect(r.derivedRiskClass == .high)
        #expect(r.requiredReview == .twoPerson)
        #expect(r.rules.contains(.highRiskAction))
    }

    @Test func parametersAreTypedAndClosed() {
        var d = FX.estimate
        d.steps[0].actions[0].params?["callback_url"] = .string("x")
        #expect(LoopPolicyValidator.validate(d, context: FX.context()).rules.contains(.unknownParameter))
        d = FX.estimate
        d.steps[0].actions[0].params?.removeValue(forKey: "amount")
        #expect(LoopPolicyValidator.validate(d, context: FX.context()).rules.contains(.missingParameter))
        for bad: JSONValue in [.string("285.28"), .object(["value": .string("-1"), "currency": .string("USD")]),
                               .object(["value": .string("1.234"), "currency": .string("USD")]),
                               .object(["value": .string("10"), "currency": .string("usd")]),
                               .object(["value": .string("10"), "currency": .string("USD"), "note": .string("x")])] {
            d = FX.estimate
            d.steps[0].actions[0].params?["amount"] = bad
            #expect(LoopPolicyValidator.validate(d, context: FX.context()).rules.contains(.invalidParameter), "\(bad)")
        }
        d = FX.estimate
        d.steps[0].actions[0].params?["reference"] = .string("EST 1042 <b>")
        #expect(LoopPolicyValidator.validate(d, context: FX.context()).rules.contains(.invalidParameter))
        d = FX.estimate
        d.steps[0].actions[0].params?["terms"] = .string("See www.example.com for terms")
        #expect(LoopPolicyValidator.validate(d, context: FX.context()).rules.contains(.linkNotAllowed))
    }

    @Test func routingRules() {
        #expect(hard(FX.modify(FX.pickupValue, ["steps", 1, "actions", 0, "routing"], nil)).contains(.missingRouting))
        // connected exists only from Phase 4.
        let connected = FX.modify(FX.pickupValue, ["steps", 1, "actions", 0, "routing", "mode"], .string("connected"))
        #expect(hard(connected).contains(.routingModeNotAvailable))
        #expect(!hard(connected, FX.context(phase: .connected)).contains(.routingModeNotAvailable))
        #expect(hard(FX.modify(FX.pickupValue, ["steps", 1, "actions", 0, "routing", "mode"], .string("email"))).contains(.invalidValue))
        // Non-delivering actions cannot route.
        #expect(hard(FX.modify(FX.pickupValue, ["steps", 0, "actions", 0, "routing"], .object(["mode": .string("hosted")]))).contains(.routingNotAllowed))
    }

    @Test func phaseGatesBindingApprovals() {
        var d = FX.estimate
        d.steps[0].actions[0].action = "approve_estimate"
        d.steps[0].actions[0].label = "approve_estimate"
        #expect(LoopPolicyValidator.validate(d, context: FX.context()).rules.contains(.actionNotAvailable))
        #expect(!LoopPolicyValidator.validate(d, context: FX.context(phase: .connected)).rules.contains(.actionNotAvailable))
    }

    // MARK: FX-5: approvals never pair with checkout

    @Test func amountBearingApprovalCanNeverBePairedWithCheckout() {
        var d = FX.estimate
        d.steps[0].actions[0].action = "approve_estimate"
        d.steps[0].actions[0].label = "approve_estimate"
        d.steps[0].actions[0].next = "pay"
        d.steps.append(LoopStep(id: "pay", type: .handoff, handoff: .shop))
        d.steps.removeAll { $0.id == "done" }
        var context = FX.context(phase: .connected)
        context.enabledHandoffs = [.shop]
        let r = LoopPolicyValidator.validate(d, context: context)
        #expect(r.rules.contains(.approvalWithCheckout))
        #expect(!r.gate.passed)
        // The read-only review is amount-bearing too.
        var review = FX.estimate
        review.steps[0].actions[0].next = "pay"
        review.steps.append(LoopStep(id: "pay", type: .handoff, handoff: .shop))
        #expect(LoopPolicyValidator.validate(review, context: context).rules.contains(.approvalWithCheckout))
        // Handoffs are refused until the shop module ships.
        #expect(LoopPolicyValidator.validate(review, context: FX.context()).rules.contains(.handoffNotAvailable))
    }

    // MARK: FX-4 healthcare ban and other prohibited content

    @Test func healthFieldTypesCannotBeExpressed() {
        for type in ["health", "medical", "diagnosis", "symptoms", "medication", "allergies", "health_condition"] {
            #expect(hard(FX.modify(FX.pickupValue, ["steps", 0, "fields", 0, "type"], .string(type))).contains(.prohibitedFieldType), "\(type)")
        }
        for type in ["password", "pin", "otp", "card_number", "cvv", "iban", "ssn", "passport", "date_of_birth", "long_text", "file", "url"] {
            #expect(hard(FX.modify(FX.pickupValue, ["steps", 0, "fields", 0, "type"], .string(type))).contains(.prohibitedFieldType), "\(type)")
        }
        #expect(hard(FX.modify(FX.pickupValue, ["steps", 0, "fields", 0, "type"], .string("color_picker"))).contains(.unknownFieldType))
        // The allowlist has no field that could hold such data.
        #expect(LoopFieldType.allCases.allSatisfy { LoopFieldType.prohibited[$0.rawValue] == nil })
    }

    @Test func healthContentInTextFailsTheHardGate() {
        let texts = ["Describe your symptoms", "Upload your prescription", "Your diagnosis", "Dental check-up", "Doctor's appointment",
                     "Patient intake: allergies", "Medication list", "Pregnancy status", "Telehealth visit", "HIPAA notice", "Mental health check-in",
                     "Clinic arrival", "MEDICAL history", "Ｍｅｄｉｃａｌ form", "médical", "X-ray results", "Nurse visit"]
        for text in texts {
            let r = report(FX.modify(FX.pickupValue, ["title"], .string(text)))
            #expect(r.rules.contains(.healthContent), "\(text)")
            #expect(!r.gate.passed)
        }
        // Same rule in every text slot.
        #expect(hard(FX.modify(FX.pickupValue, ["steps", 0, "fields", 0, "label"], .string("Any symptoms?"))).contains(.healthContent))
        #expect(hard(FX.modify(FX.pickupValue, ["steps", 0, "fields", 0, "options", 1, "label"], .string("Prescription pickup"))).contains(.healthContent))
        #expect(hard(FX.modify(FX.pickupValue, ["steps", 1, "body"], .string("Bring your insurance card and medical records"))).contains(.healthContent))
    }

    @Test func ordinaryWordsDoNotTripTheHealthRules() {
        for text in ["Healthy snacks pickup", "Garden nursery order", "Oak Dr pickup", "Be ready at 5", "Haircut appointment", "Food court pickup"] {
            let r = report(FX.modify(FX.pickupValue, ["title"], .string(text)))
            #expect(r.gate.passed, "\(text): \(r.hits)")
        }
    }

    @Test func healthAdjacentWordsForceTwoReviewers() {
        let r = report(FX.modify(FX.pickupValue, ["title"], .string("Massage therapy booking")))
        #expect(r.gate.passed)
        #expect(r.rules.contains(.healthAdjacentContent))
        #expect(r.requiredReview == .twoPerson)
        let gov = report(FX.modify(FX.pickupValue, ["title"], .string("Official notice from the government")))
        #expect(gov.rules.contains(.authorityClaim) && gov.requiredReview == .twoPerson)
    }

    @Test func sensitiveDataRequestsLinksAndSpoofingAreRefused() {
        for text in ["Enter your card number", "Your PIN code", "Social Security number", "Driver's license number", "Your password", "CVV"] {
            #expect(hard(FX.modify(FX.pickupValue, ["steps", 0, "fields", 0, "label"], .string(text))).contains(.sensitiveDataRequest), "\(text)")
        }
        for text in ["Visit https://pay.example", "See www.example.com", "bit.ly/abc", "mail me@shop.example", "example.com"] {
            #expect(hard(FX.modify(FX.pickupValue, ["title"], .string(text))).contains(.linkNotAllowed), "\(text)")
        }
        for text in ["Built by Viadere", "Secured by our team", "Verified business", "Created by Juniper Salon", "Powered by Acme"] {
            #expect(hard(FX.modify(FX.pickupValue, ["title"], .string(text))).contains(.attributionSpoofing), "\(text)")
        }
        // Viadere may not appear in any Loop text at all, including homoglyphs and spacing tricks.
        for text in ["Viadere pickup", "Pickup via VIADERE", "V.i.a.d.e.r.e", "Viаdere"] {
            #expect(hard(FX.modify(FX.pickupValue, ["title"], .string(text))).contains(.impersonation), "\(text)")
        }
        #expect(hard(FX.modify(FX.pickupValue, ["title"], .string("Pick\u{202E}up"))).contains(.disallowedCharacters))
        #expect(hard(FX.modify(FX.pickupValue, ["title"], .string(String(repeating: "a", count: 61)))).contains(.textTooLong))
        #expect(hard(FX.modify(FX.pickupValue, ["title"], .string("   "))).contains(.emptyText))
    }

    @Test func freeTextIsRefusedInHighRiskFlows() {
        var d = FX.estimate
        d.steps.insert(LoopStep(id: "note", type: .form, fields: [LoopField(id: "n", type: .shortText, label: "Anything else?")],
                                actions: [LoopActionBinding(id: "go", action: "select_option", label: "next", next: "review")]), at: 0)
        #expect(LoopPolicyValidator.validate(d, context: FX.context(kits: ["spring"])).rules.contains(.freeTextInHighRisk))
        // Fine in a medium-risk flow.
        var p = FX.pickup
        p.steps[0].fields.append(LoopField(id: "note", type: .shortText, label: "Note for the florist", maxLength: 80))
        #expect(LoopPolicyValidator.validate(p, context: FX.context()).gate.passed)
        p.steps[0].fields[1].maxLength = 500
        #expect(LoopPolicyValidator.validate(p, context: FX.context()).rules.contains(.invalidValue))
    }

    // MARK: Publisher, attribution metadata, category

    @Test func attributionMetadataIsRequiredAndConsistent() {
        #expect(hard(FX.pickupValue, FX.context(publisher: nil)).contains(.attributionMissing))
        #expect(hard(FX.pickupValue, FX.context(publisher: .business(FX.otherBusiness))).contains(.attributionMismatch))
        #expect(hard(FX.pickupValue, FX.context(publisher: .business(FX.business, status: .suspended))).contains(.publisherNotVerified))
        let viadere = LoopPublisherIdentity(publisherType: .viadere, businessId: FX.business, verificationStatus: .verified, category: .retail)
        #expect(hard(FX.pickupValue, FX.context(publisher: viadere)).contains(.publisherNotBusiness))
    }

    @Test func healthcareAndProhibitedCategoriesCannotSubmit() {
        #expect(hard(FX.pickupValue, FX.context(publisher: .business(FX.business, category: .healthcare))).contains(.categoryBanned))
        #expect(hard(FX.pickupValue, FX.context(publisher: .business(FX.business, category: BusinessCategory(rawValue: "gambling")))).contains(.categoryProhibited))
        #expect(LoopCategoryPolicy.onboarding(.healthcare) == .refused(reason: "healthcare_banned"))
        #expect(LoopCategoryPolicy.onboarding(BusinessCategory(rawValue: "Pharmacy")) == .refused(reason: "healthcare_banned"))
        #expect(LoopCategoryPolicy.onboarding(.retail) == .eligible)
        #expect(LoopCategoryPolicy.loops(.retail) == .eligible)
    }

    @Test func brandKitAppearanceMustNameAnOwnedKit() {
        let value = FX.modify(FX.pickupValue, ["appearance"], .object(["mode": .string("brand_kit"), "kit": .string("spring")]))
        #expect(hard(value, FX.context(kits: ["spring"])).isEmpty)
        #expect(hard(value, FX.context(kits: ["winter"])).contains(.unknownBrandKit))
        #expect(hard(FX.modify(FX.pickupValue, ["appearance"], .object(["mode": .string("brand_kit")]))).contains(.missingMember))
        #expect(hard(FX.modify(FX.pickupValue, ["appearance"], .object(["mode": .string("custom_css")]))).contains(.invalidValue))
    }

    @Test func contentRuleTokenizer() {
        #expect(LoopContentRules.tokens("Driver's license — X-ray!") == ["drivers", "license", "x-ray"])
        #expect(LoopContentRules.containsLink("juniper-salon.shop"))
        #expect(LoopContentRules.containsLink("bit.ly/abc"))
        #expect(!LoopContentRules.containsLink("Pickup at 5.30 pm"))
        #expect(!LoopContentRules.containsLink("Thanks. See you soon"))
        #expect(LoopContentRules.isHardGate(.health) && !LoopContentRules.isHardGate(.healthAdjacent))
    }
}
