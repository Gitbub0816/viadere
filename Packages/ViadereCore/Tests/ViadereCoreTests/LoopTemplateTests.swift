import Foundation
import Testing
@testable import ViadereCore

/// WP-3.7: the Loop Studio template gallery. Templates are locked starting points that pass the hard gate; the fast-path flag follows the
/// document's structure, never a claim.
@Suite("Loop Studio templates")
struct LoopTemplateTests {
    @Test func galleryHasTheFiveTemplatesWithValidKeys() {
        #expect(LoopTemplateCatalog.v1.map(\.key) == ["acknowledge", "callback_request", "salon_check_in", "repair_check_in", "pickup_time"])
        #expect(Set(LoopTemplateCatalog.v1.map(\.definition.key)).count == LoopTemplateCatalog.v1.count, "distinct Loop keys")
        for template in LoopTemplateCatalog.v1 {
            #expect(ContractIdentifier.isValid(template.key, maxLength: 40), "\(template.key)")
            #expect(LoopTemplateCatalog.template(template.key) == template)
        }
        #expect(LoopTemplateCatalog.template("medical_intake") == nil)
    }

    @Test func everyTemplatePassesTheHardGateWithNoFlags() {
        for template in LoopTemplateCatalog.v1 {
            let report = LoopPolicyValidator.validate(template.definition, context: FX.context())
            #expect(report.gate.passed, "\(template.key): \(report.hits)")
            #expect(report.hits.isEmpty, "\(template.key): \(report.hits)")
            #expect(report.derivedRiskClass != .high, "templates stay off the two-person path")
            // Canonical round trip: what Studio stores is exactly what the template says.
            #expect(LoopDefinition.parse(template.definition.jsonValue).definition == template.definition)
        }
    }

    @Test func templatesUseNoHealthcareWording() {
        for template in LoopTemplateCatalog.v1 {
            for text in [template.name, template.summary] {
                let topics = LoopContentRules.topics(in: text)
                #expect(!topics.contains(.health) && !topics.contains(.healthAdjacent), "\(template.key): \(text)")
            }
        }
    }

    @Test func textAndLabelChangesKeepTheFastPathButStructureChangesLeaveIt() throws {
        let template = try #require(LoopTemplateCatalog.template("callback_request"))
        var edited = template.definition
        edited.title = "Ask us to call you"
        edited.steps[0].fields[0].label = "Topic"
        edited.steps[0].fields[0].options?.append(LoopOption(id: "repair", label: "A repair"))
        edited.steps[1].actions[0].label = "request_callback"
        edited.steps[1].actions[0].routing?.queue = "phones"
        edited.entryPoints = [.message]
        edited.appearance = .brandKit("spring")
        #expect(template.matches(edited))
        #expect(LoopTemplateCatalog.matching(edited, startedFrom: "callback_request") == template)

        var added = edited
        added.steps[0].fields.append(LoopField(id: "note", type: .shortText, label: "Anything else?"))
        #expect(!template.matches(added))
        var rerouted = edited
        rerouted.steps[1].actions[0].action = "submit_inquiry"
        #expect(!template.matches(rerouted))
        var retargeted = edited
        retargeted.steps[0].actions[0].next = "done"
        #expect(!template.matches(retargeted))
        // A claim of another template, or of no template, never matches.
        #expect(LoopTemplateCatalog.matching(edited, startedFrom: "pickup_time") == nil)
        #expect(LoopTemplateCatalog.matching(edited, startedFrom: nil) == nil)
        #expect(LoopTemplateCatalog.matching(edited, startedFrom: "unknown") == nil)
    }

    @Test func prohibitedFieldTypesHaveAReasonForTheEditor() {
        #expect(LoopFieldType.prohibitionReason("medical") == "health")
        #expect(LoopFieldType.prohibitionReason("Card_Number") == "payment")
        #expect(LoopFieldType.prohibitionReason("password") == "secret")
        #expect(LoopFieldType.prohibitionReason("ssn") == "government_id")
        #expect(LoopFieldType.prohibitionReason("single_choice") == nil)
        for type in LoopFieldType.allCases { #expect(LoopFieldType.prohibitionReason(type.rawValue) == nil) }
    }
}
