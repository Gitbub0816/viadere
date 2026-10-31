import Foundation
import Testing
@testable import ViadereCore

/// WP-3.2 / WP-3.5 Core rules: the revision state machine (no path skips review, nothing past draft changes), rollout buckets, the
/// report threshold, the consent catalog and the consumer route contract.
@Suite("Loop lifecycle")
struct LoopLifecycleTests {
    @Test func noRevisionStateReachesPublishedWithoutApproval() {
        // Breadth-first search over the legal moves from `draft`: every path to `published` passes through `in_review` and `approved`.
        var paths: [[LoopRevisionState]] = [[.draft]]
        var published: [[LoopRevisionState]] = []
        while let path = paths.first {
            paths.removeFirst()
            for next in LoopRevisionState.allCases where LoopRevisionState.canMove(from: path.last!, to: next) && !path.contains(next) {
                let extended = path + [next]
                if next == .published { published.append(extended) } else { paths.append(extended) }
            }
        }
        #expect(!published.isEmpty)
        for path in published {
            #expect(path.contains(.inReview) && path.contains(.approved), "\(path)")
            #expect(path.firstIndex(of: .approved)! == path.firstIndex(of: .published)! - 1)
        }
        // A failed hard gate is a dead end: no move leaves it (a human cannot override it).
        for next in LoopRevisionState.allCases { #expect(!LoopRevisionState.canMove(from: .validationFailed, to: next)) }
        for next in LoopRevisionState.allCases { #expect(!LoopRevisionState.canMove(from: .rejected, to: next)) }
        #expect(!LoopRevisionState.canMove(from: .changesRequested, to: .inReview), "changes need a new revision")
        #expect(LoopRevisionState.allCases.filter(\.isImmutable) == LoopRevisionState.allCases.filter { $0 != .draft })
    }

    @Test func rolloutIsDeterministicAndBounded() {
        let publication = UUID()
        var inside = 0
        for _ in 0..<2000 {
            let consumer = UUID()
            let bucket = LoopRollout.bucket(consumerId: consumer, publicationId: publication)
            #expect((0..<100).contains(bucket))
            #expect(bucket == LoopRollout.bucket(consumerId: consumer, publicationId: publication))
            if LoopRollout.isEligible(consumerId: consumer, publicationId: publication, percent: 20, allowListed: false) { inside += 1 }
            #expect(!LoopRollout.isEligible(consumerId: consumer, publicationId: publication, percent: 0, allowListed: false))
            #expect(LoopRollout.isEligible(consumerId: consumer, publicationId: publication, percent: 0, allowListed: true))
            #expect(LoopRollout.isEligible(consumerId: consumer, publicationId: publication, percent: 100, allowListed: false))
        }
        #expect((250...550).contains(inside), "about 20% of 2000: \(inside)")
    }

    @Test func reportThreshold() {
        #expect(!LoopReportPolicy.shouldAutoSuspend(distinctReporters: 2, distinctCustomers: 2))
        #expect(LoopReportPolicy.shouldAutoSuspend(distinctReporters: 3, distinctCustomers: 10))
        #expect(!LoopReportPolicy.shouldAutoSuspend(distinctReporters: 3, distinctCustomers: 1000))
        #expect(LoopReportPolicy.shouldAutoSuspend(distinctReporters: 5, distinctCustomers: 100_000))
        #expect(!LoopReportPolicy.shouldAutoSuspend(distinctReporters: 0, distinctCustomers: 0))
    }

    @Test func consentCatalogDigestCoversEveryWordAndAnswersAreChecked() throws {
        let current = LoopConsentCatalog.current
        #expect(ContractHash.isValid(current.digest))
        var changed = current
        changed.businessAuthorization += " "
        #expect(changed.digest != current.digest)
        var answers: [String: String] = [:]
        for check in current.checks { answers[check.id] = check.correctOptionId }
        #expect(current.passes(answers))
        var wrong = answers
        wrong[current.checks[0].id] = "viadere"
        #expect(!current.passes(wrong))
        #expect(!current.passes([:]))
        #expect(!current.passes(answers.merging(["extra": "x"]) { a, _ in a }))
        // The text sent to devices never carries the answers.
        let wire = String(decoding: try ViadereJSON.encode(LoopConsentText(current)), as: UTF8.self)
        #expect(!wire.contains("correct"))
        #expect(LoopConsentText(current).digest == current.digest)
        // The wording is non-health, never mentions HIPAA and states that review is not an outcome guarantee (A7.7).
        let all = (current.paragraphs + [current.title, current.businessAuthorization]).joined(separator: " ").lowercased()
        #expect(!all.contains("hipaa") && !all.contains("patient"))
        #expect(all.contains("does not mean the business will do what you ask"))
    }

    @Test func consumerLoopRoutesAreDeviceSignedAndInTheCatalog() {
        let catalog = Set(APIRoutes.all.map { "\($0.method.rawValue) \($0.template)" })
        for route in ["POST /v1/loops/instances", "POST /v1/loops/instances/{instanceId}/actions", "GET /v1/loops/instances/{instanceId}",
                      "GET /v1/loops/consent", "PUT /v1/loops/consent", "DELETE /v1/loops/consent",
                      "PUT /v1/loops/consent/businesses/{businessId}", "DELETE /v1/loops/consent/businesses/{businessId}"] {
            #expect(catalog.contains(route), "\(route)")
        }
        #expect(APIRoutes.loopEndpoints.allSatisfy { $0.auth == .deviceSignedBearer })
        #expect(Set(APIRoutes.all.map(\.name)).count == APIRoutes.all.count)
    }

    @Test func actionRequestRoundTripsAndAlertTargetKindIsAdditive() throws {
        let request = LoopActionRequest(stepId: "s1", actionId: "confirm", inputs: ["slot": .string("am")], idempotencyKey: "k-1")
        let decoded = try ViadereJSON.decode(LoopActionRequest.self, from: try ViadereJSON.encode(request))
        #expect(decoded == request)
        let target = try ViadereJSON.decode(AlertTarget.self, from: Data(#"{"kind":"loop_instance","id":"x"}"#.utf8))
        #expect(target.kind == .loopInstance)
        let future = try ViadereJSON.decode(AlertTarget.self, from: Data(#"{"kind":"something_new","id":"x"}"#.utf8))
        #expect(future.kind == .unknown)
    }
}
