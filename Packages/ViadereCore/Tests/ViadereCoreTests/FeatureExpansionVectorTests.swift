import Crypto
import Foundation
import Testing
@testable import ViadereCore

/// Conformance vectors for the feature expansion v4 contracts (`docs/protocol/vectors/*-v1.json`): Loop definitions and validator
/// rule codes, publication manifests, presentation trees, brand manifests (tokens, contrast, selection, DST) and module layouts.
/// They double as the Android conformance spec (FX-2): a client that reproduces every expectation conforms.
///
/// `VIADERE_WRITE_VECTORS=1 swift test --filter FeatureExpansionVectorTests` regenerates them (signatures change: ECDSA is randomized,
/// so verifiers must verify, not compare). Without the variable the files are only read and every expectation is recomputed.
@Suite("Feature expansion v4 vectors")
struct FeatureExpansionVectorTests {
    static var writing: Bool { ProcessInfo.processInfo.environment["VIADERE_WRITE_VECTORS"] == "1" }

    static func url(_ name: String) -> URL { ProtocolVectorTests.vectorsDirectory.appendingPathComponent(name) }

    static func write(_ value: JSONValue, _ name: String) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        try FileManager.default.createDirectory(at: ProtocolVectorTests.vectorsDirectory, withIntermediateDirectories: true)
        try (try encoder.encode(value) + Data("\n".utf8)).write(to: url(name))
    }

    static func read(_ name: String) throws -> [String: JSONValue] {
        guard case .object(let o) = try JSONDecoder().decode(JSONValue.self, from: Data(contentsOf: url(name))) else { throw VectorError.shape(name) }
        return o
    }

    enum VectorError: Error { case shape(String) }

    // MARK: Loop definitions and validator rule codes

    static func definitionCases() -> [(String, JSONValue, [String: JSONValue])] {
        let base = FX.pickupValue
        let estimate = FX.estimate.jsonValue
        return [
            ("unknown_member", FX.modify(base, ["steps", 0, "fields", 0, "html"], .string("<b>x</b>")), [:]),
            ("cycle", FX.modify(base, ["steps", 1, "actions", 0, "next"], .string("s1")), [:]),
            ("unreachable_step", FX.modify(base, ["steps", 0, "actions", 0, "next"], .string("done")), [:]),
            ("unregistered_action", FX.modify(base, ["steps", 1, "actions", 0, "action"], .string("transfer_funds")), [:]),
            ("reserved_payment_action", FX.modify(base, ["steps", 1, "actions", 0, "action"], .string("payment.capture")), [:]),
            ("reserved_verify_age", FX.modify(base, ["steps", 1, "actions", 0, "action"], .string("verify_age")), [:]),
            ("label_not_allowed", FX.modify(base, ["steps", 1, "actions", 0, "label"], .string("Approve and pay")), [:]),
            ("prohibited_field_health", FX.modify(base, ["steps", 0, "fields", 0, "type"], .string("medical")), [:]),
            ("prohibited_field_card", FX.modify(base, ["steps", 0, "fields", 0, "type"], .string("card_number")), [:]),
            ("health_text", FX.modify(base, ["title"], .string("Describe your symptoms")), [:]),
            ("attribution_spoofing", FX.modify(base, ["title"], .string("Built by Viadere")), [:]),
            ("link", FX.modify(base, ["steps", 1, "body"], .string("Details at www.example.com")), [:]),
            ("connected_in_phase_3", FX.modify(base, ["steps", 1, "actions", 0, "routing", "mode"], .string("connected")), [:]),
            ("healthcare_category", base, ["category": .string("healthcare")]),
            ("attribution_missing", base, ["publisher": .null]),
            ("attribution_mismatch", base, ["publisher_business_id": .string(FX.otherBusiness.description)]),
            ("review_flag_two_person", FX.modify(base, ["title"], .string("Massage therapy booking")), [:]),
            ("high_risk_estimate", estimate, [:]),
        ]
    }

    static func context(_ overrides: [String: JSONValue]) -> LoopValidationContext {
        var publisher: LoopPublisherIdentity? = .business(FX.business)
        if overrides["publisher"] == JSONValue.null { publisher = nil }
        if let category = overrides["category"]?.stringValue { publisher?.category = BusinessCategory(rawValue: category) }
        if let id = overrides["publisher_business_id"]?.stringValue.flatMap(BusinessID.init) { publisher?.businessId = id }
        return LoopValidationContext(submittingBusinessId: FX.business, publisher: publisher, phase: .hosted)
    }

    static func reportValue(_ r: LoopValidationReport) -> JSONValue {
        .object(["gate": .string(r.gate.passed ? "passed" : "failed"), "derived_risk_class": .string(r.derivedRiskClass.rawValue),
                 "required_review": .string(r.requiredReview.rawValue), "rules": .array(r.rules.map(\.rawValue).sorted().map(JSONValue.string))])
    }

    @Test func loopDefinitionVectors() throws {
        let name = "loop-definition-v1.json"
        if Self.writing {
            let valid = FX.pickupValue
            let cases: [JSONValue] = Self.definitionCases().map { caseName, definition, overrides in
                .object(["name": .string(caseName), "definition": definition, "context": .object(overrides),
                         "expected": Self.reportValue(LoopPolicyValidator.validate(definition, context: Self.context(overrides)))])
            }
            try Self.write(.object([
                "name": .string("loop-definition-v1"), "version": .integer(1),
                "description": .string("Loop definition schema v1 and LoopPolicyValidator rule codes (SECURITY.md 2.92, plan 4.3). `valid.canonical` is the canonical JSON (SECURITY.md 2.2) and `valid.definition_hash` = \"sha256:\" + hex(SHA-256(canonical)). Each case is validated with context: submitting business = publisher business \(FX.business), publisher verified, category retail, phase hosted (3), registry v1, unless `context` overrides it. `expected.rules` is the sorted set of rule codes (hard-gate failures and review flags); `gate` is failed when any hard-gate rule is present."),
                "rule_set_version": .integer(Int64(LoopPolicyValidator.ruleSetVersion)), "registry_version": .integer(Int64(LoopActionRegistry.v1.version)),
                "submitting_business_id": .string(FX.business.description),
                "valid": .object(["definition": valid, "canonical": .string(String(decoding: try CanonicalJSON.serialize(valid), as: UTF8.self)),
                                  "definition_hash": .string(try ContractHash.sha256(valid)),
                                  "expected": Self.reportValue(LoopPolicyValidator.validate(valid, context: FX.context()))]),
                "cases": .array(cases),
            ]), name)
        }
        let v = try Self.read(name)
        guard case .object(let valid)? = v["valid"], let definition = valid["definition"], case .array(let cases)? = v["cases"] else { throw VectorError.shape(name) }
        #expect(String(decoding: try CanonicalJSON.serialize(definition), as: UTF8.self) == valid["canonical"]?.stringValue)
        #expect(try ContractHash.sha256(definition) == valid["definition_hash"]?.stringValue)
        #expect(try LoopDefinition.parse(definition).definition?.definitionHash() == valid["definition_hash"]?.stringValue)
        #expect(Self.reportValue(LoopPolicyValidator.validate(definition, context: FX.context())) == valid["expected"])
        #expect(cases.count == Self.definitionCases().count)
        for item in cases {
            guard case .object(let c) = item, let d = c["definition"], case .object(let overrides)? = c["context"] else { throw VectorError.shape(name) }
            #expect(Self.reportValue(LoopPolicyValidator.validate(d, context: Self.context(overrides))) == c["expected"], "\(c["name"]?.stringValue ?? "")")
        }
        // Every hard-gate case really fails; the flag cases pass with two reviewers.
        let failing = cases.filter { if case .object(let c) = $0, case .object(let e)? = c["expected"] { e["gate"] == .string("failed") } else { false } }
        #expect(failing.count == cases.count - 2)
    }

    // MARK: Publication manifest

    @Test func publicationManifestVectors() async throws {
        let name = "loop-publication-manifest-v1.json"
        let definition = FX.pickup
        if Self.writing {
            let manifest = LoopPublicationManifest(publisherType: .business, publisherBusinessId: FX.business, publishedDefinitionId: FX.publication,
                                                   revision: 3, definitionHash: try definition.definitionHash(),
                                                   validFrom: Int64(FX.now.timeIntervalSince1970) - 3600, notAfter: Int64(FX.now.timeIntervalSince1970) + 29 * 86400,
                                                   kid: FX.kid)
            let jws = try await manifest.sign(with: FX.publicationKey)
            let parts = jws.split(separator: ".").map(String.init)
            let forged = try await manifest.sign(with: FX.key("attacker"))
            let other = LoopPublicationManifest(publisherType: .business, publisherBusinessId: FX.otherBusiness, publishedDefinitionId: FX.publication,
                                                revision: 3, definitionHash: try definition.definitionHash(), validFrom: manifest.validFrom,
                                                notAfter: manifest.notAfter, kid: FX.kid)
            let otherJWS = try await other.sign(with: FX.publicationKey)
            let none = Base64URL.encode(Data(#"{"alg":"none","kid":"loop-publication-v1","typ":"viadere-loop-publication+jws"}"#.utf8)) + "." + parts[1] + "." + parts[2]
            let brandTyped = try await ManifestJWS.sign(payload: { if case .object(let o) = manifest.jsonValue { o } else { [:] } }(), type: BrandManifest.jwsType,
                                                        kid: FX.kid, with: FX.publicationKey)
            try Self.write(.object([
                "name": .string("loop-publication-manifest-v1"), "version": .integer(1),
                "description": .string("Signed Loop publication manifest (SECURITY.md 2.92): compact JWS, header exactly {alg: ES256, kid, typ: viadere-loop-publication+jws} as canonical JSON, payload canonical JSON repeating kid, ECDSA P-256 raw r||s over header64.payload64. Verify with the pinned key; do not compare signatures. `now` is the verification time (unix seconds). Negative cases must all be refused; the builder then renders the safe fallback."),
                "kid": .string(FX.kid), "public_key": .string(FX.publicationKey.publicKey.base64URL), "now": .integer(Int64(FX.now.timeIntervalSince1970)),
                "definition": definition.jsonValue, "payload": manifest.jsonValue,
                "payload_canonical": .string(String(decoding: try CanonicalJSON.serialize(manifest.jsonValue), as: UTF8.self)),
                "header_canonical": .string(#"{"alg":"ES256","kid":"loop-publication-v1","typ":"viadere-loop-publication+jws"}"#),
                "jws": .string(jws),
                "refused": .array([
                    .object(["name": .string("wrong_key"), "jws": .string(forged), "error": .string("bad_signature")]),
                    .object(["name": .string("alg_none"), "jws": .string(none), "error": .string("unsupported_algorithm")]),
                    .object(["name": .string("brand_manifest_typ"), "jws": .string(brandTyped), "error": .string("wrong_type")]),
                    .object(["name": .string("payload_swapped"), "jws": .string(parts[0] + "." + otherJWS.split(separator: ".")[1] + "." + parts[2]), "error": .string("bad_signature")]),
                ]),
                "binding_refused": .array([
                    .object(["name": .string("other_business"), "jws": .string(otherJWS), "fallback_reason": .string("publisher_mismatch")]),
                ]),
            ]), name)
        }
        let v = try Self.read(name)
        let key = try DevicePublicKey(base64URL: try #require(v["public_key"]?.stringValue))
        let keys = [PinnedManifestKey(kid: try #require(v["kid"]?.stringValue), publicKey: key)]
        let now = Date(timeIntervalSince1970: TimeInterval(try #require(v["now"].flatMap { if case .integer(let n) = $0 { n } else { nil } })))
        let jws = try #require(v["jws"]?.stringValue)
        let manifest = try LoopPublicationManifest.verify(jws, keys: keys, now: now)
        #expect(manifest.jsonValue == v["payload"])
        #expect(String(decoding: try CanonicalJSON.serialize(manifest.jsonValue), as: UTF8.self) == v["payload_canonical"]?.stringValue)
        #expect(String(decoding: Base64URL.decode(String(jws.split(separator: ".")[0]))!, as: UTF8.self) == v["header_canonical"]?.stringValue)
        let definitionValue = try #require(v["definition"])
        let vectorDefinition = try #require(LoopDefinition.parse(definitionValue).definition)
        #expect(try vectorDefinition.definitionHash() == manifest.definitionHash)
        let errorCodes: [ManifestVerificationError: String] = [.badSignature: "bad_signature", .unsupportedAlgorithm: "unsupported_algorithm", .wrongType: "wrong_type"]
        guard case .array(let refused)? = v["refused"], case .array(let binding)? = v["binding_refused"] else { throw VectorError.shape(name) }
        for item in refused {
            guard case .object(let c) = item else { continue }
            do {
                _ = try LoopPublicationManifest.verify(c["jws"]?.stringValue, keys: keys, now: now)
                Issue.record("\(c["name"]?.stringValue ?? "") verified")
            } catch {
                #expect(errorCodes[error] == c["error"]?.stringValue, "\(c["name"]?.stringValue ?? ""): \(error)")
            }
        }
        for item in binding {
            guard case .object(let c) = item else { continue }
            var context = FX.presentation(vectorDefinition, manifest: c["jws"]?.stringValue)
            context.pinnedKeys = keys
            context.now = now
            #expect(PresentationBuilder.build(context, phase: .step("s1")).fallbackReason == c["fallback_reason"]?.stringValue)
        }
    }

    // MARK: Presentation trees

    static func presentationCases() async throws -> [(String, LoopDefinition, String?, BrandKitPresentation?, PresentationPhase, LoopPublicationStatus)] {
        let spring = BrandKitPresentation(businessId: FX.business, kitId: "spring", tokens: FX.springTokens, frameId: "viadere.frame.hairline.v1")
        return [
            ("t1_default_style", FX.pickup, try await FX.manifest(for: FX.pickup), nil, .step("s1"), .active),
            ("summary_step", FX.pickup, try await FX.manifest(for: FX.pickup), nil, .step("s2"), .active),
            ("result_pending", FX.pickup, try await FX.manifest(for: FX.pickup), nil, .step("done", outcome: .pending), .active),
            ("t2_brand_kit", FX.estimate, try await FX.manifest(for: FX.estimate), spring, .step("review"), .active),
            ("confirmation_panel", FX.estimate, try await FX.manifest(for: FX.estimate), spring, .confirm(stepId: "review", actionId: "ack"), .active),
            ("t3_first_party_loop", FX.pickup, try await FX.manifest(for: FX.pickup, publisher: .viadere, business: nil), nil, .step("s1"), .active),
            ("fallback_missing_manifest", FX.pickup, nil, nil, .step("s1"), .active),
            ("paused", FX.pickup, try await FX.manifest(for: FX.pickup), nil, .step("s1"), .suspended),
        ]
    }

    static func phaseValue(_ p: PresentationPhase) -> JSONValue {
        switch p {
        case .step(let id, let outcome):
            var o: [String: JSONValue] = ["step": .string(id)]
            if let outcome { o["outcome"] = .string(outcome.rawValue) }
            return .object(o)
        case .confirm(let step, let action): return .object(["confirm": .object(["step": .string(step), "action": .string(action)])])
        }
    }

    static func phase(_ v: JSONValue?) -> PresentationPhase? {
        guard case .object(let o)? = v else { return nil }
        if let step = o["step"]?.stringValue { return .step(step, outcome: o["outcome"]?.stringValue.flatMap(LoopActionOutcome.init(rawValue:))) }
        if case .object(let c)? = o["confirm"], let s = c["step"]?.stringValue, let a = c["action"]?.stringValue { return .confirm(stepId: s, actionId: a) }
        return nil
    }

    @Test func presentationTreeVectors() async throws {
        let name = "presentation-tree-v1.json"
        if Self.writing {
            var cases: [JSONValue] = []
            for (caseName, definition, manifest, brand, phase, status) in try await Self.presentationCases() {
                let tree = PresentationBuilder.build(FX.presentation(definition, manifest: manifest, brand: brand, status: status), phase: phase)
                var o: [String: JSONValue] = ["name": .string(caseName), "definition": definition.jsonValue, "phase": Self.phaseValue(phase),
                                              "publication_status": .string(status.rawValue), "expected_tree": try JSONValue.encoding(tree),
                                              "expected_canonical_sha256": .string(try ContractHash.sha256(try JSONValue.encoding(tree)))]
                if let manifest { o["manifest"] = .string(manifest) }
                if let brand { o["brand"] = .object(["business_id": .string(brand.businessId.description), "kit_id": .string(brand.kitId), "tokens": brand.tokens.jsonValue,
                                                     "frame_id": brand.frameId.map(JSONValue.string) ?? .null]) }
                cases.append(.object(o))
            }
            try Self.write(.object([
                "name": .string("presentation-tree-v1"), "version": .integer(1),
                "description": .string("PresentationBuilder output (SECURITY.md 2.92, plan 4.4). Inputs: definition, publication manifest JWS (pinned key below), the verified directory record of the publisher, phase, publication status, optional Brand Kit, `now`. A conforming builder produces `expected_tree` exactly (compare canonical JSON; `expected_canonical_sha256` is its hash). Node order is reading order; nodes with protected=true use the neutral protected palette."),
                "kid": .string(FX.kid), "public_key": .string(FX.publicationKey.publicKey.base64URL), "now": .integer(Int64(FX.now.timeIntervalSince1970)),
                "instance_business_id": .string(FX.business.description),
                "publisher_record": .object(["id": .string(FX.salon.id.description), "display_name": .string(FX.salon.displayName),
                                             "verification_status": .string(FX.salon.verificationStatus.rawValue), "category": .string(FX.salon.category.rawValue)]),
                "cases": .array(cases),
            ]), name)
        }
        let v = try Self.read(name)
        let keys = [PinnedManifestKey(kid: try #require(v["kid"]?.stringValue), publicKey: try DevicePublicKey(base64URL: try #require(v["public_key"]?.stringValue)))]
        guard case .array(let cases)? = v["cases"] else { throw VectorError.shape(name) }
        #expect(cases.count == 8)
        for item in cases {
            guard case .object(let c) = item, let definition = c["definition"].flatMap({ LoopDefinition.parse($0).definition }),
                  let phase = Self.phase(c["phase"]), let status = c["publication_status"]?.stringValue.flatMap(LoopPublicationStatus.init(rawValue:)) else {
                throw VectorError.shape(name)
            }
            var brand: BrandKitPresentation?
            if case .object(let b)? = c["brand"], let business = b["business_id"]?.stringValue.flatMap(BusinessID.init), let kit = b["kit_id"]?.stringValue,
               let tokens = b["tokens"].flatMap({ BrandTokens.parse($0).tokens }) {
                brand = BrandKitPresentation(businessId: business, kitId: kit, tokens: tokens, frameId: b["frame_id"]?.stringValue)
            }
            var context = FX.presentation(definition, manifest: c["manifest"]?.stringValue, brand: brand, status: status)
            context.pinnedKeys = keys
            let tree = PresentationBuilder.build(context, phase: phase)
            let encoded = try JSONValue.encoding(tree)
            #expect(encoded == c["expected_tree"], "\(c["name"]?.stringValue ?? "")")
            #expect(try ContractHash.sha256(encoded) == c["expected_canonical_sha256"]?.stringValue)
            // The vector decodes back to the same tree (renderers can consume the JSON form).
            #expect(try JSONDecoder().decode(PresentationTree.self, from: JSONEncoder().encode(c["expected_tree"])) == tree)
        }
    }

    // MARK: Brand manifest

    @Test func brandManifestVectors() async throws {
        let name = "brand-manifest-v1.json"
        let seedKey = SymmetricKey(data: Data(SHA256.hash(data: Data("viadere-vector-brand-seed".utf8))))
        let seed = BrandSelectionSeed.derive(key: seedKey, consumer: FX.consumer, business: FX.business)
        func w(_ kit: String, _ s: String, _ e: String?, _ p: Int) -> BrandScheduleWindow {
            BrandScheduleWindow(kit: kit, startsAt: LocalDateTime(s)!, endsAt: e.map { LocalDateTime($0)! }, priority: p)
        }
        let manifest = FX.brandManifest(windows: [w("spring", "2026-11-01T00:00", "2026-11-30T00:00", 10), w("winter", "2026-11-10T00:00", "2026-11-20T00:00", 20)],
                                        pool: [BrandPoolEntry(kit: "spring", weight: 2), BrandPoolEntry(kit: "everyday", weight: 1)])
        let selectionTimes: [(Int64, String?)] = [(0, nil), (6 * 86400, nil), (20 * 86400, nil), (6 * 86400, "winter"), (40 * 86400, nil)]
        let tokenCases: [JSONValue] = [FX.springTokens.jsonValue, BrandTokens(primary: BrandColor("#FFF5D6")!, secondary: BrandColor("#D9D9D9")!,
                                                                               accent: BrandColor("#FDFDFD")!, surface: BrandColor("#808080")!).jsonValue,
                                       .object(["primary": .string("#1F1E1C")])]
        let invalidTokens: [JSONValue] = [.object(["primary": .string("#2F5D50"), "button_label": .string("Approve")]), .object(["primary": .string("url(x)")]),
                                          .object(["primary": .string("#2F5D50"), "on_primary": .string("#FFFFFF")])]
        let dst: [(String, String)] = [("2026-11-15T07:00", "America/New_York"), ("2026-03-08T02:30", "America/New_York"), ("2026-11-01T01:30", "America/New_York"),
                                       ("2026-07-01T12:00", "America/Phoenix"), ("2026-03-29T02:30", "Europe/Berlin")]
        let noPoolManifest = FX.brandManifest(windows: manifest.schedule.windows)
        if Self.writing {
            let jws = try await manifest.sign(with: FX.brandKey)
            try Self.write(.object([
                "name": .string("brand-manifest-v1"), "version": .integer(1),
                "description": .string("Brand manifest (SECURITY.md 2.93): JWS typ viadere-brand-manifest+jws, pinned key below. `manifest_hash` (sha256 of canonical payload) is the ETag. `token_resolutions`: ContrastPolicy.resolve output (integer WCAG math, see SECURITY.md 2.93). `selections`: BrandKitSelector results at now + offset (seconds), with the pool seed `selection_seed_hex` (server HMAC per customer and business) when `use_seed` is true. `dst`: local wall-clock times and the instant they denote (earlier instant for repeated times, shifted forward by the gap for skipped ones)."),
                "kid": .string(FX.brandKid), "public_key": .string(FX.brandKey.publicKey.base64URL), "now": .integer(Int64(FX.now.timeIntervalSince1970)),
                "business_id": .string(FX.business.description), "payload": manifest.jsonValue, "jws": .string(jws), "manifest_hash": .string(try manifest.manifestHash()),
                "selection_seed_hex": .string(Hex.encode(seed)),
                "selections": .array(selectionTimes.flatMap { offset, pin in [true, false].map { useSeed in
                    let s = BrandKitSelector.select(manifest: useSeed ? manifest : noPoolManifest, now: FX.now.addingTimeInterval(TimeInterval(offset)), pinnedKit: pin,
                                                    selectionSeed: useSeed ? seed : nil)
                    var o: [String: JSONValue] = ["offset": .integer(offset), "use_seed": .bool(useSeed), "expected_reason": .string(s.reason.rawValue)]
                    if let pin { o["pinned_kit"] = .string(pin) }
                    if let kit = s.kitId { o["expected_kit"] = .string(kit) }
                    return JSONValue.object(o)
                } }),
                "token_resolutions": .array(try tokenCases.map { t in .object(["tokens": t, "expected": try JSONValue.encoding(ContrastPolicy.resolve(BrandTokens.parse(t).tokens))]) }),
                "invalid_tokens": .array(invalidTokens.map { t in .object(["tokens": t, "expected_issues": .array(BrandTokens.parse(t).issues.map { .string($0.code + "@" + $0.path) })]) }),
                "dst": .array(dst.map { local, zone in .object(["local": .string(local), "timezone": .string(zone),
                                                                 "instant": .integer(LocalDateTime(local)!.instant(in: TimeZone(identifier: zone)!))]) }),
            ]), name)
        }
        let v = try Self.read(name)
        let keys = [PinnedManifestKey(kid: try #require(v["kid"]?.stringValue), publicKey: try DevicePublicKey(base64URL: try #require(v["public_key"]?.stringValue)))]
        let verified = try BrandManifest.verify(v["jws"]?.stringValue, expectedBusiness: FX.business, keys: keys, now: FX.now)
        #expect(verified.jsonValue == v["payload"])
        #expect(try verified.manifestHash() == v["manifest_hash"]?.stringValue)
        #expect(Hex.encode(seed) == v["selection_seed_hex"]?.stringValue)
        let noPool = BrandManifest.parse(v["payload"]!).manifest.map { m -> BrandManifest in var m = m; m.schedule.randomPool = []; return m }
        guard case .array(let selections)? = v["selections"], case .array(let resolutions)? = v["token_resolutions"],
              case .array(let invalid)? = v["invalid_tokens"], case .array(let dstCases)? = v["dst"] else { throw VectorError.shape(name) }
        for item in selections {
            guard case .object(let c) = item, case .integer(let offset)? = c["offset"], case .bool(let useSeed)? = c["use_seed"] else { continue }
            let s = BrandKitSelector.select(manifest: useSeed ? verified : noPool, now: FX.now.addingTimeInterval(TimeInterval(offset)),
                                            pinnedKit: c["pinned_kit"]?.stringValue, selectionSeed: useSeed ? v["selection_seed_hex"]?.stringValue.flatMap(Hex.decode) : nil)
            #expect(s.kitId == c["expected_kit"]?.stringValue && s.reason.rawValue == c["expected_reason"]?.stringValue, "\(c)")
        }
        #expect(selections.count == 10)
        for item in resolutions {
            guard case .object(let c) = item, let t = c["tokens"] else { continue }
            #expect(try JSONValue.encoding(ContrastPolicy.resolve(BrandTokens.parse(t).tokens)) == c["expected"])
        }
        for item in invalid {
            guard case .object(let c) = item, let t = c["tokens"] else { continue }
            let issues = BrandTokens.parse(t).issues
            #expect(!issues.isEmpty)
            #expect(JSONValue.array(issues.map { .string($0.code + "@" + $0.path) }) == c["expected_issues"])
        }
        for item in dstCases {
            guard case .object(let c) = item, let local = c["local"]?.stringValue.flatMap(LocalDateTime.init),
                  let zone = c["timezone"]?.stringValue.flatMap(TimeZone.init(identifier:)), case .integer(let instant)? = c["instant"] else { continue }
            #expect(local.instant(in: zone) == instant)
        }
    }

    // MARK: Module layouts

    static let layoutCases: [(String, JSONValue, Bool)] = {
        func layout(_ modules: [(String, String)], template: String = "business_home", extra: [String: JSONValue] = [:]) -> JSONValue {
            var o: [String: JSONValue] = ["v": .integer(1), "template": .string(template),
                                          "modules": .array(modules.map { .object(["module": .string($0.0), "size": .string($0.1)]) })]
            for (k, value) in extra { o[k] = value }
            return .object(o)
        }
        return [
            ("valid_business_home", layout([("profile", "regular"), ("message", "compact"), ("offers", "regular"), ("rewards", "compact"), ("recent_activity", "compact"), ("approvals", "compact")]), false),
            ("valid_widget_small", layout([("offers", "compact")], template: "widget_small"), false),
            ("unknown_module", layout([("profile", "regular"), ("casino", "regular")]), false),
            ("duplicate_module", layout([("profile", "regular"), ("offers", "regular"), ("offers", "compact")]), false),
            ("missing_profile", layout([("offers", "regular")]), false),
            ("profile_not_first", layout([("offers", "regular"), ("profile", "regular")]), false),
            ("loops_not_enabled", layout([("profile", "regular"), ("loops", "regular")]), false),
            ("loops_enabled", layout([("profile", "regular"), ("loops", "regular")]), true),
            ("shop_reserved", layout([("profile", "regular"), ("shop", "regular")]), true),
            ("navigation_member", layout([("profile", "regular")], extra: ["tabs": .array([.string("shop")])]), false),
            ("widget_slot_overflow", layout([("offers", "compact"), ("rewards", "compact")], template: "widget_small"), false),
        ]
    }()

    @Test func moduleLayoutVectors() throws {
        let name = "module-layout-v1.json"
        if Self.writing {
            try Self.write(.object([
                "name": .string("module-layout-v1"), "version": .integer(1),
                "description": .string("Business surface layouts (plan 4.7, WP-1.6) validated against module registry v1. `expected_issues` lists code@path in order; empty means valid. `loops_enabled` states whether the Loops module is enabled for the business and customer."),
                "registry": .array(ModuleRegistry.v1.modules.map { m in .object(["id": .string(m.id), "availability": .string(m.availability.rawValue),
                                                                                 "sizes": .array(m.sizes.map { .string($0.rawValue) })]) }),
                "cases": .array(Self.layoutCases.map { caseName, layout, loops in
                    .object(["name": .string(caseName), "layout": layout, "loops_enabled": .bool(loops),
                             "expected_issues": .array(SurfaceLayout.validate(layout, loopsEnabled: loops).issues.map { .string($0.code + "@" + $0.path) })])
                }),
            ]), name)
        }
        let v = try Self.read(name)
        guard case .array(let cases)? = v["cases"] else { throw VectorError.shape(name) }
        #expect(cases.count == Self.layoutCases.count)
        for item in cases {
            guard case .object(let c) = item, let layout = c["layout"], case .bool(let loops)? = c["loops_enabled"] else { continue }
            let issues = SurfaceLayout.validate(layout, loopsEnabled: loops).issues
            #expect(JSONValue.array(issues.map { .string($0.code + "@" + $0.path) }) == c["expected_issues"], "\(c["name"]?.stringValue ?? "")")
        }
    }

    // MARK: Loop action events

    @Test func loopActionEventVectors() throws {
        let name = "loop-action-event-v1.json"
        let submission = LoopActionSubmission(instanceId: LoopInstanceID(UUID(uuidString: "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d")!), stepId: "s1",
                                              actionId: "confirm", inputs: ["slot": .string("am")], idempotencyKey: "tap-1")
        let envelope = LoopDeliveryEnvelope(type: .deliver, id: UUID(uuidString: "11111111-2222-4333-8444-555555555555")!,
                                            ref: UUID(uuidString: "66666666-7777-4888-9999-000000000000")!)
        if Self.writing {
            var transitions: [JSONValue] = []
            for from in LoopActionOutcome.allCases {
                for to in LoopActionOutcome.allCases {
                    for source in LoopOutcomeSource.allCases {
                        let ok = (try? LoopOutcomeMachine.transition(from: from, to: to, source: source)) != nil
                        if ok { transitions.append(.object(["from": .string(from.rawValue), "to": .string(to.rawValue), "source": .string(source.rawValue)])) }
                    }
                }
            }
            try Self.write(.object([
                "name": .string("loop-action-event-v1"), "version": .integer(1),
                "description": .string("Loop action events (SECURITY.md 2.94). `request_digest` = sha256 of the canonical digest object; the same idempotency key with another digest is a conflict. `envelope_canonical` is the ids-only queue message; any other type or v is dead-lettered. `legal_transitions` is the complete list of allowed outcome appends (everything else is refused); `pending` is the only initial outcome."),
                "submission": .object(["instance_id": .string(submission.instanceId.description), "step_id": .string(submission.stepId), "action_id": .string(submission.actionId),
                                       "inputs": .object(submission.inputs), "idempotency_key": .string(submission.idempotencyKey)]),
                "digest_object_canonical": .string(String(decoding: try CanonicalJSON.serialize(submission.digestObject), as: UTF8.self)),
                "request_digest": .string(try submission.requestDigest()),
                "envelope_canonical": .string(String(decoding: try envelope.encoded(), as: UTF8.self)),
                "initial_outcome": .string(LoopOutcomeMachine.initial.rawValue),
                "legal_transitions": .array(transitions),
                "customer_wording": .object(Dictionary(uniqueKeysWithValues: LoopActionOutcome.allCases.map { ($0.rawValue, JSONValue.string(LoopStringCatalog.outcomeText($0, business: "{business}"))) })),
            ]), name)
        }
        let v = try Self.read(name)
        #expect(String(decoding: try CanonicalJSON.serialize(submission.digestObject), as: UTF8.self) == v["digest_object_canonical"]?.stringValue)
        #expect(try submission.requestDigest() == v["request_digest"]?.stringValue)
        #expect(String(decoding: try envelope.encoded(), as: UTF8.self) == v["envelope_canonical"]?.stringValue)
        let envelopeText = try #require(v["envelope_canonical"]?.stringValue)
        #expect(LoopDeliveryEnvelope.parse(Data(envelopeText.utf8)) == envelope)
        guard case .array(let legal)? = v["legal_transitions"] else { throw VectorError.shape(name) }
        var count = 0
        for from in LoopActionOutcome.allCases {
            for to in LoopActionOutcome.allCases {
                for source in LoopOutcomeSource.allCases {
                    let ok = (try? LoopOutcomeMachine.transition(from: from, to: to, source: source)) != nil
                    let listed = legal.contains(.object(["from": .string(from.rawValue), "to": .string(to.rawValue), "source": .string(source.rawValue)]))
                    #expect(ok == listed, "\(from)->\(to) by \(source)")
                    if ok { count += 1 }
                }
            }
        }
        #expect(count == legal.count)
    }
}
