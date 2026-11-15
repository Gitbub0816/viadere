@preconcurrency import Crypto
import Fluent
import Foundation
import ViadereCore
import struct ViadereCore.Page
import XCTest
@testable import ViadereServerKit

final class DirectoryTests: XCTestCase {
    func testHandleCodeLinkAndNameAllResolveToTheSameVerifiedBusiness() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            _ = try await h.makeBusiness(name: "Juniper Coffee", handle: "junipercoffee")
            let code = b.summary.code
            // Direct lookups (public, unauthenticated).
            let byHandle = try await h.request(.GET, "/v1/directory/handles/@northwindair").json(BusinessProfile.self)
            let byHandleBare = try await h.request(.GET, "/v1/directory/handles/NorthwindAir").json(BusinessProfile.self)
            let byCode = try await h.request(.GET, "/v1/directory/codes/\(code.display)").json(BusinessProfile.self)
            XCTAssertEqual(byHandle.id, b.id)
            XCTAssertEqual(byHandleBare.id, b.id)
            XCTAssertEqual(byCode.id, b.id)
            XCTAssertEqual(byCode.verificationStatus, .verified)
            // Resolve: link with a signed context, plain link, handle, code, name.
            let key = h.config.connectLinkKey
            let context = ConnectContext(campaign: "summer-print", action: "connect", issuedAt: h.clock.now(), expiresAt: h.clock.now().addingTimeInterval(3600))
            let signedLink = try ConnectLink(code: code, context: context, key: key).urlString
            let inputs = [signedLink, "https://viadere.com/c/\(code.canonical)", "@northwindair", code.display, code.canonical.lowercased(), "Northwind"]
            for input in inputs {
                let response = try await h.post("/v1/directory/resolve", DirectoryResolveRequest(input: input))
                XCTAssertEqual(response.status, .ok, "\(input) \(response.text)")
                let resolved = try response.json(DirectoryResolveResponse.self)
                XCTAssertEqual(resolved.matches.map(\.id), [b.id], input)
            }
            let signed = try await h.post("/v1/directory/resolve", DirectoryResolveRequest(input: signedLink)).json(DirectoryResolveResponse.self)
            XCTAssertEqual(signed.method, .link)
            XCTAssertEqual(signed.context?.campaign, "summer-print")
            // A tampered or expired context is ignored; the plain code still resolves.
            let tampered = signedLink.replacingOccurrences(of: "&sig=", with: "&sig=AAAA")
            let tamperedResponse = try await h.post("/v1/directory/resolve", DirectoryResolveRequest(input: tampered))
            XCTAssertEqual(tamperedResponse.status, .ok)
            XCTAssertNil(try tamperedResponse.json(DirectoryResolveResponse.self).context)
            h.clock.advance(by: 7200)
            let expired = try await h.post("/v1/directory/resolve", DirectoryResolveRequest(input: signedLink)).json(DirectoryResolveResponse.self)
            XCTAssertNil(expired.context)
            XCTAssertEqual(expired.matches.map(\.id), [b.id])
            // Lookalike hosts and schemes never resolve as links.
            let evil = try await h.post("/v1/directory/resolve", DirectoryResolveRequest(input: "https://viadere.com.evil.io/c/\(code.canonical)"))
            XCTAssertEqual(try evil.json(DirectoryResolveResponse.self).method, .name)
            // Search.
            let search = try await h.request(.GET, "/v1/directory/search?q=north&limit=5").json(Page<BusinessSummary>.self)
            XCTAssertEqual(search.items.map(\.id), [b.id])
        }
    }

    func testCodeNormalizationIAndOEquivalentLDistinct() async throws {
        try await withHarness { h in
            let a = try await BusinessRegistry(db: h.db, ctx: h.ctx).register(displayName: "Alpha Demo", handle: "alphademo", category: .other, status: .verified, explicitCode: BusinessCode("IO3456"))
            try await eq(try await BusinessCodeRecord.query(on: h.db).filter(\.$businessId == a.id!).first()?.canonical, "103456")
            for spelling in ["IO3456", "103456", "io-3456", "I0 3456"] {
                let response = try await h.request(.GET, "/v1/directory/codes/\(spelling.replacingOccurrences(of: " ", with: "%20"))")
                XCTAssertEqual(response.status, .ok, spelling)
            }
            // A second business cannot take a code that normalizes to the same canonical value.
            do {
                _ = try await BusinessRegistry(db: h.db, ctx: h.ctx).register(displayName: "Beta Demo", handle: "betademo", category: .other, status: .verified, explicitCode: BusinessCode("1O3456"))
                XCTFail("colliding code must be refused")
            } catch BusinessRegistry.RegistryError.codeUnavailable {}
            // L stays distinct from 1.
            let l = try await BusinessRegistry(db: h.db, ctx: h.ctx).register(displayName: "Gamma Demo", handle: "gammademo", category: .other, status: .verified, explicitCode: BusinessCode("L03456"))
            XCTAssertNotEqual(l.id, a.id)
            // The database itself enforces uniqueness on the canonical form.
            let duplicate = BusinessCodeRecord(businessId: l.id!, code: try BusinessCode("IO3456"), now: h.clock.now())
            do {
                try await duplicate.create(on: h.db)
                XCTFail("unique(canonical) must reject")
            } catch { XCTAssertTrue(error.isConstraintViolation) }
        }
    }

    func testRetiredCodesAreNeverReassigned() async throws {
        try await withHarness { h in
            let registry = BusinessRegistry(db: h.db, ctx: h.ctx)
            let a = try await registry.register(displayName: "Alpha Demo", handle: "alphademo", category: .other, status: .verified)
            let old = try await BusinessCodeRecord.query(on: h.db).filter(\.$businessId == a.id!).first()!.canonical
            let new = try await registry.rotateCode(businessId: a.id!)
            XCTAssertNotEqual(new.canonical, old)
            // The retired code no longer resolves and cannot be issued to anyone, including a spelling variant.
            try await eq(try await h.request(.GET, "/v1/directory/codes/\(old)").status, .notFound)
            do {
                _ = try await registry.register(displayName: "Beta Demo", handle: "betademo", category: .other, status: .verified, explicitCode: BusinessCode(old))
                XCTFail("retired code reused")
            } catch BusinessRegistry.RegistryError.codeUnavailable {}
            let retired = try await RetiredBusinessCodeRecord.query(on: h.db).all()
            XCTAssertEqual(retired.map(\.canonical), [old])
            XCTAssertEqual(retired.first?.businessId, a.id)
        }
    }

    func testConfusableAndReservedHandlesAreRejected() async throws {
        try await withHarness { h in
            let registry = BusinessRegistry(db: h.db, ctx: h.ctx)
            _ = try await registry.register(displayName: "Northwind Air", handle: "northwindair", category: .other, status: .verified)
            func register(_ handle: String) async -> BusinessRegistry.RegistryError? {
                do {
                    _ = try await registry.register(displayName: "Imposter", handle: handle, category: .other, status: .verified)
                    return nil
                } catch let error as BusinessRegistry.RegistryError { return error } catch { return .invalidHandle }
            }
            let dup = await register("northwindair")
            XCTAssertEqual(dup, .handleTaken)
            for lookalike in ["n0rthwindair", "northwlndair", "northwindalr", "north_windair"] {
                let result = await register(lookalike)
                XCTAssertTrue(result == .confusableHandle || result == .invalidHandle, "\(lookalike) -> \(String(describing: result))")
            }
            for bad in ["viadere", "v1adere", "viadere_support", "admin", "st0p", "nonascií", "ab", "9lives", "trailing_"] {
                let result = await register(bad)
                XCTAssertEqual(result, .invalidHandle, bad)
            }
            let count = try await BusinessHandleRecord.query(on: h.db).count()
            XCTAssertEqual(count, 1)
        }
    }

    func testOnlyVerifiedBusinessesAreDiscoverable() async throws {
        try await withHarness { h in
            let pending = try await h.makeBusiness(name: "Pendingco", handle: "pendingco", status: .pending)
            let suspended = try await h.makeBusiness(name: "Suspendedco", handle: "suspendedco", status: .suspended)
            let verified = try await h.makeBusiness(name: "Verifiedco", handle: "verifiedco")
            for b in [pending, suspended] {
                try await eq(try await h.request(.GET, "/v1/directory/handles/\(b.summary.handle!.value)").status, .notFound)
                try await eq(try await h.request(.GET, "/v1/directory/codes/\(b.summary.code.canonical)").status, .notFound)
                try await eq(try await h.post("/v1/directory/resolve", DirectoryResolveRequest(input: b.summary.code.display)).status, .notFound)
                try await eq(try await h.request(.GET, "/c/\(b.summary.code.canonical)").status, .notFound)
            }
            let search = try await h.request(.GET, "/v1/directory/search?q=co").json(Page<BusinessSummary>.self)
            XCTAssertEqual(search.items.map(\.id), [verified.id])
            // Connecting to an unverified business is refused with the same 404.
            let consumer = try await h.readyConsumer()
            let response = try await h.signedPost(consumer, "/v1/relationships", ConnectRequest(businessId: pending.id, source: .code))
            XCTAssertEqual(response.status, .notFound)
        }
    }

    func testSearchIsSafeAgainstWildcardsAndOversizedInput() async throws {
        try await withHarness { h in
            _ = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            for q in ["%", "_", "%%%%", "n%r", "'; DROP TABLE businesses; --"] {
                let response = try await h.request(.GET, "/v1/directory/search?q=\(q.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!)")
                XCTAssertTrue([200, 422].contains(response.status.code), "\(q) \(response.status)")
                if response.status == .ok { XCTAssertEqual(try response.json(Page<BusinessSummary>.self).items.count, 0, q) }
            }
            try await eq(try await h.request(.GET, "/v1/directory/search").status, .unprocessableEntity)
            try await eq(try await h.request(.GET, "/v1/directory/search?q=\(String(repeating: "a", count: 500))").status, .unprocessableEntity)
            let tables = try await BusinessRecord.query(on: h.db).count()
            XCTAssertEqual(tables, 1)
        }
    }

    func testConnectFlowsFromEveryEntryPointConvergeOnOneRelationship() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.readyConsumer()
            let link = ConnectLink(code: b.summary.code).urlString
            let first = try await h.signedPost(consumer, "/v1/relationships", ConnectRequest(businessId: b.id, source: .qr, link: link))
            XCTAssertEqual(first.status, .created, first.text)
            let second = try await h.signedPost(consumer, "/v1/relationships", ConnectRequest(businessId: b.id, source: .handle))
            XCTAssertEqual(second.status, .ok)
            XCTAssertEqual(try first.json(Relationship.self).id, try second.json(Relationship.self).id)
            // A link for a different business is refused.
            let other = try await h.makeBusiness(name: "Juniper Coffee", handle: "junipercoffee")
            let mismatch = try await h.signedPost(consumer, "/v1/relationships", ConnectRequest(businessId: other.id, source: .qr, link: link))
            XCTAssertEqual(mismatch.status, .unprocessableEntity)
            let list = try await h.signed(consumer, .GET, "/v1/relationships").json([Relationship].self)
            XCTAssertEqual(list.map(\.business.id), [b.id])
            // Another consumer cannot disconnect it.
            let mallory = try await h.readyConsumer(name: "Mallory")
            try await eq(try await h.signed(mallory, .DELETE, "/v1/relationships/\(list[0].id)").status, .notFound)
        }
    }

    func testPseudonymousReferencesDifferPerBusiness() throws {
        let hasher = Hasher256(pepper: Data(repeating: 7, count: 32))
        let consumer = ConsumerID()
        let a = BusinessID(), b = BusinessID()
        XCTAssertEqual(hasher.consumerReference(businessId: a, consumerId: consumer), hasher.consumerReference(businessId: a, consumerId: consumer))
        XCTAssertNotEqual(hasher.consumerReference(businessId: a, consumerId: consumer), hasher.consumerReference(businessId: b, consumerId: consumer))
        XCTAssertNotEqual(hasher.consumerReference(businessId: a, consumerId: consumer).uuid, consumer.uuid)
    }

    func testIssuedCodesAlwaysContainADigitSoTypedCodesAreNeverMistakenForNames() {
        for _ in 0..<2000 {
            let code = BusinessRegistry.generateDiscoverableCode()
            XCTAssertTrue(code.canonical.contains(where: \.isNumber), code.canonical)
            guard case .code(let parsed) = DirectoryInput(parsing: code.display) else { return XCTFail("\(code.display) was not classified as a code") }
            XCTAssertEqual(parsed, code)
        }
    }
}
