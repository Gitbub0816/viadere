import Testing
import Foundation
import ViadereCore
@testable import ViadereKit

@MainActor
@Suite("Security notices")
struct SecurityNoticesTests {
    static func notice(_ kind: SecurityNoticeKind, message: String = "Plain text", age: TimeInterval = 7_200) -> SecurityNotice {
        SecurityNotice(id: UUID(), kind: kind, message: message, createdAt: Date().addingTimeInterval(-age))
    }

    @Test func loadsNewestFirstAndDismissesOne() async throws {
        let api = MockViadereAPI(seed: false)
        let older = Self.notice(.newPhone, age: 9_000), newer = Self.notice(.newDevice)
        await api.setSecurityNotices([older, newer])
        let model = SecurityNoticesViewModel(services: await ViadereServices.mock(api: api))
        await model.load()
        #expect(model.current == newer)
        #expect(model.additionalCount == 1)
        #expect(model.headline(for: newer).contains("2 h ago"))
        await model.dismiss(newer)
        #expect(model.notices == [older])
        #expect(await api.dismissedNoticeIds == [newer.id])
        #expect(model.message == nil)
    }

    @Test func noNoticesMeansNoBanner() async {
        let model = SecurityNoticesViewModel(services: await ViadereServices.mock(api: MockViadereAPI(seed: false)))
        await model.load()
        #expect(model.current == nil)
    }

    @Test func coolDownExplainsInsteadOfDismissing() async throws {
        let api = MockViadereAPI(seed: false)
        let n = Self.notice(.newDevice)
        await api.setSecurityNotices([n])
        await api.setDismissNeedsTrustedDevice(true)
        let model = SecurityNoticesViewModel(services: await ViadereServices.mock(api: api))
        await model.load()
        await model.dismiss(n)
        #expect(model.notices == [n])
        #expect(model.message == SecurityNoticesViewModel.coolDownMessage)
        #expect(model.message?.contains("can't dismiss") == true)
    }

    @Test func unknownKindRendersGenerically() async {
        let model = SecurityNoticesViewModel(services: await ViadereServices.mock(api: MockViadereAPI(seed: false)))
        let n = Self.notice(.unknown, message: "Something new happened.")
        #expect(model.headline(for: n).hasPrefix("Something new happened."))
        let empty = Self.notice(.unknown, message: "  ")
        #expect(model.headline(for: empty).hasPrefix("Something changed on your account"))
    }

    @Test func unknownKindDecodesFromServer() throws {
        let json = #"{"id":"6F9619FF-8B86-D011-B42D-00C04FC964FF","kind":"somethingNew","message":"m","createdAt":"2026-01-01T00:00:00Z"}"#
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        #expect(try decoder.decode(SecurityNotice.self, from: Data(json.utf8)).kind == .unknown)
    }

    @Test func transportFailureOnLoadKeepsBannerAbsent() async {
        let model = SecurityNoticesViewModel(services: await ViadereServices.mock(api: MockViadereAPI(seed: false)))
        await model.load()
        #expect(model.notices.isEmpty && model.message == nil)
    }

    @Test func signOutStillWipesWhenLogoutIsRefused() async throws {
        for failure in [APIError.server(status: 403, code: .forbidden, message: ""), .server(status: 401, code: .signatureInvalid, message: ""), .transport("offline")] {
            let api = MockViadereAPI(seed: false)
            await api.setSignOutCallsFail(failure)
            let services = await ViadereServices.mock(api: api)
            await services.account.signOut()
            #expect(await api.logoutCalls == 1)
            #expect(await services.sessions.tokens() == nil)
            #expect(try await services.records.load() == nil)
            #expect(await services.keys.availablePurposes().isEmpty)
        }
    }
}
