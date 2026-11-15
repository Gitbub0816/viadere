import Foundation
import XCTest
import ViadereCore
@testable import ViadereBusinessSDK

/// The `push_approval` delivery record (ADR-0022 §1, ledger S6-09) reaches the SDK as an ordinary delivery view.
final class DeliveryViewSDKTests: XCTestCase {
    func testAPushApprovalRecordDecodesAsADeliveryView() async throws {
        let transport = MockTransport()
        let id = AuthDeliveryID()
        transport.enqueue(status: 200, raw: #"{"id":"\#(id)","request_id":"push_approval#login-7","method":"push_approval","purpose":"sign_in","status":"completed","#
                          + #""expires_at":"2027-01-15T08:05:00.000Z","created_at":"2027-01-15T08:00:00.000Z","events":[{"status":"created","at":"2027-01-15T08:00:00.000Z"}]}"#)
        let view = try await Fixtures.client(transport).authDelivery(id: id)
        XCTAssertEqual(view.method, .pushApproval)
        XCTAssertEqual(view.requestId, "push_approval#login-7")
        // Creatable methods are unchanged: a create request still cannot name `push_approval`.
        XCTAssertFalse(AuthDeliveryMethod.allCases.map(\.rawValue).contains("push_approval"))
        XCTAssertEqual(AuthDeliveryViewMethod(AuthDeliveryMethod.otp), .otp)
    }
}
