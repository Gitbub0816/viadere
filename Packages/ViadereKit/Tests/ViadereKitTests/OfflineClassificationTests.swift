import Foundation
import Testing
@testable import ViadereKit

/// Only a missing network may be called "offline": a refused pin or TLS check, or a missing shared container (the refresh lock), is a
/// local failure with its own message (staging report 2026-11-16: every screen said "offline" while the phone was online).
@Suite struct OfflineClassificationTests {
    @Test func aCancelledOrUntrustedConnectionIsASecureConnectionFailureNotOffline() {
        for code in [URLError.Code.cancelled, .serverCertificateUntrusted, .secureConnectionFailed] {
            let error = APIError.transport(APIError.transportReason(for: URLError(code)))
            #expect(!error.isConnectivityFailure)
            #expect(!error.userMessage.contains("connection and try again"))
        }
    }

    @Test func noNetworkIsOffline() {
        for code in [URLError.Code.notConnectedToInternet, .timedOut, .networkConnectionLost, .cannotFindHost] {
            let error = APIError.transport(APIError.transportReason(for: URLError(code)))
            #expect(error.isConnectivityFailure)
            #expect(error.userMessage == "Can't reach Viadere right now. Check your connection and try again.")
        }
    }

    @Test func aMissingRefreshLockIsNotOffline() {
        for reason in ["refresh-lock-unavailable", "refresh-lock-timeout", "refresh-busy", "credentials-locked", "non-http"] {
            #expect(!APIError.transport(reason).isConnectivityFailure)
        }
        #expect(!APIError.server(status: 500, code: .unknown, message: "").isConnectivityFailure)
    }

    @Test func aDevicePairingLocalFailureIsNotReportedAsOffline() {
        #expect(DevicePairingError.from(APIError.transport("refresh-lock-unavailable")) != .offline)
        #expect(DevicePairingError.from(APIError.transport(APIError.TransportReason.offline)) == .offline)
    }
}
