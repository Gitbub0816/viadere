import Logging
import XCTest
@testable import ViadereServerKit

final class LogLevelPolicyTests: XCTestCase {
    /// At debug/trace the database driver logs every query with its bound values (emails, phone hashes, ciphertext), so a strict
    /// environment never runs below info, whatever LOG_LEVEL says.
    func testStrictEnvironmentsNeverLogBelowInfo() {
        for environment in ["staging", "production", "Staging"] {
            XCTAssertEqual(LogLevelPolicy.effective(logLevel: "debug", environment: environment), .info, environment)
            XCTAssertEqual(LogLevelPolicy.effective(logLevel: "trace", environment: environment), .info, environment)
            XCTAssertEqual(LogLevelPolicy.effective(logLevel: "warning", environment: environment), .warning, "raising the level is allowed")
            XCTAssertEqual(LogLevelPolicy.effective(logLevel: nil, environment: environment), .info)
        }
    }

    func testDevelopmentMayDebug() {
        XCTAssertEqual(LogLevelPolicy.effective(logLevel: "debug", environment: "development"), .debug)
        XCTAssertEqual(LogLevelPolicy.effective(logLevel: "TRACE", environment: "test"), .trace)
        XCTAssertEqual(LogLevelPolicy.effective(logLevel: "nonsense", environment: "development"), .info)
        // An unknown or missing ENVIRONMENT is treated as strict here (startup refuses it anyway).
        XCTAssertEqual(LogLevelPolicy.effective(logLevel: "debug", environment: nil), .info)
        XCTAssertEqual(LogLevelPolicy.effective(logLevel: "debug", environment: "prod"), .info)
    }
}
