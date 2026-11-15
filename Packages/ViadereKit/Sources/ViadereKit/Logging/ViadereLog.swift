import Foundation
#if canImport(os)
import os
#endif

/// Privacy-first logging. The event name is a compile-time constant and public; **every dynamic value is
/// logged `.private`** (redacted unless a debugger is attached). Never pass tokens, codes, amounts, names,
/// phone numbers or message bodies, even though they would be redacted.
public struct ViadereLog: Sendable {
    public enum Category: String, Sendable { case api, security, approvals, notifications, ui, storage }

    #if canImport(os)
    private let logger: Logger
    #endif

    public init(_ category: Category) {
        #if canImport(os)
        logger = Logger(subsystem: "com.viadere", category: category.rawValue)
        #endif
    }

    public func info(_ event: StaticString, detail: @autoclosure @escaping () -> String = "") {
        #if canImport(os)
        let name = String(describing: event)
        logger.info("\(name, privacy: .public) \(detail(), privacy: .private)")
        #endif
    }

    public func error(_ event: StaticString, detail: @autoclosure @escaping () -> String = "") {
        #if canImport(os)
        let name = String(describing: event)
        logger.error("\(name, privacy: .public) \(detail(), privacy: .private)")
        #endif
    }

    public static let api = ViadereLog(.api)
    public static let security = ViadereLog(.security)
    public static let approvals = ViadereLog(.approvals)
    public static let notifications = ViadereLog(.notifications)
    public static let ui = ViadereLog(.ui)
    public static let storage = ViadereLog(.storage)
}
