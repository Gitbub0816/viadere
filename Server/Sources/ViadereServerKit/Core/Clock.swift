import Foundation
import NIOConcurrencyHelpers

/// Time source. Injected so tests can control expiry, skew and TTLs.
public protocol ServerClock: Sendable {
    func now() -> Date
}

public struct SystemClock: ServerClock {
    public init() {}
    public func now() -> Date { Date() }
}

/// A manually advanced clock for tests.
public final class ManualClock: ServerClock, @unchecked Sendable {
    private let box: NIOLockedValueBox<Date>

    public init(_ start: Date = Date()) { box = NIOLockedValueBox(start) }

    public func now() -> Date { box.withLockedValue { $0 } }

    public func advance(by interval: TimeInterval) { box.withLockedValue { $0 = $0.addingTimeInterval(interval) } }

    public func set(_ date: Date) { box.withLockedValue { $0 = date } }
}

/// Monotonic microsecond sequence used to order outbound SMS.
public final class SequenceGenerator: Sendable {
    private let last = NIOLockedValueBox<Int64>(0)

    public init() {}

    public func next(now: Date) -> Int64 {
        last.withLockedValue { value in
            let candidate = Int64(now.timeIntervalSince1970 * 1_000_000)
            value = max(value + 1, candidate)
            return value
        }
    }
}
