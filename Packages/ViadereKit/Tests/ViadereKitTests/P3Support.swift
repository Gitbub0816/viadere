import Foundation
import ViadereCore
@testable import ViadereKit

/// 2026-10-27 18:00 UTC = Tuesday 11:00 in Phoenix (UTC-7, no DST). The Juniper "free coffee on Tuesdays" reward is eligible.
let tuesdayNoon = ISO8601DateFormatter().date(from: "2026-10-27T18:00:00Z") ?? Date()
/// The next day: Wednesday.
let wednesdayNoon = ISO8601DateFormatter().date(from: "2026-10-28T18:00:00Z") ?? Date()

/// A fully seeded P3 world on a fixed clock.
@MainActor
func p3World(now: Date = tuesdayNoon, unsupportedKeys: Set<DeviceKeyPurpose> = []) async -> (services: ViadereServices, api: MockViadereAPI) {
    let clock: @Sendable () -> Date = { now }
    let api = MockViadereAPI(seed: true, p3: true, clock: clock)
    let services = await ViadereServices.mock(api: api, unsupportedKeys: unsupportedKeys, clock: clock)
    return (services, api)
}
