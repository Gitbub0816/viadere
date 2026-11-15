import Testing
import Foundation
@testable import ViadereKit

@Suite("Watch appearance sync")
struct WatchAppearanceSyncTests {
    @Test func selectionRoundTripsThroughTheContext() throws {
        let choice = AppearanceSelection(light: .folio, dark: .ember, follow: .alwaysLight, honorsIncreaseContrast: false)
        let context = WatchSync.context(items: [], appearance: choice)
        #expect(context[WatchSync.contextKey] != nil)
        let any: [String: Any] = context
        #expect(WatchSync.appearance(fromContext: any) == choice)
        #expect(WatchSync.decode(context[WatchSync.contextKey] ?? Data()).isEmpty)
    }

    @Test func missingOrUnreadablePayloadsFallBackSafely() {
        #expect(WatchSync.appearance(fromContext: [:]) == nil)
        #expect(WatchSync.appearance(fromContext: [WatchSync.appearanceKey: "text"]) == nil)
        #expect(WatchSync.decodeAppearance(Data("not json".utf8)) == nil)
        #expect(WatchSync.decodeAppearance(nil) == nil)
        let stored = AppearanceSelection(light: .sage, dark: .midnight)
        #expect(WatchSync.resolveWatchAppearance(received: nil, stored: stored) == stored)
        #expect(WatchSync.resolveWatchAppearance(received: nil, stored: nil) == .default)
        #expect(WatchSync.resolveWatchAppearance(received: .default, stored: stored) == .default)
    }

    @Test func misplacedThemesFallBackToTheirSidesDefaults() {
        let data = Data(#"{"light":"nightfall","dark":"daybreak","follow":"bogus"}"#.utf8)
        let decoded = WatchSync.decodeAppearance(data)
        #expect(decoded?.light == .daybreak)
        #expect(decoded?.dark == .nightfall)
        #expect(decoded?.follow == .system)
    }

    @Test func theWatchAlwaysDrawsTheNightSide() {
        for follow in AppearanceFollow.allCases {
            let choice = AppearanceSelection(light: .folio, dark: .ember, follow: follow)
            #expect(choice.watchTheme.id == .ember)
            #expect(choice.watchTheme.side == .dark)
        }
        #expect(AppearanceSelection.default.watchTheme.id == .nightfall)
    }

    @Test func appearancePayloadCarriesNothingSecret() throws {
        let data = try #require(WatchSync.encode(AppearanceSelection.default))
        let text = String(decoding: data, as: UTF8.self)
        #expect(!text.contains("challenge") && !text.contains("token"))
    }
}
