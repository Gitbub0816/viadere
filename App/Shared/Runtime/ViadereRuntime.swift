import Foundation
import ViadereKit

/// Process-wide configuration, resolved once from the running bundle's Info.plist.
/// The app, the notification service extension and the App Clip each ship the same keys
/// (`ViadereAPIBaseURL`, `ViadereKeychainAccessGroup`).
enum ViadereRuntime {
    static let configuration: ViadereConfiguration = {
        #if DEBUG
        let allowLocalHTTP = true
        #else
        // Release builds never talk plain HTTP, whatever the Info.plist says.
        let allowLocalHTTP = false
        #endif
        let configuration = ViadereConfiguration.resolve(info: Bundle.main.infoDictionary ?? [:], allowLocalHTTP: allowLocalHTTP)
        // Every link parser (connect, Approve enrollment, link sessions, account link, handoff) accepts only this build's link domain (WP-C3).
        configuration.installLinkDomain()
        return configuration
    }()
}
