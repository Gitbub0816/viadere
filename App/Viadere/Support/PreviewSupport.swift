#if DEBUG
import SwiftUI
import ViadereKit

/// Builds an in-memory world (mock API, software keys) and hands it to a preview.
struct PreviewHost<Content: View>: View {
    let signedIn: Bool
    let unsupportedKeys: Set<DeviceKeyPurpose>
    let content: (ViadereServices) -> Content
    @State private var services: ViadereServices?

    init(signedIn: Bool = true, unsupportedKeys: Set<DeviceKeyPurpose> = [], @ViewBuilder content: @escaping (ViadereServices) -> Content) {
        self.signedIn = signedIn
        self.unsupportedKeys = unsupportedKeys
        self.content = content
    }

    var body: some View {
        Group {
            if let services {
                content(services)
            } else {
                ViadereLoading().frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .viadereScreenBackground()
        .task {
            services = await ViadereServices.mock(signedIn: signedIn, unsupportedKeys: unsupportedKeys)
        }
    }
}
#endif
