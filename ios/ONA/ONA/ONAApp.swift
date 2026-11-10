import SwiftUI

@main
struct ONAApp: App {
    @State private var model = RemoteModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            RootView(model: model)
        }
        .onChange(of: scenePhase, initial: true) { _, phase in
            // Polls only while the app is on screen: no push notifications, no background refresh.
            if phase == .active {
                model.startPolling()
            } else if phase == .background {
                model.stopPolling()
            }
        }
    }
}
