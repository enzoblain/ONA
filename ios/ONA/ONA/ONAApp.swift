import SwiftUI

@main
struct ONAApp: App {
    @State private var model = RemoteModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            RootView(model: model)
                .task { await pairFromLaunchArgumentForSimulatorTests() }
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

    /// Simulator + Debug only: `xcrun simctl launch <device> org.ona.remote -ONAPairingText 'ona-pair:…'` pairs at
    /// launch, because the simulator has no camera and automated taps cannot use the system paste button.
    /// Compiled out of any build for a device.
    private func pairFromLaunchArgumentForSimulatorTests() async {
        #if DEBUG && targetEnvironment(simulator)
        let args = ProcessInfo.processInfo.arguments
        if !model.isPaired, let i = args.firstIndex(of: "-ONAPairingText"), i + 1 < args.count {
            await model.pair(with: args[i + 1])
        }
        #endif
    }
}
