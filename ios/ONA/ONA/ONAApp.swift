import SwiftUI

@main
struct ONAApp: App {
    @State private var model = RemoteModel(makeLink: AppLinks.make)
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            AppTabs(model: model)
                .task { await pairFromLaunchArgumentForSimulatorTests() }
        }
        .onChange(of: scenePhase, initial: true) { _, phase in
            // Polls only while the app is on screen: no push notifications, no background refresh.
            if phase == .active {
                ArtiTor.shared.setDormant(false)
                model.startPolling()
            } else if phase == .background {
                model.stopPolling()
                ArtiTor.shared.setDormant(true)
            }
        }
    }

    /// Simulator + Debug only: `xcrun simctl launch <device> org.ona.remote -ONAPairingText 'ona-pair:…'` pairs at
    /// launch, because the simulator has no camera and automated taps cannot use the system paste button.
    /// `-ONAChatText "…"` starts a chat the same way. Compiled out of any build for a device.
    private func pairFromLaunchArgumentForSimulatorTests() async {
        #if DEBUG && targetEnvironment(simulator)
        let args = ProcessInfo.processInfo.arguments
        if !model.isPaired, let i = args.firstIndex(of: "-ONAPairingText"), i + 1 < args.count {
            await model.pair(with: args[i + 1])
        }
        // Same reason for the first message of a chat: automated taps cannot type on the simulator's keyboard.
        if model.isPaired, let i = args.firstIndex(of: "-ONAChatText"), i + 1 < args.count {
            _ = await model.startChat(args[i + 1])
            model.closeChat()
        }
        #endif
    }
}

/// Bottom tab bar in Liquid Glass: Home, Pool, Tor, Settings.
struct AppTabs: View {
    @Bindable var model: RemoteModel
    @State private var selection: TabID = .home

    enum TabID: Hashable {
        case home, pool, tor, settings
    }

    var body: some View {
        TabView(selection: $selection) {
            Tab("Home", systemImage: "house", value: TabID.home) {
                HomeView(model: model)
            }
            .badge(model.waitingCount)
            Tab("Pool", systemImage: "chart.pie", value: TabID.pool) {
                PoolView(model: model)
            }
            Tab("Tor", systemImage: "network.badge.shield.half.filled", value: TabID.tor) {
                TorView(model: model)
            }
            Tab("Settings", systemImage: "gearshape", value: TabID.settings) {
                SettingsView(model: model)
            }
        }
        .tabBarMinimizeBehavior(.onScrollDown)
        .fullScreenCover(isPresented: .constant(model.verification != nil)) {
            if let verification = model.verification {
                VerificationView(model: model, verification: verification)
            }
        }
        .onChange(of: model.isPaired) { _, paired in
            if paired {
                selection = .home
                model.startPolling()
            }
        }
    }
}
