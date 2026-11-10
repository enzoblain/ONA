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

/// Bottom tab bar (Liquid Glass on iOS 26 and later): Accueil, Tor, Réglages.
struct AppTabs: View {
    @Bindable var model: RemoteModel
    @State private var selection: TabID = .home

    enum TabID: Hashable {
        case home, tor, settings
    }

    var body: some View {
        TabView(selection: $selection) {
            Tab("Accueil", systemImage: "house", value: TabID.home) {
                HomeView(model: model)
            }
            .badge(model.pending == nil ? 0 : 1)
            Tab("Tor", systemImage: "network.badge.shield.half.filled", value: TabID.tor) {
                TorView(model: model)
            }
            Tab("Réglages", systemImage: "gearshape", value: TabID.settings) {
                SettingsView(model: model)
            }
        }
        .minimizingTabBarOnScroll()
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

private extension View {
    /// The tab bar shrinks while scrolling down (iOS 26 and later; no effect before).
    @ViewBuilder
    func minimizingTabBarOnScroll() -> some View {
        if #available(iOS 26.0, *) {
            tabBarMinimizeBehavior(.onScrollDown)
        } else {
            self
        }
    }
}
