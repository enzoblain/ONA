import SwiftUI

@main
struct ONADesktopApp: App {
    @State private var model = DesktopModel()
    @NSApplicationDelegateAdaptor private var delegate: AppDelegate

    var body: some Scene {
        WindowGroup("ONA") {
            ContentView(model: model)
                .frame(minWidth: 820, minHeight: 560)
                .onAppear { delegate.model = model }
                .task { await debugHooksForAutomatedTests() }
        }
        .windowToolbarStyle(.unified)
        .commands {
            CommandGroup(replacing: .newItem) {}
        }

        Settings {
            SettingsView(model: model)
        }
    }

    /// Debug builds only, for end-to-end tests driven from a script: prints the pairing QR text on stdout, and with
    /// `-ONAAutoConfirmPairing` accepts the 6-digit code without a click. Compiled out of Release builds.
    private func debugHooksForAutomatedTests() async {
        #if DEBUG
        let autoConfirm = ProcessInfo.processInfo.arguments.contains("-ONAAutoConfirmPairing")
        var printed: String?
        while !Task.isCancelled {
            if let payload = model.pairingPayload, payload != printed {
                print("ONA_PAIRING_PAYLOAD \(payload)")
                fflush(stdout)
                printed = payload
            }
            if autoConfirm, model.pairing.awaiting != nil {
                model.pairing.confirmCode()
            }
            try? await Task.sleep(for: .milliseconds(500))
        }
        #endif
    }
}

/// Stops tor when the app quits.
final class AppDelegate: NSObject, NSApplicationDelegate {
    @MainActor var model: DesktopModel?

    func applicationWillTerminate(_ notification: Notification) {
        MainActor.assumeIsolated { model?.stop() }
    }
}
