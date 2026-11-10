import SwiftUI

@main
struct TorSpikeApp: App {
    @State private var model = SpikeModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            SpikeView(model: model)
        }
        .onChange(of: scenePhase) { _, new in
            // Only background <-> foreground matters; `inactive` is a passing state (app switcher, control centre).
            switch new {
            case .background:
                wasInBackground = true
                model.appMovedTo(foreground: false)
            case .active where wasInBackground:
                wasInBackground = false
                model.appMovedTo(foreground: true)
            default:
                break
            }
        }
    }

    @State private var wasInBackground = false
}
