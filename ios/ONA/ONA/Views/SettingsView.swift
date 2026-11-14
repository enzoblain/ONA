import SwiftUI

/// "Settings" tab: the paired computer, what the phone keeps, and the app version. Tor settings live in the Tor tab.
struct SettingsView: View {
    let model: RemoteModel
    @State private var confirmingUnpair = false

    var body: some View {
        NavigationStack {
            Form {
                computerSection
                Section {
                    Text("This phone keeps the pairing (the computer's name and address, its public key, this phone's key, the read token and the request counter) and, if Tor is used, the Tor network data (see the Tor tab). Nothing is backed up to iCloud.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                } header: {
                    Text("Data on this phone")
                }
                Section {
                    Label {
                        Text("A compromised computer can do whatever it wants: this phone confirms actions, it cannot monitor the computer.")
                    } icon: {
                        Image(systemName: "desktopcomputer.trianglebadge.exclamationmark")
                    }
                    Label {
                        Text("A stolen, unlocked phone can read the conversations. Each action (message, confirmation, payment) still requires Face ID or the device passcode.")
                    } icon: {
                        Image(systemName: "iphone.slash")
                    }
                } header: {
                    Text("Limits")
                }
                .font(.callout)
                Section {
                    LabeledContent("Version", value: Self.appVersion)
                } header: {
                    Text("About")
                }
            }
            .navigationTitle("Settings")
            .confirmationDialog("Forget this computer?", isPresented: $confirmingUnpair, titleVisibility: .visible) {
                Button("Forget", role: .destructive) { model.unpair() }
            } message: {
                Text("This phone's key will be erased. To use it again, you will need to rescan the computer's code.")
            }
        }
    }

    @ViewBuilder
    private var computerSection: some View {
        if let pairing = model.pairing {
            Section {
                LabeledContent("Name", value: pairing.name)
                LabeledContent("Connection", value: pairing.onion != nil ? "Over Tor" : "Local network")
                LabeledContent("Paired on", value: pairing.pairedAt.formatted(date: .abbreviated, time: .shortened))
                LabeledContent("Key protection") {
                    switch pairing.keyKind {
                    case .secureEnclave: Text("Secure Enclave · Face ID")
                    case .software: Text("Software (simulator)").foregroundStyle(.orange)
                    }
                }
                Button("Forget this computer", role: .destructive) { confirmingUnpair = true }
            } header: {
                Text("Paired computer")
            }
        } else {
            Section {
                Text("No paired computer. Open the Home tab to scan the code shown by the computer.")
                    .foregroundStyle(.secondary)
            } header: {
                Text("Computer")
            }
        }
    }

    private static var appVersion: String {
        let info = Bundle.main.infoDictionary
        let version = info?["CFBundleShortVersionString"] as? String ?? "?"
        let build = info?["CFBundleVersion"] as? String ?? "?"
        return "\(version) (\(build))"
    }
}
