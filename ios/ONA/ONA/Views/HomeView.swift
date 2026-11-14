import SwiftUI

/// "Home" tab: pairing when there is no computer yet, then the conversations with the agent.
struct HomeView: View {
    @Bindable var model: RemoteModel

    var body: some View {
        if model.isPaired {
            ChatListView(model: model)
        } else {
            NavigationStack {
                PairingView(model: model)
                    .navigationTitle("ONA")
            }
            .alert("Action not possible", isPresented: .constant(model.actionError != nil)) {
                Button("OK") { model.clearActionError() }
            } message: {
                Text(model.actionError ?? "")
            }
        }
    }
}

struct ConnectionStatusRow: View {
    let connection: RemoteModel.Connection
    let computer: String?
    var viaTor = false

    var body: some View {
        switch connection {
        case .notPaired:
            Label("No paired computer", systemImage: "link.badge.plus")
                .foregroundStyle(.secondary)
        case .idle, .connecting:
            Label {
                Text(viaTor ? "Securing the connection over Tor…" : "Connecting to the computer…")
            } icon: {
                ProgressView()
            }
            .foregroundStyle(.secondary)
        case .connected(let date):
            Label {
                VStack(alignment: .leading, spacing: 2) {
                    Text(computer ?? "Computer")
                    Text(viaTor ? "Connected over Tor · updated \(date.formatted(date: .omitted, time: .shortened))"
                                : "Connected · updated \(date.formatted(date: .omitted, time: .shortened))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } icon: {
                Image(systemName: viaTor ? "lock.circle.fill" : "checkmark.circle.fill").foregroundStyle(.green)
            }
        case .awaitingComputer:
            Label {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Confirm on \(computer ?? "the computer")")
                    Text("Click “The codes match” on the computer to finish pairing.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } icon: {
                Image(systemName: "hourglass").foregroundStyle(.tint)
            }
        case .failed(let message):
            Label {
                Text(message)
            } icon: {
                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
            }
        }
    }
}
