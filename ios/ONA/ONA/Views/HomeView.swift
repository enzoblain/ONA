import SwiftUI

/// "Accueil" tab: pairing when there is no computer yet, then the conversations with the agent.
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
            .alert("Action impossible", isPresented: .constant(model.actionError != nil)) {
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
            Label("Aucun ordinateur appairé", systemImage: "link.badge.plus")
                .foregroundStyle(.secondary)
        case .idle, .connecting:
            Label {
                Text(viaTor ? "Connexion sécurisée par Tor…" : "Connexion à l'ordinateur…")
            } icon: {
                ProgressView()
            }
            .foregroundStyle(.secondary)
        case .connected(let date):
            Label {
                VStack(alignment: .leading, spacing: 2) {
                    Text(computer ?? "Ordinateur")
                    Text(viaTor ? "Connecté par Tor · à jour \(date.formatted(date: .omitted, time: .shortened))"
                                : "Connecté · à jour \(date.formatted(date: .omitted, time: .shortened))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } icon: {
                Image(systemName: viaTor ? "lock.circle.fill" : "checkmark.circle.fill").foregroundStyle(.green)
            }
        case .awaitingComputer:
            Label {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Confirmez sur \(computer ?? "l'ordinateur")")
                    Text("Cliquez sur « Les codes sont identiques » sur l'ordinateur pour finir l'appairage.")
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
