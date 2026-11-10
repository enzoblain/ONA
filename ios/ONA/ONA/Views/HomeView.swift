import SwiftUI

/// "Accueil" tab: pairing when there is no computer yet, then the mission and its confirmations.
struct HomeView: View {
    @Bindable var model: RemoteModel
    @State private var openConfirmation: Pending?

    var body: some View {
        NavigationStack {
            content
                .navigationTitle("ONA")
                .refreshable { await model.refresh() }
                .safeAreaInset(edge: .top, spacing: 0) {
                    if model.isSimulation { SimulationBanner() }
                }
        }
        .sheet(item: $openConfirmation) { pending in
            ConfirmationView(model: model, pending: pending)
        }
        .alert("Action impossible", isPresented: .constant(model.actionError != nil && openConfirmation == nil)) {
            Button("OK") { model.clearActionError() }
        } message: {
            Text(model.actionError ?? "")
        }
        // A confirmation that is no longer pending (answered, or replaced) closes its sheet.
        .onChange(of: model.pending) { _, new in
            if let open = openConfirmation, open.id != new?.id { openConfirmation = nil }
        }
    }

    @ViewBuilder
    private var content: some View {
        if !model.isPaired {
            PairingView(model: model)
        } else if let mission = model.mission {
            MissionView(model: model, mission: mission) { openConfirmation = $0 }
        } else {
            noMission
        }
    }

    private var noMission: some View {
        List {
            Section {
                ConnectionStatusRow(connection: model.connection, computer: model.pairing?.name, viaTor: model.usesTor)
            }
            Section {
                ContentUnavailableView(
                    "Aucune mission en cours",
                    systemImage: "tray",
                    description: Text("Lancez une mission sur l'ordinateur. Vous suivrez ici son avancement et confirmerez les choix importants.")
                )
            }
            if model.isSimulation {
                Section {
                    Button("Démarrer une simulation") { Task { await model.mock(.start) } }
                }
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
        case .failed(let message):
            Label {
                Text(message)
            } icon: {
                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
            }
        }
    }
}
