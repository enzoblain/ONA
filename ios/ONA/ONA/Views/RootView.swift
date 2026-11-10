import SwiftUI

struct RootView: View {
    @Bindable var model: RemoteModel
    @State private var showingSettings = false
    @State private var openConfirmation: Pending?

    var body: some View {
        NavigationStack {
            content
                .navigationTitle("ONA")
                .toolbar {
                    if model.isPaired {
                        ToolbarItem(placement: .topBarTrailing) {
                            Button {
                                showingSettings = true
                            } label: {
                                Label("Ordinateur", systemImage: "desktopcomputer")
                            }
                        }
                    }
                }
                .refreshable { await model.refresh() }
                .safeAreaInset(edge: .top, spacing: 0) {
                    if model.isSimulation { SimulationBanner() }
                }
        }
        .sheet(isPresented: $showingSettings) {
            ConnectionView(model: model)
        }
        .sheet(item: $openConfirmation) { pending in
            ConfirmationView(model: model, pending: pending)
        }
        .fullScreenCover(isPresented: .constant(model.verification != nil)) {
            if let verification = model.verification {
                VerificationView(model: model, verification: verification)
            }
        }
        .alert("Action refusée", isPresented: .constant(model.actionError != nil && openConfirmation == nil)) {
            Button("OK") { model.clearActionError() }
        } message: {
            Text(model.actionError ?? "")
        }
        // A confirmation that is no longer pending (answered, or replaced) closes its sheet.
        .onChange(of: model.pending) { _, new in
            if let open = openConfirmation, open.id != new?.id { openConfirmation = nil }
        }
        .onChange(of: model.isPaired) { _, paired in
            if paired { model.startPolling() }
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
                ConnectionStatusRow(connection: model.connection, computer: model.pairing?.name)
            }
            Section {
                ContentUnavailableView(
                    "Aucune mission",
                    systemImage: "tray",
                    description: Text("Les missions se lancent sur l'ordinateur. Ce téléphone suit leur avancement et confirme les choix sensibles.")
                )
            }
            if model.isSimulation {
                Section("Simulation") {
                    Button("Démarrer une mission simulée") { Task { await model.mock(.start) } }
                }
            }
        }
    }
}

struct ConnectionStatusRow: View {
    let connection: RemoteModel.Connection
    let computer: String?

    var body: some View {
        switch connection {
        case .notPaired:
            Label("Aucun ordinateur appairé", systemImage: "link.badge.plus")
                .foregroundStyle(.secondary)
        case .idle, .connecting:
            Label("Connexion à l'ordinateur…", systemImage: "antenna.radiowaves.left.and.right")
                .foregroundStyle(.secondary)
        case .connected(let date):
            Label {
                Text("\(computer ?? "Ordinateur") — à jour \(date.formatted(date: .omitted, time: .standard))")
            } icon: {
                Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
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

/// The paired computer, and the way to forget it.
struct ConnectionView: View {
    let model: RemoteModel
    @Environment(\.dismiss) private var dismiss
    @State private var confirmingUnpair = false

    var body: some View {
        NavigationStack {
            Form {
                if let pairing = model.pairing {
                    Section {
                        LabeledContent("Nom", value: pairing.name)
                        if let address = pairing.address {
                            LabeledContent("Adresse") { Text(address.absoluteString).font(.callout.monospaced()) }
                        }
                        LabeledContent("Appairé le", value: pairing.pairedAt.formatted(date: .abbreviated, time: .shortened))
                        LabeledContent("Clé de ce téléphone") {
                            switch pairing.keyKind {
                            case .secureEnclave: Text("Secure Enclave")
                            case .software: Text("Logicielle (simulateur)").foregroundStyle(.orange)
                            }
                        }
                    } header: {
                        Text("Ordinateur appairé")
                    } footer: {
                        Text("Seul cet appairage est gardé sur le téléphone, dans le Trousseau (cet appareil seulement).")
                    }
                    Section {
                        ConnectionStatusRow(connection: model.connection, computer: pairing.name)
                    }
                }
                if model.isSimulation {
                    Section("Simulation") {
                        Button("Nouvelle mission simulée") { Task { await model.mock(.start) } }
                        Button("Effacer la mission simulée", role: .destructive) { Task { await model.mock(.reset) } }
                    }
                }
                Section {
                    Button("Oublier cet ordinateur", role: .destructive) { confirmingUnpair = true }
                }
            }
            .navigationTitle("Ordinateur")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("OK") { dismiss() }
                }
            }
            .confirmationDialog("Oublier cet ordinateur ?", isPresented: $confirmingUnpair, titleVisibility: .visible) {
                Button("Oublier", role: .destructive) {
                    model.unpair()
                    dismiss()
                }
            } message: {
                Text("La clé de ce téléphone sera effacée. Il faudra rescanner le code de l'ordinateur.")
            }
        }
    }
}
