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
                    ToolbarItem(placement: .topBarTrailing) {
                        Button {
                            showingSettings = true
                        } label: {
                            Label("Ordinateur", systemImage: "desktopcomputer")
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
        .alert("Action refusée", isPresented: .constant(model.actionError != nil && openConfirmation == nil)) {
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
        if let mission = model.mission {
            MissionView(model: model, mission: mission) { openConfirmation = $0 }
        } else {
            noMission
        }
    }

    private var noMission: some View {
        List {
            Section {
                ConnectionStatusRow(connection: model.connection, computer: model.state?.computer.name)
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

struct ConnectionView: View {
    @Bindable var model: RemoteModel
    @Environment(\.dismiss) private var dismiss
    @State private var draft = ""

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("http://adresse:8790", text: $draft)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                        .font(.body.monospaced())
                } header: {
                    Text("Adresse de l'ordinateur")
                } footer: {
                    Text("Étape 2 : serveur simulé sur le réseau local. L'adresse n'est pas enregistrée ; l'appairage par QR viendra ensuite.")
                }
                Section {
                    ConnectionStatusRow(connection: model.connection, computer: model.state?.computer.name)
                }
                if model.isSimulation {
                    Section("Simulation") {
                        Button("Nouvelle mission simulée") { Task { await model.mock(.start) } }
                        Button("Effacer la mission simulée", role: .destructive) { Task { await model.mock(.reset) } }
                    }
                }
            }
            .navigationTitle("Ordinateur")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("OK") {
                        model.address = draft
                        Task { await model.refresh() }
                        dismiss()
                    }
                }
                ToolbarItem(placement: .cancellationAction) {
                    Button("Annuler") { dismiss() }
                }
            }
            .onAppear { draft = model.address }
        }
    }
}
