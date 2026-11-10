import SwiftUI

/// What the Tor tab shows, refreshed while the tab is on screen.
@MainActor
@Observable
final class TorModel {
    enum State: Equatable {
        case stopped
        case starting(Double)
        case ready
        case failed(message: String, detail: String)
    }

    private(set) var state: State = .stopped
    private(set) var dataSize: Int64 = 0
    private(set) var busy = false
    let artiVersion: String?

    private let tor: ArtiTor
    private var watch: Task<Void, Never>?

    init(tor: ArtiTor = .shared) {
        self.tor = tor
        artiVersion = tor.artiVersion
    }

    func startWatching() {
        guard watch == nil else { return }
        watch = Task { [weak self] in
            while !Task.isCancelled {
                self?.refresh()
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    func stopWatching() {
        watch?.cancel()
        watch = nil
    }

    func start() async {
        busy = true
        defer { busy = false }
        state = .starting(0)
        do {
            try await tor.ready()
            state = .ready
        } catch let error as TorError {
            state = .failed(message: error.localizedDescription, detail: error.detail)
        } catch {
            state = .failed(message: "Tor n'a pas pu démarrer.", detail: String(describing: error))
        }
        refresh()
    }

    func stop() async {
        busy = true
        defer { busy = false }
        await tor.stop()
        state = .stopped
        refresh()
    }

    func eraseData() {
        guard state == .stopped || isFailed else { return }
        try? ArtiTor.eraseData()
        refresh()
    }

    var isFailed: Bool {
        if case .failed = state { true } else { false }
    }

    private func refresh() {
        dataSize = ArtiTor.dataSize()
        if let status = tor.status() {
            state = status.ready ? .ready : .starting(status.progress)
        } else if case .failed = state {
            // keep the error on screen
        } else if !busy {
            state = .stopped
        }
    }
}

/// "Tor" tab: whether Tor is running, whether the paired computer is reached through it, and Tor's own settings.
struct TorView: View {
    let model: RemoteModel
    @State private var tor = TorModel()
    @State private var confirmingErase = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    statusRow
                    actionButton
                } footer: {
                    Text(usageText)
                }

                if case .failed(_, let detail) = tor.state {
                    Section {
                        DisclosureGroup("Détails") {
                            Text(detail)
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                                .textSelection(.enabled)
                        }
                    }
                }

                Section {
                    LabeledContent("Données Tor sur ce téléphone",
                                   value: tor.dataSize.formatted(.byteCount(style: .file)))
                    Button("Effacer les données Tor", role: .destructive) { confirmingErase = true }
                        .disabled(tor.dataSize == 0 || !(tor.state == .stopped || tor.isFailed))
                } header: {
                    Text("Réglages Tor")
                } footer: {
                    Text("Ces données (l'annuaire du réseau Tor) accélèrent le démarrage. Après effacement, le prochain démarrage sera plus long. Arrêtez Tor pour pouvoir les effacer.")
                }

                if let version = tor.artiVersion {
                    Section {
                        LabeledContent("Moteur", value: "Arti \(version)")
                    } footer: {
                        Text("Arti est l'implémentation de Tor du Tor Project, intégrée à l'app.")
                    }
                }
            }
            .navigationTitle("Tor")
            .onAppear { tor.startWatching() }
            .onDisappear { tor.stopWatching() }
            .confirmationDialog("Effacer les données Tor ?", isPresented: $confirmingErase, titleVisibility: .visible) {
                Button("Effacer", role: .destructive) { tor.eraseData() }
            }
        }
    }

    @ViewBuilder
    private var statusRow: some View {
        switch tor.state {
        case .stopped:
            Label("Arrêté", systemImage: "pause.circle")
                .foregroundStyle(.secondary)
        case .starting(let progress):
            VStack(alignment: .leading, spacing: 8) {
                Label("Démarrage…", systemImage: "arrow.triangle.2.circlepath")
                ProgressView(value: progress)
            }
        case .ready:
            Label("Connecté au réseau Tor", systemImage: "checkmark.shield.fill")
                .foregroundStyle(.green)
        case .failed(let message, _):
            Label(message, systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
        }
    }

    @ViewBuilder
    private var actionButton: some View {
        switch tor.state {
        case .stopped, .failed:
            Button("Démarrer Tor") { Task { await tor.start() } }
                .disabled(tor.busy)
        case .starting, .ready:
            Button("Arrêter Tor", role: .destructive) { Task { await tor.stop() } }
                .disabled(tor.busy)
        }
    }

    private var usageText: String {
        guard model.isPaired else {
            return "Tor démarre tout seul quand l'ordinateur appairé est joint par une adresse .onion."
        }
        return model.usesTor
            ? "Votre ordinateur est joint par Tor. Tor démarre tout seul à l'ouverture de l'app."
            : "Votre ordinateur est joint sur le réseau local, sans Tor."
    }
}
