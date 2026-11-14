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
            state = .failed(message: "Tor could not start.", detail: String(describing: error))
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
                        DisclosureGroup("Details") {
                            Text(detail)
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                                .textSelection(.enabled)
                        }
                    }
                }

                Section {
                    LabeledContent("Tor data on this phone",
                                   value: tor.dataSize.formatted(.byteCount(style: .file)))
                    Button("Erase Tor data", role: .destructive) { confirmingErase = true }
                        .disabled(tor.dataSize == 0 || !(tor.state == .stopped || tor.isFailed))
                } header: {
                    Text("Tor settings")
                } footer: {
                    Text("This data (the Tor network directory) speeds up startup. After erasing it, the next startup takes longer. Stop Tor to erase it.")
                }

                if let version = tor.artiVersion {
                    Section {
                        LabeledContent("Engine", value: "Arti \(version)")
                    } footer: {
                        Text("Arti is the Tor Project's implementation of Tor, built into the app.")
                    }
                }
            }
            .navigationTitle("Tor")
            .onAppear { tor.startWatching() }
            .onDisappear { tor.stopWatching() }
            .confirmationDialog("Erase Tor data?", isPresented: $confirmingErase, titleVisibility: .visible) {
                Button("Erase", role: .destructive) { tor.eraseData() }
            }
        }
    }

    @ViewBuilder
    private var statusRow: some View {
        switch tor.state {
        case .stopped:
            Label("Stopped", systemImage: "pause.circle")
                .foregroundStyle(.secondary)
        case .starting(let progress):
            VStack(alignment: .leading, spacing: 8) {
                Label("Starting…", systemImage: "arrow.triangle.2.circlepath")
                ProgressView(value: progress)
            }
        case .ready:
            Label("Connected to the Tor network", systemImage: "checkmark.shield.fill")
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
            Button("Start Tor") { Task { await tor.start() } }
                .disabled(tor.busy)
        case .starting, .ready:
            Button("Stop Tor", role: .destructive) { Task { await tor.stop() } }
                .disabled(tor.busy)
        }
    }

    private var usageText: String {
        guard model.isPaired else {
            return "Tor starts on its own when the paired computer is reached through a .onion address."
        }
        return model.usesTor
            ? "Your computer is reached over Tor. Tor starts on its own when the app opens."
            : "Your computer is reached on the local network, without Tor."
    }
}
