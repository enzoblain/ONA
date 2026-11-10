import SwiftUI

struct SpikeView: View {
    @Bindable var model: SpikeModel

    var body: some View {
        NavigationStack {
            Form {
                targetSection
                torSection
                stabilitySection
                journalSection
            }
            .navigationTitle("Spike Tor")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    ShareLink(item: model.report) {
                        Label("Exporter le journal", systemImage: "square.and.arrow.up")
                    }
                }
            }
        }
    }

    private var targetSection: some View {
        Section {
            TextField("adresse.onion", text: $model.host, axis: .vertical)
                .font(.footnote.monospaced())
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .keyboardType(.URL)
            HStack {
                TextField("Port", text: $model.port)
                    .keyboardType(.numberPad)
                    .frame(maxWidth: 80)
                TextField("Chemin", text: $model.path)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
            }
            .font(.footnote.monospaced())
        } header: {
            Text("Cible")
        } footer: {
            Text("Serveur de test .onion hébergé sur le Mac. Aucune donnée ONA ne transite.")
        }
    }

    private var torSection: some View {
        Section {
            LabeledContent("Réseau", value: model.network)
            switch model.phase {
            case .stopped:
                Toggle("Démarrage à froid (effacer le cache)", isOn: $model.coldStart)
                Button("Démarrer Tor") { Task { await model.startTor() } }
                Button("Effacer le cache Arti", role: .destructive) { model.eraseCache() }
            case .bootstrapping:
                ProgressView(value: model.progress) {
                    Text("Démarrage… \(Int(model.progress * 100)) %")
                } currentValueLabel: {
                    Text(model.progressText).font(.caption2)
                }
            case .ready:
                Label("Tor prêt", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                Button {
                    Task { await model.request() }
                } label: {
                    HStack {
                        Text("Requête vers le .onion")
                        if model.requestInFlight {
                            Spacer()
                            ProgressView()
                        }
                    }
                }
                .disabled(model.requestInFlight)
                Button("Arrêter Tor", role: .destructive) { Task { await model.stopTor() } }
            }
        } header: {
            Text("Tor (Arti embarqué)")
        } footer: {
            Text(model.versions)
        }
    }

    private var stabilitySection: some View {
        Section {
            Toggle("Sonde toutes les 30 s", isOn: $model.probeEvery30s)
                .disabled(model.phase != .ready)
            Toggle("Requête au retour au premier plan", isOn: $model.probeOnForeground)
        } header: {
            Text("Stabilité")
        } footer: {
            Text("Passer du Wi-Fi au cellulaire ou mettre l'app en arrière-plan, puis lire le journal.")
        }
    }

    private var journalSection: some View {
        Section {
            if model.journal.isEmpty {
                Text("Vide").foregroundStyle(.secondary)
            }
            ForEach(model.journal.reversed()) { entry in
                Text(entry.line)
                    .font(.caption.monospaced())
                    .foregroundStyle(color(for: entry.kind))
                    .textSelection(.enabled)
            }
        } header: {
            HStack {
                Text("Journal (en mémoire)")
                Spacer()
                Button("Vider") { model.clearJournal() }
                    .font(.caption)
            }
        }
    }

    private func color(for kind: SpikeModel.Entry.Kind) -> Color {
        switch kind {
        case .info: .secondary
        case .measure: .primary
        case .error: .red
        }
    }
}
