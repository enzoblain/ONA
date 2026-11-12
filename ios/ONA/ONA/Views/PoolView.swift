import SwiftUI

/// "Pool" tab: what this wallet holds in the pool, read from the computer: the total, then one line for the cash and
/// one per vault. Read only: deposits, placements, switches
/// and exits are prepared and confirmed on the computer (docs/desktop/pool-commands.md), never on the phone.
struct PoolView: View {
    let model: RemoteModel

    var body: some View {
        NavigationStack {
            content
                .navigationTitle("Pool")
                .safeAreaInset(edge: .top, spacing: 0) {
                    if model.isSimulation { SimulationBanner() }
                }
        }
        .task(id: model.pairing?.pairingID) { await model.refreshPool() }
    }

    @ViewBuilder
    private var content: some View {
        if !model.isPaired {
            ContentUnavailableView("Aucun ordinateur appairé", systemImage: "link.badge.plus",
                                   description: Text("Appairez un ordinateur depuis l'onglet Accueil pour voir vos parts dans le pool."))
        } else if let pool = model.pool {
            List {
                totalSection(pool)
                Section {
                    row("Cash", systemImage: "banknote", value: pool.cash.value, pending: pool.cash.spendingValue != "0")
                    ForEach(pool.vaults) { vault in
                        row("Vault \(vault.vault)", systemImage: vault.frozen ? "snowflake" : "building.columns",
                            value: vault.value, pending: vault.spendingValue != "0" || vault.awaitingSignature > 0)
                    }
                } footer: {
                    Text("Pour déposer, placer ou retirer : confirmez sur l'ordinateur.")
                }
            }
            .refreshable { await model.refreshPool() }
        } else if let error = model.poolError {
            ContentUnavailableView {
                Label("Pool indisponible", systemImage: "exclamationmark.triangle")
            } description: {
                Text(error)
            } actions: {
                Button("Réessayer") { Task { await model.refreshPool() } }
                    .buttonStyle(.bordered)
            }
        } else {
            ProgressView("Lecture du pool…")
        }
    }

    private func totalSection(_ pool: PoolPortfolio) -> some View {
        Section {
            VStack(alignment: .leading, spacing: 4) {
                Text("Valeur totale").font(.subheadline).foregroundStyle(.secondary)
                Text(Self.near(pool.total)).font(.largeTitle.bold()).monospacedDigit()
            }
            .padding(.vertical, 4)
        }
    }

    /// One line per holding, like an asset in a wallet. A small clock when part of it is moving.
    private func row(_ title: String, systemImage: String, value: String, pending: Bool) -> some View {
        HStack {
            Label(title, systemImage: systemImage)
            Spacer()
            if pending {
                Image(systemName: "clock").foregroundStyle(.secondary).accessibilityLabel("Opération en cours")
            }
            Text(Self.near(value)).monospacedDigit()
        }
    }

    static func near(_ yocto: String) -> String {
        NEARAmount.text(yocto).map { "\($0) NEAR" } ?? "montant illisible"
    }
}
