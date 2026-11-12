import SwiftUI

/// The pool (docs/desktop/pool-commands.md): the portfolio, and every operation as prepare, summary, confirm here,
/// execute. Pool operations are confirmed on this Mac only, never on the phone.
struct PoolSheet: View {
    let engine: ChatEngine
    @Environment(\.dismiss) private var dismiss
    @State private var screen: Screen = .loading
    @State private var message: String?
    @State private var busy = false

    enum Screen {
        case loading
        case unavailable(String)
        case portfolio(PoolPortfolio)
        case form(Draft)
        case summary(id: String, PoolSummary)
    }

    /// An operation being filled in: `vault` is the vault it starts from (switch, exit) or goes to (enter).
    struct Draft {
        let op: PoolOperation
        let portfolio: PoolPortfolio
        var vault: Int?
        var to: Int?
        var amount = ""
        var account = ""
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("Pool").font(.title2.weight(.semibold))
                Spacer()
                if busy { ProgressView().controlSize(.small) }
                Button("Fermer") { dismiss() }.keyboardShortcut(.cancelAction)
            }
            if let message {
                Text(message)
                    .font(.callout)
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(.quaternary, in: .rect(cornerRadius: 10))
                    .textSelection(.enabled)
            }
            ScrollView {
                content.frame(maxWidth: .infinity, alignment: .leading)
            }
            .disabled(busy)
            Text("Les opérations du pool se confirment ici, jamais sur le téléphone.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .padding(24)
        .frame(width: 560, height: 560)
        .task { await load() }
    }

    @ViewBuilder
    private var content: some View {
        switch screen {
        case .loading:
            Text("Lecture du pool…").foregroundStyle(.secondary)
        case .unavailable(let error):
            VStack(alignment: .leading, spacing: 8) {
                Label("Pool indisponible : \(error)", systemImage: "exclamationmark.triangle").foregroundStyle(.red)
                Text("Le pool se configure avec pool.json dans ~/Library/Application Support/ONA (voir docs/desktop/app.md).")
                    .font(.callout).foregroundStyle(.secondary)
                Button("Réessayer") { Task { await load() } }
            }
        case .portfolio(let portfolio):
            portfolioView(portfolio)
        case .form(let form):
            formView(form)
        case .summary(let id, let summary):
            summaryView(id: id, summary)
        }
    }

    // MARK: - Portfolio

    private func portfolioView(_ portfolio: PoolPortfolio) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Valeur totale").font(.callout).foregroundStyle(.secondary)
                Text(PoolSummary.near(portfolio.total)).font(.title.weight(.bold)).monospacedDigit()
            }
            if portfolio.mode == "mock" {
                Label("Simulation : pool fictif (mode mock).", systemImage: "theatermasks").foregroundStyle(.orange)
            }
            VStack(spacing: 0) {
                holdingRow("Cash", portfolio.cash) { EmptyView() }
                ForEach(portfolio.vaults) { vault in
                    holdingRow("Vault \(vault.vault ?? 0)", vault) {
                        Button("Changer") { open(.switch, portfolio, vault: vault.vault) }
                        Button("Sortir") { open(.exit, portfolio, vault: vault.vault) }
                    }
                }
            }
            FlowButtons(portfolio: portfolio, open: open, recover: { Task { await recover() } })
        }
    }

    private func holdingRow(_ name: String, _ holding: PoolPortfolio.Holding,
                            @ViewBuilder buttons: () -> some View) -> some View {
        HStack(spacing: 10) {
            Text(name)
            if holding.frozen { Text("gelé").font(.caption).foregroundStyle(.orange) }
            if holding.pending {
                Image(systemName: "clock").foregroundStyle(.secondary).help("Opération en cours")
            }
            Spacer()
            Text(PoolSummary.near(holding.value)).monospacedDigit()
            buttons().controlSize(.small)
        }
        .padding(.vertical, 8)
        .overlay(alignment: .bottom) { Divider() }
    }

    private struct FlowButtons: View {
        let portfolio: PoolPortfolio
        let open: (PoolOperation, PoolPortfolio, Int?) -> Void
        let recover: () -> Void

        var body: some View {
            HStack {
                Button("Placer du cash") { open(.enter, portfolio, nil) }.buttonStyle(.borderedProminent)
                Button("Payer vers un compte") { open(.exitCash, portfolio, nil) }
                Button("Déposer") { open(.deposit, portfolio, nil) }
                Button("Récupérer") { recover() }
                    .help("Récupérer les opérations en attente (pool_recover)")
            }
        }
    }

    private func open(_ op: PoolOperation, _ portfolio: PoolPortfolio, vault: Int?) {
        var form = Draft(op: op, portfolio: portfolio, vault: vault)
        if op == .enter { form.vault = 0 }
        if op == .switch { form.to = (0..<portfolio.vaultCount).first { $0 != vault } }
        message = nil
        screen = .form(form)
    }

    // MARK: - Form

    private func formView(_ form: Draft) -> some View {
        let binding = Binding<Draft>(
            get: { if case .form(let current) = screen { current } else { form } },
            set: { screen = .form($0) })
        let vaults = Array(0..<form.portfolio.vaultCount)
        return VStack(alignment: .leading, spacing: 12) {
            Text(form.op.title).font(.headline)
            switch form.op {
            case .enter:
                Picker("Vault", selection: binding.vault) {
                    ForEach(vaults, id: \.self) { Text("Vault \($0)").tag(Int?.some($0)) }
                }
                TextField("Cash à placer (en NEAR, ou « tout »)", text: binding.amount)
            case .switch:
                Picker("Vers le vault", selection: binding.to) {
                    ForEach(vaults.filter { $0 != form.vault }, id: \.self) { Text("Vault \($0)").tag(Int?.some($0)) }
                }
                TextField("Parts du vault \(form.vault ?? 0) à déplacer (en NEAR, ou « tout »)", text: binding.amount)
            case .exit:
                TextField("Parts du vault \(form.vault ?? 0) à sortir en cash (en NEAR, ou « tout »)", text: binding.amount)
            case .exitCash:
                TextField("Compte NEAR qui a déposé (nom.testnet)", text: binding.account)
                TextField("Cash à payer (en NEAR)", text: binding.amount)
            case .deposit:
                TextField("Votre compte NEAR (nom.testnet)", text: binding.account)
                TextField("Montant à déposer (en NEAR)", text: binding.amount)
            }
            HStack {
                Spacer()
                Button("Annuler") { Task { await load() } }
                Button("Préparer") { Task { await prepare(binding.wrappedValue) } }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .textFieldStyle(.roundedBorder)
    }

    // MARK: - Summary

    private func summaryView(id: String, _ summary: PoolSummary) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(summary.title).font(.headline)
            Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 6) {
                ForEach(summary.rows) { row in
                    GridRow {
                        Text(row.label).foregroundStyle(.secondary)
                        Text(row.value).monospacedDigit().textSelection(.enabled)
                    }
                }
            }
            ForEach(summary.warnings, id: \.self) { warning in
                Label(warning, systemImage: "exclamationmark.triangle").foregroundStyle(.orange)
            }
            Text("Réseau \(summary.network), contrat \(summary.contract).\(expiry(summary))")
                .font(.callout).foregroundStyle(.secondary)
            if summary.op == "deposit" {
                // Sent and signed by the person's own NEAR wallet: no wallet is connected to this app yet.
                Label("Le dépôt s'envoie avec votre propre portefeuille NEAR, puis ce portefeuille signe un message. La connexion d'un portefeuille à l'app n'existe pas encore : ce dépôt ne peut pas être fait ici.",
                      systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
                if let call = summary.walletCall {
                    Text("Appel à envoyer").foregroundStyle(.secondary)
                    Text(call).font(.caption.monospaced()).textSelection(.enabled)
                }
                HStack {
                    Spacer()
                    Button("Retour") { Task { await load() } }
                }
            } else {
                HStack {
                    Spacer()
                    Button("Annuler") { Task { await load() } }
                    Button("Confirmer") { Task { await execute(id) } }
                        .buttonStyle(.borderedProminent)
                }
            }
        }
    }

    private func expiry(_ summary: PoolSummary) -> String {
        guard let date = summary.expiresAt else { return "" }
        return " Valable jusqu'à \(date.formatted(date: .omitted, time: .standard))."
    }

    // MARK: - Commands

    private func run(_ request: [String: Any]) async -> [String: Any] {
        busy = true
        defer { busy = false }
        return await engine.pool(request)
    }

    private func load() async {
        if case .portfolio = screen {} else { screen = .loading }
        let reply = await run(["cmd": "pool_portfolio"])
        if reply["ok"] as? Bool == true, let portfolio = PoolPortfolio(reply) {
            screen = .portfolio(portfolio)
        } else {
            screen = .unavailable(reply["error"] as? String ?? "réponse illisible")
        }
    }

    private func prepare(_ form: Draft) async {
        let request: [String: Any]
        switch PoolRequest.prepare(form.op, amount: form.amount, vault: form.vault, to: form.to, account: form.account) {
        case .success(let made): request = made
        case .failure(let error): message = error.text; return
        }
        let reply = await run(request)
        guard reply["ok"] as? Bool == true, let id = reply["prepared_id"] as? String,
              let summary = reply["summary"] as? [String: Any]
        else {
            message = "Préparation refusée : \(reply["error"] as? String ?? "réponse illisible")"
            return
        }
        message = nil
        screen = .summary(id: id, PoolSummary(summary))
    }

    private func execute(_ id: String) async {
        let reply = await run(["cmd": "pool_execute", "prepared_id": id])
        message = PoolOutcome.execute(reply)
        await load()
    }

    private func recover() async {
        let reply = await run(["cmd": "pool_recover"])
        message = PoolOutcome.recover(reply)
        await load()
    }
}
