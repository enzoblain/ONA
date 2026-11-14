import AppKit
import SwiftUI

/// The pool (docs/desktop/pool-commands.md): the portfolio, and every operation as prepare, summary, confirm here,
/// execute. Pool operations are confirmed on this Mac only, never on the phone.
struct PoolSheet: View {
    let engine: ChatEngine
    let wallet: WalletPage
    @Environment(\.dismiss) private var dismiss
    @State private var screen: Screen = .loading
    @State private var message: String?
    @State private var busy = false
    /// `pool_privacy`, read with the portfolio; nil when the pool does not answer it.
    @State private var privacy: PoolPrivacy?

    enum Screen {
        case loading
        case unavailable(String)
        case portfolio(PoolPortfolio)
        case form(Draft)
        case summary(id: String, PoolSummary, prepared: NSDictionary)
        /// A deposit going on in the browser: the wallet page's address.
        case walletOpen(URL)
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
                Button("Close") { dismiss() }.keyboardShortcut(.cancelAction)
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
            Text("Pool operations are confirmed here, never on the phone.")
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
            Text("Reading the pool…").foregroundStyle(.secondary)
        case .unavailable(let error):
            VStack(alignment: .leading, spacing: 8) {
                Label("Pool unavailable: \(error)", systemImage: "exclamationmark.triangle").foregroundStyle(.red)
                Text("The pool is set up with pool.json in ~/Library/Application Support/ONA (see docs/desktop/app.md).")
                    .font(.callout).foregroundStyle(.secondary)
                Button("Try again") { Task { await load() } }
            }
        case .portfolio(let portfolio):
            portfolioView(portfolio)
        case .form(let form):
            formView(form)
        case .summary(let id, let summary, let prepared):
            summaryView(id: id, summary, prepared: prepared)
        case .walletOpen(let url):
            VStack(alignment: .leading, spacing: 10) {
                Text("Deposit in progress in your browser").font(.headline)
                Text("Your wallet page has opened. If it has not, open this address:")
                    .foregroundStyle(.secondary)
                Text(url.absoluteString).font(.caption.monospaced()).textSelection(.enabled)
                Text("Once the page is done, refresh: the notes appear when the pool agent has issued them.")
                    .font(.callout).foregroundStyle(.secondary)
                HStack {
                    Spacer()
                    Button("Refresh") { Task { await load() } }.buttonStyle(.borderedProminent)
                }
            }
        }
    }

    // MARK: - Portfolio

    private func portfolioView(_ portfolio: PoolPortfolio) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Total value").font(.callout).foregroundStyle(.secondary)
                Text(PoolSummary.near(portfolio.total)).font(.title.weight(.bold)).monospacedDigit()
            }
            if portfolio.mode == "mock" {
                Label("Simulation: fake pool (mock mode).", systemImage: "theatermasks").foregroundStyle(.orange)
            }
            if let privacy {
                VStack(alignment: .leading, spacing: 4) {
                    Label("Privacy", systemImage: "eye.slash").font(.headline)
                    Text(privacy.line)
                    Text(PoolPrivacy.caveat).font(.caption).foregroundStyle(.secondary)
                }
                .padding(10)
                .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 10))
            }
            VStack(spacing: 0) {
                holdingRow("Cash", portfolio.cash) { EmptyView() }
                ForEach(portfolio.vaults) { vault in
                    holdingRow("Vault \(vault.vault ?? 0)", vault) {
                        Button("Switch") { open(.switch, portfolio, vault: vault.vault) }
                        Button("Leave") { open(.exit, portfolio, vault: vault.vault) }
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
            if holding.frozen { Text("frozen").font(.caption).foregroundStyle(.orange) }
            if holding.pending {
                Image(systemName: "clock").foregroundStyle(.secondary).help("Operation in progress")
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
                Button("Put cash in a vault") { open(.enter, portfolio, nil) }.buttonStyle(.borderedProminent)
                Button("Pay out to an account") { open(.exitCash, portfolio, nil) }
                Button("Deposit") { open(.deposit, portfolio, nil) }
                Button("Recover") { recover() }
                    .help("Recover pending operations (pool_recover)")
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
                    ForEach(vaults, id: \.self) { Text("Vault \($0)\(privacy?.label(vault: $0) ?? "")").tag(Int?.some($0)) }
                }
                TextField("Cash to put in (in NEAR, or “all”)", text: binding.amount)
            case .switch:
                Picker("To vault", selection: binding.to) {
                    ForEach(vaults.filter { $0 != form.vault }, id: \.self) { Text("Vault \($0)").tag(Int?.some($0)) }
                }
                TextField("Shares of vault \(form.vault ?? 0) to move (in NEAR, or “all”)", text: binding.amount)
            case .exit:
                TextField("Shares of vault \(form.vault ?? 0) to take out as cash (in NEAR, or “all”)", text: binding.amount)
            case .exitCash:
                TextField("NEAR account that made the deposit (name.testnet)", text: binding.account)
                TextField("Cash to pay out (in NEAR)", text: binding.amount)
            case .deposit:
                TextField("Your NEAR account (name.testnet)", text: binding.account)
                TextField("Amount to deposit (in NEAR)", text: binding.amount)
            }
            HStack {
                Spacer()
                Button("Cancel") { Task { await load() } }
                Button("Prepare") { Task { await prepare(binding.wrappedValue) } }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .textFieldStyle(.roundedBorder)
    }

    // MARK: - Summary

    private func summaryView(id: String, _ summary: PoolSummary, prepared: NSDictionary) -> some View {
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
            Text("Network \(summary.network), contract \(summary.contract).\(expiry(summary))")
                .font(.callout).foregroundStyle(.secondary)
            if summary.op == "deposit" {
                // Sent and signed by the person's own NEAR wallet, on a page opened in the browser.
                Text("Your NEAR wallet sends this deposit, then signs a message for the pool agent. ONA never sees its keys.")
                    .font(.callout).foregroundStyle(.secondary)
                HStack {
                    Spacer()
                    Button("Cancel") { Task { await load() } }
                    Button("Open my wallet") { Task { await openWallet(prepared) } }
                        .buttonStyle(.borderedProminent)
                }
            } else {
                HStack {
                    Spacer()
                    Button("Cancel") { Task { await load() } }
                    Button("Confirm") { Task { await execute(id) } }
                        .buttonStyle(.borderedProminent)
                }
            }
        }
    }

    private func expiry(_ summary: PoolSummary) -> String {
        guard let date = summary.expiresAt else { return "" }
        return " Valid until \(date.formatted(date: .omitted, time: .standard))."
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
            privacy = PoolPrivacy(await run(["cmd": "pool_privacy"]))
            screen = .portfolio(portfolio)
        } else {
            screen = .unavailable(reply["error"] as? String ?? "unreadable reply")
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
            message = "Preparation refused: \(reply["error"] as? String ?? "unreadable reply")"
            return
        }
        message = nil
        screen = .summary(id: id, PoolSummary(summary), prepared: reply as NSDictionary)
    }

    private func execute(_ id: String) async {
        let reply = await run(["cmd": "pool_execute", "prepared_id": id])
        message = PoolOutcome.execute(reply)
        await load()
    }

    private func openWallet(_ prepared: NSDictionary) async {
        do {
            let url = try await wallet.open(prepared: prepared as? [String: Any] ?? [:])
            NSWorkspace.shared.open(url)
            screen = .walletOpen(url)
        } catch {
            message = error.localizedDescription
        }
    }

    private func recover() async {
        let reply = await run(["cmd": "pool_recover"])
        message = PoolOutcome.recover(reply)
        await load()
    }
}
