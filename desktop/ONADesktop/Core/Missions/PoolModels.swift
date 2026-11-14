import Foundation

/// What the pool window shows and sends (docs/desktop/pool-commands.md), read from ona-core's replies. The texts are
/// those of the Tauri window (desktop/tauri/ui/app.js).
public enum PoolOperation: String, CaseIterable, Sendable {
    case enter, `switch`, exit, exitCash = "exit_cash", deposit

    public var title: String {
        switch self {
        case .enter: "Put cash into a vault"
        case .switch: "Switch vaults"
        case .exit: "Leave a vault (to cash)"
        case .exitCash: "Pay cash out to an account"
        case .deposit: "Deposit from a NEAR wallet"
        }
    }

    /// Whether the amount may be "all" (every note): only shares or cash already held.
    public var allowsAll: Bool { self == .enter || self == .switch || self == .exit }
}

/// `pool_portfolio`'s reply.
public struct PoolPortfolio: Equatable, Sendable {
    public struct Holding: Equatable, Sendable, Identifiable {
        /// Nil for the cash.
        public let vault: Int?
        /// yoctoNEAR.
        public let value: String
        public let frozen: Bool
        /// Notes signed for an operation whose outcome is not known yet, or new notes waiting for their signature.
        public let pending: Bool
        public var id: Int { vault ?? -1 }
    }

    public let mode: String
    /// yoctoNEAR, held notes only.
    public let total: String
    public let cash: Holding
    public let vaults: [Holding]
    public let vaultCount: Int

    public init?(_ reply: [String: Any]) {
        guard let total = reply["total"] as? String, let cash = reply["cash"] as? [String: Any],
              let cashHolding = Self.holding(cash, vault: nil)
        else { return nil }
        self.total = total
        self.cash = cashHolding
        mode = reply["mode"] as? String ?? "mock"
        vaults = (reply["vaults"] as? [[String: Any]] ?? []).compactMap { v in
            (v["vault"] as? Int).flatMap { Self.holding(v, vault: $0) }
        }
        vaultCount = reply["vault_count"] as? Int ?? vaults.count
    }

    private static func holding(_ json: [String: Any], vault: Int?) -> Holding? {
        guard let value = json["value"] as? String else { return nil }
        let spending = json["spending_value"] as? String ?? "0"
        let awaiting = json["awaiting_signature"] as? Int ?? 0
        return Holding(vault: vault, value: value, frozen: json["frozen"] as? Bool ?? false,
                       pending: spending != "0" || awaiting > 0)
    }
}

/// The `pool_prepare` request of one operation, from the window's form.
public enum PoolRequest {
    /// `amount` is what the person typed: NEAR ("1.5" or "1,5"), or "all" where the operation allows it.
    public static func prepare(_ op: PoolOperation, amount: String, vault: Int? = nil, to: Int? = nil,
                               account: String? = nil) -> Result<[String: Any], ProtocolErrorText> {
        var request: [String: Any] = ["cmd": "pool_prepare", "op": op.rawValue]
        let typed = amount.trimmingCharacters(in: .whitespaces).lowercased()
        if op.allowsAll, typed == "all" {
            request["amount"] = "all"
        } else if let yocto = NEARAmount.yocto(fromNEAR: amount), yocto != "0" {
            request["amount"] = yocto
        } else {
            return .failure("Unreadable amount: write for example 1.5")
        }
        let account = account?.trimmingCharacters(in: .whitespaces) ?? ""
        switch op {
        case .enter:
            guard let vault else { return .failure("Choose a vault") }
            request["vault"] = vault
        case .switch:
            guard let vault, let to else { return .failure("Choose a vault") }
            request["from"] = vault
            request["to"] = to
        case .exit:
            guard let vault else { return .failure("Choose a vault") }
            request["from"] = vault
        case .exitCash:
            guard !account.isEmpty else { return .failure("Enter the NEAR account") }
            request["to"] = account
        case .deposit:
            guard !account.isEmpty else { return .failure("Enter your NEAR account") }
            request["account"] = account
        }
        return .success(request)
    }
}

/// `pool_prepare`'s summary, as lines to read before confirming. The share price is not shown.
public struct PoolSummary: Sendable {
    public struct Row: Equatable, Sendable, Identifiable {
        public let label: String
        public let value: String
        public var id: String { label }
    }

    public let op: String
    public let title: String
    public let rows: [Row]
    public let warnings: [String]
    public let network: String
    public let contract: String
    public let expiresAt: Date?
    /// For a deposit: the call to send from the person's own NEAR wallet, as JSON text.
    public let walletCall: String?

    static let labels: [(key: String, label: String, amount: Bool)] = [
        ("amount", "Amount", true), ("account", "Account", false), ("vault", "Vault", false),
        ("from", "From vault", false), ("to", "To", false), ("shares_value", "Shares received (value)", true),
        ("new_shares_value", "New shares (value)", true), ("cash_value", "Cash received", true),
        ("received", "Received", true), ("left_in_cash", "Left in the pool's cash (lost)", true),
        ("exit_limit", "Account exit limit", true),
    ]

    public init(_ summary: [String: Any]) {
        op = summary["op"] as? String ?? "?"
        title = PoolOperation(rawValue: op)?.title ?? op
        var rows: [Row] = Self.labels.compactMap { key, label, amount in
            guard let value = summary[key], !(value is NSNull) else { return nil }
            let text = "\(value)"
            return Row(label: label, value: amount ? Self.near(text) : text)
        }
        let fees = summary["fees"] as? [String: Any] ?? [:]
        rows += fees.keys.sorted().map { key in Row(label: "Fees: \(key)", value: Self.near("\(fees[key] ?? "")")) }
        self.rows = rows
        let listed = (summary["warnings"] as? [Any] ?? []).map { "\($0)" }
        warnings = [summary["warning"] as? String].compactMap { $0 } + listed
        network = summary["network"] as? String ?? "?"
        contract = summary["contract"] as? String ?? "?"
        // Nanoseconds; only shown, so a Double is enough here.
        expiresAt = (summary["expires_at"] as? NSNumber).map { Date(timeIntervalSince1970: $0.doubleValue / 1e9) }
        walletCall = (summary["wallet_call"] as? [String: Any]).flatMap {
            try? JSONSerialization.data(withJSONObject: $0, options: [.sortedKeys, .withoutEscapingSlashes])
        }.map { String(decoding: $0, as: UTF8.self) }
    }

    /// "1.5 NEAR" for a yoctoNEAR string, the text itself otherwise ("unused margin").
    public static func near(_ yocto: String) -> String {
        NEARAmount.text(yocto).map { "\($0) NEAR" } ?? yocto
    }
}

/// What the window says after `pool_execute`.
public enum PoolOutcome {
    public static func execute(_ reply: [String: Any]) -> String {
        let error = reply["error"] as? String
        if reply["ok"] as? Bool == true {
            if reply["complete"] as? Bool == true { return "Operation done." }
            return "Operation partly done" + (error.map { ": \($0)" } ?? ".")
        }
        // Entries, exits and cash payments are queued by the pool agent: their outcome comes through pool_recover.
        if let error, error.contains("outcome unknown") {
            return "Sent to the pool agent: the result will come later (Recover)."
        }
        return "Operation refused: \(error ?? "pool error")"
    }

    public static func recover(_ reply: [String: Any]) -> String {
        guard reply["ok"] as? Bool == true else {
            return "Could not recover: \(reply["error"] as? String ?? "pool error")"
        }
        let count = { (key: String) in reply[key] as? Int ?? 0 }
        let agent = (reply["agent_error"] as? String).map { " (agent: \($0))" } ?? ""
        return "Recovery: \(count("spent")) done, \(count("held_again")) returned, \(count("still_spending")) pending\(agent)."
    }
}

/// The privacy figures of `pool_privacy` (docs/desktop/privacy.md): measured upper bounds, never percentages.
public struct PoolPrivacy: Equatable, Sendable {
    /// The smallest set among the wallet's notes: its weakest note. nil without notes.
    public let smallestSet: Int?
    /// Per vault: the smallest set an entry of the held cash would join, and the difference from the cash it spends.
    public let vaults: [Int: (ifEntered: Int, gain: Int?)]

    public init?(_ reply: [String: Any]) {
        guard reply["ok"] as? Bool == true, let wallet = reply["wallet"] as? [String: Any] else { return nil }
        smallestSet = (wallet["smallest_set"] as? NSNumber)?.intValue
        var vaults: [Int: (ifEntered: Int, gain: Int?)] = [:]
        for v in reply["vaults"] as? [[String: Any]] ?? [] {
            guard let id = (v["vault"] as? NSNumber)?.intValue, let entered = (v["if_entered"] as? NSNumber)?.intValue else { continue }
            vaults[id] = (entered, (v["gain"] as? NSNumber)?.intValue)
        }
        self.vaults = vaults
    }

    public static func == (a: PoolPrivacy, b: PoolPrivacy) -> Bool {
        a.smallestSet == b.smallestSet && a.vaults.keys == b.vaults.keys
            && a.vaults.allSatisfy { b.vaults[$0.key]?.ifEntered == $0.value.ifEntered && b.vaults[$0.key]?.gain == $0.value.gain }
    }

    /// The sentence of the panel.
    public var line: String {
        guard let smallestSet else { return "No notes in the pool yet." }
        if smallestSet <= 1 {
            return "Your least protected note is the only one of its value in its place: anyone watching the chain could follow it."
        }
        return "Your least protected note blends in with at most \(smallestSet) notes of the same value in the same place."
    }

    public static let caveat = "Without ONA, a direct staking deposit is tied to your account: 1. This is an upper bound, counted on the chain; someone who cross-checks dates and amounts can rule some notes out."

    /// "+ X" next to a vault offered for an entry.
    public func label(vault: Int) -> String {
        guard let v = vaults[vault] else { return "" }
        let gain = v.gain.map { $0 >= 0 ? ", +\($0)" : ", \($0)" } ?? ""
        return " — among \(v.ifEntered) notes\(gain)"
    }
}
