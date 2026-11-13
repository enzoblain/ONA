import Foundation

/// What the pool window shows and sends (docs/desktop/pool-commands.md), read from ona-core's replies. The texts are
/// those of the Tauri window (desktop/tauri/ui/app.js).
public enum PoolOperation: String, CaseIterable, Sendable {
    case enter, `switch`, exit, exitCash = "exit_cash", deposit

    public var title: String {
        switch self {
        case .enter: "Placer du cash dans un vault"
        case .switch: "Changer de vault"
        case .exit: "Sortir d'un vault (en cash)"
        case .exitCash: "Payer le cash vers un compte"
        case .deposit: "Déposer depuis un portefeuille NEAR"
        }
    }

    /// Whether the amount may be "tout" (every note): only shares or cash already held.
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
    /// `amount` is what the person typed: NEAR ("1.5" or "1,5"), or "tout" where the operation allows it.
    public static func prepare(_ op: PoolOperation, amount: String, vault: Int? = nil, to: Int? = nil,
                               account: String? = nil) -> Result<[String: Any], ProtocolErrorText> {
        var request: [String: Any] = ["cmd": "pool_prepare", "op": op.rawValue]
        let typed = amount.trimmingCharacters(in: .whitespaces).lowercased()
        if op.allowsAll, typed == "tout" || typed == "all" {
            request["amount"] = "all"
        } else if let yocto = NEARAmount.yocto(fromNEAR: amount), yocto != "0" {
            request["amount"] = yocto
        } else {
            return .failure("Montant illisible : écrivez par exemple 1.5")
        }
        let account = account?.trimmingCharacters(in: .whitespaces) ?? ""
        switch op {
        case .enter:
            guard let vault else { return .failure("Choisissez un vault") }
            request["vault"] = vault
        case .switch:
            guard let vault, let to else { return .failure("Choisissez un vault") }
            request["from"] = vault
            request["to"] = to
        case .exit:
            guard let vault else { return .failure("Choisissez un vault") }
            request["from"] = vault
        case .exitCash:
            guard !account.isEmpty else { return .failure("Indiquez le compte NEAR") }
            request["to"] = account
        case .deposit:
            guard !account.isEmpty else { return .failure("Indiquez votre compte NEAR") }
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
        ("amount", "Montant", true), ("account", "Compte", false), ("vault", "Vault", false),
        ("from", "Depuis le vault", false), ("to", "Vers", false), ("shares_value", "Parts reçues (valeur)", true),
        ("new_shares_value", "Nouvelles parts (valeur)", true), ("cash_value", "Cash reçu", true),
        ("received", "Reçu", true), ("left_in_cash", "Laissé dans le cash du pool (perdu)", true),
        ("exit_limit", "Limite de sortie du compte", true),
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
        rows += fees.keys.sorted().map { key in Row(label: "Frais : \(key)", value: Self.near("\(fees[key] ?? "")")) }
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
            if reply["complete"] as? Bool == true { return "Opération faite." }
            return "Opération en partie faite" + (error.map { " : \($0)" } ?? ".")
        }
        // Entries, exits and cash payments are queued by the pool agent: their outcome comes through pool_recover.
        if let error, error.contains("outcome unknown") {
            return "Envoyée à l'agent du pool : le résultat arrivera plus tard (Récupérer)."
        }
        return "Opération refusée : \(error ?? "erreur du pool")"
    }

    public static func recover(_ reply: [String: Any]) -> String {
        guard reply["ok"] as? Bool == true else {
            return "Récupération impossible : \(reply["error"] as? String ?? "erreur du pool")"
        }
        let count = { (key: String) in reply[key] as? Int ?? 0 }
        let agent = (reply["agent_error"] as? String).map { " (agent : \($0))" } ?? ""
        return "Récupération : \(count("spent")) faites, \(count("held_again")) revenues, \(count("still_spending")) en attente\(agent)."
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
        guard let smallestSet else { return "Aucun billet dans le pool pour l'instant." }
        if smallestSet <= 1 {
            return "Votre billet le moins protégé est seul de sa valeur à sa place : un observateur de la chaîne peut le suivre."
        }
        return "Votre billet le moins protégé se confond avec au plus \(smallestSet) billets de même valeur au même endroit."
    }

    public static let caveat = "Sans ONA, un dépôt direct en staking est lié à votre compte : 1. Chiffre maximal, compté sur la chaîne ; un observateur qui recoupe les dates et les montants peut en exclure certains."

    /// "+ X" next to a vault offered for an entry.
    public func label(vault: Int) -> String {
        guard let v = vaults[vault] else { return "" }
        let gain = v.gain.map { $0 >= 0 ? ", +\($0)" : ", \($0)" } ?? ""
        return " — parmi \(v.ifEntered) billets\(gain)"
    }
}
