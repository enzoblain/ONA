import Foundation

// The pool portfolio, read only (docs/ios/protocol-draft.md, « Pool »). The same JSON as ona-core's `pool_portfolio`
// (docs/desktop/pool-commands.md). Amounts are yoctoNEAR in decimal strings. Deposits, placements and exits are
// confirmed on the computer, never on the phone.

/// Reply of `POST /v1/pool/portfolio`.
struct PoolReply: Decodable, Sendable {
    let mode: Mode
    let portfolio: PoolPortfolio
}

struct PoolPortfolio: Decodable, Sendable, Equatable {
    /// Cash notes: money in the pool, in no vault.
    let cash: PoolHolding
    /// Only the vaults where this wallet has shares.
    let vaults: [VaultHolding]
    /// Vaults the pool lists in all.
    let vaultCount: Int
    /// Cash plus shares, at the contract's public share prices (held notes only).
    let total: String
}

struct PoolHolding: Decodable, Sendable, Equatable {
    let tiers: [PoolTier]
    let value: String
    /// Notes signed for an operation whose outcome is not known yet: not available.
    let spendingValue: String
    /// Notes the agent has not signed yet.
    let awaitingSignature: Int
}

struct VaultHolding: Decodable, Sendable, Equatable, Identifiable {
    let vault: Int
    let sharePrice: String
    /// A frozen vault takes no new money.
    let frozen: Bool
    let tiers: [PoolTier]
    let value: String
    let spendingValue: String
    let awaitingSignature: Int

    var id: Int { vault }
}

struct PoolTier: Decodable, Sendable, Equatable, Identifiable {
    let tier: Int
    let noteValue: String
    let held: Int
    let spending: Int

    var id: Int { tier }
}

extension NEARAmount {
    /// A yoctoNEAR amount from the protocol as NEAR text ("2.3"), or nil if it is not a decimal number.
    static func text(_ yocto: String) -> String? {
        guard !yocto.isEmpty, yocto.utf8.allSatisfy({ (48...57).contains($0) }), let value = UInt128(yocto, radix: 10)
        else { return nil }
        return format(value)
    }
}
