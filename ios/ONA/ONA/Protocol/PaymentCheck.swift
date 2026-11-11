import Foundation

/// Checks a payment request on the phone, without trusting the computer's `screen` or `digest`.
///
/// Digest version 2, the bytes of ona-core's payment gate:
/// `SHA-256(fields("ona/pay/v2", network, contract, mission_id, nonce, to, amount))`, lowercase hex. The nonce makes
/// every payment's digest different: an old confirmation cannot be replayed on a new payment.
enum PaymentCheck {
    enum Failure: Error, Equatable {
        case unsupportedVersion
        case missingField
        case badAccount
        case badAmount
        case digestMismatch
        case screenMismatch
    }

    /// A payment whose digest the phone computed itself. Only a verified payment can be confirmed.
    struct Verified: Equatable, Sendable {
        let to: String
        let amount: UInt128
        let digest: String
    }

    /// The confirmation text, rebuilt from the payment itself (same format as ona-core `PaymentIntent::screen`).
    static func screen(to: String, amount: UInt128) -> String {
        "Pay \(amount) yoctoNEAR to \(to)"
    }

    static func verify(_ request: PaymentRequest) -> Result<Verified, Failure> {
        guard request.digestVersion == 2 else { return .failure(.unsupportedVersion) }
        guard let network = request.network, let contract = request.contract, let missionID = request.missionId,
              let nonce = request.nonce, !network.isEmpty, !contract.isEmpty, !missionID.isEmpty, !nonce.isEmpty
        else { return .failure(.missingField) }
        // Shown only if it looks like a NEAR account: no look-alike characters, no right-to-left tricks.
        guard SignedFields.isNearAccount(request.to) else { return .failure(.badAccount) }
        guard request.amount.utf8.allSatisfy({ (48...57).contains($0) }), let amount = UInt128(request.amount, radix: 10)
        else { return .failure(.badAmount) }
        let digest = SignedFields.paymentDigest(network: network, contract: contract, missionID: missionID, nonce: nonce,
                                                to: request.to, amount: String(amount))
        guard digest == request.digest else { return .failure(.digestMismatch) }
        guard screen(to: request.to, amount: amount) == request.screen else { return .failure(.screenMismatch) }
        return .success(Verified(to: request.to, amount: amount, digest: digest))
    }
}

enum NEARAmount {
    static let yoctoPerNEAR: UInt128 = 1_000_000_000_000_000_000_000_000

    /// "1", "0.5", "12.000001" … (exact, no rounding, trailing zeros removed).
    static func format(_ yocto: UInt128) -> String {
        let whole = yocto / yoctoPerNEAR
        let fraction = yocto % yoctoPerNEAR
        guard fraction > 0 else { return "\(whole)" }
        var digits = String(fraction)
        digits = String(repeating: "0", count: 24 - digits.count) + digits
        while digits.hasSuffix("0") { digits.removeLast() }
        return "\(whole).\(digits)"
    }
}
