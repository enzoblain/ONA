import CryptoKit
import Foundation

/// Checks a payment request on the phone, without trusting the computer's `screen` or `digest`.
///
/// The bytes are the same as ona-core's `gate::PaymentIntent::bytes`: length of the account as u32 little-endian, the
/// account in UTF-8, the amount as u128 little-endian. The digest is their SHA-256 in lowercase hex.
enum PaymentCheck {
    enum Failure: Error, Equatable {
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

    static func bytes(to: String, amount: UInt128) -> Data {
        let account = Data(to.utf8)
        var out = Data()
        withUnsafeBytes(of: UInt32(account.count).littleEndian) { out.append(contentsOf: $0) }
        out.append(account)
        withUnsafeBytes(of: amount.littleEndian) { out.append(contentsOf: $0) }
        return out
    }

    static func digest(to: String, amount: UInt128) -> String {
        SHA256.hash(data: bytes(to: to, amount: amount)).map { String(format: "%02x", $0) }.joined()
    }

    /// The confirmation text, rebuilt from the payment itself (same format as ona-core `PaymentIntent::screen`).
    static func screen(to: String, amount: UInt128) -> String {
        "Pay \(amount) yoctoNEAR to \(to)"
    }

    static func verify(_ request: PaymentRequest) -> Result<Verified, Failure> {
        guard let amount = UInt128(request.amount, radix: 10) else { return .failure(.badAmount) }
        let digest = digest(to: request.to, amount: amount)
        guard digest == request.digest.lowercased() else { return .failure(.digestMismatch) }
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
