import Foundation

/// NEAR amounts as the pool commands carry them: yoctoNEAR (10^-24 NEAR) in decimal strings. Exact both ways, no
/// floating point (the same rules as the iPhone app's `NEARAmount` and the Tauri window's `yocto` and `near`).
public enum NEARAmount {
    public static let yoctoPerNEAR: UInt128 = 1_000_000_000_000_000_000_000_000

    /// "1", "0.5", "12.000001": exact, trailing zeros removed.
    public static func format(_ yocto: UInt128) -> String {
        let whole = yocto / yoctoPerNEAR
        let fraction = yocto % yoctoPerNEAR
        guard fraction > 0 else { return "\(whole)" }
        var digits = String(fraction)
        digits = String(repeating: "0", count: 24 - digits.count) + digits
        while digits.hasSuffix("0") { digits.removeLast() }
        return "\(whole).\(digits)"
    }

    /// A yoctoNEAR string from ona-core as NEAR text ("2.3"), or nil if it is not a decimal number.
    public static func text(_ yocto: String) -> String? {
        guard isDigits(yocto), let value = UInt128(yocto, radix: 10) else { return nil }
        return format(value)
    }

    /// What the person typed, in NEAR ("1.5" or "1,5", at most 24 decimals), as a yoctoNEAR string; nil when it is not
    /// such a number or does not fit.
    public static func yocto(fromNEAR text: String) -> String? {
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        let parts = trimmed.split(separator: /[.,]/, maxSplits: 1, omittingEmptySubsequences: false)
        guard let whole = parts.first, isDigits(whole) else { return nil }
        let fraction = parts.count > 1 ? parts[1] : ""
        guard fraction.count <= 24, fraction.isEmpty || isDigits(fraction),
              let wholeValue = UInt128(whole, radix: 10),
              let fractionValue = UInt128(fraction.padding(toLength: 24, withPad: "0", startingAt: 0), radix: 10)
        else { return nil }
        let (scaled, overflow) = wholeValue.multipliedReportingOverflow(by: yoctoPerNEAR)
        guard !overflow else { return nil }
        let (sum, overflowSum) = scaled.addingReportingOverflow(fractionValue)
        return overflowSum ? nil : String(sum)
    }

    private static func isDigits(_ text: some StringProtocol) -> Bool {
        !text.isEmpty && text.utf8.allSatisfy { (48...57).contains($0) }
    }
}
