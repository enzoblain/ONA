import CryptoKit
import Foundation

/// Content of the pairing QR code shown by the computer: `ona-pair:` + base64url(JSON), protocol version 1.
struct PairingPayload: Equatable, Sendable {
    static let prefix = "ona-pair:"
    static let version = 1

    let name: String
    /// Local network address (development builds only). Real use goes through `onion`.
    let address: URL?
    let onion: String?
    /// The computer's P-256 public key, X9.63 uncompressed (65 bytes). Every reply of the computer is checked with it.
    let computerKey: Data
    /// Single-use pairing code.
    let code: String
    /// After this date the computer no longer accepts the code.
    let expiresAt: Date

    enum Failure: Error, Equatable {
        case notAPairingCode
        case unreadable
        case unsupportedVersion(Int)
        case badComputerKey
        case noAddress
        case expired
    }

    private struct Wire: Decodable {
        let v: Int
        let name: String
        let address: String?
        let onion: String?
        let computerKey: String
        let code: String
        let expiresAt: Int?
    }

    /// Plain HTTP on the local network is for development builds only (`NSAllowsLocalNetworking` is in the Debug
    /// Info.plist only).
    static var acceptsLocalAddress: Bool {
        #if DEBUG
        true
        #else
        false
        #endif
    }

    static func parse(_ text: String, now: Date = .now) -> Result<PairingPayload, Failure> {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix(prefix) else { return .failure(.notAPairingCode) }
        guard let json = Data(base64URL: String(trimmed.dropFirst(prefix.count))) else { return .failure(.unreadable) }
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        guard let wire = try? decoder.decode(Wire.self, from: json) else { return .failure(.unreadable) }
        guard wire.v == version else { return .failure(.unsupportedVersion(wire.v)) }
        guard let key = Data(base64Encoded: wire.computerKey), key.count == 65,
              (try? P256.Signing.PublicKey(x963Representation: key)) != nil
        else { return .failure(.badComputerKey) }
        guard !wire.code.isEmpty, let expires = wire.expiresAt else { return .failure(.unreadable) }
        let expiresAt = Date(timeIntervalSince1970: TimeInterval(expires))
        guard expiresAt > now else { return .failure(.expired) }

        let address = acceptsLocalAddress ? wire.address.flatMap(URL.init(string:)).flatMap { url in
            url.scheme == "http" && url.host() != nil ? url : nil
        } : nil
        let onion = wire.onion.flatMap { $0.hasSuffix(".onion") ? $0 : nil }
        guard address != nil || onion != nil else { return .failure(.noAddress) }
        return .success(PairingPayload(name: wire.name, address: address, onion: onion, computerKey: key,
                                       code: wire.code, expiresAt: expiresAt))
    }
}

extension Data {
    /// base64url without padding (RFC 4648 §5), as used in the pairing QR.
    init?(base64URL text: String) {
        var base64 = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        self.init(base64Encoded: base64)
    }
}
