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
    /// With `onion`: the 32-byte x25519 key of the phone's Tor client authorization. The computer publishes its onion
    /// service for this key only, so a Tor client without it cannot even find the service.
    let onionAuth: Data?
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
        let onionAuth: String?
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
        var onionAuth: Data?
        if onion != nil, let text = wire.onionAuth {
            guard let decoded = Data(base32: text), decoded.count == 32 else { return .failure(.unreadable) }
            onionAuth = decoded
        }
        return .success(PairingPayload(name: wire.name, address: address, onion: onion, onionAuth: onionAuth, computerKey: key,
                                       code: wire.code, expiresAt: expiresAt))
    }
}

extension Data {
    /// RFC 4648 base32 without padding (upper or lower case), as Tor writes client authorization keys.
    init?(base32 text: String) {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var bytes: [UInt8] = []
        var buffer: UInt32 = 0, bits = 0
        for character in text.uppercased() {
            guard let value = alphabet.firstIndex(of: character) else { return nil }
            buffer = (buffer << 5) | UInt32(value)
            bits += 5
            if bits >= 8 {
                bits -= 8
                bytes.append(UInt8((buffer >> UInt32(bits)) & 0xFF))
            }
        }
        // Leftover bits must be zero padding, fewer than one byte.
        guard bits < 5, buffer & ((1 << UInt32(bits)) - 1) == 0 else { return nil }
        self.init(bytes)
    }

    /// base64url without padding (RFC 4648 §5), as used in the pairing QR.
    init?(base64URL text: String) {
        var base64 = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        self.init(base64Encoded: base64)
    }
}
