import CryptoKit
import Foundation

/// Bytes of the phone ↔ computer protocol, version 1 (docs/ios/protocol-draft.md). Must stay identical to the
/// Windows/Linux app (desktop/tauri/src-tauri/src/protocol.rs) and to the iPhone app: the tests share vectors.
public enum ProtocolBytes {
    public static let version = 1
    public static let commitDomain = "ona/pair-commit/v1"
    public static let pairDomain = "ona/pair/v1"
    public static let sasDomain = "ona/sas/v1"
    public static let replyDomain = "ona/reply/v1"
    public static let confirmDomain = "ona/confirm/v1"
    public static let messageDomain = "ona/message/v1"
    public static let deleteDomain = "ona/delete/v1"
    public static let planDomain = "ona/plan/v1"
    public static let offersDomain = "ona/offers/v1"
    public static let payDomain = "ona/pay/v2"
    public static let payloadPrefix = "ona-pair:"

    public enum Field {
        case text(String?)
        case bytes(Data)
    }

    /// Each field: u32 little-endian length, then its bytes (text as UTF-8, nil as empty).
    public static func encode(_ fields: [Field]) -> Data {
        var out = Data()
        for field in fields {
            let raw: Data = switch field {
            case .text(let text): Data((text ?? "").utf8)
            case .bytes(let data): data
            }
            withUnsafeBytes(of: UInt32(raw.count).littleEndian) { out.append(contentsOf: $0) }
            out.append(raw)
        }
        return out
    }

    public static func hex(_ data: some Sequence<UInt8>) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    static func sha256Hex(_ data: Data) -> String { hex(SHA256.hash(data: data)) }

    /// 16 random bytes as 32 lowercase hex characters (nonces, identifiers).
    public static func randomHex16() -> String {
        var generator = SystemRandomNumberGenerator()
        return hex((0..<16).map { _ in UInt8.random(in: 0...255, using: &generator) })
    }

    public static func isHex(_ text: String, length: Int) -> Bool {
        text.utf8.count == length && text.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }

    // MARK: - Pairing (commit, then reveal)

    public static func commitment(phoneKey: Data, phoneNonce: String) -> String {
        sha256Hex(encode([.text(commitDomain), .bytes(phoneKey), .text(phoneNonce)]))
    }

    public static func pairMessage(pairingID: String, code: String, phoneKey: Data, computerKey: Data,
                                   phoneNonce: String, computerNonce: String) -> Data {
        encode([.text(pairDomain), .text(pairingID), .text(code), .bytes(phoneKey), .bytes(computerKey),
                .text(phoneNonce), .text(computerNonce)])
    }

    /// 6-digit code shown on both screens; covers both nonces (the phone's key is committed before the computer's
    /// nonce exists).
    public static func verificationCode(computerKey: Data, phoneKey: Data, code: String, phoneNonce: String,
                                        computerNonce: String) -> String {
        let digest = Data(SHA256.hash(data: encode([.text(sasDomain), .bytes(computerKey), .bytes(phoneKey),
                                                    .text(code), .text(phoneNonce), .text(computerNonce)])))
        let value = digest.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        let number = String(value % 1_000_000)
        return String(repeating: "0", count: 6 - number.count) + number
    }

    // MARK: - Requests signed by the phone's key

    public static func confirmMessage(pairingID: String, counter: UInt64, id: String?, decision: String?,
                                      firm: String?, digest: String?, content: String) -> Data {
        encode([.text(confirmDomain), .text(pairingID), .text(String(counter)), .text(id), .text(decision),
                .text(firm), .text(digest), .text(content)])
    }

    public static func chatMessage(pairingID: String, counter: UInt64, chatID: String?, text: String?) -> Data {
        encode([.text(messageDomain), .text(pairingID), .text(String(counter)), .text(chatID), .text(text)])
    }

    public static func deleteMessage(pairingID: String, counter: UInt64, chatID: String) -> Data {
        encode([.text(deleteDomain), .text(pairingID), .text(String(counter)), .text(chatID)])
    }

    // MARK: - Replies signed by the computer's key

    /// The request's nonce, method and path, the HTTP status and the exact reply text: a reply cannot be passed off as
    /// the answer to another request.
    public static func replyMessage(nonce: String, method: String, path: String, status: Int, reply: Data) -> Data {
        encode([.text(replyDomain), .text(nonce), .text(method), .text(path), .text(String(status)), .bytes(reply)])
    }

    // MARK: - Digests of what the phone shows

    public static func planDigest(id: String, steps: [String]) -> String {
        sha256Hex(encode([.text(planDomain), .text(id), .text(String(steps.count))] + steps.map { .text($0) }))
    }

    /// Offers: firm, price (cents) and delay (days) as decimal text, then the quoted spans.
    public static func offersDigest(id: String, offers: [(firm: String, price: Int, delay: Int, spans: [String])])
        -> String {
        var fields: [Field] = [.text(offersDomain), .text(id), .text(String(offers.count))]
        for offer in offers {
            fields += [.text(offer.firm), .text(String(offer.price)), .text(String(offer.delay)),
                       .text(String(offer.spans.count))]
            fields += offer.spans.map { .text($0) }
        }
        return sha256Hex(encode(fields))
    }

    /// Payment confirmation v2 (shared with ona-core):
    /// `SHA-256(fields("ona/pay/v2", network, contract, mission_id, nonce_hex, to, amount_decimal))`.
    public static func paymentDigestV2(network: String, contract: String, missionID: String, nonce: String,
                                       to: String, amount: String) -> String {
        sha256Hex(encode([.text(payDomain), .text(network), .text(contract), .text(missionID), .text(nonce),
                          .text(to), .text(amount)]))
    }

    /// Text of the pairing QR code: `ona-pair:` + base64url(JSON).
    /// `onionAuth`: with an onion address, the phone's Tor client key (base32), as `onion_auth`.
    public static func pairingPayload(name: String, address: String?, onion: String?, onionAuth: String? = nil,
                                      computerKey: Data, code: String, expiresAt: Int) -> String {
        var object: [String: Any] = ["v": version, "name": name, "computer_key": computerKey.base64EncodedString(),
                                     "code": code, "expires_at": expiresAt]
        object["address"] = address ?? NSNull()
        object["onion"] = onion ?? NSNull()
        if let onionAuth, onion != nil { object["onion_auth"] = onionAuth }
        let json = (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data()
        return payloadPrefix + base64URL(json)
    }

    /// RFC 4648 base32, upper case, without padding: the form Tor uses for client authorization keys.
    public static func base32(_ data: Data) -> String {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var out = "", buffer: UInt32 = 0, bits = 0
        for byte in data {
            buffer = (buffer << 8) | UInt32(byte)
            bits += 8
            while bits >= 5 {
                bits -= 5
                out.append(alphabet[Int((buffer >> UInt32(bits)) & 31)])
            }
        }
        if bits > 0 { out.append(alphabet[Int((buffer << UInt32(5 - bits)) & 31)]) }
        return out
    }

    public static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Order of the P-256 group, halved: a valid signature has s ≤ n/2 (low-s), so it has a single encoding.
    static let halfOrder: [UInt8] = [
        0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
    ]

    static func isLowS(_ signature: P256.Signing.ECDSASignature) -> Bool {
        let s = Array(signature.rawRepresentation.suffix(32))
        for (a, b) in zip(s, halfOrder) where a != b { return a < b }
        return true
    }

    /// Signs with the computer's key (DER, base64), low-s.
    public static func sign(_ message: Data, with key: P256.Signing.PrivateKey) -> String? {
        guard var signature = try? key.signature(for: message) else { return nil }
        if !isLowS(signature) {
            // Replace s by n − s (same signature, low form).
            let raw = signature.rawRepresentation
            let n: [UInt8] = [0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                              0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
                              0xfc, 0x63, 0x25, 0x51]
            var s = Array(raw.suffix(32)), borrow = 0
            for i in stride(from: 31, through: 0, by: -1) {
                let value = Int(n[i]) - Int(s[i]) - borrow
                s[i] = UInt8((value + 256) % 256)
                borrow = value < 0 ? 1 : 0
            }
            guard let low = try? P256.Signing.ECDSASignature(rawRepresentation: raw.prefix(32) + Data(s)) else {
                return nil
            }
            signature = low
        }
        return signature.derRepresentation.base64EncodedString()
    }

    /// Verifies an ECDSA P-256 / SHA-256 signature (DER, base64) with a public key in X9.63 (65 bytes). High-s
    /// signatures are refused.
    public static func verify(signature base64: String?, of message: Data, by publicKey: Data) -> Bool {
        guard let base64, let der = Data(base64Encoded: base64), publicKey.count == 65,
              let key = try? P256.Signing.PublicKey(x963Representation: publicKey),
              let signature = try? P256.Signing.ECDSASignature(derRepresentation: der),
              isLowS(signature)
        else { return false }
        return key.isValidSignature(signature, for: message)
    }

    /// Constant-time comparison (pairing code, token).
    public static func sameSecret(_ a: String, _ b: String) -> Bool {
        let (x, y) = (Array(a.utf8), Array(b.utf8))
        guard x.count == y.count else { return false }
        return zip(x, y).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
    }

    /// A NEAR account id as the phone may show it: 2 to 64 characters among `a-z 0-9 . _ -`.
    public static func isNearAccount(_ account: String) -> Bool {
        (2...64).contains(account.utf8.count) && account.utf8.allSatisfy {
            (97...122).contains($0) || (48...57).contains($0) || $0 == 46 || $0 == 95 || $0 == 45
        }
    }

    /// ona-core's payment screen: "Pay {amount} yoctoNEAR to {account}".
    public static func parsePaymentScreen(_ screen: String) -> (amount: String, to: String)? {
        let parts = screen.split(separator: " ", omittingEmptySubsequences: false)
        guard parts.count == 5, parts[0] == "Pay", parts[2] == "yoctoNEAR", parts[3] == "to",
              !parts[1].isEmpty, parts[1].utf8.count <= 39, parts[1].utf8.allSatisfy({ (48...57).contains($0) }),
              isNearAccount(String(parts[4]))
        else { return nil }
        return (String(parts[1]), String(parts[4]))
    }
}
