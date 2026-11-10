import CryptoKit
import Foundation

/// Bytes of the phone ↔ computer protocol (docs/ios/protocol-draft.md). Must stay identical to the iPhone app
/// (ios/ONA/ONA/Pairing/SignedFields.swift) and to the mock (ios/MockComputer/pairing.py): the tests share vectors.
public enum ProtocolBytes {
    public static let pairDomain = "ona/pair/v0"
    public static let confirmDomain = "ona/confirm/v0"
    public static let sasDomain = "ona/sas/v0"
    public static let messageDomain = "ona/message/v0"
    public static let deleteDomain = "ona/delete/v0"
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

    public static func pairMessage(code: String, phoneKey: Data, computerKey: Data) -> Data {
        encode([.text(pairDomain), .text(code), .bytes(phoneKey), .bytes(computerKey)])
    }

    public static func confirmMessage(pairingID: String, id: String?, decision: String?, firm: String?,
                                      digest: String?) -> Data {
        encode([.text(confirmDomain), .text(pairingID), .text(id), .text(decision), .text(firm), .text(digest)])
    }

    public static func chatMessage(pairingID: String, chatID: String?, text: String?) -> Data {
        encode([.text(messageDomain), .text(pairingID), .text(chatID), .text(text)])
    }

    public static func deleteMessage(pairingID: String, chatID: String) -> Data {
        encode([.text(deleteDomain), .text(pairingID), .text(chatID)])
    }

    /// 6-digit code shown on both screens after pairing.
    public static func verificationCode(computerKey: Data, phoneKey: Data, code: String) -> String {
        let digest = Data(SHA256.hash(data: encode([.text(sasDomain), .bytes(computerKey), .bytes(phoneKey), .text(code)])))
        let value = digest.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        let number = String(value % 1_000_000)
        return String(repeating: "0", count: 6 - number.count) + number
    }

    /// Text of the pairing QR code: `ona-pair:` + base64url(JSON).
    public static func pairingPayload(name: String, address: String?, onion: String?, computerKey: Data,
                                      code: String) -> String {
        var object: [String: Any] = ["v": 0, "name": name, "computer_key": computerKey.base64EncodedString(),
                                     "code": code]
        object["address"] = address ?? NSNull()
        object["onion"] = onion ?? NSNull()
        let json = (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data()
        return payloadPrefix + base64URL(json)
    }

    public static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Verifies an ECDSA P-256 / SHA-256 signature (DER, base64) with a public key in X9.63.
    public static func verify(signature base64: String?, of message: Data, by publicKey: Data) -> Bool {
        guard let base64, let der = Data(base64Encoded: base64),
              let key = try? P256.Signing.PublicKey(x963Representation: publicKey),
              let signature = try? P256.Signing.ECDSASignature(derRepresentation: der)
        else { return false }
        return key.isValidSignature(signature, for: message)
    }

    /// ona-core's payment screen: "Pay {amount} yoctoNEAR to {account}".
    public static func parsePaymentScreen(_ screen: String) -> (amount: String, to: String)? {
        let parts = screen.split(separator: " ")
        guard parts.count == 5, parts[0] == "Pay", parts[2] == "yoctoNEAR", parts[3] == "to",
              parts[1].allSatisfy(\.isNumber)
        else { return nil }
        return (String(parts[1]), String(parts[4]))
    }
}
