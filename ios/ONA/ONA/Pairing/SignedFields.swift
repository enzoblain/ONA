import CryptoKit
import Foundation

/// Bytes signed by the phone (docs/ios/protocol-draft.md, step 3). Each field: u32 little-endian length, then bytes.
enum SignedFields {
    static let pairDomain = "ona/pair/v0"
    static let confirmDomain = "ona/confirm/v0"
    static let sasDomain = "ona/sas/v0"
    static let messageDomain = "ona/message/v0"
    static let deleteDomain = "ona/delete/v0"

    enum Field {
        case text(String?)
        case bytes(Data)
    }

    static func encode(_ fields: [Field]) -> Data {
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

    /// Proves at pairing time that the phone holds the key it sends.
    static func pairMessage(code: String, phoneKey: Data, computerKey: Data) -> Data {
        encode([.text(pairDomain), .text(code), .bytes(phoneKey), .bytes(computerKey)])
    }

    /// What a confirmation commits to: this pairing, this request, this decision, this firm or payment digest.
    static func confirmMessage(_ answer: ConfirmationAnswer, pairingID: String) -> Data {
        encode([
            .text(confirmDomain), .text(pairingID), .text(answer.id), .text(answer.decision.rawValue),
            .text(answer.firm), .text(answer.digest),
        ])
    }

    /// A message to the agent. `chatID` is nil for the first message of a new chat.
    static func chatMessage(pairingID: String, chatID: String?, text: String) -> Data {
        encode([.text(messageDomain), .text(pairingID), .text(chatID), .text(text)])
    }

    /// Deleting a chat on the computer.
    static func deleteChat(pairingID: String, chatID: String) -> Data {
        encode([.text(deleteDomain), .text(pairingID), .text(chatID)])
    }

    /// 6-digit code shown on both sides after pairing, compared by the person.
    static func verificationCode(computerKey: Data, phoneKey: Data, code: String) -> String {
        let digest = Data(SHA256.hash(data: encode([.text(sasDomain), .bytes(computerKey), .bytes(phoneKey), .text(code)])))
        let value = digest.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        let number = String(value % 1_000_000)
        return String(repeating: "0", count: 6 - number.count) + number
    }
}
