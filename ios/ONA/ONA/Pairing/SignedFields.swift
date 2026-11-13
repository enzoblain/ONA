import CryptoKit
import Foundation

/// Bytes of the phone ↔ computer protocol, version 1 (docs/ios/protocol-draft.md). Each field: u32 little-endian
/// length, then its bytes. Must stay identical to the desktop apps (`ProtocolBytes.swift`, `protocol.rs`): the tests
/// share vectors.
enum SignedFields {
    static let commitDomain = "ona/pair-commit/v1"
    static let pairDomain = "ona/pair/v1"
    static let sasDomain = "ona/sas/v1"
    static let replyDomain = "ona/reply/v1"
    static let confirmDomain = "ona/confirm/v1"
    static let messageDomain = "ona/message/v1"
    static let deleteDomain = "ona/delete/v1"
    static let planDomain = "ona/plan/v1"
    static let offersDomain = "ona/offers/v1"
    static let queriesDomain = "ona/queries/v1"
    static let payDomain = "ona/pay/v2"

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

    static func hex(_ data: some Sequence<UInt8>) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    static func sha256Hex(_ data: Data) -> String { hex(SHA256.hash(data: data)) }

    /// 16 random bytes as 32 lowercase hex characters: a new one for every request, and for pairing.
    static func randomHex16() -> String {
        var generator = SystemRandomNumberGenerator()
        return hex((0..<16).map { _ in UInt8.random(in: 0...255, using: &generator) })
    }

    // MARK: - Pairing: commit to the key, then reveal it

    static func commitment(phoneKey: Data, phoneNonce: String) -> String {
        sha256Hex(encode([.text(commitDomain), .bytes(phoneKey), .text(phoneNonce)]))
    }

    static func pairMessage(pairingID: String, code: String, phoneKey: Data, computerKey: Data, phoneNonce: String,
                            computerNonce: String) -> Data {
        encode([.text(pairDomain), .text(pairingID), .text(code), .bytes(phoneKey), .bytes(computerKey),
                .text(phoneNonce), .text(computerNonce)])
    }

    /// 6-digit code shown on both sides, compared by the person. The phone's key is committed before the computer's
    /// nonce exists, so nobody in between can pick a key that gives the same code.
    static func verificationCode(computerKey: Data, phoneKey: Data, code: String, phoneNonce: String,
                                 computerNonce: String) -> String {
        let digest = Data(SHA256.hash(data: encode([.text(sasDomain), .bytes(computerKey), .bytes(phoneKey), .text(code),
                                                    .text(phoneNonce), .text(computerNonce)])))
        let value = digest.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        let number = String(value % 1_000_000)
        return String(repeating: "0", count: 6 - number.count) + number
    }

    // MARK: - Requests signed by the phone (each with a counter that only goes up)

    /// `content` is the digest of what the phone showed, computed by the phone (never taken from the computer).
    static func confirmMessage(pairingID: String, counter: UInt64, id: String, decision: String, firm: String?,
                               digest: String?, content: String) -> Data {
        encode([.text(confirmDomain), .text(pairingID), .text(String(counter)), .text(id), .text(decision),
                .text(firm), .text(digest), .text(content)])
    }

    /// A message to the agent. `chatID` is nil for the first message of a new chat.
    static func chatMessage(pairingID: String, counter: UInt64, chatID: String?, text: String) -> Data {
        encode([.text(messageDomain), .text(pairingID), .text(String(counter)), .text(chatID), .text(text)])
    }

    static func deleteMessage(pairingID: String, counter: UInt64, chatID: String) -> Data {
        encode([.text(deleteDomain), .text(pairingID), .text(String(counter)), .text(chatID)])
    }

    // MARK: - Replies signed by the computer

    /// What the computer signs: this request's nonce, method and path, the HTTP status and the exact reply text.
    static func replyMessage(nonce: String, method: String, path: String, status: Int, reply: Data) -> Data {
        encode([.text(replyDomain), .text(nonce), .text(method), .text(path), .text(String(status)), .bytes(reply)])
    }

    // MARK: - Digests of what the phone shows

    static func planDigest(id: String, steps: [String]) -> String {
        sha256Hex(encode([.text(planDomain), .text(id), .text(String(steps.count))] + steps.map { .text($0) }))
    }

    /// Free research: `fields("ona/queries/v1", id, query_1, query_2, …)` (docs/research.md).
    static func queriesDigest(id: String, queries: [String]) -> String {
        sha256Hex(encode([.text(queriesDomain), .text(id)] + queries.map { .text($0) }))
    }

    static func offersDigest(id: String, offers: [Offer]) -> String {
        var fields: [Field] = [.text(offersDomain), .text(id), .text(String(offers.count))]
        for offer in offers {
            fields += [.text(offer.firmId), .text(String(offer.priceCents)), .text(String(offer.delayDays)),
                       .text(String(offer.sourceSpans.count))]
            fields += offer.sourceSpans.map { .text($0) }
        }
        return sha256Hex(encode(fields))
    }

    /// Payment v2, the bytes of ona-core's payment gate.
    static func paymentDigest(network: String, contract: String, missionID: String, nonce: String, to: String,
                              amount: String) -> String {
        sha256Hex(encode([.text(payDomain), .text(network), .text(contract), .text(missionID), .text(nonce),
                          .text(to), .text(amount)]))
    }

    // MARK: - Signatures (ECDSA P-256 / SHA-256, DER, low-s on both sides)

    /// Order of the P-256 group.
    static let order: [UInt8] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
    ]
    /// Half the order: a low-s signature has s ≤ n/2.
    static let halfOrder: [UInt8] = [
        0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
    ]

    static func isLowS(_ signature: P256.Signing.ECDSASignature) -> Bool {
        let s = Array(signature.rawRepresentation.suffix(32))
        for (a, b) in zip(s, halfOrder) where a != b { return a < b }
        return true
    }

    /// The same signature in its low-s form (s replaced by n − s when s > n/2). The computer refuses high-s.
    static func lowS(_ signature: P256.Signing.ECDSASignature) throws -> P256.Signing.ECDSASignature {
        guard !isLowS(signature) else { return signature }
        let raw = signature.rawRepresentation
        var s = Array(raw.suffix(32)), borrow = 0
        for i in stride(from: 31, through: 0, by: -1) {
            let value = Int(order[i]) - Int(s[i]) - borrow
            s[i] = UInt8((value + 256) % 256)
            borrow = value < 0 ? 1 : 0
        }
        return try P256.Signing.ECDSASignature(rawRepresentation: raw.prefix(32) + Data(s))
    }

    /// Checks a signature made by the computer: DER in base64, low-s, P-256 key in X9.63 (65 bytes).
    static func verify(signature base64: String?, of message: Data, by publicKey: Data) -> Bool {
        guard let base64, let der = Data(base64Encoded: base64), publicKey.count == 65,
              let key = try? P256.Signing.PublicKey(x963Representation: publicKey),
              let signature = try? P256.Signing.ECDSASignature(derRepresentation: der),
              isLowS(signature)
        else { return false }
        return key.isValidSignature(signature, for: message)
    }

    /// A NEAR account as the phone may show it: 2 to 64 characters among `a-z 0-9 . _ -`.
    static func isNearAccount(_ account: String) -> Bool {
        (2...64).contains(account.utf8.count) && account.utf8.allSatisfy {
            (97...122).contains($0) || (48...57).contains($0) || $0 == 46 || $0 == 95 || $0 == 45
        }
    }
}
