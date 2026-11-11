import Foundation

// Messages of the phone ↔ computer protocol, version 1 (docs/ios/protocol-draft.md).
// Field names follow the JSON (snake_case is converted by the decoder).

/// Where a reply comes from. Anything else than `.real` must be shown as a simulation.
enum Mode: Decodable, Equatable, Sendable {
    case mock
    case real
    case other(String)

    init(from decoder: Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        self = switch raw {
        case "mock": .mock
        case "real": .real
        default: .other(raw)
        }
    }

    var isSimulation: Bool { self != .real }
}

/// Plan steps, named as in ona-core (`crates/ona-core/src/lib.rs`, `enum Step`).
enum Step: Decodable, Equatable, Sendable {
    case search, read, compare, confirmRecipient, contact, preparePayment, confirmPayment, pay
    case unknown(String)

    init(from decoder: Decoder) throws {
        self.init(raw: try decoder.singleValueContainer().decode(String.self))
    }

    /// From the protocol's step names (`search`, `prepare_payment`…).
    init(raw: String) {
        self = switch raw {
        case "search": .search
        case "read": .read
        case "compare": .compare
        case "confirm_recipient": .confirmRecipient
        case "contact": .contact
        case "prepare_payment": .preparePayment
        case "confirm_payment": .confirmPayment
        case "pay": .pay
        default: .unknown(raw)
        }
    }

    /// The protocol's name of the step, as signed in the plan digest.
    var raw: String {
        switch self {
        case .search: "search"
        case .read: "read"
        case .compare: "compare"
        case .confirmRecipient: "confirm_recipient"
        case .contact: "contact"
        case .preparePayment: "prepare_payment"
        case .confirmPayment: "confirm_payment"
        case .pay: "pay"
        case .unknown(let raw): raw
        }
    }

    /// A step that waits for the person holding the phone.
    var needsHuman: Bool { self == .confirmRecipient || self == .confirmPayment }
}

/// A confirmation the computer is waiting for. At most one per conversation.
struct Pending: Decodable, Sendable, Identifiable, Equatable {
    let id: String
    let request: Request
    /// The computer's digest of what it asks. Never signed as is: the phone signs its own digest of what it shows.
    let content: String?

    enum Request: Equatable, Sendable {
        case plan([Step])
        case recipient([Offer])
        case payment(PaymentRequest)
        case unknown(String)
    }

    private enum Keys: String, CodingKey {
        case id, kind, plan, offers, payment, content
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Keys.self)
        id = try c.decode(String.self, forKey: .id)
        content = try c.decodeIfPresent(String.self, forKey: .content)
        let kind = try c.decode(String.self, forKey: .kind)
        request = switch kind {
        case "plan": .plan(try c.decode([Step].self, forKey: .plan))
        case "recipient": .recipient(try c.decode([Offer].self, forKey: .offers))
        case "payment": .payment(try c.decode(PaymentRequest.self, forKey: .payment))
        default: .unknown(kind)
        }
    }

    init(id: String, request: Request, content: String? = nil) {
        self.id = id
        self.request = request
        self.content = content
    }
}

/// An offer extracted by the reader (ona-core `reader::Offer`). Every field is shown, and covered by the signature.
struct Offer: Decodable, Equatable, Sendable, Identifiable {
    let firmId: String
    let priceCents: Int
    let delayDays: Int
    let sourceSpans: [String]

    var id: String { firmId }
}

/// The payment the computer prepared (digest version 2). The phone recomputes `digest` and checks `screen`.
struct PaymentRequest: Decodable, Equatable, Sendable {
    let to: String
    let amount: String
    let screen: String
    let digest: String
    let digestVersion: Int?
    let network: String?
    let contract: String?
    let missionId: String?
    let nonce: String?
}

/// What left the computer during the mission (ona-core `exposure_report`).
struct Exposure: Decodable, Sendable {
    let outputs: [String: Int]
    let refusedByGate: [String: Int]
    let firmsContacted: [String]
    let payments: [Payment]
    let modelCalls: Int
    let mode: Mode

    struct Payment: Decodable, Sendable {
        let to: String
        let amount: String
    }
}

/// What the person decided on a confirmation. Sent signed, with the digest of what was shown (`content`).
struct ConfirmationAnswer: Sendable, Equatable {
    enum Decision: String, Sendable {
        case accept, reject
    }

    let id: String
    let decision: Decision
    var firm: String?
    var digest: String?
    /// The phone's own digest of what it showed.
    let content: String
}

/// Reply of `POST /v1/pair` (commitment).
struct PairCommitReply: Decodable, Sendable {
    let pairingId: String
    let computerNonce: String
}

/// Reply of `POST /v1/pair/reveal`.
struct PairRevealReply: Decodable, Sendable {
    let pairingId: String
    let token: String
}

/// Reply of the write routes.
struct Ack: Decodable, Sendable {
    let ok: Bool?
    let mode: Mode?
}

/// Reply of `POST /v1/chats`.
struct NewChatAck: Decodable, Sendable {
    let mode: Mode?
    let chatId: String
}

/// JSON coding shared by the app and its tests: snake_case on the wire.
enum ProtocolCoding {
    static var decoder: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return decoder
    }
}
