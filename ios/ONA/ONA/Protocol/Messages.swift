import Foundation

// Messages of the phone ↔ computer protocol, draft v0 (docs/ios/protocol-draft.md).
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

struct ComputerState: Decodable, Sendable {
    let mode: Mode
    let computer: Computer
    let mission: Mission?

    struct Computer: Decodable, Sendable {
        let name: String
    }

    /// True if any part of this state comes from a fake.
    var isSimulation: Bool {
        mode.isSimulation || (mission?.exposure?.mode.isSimulation ?? false)
    }
}

struct Mission: Decodable, Sendable, Identifiable {
    let id: String
    let title: String
    let phase: Phase
    let steps: [StepState]
    let events: [Event]
    let pending: Pending?
    let exposure: Exposure?

    enum Phase: String, Decodable, Sendable {
        case planProposed = "plan_proposed"
        case running
        case waiting
        case closed
        case cancelled
    }

    struct StepState: Decodable, Sendable {
        let step: Step
        let status: Status

        enum Status: String, Decodable, Sendable {
            case done, current, pending
        }
    }

    struct Event: Decodable, Sendable {
        let at: Int
        let text: String

        var date: Date { Date(timeIntervalSince1970: TimeInterval(at)) }
    }
}

/// Plan steps, named as in ona-core (`crates/ona-core/src/lib.rs`, `enum Step`).
enum Step: Decodable, Equatable, Sendable {
    case search, read, compare, confirmRecipient, contact, preparePayment, confirmPayment, pay
    case unknown(String)

    init(from decoder: Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
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

    /// A step that waits for the person holding the phone.
    var needsHuman: Bool { self == .confirmRecipient || self == .confirmPayment }
}

/// The confirmation the computer is waiting for. At most one at a time.
struct Pending: Decodable, Sendable, Identifiable, Equatable {
    let id: String
    let request: Request

    enum Request: Equatable, Sendable {
        case plan([Step])
        case recipient([Offer])
        case payment(PaymentRequest)
        case unknown(String)
    }

    private enum Keys: String, CodingKey {
        case id, kind, plan, offers, payment
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Keys.self)
        id = try c.decode(String.self, forKey: .id)
        let kind = try c.decode(String.self, forKey: .kind)
        request = switch kind {
        case "plan": .plan(try c.decode([Step].self, forKey: .plan))
        case "recipient": .recipient(try c.decode([Offer].self, forKey: .offers))
        case "payment": .payment(try c.decode(PaymentRequest.self, forKey: .payment))
        default: .unknown(kind)
        }
    }
}

/// An offer extracted by the reader (ona-core `reader::Offer`).
struct Offer: Decodable, Equatable, Sendable, Identifiable {
    let firmId: String
    let priceCents: Int
    let delayDays: Int
    let sourceSpans: [String]

    var id: String { firmId }
}

/// The payment the computer prepared. `screen` and `digest` come from the computer; the phone checks both.
struct PaymentRequest: Decodable, Equatable, Sendable {
    let to: String
    let amount: String
    let screen: String
    let digest: String
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

/// Body of `POST /v0/confirm`.
struct ConfirmationAnswer: Encodable, Sendable, Equatable {
    enum Decision: String, Encodable, Sendable {
        case accept, reject
    }

    let id: String
    let decision: Decision
    var firm: String?
    var digest: String?
    /// Reserved for step 3 (Secure Enclave P-256 signature).
    var signature: String?
}

/// Reply of the POST routes.
struct Ack: Decodable, Sendable {
    let ok: Bool
    let error: String?
    let mode: Mode?
}
