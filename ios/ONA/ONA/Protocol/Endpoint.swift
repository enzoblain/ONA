import Foundation

/// Where the computer is reached.
enum Endpoint: Equatable, Sendable {
    /// Steps 2–3: plain HTTP on the local network (mock computer).
    case local(URL)
    /// Step 4: the computer's onion service, through Tor (Arti embedded in the app). Port 80 of the onion service.
    case onion(String)

    /// The endpoint named by a pairing: the onion address when there is one, otherwise the local address.
    init?(onion: String?, address: URL?) {
        if let onion, onion.hasSuffix(".onion") {
            self = .onion(onion)
        } else if let address {
            self = .local(address)
        } else {
            return nil
        }
    }

    var isTor: Bool {
        if case .onion = self { true } else { false }
    }
}

/// A link that always fails: used when this build cannot reach an endpoint (e.g. Tor in the Mac test package).
struct UnavailableLink: ComputerLink {
    let reason: String

    func state() async throws -> ComputerState { throw LinkError.unreachable(reason) }
    func pair(_ request: PairRequest) async throws -> Ack { throw LinkError.unreachable(reason) }
    func confirm(_ confirmation: ConfirmationAnswer) async throws -> Ack { throw LinkError.unreachable(reason) }
    func mock(_ action: MockAction) async throws -> Ack { throw LinkError.unreachable(reason) }
    func chats() async throws -> ChatList { throw LinkError.unreachable(reason) }
    func chat(_ id: String) async throws -> ChatReply { throw LinkError.unreachable(reason) }
    func newChat(_ request: ChatMessageRequest) async throws -> NewChatAck { throw LinkError.unreachable(reason) }
    func send(_ request: ChatMessageRequest, to chatID: String) async throws -> Ack { throw LinkError.unreachable(reason) }
    func deleteChat(_ chatID: String, _ request: ChatDeleteRequest) async throws -> Ack {
        throw LinkError.unreachable(reason)
    }
}

extension ProtocolCoding {
    /// Decodes a reply. The POST routes answer 4xx with an `Ack` that carries the reason (`acceptErrorBody`).
    static func decodeReply<T: Decodable>(_ type: T.Type, status: Int, body: Data, acceptErrorBody: Bool) throws -> T {
        guard (200..<300).contains(status) || acceptErrorBody else {
            let ack = try? decoder.decode(Ack.self, from: body)
            throw LinkError.badStatus(status, ack?.error)
        }
        do {
            return try decoder.decode(T.self, from: body)
        } catch {
            throw LinkError.badReply(String(describing: error))
        }
    }
}
