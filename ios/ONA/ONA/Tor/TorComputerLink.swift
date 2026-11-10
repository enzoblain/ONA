import Foundation

/// The protocol over Tor: HTTP/1.0 to port 80 of the computer's onion service, through Arti.
/// The onion address authenticates the computer: only the holder of its key can answer there.
struct TorComputerLink: ComputerLink {
    let onion: String
    var tor: ArtiTor = .shared

    func state() async throws -> ComputerState {
        try await send("GET", "/v0/state", body: nil)
    }

    func pair(_ request: PairRequest) async throws -> Ack {
        try await send("POST", "/v0/pair", body: try ProtocolCoding.encoder.encode(request), acceptErrorBody: true)
    }

    func confirm(_ confirmation: ConfirmationAnswer) async throws -> Ack {
        try await send("POST", "/v0/confirm", body: try ProtocolCoding.encoder.encode(confirmation),
                       acceptErrorBody: true)
    }

    func mock(_ action: MockAction) async throws -> Ack {
        try await send("POST", "/v0/mock/\(action.rawValue)", body: Data("{}".utf8), acceptErrorBody: true)
    }

    func chats() async throws -> ChatList {
        try await send("GET", "/" + ChatPaths.list, body: nil)
    }

    func chat(_ id: String) async throws -> ChatReply {
        try await send("GET", "/" + ChatPaths.chat(id), body: nil)
    }

    func newChat(_ request: ChatMessageRequest) async throws -> NewChatAck {
        try await send("POST", "/" + ChatPaths.list, body: try ProtocolCoding.encoder.encode(request),
                       acceptErrorBody: true)
    }

    func send(_ request: ChatMessageRequest, to chatID: String) async throws -> Ack {
        try await send("POST", "/" + ChatPaths.messages(chatID), body: try ProtocolCoding.encoder.encode(request),
                       acceptErrorBody: true)
    }

    func deleteChat(_ chatID: String, _ request: ChatDeleteRequest) async throws -> Ack {
        try await send("POST", "/" + ChatPaths.delete(chatID), body: try ProtocolCoding.encoder.encode(request),
                       acceptErrorBody: true)
    }

    private func send<T: Decodable>(_ method: String, _ path: String, body: Data?,
                                    acceptErrorBody: Bool = false) async throws -> T {
        let response: ArtiTor.Response
        do {
            response = try await tor.request(host: onion, method: method, path: path, body: body)
        } catch let error as TorError {
            throw LinkError.unreachable(error.localizedDescription)
        }
        return try ProtocolCoding.decodeReply(T.self, status: response.status, body: response.body,
                                              acceptErrorBody: acceptErrorBody)
    }
}

enum AppLinks {
    /// The app's link factory: local HTTP, or Tor for an onion address.
    static func make(_ endpoint: Endpoint) -> any ComputerLink {
        switch endpoint {
        case .local(let url): HTTPComputerLink(baseURL: url)
        case .onion(let host): TorComputerLink(onion: host)
        }
    }
}
