import Foundation

/// How the phone reaches the computer: `HTTPComputerLink` on the local network (steps 2–3), `TorComputerLink` over
/// Tor to the computer's onion service (step 4, app only).
protocol ComputerLink: Sendable {
    func state() async throws -> ComputerState
    func pair(_ request: PairRequest) async throws -> Ack
    func confirm(_ confirmation: ConfirmationAnswer) async throws -> Ack
    /// Routes that exist only on the mock computer.
    func mock(_ action: MockAction) async throws -> Ack

    // Conversations
    func chats() async throws -> ChatList
    func chat(_ id: String) async throws -> ChatReply
    func newChat(_ request: ChatMessageRequest) async throws -> NewChatAck
    func send(_ request: ChatMessageRequest, to chatID: String) async throws -> Ack
    func deleteChat(_ chatID: String, _ request: ChatDeleteRequest) async throws -> Ack
}

/// Paths of the conversation routes, shared by both links. Chat ids come from the computer: only safe characters.
enum ChatPaths {
    static let list = "v0/chats"

    static func chat(_ id: String) -> String { "v0/chats/\(safe(id))" }
    static func messages(_ id: String) -> String { "v0/chats/\(safe(id))/messages" }
    static func delete(_ id: String) -> String { "v0/chats/\(safe(id))/delete" }

    static func safe(_ id: String) -> String {
        id.unicodeScalars.allSatisfy { CharacterSet.alphanumerics.contains($0) || $0 == "-" || $0 == "_" } ? id : "invalid"
    }
}

enum MockAction: String, Sendable {
    case start, reset
}

enum LinkError: LocalizedError {
    /// The associated text is a sentence for the person (no technical detail).
    case unreachable(String)
    case badStatus(Int, String?)
    case badReply(String)

    var errorDescription: String? {
        switch self {
        case .unreachable(let message): message
        case .badStatus(_, let message): message.map(ComputerMessages.french) ?? "L'ordinateur a refusé la demande."
        case .badReply: "L'ordinateur a répondu de façon inattendue. Mettez ONA à jour des deux côtés."
        }
    }
}

/// French text for the error codes the computer sends back (protocol-draft.md).
enum ComputerMessages {
    static func french(_ error: String) -> String {
        switch error {
        case "stale confirmation": "Cette demande a changé entre-temps : rouvrez-la."
        case "not paired", "unknown pairing": "L'ordinateur ne reconnaît plus ce téléphone : refaites l'appairage."
        case "unknown or used pairing code": "Ce code d'appairage a déjà servi ou a expiré : affichez-en un nouveau sur l'ordinateur."
        case "pairing signature does not verify", "signature does not verify", "missing or malformed signature":
            "L'ordinateur a rejeté la signature de ce téléphone."
        case "digest does not match the payment screen": "Le paiement a changé : vérifiez-le à nouveau."
        case "no mission": "Aucune mission en cours sur l'ordinateur."
        default: "L'ordinateur a refusé la demande (\(error))."
        }
    }
}

/// HTTP/1.1 + JSON over URLSession. Ephemeral session: no cache, no cookies, nothing written to disk.
struct HTTPComputerLink: ComputerLink {
    let baseURL: URL
    private let session: URLSession

    init(baseURL: URL) {
        self.baseURL = baseURL
        let config = URLSessionConfiguration.ephemeral
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        config.urlCache = nil
        config.httpCookieStorage = nil
        config.timeoutIntervalForRequest = 10
        config.waitsForConnectivity = false
        session = URLSession(configuration: config)
    }

    func state() async throws -> ComputerState {
        try await send(URLRequest(url: baseURL.appending(path: "v0/state")))
    }

    func pair(_ request: PairRequest) async throws -> Ack {
        try await post("v0/pair", body: request)
    }

    func confirm(_ confirmation: ConfirmationAnswer) async throws -> Ack {
        try await post("v0/confirm", body: confirmation)
    }

    func mock(_ action: MockAction) async throws -> Ack {
        try await post("v0/mock/\(action.rawValue)", body: [String: String]())
    }

    func chats() async throws -> ChatList {
        try await send(URLRequest(url: baseURL.appending(path: ChatPaths.list)))
    }

    func chat(_ id: String) async throws -> ChatReply {
        try await send(URLRequest(url: baseURL.appending(path: ChatPaths.chat(id))))
    }

    func newChat(_ request: ChatMessageRequest) async throws -> NewChatAck {
        try await post(ChatPaths.list, body: request)
    }

    func send(_ request: ChatMessageRequest, to chatID: String) async throws -> Ack {
        try await post(ChatPaths.messages(chatID), body: request)
    }

    func deleteChat(_ chatID: String, _ request: ChatDeleteRequest) async throws -> Ack {
        try await post(ChatPaths.delete(chatID), body: request)
    }

    private func post<T: Decodable>(_ path: String, body: some Encodable) async throws -> T {
        var request = URLRequest(url: baseURL.appending(path: path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try ProtocolCoding.encoder.encode(body)
        return try await send(request, acceptErrorBody: true)
    }

    /// `acceptErrorBody`: the POST routes answer 4xx with an `Ack` that carries the reason.
    private func send<T: Decodable>(_ request: URLRequest, acceptErrorBody: Bool = false) async throws -> T {
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw LinkError.unreachable("Impossible de joindre l'ordinateur. Vérifiez qu'il est allumé et sur le même réseau.")
        }
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        return try ProtocolCoding.decodeReply(T.self, status: status, body: data, acceptErrorBody: acceptErrorBody)
    }
}
