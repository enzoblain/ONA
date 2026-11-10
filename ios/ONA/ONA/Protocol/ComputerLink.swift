import Foundation

/// How the phone reaches the computer: `HTTPComputerLink` on the local network (steps 2–3), `TorComputerLink` over
/// Tor to the computer's onion service (step 4, app only).
protocol ComputerLink: Sendable {
    func state() async throws -> ComputerState
    func pair(_ request: PairRequest) async throws -> Ack
    func confirm(_ confirmation: ConfirmationAnswer) async throws -> Ack
    /// Routes that exist only on the mock computer.
    func mock(_ action: MockAction) async throws -> Ack
}

enum MockAction: String, Sendable {
    case start, reset
}

enum LinkError: LocalizedError {
    case unreachable(String)
    case badStatus(Int, String?)
    case badReply(String)

    var errorDescription: String? {
        switch self {
        case .unreachable(let detail): "Ordinateur injoignable (\(detail)). Il doit être allumé."
        case .badStatus(let code, let message): "Réponse \(code)\(message.map { " : \($0)" } ?? "")"
        case .badReply(let detail): "Réponse illisible : \(detail)"
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

    private func post(_ path: String, body: some Encodable) async throws -> Ack {
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
            throw LinkError.unreachable(error.localizedDescription)
        }
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        return try ProtocolCoding.decodeReply(T.self, status: status, body: data, acceptErrorBody: acceptErrorBody)
    }
}
