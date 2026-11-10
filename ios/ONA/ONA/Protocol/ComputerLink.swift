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
            throw LinkError.unreachable("Impossible de joindre l'ordinateur. Vérifiez qu'il est allumé et sur le même réseau.")
        }
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        return try ProtocolCoding.decodeReply(T.self, status: status, body: data, acceptErrorBody: acceptErrorBody)
    }
}
