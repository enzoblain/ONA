import Foundation

/// How the phone reaches the computer: `HTTPComputerLink` on the local network (development builds), `TorComputerLink`
/// over Tor to the computer's onion service. A link only carries bytes; `ComputerClient` adds the protocol.
protocol ComputerLink: Sendable {
    /// POSTs a JSON body to `path` (`/v1/…`) and returns the HTTP status and the raw body.
    func post(_ path: String, body: Data) async throws -> RawReply
}

struct RawReply: Sendable {
    let status: Int
    let body: Data
}

/// Paths of protocol v1. Chat ids come from the computer: only safe characters go into a path.
enum Paths {
    static let pair = "/v1/pair"
    static let reveal = "/v1/pair/reveal"
    static let confirm = "/v1/confirm"
    static let chats = "/v1/chats"
    static let list = "/v1/chats/list"

    static func view(_ id: String) -> String { "/v1/chats/\(safe(id))/view" }
    static func messages(_ id: String) -> String { "/v1/chats/\(safe(id))/messages" }
    static func delete(_ id: String) -> String { "/v1/chats/\(safe(id))/delete" }

    static func safe(_ id: String) -> String {
        id.unicodeScalars.allSatisfy { CharacterSet.alphanumerics.contains($0) || $0 == "-" || $0 == "_" } ? id : "invalid"
    }
}

enum LinkError: LocalizedError, Equatable {
    /// The associated text is a sentence for the person (no technical detail).
    case unreachable(String)
    /// The computer answered and refused, with its error code (signed reply).
    case refused(Int, String?)
    /// The reply is not signed by the paired computer: never read, never shown.
    case notAuthenticated
    /// An unsigned failure (unreadable request, computer shutting down).
    case failed(Int)
    case badReply

    var errorDescription: String? {
        switch self {
        case .unreachable(let message): message
        case .refused(_, let code): code.map(ComputerMessages.french) ?? "L'ordinateur a refusé la demande."
        case .notAuthenticated: "Ordinateur non authentifié : la réponse ne vient pas de l'ordinateur appairé."
        case .failed(503): "L'ordinateur est en train de s'arrêter. Réessayez dans un instant."
        case .failed: "L'ordinateur n'a pas pu lire la demande. Mettez ONA à jour des deux côtés."
        case .badReply: "L'ordinateur a répondu de façon inattendue. Mettez ONA à jour des deux côtés."
        }
    }

    /// The error code sent by the computer, if it refused.
    var code: String? {
        if case .refused(_, let code) = self { return code }
        return nil
    }
}

/// French text for the error codes the computer sends back (protocol-draft.md).
enum ComputerMessages {
    static func french(_ error: String) -> String {
        switch error {
        case "stale confirmation": "Cette demande a changé entre-temps : rouvrez-la."
        case "not paired", "unknown pairing", "missing or wrong token":
            "L'ordinateur ne reconnaît plus ce téléphone : refaites l'appairage."
        case "unknown or used pairing code": "Ce code d'appairage a déjà servi : affichez-en un nouveau sur l'ordinateur."
        case "expired pairing code": "Ce code d'appairage a expiré : affichez-en un nouveau sur l'ordinateur."
        case "pairing commitment does not match", "pairing signature does not verify":
            "L'appairage a échoué : scannez le nouveau code affiché sur l'ordinateur."
        case "signature does not verify", "missing or malformed signature":
            "L'ordinateur a rejeté la signature de ce téléphone."
        case "replayed request": "Cette action a déjà été faite."
        case "could not save on the computer": "L'ordinateur n'a pas pu enregistrer : réessayez."
        case "unknown chat": "Cette conversation n'existe plus."
        case "empty or too long message": "Message vide ou trop long."
        case "payment digest does not match", "digest does not match the payment screen":
            "Le paiement a changé : vérifiez-le à nouveau."
        case "unexpected host", "browser requests are refused":
            "L'ordinateur a refusé la connexion : mettez ONA à jour des deux côtés."
        default: "L'ordinateur a refusé la demande (\(error))."
        }
    }
}

/// The protocol on top of a link: a fresh nonce per request, and every reply checked with the computer's key before
/// it is read (docs/ios/protocol-draft.md, « Réponses signées par l'ordinateur »).
struct ComputerClient: Sendable {
    let link: any ComputerLink
    /// The computer's P-256 public key, from the pairing QR.
    let computerKey: Data

    /// Sends `fields` (plus a new `nonce`) and returns the verified reply, decoded. A signed refusal throws `.refused`.
    func call<T: Decodable & Sendable>(_ path: String, _ fields: [String: any Sendable], as type: T.Type = T.self) async throws -> T {
        let reply = try await verifiedReply(path, fields)
        guard (200..<300).contains(reply.status) else {
            let error = (try? JSONSerialization.jsonObject(with: reply.text)) as? [String: Any]
            throw LinkError.refused(reply.status, error?["error"] as? String)
        }
        do {
            return try ProtocolCoding.decoder.decode(T.self, from: reply.text)
        } catch {
            throw LinkError.badReply
        }
    }

    /// The reply text, only if the computer signed it for this very request.
    func verifiedReply(_ path: String, _ fields: [String: any Sendable]) async throws -> (status: Int, text: Data) {
        let nonce = SignedFields.randomHex16()
        var body = fields
        body["nonce"] = nonce
        let json = try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])
        let raw = try await link.post(path, body: json)
        return try Self.verify(raw, nonce: nonce, path: path, computerKey: computerKey)
    }

    /// Checks the envelope `{"reply": "<text>", "signature": "<base64>"}`: the signature covers the nonce, method,
    /// path, status and the exact reply text (as decoded from the envelope, never re-encoded).
    static func verify(_ raw: RawReply, nonce: String, path: String, computerKey: Data) throws
        -> (status: Int, text: Data) {
        guard let envelope = (try? JSONSerialization.jsonObject(with: raw.body)) as? [String: Any],
              let reply = envelope["reply"] as? String,
              let signature = envelope["signature"] as? String
        else {
            // Only these may come unsigned, and they are always failures; their body is never read.
            if [400, 413, 431, 503].contains(raw.status) { throw LinkError.failed(raw.status) }
            throw LinkError.notAuthenticated
        }
        let text = Data(reply.utf8)
        let message = SignedFields.replyMessage(nonce: nonce, method: "POST", path: path, status: raw.status, reply: text)
        guard SignedFields.verify(signature: signature, of: message, by: computerKey) else {
            throw LinkError.notAuthenticated
        }
        return (raw.status, text)
    }
}

/// HTTP over URLSession on the local network (development builds). Ephemeral session: no cache, no cookies.
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

    func post(_ path: String, body: Data) async throws -> RawReply {
        var request = URLRequest(url: baseURL.appending(path: String(path.drop(while: { $0 == "/" }))))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = body
        do {
            let (data, response) = try await session.data(for: request)
            return RawReply(status: (response as? HTTPURLResponse)?.statusCode ?? 0, body: data)
        } catch {
            throw LinkError.unreachable("Impossible de joindre l'ordinateur. Vérifiez qu'il est allumé et sur le même réseau.")
        }
    }
}
