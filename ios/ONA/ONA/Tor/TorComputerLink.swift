import Foundation

/// The protocol over Tor: HTTP/1.0 to port 80 of the computer's onion service, through Arti.
/// The onion address authenticates the computer: only the holder of its key can answer there.
struct TorComputerLink: ComputerLink {
    let onion: String
    var tor: ArtiTor = .shared

    /// Arti's bridge sends `Host: <onion>`, which the computer requires, and no `Origin`.
    func post(_ path: String, body: Data) async throws -> RawReply {
        do {
            let response = try await tor.request(host: onion, method: "POST", path: path, body: body)
            return RawReply(status: response.status, body: response.body)
        } catch let error as TorError {
            throw LinkError.unreachable(error.localizedDescription)
        }
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
