import Foundation

/// The protocol over Tor: HTTP/1.0 to port 80 of the computer's onion service, through Arti.
/// The onion address authenticates the computer: only the holder of its key can answer there.
struct TorComputerLink: ComputerLink {
    let onion: String
    /// The client key of the computer's restricted onion service, given to Arti before the first request.
    var auth: Data?
    var tor: ArtiTor = .shared

    /// Arti's bridge sends `Host: <onion>`, which the computer requires, and no `Origin`.
    ///
    /// The first circuit to an onion service sometimes stays stuck (docs/ios/app.md, 2026-11-11). The bridge already
    /// starts a new attempt every 20 s; if the stream still did not open, nothing reached the computer, so the request
    /// is sent once more.
    func post(_ path: String, body: Data) async throws -> RawReply {
        var attempts = 0
        while true {
            attempts += 1
            do {
                if let auth { try await tor.setOnionAuth(host: onion, key: auth) }
                let response = try await tor.request(host: onion, method: "POST", path: path, body: body)
                return RawReply(status: response.status, body: response.body)
            } catch let error as TorError where error.nothingSent && attempts < 2 {
                continue
            } catch let error as TorError {
                throw LinkError.unreachable(error.localizedDescription)
            }
        }
    }
}

enum AppLinks {
    /// The app's link factory: local HTTP, or Tor for an onion address.
    static func make(_ endpoint: Endpoint) -> any ComputerLink {
        switch endpoint {
        case .local(let url): HTTPComputerLink(baseURL: url)
        case .onion(let host, let auth): TorComputerLink(onion: host, auth: auth)
        }
    }
}
