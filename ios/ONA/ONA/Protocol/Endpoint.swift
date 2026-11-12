import Foundation

/// Where the computer is reached.
enum Endpoint: Equatable, Sendable {
    /// Plain HTTP on the local network: development builds only.
    case local(URL)
    /// The computer's onion service, through Tor (Arti embedded in the app). Port 80 of the onion service. `auth`: the
    /// client key of a restricted service (Tor client authorization).
    case onion(String, auth: Data?)

    /// The endpoint named by a pairing: the onion address when there is one, otherwise the local address.
    init?(onion: String?, address: URL?, onionAuth: Data? = nil) {
        if let onion, onion.hasSuffix(".onion") {
            self = .onion(onion, auth: onionAuth)
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

    func post(_ path: String, body: Data) async throws -> RawReply { throw LinkError.unreachable(reason) }
}
