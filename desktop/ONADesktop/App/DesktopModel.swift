import Foundation
import Observation

/// Everything the Mac app runs: pairing, the phone server, the onion service, the agent's conversations.
@MainActor
@Observable
final class DesktopModel {
    enum ConnectionMode: String, CaseIterable, Identifiable {
        /// The phone reaches this Mac through Tor (onion service). The server listens on 127.0.0.1 only.
        case tor
        /// The phone reaches this Mac on the local network. For tests.
        case localNetwork

        var id: String { rawValue }
        var label: String { self == .tor ? "Par Tor (recommandé)" : "Réseau local (tests)" }
    }

    let pairing: PairingAuthority
    let engine: ChatEngine
    let tor = TorService()
    private(set) var serverError: String?
    private(set) var lastPhoneRequest: String?
    private(set) var lastPhoneContact: Date?

    var mode: ConnectionMode {
        didSet {
            UserDefaults.standard.set(mode.rawValue, forKey: "connectionMode")
            startServing()
        }
    }

    static let port: UInt16 = 8790

    private var server: PhoneServer?
    private var router: PhoneRouter?
    private var ticker: Task<Void, Never>?

    init() {
        pairing = PairingAuthority(name: Host.current().localizedName ?? "Mon Mac", store: KeychainPairingStore())
        engine = ChatEngine(makeCore: { OnaCoreMission() })
        mode = ConnectionMode(rawValue: UserDefaults.standard.string(forKey: "connectionMode") ?? "") ?? .tor
        let router = PhoneRouter(pairing: pairing, engine: engine)
        router.onRequest = { [weak self] line in
            self?.lastPhoneRequest = line
            self?.lastPhoneContact = .now
        }
        self.router = router
        startServing()
        ticker = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .milliseconds(1500))
                self?.engine.tick()
            }
        }
    }

    /// (Re)starts the phone server, and the onion service when the mode is Tor.
    func startServing() {
        server?.stop()
        tor.stop()
        let router = self.router
        let server = PhoneServer(port: Self.port) { request in
            await MainActor.run { router?.handle(request) ?? HTTPResponse(status: 500, json: [:]) }
        }
        server.onState = { [weak self] message in
            Task { @MainActor in self?.serverError = message }
        }
        do {
            try server.start(mode == .tor ? .localhost : .localNetwork)
            serverError = nil
        } catch {
            serverError = "Le port \(Self.port) n'est pas disponible : \(error.localizedDescription)"
        }
        self.server = server
        if mode == .tor { tor.start(port: Self.port) }
    }

    func stop() {
        server?.stop()
        tor.stop()
    }

    /// Text of the pairing QR code for the current mode, or nil while it cannot be built yet.
    var pairingPayload: String? {
        switch mode {
        case .tor:
            guard let onion = tor.onion else { return nil }
            return pairing.payload(address: nil, onion: onion)
        case .localNetwork:
            guard let ip = LocalAddress.ipv4() else { return nil }
            return pairing.payload(address: "http://\(ip):\(Self.port)", onion: nil)
        }
    }

    /// Where the phone reaches this Mac, as shown to the person.
    var reachableAt: String? {
        switch mode {
        case .tor: tor.onion
        case .localNetwork: LocalAddress.ipv4().map { "http://\($0):\(Self.port)" }
        }
    }
}

enum LocalAddress {
    /// The Mac's IPv4 address on Wi-Fi or Ethernet (en0, en1…).
    static func ipv4() -> String? {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return nil }
        defer { freeifaddrs(list) }
        for pointer in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let entry = pointer.pointee
            guard let address = entry.ifa_addr, address.pointee.sa_family == UInt8(AF_INET),
                  String(cString: entry.ifa_name).hasPrefix("en")
            else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(address, socklen_t(address.pointee.sa_len), &host, socklen_t(host.count), nil, 0,
                           NI_NUMERICHOST) == 0 {
                return String(decoding: host.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
            }
        }
        return nil
    }
}
