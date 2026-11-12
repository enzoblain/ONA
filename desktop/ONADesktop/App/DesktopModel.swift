import Foundation
import Observation

/// Everything the Mac app runs: pairing, the phone server, the onion service, the agent's conversations.
@MainActor
@Observable
final class DesktopModel {
    enum ConnectionMode: String, CaseIterable, Identifiable {
        /// The phone reaches this Mac through Tor (onion service). The server listens on 127.0.0.1 only.
        case tor
        /// The phone reaches this Mac on the local network, in plain HTTP. Debug builds only.
        case localNetwork

        var id: String { rawValue }
        var label: String { self == .tor ? "Par Tor" : "Réseau local (développement)" }

        /// The modes this build offers.
        static var available: [ConnectionMode] { LocalModePolicy.allowed ? allCases : [.tor] }
    }

    let pairing: PairingAuthority
    let engine: ChatEngine
    let tor = TorService()
    private(set) var serverError: String?
    /// Set when the app's folder could not be kept out of Time Machine.
    private(set) var backupError: String?
    private(set) var lastPhoneRequest: String?
    private(set) var lastPhoneContact: Date?
    /// The port the server got (chosen by the system in Tor mode).
    private(set) var port: UInt16?

    var mode: ConnectionMode {
        didSet {
            guard mode != oldValue else { return }
            if mode == .localNetwork && !LocalModePolicy.allowed { mode = .tor; return }
            UserDefaults.standard.set(mode.rawValue, forKey: "connectionMode")
            startServing()
        }
    }

    /// Port of the local-network mode (debug builds). Tor mode uses a port chosen by the system.
    static let localPort: UInt16 = 8790

    private var server: PhoneServer?
    private var router: PhoneRouter?
    private var ticker: Task<Void, Never>?
    /// The client key tor was started with.
    private var torAuth: String?

    init() {
        // Kept out of Time Machine: the onion key and tor's state. Shown in the window if it fails.
        do { try BackupExclusion.exclude() } catch { backupError = "Exclusion des sauvegardes impossible : \(error.localizedDescription)" }
        pairing = PairingAuthority(name: Host.current().localizedName ?? "Mon Mac", store: KeychainPairingStore())
        let tor = self.tor
        // Read when each core is made: a change to model.json, or tor becoming ready, applies to the next conversation.
        // The pool's core (pool.json): one for the app, made again when tor's port for the core changes.
        engine = ChatEngine(makeCore: { OnaCoreMission(setup: RealModel.setup(coreSocks: tor.coreSocks)) },
                            makePoolCore: { OnaCoreMission(setup: RealModel.poolSetup(coreSocks: tor.coreSocks)) })
        mode = ConnectionMode(rawValue: LocalModePolicy.resolve(stored: UserDefaults.standard.string(forKey: "connectionMode"))) ?? .tor
        let router = PhoneRouter(pairing: pairing, engine: engine)
        router.onRequest = { [weak self] line in
            self?.lastPhoneRequest = line
            self?.lastPhoneContact = .now
        }
        router.allowedHosts = { [weak self] in self?.allowedHosts ?? [] }
        self.router = router
        startServing()
        ticker = Task { [weak self] in
            var poolSocks: UInt16?
            while !Task.isCancelled {
                try? await Task.sleep(for: .milliseconds(1500))
                guard let self else { return }
                self.engine.tick()
                self.pairing.tick()
                // A phone forgotten: a new client key, and the onion service published again for it only.
                if self.mode == .tor, self.port != nil, self.pairing.onionClientAuth != self.torAuth {
                    self.startServing()
                }
                // The pool core goes through tor's port only: made again through the new one (or refusing without tor).
                let socks = self.tor.coreSocks
                if socks != poolSocks {
                    poolSocks = socks
                    self.engine.resetPool()
                }
            }
        }
    }

    /// (Re)starts the phone server; in Tor mode, the onion service starts once the server listens, on its port.
    /// While listening fails, tor stays stopped.
    func startServing() {
        server?.stop()
        tor.stop()
        port = nil
        let router = self.router
        let server = PhoneServer(port: mode == .tor ? 0 : Self.localPort) { request in
            await MainActor.run { router?.handle(request) ?? HTTPResponse(status: 503, json: [:]) }
        }
        server.onState = { [weak self] message, port in
            Task { @MainActor in
                guard let self else { return }
                self.serverError = message
                self.port = port
                if let port, self.mode == .tor {
                    self.tor.relayOnion = RealModel.relayOnion()
                    self.torAuth = self.pairing.onionClientAuth
                    self.tor.start(port: port, clientAuth: self.torAuth)
                } else if port == nil { self.tor.stop() }
            }
        }
        do {
            try server.start(mode == .tor ? .localhost : .localNetwork)
            serverError = nil
        } catch {
            serverError = "Écoute impossible : \(error.localizedDescription)"
        }
        self.server = server
    }

    func stop() {
        server?.stop()
        tor.stop()
    }

    /// The `Host` values the server answers to.
    var allowedHosts: [String] {
        guard let port else { return [] }
        var hosts = ["127.0.0.1:\(port)"]
        switch mode {
        case .tor:
            if let onion = tor.onion { hosts += [onion, "\(onion):80"] }
        case .localNetwork:
            if let ip = LocalAddress.ipv4() { hosts.append("\(ip):\(port)") }
        }
        return hosts
    }

    /// Text of the pairing QR code for the current mode, or nil while it cannot be built yet.
    var pairingPayload: String? {
        switch mode {
        case .tor:
            guard let onion = tor.onion else { return nil }
            return pairing.payload(address: nil, onion: onion)
        case .localNetwork:
            guard let reachable = reachableAt else { return nil }
            return pairing.payload(address: reachable, onion: nil)
        }
    }

    /// Where the phone reaches this Mac, as shown to the person.
    var reachableAt: String? {
        switch mode {
        case .tor: tor.onion
        case .localNetwork:
            if let ip = LocalAddress.ipv4(), let port { "http://\(ip):\(port)" } else { nil }
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
