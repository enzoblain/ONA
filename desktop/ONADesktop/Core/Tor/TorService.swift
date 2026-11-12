import Foundation
import Observation

/// Publishes the phone server as an onion service with the local `tor` daemon (Homebrew), like docs/TOR.md does for
/// the relay. The onion key stays in ~/Library/Application Support/ONA/tor/hs on this Mac.
@MainActor
@Observable
public final class TorService {
    public enum State: Equatable {
        case off
        case missing
        /// tor runs; the onion service is not reachable yet (no QR code).
        case starting
        /// The onion address answered through Tor: the phone can reach this Mac.
        case published(String)
        case failed(String)
    }

    public private(set) var state: State = .off
    /// tor's second SOCKS port, for everything ona-core sends (the relay, the pool agent, NEAR RPC nodes).
    private var coreSocksPort: UInt16?
    private var process: Process?
    private var watch: Task<Void, Never>?

    public static let candidates = ["/opt/homebrew/bin/tor", "/usr/local/bin/tor"]
    public static var binary: String? { candidates.first { FileManager.default.isExecutableFile(atPath: $0) } }

    static var root: URL {
        URL.applicationSupportDirectory.appending(path: "ONA/tor", directoryHint: .isDirectory)
    }

    public init() {}

    public var onion: String? {
        if case .published(let host) = state { return host }
        return nil
    }

    /// The SOCKS port for ona-core, once the onion service answers (so tor is connected to the network).
    public var coreSocks: UInt16? {
        if case .published = state { return coreSocksPort }
        return nil
    }

    /// The torrc. Paths quoted (escaped); `__OwningControllerProcess` makes tor exit when this app exits, even after a
    /// crash, so no orphan tor keeps publishing the onion address towards a port another program could take.
    /// The SOCKS port listens on 127.0.0.1 only: the app uses it to check that its onion address answers before
    /// showing the QR code; OnionTrafficOnly keeps other local programs from using it as a general anonymous proxy, and
    /// ExtendedErrors makes tor say "missing client authorization" for a restricted service it found (`SocksProbe`).
    /// The second port is ona-core's: the relay and the NEAR RPC nodes are ordinary host names, so it cannot be
    /// onion-only.
    static func torrc(data: String, hs: String, port: UInt16, owner: Int32, socksPort: UInt16, coreSocksPort: UInt16) -> String {
        func quoted(_ path: String) -> String {
            "\"" + path.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
        }
        return """
        SocksPort 127.0.0.1:\(socksPort) OnionTrafficOnly ExtendedErrors
        SocksPort 127.0.0.1:\(coreSocksPort)
        DataDirectory \(quoted(data))
        HiddenServiceDir \(quoted(hs))
        HiddenServicePort 80 127.0.0.1:\(port)
        __OwningControllerProcess \(owner)
        Log notice stdout

        """
    }

    /// Starts tor with an onion service whose port 80 goes to 127.0.0.1:`port` (the port the server got).
    /// With `clientAuth` (a line `descriptor:x25519:<key>`), the service is published for that client key only
    /// (restricted discovery): a Tor client without the key cannot even find it.
    public func start(port: UInt16, clientAuth: String? = nil) {
        stop()
        guard let binary = Self.binary else {
            state = .missing
            return
        }
        do {
            let hs = Self.root.appending(path: "hs"), data = Self.root.appending(path: "data")
            for dir in [hs, data] {
                try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                        attributes: [.posixPermissions: 0o700])
                try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dir.path)
            }
            // tor reads the authorized clients when it starts: the folder holds the current phone's key only.
            let clients = hs.appending(path: "authorized_clients")
            try? FileManager.default.removeItem(at: clients)
            if let clientAuth {
                try FileManager.default.createDirectory(at: clients, withIntermediateDirectories: true,
                                                        attributes: [.posixPermissions: 0o700])
                let file = clients.appending(path: "phone.auth")
                FileManager.default.createFile(atPath: file.path, contents: Data((clientAuth + "\n").utf8),
                                               attributes: [.posixPermissions: 0o600])
            }
            let torrc = Self.root.appending(path: "torrc")
            guard let socksPort = SocksProbe.freeLocalPort(), let coreSocksPort = SocksProbe.freeLocalPort(),
                  socksPort != coreSocksPort else {
                state = .failed("aucun port local libre pour tor")
                return
            }
            self.coreSocksPort = coreSocksPort
            try Self.torrc(data: data.path, hs: hs.path, port: port, owner: ProcessInfo.processInfo.processIdentifier,
                           socksPort: socksPort, coreSocksPort: coreSocksPort)
                .write(to: torrc, atomically: true, encoding: .utf8)

            let process = Process()
            process.executableURL = URL(fileURLWithPath: binary)
            process.arguments = ["-f", torrc.path]
            process.standardOutput = FileHandle.nullDevice
            process.standardError = FileHandle.nullDevice
            process.terminationHandler = { [weak self] _ in
                Task { @MainActor in
                    if case .published = self?.state {} else if self?.state != .off { self?.state = .failed("tor s'est arrêté") }
                }
            }
            try process.run()
            self.process = process
            state = .starting
            let hostname = hs.appending(path: "hostname")
            // The `hostname` file stays from one launch to the next: it does not mean the service is published. The QR
            // code waits until the onion address answers through Tor (at most 10 minutes). No attempt in the first 45 s,
            // then one every 30 s: each attempt that finds no descriptor uses up one of the directories holding it, and
            // tor does not ask it again for 15 minutes (attempts 5 s apart from the start left tor answering "not
            // found" long after the descriptor was there, 2026-11-12).
            watch = Task { [weak self] in
                let deadline = Date.now.addingTimeInterval(600)
                try? await Task.sleep(for: .seconds(45))
                while Date.now < deadline, !Task.isCancelled {
                    if let host = try? String(contentsOf: hostname, encoding: .utf8)
                        .trimmingCharacters(in: .whitespacesAndNewlines), host.hasSuffix(".onion") {
                        let reached = await Task.detached {
                            (try? SocksProbe.reach(socksPort: socksPort, host: host)) != nil
                        }.value
                        if reached, !Task.isCancelled {
                            self?.state = .published(host)
                            return
                        }
                    }
                    try? await Task.sleep(for: .seconds(30))
                }
                if !Task.isCancelled { self?.state = .failed("le service .onion ne répond pas par Tor") }
            }
        } catch {
            state = .failed(error.localizedDescription)
        }
    }

    public func stop() {
        watch?.cancel()
        watch = nil
        process?.terminationHandler = nil
        process?.terminate()
        process = nil
        coreSocksPort = nil
        state = .off
    }
}
