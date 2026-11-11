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

    /// The torrc. Paths quoted (escaped); `__OwningControllerProcess` makes tor exit when this app exits, even after a
    /// crash, so no orphan tor keeps publishing the onion address towards a port another program could take.
    /// The SOCKS port listens on 127.0.0.1 only: the app uses it to check that its onion address answers before
    /// showing the QR code.
    static func torrc(data: String, hs: String, port: UInt16, owner: Int32, socksPort: UInt16) -> String {
        func quoted(_ path: String) -> String {
            "\"" + path.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
        }
        return """
        SocksPort 127.0.0.1:\(socksPort)
        DataDirectory \(quoted(data))
        HiddenServiceDir \(quoted(hs))
        HiddenServicePort 80 127.0.0.1:\(port)
        __OwningControllerProcess \(owner)
        Log notice stdout

        """
    }

    /// Starts tor with an onion service whose port 80 goes to 127.0.0.1:`port` (the port the server got).
    public func start(port: UInt16) {
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
            let torrc = Self.root.appending(path: "torrc")
            guard let socksPort = SocksProbe.freeLocalPort() else {
                state = .failed("aucun port local libre pour tor")
                return
            }
            try Self.torrc(data: data.path, hs: hs.path, port: port, owner: ProcessInfo.processInfo.processIdentifier,
                           socksPort: socksPort)
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
            // code waits until the onion address answers through Tor (at most 5 minutes).
            watch = Task { [weak self] in
                let deadline = Date.now.addingTimeInterval(300)
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
                    try? await Task.sleep(for: .seconds(5))
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
        state = .off
    }
}
