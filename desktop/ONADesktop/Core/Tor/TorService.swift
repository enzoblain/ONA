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
        case starting
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

    /// Starts tor with an onion service whose port 80 goes to 127.0.0.1:`port`.
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
            try """
            SocksPort 0
            DataDirectory \(data.path)
            HiddenServiceDir \(hs.path)
            HiddenServicePort 80 127.0.0.1:\(port)
            Log notice stdout
            """.write(to: torrc, atomically: true, encoding: .utf8)

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
            watch = Task { [weak self] in
                for _ in 0..<120 {
                    if let host = try? String(contentsOf: hostname, encoding: .utf8)
                        .trimmingCharacters(in: .whitespacesAndNewlines), host.hasSuffix(".onion") {
                        self?.state = .published(host)
                        return
                    }
                    try? await Task.sleep(for: .seconds(1))
                }
                self?.state = .failed("l'adresse .onion n'est pas apparue")
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
