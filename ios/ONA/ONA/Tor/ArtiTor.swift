import ArtiBridge
import Foundation

/// The app's Tor client: Arti embedded through the Rust `arti-bridge` library (ios/ArtiBridge).
///
/// Bridge calls block, so they run on a private serial queue. One Tor client per process.
final class ArtiTor: Sendable {
    static let shared = ArtiTor()

    private let queue = DispatchQueue(label: "org.ona.remote.arti", qos: .userInitiated)
    private let bootstrap = BootstrapOnce()

    private init() {
        #if DEBUG
        arti_bridge_init_logging("warn")
        #endif
    }

    struct Response: Sendable {
        let status: Int
        let body: Data
    }

    struct Status: Decodable, Sendable {
        let started: Bool
        let progress: Double
        let ready: Bool
        let description: String
    }

    /// Version of Arti in this build, e.g. "0.48.0".
    var artiVersion: String? {
        struct Version: Decodable { let artiClient: String }
        let version: Version? = try? Self.decode(arti_bridge_version())
        return version?.artiClient
    }

    /// Starts Tor if needed and waits until it can carry traffic (at most 120 s). Concurrent callers share one start.
    func ready() async throws {
        try await bootstrap.run { [self] in
            try FileManager.default.createDirectory(at: Self.stateDir, withIntermediateDirectories: true)
            try FileManager.default.createDirectory(at: Self.cacheDir, withIntermediateDirectories: true)
            let _: Empty = try await call {
                Self.stateDir.path.withCString { state in
                    Self.cacheDir.path.withCString { cache in arti_bridge_bootstrap(state, cache) }
                }
            }
        }
    }

    /// Stops Tor. The next request starts it again.
    func stop() async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            queue.async {
                arti_bridge_shutdown()
                continuation.resume()
            }
        }
        await bootstrap.reset()
    }

    /// Progress of the running client; nil when Tor is stopped. Does not block.
    func status() -> Status? {
        guard let status: Status = try? Self.decode(arti_bridge_status()), status.started else { return nil }
        return status
    }

    func request(host: String, port: UInt16 = 80, method: String, path: String, body: Data?,
                 timeout: Duration = .seconds(60)) async throws -> Response {
        try await ready()
        let millis = UInt64(timeout.components.seconds) * 1000
        let reply: Reply = try await call {
            let payload = body ?? Data()
            return host.withCString { host in
                method.withCString { method in
                    path.withCString { path in
                        payload.withUnsafeBytes { raw in
                            arti_bridge_http_request(host, port, method, path,
                                                     raw.bindMemory(to: UInt8.self).baseAddress, raw.count, millis)
                        }
                    }
                }
            }
        }
        return Response(status: reply.status, body: Data(reply.body.utf8))
    }

    /// Suspends Arti's background work while the app is in the background.
    func setDormant(_ dormant: Bool) {
        arti_bridge_set_dormant(dormant)
    }

    // MARK: - Data kept on the phone

    /// Arti's state (guards) and cache (network directory), under Library/Caches: not backed up, purgeable by iOS.
    /// Keeping them makes the next start faster.
    static let root = URL.cachesDirectory.appending(path: "arti", directoryHint: .isDirectory)
    static var stateDir: URL { root.appending(path: "state", directoryHint: .isDirectory) }
    static var cacheDir: URL { root.appending(path: "cache", directoryHint: .isDirectory) }

    /// Bytes Tor keeps on this phone.
    static func dataSize() -> Int64 {
        guard let files = FileManager.default.enumerator(at: root, includingPropertiesForKeys: [.totalFileAllocatedSizeKey])
        else { return 0 }
        var total: Int64 = 0
        for case let url as URL in files {
            total += Int64((try? url.resourceValues(forKeys: [.totalFileAllocatedSizeKey]))?.totalFileAllocatedSize ?? 0)
        }
        return total
    }

    /// Deletes Tor's data. Call only while Tor is stopped.
    static func eraseData() throws {
        if FileManager.default.fileExists(atPath: root.path) {
            try FileManager.default.removeItem(at: root)
        }
    }

    // MARK: - Plumbing

    private struct Empty: Decodable {}

    private struct Reply: Decodable {
        let status: Int
        let body: String
    }

    private struct Envelope: Decodable {
        let ok: Bool
        let error: String?
    }

    private func call<T: Decodable & Sendable>(
        _ body: @escaping @Sendable () -> UnsafeMutablePointer<CChar>?
    ) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                continuation.resume(with: Result { try Self.decode(body()) })
            }
        }
    }

    private static func decode<T: Decodable>(_ pointer: UnsafeMutablePointer<CChar>?) throws -> T {
        guard let pointer else { throw TorError(detail: "empty reply from arti-bridge") }
        defer { arti_bridge_string_free(pointer) }
        let data = Data(bytes: pointer, count: strlen(pointer))
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        let envelope = try decoder.decode(Envelope.self, from: data)
        guard envelope.ok else { throw TorError(detail: envelope.error ?? "unknown error") }
        return try decoder.decode(T.self, from: data)
    }
}

/// A Tor failure: a sentence for the person, and the bridge's technical detail for the "Détails" section.
struct TorError: LocalizedError, Sendable {
    let detail: String

    var errorDescription: String? {
        if detail.contains("bootstrap timed out") || detail.hasPrefix("bootstrap") {
            "Tor n'a pas pu démarrer. Ce réseau bloque peut-être Tor : essayez un autre réseau."
        } else if detail.contains("hidden service") || detail.contains("onion") {
            "Impossible de joindre l'ordinateur par Tor. Vérifiez qu'il est allumé et que ONA y est ouvert."
        } else if detail.contains("timed out") {
            "L'ordinateur n'a pas répondu à temps par Tor."
        } else {
            "Erreur de connexion Tor."
        }
    }
}

/// Runs an async job once; later callers wait for the same job. A failed job can be retried.
private actor BootstrapOnce {
    private var task: Task<Void, Error>?

    func run(_ job: @escaping @Sendable () async throws -> Void) async throws {
        let task = self.task ?? Task { try await job() }
        self.task = task
        do {
            try await task.value
        } catch {
            if self.task == task { self.task = nil }
            throw error
        }
    }

    func reset() {
        task = nil
    }
}
