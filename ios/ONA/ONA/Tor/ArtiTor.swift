import ArtiBridge
import Foundation

/// The app's Tor client: Arti embedded through the Rust `arti-bridge` library (ios/ArtiBridge).
///
/// Bridge calls block, so they run on a private serial queue. One Tor client per process.
final class ArtiTor: Sendable {
    static let shared = ArtiTor()

    private let queue = DispatchQueue(label: "org.ona.remote.arti", qos: .userInitiated)
    private let bootstrapTask = BootstrapOnce()

    private init() {
        arti_bridge_init_logging("warn")
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

    /// Starts Tor if needed and waits until it can carry traffic. Concurrent callers share one bootstrap.
    func ready() async throws {
        try await bootstrapTask.run { [self] in
            try FileManager.default.createDirectory(at: Self.stateDir, withIntermediateDirectories: true)
            try FileManager.default.createDirectory(at: Self.cacheDir, withIntermediateDirectories: true)
            let _: Empty = try await call {
                Self.stateDir.path.withCString { state in
                    Self.cacheDir.path.withCString { cache in arti_bridge_bootstrap(state, cache) }
                }
            }
        }
    }

    /// Bootstrap progress; does not block.
    func status() -> Status? {
        try? Self.decode(arti_bridge_status())
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

    // MARK: - Storage

    /// Arti's state (guards) and cache (consensus, descriptors), under Library/Caches: not backed up, purgeable by
    /// iOS. Keeping them makes later starts faster; it is an open question for "nothing on disk except pairing".
    static let root = URL.cachesDirectory.appending(path: "arti", directoryHint: .isDirectory)
    static var stateDir: URL { root.appending(path: "state", directoryHint: .isDirectory) }
    static var cacheDir: URL { root.appending(path: "cache", directoryHint: .isDirectory) }

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
        guard let pointer else { throw LinkError.unreachable("Tor : réponse vide du pont") }
        defer { arti_bridge_string_free(pointer) }
        let data = Data(bytes: pointer, count: strlen(pointer))
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        let envelope = try decoder.decode(Envelope.self, from: data)
        guard envelope.ok else { throw LinkError.unreachable("Tor : \(envelope.error ?? "erreur inconnue")") }
        return try decoder.decode(T.self, from: data)
    }
}

/// Runs an async job once; later callers wait for the same job. A failed job can be retried.
private actor BootstrapOnce {
    private var task: Task<Void, Error>?

    func run(_ job: @escaping @Sendable () async throws -> Void) async throws {
        if let task {
            do {
                return try await task.value
            } catch {
                self.task = nil
                throw error
            }
        }
        let task = Task { try await job() }
        self.task = task
        do {
            try await task.value
        } catch {
            self.task = nil
            throw error
        }
    }
}
