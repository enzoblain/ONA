import ArtiBridge
import Foundation

/// Swift face of the Rust `arti-bridge` static library (Arti embedded).
///
/// Blocking bridge calls run on a private serial queue, never on the main thread nor on the Swift concurrency pool.
/// One Tor client per process, as in the bridge.
final class TorEngine: Sendable {
    static let shared = TorEngine()

    private let queue = DispatchQueue(label: "ona.torspike.arti", qos: .userInitiated)

    private init() {
        arti_bridge_init_logging("info")
    }

    // MARK: - Calls

    /// Library versions, as reported by the bridge.
    func version() throws -> Version {
        try Self.decode(arti_bridge_version())
    }

    /// Creates the Tor client and waits until it can carry traffic.
    func bootstrap(directories: ArtiDirectories) async throws -> Bootstrap {
        try await run {
            directories.state.path.withCString { state in
                directories.cache.path.withCString { cache in
                    arti_bridge_bootstrap(state, cache)
                }
            }
        }
    }

    /// Bootstrap progress. Does not block: safe from the main thread.
    func status() -> Status {
        (try? Self.decode(arti_bridge_status())) ?? Status(started: false, progress: 0, ready: false, description: "?")
    }

    /// Plain HTTP/1.0 GET over a Tor stream (the host can be a `.onion` address).
    func httpGet(host: String, port: UInt16, path: String, timeout: Duration) async throws -> HTTPResult {
        let millis = UInt64(timeout.components.seconds) * 1000
        return try await run {
            host.withCString { host in
                path.withCString { path in
                    arti_bridge_http_get(host, port, path, millis)
                }
            }
        }
    }

    /// Suspends (or resumes) Arti's background tasks.
    func setDormant(_ dormant: Bool) {
        arti_bridge_set_dormant(dormant)
    }

    /// Drops the Tor client. The next bootstrap starts a new one.
    func shutdown() async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            queue.async {
                arti_bridge_shutdown()
                continuation.resume()
            }
        }
    }

    // MARK: - Results (JSON from the bridge, snake_case)

    struct Version: Decodable, Sendable {
        let bridge: String
        let artiClient: String
    }

    struct Bootstrap: Decodable, Sendable {
        let bootstrapMs: UInt64?
        let alreadyStarted: Bool?
    }

    struct Status: Decodable, Sendable {
        let started: Bool
        let progress: Double
        let ready: Bool
        let description: String
    }

    struct HTTPResult: Decodable, Sendable {
        let connectMs: UInt64
        let totalMs: UInt64
        let statusLine: String
        let bytes: Int
        let body: String
    }

    struct BridgeError: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    // MARK: - Plumbing

    private func run<T: Decodable & Sendable>(
        _ call: @escaping @Sendable () -> UnsafeMutablePointer<CChar>?
    ) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                continuation.resume(with: Result { try Self.decode(call()) })
            }
        }
    }

    private struct Envelope: Decodable {
        let ok: Bool
        let error: String?
    }

    /// Decodes and frees a JSON string returned by the bridge.
    private static func decode<T: Decodable>(_ pointer: UnsafeMutablePointer<CChar>?) throws -> T {
        guard let pointer else { throw BridgeError(message: "arti-bridge returned null") }
        defer { arti_bridge_string_free(pointer) }
        let data = Data(bytes: pointer, count: strlen(pointer))

        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        let envelope = try decoder.decode(Envelope.self, from: data)
        guard envelope.ok else { throw BridgeError(message: envelope.error ?? "unknown arti-bridge error") }
        return try decoder.decode(T.self, from: data)
    }
}

/// Where Arti keeps its state (guards) and its cache (consensus, descriptors).
///
/// Both live under Library/Caches: excluded from backups, and iOS may purge them. Keeping them between launches is
/// what makes a warm start possible; it is also an open question for ONA ("nothing on disk except pairing").
struct ArtiDirectories: Sendable {
    let root: URL
    var state: URL { root.appending(path: "state", directoryHint: .isDirectory) }
    var cache: URL { root.appending(path: "cache", directoryHint: .isDirectory) }

    static let standard = ArtiDirectories(
        root: URL.cachesDirectory.appending(path: "arti", directoryHint: .isDirectory)
    )

    /// True if a previous run left a cache (warm start).
    var hasCache: Bool {
        let contents = try? FileManager.default.contentsOfDirectory(atPath: cache.path)
        return !(contents ?? []).isEmpty
    }

    func create() throws {
        for dir in [state, cache] {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        }
    }

    /// Deletes everything Arti stored, to measure a cold start.
    func erase() throws {
        if FileManager.default.fileExists(atPath: root.path) {
            try FileManager.default.removeItem(at: root)
        }
    }

    /// Bytes stored on disk by Arti.
    func size() -> Int64 {
        guard let enumerator = FileManager.default.enumerator(
            at: root, includingPropertiesForKeys: [.totalFileAllocatedSizeKey]
        ) else { return 0 }
        var total: Int64 = 0
        for case let url as URL in enumerator {
            let values = try? url.resourceValues(forKeys: [.totalFileAllocatedSizeKey])
            total += Int64(values?.totalFileAllocatedSize ?? 0)
        }
        return total
    }
}
