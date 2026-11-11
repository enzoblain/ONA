import Foundation
import Network

/// The local-network mode (plain HTTP on every interface) exists in debug builds only.
public enum LocalModePolicy {
    public static var allowed: Bool {
        #if DEBUG
        true
        #else
        false
        #endif
    }

    /// The saved mode ("tor" or "localNetwork"), Tor when absent or not allowed in this build: a choice saved by a
    /// debug build is not honoured by a release build.
    public static func resolve(stored: String?, allowLocal: Bool = allowed) -> String {
        stored == "localNetwork" && allowLocal ? "localNetwork" : "tor"
    }
}

/// Listens for the phone (Network.framework): one HTTP request per connection, answered by `PhoneRouter`.
/// Connections are capped and each request has an overall deadline.
public final class PhoneServer: @unchecked Sendable {
    public enum Exposure: Sendable {
        /// 127.0.0.1 only: reachable through the onion service (Tor) running on this Mac.
        case localhost
        /// All interfaces: reachable from the local network. Debug builds only.
        case localNetwork
    }

    /// Port asked for: 0 lets the system choose (Tor mode), so no other program can take it in advance.
    public let requestedPort: UInt16
    /// The port actually listened on, once ready.
    public private(set) var port: UInt16?
    public let maxConnections: Int
    public let deadline: TimeInterval
    /// Called with nil and the port when listening, or with a message when listening failed (the server retries).
    public var onState: (@Sendable (String?, UInt16?) -> Void)?
    private var listener: NWListener?
    private var exposure: Exposure = .localhost
    private var active = 0
    private let queue = DispatchQueue(label: "org.ona.desktop.server")
    private let handle: @Sendable (HTTPRequest) async -> HTTPResponse

    public init(port: UInt16, maxConnections: Int = 16, deadline: TimeInterval = 10,
                handle: @escaping @Sendable (HTTPRequest) async -> HTTPResponse) {
        requestedPort = port
        self.maxConnections = maxConnections
        self.deadline = deadline
        self.handle = handle
    }

    public func start(_ exposure: Exposure) throws {
        stop()
        self.exposure = exposure
        let parameters = NWParameters.tcp
        // No sharing of the port with another process.
        parameters.allowLocalEndpointReuse = false
        let port = NWEndpoint.Port(rawValue: requestedPort) ?? .any
        if exposure == .localhost {
            parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: port)
            listener = try NWListener(using: parameters)
        } else {
            listener = try NWListener(using: parameters, on: port)
        }
        listener?.newConnectionHandler = { [weak self] connection in self?.accept(connection) }
        listener?.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.port = self.listener?.port?.rawValue
                self.onState?(nil, self.port)
            case .failed(let error):
                self.port = nil
                self.onState?("Écoute impossible : \(error.localizedDescription). Nouvel essai…", nil)
                self.queue.asyncAfter(deadline: .now() + 3) { [weak self] in
                    guard let self, self.listener != nil else { return }
                    try? self.start(self.exposure)
                }
            default:
                break
            }
        }
        listener?.start(queue: queue)
    }

    public func stop() {
        listener?.cancel()
        listener = nil
        port = nil
    }

    /// Runs on `queue`.
    private func accept(_ connection: NWConnection) {
        guard active < maxConnections else { return connection.cancel() }  // over the cap: closed at once
        active += 1
        let slot = Slot()
        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .cancelled, .failed:
                guard let self else { return }
                self.queue.async { self.finish(connection, slot) }
            default: break
            }
        }
        connection.start(queue: queue)
        receive(connection, buffer: Data())
        // The whole request must arrive, and be answered, before the deadline.
        queue.asyncAfter(deadline: .now() + deadline) { [weak self] in self?.finish(connection, slot) }
    }

    /// Whether a connection was already counted out. Touched on `queue` only.
    private final class Slot: @unchecked Sendable {
        var finished = false
    }

    /// Runs on `queue`: frees the connection's place, once.
    private func finish(_ connection: NWConnection, _ slot: Slot) {
        guard !slot.finished else { return }
        slot.finished = true
        active -= 1
        connection.cancel()
    }

    private func receive(_ connection: NWConnection, buffer: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] data, _, complete, error in
            guard let self else { return connection.cancel() }
            var buffer = buffer
            if let data { buffer.append(data) }
            switch HTTPRequest.parse(buffer) {
            case .incomplete:
                if complete || error != nil { return connection.cancel() }
                self.receive(connection, buffer: buffer)
            case .invalid(let status):
                self.reply(connection, HTTPResponse(status: status, json: ["ok": false, "error": "bad request"]))
            case .request(let request):
                Task {
                    let response = await self.handle(request)
                    self.reply(connection, response)
                }
            }
        }
    }

    private func reply(_ connection: NWConnection, _ response: HTTPResponse) {
        connection.send(content: response.bytes, completion: .contentProcessed { _ in connection.cancel() })
    }
}
