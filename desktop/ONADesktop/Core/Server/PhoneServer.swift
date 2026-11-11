import Foundation
import Network

/// Listens for the phone (Network.framework): one HTTP request per connection, answered by `PhoneRouter`.
public final class PhoneServer: @unchecked Sendable {
    public enum Exposure: Sendable {
        /// 127.0.0.1 only: reachable through the onion service (Tor) running on this Mac.
        case localhost
        /// All interfaces: reachable from the local network. For tests only.
        case localNetwork
    }

    public let port: UInt16
    /// Called with nil when listening, or with a message when listening failed (the server retries by itself).
    public var onState: (@Sendable (String?) -> Void)?
    private var listener: NWListener?
    private var exposure: Exposure = .localhost
    private let queue = DispatchQueue(label: "org.ona.desktop.server")
    private let handle: @Sendable (HTTPRequest) async -> HTTPResponse

    public init(port: UInt16, handle: @escaping @Sendable (HTTPRequest) async -> HTTPResponse) {
        self.port = port
        self.handle = handle
    }

    public func start(_ exposure: Exposure) throws {
        stop()
        self.exposure = exposure
        let parameters = NWParameters.tcp
        parameters.allowLocalEndpointReuse = true
        if exposure == .localhost {
            parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!)
            listener = try NWListener(using: parameters)
        } else {
            listener = try NWListener(using: parameters, on: NWEndpoint.Port(rawValue: port)!)
        }
        listener?.newConnectionHandler = { [weak self] connection in self?.serve(connection) }
        listener?.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.onState?(nil)
            case .failed(let error):
                self.onState?("Écoute impossible sur le port \(self.port) : \(error.localizedDescription). Nouvel essai…")
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
    }

    private func serve(_ connection: NWConnection) {
        connection.start(queue: queue)
        receive(connection, buffer: Data())
        // A connection that never completes its request is dropped.
        queue.asyncAfter(deadline: .now() + 30) { connection.cancel() }
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
