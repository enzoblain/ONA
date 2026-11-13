import Foundation

/// Pool deposits with the person's own NEAR wallet (docs/desktop/wallet.md), as in the Tauri app (`wallet.rs`).
///
/// The deposit is sent and signed by the person's wallet, never by ONA. The app serves the page of
/// `desktop/wallet-page` on 127.0.0.1, under a random path that works for one deposit; the page sends the `deposit`
/// transaction with NEAR Wallet Selector, the app runs the first `pool_execute` (the cash notes, and the message the
/// agent wants signed), the page has that message signed, and the app runs the second `pool_execute` with it.
@MainActor
public final class WalletPage {
    public enum Step: Equatable {
        case deposit
        /// The agent's message (`sign_message` of the first `pool_execute`), to be signed.
        case sign(NSDictionary)
        case done
    }

    /// One deposit in progress.
    public struct Session {
        public let token: String
        let preparedID: String
        public let account: String
        public let network: String
        let walletCall: [String: Any]
        /// `summary.expires_at`, nanoseconds: the preparation and both `pool_execute` calls end then.
        let expiresAt: UInt64
        public internal(set) var step: Step = .deposit
        var executing = false

        /// From a deposit's `pool_prepare` reply; nil when it is not a deposit or lacks what the page needs.
        public init?(prepared: [String: Any]) {
            guard let summary = prepared["summary"] as? [String: Any], summary["op"] as? String == "deposit",
                  let preparedID = prepared["prepared_id"] as? String, let account = summary["account"] as? String,
                  let network = summary["network"] as? String, let call = summary["wallet_call"] as? [String: Any],
                  call["receiver"] is String, call["method"] is String, call["attached"] is String,
                  let expires = (summary["expires_at"] as? NSNumber)?.uint64Value else { return nil }
            token = ProtocolBytes.randomHex16()
            self.preparedID = preparedID
            self.account = account
            self.network = network
            walletCall = call
            expiresAt = expires
        }

        /// What the page reads: never the prepared id, which is the app's.
        public var state: [String: Any] {
            var state: [String: Any] = ["ok": true, "account": account, "network": network, "wallet_call": walletCall,
                                        "sign_message": NSNull()]
            switch step {
            case .deposit: state["step"] = "deposit"
            case .sign(let message): state["step"] = "sign"; state["sign_message"] = message
            case .done: state["step"] = "done"
            }
            return state
        }
    }

    /// The bundled page (`index.html`, `wallet.js`, `wallet.css`): the app's `dist` resource folder.
    let assets: URL
    /// Runs a pool command on the pool's core (`ChatEngine.pool`).
    let pool: ([String: Any]) async -> [String: Any]
    public private(set) var session: Session?
    private var server: PhoneServer?
    public private(set) var port: UInt16?

    public init(assets: URL, pool: @escaping ([String: Any]) async -> [String: Any]) {
        self.assets = assets
        self.pool = pool
    }

    /// Starts serving a deposit prepared in the pool window and returns the page's address (ending with "/": the page
    /// loads its files next to it). One deposit at a time: a new one replaces the previous page.
    public func open(prepared: [String: Any]) async throws -> URL {
        guard let session = Session(prepared: prepared) else { throw WalletPageError.notADeposit }
        if server == nil {
            let server = PhoneServer(port: 0) { [weak self] request in
                await self?.answer(request) ?? HTTPResponse(status: 503, json: ["ok": false, "error": "stopped"])
            }
            let ready = AsyncStream<UInt16?> { continuation in
                server.onState = { _, port in continuation.yield(port); if port != nil { continuation.finish() } }
            }
            try server.start(.localhost)
            self.server = server
            for await port in ready where port != nil {
                self.port = port
                break
            }
        }
        guard let port else { throw WalletPageError.notListening }
        self.session = session
        return URL(string: "http://127.0.0.1:\(port)/wallet/\(session.token)/")!
    }

    public func stop() {
        server?.stop()
        server = nil
        port = nil
        session = nil
    }

    /// One request of the page.
    func answer(_ request: HTTPRequest) async -> HTTPResponse {
        let refuse = { (status: Int, error: String) in HTTPResponse(status: status, json: ["ok": false, "error": error]) }
        guard let port, var session else { return refuse(404, "no deposit in progress") }
        let now = UInt64(Date.now.timeIntervalSince1970 * 1_000_000_000)
        if now >= session.expiresAt, session.step != .done {
            self.session = nil
            return refuse(410, "this deposit expired: prepare it again in the app")
        }
        let host = "127.0.0.1:\(port)"
        guard case .one(let h) = request.header("host"), h.lowercased() == host else { return refuse(403, "host not allowed") }
        let path = String(request.path.split(whereSeparator: { $0 == "?" || $0 == "#" }).first ?? "")
        let prefix = "/wallet/\(session.token)"
        guard path.hasPrefix(prefix) else { return refuse(404, "not found") }
        let rest = String(path.dropFirst(prefix.count))
        if request.method == "GET" {
            let files = ["": ("index.html", "text/html; charset=utf-8"), "/": ("index.html", "text/html; charset=utf-8"),
                         "/wallet.js": ("wallet.js", "text/javascript; charset=utf-8"),
                         "/wallet.css": ("wallet.css", "text/css; charset=utf-8")]
            guard let (name, type) = files[rest], let data = try? Data(contentsOf: assets.appending(path: name)) else {
                return refuse(404, "not found")
            }
            return HTTPResponse(asset: data, contentType: type)
        }
        guard request.method == "POST" else { return refuse(400, "method not allowed") }
        // A page of another site cannot drive the deposit, even if it guessed the address.
        guard case .one(let origin) = request.header("origin"), origin.lowercased() == "http://\(host)" else {
            return refuse(403, "origin not allowed")
        }
        guard let body = (try? JSONSerialization.jsonObject(with: request.body)) as? [String: Any] else {
            return refuse(400, "body is not JSON")
        }
        var execute: [String: Any]
        switch (rest, session.step) {
        case ("/state", _):
            return HTTPResponse(status: 200, json: session.state)
        case ("/deposited", .deposit):
            execute = ["cmd": "pool_execute", "prepared_id": session.preparedID]
        case ("/signed", .sign):
            guard let key = body["public_key"] as? String, let signature = body["signature"] as? String,
                  !key.isEmpty, !signature.isEmpty, key.count < 512, signature.count < 512 else {
                return refuse(400, "public_key and signature are required")
            }
            execute = ["cmd": "pool_execute", "prepared_id": session.preparedID,
                       "depositor_signature": ["public_key": key, "signature": signature]]
        case ("/deposited", _), ("/signed", _):
            // Sent twice (a page reloaded): the current state, nothing run again.
            return HTTPResponse(status: 200, json: session.state)
        default:
            return refuse(404, "not found")
        }
        if session.executing { return refuse(409, "the previous step is still running") }
        session.executing = true
        self.session = session
        let second = execute["depositor_signature"] != nil
        let reply = await pool(execute)
        guard var current = self.session, current.token == session.token else {
            return refuse(410, "this deposit is no longer in progress")
        }
        current.executing = false
        switch Self.next(after: reply, second: second) {
        case .success(let step):
            current.step = step
            self.session = current
            return HTTPResponse(status: 200, json: current.state)
        case .failure(let error):
            self.session = current
            return refuse(409, error.message)
        }
    }

    struct StepError: Error { let message: String }

    /// What a `pool_execute` reply means for the deposit (same rules as the Tauri app).
    static func next(after reply: [String: Any], second: Bool) -> Result<Step, StepError> {
        let error = reply["error"] as? String ?? "pool_execute failed"
        if second {
            if reply["ok"] as? Bool == true || error.contains("outcome unknown") { return .success(.done) }
            return .failure(StepError(message: error))
        }
        guard reply["ok"] as? Bool == true else { return .failure(StepError(message: error)) }
        if reply["complete"] as? Bool == true { return .success(.done) }
        guard let message = reply["sign_message"] as? [String: Any], message["message"] is String,
              message["recipient"] is String, message["nonce"] is String else {
            return .failure(StepError(message: "no message to sign"))
        }
        return .success(.sign(message as NSDictionary))
    }
}

public enum WalletPageError: LocalizedError {
    case notADeposit
    case notListening

    public var errorDescription: String? {
        switch self {
        case .notADeposit: "Seul un dépôt passe par la page du portefeuille."
        case .notListening: "La page du portefeuille n'a pas pu démarrer."
        }
    }
}
