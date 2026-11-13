import Foundation

/// The phone protocol v1 (docs/ios/protocol-draft.md) on top of the pairing authority and the chat engine.
/// Every request is a POST with a JSON body; every reply is signed with the computer's key. Reads need the token
/// given at pairing; requests that change something are also signed by the phone's key, with a counter.
@MainActor
public final class PhoneRouter {
    let pairing: PairingAuthority
    let engine: ChatEngine
    /// The `Host` values this computer answers to (`127.0.0.1:port`, the onion address, the local address in local
    /// mode). Anything else is refused (DNS rebinding).
    public var allowedHosts: () -> [String] = { [] }
    /// Called after each request, for the Mac's activity line.
    public var onRequest: ((String) -> Void)?

    static let maxNonce = 64
    /// Largest counter accepted, 2^53 − 1 (exact in every JSON implementation). Same bound in the Rust app.
    nonisolated public static let maxCounter: UInt64 = 9_007_199_254_740_991

    /// A request counter: a JSON integer from 0 to `maxCounter`. Fractions (`1.0`), booleans, negatives refused.
    nonisolated static func counter(_ number: NSNumber) -> UInt64? {
        guard CFGetTypeID(number) != CFBooleanGetTypeID(), CFNumberIsFloatType(number) == false,
              number.int64Value >= 0 else { return nil }
        let value = number.uint64Value
        return value <= maxCounter && number == NSNumber(value: value) ? value : nil
    }

    public init(pairing: PairingAuthority, engine: ChatEngine) {
        self.pairing = pairing
        self.engine = engine
    }

    public func handle(_ request: HTTPRequest) -> HTTPResponse {
        let body = request.body.isEmpty
            ? [:] as [String: Any]?
            : (try? JSONSerialization.jsonObject(with: request.body)) as? [String: Any]
        let nonce = (body?["nonce"] as? String).flatMap { $0.utf8.count <= Self.maxNonce ? $0 : nil } ?? ""
        var response = route(request, body)
        response.signature = pairing.signReply(nonce: nonce, method: request.method, path: request.path,
                                               status: response.status, reply: response.reply)
        onRequest?("\(request.method) \(request.path) → \(response.status)")
        return response
    }

    private func route(_ request: HTTPRequest, _ body: [String: Any]?) -> HTTPResponse {
        // Browsers send one of these on cross-site or scripted requests; the phone never does.
        for name in ["origin", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest"] where request.header(name) != .absent {
            return error(403, .browser)
        }
        guard case .one(let host) = request.header("host"),
              allowedHosts().contains(where: { $0.caseInsensitiveCompare(host) == .orderedSame })
        else { return error(403, .badHost) }
        let parts = request.path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        // parts: ["", "v1", …]
        guard parts.count >= 3, parts[0].isEmpty, parts[1] == "v1", request.method == "POST" else {
            return error(404, "not found")
        }
        guard let body else { return error(400, "body is not a JSON object") }
        return post(Array(parts.dropFirst(2)), body)
    }

    private func post(_ rest: [String], _ body: [String: Any]) -> HTTPResponse {
        let token = body["token"] as? String
        let pairingID = body["pairing_id"] as? String
        let signature = body["signature"] as? String
        let counter = (body["counter"] as? NSNumber).flatMap(Self.counter)

        switch (rest.count, rest.first) {
        case (1, "pair"):
            switch pairing.commit(code: body["code"] as? String, commitment: body["commitment"] as? String) {
            case .success(let (id, nonce)): return ok(["pairing_id": id, "computer_nonce": nonce])
            case .failure(let failure): return error(403, failure)
            }
        case (2, "pair") where rest[1] == "reveal":
            switch pairing.reveal(pairingID: pairingID, phoneKeyBase64: body["phone_key"] as? String,
                                  phoneNonce: body["phone_nonce"] as? String, signature: signature) {
            case .success(let (id, token)): return ok(["pairing_id": id, "token": token])
            case .failure(let failure): return error(403, failure)
            }
        case (2, "pool") where rest[1] == "portfolio":
            if let failure = pairing.authorize(token: token) { return error(403, failure) }
            switch engine.poolPortfolio() {
            case .success(let view): return HTTPResponse(status: 200, json: view)
            case .failure(let failure): return error(409, failure.code)
            }
        case (2, "chats") where rest[1] == "list":
            if let failure = pairing.authorize(token: token) { return error(403, failure) }
            return HTTPResponse(status: 200, json: engine.listJSON())
        case (3, "chats") where rest[2] == "view":
            if let failure = pairing.authorize(token: token) { return error(403, failure) }
            guard let view = engine.chatJSON(rest[1]) else { return error(404, .unknownChat) }
            return HTTPResponse(status: 200, json: view)
        case (1, "confirm"):
            let id = body["id"] as? String, decision = body["decision"] as? String
            let firm = body["firm"] as? String, digest = body["digest"] as? String
            if let failure = pairing.authorize(token: token) { return error(403, failure) }
            // The phone signs the digest of what it showed; the computer uses the digest of what it asked.
            guard let id, let content = engine.pendingContent(id) else { return error(409, .stale) }
            if let failure = pairing.check(token: token, pairingID: pairingID, counter: counter, signature: signature,
                                           confirmation: id, signed: {
                ProtocolBytes.confirmMessage(pairingID: $0, counter: $1, id: id, decision: decision, firm: firm,
                                             digest: digest, content: content)
            }) { return error(409, failure) }
            // Search queries (`kind: "queries"`) are accepted as shown, never edited from the phone: no `queries` here.
            // Actions suggested by a research are done on the computer only: the phone has no route for them.
            if let failure = engine.confirm(id: id, decision: decision, firm: firm, digest: digest, queries: nil) {
                return error(409, failure)
            }
            pairing.recordConfirmation(id)
            return ok([:])
        case (1, "chats"):
            let text = body["text"] as? String
            if let failure = pairing.check(token: token, pairingID: pairingID, counter: counter, signature: signature,
                                           signed: { ProtocolBytes.chatMessage(pairingID: $0, counter: $1, chatID: nil, text: text) }) {
                return error(409, failure)
            }
            switch engine.create(text ?? "") {
            case .success(let chat): return ok(["chat_id": chat.id])
            case .failure(let failure): return error(409, failure)
            }
        case (3, "chats") where rest[2] == "messages":
            let chatID = rest[1], text = body["text"] as? String
            if let failure = pairing.check(token: token, pairingID: pairingID, counter: counter, signature: signature,
                                           signed: { ProtocolBytes.chatMessage(pairingID: $0, counter: $1, chatID: chatID, text: text) }) {
                return error(409, failure)
            }
            if let failure = engine.post(text ?? "", to: chatID) { return error(409, failure) }
            return ok([:])
        case (3, "chats") where rest[2] == "delete":
            let chatID = rest[1]
            if let failure = pairing.check(token: token, pairingID: pairingID, counter: counter, signature: signature,
                                           signed: { ProtocolBytes.deleteMessage(pairingID: $0, counter: $1, chatID: chatID) }) {
                return error(409, failure)
            }
            if let failure = engine.delete(chatID) { return error(409, failure) }
            return ok([:])
        default:
            return error(404, "not found")
        }
    }

    private func ok(_ json: [String: Any]) -> HTTPResponse {
        var reply = json
        reply["ok"] = true
        reply["mode"] = engine.mode
        return HTTPResponse(status: 200, json: reply)
    }

    private func error(_ status: Int, _ failure: ProtocolError) -> HTTPResponse {
        error(status, failure.rawValue)
    }

    private func error(_ status: Int, _ message: String) -> HTTPResponse {
        HTTPResponse(status: status, json: ["ok": false, "error": message, "mode": engine.mode])
    }
}
