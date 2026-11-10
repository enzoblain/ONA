import Foundation

/// The phone protocol (docs/ios/protocol-draft.md) on top of the pairing authority and the chat engine.
/// Every request that changes something must be signed by the paired, verified phone.
@MainActor
public final class PhoneRouter {
    let pairing: PairingAuthority
    let engine: ChatEngine
    /// Called after each request, for the Mac's activity line.
    public var onRequest: ((String) -> Void)?

    public init(pairing: PairingAuthority, engine: ChatEngine) {
        self.pairing = pairing
        self.engine = engine
    }

    public func handle(_ request: HTTPRequest) -> HTTPResponse {
        let response = route(request)
        onRequest?("\(request.method) \(request.path) → \(response.status)")
        return response
    }

    private func route(_ request: HTTPRequest) -> HTTPResponse {
        let parts = request.path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        // parts: ["", "v0", …]
        guard parts.count >= 3, parts[0].isEmpty, parts[1] == "v0" else { return error(404, "not found") }
        let rest = Array(parts.dropFirst(2))

        switch (request.method, rest.count) {
        case ("GET", 1) where rest[0] == "chats":
            if let failure = readRefusal() { return error(403, failure) }
            return ok(engine.listJSON(), wrap: false)
        case ("GET", 2) where rest[0] == "chats":
            if let failure = readRefusal() { return error(403, failure) }
            guard let view = engine.chatJSON(rest[1]) else { return error(404, ProtocolError.unknownChat) }
            return ok(view, wrap: false)
        case ("POST", _):
            guard let body = (try? JSONSerialization.jsonObject(with: request.body.isEmpty ? Data("{}".utf8) : request.body))
                    as? [String: Any]
            else { return error(400, "body is not a JSON object") }
            return post(rest, body)
        default:
            return error(404, "not found")
        }
    }

    private func post(_ rest: [String], _ body: [String: Any]) -> HTTPResponse {
        let pairingID = body["pairing_id"] as? String
        let signature = body["signature"] as? String

        if rest == ["pair"] {
            switch pairing.pair(code: body["code"] as? String, phoneKeyBase64: body["phone_key"] as? String,
                                signature: signature) {
            case .success(let id): return ok(["pairing_id": id])
            case .failure(let failure): return error(403, failure)
            }
        }
        if rest == ["confirm"] {
            let id = body["id"] as? String, decision = body["decision"] as? String
            let firm = body["firm"] as? String, digest = body["digest"] as? String
            if let failure = pairing.check(pairingID: pairingID, signature: signature, signed: {
                ProtocolBytes.confirmMessage(pairingID: $0, id: id, decision: decision, firm: firm, digest: digest)
            }) { return error(409, failure) }
            if let failure = engine.confirm(id: id, decision: decision, firm: firm, digest: digest) {
                return error(409, failure)
            }
            return ok([:])
        }
        if rest == ["chats"] {
            let text = body["text"] as? String
            if let failure = pairing.check(pairingID: pairingID, signature: signature, signed: {
                ProtocolBytes.chatMessage(pairingID: $0, chatID: nil, text: text)
            }) { return error(409, failure) }
            switch engine.create(text ?? "") {
            case .success(let chat): return ok(["chat_id": chat.id])
            case .failure(let failure): return error(409, failure)
            }
        }
        if rest.count == 3, rest[0] == "chats", rest[2] == "messages" {
            let chatID = rest[1], text = body["text"] as? String
            if let failure = pairing.check(pairingID: pairingID, signature: signature, signed: {
                ProtocolBytes.chatMessage(pairingID: $0, chatID: chatID, text: text)
            }) { return error(409, failure) }
            if let failure = engine.post(text ?? "", to: chatID) { return error(409, failure) }
            return ok([:])
        }
        if rest.count == 3, rest[0] == "chats", rest[2] == "delete" {
            let chatID = rest[1]
            if let failure = pairing.check(pairingID: pairingID, signature: signature, signed: {
                ProtocolBytes.deleteMessage(pairingID: $0, chatID: chatID)
            }) { return error(409, failure) }
            if let failure = engine.delete(chatID) { return error(409, failure) }
            return ok([:])
        }
        return error(404, "not found")
    }

    /// Reading needs a phone paired and verified on this Mac. (Not authenticated further yet: see protocol-draft.md,
    /// question 5, Tor client authorization.)
    private func readRefusal() -> ProtocolError? {
        guard let phone = pairing.record.phone else { return .notPaired }
        return phone.verified ? nil : .notVerified
    }

    private func ok(_ json: [String: Any], wrap: Bool = true) -> HTTPResponse {
        guard wrap else { return HTTPResponse(status: 200, json: json) }
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
