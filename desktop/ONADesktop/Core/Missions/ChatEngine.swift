import Foundation
import Observation

/// Something that runs ona-core commands (`Core::dispatch`). The app uses the Rust bridge; tests can too.
public protocol MissionCore: AnyObject {
    func dispatch(_ request: [String: Any]) -> [String: Any]
}

/// An offer read by ona-core's reader (`reader::Offer`).
public struct Offer: Equatable, Sendable, Identifiable {
    public let firmID: String
    public let priceCents: Int
    public let delayDays: Int
    public let sourceSpans: [String]
    public var id: String { firmID }

    init?(_ json: Any?) {
        guard let o = json as? [String: Any], let firm = o["firm_id"] as? String,
              let price = o["price_cents"] as? Int, let delay = o["delay_days"] as? Int else { return nil }
        firmID = firm
        priceCents = price
        delayDays = delay
        sourceSpans = o["source_spans"] as? [String] ?? []
    }

    var json: [String: Any] {
        ["firm_id": firmID, "price_cents": priceCents, "delay_days": delayDays, "source_spans": sourceSpans]
    }
}

/// What binds a payment confirmation to one mission, once (format v2, shared with ona-core).
public struct PaymentBinding: Equatable, Sendable {
    public let network: String
    public let contract: String
    public let missionID: String
    public let nonce: String
}

/// A confirmation the agent waits for.
public struct Pending: Equatable, Sendable, Identifiable {
    public enum Request: Equatable, Sendable {
        case plan([String])
        case recipient([Offer])
        case payment(to: String, amount: String, screen: String, digest: String, binding: PaymentBinding)
    }

    public let id: String
    public let request: Request

    /// Digest of what the phone shows; the phone recomputes it from what it displays and signs it.
    public var content: String {
        switch request {
        case .plan(let steps): ProtocolBytes.planDigest(id: id, steps: steps)
        case .recipient(let offers):
            ProtocolBytes.offersDigest(id: id, offers: offers.map { ($0.firmID, $0.priceCents, $0.delayDays, $0.sourceSpans) })
        case .payment(_, _, _, let digest, _): digest
        }
    }

    var json: [String: Any] {
        switch request {
        case .plan(let steps): return ["id": id, "kind": "plan", "plan": steps, "content": content]
        case .recipient(let offers):
            return ["id": id, "kind": "recipient", "offers": offers.map(\.json), "content": content]
        case .payment(let to, let amount, let screen, let digest, let binding):
            let payment: [String: Any] = [
                "to": to, "amount": amount, "screen": screen, "digest": digest, "digest_version": 2,
                "network": binding.network, "contract": binding.contract, "mission_id": binding.missionID,
                "nonce": binding.nonce,
            ]
            return ["id": id, "kind": "payment", "payment": payment, "content": content]
        }
    }

    /// Reads ona-core's `prepare_payment` reply: `screen`, `digest` and `payment` {`network`, `contract`,
    /// `mission_id`, `nonce`, `to`, `amount`}. The digest must be `paymentDigestV2` of those six fields, and `to` and
    /// `amount` those of the screen. Anything else is refused: the phone could not recompute what it signs.
    public static func preparedPayment(_ reply: [String: Any]) -> Result<Request, ProtocolErrorText> {
        guard let screen = reply["screen"] as? String, let parsed = ProtocolBytes.parsePaymentScreen(screen) else {
            return .failure("unreadable payment screen")
        }
        guard let digest = reply["digest"] as? String, ProtocolBytes.isHex(digest, length: 64) else {
            return .failure("malformed payment digest")
        }
        guard let payment = reply["payment"] as? [String: Any],
              let network = payment["network"] as? String, let contract = payment["contract"] as? String,
              let missionID = payment["mission_id"] as? String, let nonce = payment["nonce"] as? String,
              let to = payment["to"] as? String, let amount = payment["amount"] as? String
        else { return .failure("payment without its mission binding (digest v2 required)") }
        guard to == parsed.to, amount == parsed.amount else {
            return .failure("payment fields differ from the payment screen")
        }
        guard ProtocolBytes.isHex(nonce, length: 32), !missionID.isEmpty else {
            return .failure("malformed payment binding")
        }
        guard ProtocolBytes.paymentDigestV2(network: network, contract: contract, missionID: missionID, nonce: nonce,
                                            to: to, amount: amount) == digest else {
            return .failure("payment digest does not match its fields")
        }
        return .success(.payment(to: to, amount: amount, screen: screen, digest: digest,
                                 binding: PaymentBinding(network: network, contract: contract, missionID: missionID,
                                                         nonce: nonce)))
    }
}

/// An error message as an `Error` (for `Result`).
public struct ProtocolErrorText: Error, Equatable, ExpressibleByStringLiteral, Sendable {
    public let text: String
    public init(stringLiteral text: String) { self.text = text }
}

public enum ChatStatus: String, Sendable {
    case idle, working, waiting
}

/// One element of a conversation.
public struct ChatItem: Identifiable, Sendable {
    public enum Content: Sendable {
        case user(String)
        case agent(String)
        case activity(tool: String, text: String)
        case confirmation(Pending)
        /// ona-core's exposure report, as JSON.
        case exposure(Data)
    }

    public let id: String
    public let at: Date
    public let content: Content
}

public enum ConfirmationState: String, Sendable {
    case pending, accepted, rejected, expired
}

/// A conversation: what the person asked, what the agent did, and the mission run that does it.
@MainActor
@Observable
public final class Chat: Identifiable {
    public let id: String
    public let title: String
    public private(set) var updatedAt: Date
    public private(set) var items: [ChatItem] = []
    public private(set) var decisions: [String: ConfirmationState] = [:]
    fileprivate var run: MissionRun?
    private var itemCount = 0

    init(id: String, title: String) {
        self.id = id
        self.title = title
        updatedAt = .now
    }

    public var status: ChatStatus {
        switch run?.phase {
        case .waiting: .waiting
        case .running: .working
        default: .idle
        }
    }

    /// The confirmation this chat waits for.
    public var pending: Pending? {
        if case .waiting(let pending) = run?.phase { return pending }
        return nil
    }

    public func state(of confirmation: Pending) -> ConfirmationState {
        pending?.id == confirmation.id ? .pending : decisions[confirmation.id] ?? .expired
    }

    /// The step in progress, for the "en cours" line.
    public var working: (tool: String, text: String)? {
        guard let run, case .running = run.phase, run.cursor < run.plan.count else { return nil }
        let tool = run.plan[run.cursor]
        guard let text = ChatEngine.runningLabels[tool] else { return nil }
        return (tool, text)
    }

    public var preview: String {
        for item in items.reversed() {
            switch item.content {
            case .user(let text), .agent(let text): return text
            default: continue
            }
        }
        return ""
    }

    fileprivate func add(_ content: ChatItem.Content) {
        itemCount += 1
        updatedAt = .now
        items.append(ChatItem(id: "\(id)-i-\(itemCount)", at: updatedAt, content: content))
    }

    fileprivate func decide(_ id: String, _ state: ConfirmationState) {
        decisions[id] = state
        updatedAt = .now
    }
}

/// ona-core driven step by step, stopping at each human confirmation. Observable: the chat's status comes from it.
@MainActor
@Observable
fileprivate final class MissionRun {
    enum Phase {
        case waiting(Pending)
        case running
        case done
        case stopped
    }

    @ObservationIgnored let core: any MissionCore
    var plan: [String] = []
    var cursor = 0
    var phase: Phase = .running
    var handles: [String] = []
    var readCount = 0
    var ranked: [Offer] = []
    var chosen: String?

    init(core: any MissionCore) {
        self.core = core
    }
}

/// All conversations of this computer, and the agent's progress in each. Chats live in memory only.
@MainActor
@Observable
public final class ChatEngine {
    public private(set) var chats: [Chat] = []
    /// Mode of the model behind ona-core: "mock" while the model is the fake.
    public private(set) var mode = "mock"

    public static let maxText = 2000
    static let contactMessage = "Bonjour, je souhaite un devis pour une consultation en droit du travail."

    static let runningLabels = [
        "search": "Recherche en cours…", "read": "Lecture d'une page…", "compare": "Comparaison des offres…",
        "contact": "Prise de contact…", "prepare_payment": "Préparation du paiement…", "pay": "Envoi du paiement…",
    ]

    static let planMessage = "J'ai préparé un plan en %d étapes. Il est figé avant toute lecture du web : je ne contacterai personne et ne paierai rien sans votre accord. Validez-le pour que je commence."
    static let recipientMessage = "J'ai trouvé %d offres. Laquelle dois-je contacter ?"
    static let paymentMessage = "Le cabinet est contacté. Il reste à confirmer le paiement de la consultation."
    static let doneMessage = "C'est fait. Voici ce qui est sorti de votre ordinateur pendant cette mission."
    static let cancelledMessage = "Mission arrêtée à votre demande. Rien d'autre ne sera envoyé."
    static let busyMessage = "Je suis encore sur la mission en cours : je vous tiens au courant ici."

    private let makeCore: () -> any MissionCore
    private var count = 0

    public init(makeCore: @escaping () -> any MissionCore) {
        self.makeCore = makeCore
    }

    /// Most recent first.
    public var sorted: [Chat] { chats.sorted { $0.updatedAt > $1.updatedAt } }

    public func chat(_ id: String) -> Chat? { chats.first { $0.id == id } }

    // MARK: - Requests (from the phone or this Mac)

    public func create(_ text: String) -> Result<Chat, ProtocolError> {
        guard let text = Self.clean(text) else { return .failure(.badText) }
        count += 1
        // Random, never reused: an old signed request cannot target a new chat that took the same id.
        let chat = Chat(id: "chat-" + ProtocolBytes.randomHex16(), title: Self.title(text))
        chats.append(chat)
        say(text, in: chat)
        return .success(chat)
    }

    public func post(_ text: String, to chatID: String) -> ProtocolError? {
        guard let text = Self.clean(text) else { return .badText }
        guard let chat = chat(chatID) else { return .unknownChat }
        say(text, in: chat)
        return nil
    }

    public func delete(_ chatID: String) -> ProtocolError? {
        guard chats.contains(where: { $0.id == chatID }) else { return .unknownChat }
        chats.removeAll { $0.id == chatID }
        return nil
    }

    /// The content digest of a confirmation still pending (what the phone must have signed).
    public func pendingContent(_ id: String) -> String? {
        chats.lazy.compactMap(\.pending).first { $0.id == id }?.content
    }

    /// A decision on a pending confirmation. Returns an error code, or nil.
    public func confirm(id: String?, decision: String?, firm: String?, digest: String?) -> String? {
        guard let id, let chat = chats.first(where: { $0.pending?.id == id }),
              let run = chat.run, let pending = chat.pending
        else { return ProtocolError.stale.rawValue }
        switch decision {
        case "reject":
            chat.decide(id, .rejected)
            finish(chat, run, cancelled: true)
            return nil
        case "accept":
            break
        default:
            return ProtocolError.badRequest.rawValue
        }
        let reply: [String: Any]
        switch pending.request {
        case .plan:
            reply = run.core.dispatch(["cmd": "accept_plan"])
        case .recipient:
            guard let firm else { return ProtocolError.badRequest.rawValue }
            reply = run.core.dispatch(["cmd": "confirm_recipient", "firm": firm])
            if Self.ok(reply) { run.chosen = firm }
        case .payment:
            // ona-core's gate checks the digest against the payment it prepared.
            guard let digest else { return ProtocolError.badRequest.rawValue }
            reply = run.core.dispatch(["cmd": "confirm_payment", "digest": digest])
        }
        guard Self.ok(reply) else { return reply["error"] as? String ?? ProtocolError.badRequest.rawValue }
        chat.decide(id, .accepted)
        if case .plan = pending.request {} else { run.cursor += 1 }
        run.phase = .running
        return nil
    }

    // MARK: - Progress

    /// Advances every working chat by one step. Called on a timer.
    public func tick() {
        for chat in chats {
            guard let run = chat.run, case .running = run.phase else { continue }
            step(chat, run)
        }
    }

    private func say(_ text: String, in chat: Chat) {
        chat.add(.user(text))
        if let run = chat.run, case .running = run.phase {
            chat.add(.agent(Self.busyMessage))
            return
        }
        if let run = chat.run, case .waiting = run.phase {
            chat.add(.agent(Self.busyMessage))
            return
        }
        start(text, in: chat)
    }

    private func start(_ text: String, in chat: Chat) {
        // A new core for every mission: the previous one (closed, or stopped by an error or a panic) is dropped.
        let run = MissionRun(core: makeCore())
        chat.run = run
        let opened = run.core.dispatch(["cmd": "open", "mission": text])
        guard Self.ok(opened) else { return fail(chat, run, opened) }
        mode = opened["mode"] as? String ?? mode
        chat.add(.activity(tool: "think", text: "Lecture de votre demande et préparation d'un plan"))
        let proposal = run.core.dispatch(["cmd": "propose_plan"])
        guard Self.ok(proposal), let plan = proposal["plan"] as? [String] else { return fail(chat, run, proposal) }
        run.plan = plan
        chat.add(.agent(String(format: Self.planMessage, plan.count)))
        wait(chat, run, .plan(plan))
    }

    private func step(_ chat: Chat, _ run: MissionRun) {
        guard run.cursor < run.plan.count else { return finish(chat, run, cancelled: false) }
        let tool = run.plan[run.cursor]
        switch tool {
        case "search":
            let reply = run.core.dispatch(["cmd": "search", "template": "lawyer", "value": "paris"])
            guard Self.ok(reply) else { return fail(chat, run, reply) }
            run.handles = reply["handles"] as? [String] ?? []
            chat.add(.activity(tool: tool, text: "Recherche « avocat droit du travail paris » : \(run.handles.count) résultats"))
        case "read":
            guard run.readCount < run.handles.count else { return fail(chat, run, ["error": "no page left to read"]) }
            let reply = run.core.dispatch(["cmd": "read", "handle": run.handles[run.readCount]])
            run.readCount += 1
            guard Self.ok(reply), let offer = Offer(reply["offer"]) else { return fail(chat, run, reply) }
            chat.add(.activity(tool: tool, text: "Lecture d'une page : \(offer.firmID), \(offer.priceCents / 100) €, sous \(offer.delayDays) jours"))
        case "compare":
            let reply = run.core.dispatch(["cmd": "compare"])
            guard Self.ok(reply) else { return fail(chat, run, reply) }
            run.ranked = (reply["ranked"] as? [Any] ?? []).compactMap(Offer.init)
            chat.add(.activity(tool: tool, text: "Comparaison : \(run.ranked.count) offres classées"))
        case "confirm_recipient":
            chat.add(.agent(String(format: Self.recipientMessage, run.ranked.count)))
            return wait(chat, run, .recipient(run.ranked))
        case "contact":
            let reply = run.core.dispatch(["cmd": "contact", "message": Self.contactMessage])
            guard Self.ok(reply) else { return fail(chat, run, reply) }
            chat.add(.activity(tool: tool, text: "Message générique envoyé à \(run.chosen ?? "?")"))
        case "prepare_payment":
            // No amount: ona-core computes it from the chosen offer's price and the policy's rate.
            let reply = run.core.dispatch(["cmd": "prepare_payment"])
            guard Self.ok(reply) else { return fail(chat, run, reply) }
            let request: Pending.Request
            switch Pending.preparedPayment(reply) {
            case .success(let prepared): request = prepared
            case .failure(let error): return fail(chat, run, ["error": error.text])
            }
            chat.add(.activity(tool: tool, text: "Paiement préparé à partir de l'annuaire"))
            run.cursor += 1
            if run.cursor < run.plan.count, run.plan[run.cursor] == "confirm_payment" {
                chat.add(.agent(Self.paymentMessage))
                return wait(chat, run, request)
            }
            return
        case "confirm_payment":
            return fail(chat, run, ["error": "payment confirmation without a prepared payment"])
        case "pay":
            let reply = run.core.dispatch(["cmd": "pay"])
            guard Self.ok(reply) else { return fail(chat, run, reply) }
            chat.add(.activity(tool: tool, text: "Paiement envoyé : \(reply["tx"] as? String ?? "?")"))
        default:
            return fail(chat, run, ["error": "unknown step \(tool)"])
        }
        run.cursor += 1
    }

    private func wait(_ chat: Chat, _ run: MissionRun, _ request: Pending.Request) {
        // 16 random bytes: never the same id twice, across missions, chats and restarts.
        let pending = Pending(id: "c-" + ProtocolBytes.randomHex16(), request: request)
        run.phase = .waiting(pending)
        chat.add(.confirmation(pending))
    }

    private func finish(_ chat: Chat, _ run: MissionRun, cancelled: Bool) {
        _ = run.core.dispatch(["cmd": "close"])
        var exposure = run.core.dispatch(["cmd": "exposure"])
        exposure.removeValue(forKey: "ok")
        run.phase = cancelled ? .stopped : .done
        chat.add(.agent(cancelled ? Self.cancelledMessage : Self.doneMessage))
        if let data = try? JSONSerialization.data(withJSONObject: exposure) {
            chat.add(.exposure(data))
        }
    }

    private func fail(_ chat: Chat, _ run: MissionRun, _ reply: [String: Any]) {
        run.phase = .stopped
        chat.add(.agent("L'agent s'est arrêté : \(reply["error"] as? String ?? "erreur inconnue")."))
    }

    // MARK: - Helpers

    static func ok(_ reply: [String: Any]) -> Bool { reply["ok"] as? Bool == true }

    static func clean(_ text: String) -> String? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty || trimmed.count > maxText ? nil : trimmed
    }

    static func title(_ text: String) -> String {
        let line = text.split(whereSeparator: \.isWhitespace).joined(separator: " ")
        return line.count <= 48 ? line : String(line.prefix(47)).trimmingCharacters(in: .whitespaces) + "…"
    }

    // MARK: - JSON views for the phone (protocol-draft.md, "Conversations")

    public func listJSON() -> [String: Any] {
        ["mode": mode, "chats": sorted.map { chat in
            ["id": chat.id, "title": chat.title, "updated_at": Int(chat.updatedAt.timeIntervalSince1970),
             "preview": chat.preview, "status": chat.status.rawValue] as [String: Any]
        }]
    }

    public func chatJSON(_ id: String) -> [String: Any]? {
        guard let chat = chat(id) else { return nil }
        let items: [[String: Any]] = chat.items.map { item in
            var json: [String: Any] = ["id": item.id, "at": Int(item.at.timeIntervalSince1970)]
            switch item.content {
            case .user(let text): json["kind"] = "user"; json["text"] = text
            case .agent(let text): json["kind"] = "agent"; json["text"] = text
            case .activity(let tool, let text): json["kind"] = "activity"; json["tool"] = tool; json["text"] = text
            case .confirmation(let pending):
                json["kind"] = "confirmation"
                json["pending"] = pending.json
                json["state"] = chat.state(of: pending).rawValue
            case .exposure(let data):
                json["kind"] = "exposure"
                json["exposure"] = (try? JSONSerialization.jsonObject(with: data)) ?? [:]
            }
            return json
        }
        var view: [String: Any] = ["id": chat.id, "title": chat.title, "status": chat.status.rawValue, "items": items]
        view["working"] = chat.working.map { ["tool": $0.tool, "text": $0.text] } ?? NSNull()
        return ["mode": mode, "chat": view]
    }
}
