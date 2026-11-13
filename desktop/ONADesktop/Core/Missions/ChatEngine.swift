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
        /// A free research's search queries, seen before anything leaves.
        case queries([String])
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
        case .queries(let queries): ProtocolBytes.queriesDigest(id: id, queries: queries)
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
        case .queries(let queries):
            return ["id": id, "kind": "queries", "queries": queries, "content": content]
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
        /// A free research's answer, with its notes and sources.
        case answer(ResearchAnswer)
        /// An action the answer suggests, completed on the computer only.
        case action(ResearchAction)
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
    /// Action items carried out.
    public private(set) var doneActions: Set<String> = []
    fileprivate var run: MissionRun?
    fileprivate var research: ResearchRun?
    private var itemCount = 0

    init(id: String, title: String) {
        self.id = id
        self.title = title
        updatedAt = .now
    }

    public var status: ChatStatus {
        if let research {
            switch research.phase {
            case .waiting: return .waiting
            case .running: return .working
            default: return .idle
            }
        }
        return switch run?.phase {
        case .waiting: .waiting
        case .running: .working
        default: .idle
        }
    }

    /// The confirmation this chat waits for.
    public var pending: Pending? {
        if case .waiting(let pending) = research?.phase { return pending }
        if case .waiting(let pending) = run?.phase { return pending }
        return nil
    }

    public func state(of confirmation: Pending) -> ConfirmationState {
        pending?.id == confirmation.id ? .pending : decisions[confirmation.id] ?? .expired
    }

    /// The step in progress, for the "en cours" line.
    public var working: (tool: String, text: String)? {
        if let research { return research.working }
        guard let run, case .running = run.phase else { return nil }
        if run.plan.isEmpty { return ("think", "Préparation d'un plan…") }
        guard run.cursor < run.plan.count else { return nil }
        let tool = run.plan[run.cursor]
        guard let text = ChatEngine.runningLabels[tool] else { return nil }
        return (tool, text)
    }

    public var preview: String {
        for item in items.reversed() {
            switch item.content {
            case .user(let text), .agent(let text): return text
            case .answer(let answer): return answer.answer
            default: continue
            }
        }
        return ""
    }

    @discardableResult
    fileprivate func add(_ content: ChatItem.Content) -> String {
        itemCount += 1
        updatedAt = .now
        let itemID = "\(id)-i-\(itemCount)"
        items.append(ChatItem(id: itemID, at: updatedAt, content: content))
        return itemID
    }

    /// Puts new content in an item, keeping its id and place (the exposure report after an action).
    fileprivate func replace(_ itemID: String, with content: ChatItem.Content) {
        guard let index = items.firstIndex(where: { $0.id == itemID }) else { return }
        updatedAt = .now
        items[index] = ChatItem(id: itemID, at: items[index].at, content: content)
    }

    fileprivate func markDone(_ itemID: String) {
        doneActions.insert(itemID)
        updatedAt = .now
    }

    fileprivate func decide(_ id: String, _ state: ConfirmationState) {
        decisions[id] = state
        updatedAt = .now
    }
}

/// One conversation's ona-core on a serial queue of its own. The main actor, which also serves the window and the phone,
/// sends one command at a time and never waits long for a slow one (`poll`): with the real model a call takes seconds
/// through Tor. The core is used on the queue only, after it was made. The pool's core is one too: the window awaits
/// its replies (`send`) without holding the main actor.
final class CoreQueue: @unchecked Sendable {
    /// How long a tick waits for ona-core: the fake model answers within it, a real call does not and is looked at
    /// again at the next tick.
    static let quickReply: DispatchTimeInterval = .milliseconds(50)

    /// Nil once released. Used on `queue` only.
    private var core: (any MissionCore)?
    private let queue = DispatchQueue(label: "org.ona.desktop.core")
    /// Left once the core is released (`release`).
    private let released = DispatchGroup()
    private let lock = NSLock()
    /// Replies ready, by ticket. Under `lock`.
    private var replies: [Int: [String: Any]] = [:]
    /// The command sent and not taken yet. Main actor only.
    private var inflight: (request: NSDictionary, ticket: Int, done: DispatchSemaphore)?
    private var tickets = 0

    init(core: any MissionCore) {
        self.core = core
    }

    /// ona-core's reply to `request` once it is there; nil while ona-core works on it, and the same request is asked
    /// again at the next tick. A different request while one is in flight waits for the first one.
    @MainActor
    func poll(_ request: [String: Any]) -> [String: Any]? {
        if let inflight, !inflight.request.isEqual(to: request) {
            inflight.done.wait()
            _ = take(inflight.ticket)
            self.inflight = nil
        }
        if inflight == nil {
            tickets += 1
            let ticket = tickets, done = DispatchSemaphore(value: 0)
            let sent = Box(request)
            queue.async { [self] in
                let reply = dispatch(sent.value)
                lock.withLock { replies[ticket] = reply }
                done.signal()
            }
            inflight = (request as NSDictionary, ticket, done)
        }
        guard let current = inflight, current.done.wait(timeout: .now() + Self.quickReply) == .success else { return nil }
        inflight = nil
        return take(current.ticket)
    }

    /// Waits for the reply: for the quick commands the person is waiting on (a confirmation, closing the mission).
    @MainActor
    func call(_ request: [String: Any]) -> [String: Any] {
        if let inflight {
            inflight.done.wait()
            _ = take(inflight.ticket)
            self.inflight = nil
        }
        let sent = Box(request)
        return queue.sync { Box(dispatch(sent.value)) }.value
    }

    /// The reply, awaited: the main actor goes on serving while ona-core works on the queue.
    @MainActor
    func send(_ request: [String: Any]) async -> [String: Any] {
        let sent = Box(request)
        return await withCheckedContinuation { (continuation: CheckedContinuation<Box<[String: Any]>, Never>) in
            queue.async { [self] in continuation.resume(returning: Box(dispatch(sent.value))) }
        }.value
    }

    /// Drops the core once the commands already sent are answered: its wallet file is unlocked then. Later commands
    /// answer `ona-core stopped`.
    @MainActor
    func release() {
        released.enter()
        queue.async { [self] in
            core = nil
            released.leave()
        }
    }

    /// Waits until `release` has dropped the core.
    func waitReleased() {
        released.wait()
    }

    /// Same, awaited.
    @MainActor
    func whenReleased() async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            released.notify(queue: .global()) { @Sendable in continuation.resume() }
        }
    }

    /// On `queue` only.
    private func dispatch(_ request: [String: Any]) -> [String: Any] {
        core?.dispatch(request) ?? ["ok": false, "error": "ona-core stopped"]
    }

    private func take(_ ticket: Int) -> [String: Any] {
        lock.withLock { replies.removeValue(forKey: ticket) } ?? ["ok": false, "error": "ona-core stopped"]
    }
}

/// JSON values cross to the core's queue and back; nothing else holds them meanwhile.
private struct Box<T>: @unchecked Sendable {
    let value: T
    init(_ value: T) { self.value = value }
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

    @ObservationIgnored let core: CoreQueue
    /// The person's request, sent to ona-core with `open`.
    let mission: String
    var opened = false
    var plan: [String] = []
    var cursor = 0
    var phase: Phase = .running
    var handles: [String] = []
    var readCount = 0
    var ranked: [Offer] = []
    var chosen: String?

    init(core: any MissionCore, mission: String) {
        self.core = CoreQueue(core: core)
        self.mission = mission
    }
}

/// A free research (docs/research.md) driven step by step: open, queries proposed then confirmed, searches and pages
/// read until the answer, then the result and the exposure report. Observable: the chat's status comes from it.
@MainActor
@Observable
fileprivate final class ResearchRun {
    enum Phase {
        case waiting(Pending)
        case running
        case done
        case stopped
    }

    enum Stage {
        case open, propose, steps
    }

    @ObservationIgnored let core: CoreQueue
    let question: String
    var stage = Stage.open
    var phase: Phase = .running
    /// The queries accepted, and how many were searched.
    var queries: [String] = []
    var searched = 0
    /// Sources found, in order (handles `s1`, `s2`…), with their site; and how many were looked at.
    var sources: [(handle: String, site: String)] = []
    var looked = 0
    /// The action items of this research, by item id: their index in ona-core's result.
    var actions: [String: ResearchAction] = [:]
    var prepared: PreparedAction?
    var exposureItem: String?

    init(core: any MissionCore, question: String) {
        self.core = CoreQueue(core: core)
        self.question = question
    }

    func site(_ handle: String?) -> String {
        sources.first { $0.handle == handle }?.site ?? "?"
    }

    /// What ona-core works on, for the "en cours" line: the next step follows from what is done.
    var working: (tool: String, text: String)? {
        guard case .running = phase else { return nil }
        switch stage {
        case .open, .propose: return ("think", "Préparation des recherches…")
        case .steps:
            if searched < queries.count { return ("search", "Recherche « \(queries[searched]) »…") }
            if looked < sources.count { return ("read", "Lecture de \(sources[looked].site)…") }
            return ("think", "Rédaction de la réponse à partir des notes…")
        }
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

    static let queriesMessage = "Je propose %d recherche(s) sur le web, faites via Tor. Rien ne part avant votre accord : validez-les ici ou sur le téléphone, ou modifiez-les sur l'ordinateur."
    static let actionsMessage = "Je vous suggère %d action(s). Elles se font sur l'ordinateur seulement : vous indiquez le destinataire, vous vérifiez l'action exacte, puis vous confirmez."
    static let researchDoneMessage = "Voici ce qui est sorti de votre ordinateur pendant cette recherche."
    static let researchCancelledMessage = "Recherche arrêtée à votre demande. Aucune requête n'a été envoyée sur le web."

    /// What new conversations run.
    public let newChats: ChatKind

    private let makeCore: () -> any MissionCore
    /// Makes the pool's core (`pool.json`, `RealModel.poolSetup`).
    private let makePoolCore: () -> any MissionCore
    private var count = 0
    /// One core for the pool, on its own queue, made on first use: it holds the wallet file's lock.
    private var poolQueue: CoreQueue?
    /// Pool cores dropped by `resetPool` whose release may not be done yet: a new one is made only after, since the
    /// wallet file is locked by the core that opened it.
    private var releasingPools: [CoreQueue] = []

    /// The commands the pool window may send (docs/desktop/pool-commands.md).
    public static let poolCommands: Set<String> = ["pool_portfolio", "pool_prepare", "pool_execute", "pool_recover", "pool_privacy"]

    /// `makePoolCore` makes the pool's core; by default `makeCore`.
    /// `newChats`: a free research (the app), or the lawyer mission (its tests).
    public init(makeCore: @escaping () -> any MissionCore, makePoolCore: (() -> any MissionCore)? = nil,
                newChats: ChatKind = .research) {
        self.makeCore = makeCore
        self.newChats = newChats
        self.makePoolCore = makePoolCore ?? makeCore
    }

    /// Drops the pool's core, so that the next pool command makes a new one: when tor's port for the core changes.
    public func resetPool() {
        guard let old = poolQueue else { return }
        poolQueue = nil
        old.release()
        releasingPools.append(old)
    }

    /// A pool command from the Mac's window: `pool_portfolio`, `pool_prepare`, `pool_execute`, `pool_recover` or `pool_privacy`.
    /// ona-core works on the pool core's queue: the main actor, which serves the window and the phone, is not held.
    /// Pool operations are confirmed on the Mac only, never from the phone.
    public func pool(_ request: [String: Any]) async -> [String: Any] {
        guard let cmd = request["cmd"] as? String, Self.poolCommands.contains(cmd) else {
            return ["ok": false, "error": "commande du pool inconnue"]
        }
        while let old = releasingPools.first {
            await old.whenReleased()
            releasingPools.removeAll { $0 === old }
        }
        return await currentPool().send(request)
    }

    private func currentPool() -> CoreQueue {
        if let poolQueue { return poolQueue }
        let made = CoreQueue(core: makePoolCore())
        poolQueue = made
        return made
    }

    /// The pool portfolio for the phone, read only: ona-core's `pool_portfolio` (cash, shares per vault, total). On
    /// failure, ona-core's error, for instance `no pool wallet configured`. Pool operations are confirmed on the Mac.
    /// It waits for ona-core's reply on the main actor (through Tor, seconds), like the Tauri app's worker thread.
    public func poolPortfolio() -> Result<[String: Any], PoolError> {
        for old in releasingPools { old.waitReleased() }
        releasingPools.removeAll()
        var reply = currentPool().call(["cmd": "pool_portfolio"])
        guard reply["ok"] as? Bool == true else {
            return .failure(PoolError(code: reply["error"] as? String ?? "pool unavailable"))
        }
        let mode = reply["mode"] as? String ?? "mock"
        reply.removeValue(forKey: "ok")
        reply.removeValue(forKey: "mode")
        return .success(["mode": mode, "portfolio": reply])
    }

    public struct PoolError: Error, Equatable {
        public let code: String
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
    /// `queries`: the queries as the person edited them on the computer; nil accepts them as shown (the phone).
    public func confirm(id: String?, decision: String?, firm: String?, digest: String?,
                        queries edited: [String]? = nil) -> String? {
        guard let id, let chat = chats.first(where: { $0.pending?.id == id }), let pending = chat.pending
        else { return ProtocolError.stale.rawValue }
        if let research = chat.research {
            return confirm(chat, research, pending, decision: decision, queries: edited)
        }
        guard let run = chat.run else { return ProtocolError.stale.rawValue }
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
            reply = run.core.call(["cmd": "accept_plan"])
        case .recipient:
            guard let firm else { return ProtocolError.badRequest.rawValue }
            reply = run.core.call(["cmd": "confirm_recipient", "firm": firm])
            if Self.ok(reply) { run.chosen = firm }
        case .payment:
            // ona-core's gate checks the digest against the payment it prepared.
            guard let digest else { return ProtocolError.badRequest.rawValue }
            reply = run.core.call(["cmd": "confirm_payment", "digest": digest])
        case .queries:
            return ProtocolError.badRequest.rawValue
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
            if let research = chat.research {
                if case .running = research.phase { step(chat, research) }
                continue
            }
            guard let run = chat.run, case .running = run.phase else { continue }
            step(chat, run)
        }
    }

    private func say(_ text: String, in chat: Chat) {
        chat.add(.user(text))
        if chat.status != .idle {
            chat.add(.agent(Self.busyMessage))
            return
        }
        switch newChats {
        case .research: startResearch(text, in: chat)
        case .mission: start(text, in: chat)
        }
    }

    private func start(_ text: String, in chat: Chat) {
        // A new core for every mission: the previous one (closed, or stopped by an error or a panic) is dropped.
        let run = MissionRun(core: makeCore(), mission: text)
        chat.research = nil
        chat.run = run
        // The first steps at once: with the fake model, the plan is there before this request returns.
        step(chat, run)
        if case .running = run.phase { step(chat, run) }
    }

    /// Moves a working mission on by one command, when ona-core has answered the previous one.
    private func step(_ chat: Chat, _ run: MissionRun) {
        if !run.opened {
            guard let opened = run.core.poll(["cmd": "open", "mission": run.mission]) else { return }
            guard Self.ok(opened) else { return fail(chat, run, opened) }
            run.opened = true
            mode = opened["mode"] as? String ?? mode
            chat.add(.activity(tool: "think", text: "Lecture de votre demande et préparation d'un plan"))
            return
        }
        if run.plan.isEmpty {
            guard let proposal = run.core.poll(["cmd": "propose_plan"]) else { return }
            guard Self.ok(proposal), let plan = proposal["plan"] as? [String], !plan.isEmpty else {
                return fail(chat, run, proposal)
            }
            run.plan = plan
            chat.add(.agent(String(format: Self.planMessage, plan.count)))
            return wait(chat, run, .plan(plan))
        }
        guard run.cursor < run.plan.count else { return finish(chat, run, cancelled: false) }
        let tool = run.plan[run.cursor]
        switch tool {
        case "search":
            guard let reply = run.core.poll(["cmd": "search", "template": "lawyer", "value": "paris"]) else { return }
            guard Self.ok(reply) else { return fail(chat, run, reply) }
            run.handles = reply["handles"] as? [String] ?? []
            chat.add(.activity(tool: tool, text: "Recherche « avocat droit du travail paris » : \(run.handles.count) résultats"))
        case "read":
            guard run.readCount < run.handles.count else { return fail(chat, run, ["error": "no page left to read"]) }
            guard let reply = run.core.poll(["cmd": "read", "handle": run.handles[run.readCount]]) else { return }
            run.readCount += 1
            guard Self.ok(reply), let offer = Offer(reply["offer"]) else { return fail(chat, run, reply) }
            chat.add(.activity(tool: tool, text: "Lecture d'une page : \(offer.firmID), \(offer.priceCents / 100) €, sous \(offer.delayDays) jours"))
        case "compare":
            guard let reply = run.core.poll(["cmd": "compare"]) else { return }
            guard Self.ok(reply) else { return fail(chat, run, reply) }
            run.ranked = (reply["ranked"] as? [Any] ?? []).compactMap(Offer.init)
            chat.add(.activity(tool: tool, text: "Comparaison : \(run.ranked.count) offres classées"))
        case "confirm_recipient":
            chat.add(.agent(String(format: Self.recipientMessage, run.ranked.count)))
            return wait(chat, run, .recipient(run.ranked))
        case "contact":
            guard let reply = run.core.poll(["cmd": "contact", "message": Self.contactMessage]) else { return }
            guard Self.ok(reply) else { return fail(chat, run, reply) }
            chat.add(.activity(tool: tool, text: "Message générique envoyé à \(run.chosen ?? "?")"))
        case "prepare_payment":
            // No amount: ona-core computes it from the chosen offer's price and the policy's rate.
            guard let reply = run.core.poll(["cmd": "prepare_payment"]) else { return }
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
            guard let reply = run.core.poll(["cmd": "pay"]) else { return }
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
        _ = run.core.call(["cmd": "close"])
        var exposure = run.core.call(["cmd": "exposure"])
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

    // MARK: - Free research (docs/research.md)

    private func startResearch(_ question: String, in chat: Chat) {
        // A new core for every research: the previous one (answered, stopped, or failed) is dropped with its actions.
        let research = ResearchRun(core: makeCore(), question: question)
        chat.run = nil
        chat.research = research
        // The first steps at once: with the fake model, the queries are there before this request returns.
        step(chat, research)
        if case .running = research.phase { step(chat, research) }
    }

    /// Moves a research on by one command, when ona-core has answered the previous one. Model calls and Tor fetches
    /// take seconds: the reply is looked at again at the next tick.
    private func step(_ chat: Chat, _ research: ResearchRun) {
        switch research.stage {
        case .open:
            guard let opened = research.core.poll(["cmd": "research_open", "question": research.question]) else { return }
            guard Self.ok(opened) else { return fail(chat, research, opened) }
            mode = opened["mode"] as? String ?? mode
            research.stage = .propose
            chat.add(.activity(tool: "think", text: "Lecture de votre question et préparation des recherches"))
        case .propose:
            guard let proposal = research.core.poll(["cmd": "research_propose"]) else { return }
            guard Self.ok(proposal), let queries = proposal["queries"] as? [String], !queries.isEmpty else {
                return fail(chat, research, proposal)
            }
            chat.add(.agent(String(format: Self.queriesMessage, queries.count)))
            // 16 random bytes: never the same id twice.
            let pending = Pending(id: "c-" + ProtocolBytes.randomHex16(), request: .queries(queries))
            research.phase = .waiting(pending)
            chat.add(.confirmation(pending))
        case .steps:
            guard let reply = research.core.poll(["cmd": "research_step"]) else { return }
            guard Self.ok(reply) else { return fail(chat, research, reply) }
            record(reply, chat, research)
            if reply["done"] as? Bool == true { answer(chat, research) }
        }
    }

    /// One `research_step` event as an activity item.
    private func record(_ event: [String: Any], _ chat: Chat, _ research: ResearchRun) {
        let handle = event["handle"] as? String
        let error = event["error"] as? String ?? "?"
        switch event["event"] as? String {
        case "searched":
            research.searched += 1
            let found: [(handle: String, site: String)] = (event["sources"] as? [[String: Any]] ?? []).compactMap {
                guard let handle = $0["handle"] as? String else { return nil }
                return (handle, $0["site"] as? String ?? "?")
            }
            research.sources += found
            let query = event["query"] as? String ?? "?"
            if let failure = event["error"] as? String {
                // One query failed; the others go on (ona-core stops only when none gave a page).
                chat.add(.activity(tool: "search", text: "Recherche « \(query) » : échec (\(failure))"))
            } else {
                chat.add(.activity(tool: "search", text: "Recherche « \(query) » : \(found.count) source\(found.count > 1 ? "s" : "")"))
            }
        case "read":
            research.looked += 1
            let notes = event["notes"] as? Int ?? 0
            chat.add(.activity(tool: "read", text: "Lecture de \(research.site(handle)) : \(notes) note\(notes > 1 ? "s" : "")"))
        case "unreadable":
            research.looked += 1
            chat.add(.activity(tool: "read", text: "Page de \(research.site(handle)) illisible : \(error)"))
        case "unread":
            research.looked += 1
            chat.add(.activity(tool: "read", text: "Page de \(research.site(handle)) non lue : \(error)"))
        case "refused":
            research.looked += 1
            chat.add(.activity(tool: "read", text: "Page de \(research.site(handle)) écartée : \(error)"))
        case "answered":
            chat.add(.activity(tool: "think", text: "Réponse rédigée à partir des notes vérifiées"))
        default:
            break
        }
    }

    /// The answer, the actions it suggests, then what left. Both commands are quick (no model call, no network).
    private func answer(_ chat: Chat, _ research: ResearchRun) {
        let result = research.core.call(["cmd": "research_result"])
        guard Self.ok(result), let answer = ResearchAnswer(result) else { return fail(chat, research, result) }
        chat.add(.answer(answer))
        let actions = (result["actions"] as? [[String: Any]] ?? []).compactMap(ResearchAction.init)
        if !actions.isEmpty { chat.add(.agent(String(format: Self.actionsMessage, actions.count))) }
        for action in actions {
            research.actions[chat.add(.action(action))] = action
        }
        research.phase = .done
        chat.add(.agent(Self.researchDoneMessage))
        research.exposureItem = exposure(chat, research, into: nil)
    }

    /// Adds ona-core's exposure report, or puts it in `item` (after an action). Returns the item's id.
    @discardableResult
    private func exposure(_ chat: Chat, _ research: ResearchRun, into item: String?) -> String? {
        var report = research.core.call(["cmd": "research_exposure"])
        guard Self.ok(report) else { return item }
        report.removeValue(forKey: "ok")
        guard let data = try? JSONSerialization.data(withJSONObject: report) else { return item }
        if let item {
            chat.replace(item, with: .exposure(data))
            return item
        }
        return chat.add(.exposure(data))
    }

    private func confirm(_ chat: Chat, _ research: ResearchRun, _ pending: Pending, decision: String?,
                         queries edited: [String]?) -> String? {
        guard case .queries(let shown) = pending.request else { return ProtocolError.badRequest.rawValue }
        switch decision {
        case "reject":
            chat.decide(pending.id, .rejected)
            research.phase = .stopped
            chat.add(.agent(Self.researchCancelledMessage))
            exposure(chat, research, into: nil)
            return nil
        case "accept":
            break
        default:
            return ProtocolError.badRequest.rawValue
        }
        // Edited on the computer: empty lines dropped; ona-core checks the rest (count, length, protected terms).
        let queries = (edited ?? shown).map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
        let reply = research.core.call(["cmd": "research_accept", "queries": queries])
        guard Self.ok(reply) else { return reply["error"] as? String ?? ProtocolError.badRequest.rawValue }
        research.queries = reply["accepted"] as? [String] ?? queries
        research.stage = .steps
        research.phase = .running
        chat.decide(pending.id, .accepted)
        return nil
    }

    private func fail(_ chat: Chat, _ research: ResearchRun, _ reply: [String: Any]) {
        research.phase = .stopped
        chat.add(.agent("L'agent s'est arrêté : \(reply["error"] as? String ?? "erreur inconnue")."))
    }

    // MARK: - Actions (on the computer only, never from the phone)

    /// The action of item `itemID`, made exact with the person's recipient (`to`: an e-mail address for a message, a
    /// NEAR account for a payment). ona-core checks the recipient and says whether a page read also wrote it.
    public func prepareAction(chat chatID: String, item itemID: String, to: String)
        -> Result<PreparedAction, ProtocolErrorText> {
        guard let chat = chat(chatID), let research = chat.research, let action = research.actions[itemID] else {
            return .failure("Cette action n'est plus disponible.")
        }
        guard !chat.doneActions.contains(itemID) else { return .failure("Cette action est déjà faite.") }
        research.prepared = nil
        let reply = research.core.call(["cmd": "research_action_prepare", "index": action.index,
                                        "to": to.trimmingCharacters(in: .whitespacesAndNewlines)])
        guard Self.ok(reply) else { return .failure(Self.failure(reply)) }
        guard let kind = reply["kind"] as? String, let recipient = reply["to"] as? String,
              let content = reply["content"] as? String, let digest = reply["digest"] as? String,
              ProtocolBytes.isHex(digest, length: 64), reply["index"] as? Int == action.index
        else { return .failure("réponse illisible d'ona-core") }
        let prepared = PreparedAction(itemID: itemID, index: action.index, kind: kind, to: recipient, content: content,
                                      digest: digest, seenInPages: reply["seen_in_pages"] as? Bool ?? true)
        research.prepared = prepared
        return .success(prepared)
    }

    /// Confirms the prepared action by its digest (what the person saw), then carries it out once. A message comes
    /// back as a `mailto:` URL for the person's mail program (the app opens it); a payment goes through ona-core.
    public func doAction(chat chatID: String, item itemID: String, digest: String)
        -> Result<ActionOutcome, ProtocolErrorText> {
        guard let chat = chat(chatID), let research = chat.research, let prepared = research.prepared,
              prepared.itemID == itemID, prepared.digest == digest
        else { return .failure("Préparez d'abord l'action.") }
        let confirmed = research.core.call(["cmd": "research_action_confirm", "digest": digest])
        guard Self.ok(confirmed) else { return .failure(Self.failure(confirmed)) }
        let reply = research.core.call(["cmd": "research_action_do"])
        research.prepared = nil
        guard Self.ok(reply) else { return .failure(Self.failure(reply)) }
        let outcome: ActionOutcome
        switch reply["done"] as? String {
        case "message":
            guard let text = reply["mailto"] as? String, text.hasPrefix("mailto:"), let url = URL(string: text) else {
                return .failure("réponse illisible d'ona-core")
            }
            outcome = .message(mailto: url)
            chat.add(.activity(tool: "contact", text: "Message prêt dans votre messagerie, pour \(prepared.to)"))
        case "payment":
            guard let tx = reply["tx"] as? String else { return .failure("réponse illisible d'ona-core") }
            outcome = .payment(tx: tx)
            chat.add(.activity(tool: "pay", text: "Paiement envoyé à \(prepared.to) : \(tx)"))
        default:
            return .failure("réponse illisible d'ona-core")
        }
        chat.markDone(itemID)
        exposure(chat, research, into: research.exposureItem)
        return .success(outcome)
    }

    private static func failure(_ reply: [String: Any]) -> ProtocolErrorText {
        ProtocolErrorText(stringLiteral: reply["error"] as? String ?? "erreur inconnue")
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
            case .answer(let answer):
                json["kind"] = "answer"
                json.merge(answer.json) { _, new in new }
            case .action(let action):
                json["kind"] = "action"
                json["action"] = action.json
                json["state"] = chat.doneActions.contains(item.id) ? "done" : "suggested"
            }
            return json
        }
        var view: [String: Any] = ["id": chat.id, "title": chat.title, "status": chat.status.rawValue, "items": items]
        view["working"] = chat.working.map { ["tool": $0.tool, "text": $0.text] } ?? NSNull()
        return ["mode": mode, "chat": view]
    }
}
