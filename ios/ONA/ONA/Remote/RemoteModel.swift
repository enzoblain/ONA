import Foundation
import Observation

/// What the remote control knows about the computer. Only the pairing is kept (Keychain); the conversations live on
/// the computer and are rebuilt in memory by polling. Protocol version 1 (docs/ios/protocol-draft.md).
@MainActor
@Observable
final class RemoteModel {
    enum Connection: Equatable {
        case notPaired
        case idle
        case connecting
        case connected(Date)
        /// Paired on this phone; the person has not yet confirmed the codes on the computer.
        case awaitingComputer
        case failed(String)
    }

    /// Shown right after pairing, until the person says the codes match.
    struct PendingVerification: Equatable {
        let code: String
        let computerName: String
    }

    private(set) var pairing: StoredPairing?
    private(set) var connection: Connection = .notPaired
    /// All conversations, most recent first.
    private(set) var chats: [ChatSummary] = []
    /// True once the chat list has been received at least once since pairing.
    private(set) var chatsLoaded = false
    /// The conversation on screen, refreshed with the list.
    private(set) var openChat: ChatDetail?
    private(set) var openChatID: String?
    private(set) var actionError: String?
    private(set) var sending = false
    private(set) var verification: PendingVerification?
    /// Set once any reply said `mode: mock`, so the simulation label never disappears in a session.
    private(set) var sawSimulation = false
    /// The pool portfolio, read only. Refreshed when the Pool tab is shown.
    private(set) var pool: PoolPortfolio?
    /// Why the portfolio could not be read (a sentence for the person), if it could not.
    private(set) var poolError: String?
    private(set) var poolLoading = false

    /// The computer no longer knows this phone (codes not confirmed in time, phone forgotten, new pairing elsewhere):
    /// the only way out is to scan a new code.
    private(set) var pairingLost = false

    /// Error codes that mean the computer no longer knows this pairing.
    static let lostPairingCodes: Set<String> = ["not paired", "unknown pairing", "missing or wrong token"]

    static let pollInterval: Duration = .seconds(2)
    /// The computer waits this long for the person to confirm the codes, then shows a new QR.
    static let computerConfirmationWindow: TimeInterval = 5 * 60

    private var client: ComputerClient?
    private var key: (any DeviceKey)?
    /// A pairing whose codes the person has not compared yet: kept in memory only, saved once the codes match.
    private var unconfirmed: StoredPairing?
    private var unconfirmedKey: (any DeviceKey)?
    private var pollTask: Task<Void, Never>?
    /// Writes go one at a time: their counters must reach the computer in order.
    private var writing = false
    private let store: any PairingStore
    private let makeLink: @Sendable (Endpoint) -> any ComputerLink
    private let makeKey: @Sendable () throws -> any DeviceKey

    init(
        store: any PairingStore = KeychainPairingStore(),
        makeLink: @escaping @Sendable (Endpoint) -> any ComputerLink = RemoteModel.localOnlyLink,
        makeKey: @escaping @Sendable () throws -> any DeviceKey = DeviceKeys.create
    ) {
        self.store = store
        self.makeLink = makeLink
        self.makeKey = makeKey
        do {
            if let stored = try store.load() { try use(stored) }
        } catch {
            actionError = error.localizedDescription
        }
    }

    var isSimulation: Bool { sawSimulation }
    var isPaired: Bool { pairing != nil }
    /// Number of conversations waiting for a confirmation from this phone (tab badge).
    var waitingCount: Int { chats.filter { $0.status == .waiting }.count }
    /// True when the paired computer is reached through Tor.
    var usesTor: Bool { pairing.flatMap { Endpoint(onion: $0.onion, address: $0.address) }?.isTor ?? false }

    /// Default link factory for builds without Tor (the Mac test package). The app passes one that handles onions.
    nonisolated static func localOnlyLink(_ endpoint: Endpoint) -> any ComputerLink {
        switch endpoint {
        case .local(let url): HTTPComputerLink(baseURL: url)
        case .onion: UnavailableLink(reason: "Tor n'est pas disponible dans cette version de l'app.")
        }
    }

    // MARK: - Pairing: commit to the key, reveal it, compare the codes

    /// Pairs with the computer named in a scanned (or pasted) pairing code. Nothing is saved until the codes match.
    func pair(with text: String) async {
        let payload: PairingPayload
        switch PairingPayload.parse(text) {
        case .success(let parsed): payload = parsed
        case .failure(let failure):
            actionError = Self.describe(failure)
            return
        }
        guard let endpoint = Endpoint(onion: payload.onion, address: payload.address) else {
            actionError = Self.describe(.noAddress)
            return
        }
        sending = true
        defer { sending = false }
        do {
            let makeKey = self.makeKey
            // Creating a Secure Enclave key can show the system sheet: off the main thread.
            let key = try await Task.detached { try makeKey() }.value
            let client = ComputerClient(link: makeLink(endpoint), computerKey: payload.computerKey)
            let phoneNonce = SignedFields.randomHex16()

            // 1. Commit to the key before the computer's nonce exists.
            let commitment = SignedFields.commitment(phoneKey: key.publicKey, phoneNonce: phoneNonce)
            let committed = try await client.call(Paths.pair, ["code": payload.code, "commitment": commitment],
                                                  as: PairCommitReply.self)
            // 2. Reveal it, signed over both nonces.
            let message = SignedFields.pairMessage(pairingID: committed.pairingId, code: payload.code,
                                                   phoneKey: key.publicKey, computerKey: payload.computerKey,
                                                   phoneNonce: phoneNonce, computerNonce: committed.computerNonce)
            let signature = try await Task.detached { try key.sign(message).base64EncodedString() }.value
            let revealed = try await client.call(Paths.reveal, [
                "pairing_id": committed.pairingId, "phone_key": key.publicKey.base64EncodedString(),
                "phone_nonce": phoneNonce, "signature": signature,
            ], as: PairRevealReply.self)
            guard revealed.pairingId == committed.pairingId else { throw LinkError.badReply }

            // 3. The person compares the codes; the pairing is saved only then.
            unconfirmed = StoredPairing(
                pairingID: committed.pairingId, name: payload.name, address: payload.address, onion: payload.onion,
                computerKey: payload.computerKey, keyKind: key.kind, keyRepresentation: key.storedRepresentation,
                pairedAt: .now, token: revealed.token, counter: 0
            )
            unconfirmedKey = key
            verification = PendingVerification(
                code: SignedFields.verificationCode(computerKey: payload.computerKey, phoneKey: key.publicKey,
                                                    code: payload.code, phoneNonce: phoneNonce,
                                                    computerNonce: committed.computerNonce),
                computerName: payload.name
            )
            actionError = nil
        } catch let error as LinkError {
            actionError = error.code.map(ComputerMessages.french) ?? error.localizedDescription
        } catch {
            actionError = error.localizedDescription
        }
    }

    /// The person saw the same code on both screens: the pairing is saved.
    func verificationMatches() {
        guard let stored = unconfirmed, let key = unconfirmedKey else {
            verification = nil
            return
        }
        do {
            try store.save(stored)
            try use(stored, key: key)
            connection = .awaitingComputer
        } catch {
            actionError = error.localizedDescription
        }
        unconfirmed = nil
        unconfirmedKey = nil
        verification = nil
    }

    /// The codes differ: nothing is saved, the computer will show a new QR.
    func cancelPairing() {
        unconfirmed = nil
        unconfirmedKey = nil
        verification = nil
    }

    /// Forgets the computer: deletes the Keychain item. The Secure Enclave key goes with its handle.
    func unpair() {
        stopPolling()
        do {
            try store.delete()
        } catch {
            actionError = error.localizedDescription
        }
        pairing = nil
        key = nil
        client = nil
        cancelPairing()
        pairingLost = false
        pool = nil
        poolError = nil
        chats = []
        chatsLoaded = false
        openChat = nil
        openChatID = nil
        connection = .notPaired
    }

    // MARK: - Polling (foreground only: no push, no background refresh)

    func startPolling() {
        guard pollTask == nil, client != nil else { return }
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refresh()
                try? await Task.sleep(for: Self.pollInterval)
            }
        }
    }

    func stopPolling() {
        pollTask?.cancel()
        pollTask = nil
    }

    func refresh() async {
        guard let client, let pairing else { return }
        if case .idle = connection { connection = .connecting }
        do {
            let list = try await client.call(Paths.list, ["token": pairing.token], as: ChatList.self)
            chats = list.chats
            chatsLoaded = true
            if list.mode.isSimulation { sawSimulation = true }
            if let id = openChatID {
                do {
                    let reply = try await client.call(Paths.view(id), ["token": pairing.token], as: ChatReply.self)
                    openChat = reply.chat
                } catch LinkError.refused(404, _) {
                    openChat = nil  // deleted elsewhere
                }
            }
            connection = .connected(.now)
            pairingLost = false
        } catch LinkError.refused(403, .some("not paired"))
            where Date.now.timeIntervalSince(pairing.pairedAt) < Self.computerConfirmationWindow + 60 {
            // Paired here, not yet confirmed on the computer: wait, this is not a failure.
            connection = .awaitingComputer
        } catch {
            connection = .failed(error.localizedDescription)
            if let code = (error as? LinkError)?.code, Self.lostPairingCodes.contains(code) { pairingLost = true }
        }
    }

    /// Forgets the lost pairing and goes back to the pairing screen, to scan the computer's new code.
    func rescan() {
        unpair()
        pairingLost = false
    }

    // MARK: - Pool (read only: operations are confirmed on the computer)

    func refreshPool() async {
        guard let client, let pairing else { return }
        poolLoading = true
        defer { poolLoading = false }
        do {
            let reply = try await client.call(Paths.poolPortfolio, ["token": pairing.token], as: PoolReply.self)
            pool = reply.portfolio
            poolError = nil
            if reply.mode.isSimulation { sawSimulation = true }
        } catch let error as LinkError {
            pool = nil
            poolError = error.code.map(ComputerMessages.french) ?? error.localizedDescription
            if let code = error.code, Self.lostPairingCodes.contains(code) { pairingLost = true }
        } catch {
            pool = nil
            poolError = error.localizedDescription
        }
    }

    // MARK: - Conversations

    /// Shows a conversation; its content is fetched now and refreshed with the list.
    func open(chat id: String) async {
        openChatID = id
        if openChat?.id != id { openChat = nil }
        await refresh()
    }

    func closeChat() {
        openChatID = nil
        openChat = nil
    }

    /// Starts a conversation with a first message. Returns the new chat's id.
    func startChat(_ text: String) async -> String? {
        guard let text = Self.clean(text) else { return nil }
        let ack: NewChatAck? = await write(Paths.chats, ["text": text], refusal: "L'ordinateur a refusé le message.") {
            SignedFields.chatMessage(pairingID: $0, counter: $1, chatID: nil, text: text)
        }
        guard let ack else { return nil }
        await open(chat: ack.chatId)
        return ack.chatId
    }

    /// Sends a message in an existing conversation.
    func send(_ text: String, in chatID: String) async -> Bool {
        guard let text = Self.clean(text) else { return false }
        let ack: Ack? = await write(Paths.messages(chatID), ["text": text], refusal: "L'ordinateur a refusé le message.") {
            SignedFields.chatMessage(pairingID: $0, counter: $1, chatID: chatID, text: text)
        }
        await refresh()
        return ack != nil
    }

    /// Deletes a conversation on the computer.
    func delete(chat chatID: String) async {
        let ack: Ack? = await write(Paths.delete(chatID), [:], refusal: "L'ordinateur a refusé la suppression.") {
            SignedFields.deleteMessage(pairingID: $0, counter: $1, chatID: chatID)
        }
        if ack != nil {
            chats.removeAll { $0.id == chatID }
            if openChatID == chatID { closeChat() }
        }
        await refresh()
    }

    // MARK: - Confirmations (each signed over the digest of what the phone shows)

    func acceptPlan(_ pending: Pending) async {
        await confirm(pending, .accept)
    }

    func chooseRecipient(_ pending: Pending, firm: String) async {
        await confirm(pending, .accept, firm: firm)
    }

    /// Only a payment verified on the phone can be confirmed; the digest sent is the phone's own.
    func confirmPayment(_ pending: Pending, verified: PaymentCheck.Verified) async {
        await confirm(pending, .accept, digest: verified.digest)
    }

    func reject(_ pending: Pending) async {
        await confirm(pending, .reject)
    }

    func clearActionError() {
        actionError = nil
    }

    /// The phone's digest of what it shows for `pending` (never the computer's `content`). Nil if it cannot be shown.
    static func content(of pending: Pending, rejecting: Bool = false) -> String? {
        switch pending.request {
        case .plan(let steps): SignedFields.planDigest(id: pending.id, steps: steps.map(\.raw))
        case .recipient(let offers): SignedFields.offersDigest(id: pending.id, offers: offers)
        case .payment(let request):
            switch PaymentCheck.verify(request) {
            case .success(let verified): verified.digest
            // A payment the phone cannot verify can still be refused.
            case .failure: rejecting ? request.digest : nil
            }
        case .unknown: nil
        }
    }

    private func confirm(_ decision: Pending, _ choice: ConfirmationAnswer.Decision, firm: String? = nil,
                         digest: String? = nil) async {
        guard let content = Self.content(of: decision, rejecting: choice == .reject) else {
            actionError = "Cette demande ne peut pas être vérifiée sur ce téléphone : mettez ONA à jour."
            return
        }
        let answer = ConfirmationAnswer(id: decision.id, decision: choice, firm: firm, digest: digest, content: content)
        var fields: [String: any Sendable] = ["id": answer.id, "decision": answer.decision.rawValue]
        fields["firm"] = answer.firm
        fields["digest"] = answer.digest
        let ack: Ack? = await write(Paths.confirm, fields, refusal: "L'ordinateur a refusé la demande.") {
            SignedFields.confirmMessage(pairingID: $0, counter: $1, id: answer.id, decision: answer.decision.rawValue,
                                        firm: answer.firm, digest: answer.digest, content: answer.content)
        }
        if ack != nil { actionError = nil }
        await refresh()
    }

    // MARK: - Writes: token, pairing id, a new counter, the phone's signature

    /// Sends one write. The counter is taken and saved before signing, so it is never reused, even if the person
    /// cancels Face ID or the network fails. Nil (with a message) on failure.
    private func write<T: Decodable & Sendable>(_ path: String, _ fields: [String: any Sendable], refusal: String,
                                     signed: @escaping @Sendable (String, UInt64) -> Data) async -> T? {
        guard client != nil, pairing != nil, key != nil else {
            actionError = "Ce téléphone n'est appairé à aucun ordinateur."
            return nil
        }
        while writing { try? await Task.sleep(for: .milliseconds(50)) }
        writing = true
        sending = true
        defer {
            writing = false
            sending = false
        }
        guard let client, var pairing, let key else { return nil }
        guard pairing.counter < 9_007_199_254_740_991 else {
            actionError = "Cet appairage est épuisé : refaites l'appairage."
            return nil
        }
        pairing.counter += 1
        do {
            try store.save(pairing)
        } catch {
            actionError = error.localizedDescription
            return nil
        }
        self.pairing = pairing
        let counter = pairing.counter, pairingID = pairing.pairingID
        let signature: String
        do {
            signature = try await Task.detached { try key.sign(signed(pairingID, counter)).base64EncodedString() }.value
        } catch {
            actionError = "Action annulée : elle n'a pas été signée."
            return nil
        }
        var body = fields
        body["token"] = pairing.token
        body["pairing_id"] = pairingID
        body["counter"] = counter
        body["signature"] = signature
        do {
            let reply = try await client.call(path, body, as: T.self)
            if let ack = reply as? Ack, ack.mode?.isSimulation == true { sawSimulation = true }
            if let ack = reply as? NewChatAck, ack.mode?.isSimulation == true { sawSimulation = true }
            return reply
        } catch let error as LinkError {
            actionError = error.code.map(ComputerMessages.french) ?? (error == .badReply ? refusal : error.localizedDescription)
            return nil
        } catch {
            actionError = error.localizedDescription
            return nil
        }
    }

    /// Longest message accepted by the computer.
    static let maxMessageLength = 2000

    private static func clean(_ text: String) -> String? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty || trimmed.count > maxMessageLength ? nil : trimmed
    }

    private func use(_ stored: StoredPairing, key: (any DeviceKey)? = nil) throws {
        guard let endpoint = Endpoint(onion: stored.onion, address: stored.address) else {
            throw LinkError.unreachable("L'appairage enregistré est incomplet : refaites-le.")
        }
        self.key = try key ?? DeviceKeys.load(kind: stored.keyKind, representation: stored.keyRepresentation)
        client = ComputerClient(link: makeLink(endpoint), computerKey: stored.computerKey)
        pairing = stored
        chats = []
        chatsLoaded = false
        connection = .idle
    }

    private static func describe(_ failure: PairingPayload.Failure) -> String {
        switch failure {
        case .notAPairingCode: "Ce n'est pas un code d'appairage ONA."
        case .unreadable: "Code d'appairage illisible."
        case .unsupportedVersion(let v): "Version d'appairage \(v) non prise en charge : mettez ONA à jour des deux côtés."
        case .badComputerKey: "La clé de l'ordinateur dans ce code est invalide."
        case .noAddress: "Ce code ne contient pas d'adresse utilisable pour joindre l'ordinateur."
        case .expired: "Ce code d'appairage a expiré : affichez-en un nouveau sur l'ordinateur."
        }
    }
}
