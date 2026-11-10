import Foundation
import Observation

/// What the remote control knows about the computer. Only the pairing is kept (Keychain); the conversations live on
/// the computer and are rebuilt in memory by polling.
@MainActor
@Observable
final class RemoteModel {
    enum Connection: Equatable {
        case notPaired
        case idle
        case connecting
        case connected(Date)
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

    static let pollInterval: Duration = .seconds(2)

    private var link: (any ComputerLink)?
    private var key: (any DeviceKey)?
    private var pollTask: Task<Void, Never>?
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

    // MARK: - Pairing

    /// Pairs with the computer named in a scanned (or pasted) pairing code.
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
            // Creating and using a Secure Enclave key can show the Face ID sheet: off the main thread.
            let (key, request) = try await Task.detached {
                let key = try makeKey()
                let message = SignedFields.pairMessage(code: payload.code, phoneKey: key.publicKey,
                                                       computerKey: payload.computerKey)
                let request = PairRequest(code: payload.code, phoneKey: key.publicKey.base64EncodedString(),
                                          signature: try key.sign(message).base64EncodedString())
                return (key, request)
            }.value
            let link = makeLink(endpoint)
            let ack = try await link.pair(request)
            if ack.mode?.isSimulation == true { sawSimulation = true }
            guard ack.ok, let pairingID = ack.pairingId else {
                actionError = ack.error.map(ComputerMessages.french) ?? "L'ordinateur a refusé l'appairage."
                return
            }
            let stored = StoredPairing(
                pairingID: pairingID, name: payload.name, address: payload.address, onion: payload.onion,
                computerKey: payload.computerKey, keyKind: key.kind, keyRepresentation: key.storedRepresentation,
                pairedAt: .now
            )
            try store.save(stored)
            try use(stored, key: key, link: link)
            verification = PendingVerification(
                code: SignedFields.verificationCode(computerKey: payload.computerKey, phoneKey: key.publicKey,
                                                    code: payload.code),
                computerName: payload.name
            )
            actionError = nil
            await refresh()
        } catch {
            actionError = error.localizedDescription
        }
    }

    /// The person saw the same code on both screens.
    func verificationMatches() {
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
        link = nil
        chats = []
        chatsLoaded = false
        openChat = nil
        openChatID = nil
        verification = nil
        connection = .notPaired
    }

    // MARK: - Polling (foreground only: no push, no background refresh)

    func startPolling() {
        guard pollTask == nil, link != nil else { return }
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
        guard let link else { return }
        if case .idle = connection { connection = .connecting }
        do {
            let list = try await link.chats()
            chats = list.chats
            chatsLoaded = true
            if list.mode.isSimulation { sawSimulation = true }
            if let id = openChatID {
                do {
                    openChat = try await link.chat(id).chat
                } catch LinkError.badStatus(404, _) {
                    openChat = nil  // deleted elsewhere
                }
            }
            connection = .connected(.now)
        } catch {
            connection = .failed(error.localizedDescription)
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
        guard let text = Self.clean(text), let pairing else { return nil }
        guard let request = await signedMessage(text, pairingID: pairing.pairingID, chatID: nil) else { return nil }
        guard let link else { return nil }
        sending = true
        defer { sending = false }
        do {
            let ack = try await link.newChat(request)
            if ack.mode?.isSimulation == true { sawSimulation = true }
            guard ack.ok, let id = ack.chatId else {
                actionError = ack.error.map(ComputerMessages.french) ?? "L'ordinateur a refusé le message."
                return nil
            }
            await open(chat: id)
            return id
        } catch {
            actionError = error.localizedDescription
            return nil
        }
    }

    /// Sends a message in an existing conversation.
    func send(_ text: String, in chatID: String) async -> Bool {
        guard let text = Self.clean(text), let pairing, let link else { return false }
        guard let request = await signedMessage(text, pairingID: pairing.pairingID, chatID: chatID) else { return false }
        sending = true
        defer { sending = false }
        do {
            let ack = try await link.send(request, to: chatID)
            if ack.mode?.isSimulation == true { sawSimulation = true }
            guard ack.ok else {
                actionError = ack.error.map(ComputerMessages.french) ?? "L'ordinateur a refusé le message."
                return false
            }
            await refresh()
            return true
        } catch {
            actionError = error.localizedDescription
            return false
        }
    }

    /// Deletes a conversation on the computer.
    func delete(chat chatID: String) async {
        guard let pairing, let link else { return }
        let pairingID = pairing.pairingID
        guard let signature = await sign(SignedFields.deleteChat(pairingID: pairingID, chatID: chatID)) else { return }
        do {
            let ack = try await link.deleteChat(chatID, ChatDeleteRequest(pairingId: pairingID, signature: signature))
            guard ack.ok else {
                actionError = ack.error.map(ComputerMessages.french) ?? "L'ordinateur a refusé la suppression."
                return
            }
            chats.removeAll { $0.id == chatID }
            if openChatID == chatID { closeChat() }
            await refresh()
        } catch {
            actionError = error.localizedDescription
        }
    }

    // MARK: - Confirmations (each one signed, each signature asks for Face ID on an iPhone)

    func acceptPlan(_ pending: Pending) async {
        await confirm(ConfirmationAnswer(id: pending.id, decision: .accept))
    }

    func chooseRecipient(_ pending: Pending, firm: String) async {
        await confirm(ConfirmationAnswer(id: pending.id, decision: .accept, firm: firm))
    }

    /// Only a payment verified on the phone can be confirmed; the digest sent is the phone's own.
    func confirmPayment(_ pending: Pending, verified: PaymentCheck.Verified) async {
        await confirm(ConfirmationAnswer(id: pending.id, decision: .accept, digest: verified.digest))
    }

    func reject(_ pending: Pending) async {
        await confirm(ConfirmationAnswer(id: pending.id, decision: .reject))
    }

    func clearActionError() {
        actionError = nil
    }

    private func confirm(_ answer: ConfirmationAnswer) async {
        guard let link, let pairing else {
            actionError = "Ce téléphone n'est appairé à aucun ordinateur."
            return
        }
        let pairingID = pairing.pairingID
        sending = true
        guard let signature = await sign(SignedFields.confirmMessage(answer.unsigned, pairingID: pairingID)) else {
            sending = false
            return
        }
        var signed = answer.unsigned
        signed.pairingId = pairingID
        signed.signature = signature
        do {
            let ack = try await link.confirm(signed)
            if ack.mode?.isSimulation == true { sawSimulation = true }
            actionError = ack.ok ? nil : (ack.error.map(ComputerMessages.french) ?? "L'ordinateur a refusé la demande.")
        } catch {
            actionError = error.localizedDescription
        }
        sending = false
        await refresh()
    }

    // MARK: - Signing

    /// Signs off the main thread (a Secure Enclave key can show Face ID). Nil, with a message, if it was refused.
    private func sign(_ bytes: Data) async -> String? {
        guard let key else {
            actionError = "Ce téléphone n'est appairé à aucun ordinateur."
            return nil
        }
        do {
            return try await Task.detached { try key.sign(bytes).base64EncodedString() }.value
        } catch {
            actionError = "Action annulée : elle n'a pas été signée."
            return nil
        }
    }

    private func signedMessage(_ text: String, pairingID: String, chatID: String?) async -> ChatMessageRequest? {
        let bytes = SignedFields.chatMessage(pairingID: pairingID, chatID: chatID, text: text)
        guard let signature = await sign(bytes) else { return nil }
        return ChatMessageRequest(text: text, pairingId: pairingID, signature: signature)
    }

    /// Longest message accepted by the computer.
    static let maxMessageLength = 2000

    private static func clean(_ text: String) -> String? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty || trimmed.count > maxMessageLength ? nil : trimmed
    }

    private func use(_ stored: StoredPairing, key: (any DeviceKey)? = nil, link: (any ComputerLink)? = nil) throws {
        guard let endpoint = Endpoint(onion: stored.onion, address: stored.address) else {
            throw LinkError.unreachable("L'appairage enregistré est incomplet : refaites-le.")
        }
        self.key = try key ?? DeviceKeys.load(kind: stored.keyKind, representation: stored.keyRepresentation)
        self.link = link ?? makeLink(endpoint)
        pairing = stored
        chats = []
        chatsLoaded = false
        connection = .idle
    }

    private static func describe(_ failure: PairingPayload.Failure) -> String {
        switch failure {
        case .notAPairingCode: "Ce n'est pas un code d'appairage ONA."
        case .unreadable: "Code d'appairage illisible."
        case .unsupportedVersion(let v): "Version d'appairage \(v) non prise en charge : mettez l'app à jour."
        case .badComputerKey: "La clé de l'ordinateur dans ce code est invalide."
        case .noAddress: "Ce code ne contient pas l'adresse de l'ordinateur."
        }
    }
}
