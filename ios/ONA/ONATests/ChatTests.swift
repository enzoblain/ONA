import CryptoKit
import Foundation
import Testing
@testable import ONA

/// Plays a computer that speaks protocol v1 like the desktop apps: checks the commitment, the reveal, the token, the
/// counters and the phone's signatures, and signs every reply with its own key.
final class FakeComputer: ComputerLink, @unchecked Sendable {
    let lock = NSLock()
    let key = P256.Signing.PrivateKey()
    var publicKey: Data { key.publicKey.x963Representation }
    let code = "Y29kZS0xMjM0NTY3OA"
    let pairingID = "p-0123456789abcdef0123456789abcdef"
    let computerNonce = "ffeeddccbbaa99887766554433221100"
    let token = "dG9rZW4tZm9yLXRoZS1waG9uZS0zMi1ieXRlcy0xMjM"

    // Behaviour switches.
    var confirmedOnComputer = true
    var forgeReplies = false
    var refuseAll: (Int, String)?

    // What the phone sent.
    private(set) var commitment: String?
    private(set) var phoneKey: Data?
    private(set) var lastCounter: UInt64 = 0
    private(set) var writes: [(path: String, body: [String: Any])] = []
    private(set) var deleted = false

    /// The pending confirmation of chat-1 (payment v2), as the computer would ask it.
    let pending = Pending(id: "c-" + String(repeating: "3", count: 32), request: .payment(demoPayment()),
                          content: paymentV2Digest)

    func post(_ path: String, body: Data) async throws -> RawReply {
        lock.withLock {
            let object = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any] ?? [:]
            let nonce = object["nonce"] as? String ?? ""
            let (status, reply) = refuseAll.map { ($0.0, ["ok": false, "error": $0.1] as [String: Any]) }
                ?? route(path, object)
            let text = String(decoding: try! JSONSerialization.data(withJSONObject: reply, options: [.sortedKeys]),
                              as: UTF8.self)
            let message = SignedFields.replyMessage(nonce: nonce, method: "POST", path: path, status: status,
                                                    reply: Data(text.utf8))
            let signature = try! SignedFields.lowS(key.signature(for: message)).derRepresentation.base64EncodedString()
            // A forger without the computer's key changes the reply but cannot sign it.
            let sent = forgeReplies ? text.replacingOccurrences(of: "cabinet-b", with: "attacker") : text
            let envelope = try! JSONSerialization.data(withJSONObject: ["reply": sent, "signature": signature])
            return RawReply(status: status, body: envelope)
        }
    }

    private func refuse(_ status: Int, _ error: String) -> (Int, [String: Any]) {
        (status, ["ok": false, "error": error, "mode": "mock"])
    }

    private func route(_ path: String, _ body: [String: Any]) -> (Int, [String: Any]) {
        switch path {
        case Paths.pair:
            guard body["code"] as? String == code else { return refuse(403, "unknown or used pairing code") }
            commitment = body["commitment"] as? String
            return (200, ["ok": true, "pairing_id": pairingID, "computer_nonce": computerNonce, "mode": "mock"])
        case Paths.reveal:
            guard let key = (body["phone_key"] as? String).flatMap({ Data(base64Encoded: $0) }),
                  let phoneNonce = body["phone_nonce"] as? String,
                  SignedFields.commitment(phoneKey: key, phoneNonce: phoneNonce) == commitment
            else { return refuse(403, "pairing commitment does not match") }
            let message = SignedFields.pairMessage(pairingID: pairingID, code: code, phoneKey: key,
                                                   computerKey: publicKey, phoneNonce: phoneNonce,
                                                   computerNonce: computerNonce)
            guard SignedFields.verify(signature: body["signature"] as? String, of: message, by: key)
            else { return refuse(403, "pairing signature does not verify") }
            phoneKey = key
            return (200, ["ok": true, "pairing_id": pairingID, "token": token, "mode": "mock"])
        default:
            break
        }
        guard confirmedOnComputer else { return refuse(403, "not paired") }
        guard body["token"] as? String == token else { return refuse(403, "missing or wrong token") }
        if path == Paths.list {
            let chats: [[String: Any]] = deleted ? [] : [
                ["id": "chat-1", "title": "Trouver un avocat", "updated_at": 1762790000,
                 "preview": "Il reste à confirmer le paiement.", "status": "waiting"],
            ]
            return (200, ["mode": "mock", "chats": chats])
        }
        if path == Paths.view("chat-1") {
            guard !deleted else { return refuse(404, "unknown chat") }
            return (200, ["mode": "mock", "chat": chatView])
        }
        // Writes: pairing id, a counter that goes up, the phone's signature.
        guard let phoneKey, body["pairing_id"] as? String == pairingID else { return refuse(409, "unknown pairing") }
        guard let number = body["counter"] as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              !CFNumberIsFloatType(number), number.int64Value > Int64(lastCounter)
        else { return refuse(409, "replayed request") }
        let counter = number.uint64Value
        let signed: Data
        switch path {
        case Paths.chats:
            signed = SignedFields.chatMessage(pairingID: pairingID, counter: counter, chatID: nil,
                                              text: body["text"] as? String ?? "")
        case Paths.messages("chat-1"):
            signed = SignedFields.chatMessage(pairingID: pairingID, counter: counter, chatID: "chat-1",
                                              text: body["text"] as? String ?? "")
        case Paths.delete("chat-1"):
            signed = SignedFields.deleteMessage(pairingID: pairingID, counter: counter, chatID: "chat-1")
        case Paths.confirm:
            guard body["id"] as? String == pending.id, let content = pending.content else {
                return refuse(409, "stale confirmation")
            }
            // The computer puts the digest of what it asked: the phone must have shown the same thing.
            signed = SignedFields.confirmMessage(pairingID: pairingID, counter: counter, id: pending.id,
                                                 decision: body["decision"] as? String ?? "",
                                                 firm: body["firm"] as? String, digest: body["digest"] as? String,
                                                 content: content)
        default:
            return refuse(404, "not found")
        }
        lastCounter = counter
        guard SignedFields.verify(signature: body["signature"] as? String, of: signed, by: phoneKey) else {
            return refuse(409, "signature does not verify")
        }
        writes.append((path, body))
        if path == Paths.delete("chat-1") { deleted = true }
        if path == Paths.chats { return (200, ["ok": true, "chat_id": "chat-1", "mode": "mock"]) }
        return (200, ["ok": true, "mode": "mock"])
    }

    private var chatView: [String: Any] {
        guard case .payment(let payment) = pending.request else { return [:] }
        return ["id": "chat-1", "title": "Trouver un avocat", "status": "waiting", "working": NSNull(), "items": [
            ["id": "i-1", "kind": "user", "at": 1, "text": "Trouve-moi un avocat"],
            ["id": "i-2", "kind": "activity", "at": 2, "tool": "search", "text": "Recherche : 2 résultats"],
            ["id": "i-3", "kind": "confirmation", "at": 3, "state": "accepted",
             "pending": ["id": "c-1", "kind": "plan", "plan": ["search"], "content": "x"]],
            ["id": "i-4", "kind": "confirmation", "at": 4, "state": "pending", "pending": [
                "id": pending.id, "kind": "payment", "content": paymentV2Digest, "payment": [
                    "to": payment.to, "amount": payment.amount, "screen": payment.screen, "digest": payment.digest,
                    "digest_version": 2, "network": "testnet", "contract": "pay.ona.testnet", "mission_id": "m-1",
                    "nonce": "00112233445566778899aabbccddeeff",
                ],
            ]],
            ["id": "i-5", "kind": "teleport", "at": 5],
        ]]
    }

    func lastWrite() -> (path: String, body: [String: Any])? { lock.withLock { writes.last } }
}

private struct RefusingKey: DeviceKey {
    let inner = SoftwareDeviceKey()
    var kind: DeviceKeyKind { inner.kind }
    var publicKey: Data { inner.publicKey }
    var storedRepresentation: Data { inner.storedRepresentation }
    struct Cancelled: Error {}
    func sign(_ message: Data) throws -> Data { throw Cancelled() }
}

@MainActor
@Suite("Pairing v1 in the model")
struct PairingModelTests {
    let computer = FakeComputer()

    private func model(store: MemoryPairingStore = MemoryPairingStore(),
                       key: @escaping @Sendable () throws -> any DeviceKey = { SoftwareDeviceKey() }) -> RemoteModel {
        let computer = self.computer
        return RemoteModel(store: store, makeLink: { _ in computer }, makeKey: key)
    }

    @Test func commitsRevealsAndSavesOnlyOnceTheCodesMatch() async throws {
        let store = MemoryPairingStore()
        let key = SoftwareDeviceKey()
        let model = model(store: store, key: { key })
        await model.pair(with: payloadText(computerKey: computer.publicKey))
        #expect(model.actionError == nil)
        #expect(computer.phoneKey == key.publicKey)
        let verification = try #require(model.verification)
        #expect(verification.code.count == 6)
        // Nothing is kept before the person compares the codes.
        #expect(!model.isPaired)
        #expect(try store.load() == nil)

        model.verificationMatches()
        let stored = try #require(try store.load())
        #expect(stored.pairingID == computer.pairingID)
        #expect(stored.token == computer.token)
        #expect(stored.counter == 0)
        #expect(stored.computerKey == computer.publicKey)
        #expect(model.isPaired)
    }

    @Test func differentCodesSaveNothing() async throws {
        let store = MemoryPairingStore()
        let model = model(store: store)
        await model.pair(with: payloadText(computerKey: computer.publicKey))
        model.cancelPairing()
        #expect(model.verification == nil)
        #expect(!model.isPaired)
        #expect(try store.load() == nil)
    }

    @Test func waitsForTheComputerConfirmation() async throws {
        computer.lock.withLock { computer.confirmedOnComputer = false }
        let model = model()
        await model.pair(with: payloadText(computerKey: computer.publicKey))
        model.verificationMatches()
        await model.refresh()
        #expect(model.connection == .awaitingComputer)
        computer.lock.withLock { computer.confirmedOnComputer = true }
        await model.refresh()
        guard case .connected = model.connection else { Issue.record("\(model.connection)"); return }
        #expect(model.waitingCount == 1)
        #expect(model.isSimulation)
    }

    @Test func aRefusedCodeStoresNothing() async throws {
        let store = MemoryPairingStore()
        let model = model(store: store)
        await model.pair(with: payloadText(computerKey: computer.publicKey, code: "autre"))
        #expect(model.actionError == ComputerMessages.french("unknown or used pairing code"))
        #expect(model.verification == nil)
        #expect(try store.load() == nil)
    }

    @Test func aComputerWithAnotherKeyIsRefused() async throws {
        // The QR names a key; a program on the computer's port without it cannot answer.
        let model = model()
        await model.pair(with: payloadText(computerKey: SoftwareDeviceKey().publicKey))
        #expect(model.actionError == LinkError.notAuthenticated.localizedDescription)
        #expect(model.verification == nil)
    }

    @Test func cancelledSignatureSendsNoReveal() async throws {
        let model = model(key: { RefusingKey() })
        await model.pair(with: payloadText(computerKey: computer.publicKey))
        #expect(model.actionError != nil)
        #expect(computer.phoneKey == nil)
        #expect(model.verification == nil)
    }
}

@MainActor
@Suite("Conversations v1 in the model")
struct ChatModelTests {
    let computer = FakeComputer()
    let store = MemoryPairingStore()

    private func paired(key: any DeviceKey = SoftwareDeviceKey()) async -> RemoteModel {
        let computer = self.computer
        let model = RemoteModel(store: store, makeLink: { _ in computer }, makeKey: { key })
        await model.pair(with: payloadText(computerKey: computer.publicKey))
        model.verificationMatches()
        await model.refresh()
        return model
    }

    @Test func eachWriteTakesANewSavedCounter() async throws {
        let model = await paired()
        #expect(await model.startChat("  Trouve-moi un avocat  ") == "chat-1")
        #expect(model.openChat?.id == "chat-1")
        #expect(computer.lastWrite()?.body["text"] as? String == "Trouve-moi un avocat")
        #expect(computer.lastWrite()?.body["counter"] as? Int == 1)
        #expect(await model.send("Plutôt à Lyon ?", in: "chat-1"))
        #expect(computer.lastWrite()?.body["counter"] as? Int == 2)
        #expect(try store.load()?.counter == 2)
        #expect(model.actionError == nil)
    }

    @Test func aCounterIsNeverReusedAfterARefusal() async throws {
        let model = await paired()
        computer.lock.withLock { computer.refuseAll = (409, "empty or too long message") }
        #expect(await model.send("a", in: "chat-1") == false)
        #expect(model.actionError == ComputerMessages.french("empty or too long message"))
        computer.lock.withLock { computer.refuseAll = nil }
        #expect(await model.send("b", in: "chat-1"))
        #expect(computer.lastWrite()?.body["counter"] as? Int == 2)
    }

    @Test func confirmsThePaymentOverWhatThePhoneShows() async throws {
        let model = await paired()
        await model.open(chat: "chat-1")
        let pending = try #require(model.openChat?.pending)
        #expect(pending.id == computer.pending.id)
        guard case .payment(let request) = pending.request else { Issue.record("payment"); return }
        await model.confirmPayment(pending, verified: try PaymentCheck.verify(request).get())
        #expect(model.actionError == nil)
        let write = try #require(computer.lastWrite())
        #expect(write.path == Paths.confirm)
        #expect(write.body["digest"] as? String == paymentV2Digest)
        #expect(write.body["decision"] as? String == "accept")
        #expect(write.body["firm"] == nil)
    }

    @Test func aForgedReplyIsNeverShown() async throws {
        let model = await paired()
        computer.lock.withLock { computer.forgeReplies = true }
        await model.open(chat: "chat-1")
        #expect(model.openChat == nil)
        #expect(model.connection == .failed(LinkError.notAuthenticated.localizedDescription))
    }

    @Test func contentIsTheDigestOfWhatIsShown() throws {
        let plan = Pending(id: "c-1", request: .plan([.search, .read]), content: "whatever the computer says")
        #expect(RemoteModel.content(of: plan) == "10b2ecd6ff60485e505b911709ed14b162137f0237abaa8aed21eee7c26edb84")
        let offer = Offer(firmId: "cabinet-b", priceCents: 60000, delayDays: 10, sourceSpans: ["Forfait 600 euros, sous 10 jours"])
        #expect(RemoteModel.content(of: Pending(id: "c-2", request: .recipient([offer])))
                == "5127c86b14fc1406536bc274ea9c5b9e85e4a9b7e2adaf0c7b156ccf2dfb97b6")
        let bad = Pending(id: "c-3", request: .payment(demoPayment(to: "attacker.testnet")))
        #expect(RemoteModel.content(of: bad) == nil)
        #expect(RemoteModel.content(of: bad, rejecting: true) == paymentV2Digest)
    }

    @Test func rejectIsSignedToo() async throws {
        let model = await paired()
        await model.open(chat: "chat-1")
        await model.reject(try #require(model.openChat?.pending))
        #expect(model.actionError == nil)
        #expect(computer.lastWrite()?.body["decision"] as? String == "reject")
    }

    @Test func deleteClosesTheChat() async throws {
        let model = await paired()
        await model.open(chat: "chat-1")
        await model.delete(chat: "chat-1")
        #expect(computer.lastWrite()?.path == Paths.delete("chat-1"))
        #expect(model.openChatID == nil)
        #expect(model.chats.isEmpty)
    }

    @Test func emptyOrHugeMessagesAreNotSent() async {
        let model = await paired()
        #expect(await model.startChat("   ") == nil)
        #expect(await model.send(String(repeating: "a", count: RemoteModel.maxMessageLength + 1), in: "chat-1") == false)
        #expect(computer.lastWrite() == nil)
    }

    @Test func reloadsAStoredPairingAndKeepsCounting() async throws {
        let key = SoftwareDeviceKey()
        let model = await paired(key: key)
        #expect(await model.send("un", in: "chat-1"))
        let computer = self.computer
        let reopened = RemoteModel(store: store, makeLink: { _ in computer }, makeKey: { SoftwareDeviceKey() })
        #expect(reopened.isPaired)
        #expect(await reopened.send("deux", in: "chat-1"))
        // Signed with the key loaded back, and a counter after the last one.
        #expect(computer.lastWrite()?.body["counter"] as? Int == 2)
    }

    @Test func notPairedCannotConfirm() async {
        let model = RemoteModel(store: MemoryPairingStore(), makeLink: { _ in UnavailableLink(reason: "") },
                                makeKey: { SoftwareDeviceKey() })
        await model.acceptPlan(Pending(id: "c-1", request: .plan([.search])))
        #expect(model.actionError == "Ce téléphone n'est appairé à aucun ordinateur.")
    }

    @Test func aLostPairingOffersToRescan() async throws {
        let model = await paired()
        #expect(!model.pairingLost)
        computer.lock.withLock { computer.refuseAll = (403, "missing or wrong token") }
        await model.refresh()
        #expect(model.pairingLost)
        model.rescan()
        #expect(!model.isPaired)
        #expect(!model.pairingLost)
        #expect(try store.load() == nil)
    }

    @Test func anOrdinaryFailureDoesNotAskToRescan() async {
        let model = await paired()
        computer.lock.withLock { computer.refuseAll = (409, "empty or too long message") }
        await model.refresh()
        #expect(!model.pairingLost)
    }

    @Test func unpairForgetsEverything() async throws {
        let model = await paired()
        model.unpair()
        #expect(!model.isPaired)
        #expect(model.connection == .notPaired)
        #expect(try store.load() == nil)
    }
}
