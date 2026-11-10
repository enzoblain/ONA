import CryptoKit
import Foundation
import Testing
@testable import ONA

/// JSON shaped like the mock computer's replies (ios/MockComputer/chats.py).
enum ChatFixtures {
    static let list = Data("""
    {"mode":"mock","chats":[
      {"id":"chat-1","title":"Trouver un avocat","updated_at":1762790000,"preview":"Il reste à confirmer le paiement.",
       "status":"waiting"},
      {"id":"chat-2","title":"Ancienne demande","updated_at":1762700000,"preview":"C'est fait.","status":"idle"}]}
    """.utf8)

    static let emptyList = Data(#"{"mode":"mock","chats":[]}"#.utf8)

    static let waitingForPayment = Data("""
    {"mode":"mock","chat":{"id":"chat-1","title":"Trouver un avocat","status":"waiting","working":null,"items":[
      {"id":"i-1","kind":"user","at":1,"text":"Trouve-moi un avocat"},
      {"id":"i-2","kind":"activity","at":2,"tool":"search","text":"Recherche : 2 résultats"},
      {"id":"i-3","kind":"agent","at":3,"text":"Il reste à confirmer le paiement."},
      {"id":"i-4","kind":"confirmation","at":4,"state":"accepted","pending":{"id":"c-1","kind":"plan","plan":["search"]}},
      {"id":"i-5","kind":"confirmation","at":5,"state":"pending","pending":{"id":"c-3","kind":"payment","payment":{
        "to":"cabinet-b.testnet","amount":"1000000000000000000000000",
        "screen":"Pay 1000000000000000000000000 yoctoNEAR to cabinet-b.testnet",
        "digest":"a43ba249fbdd55a64a0647282b6dff66d660a1d8a8d75a8fbf3533bfa450fa31"}}},
      {"id":"i-6","kind":"teleport","at":6}]}}
    """.utf8)
}

@Suite("Chat messages")
struct ChatMessageTests {
    @Test func decodesTheList() throws {
        let list = try ProtocolCoding.decoder.decode(ChatList.self, from: ChatFixtures.list)
        #expect(list.mode.isSimulation)
        #expect(list.chats.map(\.id) == ["chat-1", "chat-2"])
        #expect(list.chats.map(\.status) == [.waiting, .idle])
    }

    @Test func decodesAConversation() throws {
        let chat = try ProtocolCoding.decoder.decode(ChatReply.self, from: ChatFixtures.waitingForPayment).chat
        #expect(chat.items.count == 6)
        guard case .user(let text) = chat.items[0].content else { Issue.record("user"); return }
        #expect(text == "Trouve-moi un avocat")
        guard case .activity(let tool, _) = chat.items[1].content else { Issue.record("activity"); return }
        #expect(tool == "search")
        guard case .unknown(let kind) = chat.items[5].content else { Issue.record("unknown"); return }
        #expect(kind == "teleport")
        // Only the confirmation still pending counts, not the plan already accepted.
        #expect(chat.pending?.id == "c-3")
    }

    @Test func messageBytesBindTheChatAndTheText() {
        let a = SignedFields.chatMessage(pairingID: "p-1", chatID: nil, text: "bonjour")
        #expect(a != SignedFields.chatMessage(pairingID: "p-1", chatID: "chat-1", text: "bonjour"))
        #expect(a != SignedFields.chatMessage(pairingID: "p-1", chatID: nil, text: "bonsoir"))
        #expect(a != SignedFields.chatMessage(pairingID: "p-2", chatID: nil, text: "bonjour"))
        #expect(SignedFields.deleteChat(pairingID: "p-1", chatID: "chat-1")
                != SignedFields.deleteChat(pairingID: "p-1", chatID: "chat-2"))
    }

    @Test func chatIdsCannotEscapeThePath() {
        #expect(ChatPaths.chat("chat-1") == "v0/chats/chat-1")
        #expect(ChatPaths.chat("../v0/confirm") == "v0/chats/invalid")
        #expect(ChatPaths.delete("a b") == "v0/chats/invalid/delete")
    }
}

@MainActor
@Suite("Conversations in the model")
struct ChatModelTests {
    let computer = SoftwareDeviceKey()

    private func paired(key: any DeviceKey = SoftwareDeviceKey()) async -> (RemoteModel, FakeLink) {
        let link = FakeLink(stateData: Data(), computerKey: computer.publicKey)
        let model = RemoteModel(store: MemoryPairingStore(), makeLink: { _ in link }, makeKey: { key })
        await model.pair(with: PairingPayloadFixture.text(computerKey: computer.publicKey))
        return (model, link)
    }

    private func verifies(_ signature: String, _ bytes: Data, key: any DeviceKey) throws -> Bool {
        let der = try #require(Data(base64Encoded: signature))
        return try P256.Signing.PublicKey(x963Representation: key.publicKey)
            .isValidSignature(P256.Signing.ECDSASignature(derRepresentation: der), for: bytes)
    }

    @Test func loadsTheListAndCountsWaitingChats() async {
        let (model, _) = await paired()
        #expect(model.chatsLoaded)
        #expect(model.chats.count == 2)
        #expect(model.waitingCount == 1)
        #expect(model.isSimulation)
    }

    @Test func newChatIsSignedWithoutChatID() async throws {
        let key = SoftwareDeviceKey()
        let (model, link) = await paired(key: key)
        let id = await model.startChat("  Trouve-moi un avocat  ")
        #expect(id == "chat-1")
        #expect(model.openChatID == "chat-1")
        #expect(model.openChat?.id == "chat-1")
        let request = try #require(link.newChats.first)
        #expect(request.text == "Trouve-moi un avocat")
        #expect(request.pairingId == "p-7")
        #expect(try verifies(request.signature,
                             SignedFields.chatMessage(pairingID: "p-7", chatID: nil, text: "Trouve-moi un avocat"),
                             key: key))
    }

    @Test func messageIsSignedForItsChat() async throws {
        let key = SoftwareDeviceKey()
        let (model, link) = await paired(key: key)
        #expect(await model.send("Plutôt à Lyon ?", in: "chat-1"))
        let (chatID, request) = try #require(link.messages.first)
        #expect(chatID == "chat-1")
        #expect(try verifies(request.signature,
                             SignedFields.chatMessage(pairingID: "p-7", chatID: "chat-1", text: "Plutôt à Lyon ?"),
                             key: key))
    }

    @Test func emptyOrHugeMessagesAreNotSent() async {
        let (model, link) = await paired()
        #expect(await model.startChat("   ") == nil)
        #expect(await model.send(String(repeating: "a", count: RemoteModel.maxMessageLength + 1), in: "chat-1") == false)
        #expect(link.newChats.isEmpty)
        #expect(link.messages.isEmpty)
    }

    @Test func deleteIsSignedAndClosesTheChat() async throws {
        let key = SoftwareDeviceKey()
        let (model, link) = await paired(key: key)
        await model.open(chat: "chat-1")
        await model.delete(chat: "chat-1")
        let (chatID, request) = try #require(link.deletions.first)
        #expect(chatID == "chat-1")
        #expect(try verifies(request.signature, SignedFields.deleteChat(pairingID: "p-7", chatID: "chat-1"), key: key))
        #expect(model.openChatID == nil)
        #expect(model.chats.isEmpty)
    }

    @Test func aChatDeletedElsewhereDisappears() async {
        let (model, link) = await paired()
        await model.open(chat: "chat-1")
        #expect(model.openChat != nil)
        link.lock.withLock { link.deleted = true }
        await model.refresh()
        #expect(model.openChat == nil)
        #expect(model.chats.isEmpty)
    }
}

enum PairingPayloadFixture {
    static func text(computerKey: Data) -> String {
        let object: [String: Any] = ["v": 0, "name": "Mac de test", "address": "http://computer.test:8790",
                                     "onion": NSNull(), "computer_key": computerKey.base64EncodedString(),
                                     "code": "Y29kZS0xMjM0NTY3OA"]
        let json = try! JSONSerialization.data(withJSONObject: object).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return PairingPayload.prefix + json
    }
}
