import CryptoKit
import Foundation
import Testing
@testable import ONADesktopCore

private let onaCoreDemoDigest = "a43ba249fbdd55a64a0647282b6dff66d660a1d8a8d75a8fbf3533bfa450fa31"

@Suite("Protocol bytes (same vectors as the iPhone app and the Python mock)")
struct ProtocolBytesTests {
    @Test func fieldsLayout() {
        let encoded = ProtocolBytes.encode([.text("ab"), .bytes(Data([1])), .text(nil)])
        #expect(Array(encoded) == [2, 0, 0, 0, 0x61, 0x62, 1, 0, 0, 0, 1, 0, 0, 0, 0])
    }

    @Test func verificationCodeVector() {
        let computer = Data([4] + (1...64).map { UInt8($0) }), phone = Data([4] + (65...128).map { UInt8($0) })
        #expect(ProtocolBytes.verificationCode(computerKey: computer, phoneKey: phone, code: "c29tZS1jb2Rl") == "093832")
    }

    @Test func verifiesTheCryptoKitVectorFromTheIPhoneApp() throws {
        // Same vector as ios/MockComputer/test_pairing.py (produced by CryptoKit in ios/ONA's tests).
        let key = try #require(Data(base64Encoded: "BAyQHUI8gxyoXifHPCY7oTJyG7nXqExPA4CypnVv1gEzHIhwI03sh4UEwXQUT6SxS2amUWkWBtgXPlW9N+OBVp4="))
        let message = ProtocolBytes.confirmMessage(pairingID: "p-1", id: "c-3", decision: "accept", firm: nil, digest: "ab")
        let signature = "MEYCIQD0k1mmYvXAC4IWy6hNET+ZmTBAdqnrm+5gdIb1rIs7QgIhALKtYM/kYDAzqHau+ifTx8uJI9AdlkYaUn5w9w8M3AdK"
        #expect(ProtocolBytes.verify(signature: signature, of: message, by: key))
        #expect(!ProtocolBytes.verify(signature: signature, of: message + Data([0]), by: key))
    }

    @Test func parsesTheOnaCorePaymentScreen() {
        let parsed = ProtocolBytes.parsePaymentScreen("Pay 1000000000000000000000000 yoctoNEAR to cabinet-b.testnet")
        #expect(parsed?.amount == "1000000000000000000000000")
        #expect(parsed?.to == "cabinet-b.testnet")
        #expect(ProtocolBytes.parsePaymentScreen("Pay me to x") == nil)
    }
}

@Suite("HTTP")
struct HTTPTests {
    @Test func parsesARequestWithABody() {
        let raw = Data("POST /v0/pair HTTP/1.0\r\nHost: x.onion\r\nContent-Length: 2\r\n\r\n{}".utf8)
        #expect(HTTPRequest.parse(raw) == .request(HTTPRequest(method: "POST", path: "/v0/pair", body: Data("{}".utf8))))
    }

    @Test func waitsForTheWholeBody() {
        #expect(HTTPRequest.parse(Data("POST /v0/pair HTTP/1.0\r\nContent-Length: 5\r\n\r\n{}".utf8)) == .incomplete)
        #expect(HTTPRequest.parse(Data("GET /v0/chats HTTP/1.0\r\n".utf8)) == .incomplete)
    }

    @Test func refusesBadOrHugeRequests() {
        #expect(HTTPRequest.parse(Data("HELLO\r\n\r\n".utf8)) == .invalid(400))
        #expect(HTTPRequest.parse(Data("POST /x HTTP/1.0\r\nContent-Length: 999999\r\n\r\n".utf8)) == .invalid(413))
        #expect(HTTPRequest.parse(Data(repeating: 0x41, count: HTTPRequest.maxHeader + 1)) == .invalid(431))
    }
}

/// Plays the iPhone: its own key, signing like the app.
struct Phone {
    let key = P256.Signing.PrivateKey()
    var publicKey: Data { key.publicKey.x963Representation }

    func sign(_ data: Data) -> String {
        try! key.signature(for: data).derRepresentation.base64EncodedString()
    }

    @MainActor
    func pair(with authority: PairingAuthority) -> String? {
        guard let code = authority.pairingCode else { return nil }
        let proof = sign(ProtocolBytes.pairMessage(code: code, phoneKey: publicKey, computerKey: authority.computerPublicKey))
        return try? authority.pair(code: code, phoneKeyBase64: publicKey.base64EncodedString(), signature: proof).get()
    }
}

@MainActor
@Suite("Pairing on the computer")
struct PairingTests {
    @Test func pairsThenWaitsForTheCodeComparison() throws {
        let authority = PairingAuthority(name: "Mac", store: MemoryPairingStore())
        let phone = Phone()
        let code = try #require(authority.pairingCode)
        let id = try #require(phone.pair(with: authority))
        #expect(authority.awaiting?.code == ProtocolBytes.verificationCode(
            computerKey: authority.computerPublicKey, phoneKey: phone.publicKey, code: code))
        #expect(authority.pairingCode == nil)  // single use

        let message = ProtocolBytes.chatMessage(pairingID: id, chatID: nil, text: "bonjour")
        #expect(authority.check(pairingID: id, signature: phone.sign(message), signed: { _ in message }) == .notVerified)
        authority.confirmCode()
        #expect(authority.isPaired)
        #expect(authority.check(pairingID: id, signature: phone.sign(message), signed: { _ in message }) == nil)
        #expect(authority.check(pairingID: id, signature: Phone().sign(message), signed: { _ in message }) == .badSignature)
        #expect(authority.check(pairingID: "p-x", signature: phone.sign(message), signed: { _ in message }) == .unknownPairing)
    }

    @Test func refusesAProofFromAnotherKey() throws {
        let authority = PairingAuthority(name: "Mac", store: MemoryPairingStore())
        let code = try #require(authority.pairingCode)
        let phone = Phone(), other = Phone()
        let proof = other.sign(ProtocolBytes.pairMessage(code: code, phoneKey: phone.publicKey,
                                                         computerKey: authority.computerPublicKey))
        let result = authority.pair(code: code, phoneKeyBase64: phone.publicKey.base64EncodedString(), signature: proof)
        #expect(throws: ProtocolError.pairingSignature) { try result.get() }
        #expect(authority.pairingCode == code)  // still usable
    }

    @Test func keepsTheComputerKeyAcrossLaunches() {
        let store = MemoryPairingStore()
        let first = PairingAuthority(name: "Mac", store: store).computerPublicKey
        #expect(PairingAuthority(name: "Mac", store: store).computerPublicKey == first)
    }

    @Test func forgettingIssuesANewCode() throws {
        let authority = PairingAuthority(name: "Mac", store: MemoryPairingStore())
        _ = Phone().pair(with: authority)
        authority.confirmCode()
        authority.forgetPhone()
        #expect(!authority.isPaired)
        #expect(authority.pairingCode != nil)
    }
}

@MainActor
@Suite("Missions over the real ona-core")
struct EngineTests {
    func run(_ engine: ChatEngine, _ chat: Chat, until status: ChatStatus, limit: Int = 30) {
        for _ in 0..<limit where chat.status != status { engine.tick() }
    }

    @Test func fullMissionDrivenByOnaCore() throws {
        let engine = ChatEngine(makeCore: { OnaCoreMission() })
        let chat = try engine.create("Trouve-moi un avocat en droit du travail").get()
        let plan = try #require(chat.pending)
        guard case .plan(let steps) = plan.request else { Issue.record("plan"); return }
        #expect(steps.first == "search")
        #expect(engine.mode == "mock")

        #expect(engine.confirm(id: plan.id, decision: "accept", firm: nil, digest: nil) == nil)
        run(engine, chat, until: .waiting)
        let offers = try #require(chat.pending)
        guard case .recipient(let ranked) = offers.request else { Issue.record("recipient"); return }
        #expect(Set(ranked.map(\.firmID)) == ["cabinet-a", "cabinet-b"])
        #expect(engine.confirm(id: offers.id, decision: "accept", firm: "cabinet-b", digest: nil) == nil)

        run(engine, chat, until: .waiting)
        let payment = try #require(chat.pending)
        guard case .payment(let to, let amount, _, let digest) = payment.request else { Issue.record("payment"); return }
        #expect(to == "cabinet-b.testnet")
        #expect(amount == "1000000000000000000000000")
        #expect(digest == onaCoreDemoDigest)
        // ona-core's gate refuses a digest that is not the one of the payment screen.
        #expect(engine.confirm(id: payment.id, decision: "accept", firm: nil, digest: "00") != nil)
        #expect(engine.confirm(id: payment.id, decision: "accept", firm: nil, digest: digest) == nil)

        run(engine, chat, until: .idle)
        guard case .exposure(let data) = chat.items.last?.content,
              let exposure = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { Issue.record("exposure"); return }
        #expect(exposure["firms_contacted"] as? [String] == ["cabinet-b"])
        #expect((exposure["payments"] as? [[String: String]])?.first?["to"] == "cabinet-b.testnet")
        #expect(exposure["mode"] as? String == "mock")
    }

    @Test func refusingStopsTheMission() throws {
        let engine = ChatEngine(makeCore: { OnaCoreMission() })
        let chat = try engine.create("Trouve un avocat").get()
        let plan = try #require(chat.pending)
        #expect(engine.confirm(id: plan.id, decision: "reject", firm: nil, digest: nil) == nil)
        #expect(chat.status == .idle)
        #expect(chat.state(of: plan) == .rejected)
        #expect(engine.confirm(id: plan.id, decision: "accept", firm: nil, digest: nil) == ProtocolError.stale.rawValue)
    }

    @Test func listAndChatJSONMatchWhatThePhoneDecodes() throws {
        let engine = ChatEngine(makeCore: { OnaCoreMission() })
        let chat = try engine.create("Bonjour").get()
        let list = engine.listJSON()
        #expect(list["mode"] as? String == "mock")
        let first = try #require((list["chats"] as? [[String: Any]])?.first)
        #expect(first["status"] as? String == "waiting")
        let view = try #require(engine.chatJSON(chat.id)?["chat"] as? [String: Any])
        let kinds = (view["items"] as? [[String: Any]])?.compactMap { $0["kind"] as? String }
        #expect(kinds == ["user", "activity", "agent", "confirmation"])
        #expect(view["working"] is NSNull)
    }
}

@MainActor
@Suite("Phone router")
struct RouterTests {
    @Test func signedRequestsOnlyAfterTheCodeIsConfirmed() throws {
        let authority = PairingAuthority(name: "Mac", store: MemoryPairingStore())
        let engine = ChatEngine(makeCore: { OnaCoreMission() })
        let router = PhoneRouter(pairing: authority, engine: engine)
        let phone = Phone()
        let code = try #require(authority.pairingCode)

        func post(_ path: String, _ body: [String: Any]) -> (Int, [String: Any]) {
            let data = try! JSONSerialization.data(withJSONObject: body)
            let response = router.handle(HTTPRequest(method: "POST", path: path, body: data))
            return (response.status, (try? JSONSerialization.jsonObject(with: response.body)) as? [String: Any] ?? [:])
        }

        let proof = phone.sign(ProtocolBytes.pairMessage(code: code, phoneKey: phone.publicKey,
                                                         computerKey: authority.computerPublicKey))
        let (status, paired) = post("/v0/pair", ["code": code, "phone_key": phone.publicKey.base64EncodedString(),
                                                 "signature": proof])
        #expect(status == 200)
        let id = try #require(paired["pairing_id"] as? String)

        let text = "Trouve un avocat"
        let signed = phone.sign(ProtocolBytes.chatMessage(pairingID: id, chatID: nil, text: text))
        #expect(post("/v0/chats", ["text": text, "pairing_id": id, "signature": signed]).1["error"] as? String
                == "pairing not verified")
        #expect(router.handle(HTTPRequest(method: "GET", path: "/v0/chats", body: Data())).status == 403)

        authority.confirmCode()
        let (created, reply) = post("/v0/chats", ["text": text, "pairing_id": id, "signature": signed])
        #expect(created == 200)
        let chatID = try #require(reply["chat_id"] as? String)
        #expect(router.handle(HTTPRequest(method: "GET", path: "/v0/chats/\(chatID)", body: Data())).status == 200)

        // Deleting needs its own signature.
        #expect(post("/v0/chats/\(chatID)/delete", ["pairing_id": id, "signature": signed]).0 == 409)
        let deletion = phone.sign(ProtocolBytes.deleteMessage(pairingID: id, chatID: chatID))
        #expect(post("/v0/chats/\(chatID)/delete", ["pairing_id": id, "signature": deletion]).0 == 200)
        #expect(engine.chats.isEmpty)
    }
}
