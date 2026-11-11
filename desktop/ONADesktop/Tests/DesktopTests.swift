import CryptoKit
import Foundation
import Security
import Testing
@testable import ONADesktopCore

/// Fixed inputs shared with the Windows/Linux tests (desktop/tauri/src-tauri/src/protocol.rs) and the iPhone app.
enum Vector {
    static let computerKey = Data([4] + (1...64).map { UInt8($0) })
    static let phoneKey = Data([4] + (65...128).map { UInt8($0) })
    static let phoneNonce = "00112233445566778899aabbccddeeff"
    static let computerNonce = "ffeeddccbbaa99887766554433221100"
    static let code = "c29tZS1jb2Rl"
    static let pairingID = "p-0123456789abcdef0123456789abcdef"
}

private func sha(_ data: Data) -> String { ProtocolBytes.hex(SHA256.hash(data: data)) }

@Suite("Protocol bytes v1 (same vectors as the Windows/Linux app)")
struct ProtocolBytesTests {
    @Test func fieldsLayout() {
        let encoded = ProtocolBytes.encode([.text("ab"), .bytes(Data([1])), .text(nil)])
        #expect(Array(encoded) == [2, 0, 0, 0, 0x61, 0x62, 1, 0, 0, 0, 1, 0, 0, 0, 0])
    }

    @Test func protocolV1Vectors() throws {
        let (computer, phone) = (Vector.computerKey, Vector.phoneKey)
        #expect(ProtocolBytes.commitment(phoneKey: phone, phoneNonce: Vector.phoneNonce)
                == "6c2ee677c6aa3c2c1721f781e55f7e223caf87d729cc5e68bd6414de0a17bb7b")
        #expect(ProtocolBytes.verificationCode(computerKey: computer, phoneKey: phone, code: Vector.code,
                                               phoneNonce: Vector.phoneNonce, computerNonce: Vector.computerNonce) == "587047")
        #expect(sha(ProtocolBytes.pairMessage(pairingID: Vector.pairingID, code: Vector.code, phoneKey: phone,
                                              computerKey: computer, phoneNonce: Vector.phoneNonce,
                                              computerNonce: Vector.computerNonce))
                == "3332d89e36dd9adeb88e8f5f18861d92fdcc048357c78bc7c7ed6284c1a069cd")
        let confirm = ProtocolBytes.confirmMessage(pairingID: Vector.pairingID, counter: 7, id: "c-1", decision: "accept",
                                                   firm: nil, digest: "ab", content: "cd")
        #expect(sha(confirm) == "1c61312dbd420b5f78b85dc82cf6f3c505386043f9704f4cd087f882a9389139")
        #expect(sha(ProtocolBytes.chatMessage(pairingID: Vector.pairingID, counter: 8, chatID: nil, text: "bonjour"))
                == "7f4041bdaaef1fae3f26bd2abf1ad93d65e5f0b086c585ac5cb2e5979e5da082")
        #expect(sha(ProtocolBytes.deleteMessage(pairingID: Vector.pairingID, counter: 9, chatID: "chat-1"))
                == "ee3c7db20a817bb5c643f005a052fbf5af413ce9780a6fa31f3acc0e91ed959c")
        #expect(sha(ProtocolBytes.replyMessage(nonce: Vector.phoneNonce, method: "POST", path: "/v1/chats/list",
                                               status: 200, reply: Data(#"{"ok":true}"#.utf8)))
                == "c9e6dc8eb32a3f5a97b226281a3151a023754cf518c0828468f3b25dd4e855b0")
        #expect(ProtocolBytes.planDigest(id: "c-1", steps: ["search", "read"])
                == "10b2ecd6ff60485e505b911709ed14b162137f0237abaa8aed21eee7c26edb84")
        #expect(ProtocolBytes.offersDigest(id: "c-2", offers: [("cabinet-b", 60000, 10, ["Forfait 600 euros, sous 10 jours"])])
                == "5127c86b14fc1406536bc274ea9c5b9e85e4a9b7e2adaf0c7b156ccf2dfb97b6")
        #expect(ProtocolBytes.paymentDigestV2(network: "testnet", contract: "pay.ona.testnet", missionID: "m-1",
                                              nonce: Vector.phoneNonce, to: "cabinet-b.testnet",
                                              amount: "1000000000000000000000000")
                == "ee00b991ccc819a4b64630c245ae7e281ef98d74f0eb971b1ff4dd9290957950")
        // Signature made by the Rust app (p256, RFC 6979) with the private key 0x07…07.
        let key = try #require(Data(base64Encoded: "BB4YUy/UdUwC8wQdnHXOszuD/9gax85P6ILMscmLxYlupGwxHE4v9A3ZajZT5uRURdMt/khuztdcepDGoYiBwKM="))
        let signature = "MEUCIQCKpmfTBH6QHkQjK+2OSErWZ8NWVddjujyvnAIvA9OSSAIgPYwZ31pcNKYUz59ysuap+EQESYYeUfOI8n8sUxE/SHU="
        #expect(ProtocolBytes.verify(signature: signature, of: confirm, by: key))
        #expect(!ProtocolBytes.verify(signature: signature, of: confirm + Data([0]), by: key))
        let privateKey = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 7, count: 32))
        #expect(privateKey.publicKey.x963Representation == key)
    }

    /// (r, n − s) is refused; the computer's own signatures are low-s.
    @Test func refusesHighSSignatures() throws {
        let key = P256.Signing.PrivateKey()
        let message = Data("ona".utf8)
        for _ in 0..<8 {
            let signature = try #require(ProtocolBytes.sign(message, with: key))
            #expect(ProtocolBytes.verify(signature: signature, of: message, by: key.publicKey.x963Representation))
            let raw = try P256.Signing.ECDSASignature(derRepresentation: Data(base64Encoded: signature)!).rawRepresentation
            let n: [UInt8] = [0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                              0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
                              0x25, 0x51]
            var s = Array(raw.suffix(32)), borrow = 0
            for i in stride(from: 31, through: 0, by: -1) {
                let value = Int(n[i]) - Int(s[i]) - borrow
                s[i] = UInt8((value + 256) % 256)
                borrow = value < 0 ? 1 : 0
            }
            let high = try P256.Signing.ECDSASignature(rawRepresentation: raw.prefix(32) + Data(s))
            #expect(key.publicKey.isValidSignature(high, for: message))
            #expect(!ProtocolBytes.verify(signature: high.derRepresentation.base64EncodedString(), of: message,
                                          by: key.publicKey.x963Representation))
        }
    }

    /// The account shown must look like a NEAR account.
    @Test func checksThePaymentScreenAndTheAccountShape() {
        let parsed = ProtocolBytes.parsePaymentScreen("Pay 1000000000000000000000000 yoctoNEAR to cabinet-b.testnet")
        #expect(parsed?.amount == "1000000000000000000000000")
        #expect(parsed?.to == "cabinet-b.testnet")
        #expect(ProtocolBytes.parsePaymentScreen("Pay me to x") == nil)
        #expect(ProtocolBytes.parsePaymentScreen("Pay 1 yoctoNEAR to Cabinet-B.testnet") == nil)
        #expect(ProtocolBytes.parsePaymentScreen("Pay 1 yoctoNEAR to cabinet\u{202e}b.testnet") == nil)
    }
}

@Suite("HTTP")
struct HTTPTests {
    @Test func parsesARequestWithABodyAndHeaders() {
        let raw = Data("POST /v1/pair HTTP/1.0\r\nHost: x.onion\r\nContent-Length: 2\r\n\r\n{}".utf8)
        guard case .request(let request) = HTTPRequest.parse(raw) else { Issue.record("request"); return }
        #expect(request.path == "/v1/pair")
        #expect(request.body == Data("{}".utf8))
        #expect(request.header("host") == .one("x.onion"))
    }

    @Test func waitsForTheWholeBody() {
        #expect(HTTPRequest.parse(Data("POST /v1/pair HTTP/1.0\r\nContent-Length: 5\r\n\r\n{}".utf8)) == .incomplete)
        #expect(HTTPRequest.parse(Data("GET /v1/chats HTTP/1.0\r\n".utf8)) == .incomplete)
    }

    @Test func refusesBadOrHugeRequests() {
        #expect(HTTPRequest.parse(Data("HELLO\r\n\r\n".utf8)) == .invalid(400))
        #expect(HTTPRequest.parse(Data("POST /x HTTP/1.0\r\nContent-Length: 999999\r\n\r\n".utf8)) == .invalid(413))
        #expect(HTTPRequest.parse(Data(repeating: 0x41, count: HTTPRequest.maxHeader + 1)) == .invalid(431))
        #expect(HTTPRequest.parse(Data("POST /x HTTP/1.0\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n{}".utf8)) == .invalid(400))
    }
}

/// Plays the iPhone: its own key, signing like the app, with its request counter.
final class Phone {
    let key = P256.Signing.PrivateKey()
    var counter: UInt64 = 0
    var publicKey: Data { key.publicKey.x963Representation }

    /// CryptoKit signatures are high-s about half the time; the phone must send the low-s form (as the app will).
    func sign(_ data: Data) -> String {
        ProtocolBytes.sign(data, with: key)!
    }

    func next() -> UInt64 {
        counter += 1
        return counter
    }

    /// Commit then reveal. Returns (pairing id, token, code shown on the phone).
    @MainActor
    func pair(with authority: PairingAuthority) -> (id: String, token: String, shown: String)? {
        guard let code = authority.pairingCode?.value else { return nil }
        let nonce = ProtocolBytes.randomHex16()
        guard case .success(let (id, computerNonce)) = authority.commit(
            code: code, commitment: ProtocolBytes.commitment(phoneKey: publicKey, phoneNonce: nonce)) else { return nil }
        let proof = sign(ProtocolBytes.pairMessage(pairingID: id, code: code, phoneKey: publicKey,
                                                   computerKey: authority.computerPublicKey, phoneNonce: nonce,
                                                   computerNonce: computerNonce))
        guard case .success(let (_, token)) = authority.reveal(pairingID: id, phoneKeyBase64: publicKey.base64EncodedString(),
                                                              phoneNonce: nonce, signature: proof) else { return nil }
        let shown = ProtocolBytes.verificationCode(computerKey: authority.computerPublicKey, phoneKey: publicKey,
                                                   code: code, phoneNonce: nonce, computerNonce: computerNonce)
        return (id, token, shown)
    }
}

@MainActor
@Suite("Pairing on the computer")
struct PairingTests {
    @Test func pairsByCommitAndRevealThenWaitsForTheCodeComparison() throws {
        let store = MemoryPairingStore()
        let authority = PairingAuthority(name: "Mac", store: store)
        let phone = Phone()
        let paired = try #require(phone.pair(with: authority))
        #expect(authority.awaiting?.code == paired.shown)
        #expect(authority.pairingCode == nil)
        // Nothing saved before the comparison.
        #expect(try store.load()?.phone == nil)
        let message = { (p: String, c: UInt64) in ProtocolBytes.chatMessage(pairingID: p, counter: c, chatID: nil, text: "bonjour") }
        let counter = phone.next()
        let signature = phone.sign(message(paired.id, counter))
        #expect(authority.check(token: paired.token, pairingID: paired.id, counter: counter, signature: signature,
                                signed: message) == .notPaired)
        #expect(authority.confirmCode())
        #expect(try store.load()?.phone != nil)
        #expect(authority.check(token: paired.token, pairingID: paired.id, counter: counter, signature: signature,
                                signed: message) == nil)
        let other = Phone().sign(message(paired.id, 9))
        #expect(authority.check(token: paired.token, pairingID: paired.id, counter: 9, signature: other, signed: message) == .badSignature)
        #expect(authority.check(token: "x", pairingID: paired.id, counter: 9, signature: other, signed: message) == .badToken)
    }

    /// A key chosen after seeing the exchange cannot be swapped in.
    @Test func refusesAKeyThatDoesNotMatchTheCommitment() throws {
        let authority = PairingAuthority(name: "Mac", store: MemoryPairingStore())
        let code = try #require(authority.pairingCode?.value)
        let phone = Phone(), attacker = Phone()
        let nonce = ProtocolBytes.randomHex16()
        let (id, computerNonce) = try authority.commit(
            code: code, commitment: ProtocolBytes.commitment(phoneKey: phone.publicKey, phoneNonce: nonce)).get()
        #expect(throws: ProtocolError.usedCode) {
            try authority.commit(code: code, commitment: ProtocolBytes.commitment(phoneKey: attacker.publicKey,
                                                                                 phoneNonce: nonce)).get()
        }
        let proof = attacker.sign(ProtocolBytes.pairMessage(pairingID: id, code: code, phoneKey: attacker.publicKey,
                                                            computerKey: authority.computerPublicKey, phoneNonce: nonce,
                                                            computerNonce: computerNonce))
        #expect(throws: ProtocolError.commitmentMismatch) {
            try authority.reveal(pairingID: id, phoneKeyBase64: attacker.publicKey.base64EncodedString(),
                                 phoneNonce: nonce, signature: proof).get()
        }
        #expect(authority.awaiting == nil)
        #expect(authority.pairingCode?.value != code)
    }

    /// Limited attempts, expiry.
    @Test func theCodeExpiresAndWrongCodesAreLimited() throws {
        let authority = PairingAuthority(name: "Mac", store: MemoryPairingStore())
        let commitment = ProtocolBytes.commitment(phoneKey: Phone().publicKey, phoneNonce: ProtocolBytes.randomHex16())
        let code = try #require(authority.pairingCode?.value)
        for _ in 0..<PairingAuthority.maxFailedCodes {
            #expect(throws: ProtocolError.usedCode) { try authority.commit(code: "guess", commitment: commitment).get() }
        }
        #expect(throws: ProtocolError.usedCode) { try authority.commit(code: code, commitment: commitment).get() }

        let fresh = try #require(authority.pairingCode?.value)
        authority.pairingCode?.issuedAt -= PairingAuthority.codeLifetime
        #expect(authority.payload(address: nil, onion: "x.onion") == nil)
        #expect(throws: ProtocolError.expiredCode) { try authority.commit(code: fresh, commitment: commitment).get() }
        #expect(authority.pairingCode?.value != fresh)
    }

    /// A counter or a confirmation id accepted once is refused afterwards, also after a restart.
    @Test func refusesReplaysEvenAfterARestart() throws {
        let store = MemoryPairingStore()
        let authority = PairingAuthority(name: "Mac", store: store)
        let phone = Phone()
        let paired = try #require(phone.pair(with: authority))
        authority.confirmCode()
        let message = { (p: String, c: UInt64) in
            ProtocolBytes.confirmMessage(pairingID: p, counter: c, id: "c-1", decision: "accept", firm: nil, digest: nil, content: "x")
        }
        func check(_ a: PairingAuthority, _ counter: UInt64) -> ProtocolError? {
            a.check(token: paired.token, pairingID: paired.id, counter: counter,
                    signature: phone.sign(message(paired.id, counter)), confirmation: "c-1", signed: message)
        }
        #expect(check(authority, 5) == nil)
        authority.recordConfirmation("c-1")  // carried out
        #expect(check(authority, 5) == .replayed)
        let restarted = PairingAuthority(name: "Mac", store: store)
        #expect(check(restarted, 5) == .replayed)
        #expect(check(restarted, 4) == .replayed)
        #expect(check(restarted, 6) == .replayed)  // same confirmation id
    }

    /// A code comparison left pending expires: neither a late click nor the timer trusts the phone.
    @Test func aPendingCodeComparisonExpires() throws {
        let authority = PairingAuthority(name: "Mac", store: MemoryPairingStore())
        _ = try #require(Phone().pair(with: authority))
        authority.awaiting?.at -= PairingAuthority.awaitLifetime
        #expect(!authority.confirmCode())
        #expect(!authority.isPaired && authority.pairingCode != nil)

        _ = try #require(Phone().pair(with: authority))
        authority.awaiting?.at -= PairingAuthority.awaitLifetime
        authority.tick()
        #expect(authority.awaiting == nil && authority.pairingCode != nil)
        #expect(authority.confirmCode())
        #expect(!authority.isPaired)
    }

    /// A record that exists but cannot be read is shown as an error and never overwritten.
    @Test func leavesAnUnreadableRecordUntouched() throws {
        let original = PairingRecord(computerKey: P256.Signing.PrivateKey().rawRepresentation, phone: nil)
        let store = MemoryPairingStore(original)
        store.unreadable = true
        let authority = PairingAuthority(name: "Mac", store: store)
        #expect(authority.storageError != nil)
        #expect(authority.pairingCode == nil)
        #expect(!authority.forgetPhone())
        #expect(authority.pairingCode == nil)
        store.unreadable = false
        #expect(try store.load() == original)
    }

    /// A failed save is reported.
    @Test func reportsARecordThatCannotBeSaved() {
        let store = MemoryPairingStore()
        let authority = PairingAuthority(name: "Mac", store: store)
        store.failing = true
        #expect(!authority.forgetPhone())
        #expect(authority.storageError != nil)
    }

    @Test func dropsAPhoneSavedByAnEarlierVersion() throws {
        let old = #"{"computerKey":"\#(P256.Signing.PrivateKey().rawRepresentation.base64EncodedString())","phone":{"pairingID":"p-1-x","phoneKey":"\#(Phone().publicKey.base64EncodedString())","pairedAt":0,"verified":false}}"#
        let record = try JSONDecoder().decode(PairingRecord.self, from: Data(old.utf8))
        let authority = PairingAuthority(name: "Mac", store: MemoryPairingStore(record))
        #expect(!authority.isPaired)
        #expect(authority.pairingCode != nil)
    }

    /// The keychain item is readable only while unlocked, on this Mac.
    @Test func keychainItemIsThisDeviceOnly() {
        let attributes = KeychainPairingStore.attributes(Data())
        #expect(attributes[kSecAttrAccessible as String] as? String == kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
    }

    @Test func keepsTheComputerKeyAcrossLaunches() {
        let store = MemoryPairingStore()
        let first = PairingAuthority(name: "Mac", store: store).computerPublicKey
        #expect(PairingAuthority(name: "Mac", store: store).computerPublicKey == first)
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
        #expect(engine.pendingContent(plan.id) == ProtocolBytes.planDigest(id: plan.id, steps: steps))

        #expect(engine.confirm(id: plan.id, decision: "accept", firm: nil, digest: nil) == nil)
        run(engine, chat, until: .waiting)
        let offers = try #require(chat.pending)
        guard case .recipient(let ranked) = offers.request else { Issue.record("recipient"); return }
        #expect(Set(ranked.map(\.firmID)) == ["cabinet-a", "cabinet-b"])
        #expect(engine.confirm(id: offers.id, decision: "accept", firm: "cabinet-b", digest: nil) == nil)

        run(engine, chat, until: .waiting)
        let payment = try #require(chat.pending)
        guard case .payment(let to, let amount, let screen, let digest, let binding) = payment.request else {
            Issue.record("payment"); return
        }
        #expect(to == "cabinet-b.testnet")
        // The amount comes from ona-core (offer price × policy rate), the digest is v2 (new nonce each payment).
        #expect(screen == "Pay \(amount) yoctoNEAR to \(to)")
        #expect(digest == ProtocolBytes.paymentDigestV2(network: binding.network, contract: binding.contract,
                                                        missionID: binding.missionID, nonce: binding.nonce,
                                                        to: to, amount: amount))
        #expect(payment.content == digest)
        #expect(engine.confirm(id: payment.id, decision: "accept", firm: nil, digest: "00") != nil)
        #expect(engine.confirm(id: payment.id, decision: "accept", firm: nil, digest: digest) == nil)

        run(engine, chat, until: .idle)
        guard case .exposure(let data) = chat.items.last?.content,
              let exposure = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { Issue.record("exposure"); return }
        #expect(exposure["firms_contacted"] as? [String] == ["cabinet-b"])
        #expect(exposure["mode"] as? String == "mock")
    }

    /// Ids never repeat (they used to restart at chat-1-c-1).
    @Test func idsAreRandomAndNeverReused() throws {
        let engine = ChatEngine(makeCore: { OnaCoreMission() })
        let chat = try engine.create("Trouve un avocat").get()
        let other = try engine.create("Trouve un avocat").get()
        #expect(chat.id != other.id)
        #expect(chat.id.hasPrefix("chat-") && ProtocolBytes.isHex(String(chat.id.dropFirst(5)), length: 32))
        let first = try #require(chat.pending)
        #expect(first.id.hasPrefix("c-") && ProtocolBytes.isHex(String(first.id.dropFirst(2)), length: 32))
        #expect(engine.confirm(id: first.id, decision: "reject", firm: nil, digest: nil) == nil)
        #expect(engine.post("Recommence", to: chat.id) == nil)
        let second = try #require(chat.pending)
        #expect(second.id != first.id)
        #expect(engine.confirm(id: first.id, decision: "accept", firm: nil, digest: nil) == ProtocolError.stale.rawValue)
    }

    /// After a failure (here the bridge's answer to a panic), the chat's next mission gets a new core.
    @Test func aFailedCoreIsNotReused() throws {
        final class Failing: MissionCore {
            func dispatch(_ request: [String: Any]) -> [String: Any] {
                request["cmd"] as? String == "propose_plan"
                    ? ["ok": false, "error": "panic inside ona-core", "mode": "mock"] : ["ok": true, "mode": "mock"]
            }
        }
        var made = 0
        let engine = ChatEngine(makeCore: { made += 1; return Failing() })
        let chat = try engine.create("Trouve un avocat").get()
        #expect(chat.status == .idle)
        #expect(engine.post("Recommence", to: chat.id) == nil)
        #expect(made == 2)
    }

    /// Payment v2: the digest binds network, contract, mission, nonce, account and amount.
    @Test func readsAV2PaymentAndRefusesUnboundOnes() {
        let nonce = Vector.phoneNonce
        let screen = "Pay 1000000000000000000000000 yoctoNEAR to cabinet-b.testnet"
        let digest = ProtocolBytes.paymentDigestV2(network: "testnet", contract: "pay.ona.testnet", missionID: "m-1",
                                                   nonce: nonce, to: "cabinet-b.testnet", amount: "1000000000000000000000000")
        let fields: [String: Any] = ["network": "testnet", "contract": "pay.ona.testnet", "mission_id": "m-1",
                                     "nonce": nonce, "to": "cabinet-b.testnet", "amount": "1000000000000000000000000"]
        var reply: [String: Any] = ["ok": true, "screen": screen, "digest": digest, "mode": "mock", "payment": fields]
        guard case .success(let request) = Pending.preparedPayment(reply) else { Issue.record("v2"); return }
        let json = Pending(id: "c-1", request: request).json
        #expect((json["payment"] as? [String: Any])?["digest_version"] as? Int == 2)
        #expect((json["payment"] as? [String: Any])?["screen"] as? String == screen)
        #expect(json["content"] as? String == digest)
        for (key, value) in [("mission_id", "m-2"), ("to", "attacker.testnet"), ("amount", "2")] {
            var changed = fields
            changed[key] = value
            reply["payment"] = changed
            guard case .failure = Pending.preparedPayment(reply) else { Issue.record("\(key) changed"); return }
        }
        // The old digest (account and amount only), even for a mock payment: refused.
        let unbound: [String: Any] = ["ok": true, "screen": screen, "digest": digest, "mode": "mock"]
        guard case .failure = Pending.preparedPayment(unbound) else { Issue.record("unbound"); return }
    }

    @Test func listAndChatJSONMatchWhatThePhoneDecodes() throws {
        let engine = ChatEngine(makeCore: { OnaCoreMission() })
        let chat = try engine.create("Bonjour").get()
        let list = engine.listJSON()
        #expect(list["mode"] as? String == "mock")
        let view = try #require(engine.chatJSON(chat.id)?["chat"] as? [String: Any])
        let items = view["items"] as? [[String: Any]] ?? []
        #expect(items.compactMap { $0["kind"] as? String } == ["user", "activity", "agent", "confirmation"])
        #expect((items.last?["pending"] as? [String: Any])?["content"] is String)
    }
}

@MainActor
@Suite("Phone router")
struct RouterTests {
    static let host = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion"

    @MainActor
    final class Setup {
        let authority = PairingAuthority(name: "Mac", store: MemoryPairingStore())
        let engine = ChatEngine(makeCore: { OnaCoreMission() })
        let router: PhoneRouter
        let phone = Phone()
        var id = "", token = ""

        init(pair: Bool = true) {
            router = PhoneRouter(pairing: authority, engine: engine)
            router.allowedHosts = { [RouterTests.host, "127.0.0.1:8790"] }
            if pair, let paired = phone.pair(with: authority) {
                (id, token) = (paired.id, paired.token)
                authority.confirmCode()
            }
        }

        func post(_ path: String, _ body: [String: Any], headers: [HTTPRequest.Header] = [.init("host", RouterTests.host)])
            -> (status: Int, json: [String: Any], response: HTTPResponse) {
            let data = try! JSONSerialization.data(withJSONObject: body)
            let response = router.handle(HTTPRequest(method: "POST", path: path, headers: headers, body: data))
            return (response.status, (try? JSONSerialization.jsonObject(with: response.reply)) as? [String: Any] ?? [:], response)
        }

        func create(_ text: String) -> ([String: Any], String?) {
            let counter = phone.next()
            let body: [String: Any] = ["token": token, "pairing_id": id, "counter": counter, "text": text,
                                       "signature": phone.sign(ProtocolBytes.chatMessage(pairingID: id, counter: counter,
                                                                                         chatID: nil, text: text))]
            return (body, post("/v1/chats", body).json["chat_id"] as? String)
        }

        func confirmBody(_ pending: Pending, content: String) -> [String: Any] {
            let counter = phone.next()
            let signature = phone.sign(ProtocolBytes.confirmMessage(pairingID: id, counter: counter, id: pending.id,
                                                                    decision: "accept", firm: nil, digest: nil, content: content))
            return ["token": token, "pairing_id": id, "counter": counter, "id": pending.id, "decision": "accept",
                    "signature": signature]
        }
    }

    /// Every reply is signed with the computer's key, bound to the request nonce.
    @Test func signsEveryReply() throws {
        let setup = Setup(pair: false)
        let nonce = ProtocolBytes.randomHex16()
        let code = try #require(setup.authority.pairingCode?.value)
        let reply = setup.post("/v1/pair", ["code": code, "nonce": nonce,
                                            "commitment": ProtocolBytes.commitment(phoneKey: setup.phone.publicKey,
                                                                                   phoneNonce: nonce)])
        #expect(reply.status == 200)
        let key = setup.authority.computerPublicKey, text = reply.response.reply
        let signed = ProtocolBytes.replyMessage(nonce: nonce, method: "POST", path: "/v1/pair", status: 200, reply: text)
        #expect(ProtocolBytes.verify(signature: reply.response.signature, of: signed, by: key))
        // Not valid for another nonce, nor as the reply to another request with the same nonce.
        for other in [ProtocolBytes.replyMessage(nonce: "other", method: "POST", path: "/v1/pair", status: 200, reply: text),
                      ProtocolBytes.replyMessage(nonce: nonce, method: "POST", path: "/v1/chats/list", status: 200, reply: text),
                      ProtocolBytes.replyMessage(nonce: nonce, method: "GET", path: "/v1/pair", status: 200, reply: text)] {
            #expect(!ProtocolBytes.verify(signature: reply.response.signature, of: other, by: key))
        }
        let envelope = try #require(try JSONSerialization.jsonObject(with: reply.response.body) as? [String: Any])
        #expect((envelope["reply"] as? String).map { Data($0.utf8) } == reply.response.reply)
    }

    /// Reads need the token; browsers and foreign Host values are refused.
    @Test func readsNeedTheTokenAndBrowsersAreRefused() throws {
        let setup = Setup()
        let (_, chat) = setup.create("Trouve un avocat")
        let chatID = try #require(chat)
        #expect(setup.post("/v1/chats/list", [:]).status == 403)
        #expect(setup.post("/v1/chats/\(chatID)/view", ["token": "x"]).status == 403)
        #expect(setup.post("/v1/chats/list", ["token": setup.token]).status == 200)
        #expect(setup.post("/v1/chats/list", ["token": setup.token], headers: [.init("host", "evil.example:8790")]).json["error"]
                as? String == "unexpected host")
        #expect(setup.post("/v1/chats/list", ["token": setup.token], headers: []).status == 403)
        #expect(setup.post("/v1/chats/list", ["token": setup.token],
                           headers: [.init("host", RouterTests.host), .init("origin", "http://evil.example")]).json["error"]
                as? String == "browser requests are refused")
        #expect(setup.post("/v0/chats", ["token": setup.token]).status == 404)
    }

    /// A recorded request replayed as is is refused.
    @Test func refusesReplays() throws {
        let setup = Setup()
        let (body, chat) = setup.create("Trouve un avocat")
        #expect(chat != nil)
        #expect(setup.post("/v1/chats", body).json["error"] as? String == "replayed request")
        let pending = try #require(setup.engine.chats.first?.pending)
        let accept = setup.confirmBody(pending, content: pending.content)
        #expect(setup.post("/v1/confirm", accept).status == 200)
        #expect(setup.post("/v1/confirm", accept).json["error"] as? String == "stale confirmation")
    }

    /// A confirmation signed over other content does not verify.
    @Test func aConfirmationSignedOverOtherContentIsRefused() throws {
        let setup = Setup()
        _ = setup.create("Trouve un avocat")
        let pending = try #require(setup.engine.chats.first?.pending)
        let shown = ProtocolBytes.planDigest(id: pending.id, steps: ["search"])
        #expect(setup.post("/v1/confirm", setup.confirmBody(pending, content: shown)).json["error"] as? String
                == "signature does not verify")
        #expect(setup.post("/v1/confirm", setup.confirmBody(pending, content: pending.content)).status == 200)
    }

    /// Counters are JSON integers from 0 to 2^53 − 1, as in the Rust app.
    @Test func countersAreIntegersWithinTheSharedBound() throws {
        let values = try #require(try JSONSerialization.jsonObject(
            with: Data(#"[1.0, true, -1, 9007199254740992, 9007199254740991, 7, "7"]"#.utf8)) as? [Any])
        let read = values.map { ($0 as? NSNumber).flatMap(PhoneRouter.counter) }
        #expect(read == [nil, nil, nil, nil, PhoneRouter.maxCounter, 7, nil])
    }

    /// A header sent with an empty value counts as sent.
    @Test func anEmptyOriginHeaderIsStillABrowser() throws {
        let setup = Setup()
        guard case .request(let parsed) = HTTPRequest.parse(Data("POST /v1/chats/list HTTP/1.0\r\nOrigin:\r\n\r\n".utf8)) else {
            Issue.record("parse"); return
        }
        #expect(parsed.header("origin") == .one(""))
        #expect(setup.post("/v1/chats/list", ["token": setup.token],
                           headers: parsed.headers + [.init("host", RouterTests.host)]).json["error"] as? String
                == "browser requests are refused")
    }

    /// An answer the agent refuses does not block the next answer to the same confirmation.
    @Test func aRefusedAnswerDoesNotBlockTheConfirmation() throws {
        let setup = Setup()
        _ = setup.create("Trouve un avocat")
        let pending = try #require(setup.engine.chats.first?.pending)
        let counter = setup.phone.next()
        let signature = setup.phone.sign(ProtocolBytes.confirmMessage(pairingID: setup.id, counter: counter, id: pending.id,
                                                                      decision: "maybe", firm: nil, digest: nil,
                                                                      content: pending.content))
        #expect(setup.post("/v1/confirm", ["token": setup.token, "pairing_id": setup.id, "counter": counter,
                                           "id": pending.id, "decision": "maybe", "signature": signature]).json["error"]
                as? String == "bad request")
        #expect(setup.post("/v1/confirm", setup.confirmBody(pending, content: pending.content)).status == 200)
    }

    @Test func deletingNeedsItsOwnSignature() throws {
        let setup = Setup()
        let (body, chat) = setup.create("Trouve un avocat")
        let chatID = try #require(chat)
        var wrong = body
        wrong["counter"] = setup.phone.next()
        #expect(setup.post("/v1/chats/\(chatID)/delete", wrong).status == 409)
        let counter = setup.phone.next()
        let deletion = setup.phone.sign(ProtocolBytes.deleteMessage(pairingID: setup.id, counter: counter, chatID: chatID))
        #expect(setup.post("/v1/chats/\(chatID)/delete", ["token": setup.token, "pairing_id": setup.id,
                                                          "counter": counter, "signature": deletion]).status == 200)
        #expect(setup.engine.chats.isEmpty)
    }
}

@Suite("Desktop settings")
struct SettingsTests {
    /// A release build ignores a saved local-network choice.
    @Test func localNetworkModeIsForDebugBuildsOnly() {
        #expect(LocalModePolicy.resolve(stored: "localNetwork", allowLocal: false) == "tor")
        #expect(LocalModePolicy.resolve(stored: "localNetwork", allowLocal: true) == "localNetwork")
        #expect(LocalModePolicy.resolve(stored: nil, allowLocal: true) == "tor")
    }

    /// Tor exits with the app.
    @MainActor
    @Test func torExitsWithTheApp() {
        let torrc = TorService.torrc(data: "/a b/data", hs: "/a\"b/hs", port: 49152, owner: 4242)
        #expect(torrc.contains("__OwningControllerProcess 4242"))
        #expect(torrc.contains("HiddenServicePort 80 127.0.0.1:49152"))
        #expect(torrc.contains(#"HiddenServiceDir "/a\"b/hs""#))
    }
}
