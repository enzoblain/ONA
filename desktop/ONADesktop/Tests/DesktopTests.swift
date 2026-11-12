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

    /// The pool portfolio is a read: token only. Without a pool wallet, ona-core says so in a signed refusal.
    @Test func poolPortfolioNeedsTheToken() {
        let setup = Setup()
        #expect(setup.post("/v1/pool/portfolio", ["token": "x"]).status == 403)
        let reply = setup.post("/v1/pool/portfolio", ["token": setup.token])
        #expect(reply.status == 409)
        #expect(reply.json["error"] as? String == "no pool wallet configured")
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
        let torrc = TorService.torrc(data: "/a b/data", hs: "/a\"b/hs", port: 49152, owner: 4242, socksPort: 50123,
                                     coreSocksPort: 50124)
        #expect(torrc.contains("__OwningControllerProcess 4242"))
        #expect(torrc.contains("SocksPort 127.0.0.1:50123 OnionTrafficOnly ExtendedErrors\n"))
        #expect(torrc.contains("SocksPort 127.0.0.1:50124\n"))
        #expect(torrc.contains("HiddenServicePort 80 127.0.0.1:49152"))
        #expect(torrc.contains(#"HiddenServiceDir "/a\"b/hs""#))
    }
}

/// A minimal SOCKS5 proxy on 127.0.0.1 that answers `reply` to one CONNECT and reports the host it was asked for.
private func fakeSocks(reply: UInt8) -> (port: UInt16, asked: Task<String, Never>) {
    let fd = socket(AF_INET, SOCK_STREAM, 0)
    var address = SocksProbe.loopback(port: 0)
    _ = SocksProbe.withSockaddr(&address) { bind(fd, $0, $1) }
    listen(fd, 1)
    var length = socklen_t(MemoryLayout<sockaddr_in>.size)
    _ = withUnsafeMutablePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
    }
    let port = UInt16(bigEndian: address.sin_port)
    let asked = Task.detached { () -> String in
        let client = accept(fd, nil, nil)
        defer { close(client); close(fd) }
        guard (try? SocksProbe.receive(client, 3)) == [5, 1, 0] else { return "bad greeting" }
        try? SocksProbe.send(client, [5, 0])
        guard let head = try? SocksProbe.receive(client, 5), head[3] == 3,
              let rest = try? SocksProbe.receive(client, Int(head[4]) + 2) else { return "bad request" }
        try? SocksProbe.send(client, [5, reply, 0, 1, 0, 0, 0, 0, 0, 0])
        return String(decoding: rest.dropLast(2), as: UTF8.self)
    }
    return (port, asked)
}

@Suite("Onion published")
struct OnionPublishedTests {
    /// The QR code waits until the onion address answers through Tor, not just until the hostname file exists.
    @Test func reachesTheOnionThroughSocks() async throws {
        let onion = String(repeating: "a", count: 56) + ".onion"
        let ok = fakeSocks(reply: 0)
        try SocksProbe.reach(socksPort: ok.port, host: onion, timeout: 5)
        #expect(await ok.asked.value == onion)
        // Tor answers 4 (host unreachable) while the descriptor is not published.
        let notYet = fakeSocks(reply: 4)
        #expect(throws: SocksProbe.Failure.reply(4)) { try SocksProbe.reach(socksPort: notYet.port, host: onion, timeout: 5) }
        _ = await notYet.asked.value
        // Nothing listening: not published either.
        let free = try #require(SocksProbe.freeLocalPort())
        #expect(throws: SocksProbe.Failure.socket("connect")) { try SocksProbe.reach(socksPort: free, host: onion, timeout: 2) }
    }
}


@Suite struct RealModelTests {
    private func folder() throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appending(path: "ona-real-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    @Test func noSettingsFileKeepsTheFakeModel() throws {
        let setup = RealModel.setup(file: try folder().appending(path: "model.json"), coreSocks: nil)
        let core = OnaCoreMission(setup: setup)
        #expect(core.dispatch(["cmd": "exposure"])["mode"] as? String == "mock")
    }

    @Test func anUnreadableSettingsFileIsRefusedNotIgnored() throws {
        let file = try folder().appending(path: "model.json")
        try Data("not json".utf8).write(to: file)
        let reply = OnaCoreMission(setup: RealModel.setup(file: file, coreSocks: 9050)).dispatch(["cmd": "exposure"])
        #expect(reply["ok"] as? Bool == false)
        #expect(reply["mode"] as? String == "real")
        #expect((reply["error"] as? String)?.hasPrefix("model.json") == true)
    }

    @Test func theRealModelWaitsForTor() throws {
        let file = try folder().appending(path: "model.json")
        try Data(#"{"relay_url":"https://relay.example.org","model":"m","max_tokens":200,"token_budget":2000,"tokens_file":"/nonexistent"}"#.utf8)
            .write(to: file)
        let reply = OnaCoreMission(setup: RealModel.setup(file: file, coreSocks: nil)).dispatch(["cmd": "open", "mission": "x"])
        #expect(reply["mode"] as? String == "real")
        #expect((reply["error"] as? String)?.contains("Tor") == true)
    }
}

@MainActor
@Suite struct SlowCoreTests {
    /// The real model through Tor takes seconds: the window and the phone are still served meanwhile.
    final class Slow: MissionCore {
        let core = OnaCoreMission()
        func dispatch(_ request: [String: Any]) -> [String: Any] {
            if request["cmd"] as? String == "propose_plan" { Thread.sleep(forTimeInterval: 1.5) }
            return core.dispatch(request)
        }
    }

    @Test func aSlowCoreDoesNotBlockTheEngine() throws {
        let engine = ChatEngine(makeCore: { Slow() })
        let started = Date.now
        _ = try engine.create("Trouve-moi un avocat en droit du travail à Paris").get()
        engine.tick()
        #expect(Date.now.timeIntervalSince(started) < 1.0)
        #expect(engine.chats.first?.status == .working)
        #expect(engine.chats.first?.working?.tool == "think")
        let deadline = started.addingTimeInterval(10)
        while engine.chats.first?.status == .working, Date.now < deadline { engine.tick() }
        #expect(engine.chats.first?.status == .waiting)
    }
}

@Suite struct BackupExclusionTests {
    @Test func theAppFolderIsKeptOutOfBackups() throws {
        let folder = FileManager.default.temporaryDirectory.appending(path: "ona-backup-\(UUID().uuidString)")
        try BackupExclusion.exclude(folder)
        let values = try folder.resourceValues(forKeys: [.isExcludedFromBackupKey])
        #expect(values.isExcludedFromBackup == true)
        try? FileManager.default.removeItem(at: folder)
    }
}

@Suite struct PoolSettingsTests {
    private func folder() throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appending(path: "ona-pool-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private func setup(_ text: String) throws -> [String: Any] {
        try #require(try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any])
    }

    @Test func withoutPoolJSONThePoolIsNotConfigured() throws {
        let text = RealModel.poolSetup(file: try folder().appending(path: "pool.json"), coreSocks: 9050)
        let json = try setup(text)
        #expect(json["pool"] is NSNull && json["model"] is NSNull && json["core_socks"] as? Int == 9050)
        let reply = OnaCoreMission(setup: text).dispatch(["cmd": "pool_portfolio"])
        #expect(reply["error"] as? String == "no pool wallet configured")
    }

    @Test func anUnreadablePoolJSONIsRefusedNotIgnored() throws {
        let file = try folder().appending(path: "pool.json")
        try Data("[1]".utf8).write(to: file)
        let text = RealModel.poolSetup(file: file, coreSocks: 9050)
        #expect((try setup(text)["error"] as? String)?.hasPrefix("pool.json") == true)
        let reply = OnaCoreMission(setup: text).dispatch(["cmd": "pool_portfolio"])
        #expect(reply["ok"] as? Bool == false)
        #expect(reply["mode"] as? String == "real")
        #expect((reply["error"] as? String)?.hasPrefix("pool.json") == true)
    }

    @Test func thePoolWaitsForTorThenUsesItsSettings() throws {
        let file = try folder().appending(path: "pool.json")
        try Data(#"{"wallet_file":"/nonexistent/wallet","wallet_key_file":"/nonexistent/key","pool":"pool.testnet","rpc_url":"https://rpc.testnet.near.org"}"#.utf8)
            .write(to: file)
        let text = RealModel.poolSetup(file: file, coreSocks: nil)
        #expect((try setup(text)["pool"] as? [String: Any])?["pool"] as? String == "pool.testnet")
        let waiting = OnaCoreMission(setup: text).dispatch(["cmd": "pool_portfolio"])
        #expect((waiting["error"] as? String)?.contains("Tor") == true)
        // With tor, ona-core reads the key file: missing here, so refused with ona-core's reason.
        let refused = OnaCoreMission(setup: RealModel.poolSetup(file: file, coreSocks: 9)).dispatch(["cmd": "pool_portfolio"])
        #expect(refused["mode"] as? String == "real")
        #expect((refused["error"] as? String)?.contains("wallet key") == true)
    }

    @Test func modelJSONIsNotReadForThePool() throws {
        // The pool core never gets the real model: model stays null whatever model.json says.
        let json = try setup(RealModel.poolSetup(file: try folder().appending(path: "pool.json"), coreSocks: nil))
        #expect(json["model"] is NSNull)
    }
}

@MainActor
@Suite struct PoolEngineTests {
    /// How many fake cores of one test are alive.
    final class Alive: @unchecked Sendable {
        private let lock = NSLock()
        private var count = 0
        var value: Int { lock.withLock { count } }
        func add(_ n: Int) { lock.withLock { count += n } }
    }

    /// Answers every pool command with its name.
    final class FakePool: MissionCore, @unchecked Sendable {
        let alive: Alive?
        let delay: TimeInterval
        /// When set, every command waits for it (at most 5 s, then refuses).
        let gate: DispatchSemaphore?
        private(set) var received: [String] = []
        init(delay: TimeInterval = 0, gate: DispatchSemaphore? = nil, alive: Alive? = nil) {
            self.delay = delay
            self.gate = gate
            self.alive = alive
            alive?.add(1)
        }
        deinit { alive?.add(-1) }
        func dispatch(_ request: [String: Any]) -> [String: Any] {
            if delay > 0 { Thread.sleep(forTimeInterval: delay) }
            if let gate, gate.wait(timeout: .now() + 5) == .timedOut { return ["ok": false, "error": "blocked"] }
            let cmd = request["cmd"] as? String ?? "?"
            received.append(cmd)
            if cmd == "pool_portfolio" {
                return ["ok": true, "mode": "mock", "total": "0", "vault_count": 0, "vaults": [],
                        "cash": ["value": "0", "spending_value": "0", "awaiting_signature": 0, "tiers": []]]
            }
            return ["ok": true, "mode": "mock", "cmd": cmd]
        }
    }

    @Test func onlyPoolCommandsAndOneCoreForTheApp() async {
        var made: [FakePool] = []
        var chatCores = 0
        let engine = ChatEngine(makeCore: { chatCores += 1; return OnaCoreMission() },
                                makePoolCore: { let core = FakePool(); made.append(core); return core })
        for cmd in ["open", "pay", "pool_request_exit", "confirm_payment"] {
            #expect(await engine.pool(["cmd": cmd])["error"] as? String == "commande du pool inconnue")
        }
        #expect(await engine.pool(["foo": 1])["ok"] as? Bool == false)
        #expect(made.isEmpty)
        for cmd in ["pool_portfolio", "pool_prepare", "pool_execute", "pool_recover"] {
            #expect(await engine.pool(["cmd": cmd])["ok"] as? Bool == true)
        }
        #expect(engine.poolPortfolio().map { $0["mode"] as? String } == .success("mock"))
        #expect(made.count == 1)
        #expect(made[0].received == ["pool_portfolio", "pool_prepare", "pool_execute", "pool_recover", "pool_portfolio"])
        #expect(chatCores == 0)
    }

    @Test func resetMakesANewCoreOnlyOnceTheOldOneIsReleased() async {
        let alive = Alive()
        var made = 0
        var aliveWhenMade: [Int] = []
        let engine = ChatEngine(makeCore: { OnaCoreMission() }, makePoolCore: {
            made += 1
            aliveWhenMade.append(alive.value)
            return FakePool(delay: 0.3, alive: alive)
        })
        engine.resetPool() // nothing made yet: nothing to do
        _ = await engine.pool(["cmd": "pool_recover"])
        // A slow command in flight, then tor's port changes: the old core (and its wallet lock) goes first.
        let slow = Task { await engine.pool(["cmd": "pool_recover"])["ok"] as? Bool == true }
        try? await Task.sleep(for: .milliseconds(50))
        engine.resetPool()
        _ = await engine.pool(["cmd": "pool_portfolio"])
        #expect(made == 2)
        #expect(aliveWhenMade == [0, 0])
        #expect(alive.value == 1)
        #expect(await slow.value)
    }

    @Test func aSlowPoolDoesNotHoldTheMainActor() async throws {
        // ona-core answers only once this test, on the main actor, lets it: if the engine held the main actor while
        // waiting for the reply, the test could not run and the fake would refuse after 5 s.
        let gate = DispatchSemaphore(value: 0)
        let engine = ChatEngine(makeCore: { OnaCoreMission() }, makePoolCore: { FakePool(gate: gate) })
        let pending = Task { await engine.pool(["cmd": "pool_portfolio"])["ok"] as? Bool == true }
        try await Task.sleep(for: .milliseconds(100))
        gate.signal()
        #expect(await pending.value)
    }

    @Test func withoutAPoolWalletTheRealCoreSaysSo() async {
        let engine = ChatEngine(makeCore: { OnaCoreMission() })
        #expect(await engine.pool(["cmd": "pool_portfolio"])["error"] as? String == "no pool wallet configured")
    }
}

@Suite struct PoolWindowTests {
    @Test func nearAmountsAreExact() {
        #expect(NEARAmount.yocto(fromNEAR: "1.5") == "1500000000000000000000000")
        #expect(NEARAmount.yocto(fromNEAR: " 1,5 ") == "1500000000000000000000000")
        #expect(NEARAmount.yocto(fromNEAR: "0.000000000000000000000001") == "1")
        #expect(NEARAmount.yocto(fromNEAR: "2000") == "2000000000000000000000000000")
        #expect(NEARAmount.yocto(fromNEAR: "0.1234567890123456789012345") == nil) // 25 decimals
        #expect(NEARAmount.yocto(fromNEAR: "340282366920938463463374607431768211455") == nil) // overflows
        for bad in ["", "abc", "1.2.3", "-1", ".5", "1e3", "1 000"] { #expect(NEARAmount.yocto(fromNEAR: bad) == nil) }
        #expect(NEARAmount.text("9990000000000000000000000") == "9.99")
        #expect(NEARAmount.text("1") == "0.000000000000000000000001")
        #expect(NEARAmount.text("12") != nil && NEARAmount.text("1.5") == nil)
        let typed = "123456.000000000000000000000789"
        #expect(NEARAmount.text(NEARAmount.yocto(fromNEAR: typed)!) == "123456.000000000000000000000789")
    }

    @Test func buildsThePrepareRequests() throws {
        let enter = try PoolRequest.prepare(.enter, amount: "tout", vault: 2).get()
        #expect(enter["cmd"] as? String == "pool_prepare" && enter["op"] as? String == "enter")
        #expect(enter["amount"] as? String == "all" && enter["vault"] as? Int == 2)
        let move = try PoolRequest.prepare(.switch, amount: "1", vault: 0, to: 1).get()
        #expect(move["from"] as? Int == 0 && move["to"] as? Int == 1 && move["amount"] as? String == "1000000000000000000000000")
        let pay = try PoolRequest.prepare(.exitCash, amount: "1.9", account: " alice.testnet ").get()
        #expect(pay["to"] as? String == "alice.testnet" && pay["op"] as? String == "exit_cash")
        let deposit = try PoolRequest.prepare(.deposit, amount: "100", account: "alice.testnet").get()
        #expect(deposit["account"] as? String == "alice.testnet")
        // "tout" only for what is already held; never a zero or unreadable amount.
        #expect(throws: ProtocolErrorText.self) { try PoolRequest.prepare(.deposit, amount: "tout", account: "a.testnet").get() }
        #expect(throws: ProtocolErrorText.self) { try PoolRequest.prepare(.exitCash, amount: "all", account: "a.testnet").get() }
        #expect(throws: ProtocolErrorText.self) { try PoolRequest.prepare(.exit, amount: "0", vault: 0).get() }
        #expect(throws: ProtocolErrorText.self) { try PoolRequest.prepare(.exitCash, amount: "1", account: " ").get() }
    }

    @Test func readsThePortfolioAndTheSummary() throws {
        // The example values of docs/desktop/pool-commands.md.
        let portfolio = try #require(PoolPortfolio([
            "ok": true, "mode": "mock", "total": "10990000000000000000000000", "vault_count": 2,
            "cash": ["value": "1000000000000000000000000", "spending_value": "0", "awaiting_signature": 0],
            "vaults": [["vault": 0, "frozen": true, "share_price": "1000000000000000000", "value": "9990000000000000000000000",
                        "spending_value": "0", "awaiting_signature": 1]],
        ]))
        #expect(portfolio.vaults.count == 1 && portfolio.vaultCount == 2)
        #expect(portfolio.vaults[0].frozen && portfolio.vaults[0].pending && !portfolio.cash.pending)
        let summary = PoolSummary(["amount": "1000000000000000000000000", "contract": "pool.test",
                                   "expires_at": 1000000300000000000, "fees": ["storage": "20000000000000000000000"],
                                   "from": 0, "left_in_cash": "170000000000000000000000", "network": "sandbox",
                                   "new_shares_value": "810000000000000000000000", "op": "switch",
                                   "share_price": "1000000000000000000", "to": 1])
        #expect(summary.title == "Changer de vault")
        #expect(summary.rows.map(\.label) == ["Montant", "Depuis le vault", "Vers", "Nouvelles parts (valeur)",
                                              "Laissé dans le cash du pool (perdu)", "Frais : storage"])
        #expect(summary.rows.map(\.value) == ["1 NEAR", "0", "1", "0.81 NEAR", "0.17 NEAR", "0.02 NEAR"])
        #expect(!summary.rows.contains { $0.value.contains("1000000000000000000") }) // no share price
        #expect(summary.expiresAt == Date(timeIntervalSince1970: 1000000300))
        let deposit = PoolSummary(["op": "deposit", "account": "alice.test", "warning": "montant peu courant",
                                   "fees": ["refundable": "unused margin"],
                                   "wallet_call": ["receiver": "pool.test", "method": "deposit", "args": [:], "attached": "11010000000000000000000000"]])
        #expect(deposit.warnings == ["montant peu courant"])
        #expect(deposit.rows.last == PoolSummary.Row(label: "Frais : refundable", value: "unused margin"))
        #expect(deposit.walletCall == #"{"args":{},"attached":"11010000000000000000000000","method":"deposit","receiver":"pool.test"}"#)
    }

    @Test func saysWhatAnExecutionDid() {
        #expect(PoolOutcome.execute(["ok": false, "error": "outcome unknown, run pool_recover later: timeout"])
            == "Envoyée à l'agent du pool : le résultat arrivera plus tard (Récupérer).")
        #expect(PoolOutcome.execute(["ok": true, "complete": true]) == "Opération faite.")
        #expect(PoolOutcome.execute(["ok": false, "error": "no vault 9"]) == "Opération refusée : no vault 9")
        #expect(PoolOutcome.recover(["ok": true, "spent": 2, "held_again": 1, "still_spending": 0, "agent_error": "down"])
            == "Récupération : 2 faites, 1 revenues, 0 en attente (agent : down).")
    }
}


@MainActor
@Suite struct OnionClientAuthTests {
    @Test func base32MatchesRFC4648() {
        for (text, encoded) in [("", ""), ("f", "MY"), ("fo", "MZXQ"), ("foo", "MZXW6"), ("foob", "MZXW6YQ"),
                                ("fooba", "MZXW6YTB"), ("foobar", "MZXW6YTBOI")] {
            #expect(ProtocolBytes.base32(Data(text.utf8)) == encoded)
        }
    }

    /// The QR gives the phone the client key; tor gets its public half; forgetting the phone changes the key.
    @Test func theQRGivesThePhoneATorClientKey() throws {
        let pairing = PairingAuthority(name: "Mac", store: MemoryPairingStore())
        let secret = try #require(pairing.record.onionAuth)
        #expect(secret.count == 32)
        let text = try #require(pairing.payload(address: nil, onion: "x.onion"))
        var base64 = String(text.dropFirst(ProtocolBytes.payloadPrefix.count))
            .replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        let json = try #require(Data(base64Encoded: base64))
        let object = try #require(try JSONSerialization.jsonObject(with: json) as? [String: Any])
        #expect(object["onion_auth"] as? String == ProtocolBytes.base32(secret))
        let local = try #require(pairing.payload(address: "http://192.168.1.2:8790", onion: nil))
        #expect(!local.isEmpty)
        let line = try #require(pairing.onionClientAuth)
        let publicKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: secret).publicKey.rawRepresentation
        #expect(line == "descriptor:x25519:" + ProtocolBytes.base32(publicKey))
        pairing.forgetPhone()
        #expect(pairing.onionClientAuth != line)
    }
}


@MainActor
@Suite struct RelayClientTests {
    @Test func oneClientKeyForARestrictedRelay() throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: "ona-relay-\(UUID().uuidString)")
        let line = try TorService.relayClientAuth(dir: dir)
        #expect(line.hasPrefix("descriptor:x25519:") && line.count == 18 + 52)
        #expect(try TorService.relayClientAuth(dir: dir) == line, "the same key next time")
        let onion = String(repeating: "c", count: 56)
        let auth = try TorService.relayAuthDir(onion: onion, dir: dir)
        let text = try String(contentsOf: auth.appending(path: "relay.auth_private"), encoding: .utf8)
        #expect(text.hasPrefix(onion + ":descriptor:x25519:") && text.hasSuffix("\n"))
    }

    @Test func theRelayOnionComesFromModelJSON() throws {
        let file = FileManager.default.temporaryDirectory.appending(path: "ona-model-\(UUID().uuidString).json")
        let onion = String(repeating: "d", count: 56)
        try Data(#"{"relay_url":"http://\#(onion).onion/","model":"m","max_tokens":1,"token_budget":1}"#.utf8).write(to: file)
        #expect(RealModel.relayOnion(file: file) == onion)
        try Data(#"{"relay_url":"https://relay.example.org"}"#.utf8).write(to: file)
        #expect(RealModel.relayOnion(file: file) == nil)
    }
}
