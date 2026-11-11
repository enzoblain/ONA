import CryptoKit
import Foundation
import Testing
@testable import ONA

func sha(_ data: Data) -> String { SignedFields.sha256Hex(data) }

/// Values shared with the desktop apps' tests (`protocol_v1_vectors` in Rust, `protocolV1Vectors` in Swift).
enum Vector {
    static let computerKey = Data([4] + (1...64).map { UInt8($0) })
    static let phoneKey = Data([4] + (65...128).map { UInt8($0) })
    static let phoneNonce = "00112233445566778899aabbccddeeff"
    static let computerNonce = "ffeeddccbbaa99887766554433221100"
    static let code = "c29tZS1jb2Rl"
    static let pairingID = "p-0123456789abcdef0123456789abcdef"
}

func payloadText(computerKey: Data, code: String = "Y29kZS0xMjM0NTY3OA", address: String? = "http://computer.test:8790",
                 onion: String? = nil, version: Int = 1, expiresAt: Int? = Int(Date.now.timeIntervalSince1970) + 600)
    -> String {
    var object: [String: Any] = ["v": version, "name": "Mac de test", "computer_key": computerKey.base64EncodedString(),
                                 "code": code]
    object["address"] = address ?? NSNull()
    object["onion"] = onion ?? NSNull()
    object["expires_at"] = expiresAt
    let json = try! JSONSerialization.data(withJSONObject: object)
    return PairingPayload.prefix + json.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

@Suite("Protocol v1 vectors")
struct ProtocolV1Tests {
    @Test func layout() {
        let encoded = SignedFields.encode([.text("ab"), .bytes(Data([1])), .text(nil)])
        #expect(Array(encoded) == [2, 0, 0, 0, 0x61, 0x62, 1, 0, 0, 0, 1, 0, 0, 0, 0])
    }

    @Test func pairing() {
        #expect(SignedFields.commitment(phoneKey: Vector.phoneKey, phoneNonce: Vector.phoneNonce)
                == "6c2ee677c6aa3c2c1721f781e55f7e223caf87d729cc5e68bd6414de0a17bb7b")
        #expect(SignedFields.verificationCode(computerKey: Vector.computerKey, phoneKey: Vector.phoneKey, code: Vector.code,
                                              phoneNonce: Vector.phoneNonce, computerNonce: Vector.computerNonce) == "587047")
        #expect(sha(SignedFields.pairMessage(pairingID: Vector.pairingID, code: Vector.code, phoneKey: Vector.phoneKey,
                                             computerKey: Vector.computerKey, phoneNonce: Vector.phoneNonce,
                                             computerNonce: Vector.computerNonce))
                == "3332d89e36dd9adeb88e8f5f18861d92fdcc048357c78bc7c7ed6284c1a069cd")
    }

    @Test func writes() {
        #expect(sha(SignedFields.confirmMessage(pairingID: Vector.pairingID, counter: 7, id: "c-1", decision: "accept",
                                                firm: nil, digest: "ab", content: "cd"))
                == "1c61312dbd420b5f78b85dc82cf6f3c505386043f9704f4cd087f882a9389139")
        #expect(sha(SignedFields.chatMessage(pairingID: Vector.pairingID, counter: 8, chatID: nil, text: "bonjour"))
                == "7f4041bdaaef1fae3f26bd2abf1ad93d65e5f0b086c585ac5cb2e5979e5da082")
        #expect(sha(SignedFields.deleteMessage(pairingID: Vector.pairingID, counter: 9, chatID: "chat-1"))
                == "ee3c7db20a817bb5c643f005a052fbf5af413ce9780a6fa31f3acc0e91ed959c")
    }

    @Test func reply() {
        #expect(sha(SignedFields.replyMessage(nonce: "00112233445566778899aabbccddeeff", method: "POST",
                                              path: "/v1/chats/list", status: 200, reply: Data(#"{"ok":true}"#.utf8)))
                == "c9e6dc8eb32a3f5a97b226281a3151a023754cf518c0828468f3b25dd4e855b0")
    }

    @Test func digestsOfWhatIsShown() {
        #expect(SignedFields.planDigest(id: "c-1", steps: ["search", "read"])
                == "10b2ecd6ff60485e505b911709ed14b162137f0237abaa8aed21eee7c26edb84")
        let offer = Offer(firmId: "cabinet-b", priceCents: 60000, delayDays: 10, sourceSpans: ["Forfait 600 euros, sous 10 jours"])
        #expect(SignedFields.offersDigest(id: "c-2", offers: [offer])
                == "5127c86b14fc1406536bc274ea9c5b9e85e4a9b7e2adaf0c7b156ccf2dfb97b6")
    }

    /// Signature made by the Rust desktop app (p256, RFC 6979) with the private key 0x07…07.
    @Test func verifiesTheRustSignature() throws {
        let key = try #require(Data(base64Encoded: "BB4YUy/UdUwC8wQdnHXOszuD/9gax85P6ILMscmLxYlupGwxHE4v9A3ZajZT5uRURdMt/khuztdcepDGoYiBwKM="))
        let signature = "MEUCIQCKpmfTBH6QHkQjK+2OSErWZ8NWVddjujyvnAIvA9OSSAIgPYwZ31pcNKYUz59ysuap+EQESYYeUfOI8n8sUxE/SHU="
        let message = SignedFields.confirmMessage(pairingID: Vector.pairingID, counter: 7, id: "c-1", decision: "accept",
                                                  firm: nil, digest: "ab", content: "cd")
        #expect(SignedFields.verify(signature: signature, of: message, by: key))
        #expect(!SignedFields.verify(signature: signature, of: message + Data([0]), by: key))
        let privateKey = try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 7, count: 32))
        #expect(privateKey.publicKey.x963Representation == key)
    }

    /// CryptoKit makes a high-s signature about half the time: the phone always sends the low form, and refuses high-s.
    @Test func signaturesAreAlwaysLowS() throws {
        let key = SoftwareDeviceKey()
        let message = Data("ona".utf8)
        for _ in 0..<32 {
            let der = try key.sign(message)
            let signature = try P256.Signing.ECDSASignature(derRepresentation: der)
            #expect(SignedFields.isLowS(signature))
            #expect(SignedFields.verify(signature: der.base64EncodedString(), of: message, by: key.publicKey))
        }
        // The high form of a valid signature is refused.
        var high: P256.Signing.ECDSASignature?
        while high == nil {
            let signature = try key.key.signature(for: message)
            if !SignedFields.isLowS(signature) { high = signature }
        }
        let highSignature = try #require(high)
        #expect(key.key.publicKey.isValidSignature(highSignature, for: message))
        #expect(!SignedFields.verify(signature: highSignature.derRepresentation.base64EncodedString(), of: message,
                                     by: key.publicKey))
        #expect(SignedFields.verify(signature: try SignedFields.lowS(highSignature).derRepresentation.base64EncodedString(),
                                    of: message, by: key.publicKey))
    }
}

@Suite("Pairing payload v1")
struct PairingPayloadTests {
    let computerKey = SoftwareDeviceKey().publicKey

    @Test func parsesAValidCode() throws {
        let payload = try PairingPayload.parse(payloadText(computerKey: computerKey)).get()
        #expect(payload.name == "Mac de test")
        #expect(payload.address == URL(string: "http://computer.test:8790"))
        #expect(payload.computerKey == computerKey)
        #expect(payload.code == "Y29kZS0xMjM0NTY3OA")
    }

    @Test func refusesOtherTextAndVersions() {
        #expect(PairingPayload.parse("https://example.com") == .failure(.notAPairingCode))
        #expect(PairingPayload.parse("ona-pair:%%%") == .failure(.unreadable))
        #expect(PairingPayload.parse(payloadText(computerKey: computerKey, version: 0)) == .failure(.unsupportedVersion(0)))
        #expect(PairingPayload.parse(payloadText(computerKey: computerKey, version: 2)) == .failure(.unsupportedVersion(2)))
    }

    @Test func refusesAnExpiredCodeOrOneWithoutExpiry() {
        let past = Int(Date.now.timeIntervalSince1970) - 1
        #expect(PairingPayload.parse(payloadText(computerKey: computerKey, expiresAt: past)) == .failure(.expired))
        #expect(PairingPayload.parse(payloadText(computerKey: computerKey, expiresAt: nil)) == .failure(.unreadable))
    }

    @Test func refusesAKeyOffTheCurve() {
        let bad = Data([4] + [UInt8](repeating: 0, count: 64))
        #expect(PairingPayload.parse(payloadText(computerKey: bad)) == .failure(.badComputerKey))
    }

    @Test func refusesACodeWithoutUsableAddress() {
        #expect(PairingPayload.parse(payloadText(computerKey: computerKey, address: nil)) == .failure(.noAddress))
        #expect(PairingPayload.parse(payloadText(computerKey: computerKey, address: "ftp://x")) == .failure(.noAddress))
        #expect(PairingPayload.parse(payloadText(computerKey: computerKey, address: "https://x")) == .failure(.noAddress))
    }

    @Test func onionWinsOverLocalAddress() {
        let local = URL(string: "http://10.0.0.2:8790")!
        #expect(Endpoint(onion: "abc.onion", address: local) == .onion("abc.onion"))
        #expect(Endpoint(onion: nil, address: local) == .local(local))
        #expect(Endpoint(onion: "not-an-onion", address: local) == .local(local))
        #expect(Endpoint(onion: nil, address: nil) == nil)
    }
}

@Suite("Signed replies")
struct SignedReplyTests {
    let computer = P256.Signing.PrivateKey()

    private func envelope(_ reply: String, nonce: String, path: String, status: Int, key: P256.Signing.PrivateKey? = nil)
        throws -> RawReply {
        let message = SignedFields.replyMessage(nonce: nonce, method: "POST", path: path, status: status,
                                                reply: Data(reply.utf8))
        let signature = try SignedFields.lowS((key ?? computer).signature(for: message)).derRepresentation
        let body = try JSONSerialization.data(withJSONObject: ["reply": reply, "signature": signature.base64EncodedString()])
        return RawReply(status: status, body: body)
    }

    private var publicKey: Data { computer.publicKey.x963Representation }

    @Test func acceptsTheExactSignedText() throws {
        // The Mac app writes "/" as "\/": the phone checks the decoded text, never a re-encoding.
        let reply = #"{"ok":true,"path":"a\/b"}"#
        let raw = try envelope(reply, nonce: "n1", path: "/v1/chats/list", status: 200)
        let verified = try ComputerClient.verify(raw, nonce: "n1", path: "/v1/chats/list", computerKey: publicKey)
        #expect(verified.text == Data(reply.utf8))
    }

    @Test func refusesAnotherNoncePathStatusOrKey() throws {
        let raw = try envelope(#"{"ok":true}"#, nonce: "n1", path: "/v1/chats/list", status: 200)
        #expect(throws: LinkError.notAuthenticated) {
            try ComputerClient.verify(raw, nonce: "n2", path: "/v1/chats/list", computerKey: publicKey)
        }
        #expect(throws: LinkError.notAuthenticated) {
            try ComputerClient.verify(raw, nonce: "n1", path: "/v1/chats/x/view", computerKey: publicKey)
        }
        #expect(throws: LinkError.notAuthenticated) {
            try ComputerClient.verify(RawReply(status: 409, body: raw.body), nonce: "n1", path: "/v1/chats/list",
                                      computerKey: publicKey)
        }
        let other = try envelope(#"{"ok":true}"#, nonce: "n1", path: "/v1/chats/list", status: 200,
                                 key: P256.Signing.PrivateKey())
        #expect(throws: LinkError.notAuthenticated) {
            try ComputerClient.verify(other, nonce: "n1", path: "/v1/chats/list", computerKey: publicKey)
        }
    }

    @Test func unsignedRepliesAreFailuresWhoseBodyIsNotRead() {
        let body = Data(#"{"ok":true,"chats":[]}"#.utf8)
        #expect(throws: LinkError.notAuthenticated) {
            try ComputerClient.verify(RawReply(status: 200, body: body), nonce: "n", path: "/v1/chats/list", computerKey: publicKey)
        }
        #expect(throws: LinkError.failed(503)) {
            try ComputerClient.verify(RawReply(status: 503, body: body), nonce: "n", path: "/v1/chats/list", computerKey: publicKey)
        }
    }

    @Test func chatIdsCannotEscapeThePath() {
        #expect(Paths.view("chat-1") == "/v1/chats/chat-1/view")
        #expect(Paths.view("../confirm") == "/v1/chats/invalid/view")
        #expect(Paths.delete("a b") == "/v1/chats/invalid/delete")
    }
}
