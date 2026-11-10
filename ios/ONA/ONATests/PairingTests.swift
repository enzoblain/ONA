import CryptoKit
import Foundation
import Testing
@testable import ONA

/// Fixed software key used to produce the cross-language vector checked by ios/MockComputer/test_pairing.py.
private let vectorKey = try! P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x2A, count: 32))

private func payloadText(computerKey: Data, code: String = "Y29kZS0xMjM0NTY3OA",
                         address: String? = "http://computer.test:8790", version: Int = 0) -> String {
    var object: [String: Any] = ["v": version, "name": "Mac de test", "computer_key": computerKey.base64EncodedString(),
                                 "code": code, "onion": NSNull()]
    object["address"] = address ?? NSNull()
    let json = try! JSONSerialization.data(withJSONObject: object)
    let base64url = json.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
    return PairingPayload.prefix + base64url
}

@Suite("Signed fields")
struct SignedFieldsTests {
    @Test func layoutMatchesThePythonMock() {
        // Same expectation as FieldsTests.test_layout in test_pairing.py.
        let encoded = SignedFields.encode([.text("ab"), .bytes(Data([1])), .text(nil)])
        #expect(Array(encoded) == [2, 0, 0, 0, 0x61, 0x62, 1, 0, 0, 0, 1, 0, 0, 0, 0])
    }

    @Test func sasVector() {
        let computerKey = Data([4] + (1...64).map { UInt8($0) })
        let phoneKey = Data([4] + (65...128).map { UInt8($0) })
        let code = SignedFields.verificationCode(computerKey: computerKey, phoneKey: phoneKey, code: "c29tZS1jb2Rl")
        #expect(code.count == 6)
        let allDigits = code.allSatisfy { $0.isNumber }
        #expect(allDigits)
        print("SAS_EXPECTED = \"\(code)\"")
    }

    @Test func confirmMessageCoversEveryDecisionField() {
        let base = ConfirmationAnswer(id: "c-2", decision: .accept, firm: "cabinet-b")
        let message = SignedFields.confirmMessage(base, pairingID: "p-1")
        #expect(message != SignedFields.confirmMessage(ConfirmationAnswer(id: "c-2", decision: .accept, firm: "cabinet-a"), pairingID: "p-1"))
        #expect(message != SignedFields.confirmMessage(ConfirmationAnswer(id: "c-3", decision: .accept, firm: "cabinet-b"), pairingID: "p-1"))
        #expect(message != SignedFields.confirmMessage(ConfirmationAnswer(id: "c-2", decision: .reject, firm: "cabinet-b"), pairingID: "p-1"))
        #expect(message != SignedFields.confirmMessage(base, pairingID: "p-2"))
        // The signature fields themselves are not signed.
        var signed = base
        signed.pairingId = "p-1"
        signed.signature = "xyz"
        #expect(SignedFields.confirmMessage(signed.unsigned, pairingID: "p-1") == message)
    }

    @Test func crossLanguageVector() throws {
        let message = SignedFields.confirmMessage(ConfirmationAnswer(id: "c-3", decision: .accept, digest: "ab"), pairingID: "p-1")
        let signature = try vectorKey.signature(for: message)
        #expect(vectorKey.publicKey.isValidSignature(signature, for: message))
        print("SWIFT_PUBLIC_KEY = \"\(vectorKey.publicKey.x963Representation.base64EncodedString())\"")
        print("SWIFT_MESSAGE_HEX = \"\(message.map { String(format: "%02x", $0) }.joined())\"")
        print("SWIFT_SIGNATURE = \"\(signature.derRepresentation.base64EncodedString())\"")
    }
}

@Suite("Pairing payload")
struct PairingPayloadTests {
    let computerKey = SoftwareDeviceKey().publicKey

    @Test func parsesAValidCode() throws {
        let payload = try PairingPayload.parse(payloadText(computerKey: computerKey)).get()
        #expect(payload.name == "Mac de test")
        #expect(payload.address == URL(string: "http://computer.test:8790"))
        #expect(payload.computerKey == computerKey)
        #expect(payload.code == "Y29kZS0xMjM0NTY3OA")
    }

    @Test func refusesOtherText() {
        #expect(PairingPayload.parse("https://example.com") == .failure(.notAPairingCode))
        #expect(PairingPayload.parse("ona-pair:%%%") == .failure(.unreadable))
    }

    @Test func refusesAnotherVersion() {
        #expect(PairingPayload.parse(payloadText(computerKey: computerKey, version: 1)) == .failure(.unsupportedVersion(1)))
    }

    @Test func refusesAKeyOffTheCurve() {
        let bad = Data([4] + [UInt8](repeating: 0, count: 64))
        #expect(PairingPayload.parse(payloadText(computerKey: bad)) == .failure(.badComputerKey))
    }

    @Test func refusesACodeWithoutAddress() {
        #expect(PairingPayload.parse(payloadText(computerKey: computerKey, address: nil)) == .failure(.noAddress))
        #expect(PairingPayload.parse(payloadText(computerKey: computerKey, address: "ftp://x")) == .failure(.noAddress))
    }
}

/// Plays the computer: checks the pairing signature, records signed confirmations.
final class FakeLink: ComputerLink, @unchecked Sendable {
    let lock = NSLock()
    var pairRequests: [PairRequest] = []
    var sent: [ConfirmationAnswer] = []
    let stateData: Data
    let computerKey: Data
    var acceptPairing = true

    init(stateData: Data, computerKey: Data) {
        self.stateData = stateData
        self.computerKey = computerKey
    }

    func state() async throws -> ComputerState {
        try ProtocolCoding.decoder.decode(ComputerState.self, from: stateData)
    }

    func pair(_ request: PairRequest) async throws -> Ack {
        lock.withLock { pairRequests.append(request) }
        return acceptPairing ? Ack(ok: true, error: nil, mode: .mock, pairingId: "p-7")
            : Ack(ok: false, error: "unknown or used pairing code", mode: .mock)
    }

    func confirm(_ confirmation: ConfirmationAnswer) async throws -> Ack {
        lock.withLock { sent.append(confirmation) }
        return Ack(ok: true, error: nil, mode: .mock)
    }

    func mock(_ action: MockAction) async throws -> Ack {
        Ack(ok: true, error: nil, mode: .mock)
    }
}

/// Signs, but remembers that it was asked to.
private struct RecordingKey: DeviceKey {
    let inner = SoftwareDeviceKey()
    var kind: DeviceKeyKind { inner.kind }
    var publicKey: Data { inner.publicKey }
    var storedRepresentation: Data { inner.storedRepresentation }
    func sign(_ message: Data) throws -> Data { try inner.sign(message) }
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
@Suite("Remote model with pairing")
struct RemoteModelTests {
    let computer = SoftwareDeviceKey()

    private func pairedModel(key: any DeviceKey = RecordingKey()) async throws -> (RemoteModel, FakeLink, any DeviceKey, MemoryPairingStore) {
        let link = FakeLink(stateData: MessageTests.waitingForPayment, computerKey: computer.publicKey)
        let store = MemoryPairingStore()
        let model = RemoteModel(store: store, makeLink: { _ in link }, makeKey: { key })
        await model.pair(with: payloadText(computerKey: computer.publicKey))
        #expect(model.actionError == nil)
        return (model, link, key, store)
    }

    private func verify(_ answer: ConfirmationAnswer, with key: any DeviceKey) throws -> Bool {
        let publicKey = try P256.Signing.PublicKey(x963Representation: key.publicKey)
        let text = try #require(answer.signature)
        let der = try #require(Data(base64Encoded: text))
        let signature = try P256.Signing.ECDSASignature(derRepresentation: der)
        let pairingID = try #require(answer.pairingId)
        let message = SignedFields.confirmMessage(answer.unsigned, pairingID: pairingID)
        return publicKey.isValidSignature(signature, for: message)
    }

    @Test func pairingSendsAProofAndStoresThePairing() async throws {
        let (model, link, key, store) = try await pairedModel()
        let request = try #require(link.pairRequests.first)
        #expect(request.code == "Y29kZS0xMjM0NTY3OA")
        #expect(Data(base64Encoded: request.phoneKey) == key.publicKey)
        let proofDER = try #require(Data(base64Encoded: request.signature))
        let proof = try P256.Signing.ECDSASignature(derRepresentation: proofDER)
        let message = SignedFields.pairMessage(code: request.code, phoneKey: key.publicKey, computerKey: computer.publicKey)
        #expect(try P256.Signing.PublicKey(x963Representation: key.publicKey).isValidSignature(proof, for: message))

        let stored = try #require(try store.load())
        #expect(stored.pairingID == "p-7")
        #expect(stored.computerKey == computer.publicKey)
        #expect(model.isPaired)
        let verification = try #require(model.verification)
        #expect(verification.code == SignedFields.verificationCode(computerKey: computer.publicKey, phoneKey: key.publicKey, code: request.code))
    }

    @Test func refusedPairingStoresNothing() async throws {
        let link = FakeLink(stateData: MessageTests.waitingForPayment, computerKey: computer.publicKey)
        link.acceptPairing = false
        let store = MemoryPairingStore()
        let model = RemoteModel(store: store, makeLink: { _ in link }, makeKey: { SoftwareDeviceKey() })
        await model.pair(with: payloadText(computerKey: computer.publicKey))
        #expect(model.actionError == ComputerMessages.french("unknown or used pairing code"))
        #expect(!model.isPaired)
        #expect(try store.load() == nil)
    }

    @Test func confirmsAPaymentWithASignatureOverThePhonesDigest() async throws {
        let (model, link, key, _) = try await pairedModel()
        #expect(model.isSimulation)
        let pending = try #require(model.pending)
        guard case .payment(let request) = pending.request else {
            Issue.record("expected a payment")
            return
        }
        await model.confirmPayment(pending, verified: try PaymentCheck.verify(request).get())
        let sent = try #require(link.sent.first)
        #expect(sent.unsigned == ConfirmationAnswer(id: "c-3", decision: .accept, digest: "a43ba249fbdd55a64a0647282b6dff66d660a1d8a8d75a8fbf3533bfa450fa31"))
        #expect(sent.pairingId == "p-7")
        #expect(try verify(sent, with: key))
    }

    @Test func rejectIsSignedToo() async throws {
        let (model, link, key, _) = try await pairedModel()
        await model.reject(try #require(model.pending))
        let sent = try #require(link.sent.first)
        #expect(sent.decision == .reject)
        #expect(try verify(sent, with: key))
    }

    @Test func cancelledSignatureSendsNothing() async throws {
        // Pairing itself needs a signature (Face ID cancelled, for instance): nothing is sent, nothing is stored.
        let link = FakeLink(stateData: MessageTests.waitingForPayment, computerKey: computer.publicKey)
        let store = MemoryPairingStore()
        let model = RemoteModel(store: store, makeLink: { _ in link }, makeKey: { RefusingKey() })
        await model.pair(with: payloadText(computerKey: computer.publicKey))
        #expect(model.actionError != nil)
        #expect(!model.isPaired)
        #expect(try store.load() == nil)
        #expect(link.pairRequests.isEmpty)
        #expect(link.sent.isEmpty)
    }

    @Test func notPairedCannotConfirm() async throws {
        let link = FakeLink(stateData: MessageTests.waitingForPayment, computerKey: computer.publicKey)
        let model = RemoteModel(store: MemoryPairingStore(), makeLink: { _ in link }, makeKey: { SoftwareDeviceKey() })
        #expect(model.connection == .notPaired)
        await model.acceptPlan(try PairingTestsHelpers.planPending())
        #expect(model.actionError == "Ce téléphone n'est appairé à aucun ordinateur.")
        #expect(link.sent.isEmpty)
    }

    @Test func reloadsAStoredPairing() async throws {
        let (_, _, key, store) = try await pairedModel()
        let link = FakeLink(stateData: MessageTests.waitingForPayment, computerKey: computer.publicKey)
        let reopened = RemoteModel(store: store, makeLink: { _ in link }, makeKey: { SoftwareDeviceKey() })
        #expect(reopened.isPaired)
        #expect(reopened.connection == .idle)
        await reopened.refresh()
        await reopened.reject(try #require(reopened.pending))
        // Signed with the key loaded back from the store, not a new one.
        #expect(try verify(try #require(link.sent.first), with: key))
    }

    @Test func unpairForgetsEverything() async throws {
        let (model, _, _, store) = try await pairedModel()
        model.unpair()
        #expect(!model.isPaired)
        #expect(model.connection == .notPaired)
        #expect(model.state == nil)
        #expect(try store.load() == nil)
    }
}

enum PairingTestsHelpers {
    static func planPending() throws -> Pending {
        try ProtocolCoding.decoder.decode(Pending.self, from: Data(#"{"id":"c-1","kind":"plan","plan":["search"]}"#.utf8))
    }
}

@Suite("Endpoints and replies")
struct EndpointTests {
    @Test func onionWinsOverLocalAddress() {
        let local = URL(string: "http://10.0.0.2:8790")!
        #expect(Endpoint(onion: "abc.onion", address: local) == .onion("abc.onion"))
        #expect(Endpoint(onion: nil, address: local) == .local(local))
        #expect(Endpoint(onion: "not-an-onion", address: local) == .local(local))
        #expect(Endpoint(onion: nil, address: nil) == nil)
    }

    @Test func decodesErrorBodiesOnlyWhenAsked() throws {
        let body = Data(#"{"ok":false,"error":"stale confirmation","mode":"mock"}"#.utf8)
        let ack = try ProtocolCoding.decodeReply(Ack.self, status: 409, body: body, acceptErrorBody: true)
        #expect(ack.error == "stale confirmation")
        #expect(throws: LinkError.self) {
            try ProtocolCoding.decodeReply(ComputerState.self, status: 409, body: body, acceptErrorBody: false)
        }
    }

    @MainActor @Test func pairsWithAnOnionCode() async throws {
        let computer = SoftwareDeviceKey()
        let link = FakeLink(stateData: MessageTests.waitingForPayment, computerKey: computer.publicKey)
        let endpoints = EndpointRecorder()
        let store = MemoryPairingStore()
        let model = RemoteModel(store: store, makeLink: { endpoint in endpoints.add(endpoint); return link },
                                makeKey: { SoftwareDeviceKey() })
        let onion = String(repeating: "a", count: 56) + ".onion"
        let object: [String: Any] = ["v": 0, "name": "Mac", "address": NSNull(), "onion": onion,
                                     "computer_key": computer.publicKey.base64EncodedString(), "code": "abc"]
        let json = try JSONSerialization.data(withJSONObject: object).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        await model.pair(with: PairingPayload.prefix + json)
        #expect(model.actionError == nil)
        #expect(model.usesTor)
        #expect(endpoints.all == [.onion(onion)])
        #expect(try store.load()?.onion == onion)
    }

    @MainActor @Test func theMacPackageCannotReachAnOnion() async {
        let model = RemoteModel(store: MemoryPairingStore(), makeKey: { SoftwareDeviceKey() })
        let link = RemoteModel.localOnlyLink(.onion("x.onion"))
        await #expect(throws: LinkError.self) { try await link.state() }
        #expect(!model.isPaired)
    }
}

final class EndpointRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var endpoints: [Endpoint] = []
    func add(_ endpoint: Endpoint) { lock.withLock { endpoints.append(endpoint) } }
    var all: [Endpoint] { lock.withLock { endpoints } }
}
