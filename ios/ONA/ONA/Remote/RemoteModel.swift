import Foundation
import Observation

/// What the remote control knows about the computer. Only the pairing is kept (Keychain); the rest lives in memory and
/// is rebuilt by polling.
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
    private(set) var state: ComputerState?
    private(set) var actionError: String?
    private(set) var sending = false
    private(set) var verification: PendingVerification?
    /// Set once any reply said `mode: mock`, so the simulation label never disappears in a session.
    private(set) var sawSimulation = false

    static let pollInterval: Duration = .seconds(3)

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

    var mission: Mission? { state?.mission }
    var pending: Pending? { state?.mission?.pending }
    var isSimulation: Bool { sawSimulation || (state?.isSimulation ?? false) }
    var isPaired: Bool { pairing != nil }
    /// True when the paired computer is reached through Tor.
    var usesTor: Bool { pairing.flatMap { Endpoint(onion: $0.onion, address: $0.address) }?.isTor ?? false }

    /// Default link factory for builds without Tor (the Mac test package). The app passes one that handles onions.
    nonisolated static func localOnlyLink(_ endpoint: Endpoint) -> any ComputerLink {
        switch endpoint {
        case .local(let url): HTTPComputerLink(baseURL: url)
        case .onion: UnavailableLink(reason: "Tor n'est pas disponible dans cette version")
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
                actionError = ack.error ?? "Appairage refusé par l'ordinateur"
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
        state = nil
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
            let state = try await link.state()
            self.state = state
            if state.isSimulation { sawSimulation = true }
            connection = .connected(.now)
        } catch {
            connection = .failed(error.localizedDescription)
        }
    }

    // MARK: - Confirmations (each one signed, each signature asks for Face ID on an iPhone)

    func acceptPlan(_ pending: Pending) async {
        await send(ConfirmationAnswer(id: pending.id, decision: .accept))
    }

    func chooseRecipient(_ pending: Pending, firm: String) async {
        await send(ConfirmationAnswer(id: pending.id, decision: .accept, firm: firm))
    }

    /// Only a payment verified on the phone can be confirmed; the digest sent is the phone's own.
    func confirmPayment(_ pending: Pending, verified: PaymentCheck.Verified) async {
        await send(ConfirmationAnswer(id: pending.id, decision: .accept, digest: verified.digest))
    }

    func reject(_ pending: Pending) async {
        await send(ConfirmationAnswer(id: pending.id, decision: .reject))
    }

    func mock(_ action: MockAction) async {
        guard let link else { return }
        await perform { try await link.mock(action) }
    }

    func clearActionError() {
        actionError = nil
    }

    private func send(_ answer: ConfirmationAnswer) async {
        guard let link, let key, let pairing else {
            actionError = "Ce téléphone n'est appairé à aucun ordinateur."
            return
        }
        let pairingID = pairing.pairingID
        sending = true
        let signed: ConfirmationAnswer
        do {
            signed = try await Task.detached {
                var signed = answer.unsigned
                signed.pairingId = pairingID
                signed.signature = try key.sign(SignedFields.confirmMessage(answer.unsigned, pairingID: pairingID))
                    .base64EncodedString()
                return signed
            }.value
        } catch {
            sending = false
            actionError = "Confirmation non signée : \(error.localizedDescription)"
            return
        }
        sending = false
        await perform { try await link.confirm(signed) }
    }

    private func perform(_ action: @Sendable () async throws -> Ack) async {
        sending = true
        defer { sending = false }
        do {
            let ack = try await action()
            if ack.mode?.isSimulation == true { sawSimulation = true }
            actionError = ack.ok ? nil : (ack.error ?? "refusé par l'ordinateur")
        } catch {
            actionError = error.localizedDescription
        }
        await refresh()
    }

    private func use(_ stored: StoredPairing, key: (any DeviceKey)? = nil, link: (any ComputerLink)? = nil) throws {
        guard let endpoint = Endpoint(onion: stored.onion, address: stored.address) else {
            throw LinkError.unreachable("appairage sans adresse")
        }
        self.key = try key ?? DeviceKeys.load(kind: stored.keyKind, representation: stored.keyRepresentation)
        self.link = link ?? makeLink(endpoint)
        pairing = stored
        state = nil
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
