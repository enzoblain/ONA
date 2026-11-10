import Foundation
import Observation

/// What the remote control knows about the computer. Kept in memory only, rebuilt by polling.
@MainActor
@Observable
final class RemoteModel {
    enum Connection: Equatable {
        case idle
        case connecting
        case connected(Date)
        case failed(String)
    }

    /// Address of the computer. Comes from Info.plist (`ONAComputerURL`) and can be changed in the app;
    /// it is not saved (pairing comes at step 3).
    var address: String {
        didSet { if address != oldValue { rebuildLink() } }
    }

    private(set) var connection: Connection = .idle
    private(set) var state: ComputerState?
    private(set) var actionError: String?
    private(set) var sending = false
    /// Set once any reply said `mode: mock`, so the simulation label never disappears in a session.
    private(set) var sawSimulation = false

    static let pollInterval: Duration = .seconds(3)

    private var link: (any ComputerLink)?
    private var pollTask: Task<Void, Never>?
    private let makeLink: @Sendable (URL) -> any ComputerLink

    init(
        address: String? = nil,
        makeLink: @escaping @Sendable (URL) -> any ComputerLink = { HTTPComputerLink(baseURL: $0) }
    ) {
        self.address = address
            ?? (Bundle.main.object(forInfoDictionaryKey: "ONAComputerURL") as? String)
            ?? "http://127.0.0.1:8790"
        self.makeLink = makeLink
        rebuildLink()
    }

    var mission: Mission? { state?.mission }
    var pending: Pending? { state?.mission?.pending }
    var isSimulation: Bool { sawSimulation || (state?.isSimulation ?? false) }

    // MARK: - Polling (foreground only: no push, no background refresh)

    func startPolling() {
        guard pollTask == nil else { return }
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

    // MARK: - Confirmations

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

    private func send(_ confirmation: ConfirmationAnswer) async {
        guard let link else { return }
        await perform { try await link.confirm(confirmation) }
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

    private func rebuildLink() {
        state = nil
        connection = .idle
        if let url = URL(string: address.trimmingCharacters(in: .whitespaces)), url.scheme != nil, url.host() != nil {
            link = makeLink(url)
        } else {
            link = nil
            connection = .failed("Adresse invalide")
        }
    }
}
