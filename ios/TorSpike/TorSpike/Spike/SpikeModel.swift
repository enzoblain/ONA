import Foundation
import Network
import Observation
import UIKit

/// State of the Tor spike screen: runs the measurements and keeps their journal in memory (never on disk).
@MainActor
@Observable
final class SpikeModel {
    enum Phase: Equatable {
        case stopped
        case bootstrapping
        case ready
    }

    // Target (.onion test server). Default comes from Info.plist (Local.xcconfig), never from user defaults.
    var host: String = Bundle.main.object(forInfoDictionaryKey: "ONATestOnion") as? String ?? ""
    var port: String = "80"
    var path: String = "/"

    var coldStart = false
    var probeEvery30s = false {
        didSet { updateProbeLoop() }
    }
    var probeOnForeground = true

    private(set) var phase: Phase = .stopped
    private(set) var progress: Double = 0
    private(set) var progressText = ""
    private(set) var requestInFlight = false
    private(set) var journal: [Entry] = []
    private(set) var network = "?"
    private(set) var versions = ""

    private let engine = TorEngine.shared
    private let directories = ArtiDirectories.standard
    private let pathMonitor = NWPathMonitor()
    private var probeTask: Task<Void, Never>?
    private var probeCount = (ok: 0, failed: 0)

    init() {
        if let v = try? engine.version() {
            versions = "arti-bridge \(v.bridge) · arti-client \(v.artiClient)"
        }
        let device = UIDevice.current
        log(.info, "App lancée — \(Self.modelIdentifier()) · \(device.systemName) \(device.systemVersion) · \(versions)")
        startNetworkMonitor()
    }

    // MARK: - Actions

    func startTor() async {
        guard phase == .stopped else { return }
        phase = .bootstrapping
        progress = 0
        do {
            if coldStart { try directories.erase() }
            try directories.create()
        } catch {
            log(.error, "Dossiers Arti : \(error.localizedDescription)")
            phase = .stopped
            return
        }
        let warm = directories.hasCache
        let kind = warm ? "à chaud (cache présent)" : "à froid (pas de cache)"
        log(.info, "Démarrage de Tor \(kind), réseau \(network)")

        let progressTask = Task { [weak self] in
            while !Task.isCancelled {
                self?.refreshProgress()
                try? await Task.sleep(for: .milliseconds(250))
            }
        }
        defer { progressTask.cancel() }

        let clock = ContinuousClock()
        let started = clock.now
        do {
            let result = try await engine.bootstrap(directories: directories)
            let swiftMs = (clock.now - started).milliseconds
            let rustMs = result.bootstrapMs.map { "\($0) ms" } ?? "déjà démarré"
            phase = .ready
            refreshProgress()
            log(.measure, "Tor prêt \(kind) : \(rustMs) (vu de Swift : \(swiftMs) ms). Cache Arti : \(Self.bytes(directories.size()))")
        } catch {
            phase = .stopped
            log(.error, "Démarrage échoué après \((clock.now - started).milliseconds) ms : \(error.localizedDescription)")
        }
    }

    func stopTor() async {
        probeEvery30s = false
        await engine.shutdown()
        phase = .stopped
        progress = 0
        progressText = ""
        log(.info, "Tor arrêté (cache conservé : \(Self.bytes(directories.size())))")
    }

    func request(reason: String = "manuelle") async {
        guard phase == .ready, !requestInFlight else { return }
        let target = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !target.isEmpty, let port = UInt16(port) else {
            log(.error, "Adresse ou port invalide")
            return
        }
        requestInFlight = true
        defer { requestInFlight = false }

        let clock = ContinuousClock()
        let started = clock.now
        do {
            let result = try await engine.httpGet(host: target, port: port, path: path, timeout: .seconds(60))
            probeCount.ok += 1
            let body = result.body.trimmingCharacters(in: .whitespacesAndNewlines).prefix(80)
            log(.measure, "Requête \(reason) OK [\(network)] : connexion \(result.connectMs) ms, total \(result.totalMs) ms, "
                + "\(result.bytes) o — \(result.statusLine) — « \(body) »")
        } catch {
            probeCount.failed += 1
            log(.error, "Requête \(reason) échouée [\(network)] après \((clock.now - started).milliseconds) ms : "
                + error.localizedDescription)
        }
    }

    func eraseCache() {
        guard phase == .stopped else { return }
        do {
            try directories.erase()
            log(.info, "Cache Arti effacé")
        } catch {
            log(.error, "Effacement : \(error.localizedDescription)")
        }
    }

    func clearJournal() {
        journal.removeAll()
        probeCount = (0, 0)
    }

    /// Called on scene phase changes: Arti goes dormant in the background.
    func appMovedTo(foreground: Bool) {
        log(.info, foreground ? "Retour au premier plan" : "Passage en arrière-plan")
        engine.setDormant(!foreground)
        if foreground, probeOnForeground, phase == .ready {
            Task { await request(reason: "au retour") }
        }
    }

    var report: String {
        let header = """
        # Spike Tor (Arti) — journal
        Appareil : \(Self.modelIdentifier()), \(UIDevice.current.systemName) \(UIDevice.current.systemVersion)
        \(versions)
        Requêtes : \(probeCount.ok) OK, \(probeCount.failed) échecs

        """
        return header + journal.map(\.line).joined(separator: "\n")
    }

    // MARK: - Journal

    struct Entry: Identifiable, Sendable {
        enum Kind: Sendable { case info, measure, error }
        let id = UUID()
        let date: Date
        let kind: Kind
        let text: String

        var line: String {
            let mark = switch kind {
            case .info: "·"
            case .measure: "⏱"
            case .error: "✗"
            }
            return "\(date.formatted(.iso8601.time(includingFractionalSeconds: false))) \(mark) \(text)"
        }
    }

    private func log(_ kind: Entry.Kind, _ text: String) {
        journal.append(Entry(date: .now, kind: kind, text: text))
    }

    // MARK: - Helpers

    private func refreshProgress() {
        let status = engine.status()
        progress = status.progress
        progressText = status.description
    }

    private func updateProbeLoop() {
        probeTask?.cancel()
        probeTask = nil
        guard probeEvery30s else { return }
        log(.info, "Sonde toutes les 30 s activée")
        probeTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.request(reason: "sonde")
                try? await Task.sleep(for: .seconds(30))
            }
        }
    }

    private func startNetworkMonitor() {
        pathMonitor.pathUpdateHandler = { [weak self] path in
            let description = Self.describe(path)
            Task { @MainActor in
                guard let self, self.network != description else { return }
                let previous = self.network
                self.network = description
                if previous != "?" { self.log(.info, "Réseau : \(previous) → \(description)") }
            }
        }
        pathMonitor.start(queue: DispatchQueue(label: "ona.torspike.network"))
    }

    nonisolated private static func describe(_ path: NWPath) -> String {
        guard path.status == .satisfied else { return "hors ligne" }
        if path.usesInterfaceType(.wifi) { return "Wi-Fi" }
        if path.usesInterfaceType(.cellular) { return "cellulaire" }
        if path.usesInterfaceType(.wiredEthernet) { return "Ethernet" }
        return "autre"
    }

    private static func modelIdentifier() -> String {
        var info = utsname()
        uname(&info)
        return withUnsafeBytes(of: &info.machine) { raw in
            String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self)
        }
    }

    private static func bytes(_ count: Int64) -> String {
        count.formatted(.byteCount(style: .file))
    }
}

private extension Duration {
    var milliseconds: Int64 {
        components.seconds * 1000 + components.attoseconds / 1_000_000_000_000_000
    }
}
