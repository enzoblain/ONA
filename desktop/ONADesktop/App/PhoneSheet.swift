import CoreImage.CIFilterBuiltins
import SwiftUI

/// Pairing the phone: the QR code, then the 6-digit code to compare; or the paired phone and the way to forget it.
struct PhoneSheet: View {
    @Bindable var model: DesktopModel
    @Environment(\.dismiss) private var dismiss
    @State private var confirmingForget = false

    var body: some View {
        VStack(spacing: 20) {
            if let awaiting = model.pairing.awaiting {
                verification(awaiting)
            } else if let phone = model.pairing.record.phone, phone.verified {
                paired(phone)
            } else {
                pairing
            }
        }
        .padding(28)
        .frame(width: 460)
        .alert("Oublier ce téléphone ?", isPresented: $confirmingForget) {
            Button("Annuler", role: .cancel) {}
            Button("Oublier", role: .destructive) { model.pairing.forgetPhone() }
        } message: {
            Text("Il ne pourra plus rien demander ni confirmer à cet ordinateur. Un nouveau code d'appairage sera créé.")
        }
    }

    // MARK: - States

    @ViewBuilder
    private var pairing: some View {
        Text("Appairer un téléphone").font(.title2.weight(.semibold))
        Text("Dans l'app ONA du téléphone, scannez ce code. Il ne sert qu'une fois.")
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
        if let payload = model.pairingPayload, let image = QRCode.image(payload) {
            Image(nsImage: image)
                .interpolation(.none)
                .resizable()
                .frame(width: 260, height: 260)
                .padding(12)
                .background(.white, in: .rect(cornerRadius: 16))
            if let reachable = model.reachableAt {
                Label(reachable, systemImage: model.mode == .tor ? "lock.shield" : "wifi")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .lineLimit(2)
            }
            #if DEBUG
            // Debug builds only (the simulator has no camera): the general pasteboard is readable by every app.
            Button("Copier le texte du code") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(payload, forType: .string)
            }
            .buttonStyle(.glass)
            #endif
        } else {
            waitingForAddress
        }
        if DesktopModel.ConnectionMode.available.count > 1 {
            Picker("Connexion", selection: $model.mode) {
                ForEach(DesktopModel.ConnectionMode.available) { Text($0.label).tag($0) }
            }
            .pickerStyle(.segmented)
        }
        if let error = model.pairing.storageError {
            Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.red).font(.caption)
        }
        footer
    }

    @ViewBuilder
    private var waitingForAddress: some View {
        VStack(spacing: 10) {
            switch (model.mode, model.tor.state) {
            case (.tor, .missing):
                Label("Tor n'est pas installé sur ce Mac.", systemImage: "exclamationmark.triangle").foregroundStyle(.orange)
                Text("Installez-le avec Homebrew : brew install tor").font(.callout.monospaced()).textSelection(.enabled)
                Button("Réessayer") { model.startServing() }
            case (.tor, .failed(let message)):
                Label("Tor : \(message)", systemImage: "exclamationmark.triangle").foregroundStyle(.red)
                Button("Réessayer") { model.startServing() }
            case (.tor, _):
                ProgressView()
                Text("Publication de l'adresse .onion…").foregroundStyle(.secondary)
            case (.localNetwork, _):
                Label("Pas d'adresse sur le réseau local.", systemImage: "wifi.slash").foregroundStyle(.orange)
            }
        }
        .frame(width: 284, height: 284)
    }

    private func verification(_ awaiting: PairingAuthority.Awaiting) -> some View {
        VStack(spacing: 18) {
            Image(systemName: "checkmark.shield").font(.system(size: 48)).foregroundStyle(.tint)
            Text("Vérifiez le code").font(.title2.weight(.semibold))
            Text("Le téléphone doit afficher le même code :").foregroundStyle(.secondary)
            Text("\(awaiting.code.prefix(3)) \(awaiting.code.suffix(3))")
                .font(.system(size: 46, weight: .semibold, design: .monospaced))
            Text("Si les codes diffèrent, ou si le téléphone n'affiche aucun code, quelqu'un s'est peut-être interposé : refusez. Ce code expire au bout de 5 minutes.")
                .font(.caption)
                .foregroundStyle(.secondary)
            HStack {
                Button("Refuser", role: .destructive) { model.pairing.forgetPhone() }
                    .buttonStyle(.glass)
                Button("Les codes sont identiques") {
                    if model.pairing.confirmCode() { dismiss() }
                }
                .buttonStyle(.glassProminent)
                .keyboardShortcut(.defaultAction)
            }
        }
    }

    private func paired(_ phone: PairingRecord.PairedPhone) -> some View {
        VStack(spacing: 16) {
            Image(systemName: "iphone.gen3.circle.fill").font(.system(size: 48)).foregroundStyle(.green)
            Text("Téléphone appairé").font(.title2.weight(.semibold))
            Form {
                LabeledContent("Appairé le", value: phone.pairedAt.formatted(date: .abbreviated, time: .shortened))
                LabeledContent("Connexion", value: model.mode.label)
                if let contact = model.lastPhoneContact {
                    LabeledContent("Dernier contact", value: contact.formatted(.relative(presentation: .named)))
                }
            }
            .formStyle(.grouped)
            .frame(height: 150)
            if let error = model.pairing.storageError {
                Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.red).font(.caption)
            }
            HStack {
                Button("Oublier ce téléphone", role: .destructive) { confirmingForget = true }
                    .buttonStyle(.glass)
                Spacer()
                Button("OK") { dismiss() }
                    .buttonStyle(.glassProminent)
                    .keyboardShortcut(.defaultAction)
            }
        }
    }

    private var footer: some View {
        HStack {
            Spacer()
            Button("Fermer") { dismiss() }
                .keyboardShortcut(.cancelAction)
        }
    }
}

enum QRCode {
    static func image(_ text: String) -> NSImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 10, y: 10)) else { return nil }
        let rep = NSCIImageRep(ciImage: output)
        let image = NSImage(size: rep.size)
        image.addRepresentation(rep)
        return image
    }
}

/// Settings window (⌘,): how the phone reaches this Mac.
struct SettingsView: View {
    @Bindable var model: DesktopModel

    var body: some View {
        Form {
            if DesktopModel.ConnectionMode.available.count > 1 {
                Picker("Le téléphone joint ce Mac", selection: $model.mode) {
                    ForEach(DesktopModel.ConnectionMode.available) { Text($0.label).tag($0) }
                }
                .pickerStyle(.radioGroup)
            }
            Text(model.mode == .tor
                 ? "Le serveur écoute seulement sur cet ordinateur (127.0.0.1) et est publié en service .onion par Tor."
                 : "Version de développement : le serveur écoute sur le réseau local, en clair. Tout appareil de ce réseau voit les échanges.")
                .font(.caption)
                .foregroundStyle(.secondary)
            LabeledContent("Tor") { TorStatusLabel(state: model.tor.state) }
            if let address = model.reachableAt {
                LabeledContent("Adresse") { Text(address).font(.caption.monospaced()).textSelection(.enabled) }
            }
            if let request = model.lastPhoneRequest {
                LabeledContent("Dernière requête du téléphone") { Text(request).font(.caption.monospaced()) }
            }
            if RealModel.relayOnion() != nil, let line = try? TorService.relayClientAuth() {
                LabeledContent("Clé pour le relais") { Text(line).font(.caption.monospaced()).textSelection(.enabled) }
                Text("Si le relais .onion est réservé à des clients nommés, donnez cette ligne à la personne qui le fait tourner.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .frame(width: 520)
        .padding()
    }
}
