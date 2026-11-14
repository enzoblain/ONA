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
        .alert("Forget this phone?", isPresented: $confirmingForget) {
            Button("Cancel", role: .cancel) {}
            Button("Forget", role: .destructive) { model.pairing.forgetPhone() }
        } message: {
            Text("It will no longer be able to ask or confirm anything on this computer. A new pairing code will be created.")
        }
    }

    // MARK: - States

    @ViewBuilder
    private var pairing: some View {
        Text("Pair a phone").font(.title2.weight(.semibold))
        Text("Scan this code in the ONA app on the phone. It works only once.")
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
            Button("Copy the code as text") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(payload, forType: .string)
            }
            .buttonStyle(.glass)
            #endif
        } else {
            waitingForAddress
        }
        if DesktopModel.ConnectionMode.available.count > 1 {
            Picker("Connection", selection: $model.mode) {
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
                Label("Tor is not installed on this Mac.", systemImage: "exclamationmark.triangle").foregroundStyle(.orange)
                Text("Install it with Homebrew: brew install tor").font(.callout.monospaced()).textSelection(.enabled)
                Button("Try again") { model.startServing() }
            case (.tor, .failed(let message)):
                Label("Tor: \(message)", systemImage: "exclamationmark.triangle").foregroundStyle(.red)
                Button("Try again") { model.startServing() }
            case (.tor, _):
                ProgressView()
                Text("Publishing the .onion address…").foregroundStyle(.secondary)
            case (.localNetwork, _):
                Label("No address on the local network.", systemImage: "wifi.slash").foregroundStyle(.orange)
            }
        }
        .frame(width: 284, height: 284)
    }

    private func verification(_ awaiting: PairingAuthority.Awaiting) -> some View {
        VStack(spacing: 18) {
            Image(systemName: "checkmark.shield").font(.system(size: 48)).foregroundStyle(.tint)
            Text("Check the code").font(.title2.weight(.semibold))
            Text("The phone must show the same code:").foregroundStyle(.secondary)
            Text("\(awaiting.code.prefix(3)) \(awaiting.code.suffix(3))")
                .font(.system(size: 46, weight: .semibold, design: .monospaced))
            Text("If the codes differ, or if the phone shows no code, someone may have stepped in between: refuse. This code expires after 5 minutes.")
                .font(.caption)
                .foregroundStyle(.secondary)
            HStack {
                Button("Refuse", role: .destructive) { model.pairing.forgetPhone() }
                    .buttonStyle(.glass)
                Button("The codes match") {
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
            Text("Phone paired").font(.title2.weight(.semibold))
            Form {
                LabeledContent("Paired on", value: phone.pairedAt.formatted(date: .abbreviated, time: .shortened))
                LabeledContent("Connection", value: model.mode.label)
                if let contact = model.lastPhoneContact {
                    LabeledContent("Last contact", value: contact.formatted(.relative(presentation: .named)))
                }
            }
            .formStyle(.grouped)
            .frame(height: 150)
            if let error = model.pairing.storageError {
                Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.red).font(.caption)
            }
            HStack {
                Button("Forget this phone", role: .destructive) { confirmingForget = true }
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
            Button("Close") { dismiss() }
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
                Picker("The phone reaches this Mac", selection: $model.mode) {
                    ForEach(DesktopModel.ConnectionMode.available) { Text($0.label).tag($0) }
                }
                .pickerStyle(.radioGroup)
            }
            Text(model.mode == .tor
                 ? "The server listens on this computer only (127.0.0.1) and is published as a .onion service by Tor."
                 : "Development build: the server listens on the local network, unencrypted. Any device on this network sees the traffic.")
                .font(.caption)
                .foregroundStyle(.secondary)
            LabeledContent("Tor") { TorStatusLabel(state: model.tor.state) }
            if let address = model.reachableAt {
                LabeledContent("Address") { Text(address).font(.caption.monospaced()).textSelection(.enabled) }
            }
            if let request = model.lastPhoneRequest {
                LabeledContent("Last request from the phone") { Text(request).font(.caption.monospaced()) }
            }
            if RealModel.relayOnion() != nil, let line = try? TorService.relayClientAuth() {
                LabeledContent("Key for the relay") { Text(line).font(.caption.monospaced()).textSelection(.enabled) }
                Text("If the .onion relay is limited to named clients, give this line to the person who runs it.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .frame(width: 520)
        .padding()
    }
}
