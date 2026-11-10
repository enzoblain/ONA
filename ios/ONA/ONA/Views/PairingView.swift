import SwiftUI
import VisionKit

/// First screen when the phone is not paired: scan the computer's QR code (or paste its text).
struct PairingView: View {
    let model: RemoteModel
    @State private var scanning = false
    @State private var pasted = ""

    var body: some View {
        List {
            Section {
                VStack(alignment: .leading, spacing: 8) {
                    Label("Appairer un ordinateur", systemImage: "qrcode.viewfinder").font(.headline)
                    Text("Ouvrez ONA sur l'ordinateur et affichez son code d'appairage. Ce téléphone crée alors sa propre clé, gardée dans le Secure Enclave : chaque confirmation sera signée avec, après Face ID.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                .padding(.vertical, 4)
            }

            Section {
                Button {
                    scanning = true
                } label: {
                    Label("Scanner le QR code", systemImage: "camera")
                }
                .disabled(!QRScanner.isAvailable || model.sending)
            } footer: {
                if !QRScanner.isAvailable {
                    Text("Pas de caméra utilisable ici (simulateur ?) : collez le texte du code ci-dessous.")
                }
            }

            Section {
                TextField("ona-pair:…", text: $pasted, axis: .vertical)
                    .font(.footnote.monospaced())
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .lineLimit(3...6)
                    .accessibilityIdentifier("pairing-text")
                // System paste button: reads the clipboard only when tapped, without the paste permission prompt.
                PasteButton(payloadType: String.self) { strings in
                    if let text = strings.first { pasted = text }
                }
                .labelStyle(.titleAndIcon)
                Button("Appairer avec ce texte") {
                    Task { await model.pair(with: pasted) }
                }
                .disabled(pasted.isEmpty || model.sending)
                .accessibilityIdentifier("pair-pasted")
            } header: {
                Text("Ou coller le texte du code")
            }

            if model.sending {
                Section {
                    HStack {
                        ProgressView()
                        Text("Appairage…")
                    }
                }
            }
        }
        .sheet(isPresented: $scanning) {
            NavigationStack {
                QRScanner { text in
                    scanning = false
                    Task { await model.pair(with: text) }
                }
                .ignoresSafeArea()
                .navigationTitle("Code d'appairage")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Annuler") { scanning = false }
                    }
                }
            }
        }
    }
}

/// Shown once right after pairing: both screens must show the same 6 digits.
struct VerificationView: View {
    let model: RemoteModel
    let verification: RemoteModel.PendingVerification

    var body: some View {
        VStack(spacing: 24) {
            Image(systemName: "checkmark.shield")
                .font(.system(size: 56))
                .foregroundStyle(.tint)
            Text("Vérifiez le code").font(.title2.bold())
            Text("« \(verification.computerName) » doit afficher le même code :")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
            Text(spaced(verification.code))
                .font(.system(size: 44, weight: .semibold, design: .monospaced))
                .accessibilityIdentifier("verification-code")
            Text("Si les codes diffèrent, quelqu'un s'est peut-être interposé : annulez.")
                .font(.footnote)
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
            Spacer()
            VStack(spacing: 10) {
                Button {
                    model.verificationMatches()
                } label: {
                    Text("Les codes sont identiques").frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .accessibilityIdentifier("codes-match")
                Button(role: .destructive) {
                    model.unpair()
                } label: {
                    Text("Ils diffèrent : annuler l'appairage").frame(maxWidth: .infinity)
                }
                .controlSize(.large)
            }
        }
        .padding(24)
        .interactiveDismissDisabled()
    }

    private func spaced(_ code: String) -> String {
        "\(code.prefix(3)) \(code.suffix(3))"
    }
}

/// VisionKit live QR scanner. Calls `found` once with the first `ona-pair:` code seen.
struct QRScanner: UIViewControllerRepresentable {
    let found: (String) -> Void

    static var isAvailable: Bool {
        DataScannerViewController.isSupported && DataScannerViewController.isAvailable
    }

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let scanner = DataScannerViewController(
            recognizedDataTypes: [.barcode(symbologies: [.qr])],
            qualityLevel: .balanced,
            isHighlightingEnabled: true
        )
        scanner.delegate = context.coordinator
        try? scanner.startScanning()
        return scanner
    }

    func updateUIViewController(_ controller: DataScannerViewController, context: Context) {}

    func makeCoordinator() -> Coordinator { Coordinator(found: found) }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        let found: (String) -> Void
        private var done = false

        init(found: @escaping (String) -> Void) { self.found = found }

        func dataScanner(_ scanner: DataScannerViewController, didAdd items: [RecognizedItem], allItems: [RecognizedItem]) {
            guard !done else { return }
            for case .barcode(let code) in items {
                if let text = code.payloadStringValue, text.hasPrefix(PairingPayload.prefix) {
                    done = true
                    scanner.stopScanning()
                    found(text)
                    return
                }
            }
        }
    }
}
