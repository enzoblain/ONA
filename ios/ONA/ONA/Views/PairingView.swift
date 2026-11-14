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
                    Label("Pair a computer", systemImage: "qrcode.viewfinder").font(.headline)
                    Text("Open ONA on your computer and show its pairing code. This phone then creates a key that never leaves its secure chip: each confirmation is signed with it, after Face ID.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                .padding(.vertical, 4)
            }

            Section {
                Button {
                    scanning = true
                } label: {
                    Label("Scan the QR code", systemImage: "camera")
                }
                .disabled(!QRScanner.isAvailable || model.sending)
            } footer: {
                if !QRScanner.isAvailable {
                    Text("The camera is not available: paste the code's text below.")
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
                Button("Pair with this text") {
                    Task { await model.pair(with: pasted) }
                }
                .disabled(pasted.isEmpty || model.sending)
                .accessibilityIdentifier("pair-pasted")
            } header: {
                Text("Or paste the code's text")
            }

            if model.sending {
                Section {
                    HStack {
                        ProgressView()
                        Text("Pairing…")
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
                .navigationTitle("Pairing code")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") { scanning = false }
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
            Text("Check the code").font(.title2.bold())
            Text("“\(verification.computerName)” must show the same code:")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
            Text(spaced(verification.code))
                .font(.system(size: 44, weight: .semibold, design: .monospaced))
                .accessibilityIdentifier("verification-code")
            Text("If the codes differ, someone may be intercepting the pairing: cancel.")
                .font(.footnote)
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
            Spacer()
            VStack(spacing: 10) {
                Button {
                    model.verificationMatches()
                } label: {
                    Text("The codes match").frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .accessibilityIdentifier("codes-match")
                Button(role: .destructive) {
                    model.cancelPairing()
                } label: {
                    Text("They differ: cancel pairing").frame(maxWidth: .infinity)
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
