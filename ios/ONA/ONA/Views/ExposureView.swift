import SwiftUI

/// What left the computer during the mission, as reported by the computer's journal.
struct ExposureView: View {
    let exposure: Exposure

    var body: some View {
        if exposure.mode.isSimulation {
            Label("Relevé d'une simulation", systemImage: "theatermasks")
                .font(.caption)
                .foregroundStyle(.orange)
        }
        LabeledContent("Appels au modèle", value: "\(exposure.modelCalls)")
        ForEach(exposure.outputs.sorted(by: { $0.key < $1.key }), id: \.key) { name, count in
            LabeledContent(outputLabel(name), value: "\(count)")
        }
        LabeledContent("Cabinets contactés") {
            Text(exposure.firmsContacted.isEmpty ? "aucun" : exposure.firmsContacted.joined(separator: ", "))
        }
        ForEach(Array(exposure.payments.enumerated()), id: \.offset) { _, payment in
            LabeledContent("Paiement") {
                Text("\(amount(payment.amount)) NEAR → \(SignedFields.isNearAccount(payment.to) ? payment.to : "compte illisible")")
                    .font(.callout.monospaced())
                    .multilineTextAlignment(.trailing)
            }
        }
        if exposure.refusedByGate.isEmpty {
            LabeledContent("Refus du garde-fou", value: "aucun")
        } else {
            ForEach(exposure.refusedByGate.sorted(by: { $0.key < $1.key }), id: \.key) { reason, count in
                LabeledContent("Refusé : \(reason)", value: "\(count)")
            }
        }
    }

    private func outputLabel(_ name: String) -> String {
        switch name {
        case "search": "Recherches envoyées"
        case "fetch": "Pages lues"
        case "contact": "Messages envoyés"
        default: name
        }
    }

    private func amount(_ yocto: String) -> String {
        UInt128(yocto, radix: 10).map(NEARAmount.format) ?? yocto
    }
}
