import SwiftUI

/// What left the computer during the mission, as reported by the computer's journal.
struct ExposureView: View {
    let exposure: Exposure

    var body: some View {
        if exposure.mode.isSimulation {
            Label("Simulated report", systemImage: "theatermasks")
                .font(.caption)
                .foregroundStyle(.orange)
        }
        LabeledContent("Model calls", value: "\(exposure.modelCalls)")
        ForEach(exposure.outputs.sorted(by: { $0.key < $1.key }), id: \.key) { name, count in
            LabeledContent(outputLabel(name), value: "\(count)")
        }
        LabeledContent("Firms contacted") {
            Text(exposure.firmsContacted.isEmpty ? "none" : exposure.firmsContacted.joined(separator: ", "))
        }
        ForEach(Array(exposure.payments.enumerated()), id: \.offset) { _, payment in
            LabeledContent("Payment") {
                Text("\(amount(payment.amount)) NEAR → \(SignedFields.isNearAccount(payment.to) ? payment.to : "unreadable account")")
                    .font(.callout.monospaced())
                    .multilineTextAlignment(.trailing)
            }
        }
        if exposure.refusedByGate.isEmpty {
            LabeledContent("Guardrail refusals", value: "none")
        } else {
            ForEach(exposure.refusedByGate.sorted(by: { $0.key < $1.key }), id: \.key) { reason, count in
                LabeledContent("Refused: \(reason)", value: "\(count)")
            }
        }
    }

    private func outputLabel(_ name: String) -> String {
        switch name {
        case "search": "Searches sent"
        case "fetch": "Pages read"
        case "contact": "Messages sent"
        default: name
        }
    }

    private func amount(_ yocto: String) -> String {
        UInt128(yocto, radix: 10).map(NEARAmount.format) ?? yocto
    }
}
