import SwiftUI

struct MissionView: View {
    let model: RemoteModel
    let mission: Mission
    let open: (Pending) -> Void

    var body: some View {
        List {
            Section {
                ConnectionStatusRow(connection: model.connection, computer: model.state?.computer.name, viaTor: model.usesTor)
            }

            Section {
                VStack(alignment: .leading, spacing: 6) {
                    Text(mission.title).font(.headline)
                    Text(mission.phase.label)
                        .font(.subheadline.weight(.medium))
                        .foregroundStyle(mission.phase.color)
                }
                .padding(.vertical, 4)
            }

            if let pending = mission.pending {
                Section {
                    Button {
                        open(pending)
                    } label: {
                        PendingCard(pending: pending)
                    }
                    .accessibilityIdentifier("pending-card")
                }
            }

            if let exposure = mission.exposure {
                Section("Relevé d'exposition") {
                    ExposureView(exposure: exposure)
                }
            }

            Section("Étapes") {
                ForEach(Array(mission.steps.enumerated()), id: \.offset) { _, item in
                    StepRow(item: item)
                }
            }

            Section("Journal") {
                ForEach(Array(mission.events.reversed().enumerated()), id: \.offset) { _, event in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(event.text).font(.callout)
                        Text(event.date.formatted(date: .omitted, time: .standard))
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
            }

            if model.isSimulation, mission.phase == .closed || mission.phase == .cancelled {
                Section {
                    Button("Nouvelle simulation") { Task { await model.mock(.start) } }
                }
            }
        }
    }
}

private struct PendingCard: View {
    let pending: Pending

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "hand.raised.fill")
                .font(.title2)
                .foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 2) {
                Text("Confirmation demandée").font(.headline)
                Text(summary).font(.subheadline).foregroundStyle(.secondary)
            }
            Spacer()
            Image(systemName: "chevron.right").foregroundStyle(.tertiary)
        }
        .padding(.vertical, 6)
    }

    private var summary: String {
        switch pending.request {
        case .plan(let steps): "Valider le plan (\(steps.count) étapes)"
        case .recipient(let offers): "Choisir parmi \(offers.count) offres"
        case .payment: "Vérifier et confirmer le paiement"
        case .unknown(let kind): "Type inconnu : \(kind)"
        }
    }
}

private struct StepRow: View {
    let item: Mission.StepState

    var body: some View {
        HStack(spacing: 12) {
            statusIcon.frame(width: 22)
            Label(item.step.label, systemImage: item.step.symbol)
                .foregroundStyle(item.status == .pending ? .secondary : .primary)
                .fontWeight(item.status == .current ? .semibold : .regular)
        }
    }

    @ViewBuilder
    private var statusIcon: some View {
        switch item.status {
        case .done: Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
        case .current:
            if item.step.needsHuman {
                Image(systemName: "hand.raised.circle.fill").foregroundStyle(.orange)
            } else {
                ProgressView()
            }
        case .pending: Image(systemName: "circle").foregroundStyle(.tertiary)
        }
    }
}
