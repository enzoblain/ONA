import SwiftUI

/// One sheet per confirmation kind. Nothing is sent until the person taps a button.
struct ConfirmationView: View {
    let model: RemoteModel
    let pending: Pending
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Group {
                switch pending.request {
                case .plan(let steps):
                    PlanConfirmation(steps: steps, model: model, pending: pending)
                case .recipient(let offers):
                    RecipientConfirmation(offers: offers, model: model, pending: pending)
                case .payment(let request):
                    PaymentConfirmation(request: request, model: model, pending: pending)
                case .unknown(let kind):
                    ContentUnavailableView(
                        "Confirmation inconnue",
                        systemImage: "questionmark.diamond",
                        description: Text("Type « \(kind) » non pris en charge par cette version de l'app.")
                    )
                }
            }
            .safeAreaInset(edge: .top, spacing: 0) {
                if model.isSimulation { SimulationBanner() }
            }
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Plus tard") { dismiss() }
                }
            }
            .overlay {
                if model.sending { ProgressView().controlSize(.large) }
            }
            .alert("Action refusée", isPresented: .constant(model.actionError != nil)) {
                Button("OK") { model.clearActionError() }
            } message: {
                Text(model.actionError ?? "")
            }
        }
        .interactiveDismissDisabled(model.sending)
    }
}

/// Accept / reject buttons shared by the three screens.
private struct DecisionButtons: View {
    let acceptTitle: String
    let canAccept: Bool
    let model: RemoteModel
    let pending: Pending
    let accept: () async -> Void

    var body: some View {
        VStack(spacing: 10) {
            Button {
                Task { await accept() }
            } label: {
                Text(acceptTitle).frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(!canAccept || model.sending)
            .accessibilityIdentifier("accept")

            Button(role: .destructive) {
                Task { await model.reject(pending) }
            } label: {
                Text("Refuser et arrêter la mission").frame(maxWidth: .infinity)
            }
            .controlSize(.large)
            .disabled(model.sending)
        }
        .padding()
        .background(.bar)
    }
}

// MARK: - Plan

private struct PlanConfirmation: View {
    let steps: [Step]
    let model: RemoteModel
    let pending: Pending

    var body: some View {
        List {
            Section {
                ForEach(Array(steps.enumerated()), id: \.offset) { index, step in
                    Label("\(index + 1). \(step.label)", systemImage: step.symbol)
                }
            } header: {
                Text("Plan proposé")
            } footer: {
                Text("Le plan est figé avant toute lecture du web. Les étapes marquées « vous » attendront ce téléphone.")
            }
        }
        .navigationTitle("Valider le plan")
        .safeAreaInset(edge: .bottom) {
            DecisionButtons(acceptTitle: "Valider le plan", canAccept: true, model: model, pending: pending) {
                await model.acceptPlan(pending)
            }
        }
    }
}

// MARK: - Recipient

private struct RecipientConfirmation: View {
    let offers: [Offer]
    let model: RemoteModel
    let pending: Pending
    @State private var selected: String?

    var body: some View {
        List {
            Section {
                ForEach(offers) { offer in
                    Button {
                        selected = offer.firmId
                    } label: {
                        OfferRow(offer: offer, selected: selected == offer.firmId)
                    }
                    .buttonStyle(.plain)
                    .accessibilityIdentifier("offer-\(offer.firmId)")
                }
            } header: {
                Text("Offres trouvées")
            } footer: {
                Text("Seul le cabinet choisi sera contacté. Les extraits cités viennent des pages lues.")
            }
        }
        .navigationTitle("Choisir le destinataire")
        .safeAreaInset(edge: .bottom) {
            DecisionButtons(
                acceptTitle: selected.map { "Choisir \($0)" } ?? "Choisissez une offre",
                canAccept: selected != nil,
                model: model,
                pending: pending
            ) {
                if let selected { await model.chooseRecipient(pending, firm: selected) }
            }
        }
    }
}

private struct OfferRow: View {
    let offer: Offer
    let selected: Bool

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                .font(.title3)
                .foregroundStyle(selected ? Color.accentColor : .secondary)
            VStack(alignment: .leading, spacing: 4) {
                Text(offer.firmId).font(.headline.monospaced())
                Text("\(Format.euros(cents: offer.priceCents)) · sous \(Format.days(offer.delayDays))")
                ForEach(offer.sourceSpans, id: \.self) { span in
                    Text("« \(span) »").font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .padding(.vertical, 4)
        .contentShape(Rectangle())
    }
}

// MARK: - Payment

private struct PaymentConfirmation: View {
    let request: PaymentRequest
    let model: RemoteModel
    let pending: Pending

    private var check: Result<PaymentCheck.Verified, PaymentCheck.Failure> { PaymentCheck.verify(request) }

    var body: some View {
        List {
            switch check {
            case .success(let verified):
                Section {
                    LabeledContent("Montant") {
                        Text("\(NEARAmount.format(verified.amount)) NEAR").font(.title3.bold())
                    }
                    LabeledContent("Destinataire") {
                        Text(verified.to).font(.body.monospaced())
                    }
                } header: {
                    Text("Paiement préparé par l'ordinateur")
                }
                Section {
                    Text(request.screen).font(.callout.monospaced())
                    LabeledContent("Empreinte", value: String(verified.digest.prefix(16)) + "…")
                        .font(.caption.monospaced())
                } header: {
                    Text("Vérifié sur ce téléphone")
                } footer: {
                    Text("Le téléphone a recalculé l'empreinte à partir du montant et du destinataire : elle correspond à celle de l'ordinateur. C'est cette empreinte qui est confirmée.")
                }
            case .failure(let failure):
                Section {
                    Label(message(for: failure), systemImage: "xmark.octagon.fill")
                        .foregroundStyle(.red)
                    Text(request.screen).font(.callout.monospaced())
                } header: {
                    Text("Paiement incohérent")
                } footer: {
                    Text("Ce paiement ne peut pas être confirmé. Refusez-le et vérifiez l'ordinateur.")
                }
            }
        }
        .navigationTitle("Confirmer le paiement")
        .safeAreaInset(edge: .bottom) {
            DecisionButtons(
                acceptTitle: "Confirmer le paiement",
                canAccept: (try? check.get()) != nil,
                model: model,
                pending: pending
            ) {
                if case .success(let verified) = check {
                    await model.confirmPayment(pending, verified: verified)
                }
            }
        }
    }

    private func message(for failure: PaymentCheck.Failure) -> String {
        switch failure {
        case .badAmount: "Montant illisible"
        case .digestMismatch: "L'empreinte ne correspond pas au montant et au destinataire"
        case .screenMismatch: "Le texte affiché ne correspond pas au paiement"
        }
    }
}
