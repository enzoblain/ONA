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
                case .queries(let queries):
                    QueriesConfirmation(queries: queries, model: model, pending: pending)
                case .unknown(let kind):
                    ContentUnavailableView(
                        "Unknown confirmation",
                        systemImage: "questionmark.diamond",
                        description: Text("Type “\(kind)” is not supported by this version of the app.")
                    )
                }
            }
            .safeAreaInset(edge: .top, spacing: 0) {
                if model.isSimulation { SimulationBanner() }
            }
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Later") { dismiss() }
                }
            }
            .overlay {
                if model.sending { ProgressView().controlSize(.large) }
            }
            .alert("Action refused", isPresented: .constant(model.actionError != nil)) {
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
                Text("Decline and stop the mission").frame(maxWidth: .infinity)
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
                Text("Proposed plan")
            } footer: {
                Text("The plan is fixed before anything is read on the web. Steps marked “you” will wait for this phone.")
            }
        }
        .navigationTitle("Approve the plan")
        .safeAreaInset(edge: .bottom) {
            DecisionButtons(acceptTitle: "Approve the plan", canAccept: true, model: model, pending: pending) {
                await model.acceptPlan(pending)
            }
        }
    }
}

// MARK: - Research queries

/// The searches a research wants to send, before anything leaves. Accepted as shown; editing is done on the computer.
private struct QueriesConfirmation: View {
    let queries: [String]
    let model: RemoteModel
    let pending: Pending

    var body: some View {
        List {
            Section {
                ForEach(Array(queries.enumerated()), id: \.offset) { _, query in
                    Label(query, systemImage: "magnifyingglass").textSelection(.enabled)
                }
            } header: {
                Text("Proposed searches")
            } footer: {
                Text("They will go over Tor to a search engine, exactly as written. To change them, do it on the computer.")
            }
        }
        .navigationTitle("Approve the searches")
        .safeAreaInset(edge: .bottom) {
            DecisionButtons(acceptTitle: "Run these searches", canAccept: !queries.isEmpty, model: model, pending: pending) {
                await model.acceptQueries(pending)
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
                Text("Offers found")
            } footer: {
                Text("Only the chosen firm will be contacted. The quoted excerpts come from the pages read.")
            }
        }
        .navigationTitle("Choose the recipient")
        .safeAreaInset(edge: .bottom) {
            DecisionButtons(
                acceptTitle: selected.map { "Choose \($0)" } ?? "Choose an offer",
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
                Text("\(Format.euros(cents: offer.priceCents)) · within \(Format.days(offer.delayDays))")
                ForEach(offer.sourceSpans, id: \.self) { span in
                    Text("“\(span)”").font(.caption).foregroundStyle(.secondary)
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
                    LabeledContent("Amount") {
                        Text("\(NEARAmount.format(verified.amount)) NEAR").font(.title3.bold())
                    }
                    LabeledContent("Recipient") {
                        Text(verified.to).font(.body.monospaced())
                    }
                    Label("Checked by this phone", systemImage: "checkmark.seal.fill")
                        .foregroundStyle(.green)
                } header: {
                    Text("Payment prepared by the computer")
                } footer: {
                    Text("This phone checked that the amount and recipient shown are the ones the computer will pay.")
                }
                Section {
                    DisclosureGroup("Technical details") {
                        Text(request.screen).font(.caption.monospaced())
                        LabeledContent("Digest", value: String(verified.digest.prefix(16)) + "…")
                            .font(.caption.monospaced())
                    }
                }
            case .failure(let failure):
                Section {
                    Label(message(for: failure), systemImage: "xmark.octagon.fill")
                        .foregroundStyle(.red)
                } header: {
                    Text("Inconsistent payment")
                } footer: {
                    Text("This payment cannot be confirmed. Decline it and check the computer.")
                }
            }
        }
        .navigationTitle("Confirm the payment")
        .safeAreaInset(edge: .bottom) {
            DecisionButtons(
                acceptTitle: "Confirm the payment",
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
        case .unsupportedVersion: "Unknown payment version: update ONA on both devices"
        case .missingField: "The payment is incomplete"
        case .badAccount: "The recipient is not a valid NEAR account"
        case .badAmount: "Unreadable amount"
        case .digestMismatch: "The digest does not match the payment"
        case .screenMismatch: "The text shown does not match the payment"
        }
    }
}
