import SwiftUI

/// A conversation on the Mac: the same content as on the phone, and the confirmations can be answered here too.
struct ChatPane: View {
    let model: DesktopModel
    let chat: Chat
    @State private var draft = ""
    @State private var error: String?

    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 18) {
                ForEach(chat.items) { item in
                    ItemView(item: item, chat: chat, engine: model.engine, error: $error)
                }
                if let working = chat.working {
                    HStack(spacing: 8) {
                        ProgressView().controlSize(.small)
                        Text(working.text).foregroundStyle(.secondary)
                    }
                    .transaction { $0.animation = nil }
                }
            }
            .padding(24)
            .frame(maxWidth: 760)
            .frame(maxWidth: .infinity)
        }
        .defaultScrollAnchor(.bottom)
        .safeAreaInset(edge: .bottom) {
            Composer(text: $draft) {
                if let failure = model.engine.post(draft, to: chat.id) {
                    error = failure.rawValue
                } else {
                    draft = ""
                }
            }
        }
        .safeAreaInset(edge: .top, spacing: 0) {
            if model.engine.mode != "real" { SimulationBanner() }
        }
        .navigationTitle(chat.title)
        .alert("Cannot do this", isPresented: Binding(get: { error != nil }, set: { if !$0 { error = nil } })) {
            Button("OK") { error = nil }
        } message: {
            Text(error ?? "")
        }
    }
}

/// Start a conversation from the Mac.
struct NewChatPane: View {
    let model: DesktopModel
    let created: (String) -> Void
    @State private var draft = ""

    var body: some View {
        VStack(spacing: 14) {
            Spacer()
            Image(systemName: "sparkles").font(.system(size: 44)).foregroundStyle(.tint)
            Text("What can I do for you?").font(.title.weight(.semibold))
            Text("Ask a question: once you approve its searches, the agent searches the web through Tor and answers with its sources. If it suggests a message or a payment, you are the one who makes it, on this computer.")
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 460)
            Spacer()
        }
        .frame(maxWidth: .infinity)
        .safeAreaInset(edge: .bottom) {
            Composer(text: $draft) {
                if case .success(let chat) = model.engine.create(draft) {
                    draft = ""
                    created(chat.id)
                }
            }
        }
        .safeAreaInset(edge: .top, spacing: 0) {
            if model.engine.mode != "real" { SimulationBanner() }
        }
        .navigationTitle("New conversation")
    }
}

struct SimulationBanner: View {
    var body: some View {
        Label("Simulation — fake model, web and payments (ona-core in mock mode)", systemImage: "theatermasks")
            .font(.callout.weight(.semibold))
            .foregroundStyle(.black)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 5)
            .background(.yellow)
    }
}

private struct Composer: View {
    @Binding var text: String
    let send: () -> Void

    private var canSend: Bool {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return !trimmed.isEmpty && trimmed.count <= ChatEngine.maxText
    }

    var body: some View {
        GlassEffectContainer(spacing: 10) {
            HStack(alignment: .bottom, spacing: 10) {
                TextField("Ask the agent…", text: $text, axis: .vertical)
                    .textFieldStyle(.plain)
                    .lineLimit(1...8)
                    .onSubmit { if canSend { send() } }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 12)
                    .glassEffect(.regular.interactive(), in: .rect(cornerRadius: 22))
                Button(action: send) {
                    Image(systemName: "arrow.up").font(.body.weight(.semibold)).frame(width: 22, height: 22)
                }
                .buttonStyle(.glassProminent)
                .buttonBorderShape(.circle)
                .controlSize(.large)
                .disabled(!canSend)
                .keyboardShortcut(.return, modifiers: .command)
            }
        }
        .frame(maxWidth: 760)
        .padding(16)
        .frame(maxWidth: .infinity)
    }
}

// MARK: - Items

private struct ItemView: View {
    let item: ChatItem
    let chat: Chat
    let engine: ChatEngine
    @Binding var error: String?

    var body: some View {
        switch item.content {
        case .user(let text):
            HStack {
                Spacer(minLength: 120)
                Text(text)
                    .textSelection(.enabled)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 10)
                    .background(.fill.tertiary, in: .rect(cornerRadius: 18))
            }
        case .agent(let text):
            Text(text).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
        case .activity(let tool, let text):
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Image(systemName: Self.symbol(tool)).frame(width: 18).foregroundStyle(.secondary)
                Text(text).foregroundStyle(.secondary)
                Spacer()
                Image(systemName: "checkmark").font(.caption.bold()).foregroundStyle(.green)
            }
        case .confirmation(let pending):
            ConfirmationCard(pending: pending, state: chat.state(of: pending)) { decision, firm, digest, queries in
                if let failure = engine.confirm(id: pending.id, decision: decision, firm: firm, digest: digest,
                                                queries: queries) {
                    error = failure
                }
            }
        case .exposure(let data):
            ExposureCard(data: data)
        case .answer(let answer):
            AnswerCard(answer: answer)
        case .action(let action):
            ActionCard(itemID: item.id, action: action, chat: chat, engine: engine, error: $error)
        }
    }

    static func symbol(_ tool: String) -> String {
        switch tool {
        case "think": "sparkles"
        case "search": "magnifyingglass"
        case "read": "doc.text"
        case "compare": "list.number"
        case "contact": "envelope"
        case "prepare_payment": "doc.badge.gearshape"
        case "pay": "creditcard"
        default: "circle"
        }
    }
}

private struct ConfirmationCard: View {
    let pending: Pending
    let state: ConfirmationState
    let answer: (_ decision: String, _ firm: String?, _ digest: String?, _ queries: [String]?) -> Void
    @State private var firm: String?
    /// The queries as edited here.
    @State private var edited: [String] = []

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(title, systemImage: symbol).font(.headline)
            switch pending.request {
            case .plan(let steps):
                Text(steps.enumerated().map { "\($0.offset + 1). \(Self.stepLabel($0.element))" }.joined(separator: "\n"))
                    .foregroundStyle(.secondary)
            case .recipient(let offers):
                Picker("Offer", selection: $firm) {
                    ForEach(offers) { offer in
                        Text("\(offer.firmID) — €\(offer.priceCents / 100), within \(offer.delayDays) days")
                            .tag(Optional(offer.firmID))
                    }
                }
                .pickerStyle(.radioGroup)
                .disabled(state != .pending)
            case .payment(let to, let amount, let screen, _, _):
                LabeledContent("Amount", value: Self.near(amount))
                LabeledContent("Recipient", value: to)
                Text(screen).font(.caption.monospaced()).foregroundStyle(.secondary)
            case .queries(let queries):
                QueriesEditor(queries: queries, editable: state == .pending, edited: $edited)
            }
            switch state {
            case .pending:
                HStack {
                    Button(acceptTitle) {
                        switch pending.request {
                        case .plan: answer("accept", nil, nil, nil)
                        case .recipient: answer("accept", firm, nil, nil)
                        case .payment(_, _, _, let digest, _): answer("accept", nil, digest, nil)
                        case .queries: answer("accept", nil, nil, edited)
                        }
                    }
                    .buttonStyle(.glassProminent)
                    .disabled(isRecipient && firm == nil)
                    Button("Refuse", role: .destructive) { answer("reject", nil, nil, nil) }
                        .buttonStyle(.glass)
                    Spacer()
                    Text("or on the phone").font(.caption).foregroundStyle(.secondary)
                }
            case .accepted: Label("Confirmed", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
            case .rejected: Label("Refused", systemImage: "xmark.circle.fill").foregroundStyle(.red)
            case .expired: Label("No longer relevant", systemImage: "clock").foregroundStyle(.secondary)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassEffect(.regular, in: .rect(cornerRadius: 20))
    }

    private var isRecipient: Bool {
        if case .recipient = pending.request { return true }
        return false
    }

    private var title: String {
        switch pending.request {
        case .plan: "Approve the plan"
        case .recipient: "Choose the recipient"
        case .payment: "Confirm the payment"
        case .queries: "Approve the searches"
        }
    }

    private var symbol: String {
        switch pending.request {
        case .plan: "list.bullet.clipboard"
        case .recipient: "person.crop.circle.badge.checkmark"
        case .payment: "creditcard"
        case .queries: "magnifyingglass"
        }
    }

    private var acceptTitle: String {
        switch pending.request {
        case .plan: "Approve the plan"
        case .recipient: "Contact this firm"
        case .payment: "Confirm the payment"
        case .queries: "Run the searches"
        }
    }

    static func stepLabel(_ step: String) -> String {
        switch step {
        case "search": "Search"
        case "read": "Read a page"
        case "compare": "Compare the offers"
        case "confirm_recipient": "Choose the recipient (you)"
        case "contact": "Contact the firm"
        case "prepare_payment": "Prepare the payment"
        case "confirm_payment": "Confirm the payment (you)"
        case "pay": "Pay"
        default: step
        }
    }

    /// yoctoNEAR (decimal string) as NEAR, exact.
    static func near(_ yocto: String) -> String {
        let digits = yocto.count > 24 ? yocto : String(repeating: "0", count: 25 - yocto.count) + yocto
        let whole = String(digits.dropLast(24)), fraction = String(digits.suffix(24))
        let trimmed = fraction.replacingOccurrences(of: "0+$", with: "", options: .regularExpression)
        return (trimmed.isEmpty ? whole : "\(whole).\(trimmed)") + " NEAR"
    }
}

private struct ExposureCard: View {
    let data: Data

    var body: some View {
        let report = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
        let outputs = report["outputs"] as? [String: Int] ?? [:]
        let payments = report["payments"] as? [[String: String]] ?? []
        VStack(alignment: .leading, spacing: 8) {
            Label("Exposure report", systemImage: "eye").font(.headline)
            Text("What left this computer during the mission.").foregroundStyle(.secondary)
            Divider()
            LabeledContent("Model calls", value: "\(report["model_calls"] as? Int ?? 0)")
            ForEach(outputs.sorted(by: { $0.key < $1.key }), id: \.key) { name, count in
                LabeledContent(Self.label(name), value: "\(count)")
            }
            if let firms = report["firms_contacted"] as? [String], !firms.isEmpty {
                LabeledContent("Firms contacted", value: firms.joined(separator: ", "))
            }
            ForEach(Array(payments.enumerated()), id: \.offset) { _, payment in
                LabeledContent("Payment", value: "\(ConfirmationCard.near(payment["amount"] ?? "0")) → \(payment["to"] ?? "?")")
            }
            if (report["mode"] as? String) != "real" {
                Label("Report of a simulation", systemImage: "theatermasks").font(.caption).foregroundStyle(.orange)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.fill.quaternary, in: .rect(cornerRadius: 20))
    }

    static func label(_ name: String) -> String {
        switch name {
        case "search": "Searches sent"
        case "fetch": "Pages read"
        case "contact": "Messages sent"
        case "message": "Messages handed to your mail app"
        default: name
        }
    }
}

