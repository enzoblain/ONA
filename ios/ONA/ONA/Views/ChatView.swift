import SwiftUI

/// One conversation with the agent: the person's messages, the agent's replies, what the agent is doing, the
/// confirmations it asks for. Text only (no photos, no files).
struct ChatView: View {
    @Bindable var model: RemoteModel
    /// Nil for a new conversation, until its first message is sent.
    @State var chatID: String?
    @State private var draft = ""
    @State private var openConfirmation: Pending?
    @State private var confirmingDelete = false
    @FocusState private var composerFocused: Bool
    @Environment(\.dismiss) private var dismiss

    init(model: RemoteModel, chatID: String?) {
        self.model = model
        _chatID = State(initialValue: chatID)
    }

    /// The conversation, once the computer has sent it.
    private var chat: ChatDetail? {
        guard let chatID, model.openChat?.id == chatID else { return nil }
        return model.openChat
    }

    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 18) {
                if chatID == nil {
                    Greeting()
                } else if let chat {
                    ForEach(blocks(of: chat)) { block in
                        block.view(open: { openConfirmation = $0 })
                    }
                    if chat.status == .working {
                        WorkingLine(text: chat.working?.text ?? "The agent is thinking…")
                            .id("working")
                    }
                } else {
                    ProgressView().frame(maxWidth: .infinity).padding(.top, 40)
                }
            }
            .padding(.horizontal)
            .padding(.top, 12)
            .padding(.bottom, 8)
        }
        .defaultScrollAnchor(.bottom)
        .scrollDismissesKeyboard(.interactively)
        .safeAreaInset(edge: .top, spacing: 0) {
            if model.isSimulation { SimulationBanner() }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            Composer(text: $draft, focused: $composerFocused, busy: model.sending, send: send)
        }
        .navigationTitle(chat?.title ?? (chatID == nil ? "New conversation" : ""))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar(.hidden, for: .tabBar)
        .toolbar {
            if chatID != nil {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Button("Delete conversation", systemImage: "trash", role: .destructive) {
                            confirmingDelete = true
                        }
                    } label: {
                        Label("Options", systemImage: "ellipsis")
                    }
                }
            }
        }
        .task(id: chatID) {
            if let chatID { await model.open(chat: chatID) }
        }
        .onAppear { if chatID == nil { composerFocused = true } }
        .onDisappear { model.closeChat() }
        .sheet(item: $openConfirmation) { pending in
            ConfirmationView(model: model, pending: pending)
        }
        // A confirmation that is no longer pending (answered, or replaced) closes its sheet.
        .onChange(of: chat?.pending?.id) { _, new in
            if let open = openConfirmation, open.id != new { openConfirmation = nil }
        }
        .alert("Delete this conversation?", isPresented: $confirmingDelete) {
            Button("Cancel", role: .cancel) {}
            Button("Delete", role: .destructive) {
                guard let chatID else { return }
                Task {
                    await model.delete(chat: chatID)
                    dismiss()
                }
            }
        } message: {
            Text("It will be deleted from your computer.")
        }
        .alert("Action not possible", isPresented: .constant(model.actionError != nil && openConfirmation == nil)) {
            Button("OK") { model.clearActionError() }
        } message: {
            Text(model.actionError ?? "")
        }
    }

    private func send() {
        let text = draft
        Task {
            if let chatID {
                if await model.send(text, in: chatID) { draft = "" }
            } else if let id = await model.startChat(text) {
                draft = ""
                chatID = id
            }
        }
    }
}

// MARK: - Blocks

/// Consecutive activities are shown together, like the steps of a coding agent.
private enum Block: Identifiable {
    case item(ChatItem)
    case activities([ChatItem])

    var id: String {
        switch self {
        case .item(let item): item.id
        case .activities(let items): "group-" + (items.first?.id ?? "")
        }
    }

    @MainActor @ViewBuilder
    func view(open: @escaping (Pending) -> Void) -> some View {
        switch self {
        case .activities(let items): ActivityGroup(items: items)
        case .item(let item): ItemView(item: item, open: open)
        }
    }
}

private func blocks(of chat: ChatDetail) -> [Block] {
    var out: [Block] = []
    var run: [ChatItem] = []
    for item in chat.items {
        if case .activity = item.content {
            run.append(item)
            continue
        }
        if !run.isEmpty { out.append(.activities(run)); run = [] }
        out.append(.item(item))
    }
    if !run.isEmpty { out.append(.activities(run)) }
    return out
}

private struct ItemView: View {
    let item: ChatItem
    let open: (Pending) -> Void

    var body: some View {
        switch item.content {
        case .user(let text):
            HStack {
                Spacer(minLength: 56)
                Text(text)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 10)
                    .background(.fill.tertiary, in: .rect(cornerRadius: 20))
                    .textSelection(.enabled)
            }
        case .agent(let text):
            Text(text)
                .frame(maxWidth: .infinity, alignment: .leading)
                .textSelection(.enabled)
        case .activity(let tool, let text):
            ActivityRow(tool: tool, text: text)
        case .confirmation(let pending, let state):
            ConfirmationCard(pending: pending, state: state, open: open)
        case .exposure(let exposure):
            ExposureCard(exposure: exposure)
        case .answer(let answer):
            AnswerCard(answer: answer)
        case .action(let action, let done):
            ActionCard(action: action, done: done)
        case .unknown:
            EmptyView()
        }
    }
}

// MARK: - Pieces

private struct Greeting: View {
    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "sparkles")
                .font(.system(size: 40))
                .foregroundStyle(.tint)
            Text("What can I do for you?")
                .font(.title2.weight(.semibold))
            Text("The agent works on your computer. It will ask for your approval before contacting anyone or paying.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.top, 80)
        .padding(.horizontal, 24)
    }
}

private struct ActivityGroup: View {
    let items: [ChatItem]
    @State private var expanded = true

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Button {
                withAnimation(.snappy) { expanded.toggle() }
            } label: {
                HStack(spacing: 6) {
                    Text(items.count == 1 ? "1 step" : "\(items.count) steps")
                    Image(systemName: "chevron.right")
                        .rotationEffect(.degrees(expanded ? 90 : 0))
                }
                .font(.caption.weight(.medium))
                .foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
            if expanded {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(items) { item in
                        if case .activity(let tool, let text) = item.content {
                            ActivityRow(tool: tool, text: text)
                        }
                    }
                }
                .padding(.leading, 2)
            }
        }
    }
}

private struct ActivityRow: View {
    let tool: String
    let text: String

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: Self.symbol(tool))
                .frame(width: 18)
                .foregroundStyle(.secondary)
            Text(text)
                .foregroundStyle(.secondary)
            Spacer(minLength: 0)
            Image(systemName: "checkmark")
                .font(.caption2.weight(.bold))
                .foregroundStyle(.green)
        }
        .font(.subheadline)
    }

    static func symbol(_ tool: String) -> String {
        tool == "think" ? "sparkles" : Step(raw: tool).symbol
    }
}

private struct WorkingLine: View {
    let text: String

    var body: some View {
        HStack(spacing: 10) {
            ProgressView().controlSize(.small)
            Text(text)
                .font(.subheadline)
                .foregroundStyle(.secondary)
        }
        // The label changes in place: no cross-fade between the old and the new step.
        .transaction { $0.animation = nil }
    }
}

private struct ConfirmationCard: View {
    let pending: Pending
    let state: ChatItem.ConfirmationState
    let open: (Pending) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(title, systemImage: symbol)
                .font(.headline)
            Text(detail)
                .font(.subheadline)
                .foregroundStyle(.secondary)
            switch state {
            case .pending:
                Button {
                    open(pending)
                } label: {
                    Text(action).frame(maxWidth: .infinity)
                }
                .buttonStyle(.glassProminent)
                .controlSize(.large)
                .accessibilityIdentifier("open-confirmation")
            case .accepted:
                Label("Confirmed", systemImage: "checkmark.circle.fill").foregroundStyle(.green).font(.subheadline)
            case .rejected:
                Label("Declined", systemImage: "xmark.circle.fill").foregroundStyle(.red).font(.subheadline)
            case .expired:
                Label("No longer current", systemImage: "clock").foregroundStyle(.secondary).font(.subheadline)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassEffect(.regular, in: .rect(cornerRadius: 24))
    }

    private var title: String {
        switch pending.request {
        case .plan: "Approve the plan"
        case .recipient: "Choose the recipient"
        case .payment: "Confirm the payment"
        case .queries: "Approve the searches"
        case .unknown: "Confirmation"
        }
    }

    private var symbol: String {
        switch pending.request {
        case .plan: "list.bullet.clipboard"
        case .recipient: "person.crop.circle.badge.checkmark"
        case .payment: "creditcard"
        case .queries: "magnifyingglass"
        case .unknown: "hand.raised"
        }
    }

    private var detail: String {
        switch pending.request {
        case .plan(let steps): "\(steps.count) steps, fixed before anything is read on the web."
        case .recipient(let offers): "\(offers.count) offers found. Only the one you choose will be contacted."
        case .payment(let payment):
            // Only a payment the phone verified shows its account (F-14: no look-alike names).
            switch PaymentCheck.verify(payment) {
            case .success(let verified): "\(NEARAmount.format(verified.amount)) NEAR to \(verified.to)"
            case .failure: "Inconsistent payment: decline it."
            }
        case .queries(let queries): "\(queries.count) search\(queries.count > 1 ? "es" : "") to send over Tor. Nothing has been sent yet."
        case .unknown: "This version of the app cannot display it."
        }
    }

    private var action: String {
        switch pending.request {
        case .plan: "View the plan"
        case .recipient: "View the offers"
        case .payment: "Check the payment"
        case .queries: "View the searches"
        case .unknown: "Open"
        }
    }
}

private struct ExposureCard: View {
    let exposure: Exposure

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Exposure report", systemImage: "eye")
                .font(.headline)
            Text("What left your computer during the mission.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
            Divider()
            ExposureView(exposure: exposure)
                .font(.subheadline)
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.fill.quaternary, in: .rect(cornerRadius: 24))
    }
}

/// Text field and send button floating on Liquid Glass at the bottom.
private struct Composer: View {
    @Binding var text: String
    var focused: FocusState<Bool>.Binding
    let busy: Bool
    let send: () -> Void

    private var canSend: Bool {
        !busy && !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && text.count <= RemoteModel.maxMessageLength
    }

    var body: some View {
        GlassEffectContainer(spacing: 10) {
            HStack(alignment: .bottom, spacing: 10) {
                TextField("Ask the agent…", text: $text, axis: .vertical)
                    .lineLimit(1...6)
                    .focused(focused)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.sentences)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 12)
                    .glassEffect(.regular.interactive(), in: .rect(cornerRadius: 24))
                    .accessibilityIdentifier("composer")
                Button(action: send) {
                    Group {
                        if busy {
                            ProgressView()
                        } else {
                            Image(systemName: "arrow.up").font(.body.weight(.semibold))
                        }
                    }
                    .frame(width: 30, height: 30)
                }
                .buttonStyle(.glassProminent)
                .buttonBorderShape(.circle)
                .disabled(!canSend)
                .accessibilityLabel("Send")
                .accessibilityIdentifier("send")
            }
        }
        .padding(.horizontal)
        .padding(.vertical, 8)
    }
}

// MARK: - Free research

/// The answer of a research, with the notes it relies on and the pages they come from (docs/research.md).
struct AnswerCard: View {
    let answer: ResearchAnswer

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(answer.text).textSelection(.enabled)
            if !answer.notes.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(Array(answer.notes.enumerated()), id: \.offset) { _, note in
                        VStack(alignment: .leading, spacing: 2) {
                            Text("“\(note.quote)”").font(.footnote).italic()
                            Text("\(note.source) · \(source(note.source)?.title ?? "")").font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            }
            if !answer.sources.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Sources").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                    ForEach(answer.sources, id: \.handle) { s in
                        // Shown as text, never opened from here: the phone does not visit the pages.
                        Text("\(s.handle) · \(s.title)\n\(s.url)").font(.caption).textSelection(.enabled)
                    }
                }
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassEffect(.regular, in: .rect(cornerRadius: 24))
    }

    private func source(_ handle: String) -> ResearchAnswer.Source? {
        answer.sources.first { $0.handle == handle }
    }
}

/// An action the answer suggests. Its recipient is given and confirmed on the computer only.
struct ActionCard: View {
    let action: SuggestedAction
    let done: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(action.purpose, systemImage: action.kind == "payment" ? "creditcard" : "envelope")
                .font(.headline)
            if let text = action.text {
                Text(text).font(.footnote).textSelection(.enabled)
            }
            if let amount = action.amount {
                Text("\(NEARAmount.text(amount) ?? "unreadable amount") NEAR").monospacedDigit()
            }
            if done {
                Label("Done on the computer", systemImage: "checkmark.circle.fill").foregroundStyle(.green).font(.subheadline)
            } else {
                Text("To do on the computer: you give the recipient there and confirm the exact action.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassEffect(.regular, in: .rect(cornerRadius: 24))
    }
}
