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
                        WorkingLine(text: chat.working?.text ?? "L'agent réfléchit…")
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
        .navigationTitle(chat?.title ?? (chatID == nil ? "Nouvelle conversation" : ""))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar(.hidden, for: .tabBar)
        .toolbar {
            if chatID != nil {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Button("Supprimer la conversation", systemImage: "trash", role: .destructive) {
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
        .alert("Supprimer la conversation ?", isPresented: $confirmingDelete) {
            Button("Annuler", role: .cancel) {}
            Button("Supprimer", role: .destructive) {
                guard let chatID else { return }
                Task {
                    await model.delete(chat: chatID)
                    dismiss()
                }
            }
        } message: {
            Text("Elle sera supprimée de votre ordinateur.")
        }
        .alert("Action impossible", isPresented: .constant(model.actionError != nil && openConfirmation == nil)) {
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
            Text("Que dois-je faire pour vous ?")
                .font(.title2.weight(.semibold))
            Text("L'agent travaille sur votre ordinateur. Il vous demandera votre accord avant de contacter quelqu'un ou de payer.")
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
                    Text(items.count == 1 ? "1 étape" : "\(items.count) étapes")
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
                Label("Confirmé", systemImage: "checkmark.circle.fill").foregroundStyle(.green).font(.subheadline)
            case .rejected:
                Label("Refusé", systemImage: "xmark.circle.fill").foregroundStyle(.red).font(.subheadline)
            case .expired:
                Label("Plus d'actualité", systemImage: "clock").foregroundStyle(.secondary).font(.subheadline)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassEffect(.regular, in: .rect(cornerRadius: 24))
    }

    private var title: String {
        switch pending.request {
        case .plan: "Valider le plan"
        case .recipient: "Choisir le destinataire"
        case .payment: "Confirmer le paiement"
        case .unknown: "Confirmation"
        }
    }

    private var symbol: String {
        switch pending.request {
        case .plan: "list.bullet.clipboard"
        case .recipient: "person.crop.circle.badge.checkmark"
        case .payment: "creditcard"
        case .unknown: "hand.raised"
        }
    }

    private var detail: String {
        switch pending.request {
        case .plan(let steps): "\(steps.count) étapes, figées avant toute lecture du web."
        case .recipient(let offers): "\(offers.count) offres trouvées. Seule celle choisie sera contactée."
        case .payment(let payment):
            UInt128(payment.amount, radix: 10).map { "\(NEARAmount.format($0)) NEAR à \(payment.to)" } ?? payment.to
        case .unknown: "Cette version de l'app ne sait pas l'afficher."
        }
    }

    private var action: String {
        switch pending.request {
        case .plan: "Voir le plan"
        case .recipient: "Voir les offres"
        case .payment: "Vérifier le paiement"
        case .unknown: "Ouvrir"
        }
    }
}

private struct ExposureCard: View {
    let exposure: Exposure

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Relevé d'exposition", systemImage: "eye")
                .font(.headline)
            Text("Ce qui est sorti de votre ordinateur pendant la mission.")
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
                TextField("Demandez à l'agent…", text: $text, axis: .vertical)
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
                .accessibilityLabel("Envoyer")
                .accessibilityIdentifier("send")
            }
        }
        .padding(.horizontal)
        .padding(.vertical, 8)
    }
}
