import SwiftUI

/// "Home" tab once paired: every conversation with the agent, newest first, like the Claude or ChatGPT apps.
struct ChatListView: View {
    @Bindable var model: RemoteModel
    @State private var path: [Route] = []
    @State private var chatToDelete: ChatSummary?

    enum Route: Hashable {
        case chat(String)
        case newChat
    }

    var body: some View {
        NavigationStack(path: $path) {
            content
                .navigationTitle("Conversations")
                .toolbar {
                    ToolbarItem(placement: .topBarTrailing) {
                        Button {
                            path.append(.newChat)
                        } label: {
                            Label("New conversation", systemImage: "plus")
                        }
                        .accessibilityIdentifier("new-chat")
                    }
                }
                .navigationDestination(for: Route.self) { route in
                    switch route {
                    case .chat(let id): ChatView(model: model, chatID: id)
                    case .newChat: ChatView(model: model, chatID: nil)
                    }
                }
                .safeAreaInset(edge: .top, spacing: 0) {
                    if model.isSimulation { SimulationBanner() }
                }
                .refreshable { await model.refresh() }
        }
        .alert(
            "Delete this conversation?",
            isPresented: Binding(get: { chatToDelete != nil }, set: { if !$0 { chatToDelete = nil } }),
            presenting: chatToDelete
        ) { chat in
            Button("Cancel", role: .cancel) {}
            Button("Delete", role: .destructive) {
                Task { await model.delete(chat: chat.id) }
            }
        } message: { chat in
            Text("“\(chat.title)” will be deleted from your computer.")
        }
    }

    @ViewBuilder
    private var content: some View {
        if model.chats.isEmpty {
            emptyState
        } else {
            List {
                if case .failed = model.connection {
                    ConnectionStatusRow(connection: model.connection, computer: model.pairing?.name, viaTor: model.usesTor)
                    if model.pairingLost { RescanButton(model: model) }
                }
                ForEach(model.chats) { chat in
                    NavigationLink(value: Route.chat(chat.id)) {
                        ChatRow(chat: chat)
                    }
                    .swipeActions(edge: .trailing) {
                        Button(role: .destructive) {
                            chatToDelete = chat
                        } label: {
                            Label("Supprimer", systemImage: "trash")
                        }
                    }
                    .contextMenu {
                        Button(role: .destructive) {
                            chatToDelete = chat
                        } label: {
                            Label("Supprimer", systemImage: "trash")
                        }
                    }
                }
            }
            .listStyle(.plain)
        }
    }

    @ViewBuilder
    private var emptyState: some View {
        if !model.chatsLoaded {
            VStack(spacing: 16) {
                Spacer()
                ConnectionStatusRow(connection: model.connection, computer: model.pairing?.name, viaTor: model.usesTor)
                    .padding(.horizontal)
                if model.pairingLost {
                    RescanButton(model: model)
                        .buttonStyle(.borderedProminent)
                }
                Spacer()
            }
        } else {
            ContentUnavailableView {
                Label("No conversations", systemImage: "bubble.left.and.text.bubble.right")
            } description: {
                Text("Ask the agent to do something on your computer. You will follow each step here and confirm the important choices.")
            } actions: {
                Button("New conversation") { path.append(.newChat) }
                    .buttonStyle(.glassProminent)
            }
        }
    }
}

private struct ChatRow: View {
    let chat: ChatSummary

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                HStack(alignment: .firstTextBaseline) {
                    Text(chat.title)
                        .font(.headline)
                        .lineLimit(1)
                    Spacer(minLength: 8)
                    Text(chat.updated, format: .relative(presentation: .named))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                HStack(spacing: 6) {
                    switch chat.status {
                    case .waiting:
                        Image(systemName: "hand.raised.fill").foregroundStyle(.orange)
                        Text("Confirmation needed").foregroundStyle(.orange)
                    case .working:
                        ProgressView().controlSize(.mini)
                        Text("The agent is working…").foregroundStyle(.secondary)
                    case .idle:
                        Text(chat.preview).foregroundStyle(.secondary)
                    }
                }
                .font(.subheadline)
                .lineLimit(2)
            }
        }
        .padding(.vertical, 4)
    }
}

/// Shown when the computer no longer knows this phone: back to the pairing screen.
struct RescanButton: View {
    let model: RemoteModel

    var body: some View {
        Button {
            model.rescan()
        } label: {
            Label("Rescan the computer's code", systemImage: "qrcode.viewfinder")
        }
        .accessibilityIdentifier("rescan")
    }
}
