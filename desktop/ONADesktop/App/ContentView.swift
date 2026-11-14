import SwiftUI

struct ContentView: View {
    @Bindable var model: DesktopModel
    @State private var selection: Selection? = .newChat
    @State private var showingPhone = false
    @State private var showingPool = false
    @State private var chatToDelete: Chat?

    enum Selection: Hashable {
        case newChat
        case chat(String)
    }

    var body: some View {
        NavigationSplitView {
            sidebar
                .navigationSplitViewColumnWidth(min: 240, ideal: 280)
        } detail: {
            detail
        }
        .toolbar {
            ToolbarItem(placement: .navigation) {
                Button {
                    selection = .newChat
                } label: {
                    Label("New conversation", systemImage: "square.and.pencil")
                }
                .keyboardShortcut("n")
            }
            ToolbarItem(placement: .primaryAction) {
                Button {
                    showingPool = true
                } label: {
                    Label("Pool", systemImage: "building.columns")
                }
                .help("The pool: holdings and operations, confirmed on this Mac")
            }
            ToolbarItem(placement: .primaryAction) {
                Button {
                    showingPhone = true
                } label: {
                    Label(phoneLabel, systemImage: phoneSymbol)
                }
                .help("Pair or manage the phone")
            }
        }
        .sheet(isPresented: $showingPhone) {
            PhoneSheet(model: model)
        }
        .sheet(isPresented: $showingPool) {
            PoolSheet(engine: model.engine, wallet: model.wallet)
        }
        // A phone that just paired: the codes must be compared now.
        .onChange(of: model.pairing.awaiting) { _, awaiting in
            if awaiting != nil { showingPhone = true }
        }
        .alert("Delete the conversation?", isPresented: Binding(
            get: { chatToDelete != nil }, set: { if !$0 { chatToDelete = nil } }
        ), presenting: chatToDelete) { chat in
            Button("Cancel", role: .cancel) {}
            Button("Delete", role: .destructive) {
                _ = model.engine.delete(chat.id)
                if selection == .chat(chat.id) { selection = .newChat }
            }
        } message: { chat in
            Text("“\(chat.title)” will be deleted from this computer.")
        }
    }

    private var sidebar: some View {
        List(selection: $selection) {
            Section("Conversations") {
                ForEach(model.engine.sorted) { chat in
                    ChatRow(chat: chat)
                        .tag(Selection.chat(chat.id))
                        .contextMenu {
                            Button("Delete", systemImage: "trash", role: .destructive) { chatToDelete = chat }
                        }
                }
                if model.engine.chats.isEmpty {
                    Text("No conversations").foregroundStyle(.secondary)
                }
            }
        }
        .safeAreaInset(edge: .bottom) {
            StatusFooter(model: model)
        }
    }

    @ViewBuilder
    private var detail: some View {
        switch selection {
        case .chat(let id):
            if let chat = model.engine.chat(id) {
                ChatPane(model: model, chat: chat)
            } else {
                NewChatPane(model: model) { selection = .chat($0) }
            }
        case .newChat, nil:
            NewChatPane(model: model) { selection = .chat($0) }
        }
    }

    private var phoneLabel: String {
        if model.pairing.awaiting != nil { return "Code to check" }
        return model.pairing.isPaired ? "Phone paired" : "Pair a phone"
    }

    private var phoneSymbol: String {
        model.pairing.isPaired ? "iphone.gen3.circle.fill" : "iphone.gen3.badge.plus"
    }
}

private struct ChatRow: View {
    let chat: Chat

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(chat.title).lineLimit(1)
            HStack(spacing: 4) {
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
            .font(.caption)
            .lineLimit(1)
        }
        .padding(.vertical, 2)
    }
}

/// Phone and Tor at a glance, under the sidebar.
private struct StatusFooter: View {
    let model: DesktopModel

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label(model.pairing.isPaired ? "Phone paired" : "No phone",
                  systemImage: model.pairing.isPaired ? "iphone.gen3" : "iphone.gen3.slash")
                .foregroundStyle(model.pairing.isPaired ? .primary : .secondary)
            if model.mode == .tor {
                TorStatusLabel(state: model.tor.state)
            } else {
                Label("Local network (testing)", systemImage: "wifi").foregroundStyle(.orange)
            }
            if let error = model.serverError {
                Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.red)
            }
            if let error = model.backupError {
                Label(error, systemImage: "externaldrive.badge.exclamationmark").foregroundStyle(.orange)
            }
        }
        .font(.caption)
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
    }
}

struct TorStatusLabel: View {
    let state: TorService.State

    var body: some View {
        switch state {
        case .off: Label("Tor stopped", systemImage: "pause.circle").foregroundStyle(.secondary)
        case .missing: Label("Tor is not installed", systemImage: "exclamationmark.triangle").foregroundStyle(.orange)
        case .starting: Label("Tor is starting…", systemImage: "arrow.triangle.2.circlepath").foregroundStyle(.secondary)
        case .published: Label("Reachable through Tor", systemImage: "lock.shield.fill").foregroundStyle(.green)
        case .failed(let message): Label("Tor: \(message)", systemImage: "exclamationmark.triangle").foregroundStyle(.red)
        }
    }
}
