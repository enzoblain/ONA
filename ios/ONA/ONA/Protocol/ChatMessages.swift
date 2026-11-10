import Foundation

// Conversations with the agent (docs/ios/protocol-draft.md, "Conversations"). Chats live on the computer; the phone
// only shows them and keeps nothing on disk.

/// One line of the chat list.
struct ChatSummary: Decodable, Sendable, Identifiable, Equatable {
    let id: String
    let title: String
    let updatedAt: Int
    let preview: String
    let status: ChatStatus

    var updated: Date { Date(timeIntervalSince1970: TimeInterval(updatedAt)) }
}

enum ChatStatus: String, Decodable, Sendable {
    /// Nothing running.
    case idle
    /// The agent is working on a step.
    case working
    /// The agent waits for a confirmation from this phone.
    case waiting
}

struct ChatList: Decodable, Sendable {
    let mode: Mode
    let chats: [ChatSummary]
}

struct ChatReply: Decodable, Sendable {
    let mode: Mode
    let chat: ChatDetail
}

/// A conversation, as the computer shows it.
struct ChatDetail: Decodable, Sendable, Identifiable {
    let id: String
    let title: String
    let status: ChatStatus
    /// The step in progress (spinner line), if any.
    let working: Activity?
    let items: [ChatItem]

    /// The confirmation this chat waits for.
    var pending: Pending? {
        items.lazy.compactMap { item -> Pending? in
            if case .confirmation(let pending, .pending) = item.content { return pending }
            return nil
        }.first
    }

    struct Activity: Decodable, Sendable, Equatable {
        let tool: String
        let text: String
    }
}

struct ChatItem: Decodable, Sendable, Identifiable {
    let id: String
    let at: Int
    let content: Content

    enum Content: Sendable {
        /// Written by the person.
        case user(String)
        /// Written by the agent.
        case agent(String)
        /// Something the agent did (search, read a page, compare…).
        case activity(tool: String, text: String)
        /// A confirmation the agent asked for, and what became of it.
        case confirmation(Pending, ConfirmationState)
        /// The exposure report at the end of a mission.
        case exposure(Exposure)
        case unknown(String)
    }

    enum ConfirmationState: String, Decodable, Sendable {
        case pending, accepted, rejected, expired
    }

    private enum Keys: String, CodingKey {
        case id, at, kind, text, tool, pending, state, exposure
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Keys.self)
        id = try c.decode(String.self, forKey: .id)
        at = try c.decode(Int.self, forKey: .at)
        let kind = try c.decode(String.self, forKey: .kind)
        content = switch kind {
        case "user": .user(try c.decode(String.self, forKey: .text))
        case "agent": .agent(try c.decode(String.self, forKey: .text))
        case "activity": .activity(tool: try c.decode(String.self, forKey: .tool),
                                   text: try c.decode(String.self, forKey: .text))
        case "confirmation": .confirmation(try c.decode(Pending.self, forKey: .pending),
                                           (try? c.decode(ConfirmationState.self, forKey: .state)) ?? .expired)
        case "exposure": .exposure(try c.decode(Exposure.self, forKey: .exposure))
        default: .unknown(kind)
        }
    }
}

/// Body of `POST /v0/chats` (new chat) and `POST /v0/chats/{id}/messages`.
struct ChatMessageRequest: Encodable, Sendable, Equatable {
    let text: String
    let pairingId: String
    /// base64 DER signature over `SignedFields.chatMessage`.
    let signature: String
}

/// Body of `POST /v0/chats/{id}/delete`.
struct ChatDeleteRequest: Encodable, Sendable, Equatable {
    let pairingId: String
    let signature: String
}

/// Reply of `POST /v0/chats`.
struct NewChatAck: Decodable, Sendable {
    let ok: Bool
    let error: String?
    let mode: Mode?
    let chatId: String?
}
