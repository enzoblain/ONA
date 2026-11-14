import Foundation

// Conversations with the agent (docs/ios/protocol-draft.md, "Reads" and "Writes"). Chats live on the computer; the phone
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
        /// Free research: the answer with its notes and sources.
        case answer(ResearchAnswer)
        /// Free research: an action the answer suggests, completed on the computer only.
        case action(SuggestedAction, done: Bool)
        case unknown(String)
    }

    enum ConfirmationState: String, Decodable, Sendable {
        case pending, accepted, rejected, expired
    }

    private enum Keys: String, CodingKey {
        case id, at, kind, text, tool, pending, state, exposure, answer, notes, sources, action
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
        case "answer": .answer(ResearchAnswer(text: try c.decode(String.self, forKey: .answer),
                                              notes: (try? c.decode([ResearchAnswer.Note].self, forKey: .notes)) ?? [],
                                              sources: (try? c.decode([ResearchAnswer.Source].self, forKey: .sources)) ?? []))
        case "action": .action(try c.decode(SuggestedAction.self, forKey: .action),
                               done: (try? c.decode(String.self, forKey: .state)) == "done")
        default: .unknown(kind)
        }
    }
}

/// The answer of a free research (docs/research.md): written from notes whose quotes were found in the pages.
struct ResearchAnswer: Sendable, Equatable {
    let text: String
    let notes: [Note]
    let sources: [Source]

    struct Note: Decodable, Sendable, Equatable {
        let source: String
        let claim: String
        let quote: String
    }

    struct Source: Decodable, Sendable, Equatable {
        let handle: String
        let title: String
        let url: String
    }
}

/// An action a research answer suggests. Its recipient is given on the computer, never by the agent.
struct SuggestedAction: Decodable, Sendable, Equatable {
    let index: Int
    let kind: String
    let purpose: String
    let text: String?
    /// yoctoNEAR, for a payment.
    let amount: String?
}
