import Foundation

/// What a new conversation runs: a free research (docs/research.md), or the lawyer mission (kept for its tests).
public enum ChatKind: Sendable {
    case research, mission
}

/// ona-core's `research_result`, as the conversation shows it: the answer, the notes it cites (each with the quote found
/// word for word in a page) and the sources read.
public struct ResearchAnswer: Equatable, Sendable {
    public struct Note: Equatable, Sendable {
        public let source: String
        public let claim: String
        public let quote: String
    }

    public struct Source: Equatable, Sendable, Identifiable {
        public let handle: String
        public let title: String
        public let url: String
        public var id: String { handle }
        /// The site, as shown next to the title.
        public var host: String { URL(string: url)?.host() ?? "" }
    }

    public let answer: String
    public let notes: [Note]
    public let sources: [Source]

    public init(answer: String, notes: [Note], sources: [Source]) {
        self.answer = answer
        self.notes = notes
        self.sources = sources
    }

    init?(_ reply: [String: Any]) {
        guard let answer = reply["answer"] as? String else { return nil }
        self.answer = answer
        notes = (reply["notes"] as? [[String: Any]] ?? []).compactMap { note in
            guard let source = note["source"] as? String, let claim = note["claim"] as? String,
                  let quote = note["quote"] as? String else { return nil }
            return Note(source: source, claim: claim, quote: quote)
        }
        sources = (reply["sources"] as? [[String: Any]] ?? []).compactMap { source in
            guard let handle = source["handle"] as? String, let title = source["title"] as? String,
                  let url = source["url"] as? String else { return nil }
            return Source(handle: handle, title: title, url: url)
        }
    }

    /// The item's fields in the phone's view (`kind: "answer"`).
    var json: [String: Any] {
        ["answer": answer,
         "notes": notes.map { ["source": $0.source, "claim": $0.claim, "quote": $0.quote] },
         "sources": sources.map { ["handle": $0.handle, "title": $0.title, "url": $0.url] }]
    }
}

/// An action the answer suggests. The recipient is never part of it: the person types it, on the computer.
public struct ResearchAction: Equatable, Sendable {
    public enum Kind: Equatable, Sendable {
        case message(text: String)
        /// yoctoNEAR, decimal.
        case payment(amount: String)
    }

    public let index: Int
    public let purpose: String
    public let kind: Kind

    public init(index: Int, purpose: String, kind: Kind) {
        self.index = index
        self.purpose = purpose
        self.kind = kind
    }

    init?(_ json: [String: Any]) {
        guard let index = json["index"] as? Int, let purpose = json["purpose"] as? String else { return nil }
        switch json["kind"] as? String {
        case "message":
            guard let text = json["text"] as? String else { return nil }
            kind = .message(text: text)
        case "payment":
            guard let amount = json["amount"] as? String, NEARAmount.text(amount) != nil else { return nil }
            kind = .payment(amount: amount)
        default:
            return nil
        }
        self.index = index
        self.purpose = purpose
    }

    var json: [String: Any] {
        switch kind {
        case .message(let text): ["index": index, "kind": "message", "purpose": purpose, "text": text]
        case .payment(let amount): ["index": index, "kind": "payment", "purpose": purpose, "amount": amount]
        }
    }
}

/// An action with the person's recipient, as ona-core prepared it (`research_action_prepare`): what will be done
/// exactly, and the digest that confirms it.
public struct PreparedAction: Equatable, Sendable {
    /// The conversation item of the action.
    public let itemID: String
    public let index: Int
    /// `message` or `payment`.
    public let kind: String
    public let to: String
    /// The message text, or the amount in yoctoNEAR.
    public let content: String
    public let digest: String
    /// The recipient is also written in a page read: it may have been put there for the agent.
    public let seenInPages: Bool
}

/// What carrying out an action did.
public enum ActionOutcome: Equatable, Sendable {
    /// The message, for the person's own mail program: the app opens it, the person sends it.
    case message(mailto: URL)
    case payment(tx: String)
}
