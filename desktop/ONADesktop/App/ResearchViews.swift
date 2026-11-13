import AppKit
import SwiftUI

/// The search queries of a free research, before anything leaves: editable here, accepted as shown from the phone.
struct QueriesEditor: View {
    let queries: [String]
    let editable: Bool
    @Binding var edited: [String]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Ces recherches partiront sur le web, via Tor, telles qu'écrites ici. Modifiez-les ou videz-en une pour la retirer.")
                .font(.callout)
                .foregroundStyle(.secondary)
            if editable {
                ForEach(edited.indices, id: \.self) { index in
                    TextField("Recherche \(index + 1)", text: $edited[index])
                        .textFieldStyle(.roundedBorder)
                }
            } else {
                Text(queries.map { "« \($0) »" }.joined(separator: "\n")).textSelection(.enabled)
            }
        }
        .onAppear { if edited.isEmpty { edited = queries } }
    }
}

/// The answer of a free research, with the notes it cites and the sources read. Addresses are shown as text to
/// select, never as links that open.
struct AnswerCard: View {
    let answer: ResearchAnswer

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(answer.answer).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
            if !answer.notes.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Ce que disent les pages").font(.subheadline.weight(.semibold))
                    ForEach(Array(answer.notes.enumerated()), id: \.offset) { _, note in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(note.claim)
                            Text("« \(note.quote) » — \(sourceName(note.source))")
                                .font(.callout).italic().foregroundStyle(.secondary)
                        }
                        .textSelection(.enabled)
                    }
                }
            }
            if !answer.sources.isEmpty {
                Divider()
                VStack(alignment: .leading, spacing: 8) {
                    Text("Sources").font(.subheadline.weight(.semibold))
                    ForEach(answer.sources) { source in
                        VStack(alignment: .leading, spacing: 1) {
                            Text("[\(source.handle)] \(source.title)")
                            Text(source.host).font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                            Text(source.url).font(.caption.monospaced()).foregroundStyle(.secondary)
                        }
                        .textSelection(.enabled)
                    }
                    Text("Adresses à copier : elles ne s'ouvrent pas d'un clic.").font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassEffect(.regular, in: .rect(cornerRadius: 20))
    }

    private func sourceName(_ handle: String) -> String {
        answer.sources.first { $0.handle == handle }.map { $0.host.isEmpty ? $0.title : $0.host } ?? handle
    }
}

/// An action the answer suggests: the person types the recipient, sees the exact action, then confirms. On the Mac
/// only; the phone shows it.
struct ActionCard: View {
    let itemID: String
    let action: ResearchAction
    let chat: Chat
    let engine: ChatEngine
    @Binding var error: String?
    @State private var recipient = ""
    @State private var prepared: PreparedAction?

    private var done: Bool { chat.doneActions.contains(itemID) }
    private var isMessage: Bool {
        if case .message = action.kind { return true }
        return false
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(isMessage ? "Message suggéré" : "Paiement suggéré", systemImage: isMessage ? "envelope" : "creditcard")
                .font(.headline)
            Text(action.purpose).foregroundStyle(.secondary)
            switch action.kind {
            case .message(let text):
                Text(text).textSelection(.enabled)
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(.fill.quaternary, in: .rect(cornerRadius: 12))
            case .payment(let amount):
                LabeledContent("Montant", value: (NEARAmount.text(amount) ?? amount) + " NEAR")
            }
            if done {
                Label(isMessage ? "Remis à votre messagerie" : "Payé", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
            } else if let prepared {
                exact(prepared)
            } else {
                HStack {
                    TextField(isMessage ? "Adresse e-mail du destinataire" : "Compte NEAR du destinataire (nom.testnet)",
                              text: $recipient)
                        .textFieldStyle(.roundedBorder)
                        .onSubmit(prepare)
                    Button("Préparer", action: prepare)
                        .buttonStyle(.glass)
                        .disabled(recipient.trimmingCharacters(in: .whitespaces).isEmpty)
                }
                Text("Le destinataire vient de vous, jamais de l'agent. Sur cet ordinateur seulement.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassEffect(.regular, in: .rect(cornerRadius: 20))
    }

    @ViewBuilder
    private func exact(_ prepared: PreparedAction) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Divider()
            Text("Action exacte").font(.subheadline.weight(.semibold))
            LabeledContent("Destinataire", value: prepared.to)
            if prepared.kind == "payment" {
                LabeledContent("Montant", value: (NEARAmount.text(prepared.content) ?? prepared.content) + " NEAR")
            } else {
                Text(prepared.content).textSelection(.enabled).foregroundStyle(.secondary)
            }
            if prepared.seenInPages {
                Label("Cette adresse figure dans une page lue : vérifiez qu'elle est bien la bonne.",
                      systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
            }
            HStack {
                Button(prepared.kind == "payment" ? "Payer" : "Envoyer depuis ma messagerie") { carryOut(prepared) }
                    .buttonStyle(.glassProminent)
                Button("Modifier") { self.prepared = nil }
                    .buttonStyle(.glass)
            }
        }
    }

    private func prepare() {
        switch engine.prepareAction(chat: chat.id, item: itemID, to: recipient) {
        case .success(let made): prepared = made
        case .failure(let failure): error = failure.text
        }
    }

    private func carryOut(_ prepared: PreparedAction) {
        switch engine.doAction(chat: chat.id, item: itemID, digest: prepared.digest) {
        case .success(.message(let mailto)):
            // The person's own mail program: the person sends the message from there.
            if !NSWorkspace.shared.open(mailto) { error = "Aucune messagerie n'a pu ouvrir le message." }
        case .success(.payment):
            break
        case .failure(let failure):
            error = failure.text
        }
        self.prepared = nil
    }
}
