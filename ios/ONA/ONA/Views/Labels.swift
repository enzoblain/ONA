import SwiftUI

extension Step {
    var label: String {
        switch self {
        case .search: "Recherche"
        case .read: "Lecture d'une page"
        case .compare: "Comparaison des offres"
        case .confirmRecipient: "Choix du destinataire (vous)"
        case .contact: "Prise de contact"
        case .preparePayment: "Préparation du paiement"
        case .confirmPayment: "Confirmation du paiement (vous)"
        case .pay: "Paiement"
        case .unknown(let raw): raw
        }
    }

    var symbol: String {
        switch self {
        case .search: "magnifyingglass"
        case .read: "doc.text"
        case .compare: "list.number"
        case .confirmRecipient: "person.crop.circle.badge.checkmark"
        case .contact: "envelope"
        case .preparePayment: "doc.badge.gearshape"
        case .confirmPayment: "checkmark.seal"
        case .pay: "creditcard"
        case .unknown: "questionmark.circle"
        }
    }
}

extension Mission.Phase {
    var label: String {
        switch self {
        case .planProposed: "Plan à valider"
        case .running: "En cours"
        case .waiting: "En attente de vous"
        case .closed: "Terminée"
        case .cancelled: "Arrêtée"
        }
    }

    var color: Color {
        switch self {
        case .planProposed, .waiting: .orange
        case .running: .blue
        case .closed: .green
        case .cancelled: .secondary
        }
    }
}

enum Format {
    static func euros(cents: Int) -> String {
        (Decimal(cents) / 100).formatted(.currency(code: "EUR").locale(Locale(identifier: "fr_FR")))
    }

    static func days(_ n: Int) -> String {
        n == 1 ? "1 jour" : "\(n) jours"
    }
}

/// Always-visible label while anything shown comes from a fake.
struct SimulationBanner: View {
    var body: some View {
        Label("Simulation — données fictives, rien n'est réel", systemImage: "theatermasks")
            .font(.footnote.weight(.semibold))
            .foregroundStyle(.black)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 6)
            .background(.yellow, ignoresSafeAreaEdges: [])
            .accessibilityIdentifier("simulation-banner")
    }
}
