import SwiftUI

extension Step {
    var label: String {
        switch self {
        case .search: "Search"
        case .read: "Reading a page"
        case .compare: "Comparing offers"
        case .confirmRecipient: "Choosing the recipient (you)"
        case .contact: "Contacting the firm"
        case .preparePayment: "Preparing the payment"
        case .confirmPayment: "Confirming the payment (you)"
        case .pay: "Payment"
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

enum Format {
    static func euros(cents: Int) -> String {
        (Decimal(cents) / 100).formatted(.currency(code: "EUR").locale(Locale(identifier: "en_IE")))
    }

    static func days(_ n: Int) -> String {
        n == 1 ? "1 day" : "\(n) days"
    }
}

/// Always-visible label while anything shown comes from a fake.
struct SimulationBanner: View {
    var body: some View {
        Label("Simulation — fake data, nothing is real", systemImage: "theatermasks")
            .font(.footnote.weight(.semibold))
            .foregroundStyle(.black)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 6)
            .background(.yellow, ignoresSafeAreaEdges: [])
            .accessibilityIdentifier("simulation-banner")
    }
}
