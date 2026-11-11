import SwiftUI

/// "Réglages" tab: the paired computer, what the phone keeps, and the app version. Tor settings live in the Tor tab.
struct SettingsView: View {
    let model: RemoteModel
    @State private var confirmingUnpair = false

    var body: some View {
        NavigationStack {
            Form {
                computerSection
                Section {
                    Text("Ce téléphone garde l'appairage (nom et adresse de l'ordinateur, sa clé publique, la clé de ce téléphone, le jeton de lecture et le compteur des demandes) et, si Tor sert, les données du réseau Tor (voir l'onglet Tor). Rien n'est sauvegardé dans iCloud.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                } header: {
                    Text("Données sur ce téléphone")
                }
                Section {
                    Label {
                        Text("Un ordinateur compromis peut faire ce qu'il veut : ce téléphone confirme les actions, il ne peut pas surveiller l'ordinateur.")
                    } icon: {
                        Image(systemName: "desktopcomputer.trianglebadge.exclamationmark")
                    }
                    Label {
                        Text("Un téléphone volé et déverrouillé peut lire les conversations. Chaque action (message, confirmation, paiement) demande encore Face ID ou le code de l'appareil.")
                    } icon: {
                        Image(systemName: "iphone.slash")
                    }
                } header: {
                    Text("Limites")
                }
                .font(.callout)
                Section {
                    LabeledContent("Version", value: Self.appVersion)
                } header: {
                    Text("À propos")
                }
            }
            .navigationTitle("Réglages")
            .confirmationDialog("Oublier cet ordinateur ?", isPresented: $confirmingUnpair, titleVisibility: .visible) {
                Button("Oublier", role: .destructive) { model.unpair() }
            } message: {
                Text("La clé de ce téléphone sera effacée. Pour l'utiliser à nouveau, il faudra rescanner le code de l'ordinateur.")
            }
        }
    }

    @ViewBuilder
    private var computerSection: some View {
        if let pairing = model.pairing {
            Section {
                LabeledContent("Nom", value: pairing.name)
                LabeledContent("Connexion", value: pairing.onion != nil ? "Par Tor" : "Réseau local")
                LabeledContent("Appairé le", value: pairing.pairedAt.formatted(date: .abbreviated, time: .shortened))
                LabeledContent("Protection de la clé") {
                    switch pairing.keyKind {
                    case .secureEnclave: Text("Secure Enclave · Face ID")
                    case .software: Text("Logicielle (simulateur)").foregroundStyle(.orange)
                    }
                }
                Button("Oublier cet ordinateur", role: .destructive) { confirmingUnpair = true }
            } header: {
                Text("Ordinateur appairé")
            }
        } else {
            Section {
                Text("Aucun ordinateur appairé. Ouvrez l'onglet Accueil pour scanner le code affiché par l'ordinateur.")
                    .foregroundStyle(.secondary)
            } header: {
                Text("Ordinateur")
            }
        }
    }

    private static var appVersion: String {
        let info = Bundle.main.infoDictionary
        let version = info?["CFBundleShortVersionString"] as? String ?? "?"
        let build = info?["CFBundleVersion"] as? String ?? "?"
        return "\(version) (\(build))"
    }
}
