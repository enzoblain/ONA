# App iOS ONA — étape 2 (écrans sur serveur simulé)

Document interne. Créé le 2026-11-10.

## Ce qui existe

| Chemin | Rôle |
|---|---|
| `ios/ONA/` | App SwiftUI « ONA » (iOS 18+) : suivi de mission, trois confirmations, relevé d'exposition. Pas encore de Tor ni d'appairage. |
| `ios/ONA/ONATests/` | Tests unitaires (Swift Testing) : octets et empreinte du paiement, décodage des messages, envoi des confirmations. |
| `ios/ONA/Package.swift` | Fait tourner la partie sans interface (`Protocol/`, `Remote/`) et ses tests sur le Mac : `cd ios/ONA && swift test`. |
| `ios/MockComputer/mock_computer.py` | Faux ordinateur (Python, bibliothèque standard seulement), suit `protocol-draft.md`. Tout ce qu'il renvoie porte `mode: mock`. |
| `ios/MockComputer/test_mock_computer.py` | Tests du faux ordinateur. |
| `docs/ios/protocol-draft.md` | Brouillon du protocole téléphone ↔ ordinateur, à valider avec Hugo. |

## Lancer

```bash
python3 ios/MockComputer/mock_computer.py                  # simulateur iOS : http://127.0.0.1:8790
python3 ios/MockComputer/mock_computer.py --host 0.0.0.0   # iPhone sur le même Wi-Fi
open ios/ONA/ONA.xcodeproj
```

Sur un iPhone, mettre l'adresse du Mac dans l'app (bouton « Ordinateur ») ou dans `Config/Local.xcconfig`
(`ONA_COMPUTER_URL`). iOS demande l'autorisation « réseau local ».

## Comportement

- **Simulation visible** : un bandeau jaune « SIMULATION » s'affiche dès qu'une réponse dit `mode` ≠ `real`, et reste
  jusqu'à la fermeture de l'app. Le relevé d'exposition d'une mission simulée le dit aussi.
- **Pas de push** : l'app interroge l'ordinateur toutes les 3 s, seulement au premier plan.
- **Rien sur le disque** : session `URLSession` éphémère (pas de cache, pas de cookies), adresse non enregistrée.
- **Paiement vérifié sur le téléphone** : l'app recalcule l'empreinte (mêmes octets qu'`ona-core`) et le texte de
  l'écran à partir du montant et du destinataire. Si l'un ne correspond pas, le bouton « Confirmer » est désactivé.
  L'empreinte envoyée est celle calculée par le téléphone.
- **Refus** : chaque confirmation peut être refusée, ce qui arrête la mission.

## Vérifié le 2026-11-10

- Tests de l'app sur le Mac (`swift test`, Swift 6.4) : 16 tests, 20 cas, tous passés. Dont : l'empreinte calculée
  en Swift est celle d'`ona-core` ; un autre destinataire, un autre montant ou un texte d'écran différent sont refusés.
- Les mêmes tests dans Xcode sur simulateur iOS 27 : le lanceur de tests ne se connecte pas (« test runner hung »,
  « unable to connect … service hub »), sur deux simulateurs. Problème de Xcode 27 bêta, l'app elle-même tourne.
- Tests du faux ordinateur : 6/6 (Python 3.14.7). L'empreinte du paiement de démonstration est identique à celle
  imprimée par `ona demo` (branche `main`) : `a43ba249…fa31`. Le relevé d'exposition a les mêmes valeurs que celui
  d'`ona demo` (`search` 1, `fetch` 2, `contact` 1, 3 appels au modèle, 1 paiement).
- Simulateur iPhone 17 (iOS 27.0, Xcode 27.0 bêta) contre le faux ordinateur : une mission complète déroulée à la main
  (plan validé → cabinet-b choisi → paiement vérifié puis confirmé → relevé affiché).
- `localhost` ne marchait pas de façon fiable depuis le simulateur (requêtes expirées, serveur lié en IPv4) :
  l'adresse par défaut est `127.0.0.1`.

## Pas encore fait

- iPhone réel : app installée et lancée le 2026-11-10, mais aucune requête n'est arrivée au faux ordinateur. Le Wi-Fi
  utilisé (réseau d'école, 10.2.x.x) isole probablement les appareils entre eux. À refaire avec le Mac sur le partage
  de connexion de l'iPhone.
- Étape 3 (appairage QR, signature Secure Enclave) et étape 4 (Tor) : le champ `signature` est réservé.
