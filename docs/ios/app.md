# App iOS ONA — étapes 2 et 3 (écrans, appairage, signatures)

Document interne. Créé le 2026-11-10.

## Ce qui existe

| Chemin | Rôle |
|---|---|
| `ios/ONA/` | App SwiftUI « ONA » (iOS 18+) : appairage par QR, suivi de mission, trois confirmations signées, relevé d'exposition. Pas encore de Tor. |
| `ios/ONA/ONATests/` | Tests unitaires (Swift Testing) : paiement, messages, appairage, octets signés, signatures, Trousseau simulé. |
| `ios/ONA/Package.swift` | Fait tourner la partie sans interface (`Protocol/`, `Pairing/`, `Remote/`) et ses tests sur le Mac : `cd ios/ONA && swift test`. |
| `ios/MockComputer/mock_computer.py` | Faux ordinateur (Python, bibliothèque standard seulement), suit `protocol-draft.md`. Tout ce qu'il renvoie porte `mode: mock`. |
| `ios/MockComputer/pairing.py`, `p256.py` | Appairage et vérification des signatures du faux ordinateur. `p256.py` : P-256 en Python pur, **pour le faux ordinateur seulement** (ni revu, ni à temps constant). |
| `ios/MockComputer/pairing_qr.swift` | Affiche le QR d'appairage en image (`--qr`). |
| `ios/MockComputer/test_*.py` | Tests du faux ordinateur. |
| `docs/ios/protocol-draft.md` | Brouillon du protocole téléphone ↔ ordinateur, à valider avec Hugo. |

## Lancer

```bash
python3 ios/MockComputer/mock_computer.py --qr              # simulateur iOS ; ouvre aussi le QR en image
python3 ios/MockComputer/mock_computer.py --host 0.0.0.0 --qr   # iPhone sur le même réseau
open ios/ONA/ONA.xcodeproj
```

Le terminal du faux ordinateur affiche le texte du QR (usage unique) et, après l'appairage, le code à 6 chiffres.
Sur iPhone : scanner le QR. Dans le simulateur (pas de caméra) : bouton « Coller », ou au lancement
`xcrun simctl launch <simulateur> org.ona.remote -ONAPairingText 'ona-pair:…'` (Debug + simulateur seulement, absent
des builds pour iPhone). Un nouveau QR : `curl -X POST http://127.0.0.1:8790/v0/mock/unpair`.

## Comportement

- **Simulation visible** : un bandeau jaune « SIMULATION » s'affiche dès qu'une réponse dit `mode` ≠ `real`, et reste
  jusqu'à la fermeture de l'app. Le relevé d'exposition d'une mission simulée le dit aussi.
- **Pas de push** : l'app interroge l'ordinateur toutes les 3 s, seulement au premier plan.
- **Rien sur le disque sauf l'appairage** : session `URLSession` éphémère (pas de cache, pas de cookies). L'appairage
  (nom, adresse, clé publique de l'ordinateur, identifiant, référence de la clé du téléphone) est un seul élément du
  Trousseau, « cet appareil seulement », jamais synchronisé. « Oublier cet ordinateur » l'efface.
- **Appairage** : QR `ona-pair:…` → le téléphone crée sa clé P-256 (Secure Enclave, Face ID ou code à chaque usage),
  prouve qu'il la détient, puis affiche un code à 6 chiffres à comparer avec l'ordinateur.
- **Confirmations signées** : plan, destinataire, paiement et refus sont signés (`protocol-draft.md`). Le faux
  ordinateur refuse une confirmation non signée, mal signée ou d'un autre appairage.
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

### Étape 3, vérifié le 2026-11-10

- `swift test` : 30 tests (dont 14 nouveaux sur l'appairage et les signatures), tous passés. Python : 19 tests, tous
  passés, dont le vecteur de la RFC 6979 (P-256, SHA-256) pour `p256.py`.
- Entre langages : une signature produite par CryptoKit est vérifiée par `p256.py`, les octets signés sont identiques
  en Swift et en Python, et le code à 6 chiffres aussi (vecteurs dans `PairingTests.swift` et `test_pairing.py`).
- Simulateur iPhone 17 contre le faux ordinateur : appairage, même code à 6 chiffres des deux côtés (871 519),
  confirmations signées acceptées, confirmation non signée refusée, appairage conservé après redémarrage de l'app et
  signature avec la clé rechargée acceptée.
- **Le simulateur n'a pas de Secure Enclave** : il utilise une clé logicielle (affichée comme telle dans l'app). Le
  chemin Secure Enclave + Face ID n'a pas encore tourné.

## Pas encore fait

- iPhone réel : app installée et lancée le 2026-11-10 (étape 2), mais aucune requête n'est arrivée au faux ordinateur.
  Le Wi-Fi utilisé (réseau d'école, 10.2.x.x) isole probablement les appareils entre eux. À refaire avec le Mac sur le
  partage de connexion de l'iPhone ; ce sera aussi le premier essai du Secure Enclave et de Face ID.
- Côté ordinateur réel : afficher le QR, montrer le code à 6 chiffres, garder la clé du téléphone (questions pour Hugo).
- Étape 4 (Tor) : `onion` dans le QR, autorisation client Tor.
