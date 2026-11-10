# App bureau macOS (SwiftUI) — document interne

Créée le 2026-11-10 sur la branche `desktop-app`. **Changement d'architecture à valider avec Hugo** : le README prévoyait
une app bureau Tauri + JavaScript, et l'app bureau lui est attribuée dans `CLAUDE.md`.

## Ce qui existe

| Chemin | Rôle |
|---|---|
| `desktop/OnaCoreBridge/` | Crate Rust : interface C autour d'`ona-core` (`ona_core_new`, `ona_core_dispatch(json)`, `ona_core_free`). Hors du workspace racine ; `Cargo.lock` repris de la racine pour avoir les mêmes versions. `build.sh` produit `OnaCore.xcframework` (macOS, Apple Silicon). |
| `desktop/ONADesktop/Core/` | Logique de l'app, testée par `swift test` : octets du protocole, appairage et vérification des signatures (CryptoKit), serveur HTTP pour le téléphone (Network.framework), moteur de conversations qui pilote `ona-core`, service Tor. |
| `desktop/ONADesktop/App/` | Interface SwiftUI (macOS 26, Liquid Glass) : conversations, fenêtre d'appairage, réglages. |

## Fonctionnement

- **Agent** : chaque conversation a son propre `ona-core` (`Core::dispatch`). Le moteur l'avance d'une étape toutes les
  1,5 s (`open`, `propose_plan`, `search`, `read`, `compare`, `contact`, `prepare_payment`, `pay`, `close`,
  `exposure`) et s'arrête aux trois confirmations. Modèle, web et paiements sont les faux d'`ona-core` (`mode: mock`),
  d'où le bandeau « Simulation ». La recherche utilise le modèle de recherche `lawyer` / `paris` de la politique de
  démonstration d'`ona-core`, quelle que soit la demande.
- **Confirmations** : depuis le Mac (boutons dans la conversation) ou depuis le téléphone (signées). Le paiement est
  confirmé par `confirm_payment(digest)` : c'est le garde-fou d'`ona-core` qui compare l'empreinte.
- **Appairage** : le Mac garde sa clé P-256 et la clé publique du téléphone dans le trousseau de session. Fenêtre
  « Appairer un téléphone » : QR à usage unique, puis code à 6 chiffres à comparer ; tant que l'utilisateur n'a pas
  confirmé sur le Mac, le téléphone reçoit `pairing not verified`.
- **Téléphone** : même protocole que le faux ordinateur (`docs/ios/protocol-draft.md`). Lecture (`GET`) seulement
  après appairage vérifié ; écritures signées.
- **Connexion** : « Par Tor » (défaut) : serveur sur 127.0.0.1:8790, publié en service `.onion` par le démon `tor` local
  (Homebrew), comme `docs/TOR.md`. « Réseau local (tests) » : serveur sur toutes les interfaces.
- **Rien sur disque pour les conversations** : en mémoire seulement (le coffre d'`ona-core` n'est pas branché).

## Lancer

```bash
desktop/OnaCoreBridge/build.sh                 # une fois (~1 min)
open desktop/ONADesktop/ONADesktop.xcodeproj   # cible ONADesktop
cd desktop/ONADesktop && swift test            # tests, avec le vrai ona-core
```

L'app n'est pas sandboxée (elle lance `tor`) et est signée « Sign to Run Locally ».

## Vérifié le 2026-11-10

- `swift test` : 15 tests passés, dont une mission complète sur le vrai `ona-core` (plan, choix du cabinet, refus d'une
  mauvaise empreinte par le garde-fou, paiement, relevé) et le routeur (appairage, refus avant vérification du code,
  signatures). Rust : 2 tests du pont.
- **Bout en bout, réseau local** : app iPhone (simulateur) ↔ app Mac ↔ `ona-core`. Appairage, création d'une
  conversation signée, plan, choix de cabinet-b, paiement vérifié sur le téléphone puis confirmé, relevé
  d'`ona-core` (cabinet-b, 1 NEAR) reçu par le téléphone. Appairage conservé après redémarrage de l'app Mac.
- Barre latérale du Mac mise à jour en direct (capture de la fenêtre).

## Pas vérifié

- Le mode Tor de l'app Mac (même torrc que `ios/MockComputer/run_onion.sh`, qui a marché).
- L'affichage d'une conversation dans la fenêtre Mac et les confirmations depuis le Mac : pas de clic automatisé
  possible ici, seules la liste et la fenêtre « Téléphone appairé » ont été vues.
- Une fois, l'écoute du port n'a pas démarré après un redémarrage (cause inconnue) ; l'app affiche maintenant l'erreur
  et réessaie toute seule.
- Portefeuille NEAR, dépôts, vrai modèle : pas dans cette app.
