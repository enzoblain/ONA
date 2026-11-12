# App bureau macOS (SwiftUI) — document interne

Créée le 2026-11-10 sur la branche `desktop-app`. **Changement d'architecture à valider par l'équipe** : le README
prévoyait une app bureau Tauri + JavaScript. Protocole téléphone passé en version 1 le 2026-11-11 (correctifs de
sécurité, voir `docs/ios/protocol-draft.md`).

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
- **Appairage** : le Mac garde sa clé P-256 et le téléphone appairé (clé publique, jeton, dernier compteur, identifiants
  de confirmation déjà exécutés) dans un élément du trousseau de session. Le code demande
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` à chaque écriture ; l'effet réel sur le trousseau de session d'un
  Mac (fichier, app non signée) n'est **pas vérifié**. Un élément illisible n'est jamais écrasé : l'erreur est affichée
  et l'appairage désactivé. Fenêtre « Appairer un téléphone » : QR à usage unique valable 10 minutes, engagement puis
  révélation de la clé du téléphone, code à 6 chiffres à comparer dans les 5 minutes (« Refuser » aussi si le
  téléphone n'affiche aucun code). Rien n'est enregistré avant la comparaison. Un échec d'enregistrement est affiché.
- **Téléphone** : protocole v1 (`docs/ios/protocol-draft.md`) : tout en `POST`, lectures avec le jeton d'appairage,
  écritures signées par le téléphone avec un compteur croissant, réponses signées par le Mac. En-tête `Host` vérifié,
  requêtes de navigateur refusées.
- **Connexion** : « Par Tor » : serveur sur 127.0.0.1, port choisi par le système à chaque démarrage, publié en
  service `.onion` par le démon `tor` local (Homebrew) une fois le serveur à l'écoute ; `__OwningControllerProcess`
  arrête `tor` avec l'app. « Réseau local » (HTTP en clair sur toutes les interfaces, port 8790) : **versions Debug
  seulement**, absent des versions Release.
- **Serveur** : au plus 16 connexions simultanées, 10 s pour recevoir et traiter une requête.
- **Rien sur disque pour les conversations** : en mémoire seulement (le coffre d'`ona-core` n'est pas branché).

## Lancer

```bash
desktop/OnaCoreBridge/build.sh                 # une fois (~1 min)
open desktop/ONADesktop/ONADesktop.xcodeproj   # cible ONADesktop
cd desktop/ONADesktop && swift test            # tests, avec le vrai ona-core
```

L'app n'est pas sandboxée (elle lance le `tor` de Homebrew, ce que le bac à sable interdit) et est signée « Sign to Run
Locally ». « Hardened runtime » activé en Release (pas vérifié : pas de Xcode ici). Le bouton « Copier le texte du
code » (presse-papiers général) n'existe qu'en Debug.

## Vérifié le 2026-11-11 (protocole v1)

- Tests de `Core` (32, framework Testing) compilés avec `swiftc` et exécutés contre le vrai `ona-core` : vecteurs
  partagés avec l'app Tauri (dont une signature produite par `p256`), engagement et révélation, rejeu refusé après
  redémarrage, jeton, `Host`, navigateur, contenu signé, empreinte de paiement v2. `swift test` lui-même n'a pas pu
  tourner (pas de Xcode dans l'environnement de test). La cible App (SwiftUI) n'a pas été compilée.
- Bout en bout en protocole v1 le 2026-11-11, réseau local : app iPhone (simulateur) ↔ app Mac (Debug, branche
  `desktop-onion-ready`) ↔ `ona-core`, de l'appairage au relevé (paiement de 0,6 NEAR vérifié en v2).

## Vérifié le 2026-11-10 (protocole v0, avant les correctifs)

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
- Les appels à `ona-core` se font sur le fil principal : avec un vrai modèle (secondes par appel), la fenêtre et le
  serveur du téléphone seraient bloqués pendant chaque appel. À déplacer sur une file dédiée avant le vrai modèle.
- Le plafond de connexions et le délai global du serveur Swift n'ont pas de test automatique (ceux de l'app Tauri en
  ont).

## Real model

Same settings and same rules as the Tauri app (docs/desktop/tauri.md, "Real model"), in
`~/Library/Application Support/ONA/model.json`. The bridge takes them with `ona_core_new_with`, and the core's traffic
goes through the app's tor, on a second SOCKS port. Tested with unit tests only, not against a relay yet.

The bridge's release profile does not strip build-time dylibs (proc macros): the `strip` of Xcode 27 (beta) leaves them
unloadable.

Each conversation's ona-core runs on a serial queue of its own (`CoreQueue`). The main actor, which also serves the
window and the phone, sends one command at a time and waits at most 50 ms per tick: a real model call goes on while
the app stays responsive, and its reply is taken at a later tick. Confirmations and the end of a mission wait for their
reply (they do not reach the model). Reading the pool for the phone still waits for its reply.

## Erasure and backups

Conversations are kept in memory only: they are gone when the app quits, and nothing about them is written to disk, so
no system task is needed to erase them. ona-core's vault (chats kept up to 24 hours) is not used by the app; if it is,
an erasure task running while the app is closed will be needed. The app's folder (`~/Library/Application Support/ONA`:
onion key, tor's state, `model.json`) is marked excluded from Time Machine at every launch; a failure is shown in the
window. A request tokens file elsewhere is not covered.

## Pool

The **Pool** toolbar button opens a sheet with the pool (docs/desktop/pool-commands.md): the total, the cash, one line
per vault (its value, "gelé" when frozen, a clock while notes are spending or waiting for their signature), and the
operations: **Placer du cash** (enter), **Changer** and **Sortir** on a vault (switch, exit), **Payer vers un compte**
(exit_cash), **Déposer** (deposit) and **Récupérer** (`pool_recover`). Each operation is prepared by ona-core
(`pool_prepare`), its summary shown (amount, vaults or account, what is received, what is left in the pool's cash and
lost, exit limit, fees, warnings, network, contract, expiry; not the share price), and executed only when the person
clicks **Confirmer** in this sheet: never from the phone, which only reads the portfolio. An `outcome unknown` error is
shown as sent to the pool agent, result later through **Récupérer**. A deposit is prepared and its summary and wallet
call shown, without a confirm button: it is sent and signed by the person's own NEAR wallet, and connecting a wallet to
the app is not built. Amounts typed in NEAR ("1.5", "1,5", or "tout" where the operation allows it) are turned into
yoctoNEAR exactly, without floating point.

Settings: `~/Library/Application Support/ONA/pool.json`, with the same keys as the Tauri app (docs/desktop/tauri.md,
"Pool"): `wallet_file`, `wallet_key_file`, `pool`, `rpc_url`, and optionally `rpc_url_2`, `recommended_near`,
`agent_url`. The bridge (`ona_core_new_with` with a `pool` object) refuses unknown keys and values that are not text.
Without the file the pool answers `no pool wallet configured`; an unreadable file is refused with its reason. With it,
the pool goes through the app's tor only, like the real model, and never has the real model itself.

The app has one pool core, on a serial queue of its own (`CoreQueue`). The sheet awaits its replies without holding
the main actor. When tor's port for the core changes (checked every 1.5 s), the core is released once the commands
already sent are answered, and the next pool command makes a new one: the wallet file is locked by the core that
opened it, so the new one is made only after the old one is gone. The phone's portfolio read still waits for its reply
on the main actor.

Tested with unit tests: the bridge's pool setup and refusals (`cargo test` in `desktop/OnaCoreBridge`), the settings
file handling, the engine's pool commands (only the four pool commands accepted, one core, a new core only after the
old one is released, the main actor not held) with a fake core, the NEAR amount conversions, and the reading of the
example replies of pool-commands.md. Not tested: the sheet itself (built, not run or looked at), and the pool against a
pool contract, an RPC node or a pool agent.

## Tor client authorization

Same as the Tauri app (docs/desktop/tauri.md, "Tor client authorization"): the onion service is published for the
paired phone's x25519 client key only, written to `tor/hs/authorized_clients/phone.auth` before `tor` starts; the QR
code gives the secret to the phone (`onion_auth`); the key is kept in the pairing record in the Keychain; forgetting the
phone makes a new key and starts `tor` again; a pairing made before this change is dropped once. The QR waits for the
self-check through `tor`, which answers "missing client authorization" (0xF4, `ExtendedErrors`) for a restricted
service it found.
