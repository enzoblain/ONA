# App bureau Windows et Linux (Tauri) — document interne

Créée le 2026-11-10 sur la branche `desktop-tauri` (partie de `desktop-app`). Même rôle que l'app macOS
([app.md](app.md)) pour les ordinateurs qui ne sont pas des Mac. **À valider par l'équipe**, comme l'app macOS.
Protocole téléphone v1 depuis le 2026-11-11 (`docs/ios/protocol-draft.md`).

## Ce qui existe

| Chemin | Rôle |
|---|---|
| `desktop/tauri/src-tauri/` | Crate Rust `ona-desktop` (Tauri 2), hors du workspace racine. `Cargo.lock` part de celui de la racine : `ona-core` et ses dépendances gardent les mêmes versions. |
| `src/protocol.rs` | Octets signés (v1), engagement, code à 6 chiffres, condensés du contenu affiché et du paiement v2, texte du QR, signature et vérification ECDSA P-256 low-s (`p256`). Mêmes vecteurs de test que l'app Mac. |
| `src/pairing.rs` | Appairage : clé P-256 de l'ordinateur, QR à usage unique valable 10 min, 5 codes faux au plus, engagement puis révélation, code à comparer, jeton, compteur et identifiants déjà utilisés. Fichier `pairing.json` écrit atomiquement (fichier temporaire, renommage, dossier synchronisé), droits 0600 sous Linux à chaque écriture ; rien n'est écrit avant la comparaison des codes (5 min pour comparer) ; un échec d'écriture est affiché ; un fichier illisible n'est jamais écrasé (erreur affichée, appairage désactivé). |
| `src/engine.rs` | Conversations : un `ona-core` par conversation, une étape toutes les 1,5 s, arrêt aux trois confirmations. Identifiants aléatoires (16 octets). Même comportement et même JSON que le `ChatEngine` Swift. |
| `src/http.rs`, `src/router.rs`, `src/server.rs` | Serveur pour le téléphone : routes v1 de `docs/ios/protocol-draft.md`, réponses signées, `Host` vérifié, requêtes de navigateur refusées ; 16 connexions au plus, 10 s par requête. Port choisi par le système en mode Tor. |
| `src/tor.rs` | Lance le programme `tor` installé (d'abord `/usr/bin/tor`, `/usr/sbin/tor`, `/usr/local/bin/tor`, `/opt/homebrew/bin/tor`, `C:\Program Files\Tor\tor.exe`, puis le PATH) avec un service `.onion`, seulement une fois le serveur à l'écoute. `__OwningControllerProcess` : tor s'arrête avec l'app, même après un plantage. |
| `src/worker.rs` | Un seul fil possède tout (`ona-core` n'est pas `Send`) ; la fenêtre et le serveur lui envoient des tâches. |
| `src/main.rs` | Commandes Tauri appelées par la fenêtre. |
| `desktop/tauri/ui/` | Fenêtre en HTML/CSS/JavaScript sans bibliothèque : conversations, confirmations, relevé, fenêtre « Téléphone ». Thème clair et sombre. |
| `assets/make_icons.swift` | Dessine le logo et toutes les icônes (iOS, macOS, Tauri) : `swift assets/make_icons.swift`. |

## Lancer

Rust (essayé avec 1.97.1), puis :

- **Linux** (Debian/Ubuntu) : `sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev libayatana-appindicator3-dev`
  et le paquet `tor`.
- **Windows** : WebView2 (déjà présent sur Windows 10/11 à jour), outils de compilation MSVC, et le « Tor Expert Bundle »
  avec `tor.exe` dans le PATH.

```bash
cd desktop/tauri/src-tauri
cargo test --locked     # 45 tests, avec le vrai ona-core
cargo run --locked      # l'app (build debug)
```

Le mode « Réseau local » (HTTP en clair sur toutes les interfaces, port 8790) n'existe que dans les builds debug
(`cargo run`) ; un build release l'ignore, même s'il a été choisi auparavant.

Pour les installeurs (`.deb`, `.rpm`, AppImage, `.msi`, NSIS), il faut la CLI Tauri, à épingler aussi :
`cargo install tauri-cli --version <version> --locked`, puis `cargo tauri build`. Jamais essayé.

En debug seulement : le texte du QR est écrit sur la sortie (`ONA_PAIRING_PAYLOAD …`), pour le simulateur iOS qui n'a
pas de caméra, et `ONA_AUTO_CONFIRM_PAIRING=1` confirme le code sans clic. Qui lit ce texte peut s'appairer avant
le téléphone : à réserver aux tests. La fenêtre ne reçoit que l'image du QR, pas son texte.

## Vérifié le 2026-11-11 (protocole v1), sur macOS

- Les crates `tauri` et `qrcode` ne sont pas dans le cache hors ligne : `cargo test` dans `src-tauri` n'a pas pu
  tourner. Les modules (tout sauf `main.rs`) ont été compilés et testés hors ligne dans un banc d'essai externe avec les
  mêmes versions épinglées (`qrcode` remplacé par un bouchon) : 45 tests passés. `main.rs` et la fenêtre n'ont pas été
  compilés. Bout en bout en protocole v1 le 2026-11-11, sur macOS, réseau local : app iPhone (simulateur) ↔ app Tauri ↔
  `ona-core`, de l'appairage (engagement puis révélation) au relevé, paiement de 0,6 NEAR vérifié en v2 sur le téléphone.

## Vérifié le 2026-11-10, sur macOS (protocole v0, avant les correctifs)

- `cargo test` : 17 tests passés (vecteurs du protocole, appairage, fichier 0600, mission complète sur `ona-core` avec
  refus d'une mauvaise empreinte, refus, routeur avec signatures, serveur TCP, appairage et conversation par HTTP).
  `cargo clippy --all-targets` : aucun avertissement.
- **Bout en bout, réseau local** : app iPhone (simulateur) ↔ app Tauri ↔ `ona-core`. Appairage par le texte du QR,
  conversation signée, plan validé, cabinet-b choisi, paiement vérifié par le téléphone puis confirmé, relevé
  d'`ona-core` (cabinet-b, 1 NEAR) reçu.
- Fenêtre Tauri : liste mise à jour en direct et « Téléphone appairé » (capture). Le contenu d'une conversation, le choix
  du cabinet et l'appel `confirm` ont été vérifiés avec la même interface dans un navigateur, avec un faux pont Tauri
  et les vraies données de la conversation.
- **Mode Tor** : serveur sur 127.0.0.1 seulement, `tor` lancé, adresse `.onion` publiée. Après `kill -9` de l'app,
  `tor` s'arrête aussi.

## Pas vérifié

- **Aucune compilation ni exécution sous Windows ou Linux.** Le code propre à Windows (`CREATE_NO_WINDOW`, chemins
  de `tor.exe`) n'a jamais été compilé.
- Le téléphone joignant l'app par Tor (seule la publication de l'adresse a été vue).
- Les clics dans la vraie fenêtre Tauri (pas de clic automatisé possible ici) ; le QR affiché dans la fenêtre.
- Les installeurs.
- Chaque conversation a son `ona-core` sur un fil à elle. Le fil qui sert la fenêtre et le téléphone lui envoie une
  commande à la fois et n'attend pas plus de 200 ms : un appel au vrai modèle continue pendant que la fenêtre et le
  téléphone sont servis, et la réponse est reprise au tour suivant. Les confirmations (plan, destinataire, paiement)
  et la fin de mission attendent la réponse : elles ne passent pas par le modèle. La lecture du pool pour le téléphone
  attend encore la sienne.
- La **clé privée de l'ordinateur** (qui signe les réponses au téléphone) et le **jeton** du téléphone (qui ouvre les
  lectures) sont dans le coffre du système (bibliothèque `keyring` : Trousseau sur Mac, Gestionnaire d'identification
  sous Windows, Secret Service sous Linux), pas dans `pairing.json`, qui ne garde que la clé publique du téléphone, le
  compteur et les identifiants déjà utilisés. Un `pairing.json` d'une version précédente donne ses secrets au coffre
  au démarrage, puis est réécrit sans eux. Sans coffre utilisable (Linux sans Secret Service lancé), les secrets
  restent dans le fichier, lisible par l'utilisateur seul, et la fenêtre le dit. Testé avec un faux coffre ; le vrai
  coffre de chaque système n'a pas été essayé. Un autre programme du même utilisateur peut en général lire le coffre
  aussi : il protège surtout contre la copie d'un fichier (sauvegarde, autre machine).
- Le coffre est lu au démarrage sur un fil à part : macOS peut d'abord demander l'accord de la personne (après une mise
  à jour non signée de la même façon, par exemple). Pendant ce temps la fenêtre répond et dit « Lecture du trousseau du
  système… » ; le téléphone n'est pas servi et aucun QR n'est montré tant que l'appairage n'est pas chargé. Une écriture
  dans le coffre (nouvel appairage) se fait encore sur le fil principal. Les tests n'utilisent jamais le coffre du
  système.
- Le fichier d'appairage et la clé du service onion (`tor/hs`) sous Windows n'ont pas de droits restreints au-delà du
  dossier de l'utilisateur (pas d'ACL posée). Sous Linux, la clé onion est un fichier simple dans un dossier 0700 : qui
  la copie peut publier la même adresse ; les réponses signées par la clé de l'ordinateur limitent alors l'usurpation.

## Real model

Without settings, ona-core keeps its fake model (`mode: mock`) and the app and the phone show the simulation banner. To
use the real one, write `model.json` in the app's data folder (next to `pairing.json`):

```json
{
  "relay_url": "https://relay.example.org",
  "model": "<a model the relay allows>",
  "max_tokens": 512,
  "token_budget": 20000,
  "tokens_file": "/path/to/request-tokens"
}
```

The names are those of `ona real` (docs/INSTALL.md, "Use the real model"); `token_budget` is for each conversation.
`tokens_file` holds one request token per line, readable by its owner only.

- Every connection ona-core opens goes through the app's own tor, on a second SOCKS port that is not onion-only
  (`ONA_REQUIRE_TOR`). The real model is used only in Tor mode, once the QR code is shown; before that, or in the
  local-network mode, a conversation is refused with the reason. Through Tor, the relay must be an `https` host name
  or an `http` onion address: an IP address is refused by ona-core.
- An unreadable `model.json`, or settings ona-core refuses, give a core that refuses every command with the reason: the
  app never falls back to the fake model in silence.
- The NEAR AI key is not in the app: the relay holds it (docs/INSTALL.md, "Run the relay").
- Only one conversation at a time can use the tokens file (ona-core locks it).

Tested with unit tests only (settings, refusals, a core set up through a SOCKS port). Not run against a relay yet.

## Erasure and backups

Conversations are kept in memory only and are gone when the app quits; nothing about them is written to disk. Nothing
marks the app's data folder (onion key, `pairing.json`, `model.json`) as excluded from backups on Windows or Linux:
there is no single mechanism every backup tool follows there.

## Pool

The **Pool** button opens the pool: the total, the cash, one line per vault, and the operations of
docs/desktop/pool-commands.md. Each operation is prepared by ona-core (`pool_prepare`), its summary shown (amount, what
is received, what is left in the pool's cash and lost, fees, network, contract, expiry), and executed only when the
person clicks **Confirmer** in this window: never from the phone, which only reads the portfolio. Entries, exits and
payments are queued by the pool agent: the window says the result comes later, and **Récupérer** runs `pool_recover`.
A deposit is prepared and its summary shown, but cannot be finished: it is sent and signed by the person's own NEAR
wallet, and connecting a wallet to the app is not decided yet.

Settings: `pool.json` in the app's data folder, with the names of `ona`'s variables (docs/INSTALL.md, "The pool
commands"):

```json
{
  "wallet_file": "/path/to/wallet",
  "wallet_key_file": "/path/to/wallet-key",
  "pool": "pool.<account>.testnet",
  "rpc_url": "https://…",
  "rpc_url_2": "https://… (optional, another operator)",
  "recommended_near": "100,500,2000",
  "agent_url": "https://… or http://….onion (optional)"
}
```

Without the file, the pool answers `no pool wallet configured`. With it, the pool goes through the app's tor only, like
the real model, and its core is made again when tor's port changes. Its core runs on its own thread: the window waits
for a pool reply there; the phone's portfolio read waits on the worker thread.

Tested: the settings and refusals (unit tests), and the window against a fake bridge returning the example values of
pool-commands.md (in a browser). Not run against a pool contract.

## Tor client authorization

In Tor mode the onion service is published for the paired phone's client key only (Tor "restricted discovery"): a Tor
client without the key cannot find it, so it cannot try a pairing code or a request. The app makes an x25519 key,
writes its public half to `tor/hs/authorized_clients/phone.auth` before starting `tor`, and gives the secret half to
the phone in the QR code (`onion_auth`, docs/ios/protocol-draft.md). The secret is kept with the pairing secrets (in
the system's credential store). Forgetting the phone makes a new key and starts `tor` again. A pairing made before
this change is dropped once: the phone pairs again.

Before showing the QR code, the app checks its own onion address through its own `tor` without the key: with
`ExtendedErrors` on that SOCKS port, `tor` answers "missing client authorization" (0xF4) once it found the descriptor,
which shows the service is published.
