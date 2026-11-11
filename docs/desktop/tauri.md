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
  compilés. Pas de nouvel essai de bout en bout : l'app iPhone parle encore le protocole v0.

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
- Les appels à `ona-core` se font sur le fil unique qui sert aussi la fenêtre et le téléphone : avec un vrai modèle,
  tout attendrait la fin de chaque appel.
- `pairing.json` contient **en clair la clé privée de l'ordinateur** (qui signe les réponses au téléphone) et le
  **jeton** du téléphone (qui ouvre les lectures), protégés seulement par les droits 0600 et la session de
  l'utilisateur. Qui le copie (sauvegarde, autre programme du même utilisateur, administrateur) peut se faire passer
  pour l'ordinateur auprès du téléphone et lire les conversations ; il ne peut pas signer à la place du téléphone
  (clé dans son Secure Enclave). Pas de trousseau système utilisé sous Linux ni Windows.
- Le fichier d'appairage et la clé du service onion (`tor/hs`) sous Windows n'ont pas de droits restreints au-delà du
  dossier de l'utilisateur (pas d'ACL posée). Sous Linux, la clé onion est un fichier simple dans un dossier 0700 : qui
  la copie peut publier la même adresse ; les réponses signées par la clé de l'ordinateur limitent alors l'usurpation.
