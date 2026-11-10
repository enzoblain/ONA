# App bureau Windows et Linux (Tauri) — document interne

Créée le 2026-11-10 sur la branche `desktop-tauri` (partie de `desktop-app`). Même rôle que l'app macOS
([app.md](app.md)) pour les ordinateurs qui ne sont pas des Mac. **À valider avec Hugo**, comme l'app macOS.

## Ce qui existe

| Chemin | Rôle |
|---|---|
| `desktop/tauri/src-tauri/` | Crate Rust `ona-desktop` (Tauri 2), hors du workspace racine. `Cargo.lock` part de celui de la racine : `ona-core` et ses dépendances gardent les mêmes versions. |
| `src/protocol.rs` | Octets signés, code à 6 chiffres, texte du QR, vérification ECDSA P-256 (`p256`). Mêmes vecteurs de test que l'iPhone et l'app Mac, dont une signature CryptoKit. |
| `src/pairing.rs` | Appairage : clé P-256 de l'ordinateur, QR à usage unique, code à comparer, vérification de chaque requête. Fichier `pairing.json` dans le dossier de données de l'app, droits 0600 sous Linux. |
| `src/engine.rs` | Conversations : un `ona-core` par conversation, une étape toutes les 1,5 s, arrêt aux trois confirmations. Même comportement et même JSON que le `ChatEngine` Swift. |
| `src/http.rs`, `src/router.rs`, `src/server.rs` | Serveur pour le téléphone (port 8790), routes de `docs/ios/protocol-draft.md`. |
| `src/tor.rs` | Lance le programme `tor` installé (PATH, `/usr/bin/tor`, `C:\Program Files\Tor\tor.exe`…) avec un service `.onion`. `__OwningControllerProcess` : tor s'arrête avec l'app, même après un plantage. |
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
cargo test --locked     # 17 tests, avec le vrai ona-core
cargo run --locked      # l'app
```

Pour les installeurs (`.deb`, `.rpm`, AppImage, `.msi`, NSIS), il faut la CLI Tauri, à épingler aussi :
`cargo install tauri-cli --version <version> --locked`, puis `cargo tauri build`. Jamais essayé.

En debug seulement : le texte du QR est écrit sur la sortie (`ONA_PAIRING_PAYLOAD …`), pour le simulateur iOS qui n'a
pas de caméra, et `ONA_AUTO_CONFIRM_PAIRING=1` confirme le code sans clic.

## Vérifié le 2026-11-10, sur macOS (pas sur Windows ni Linux)

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
- Le fichier d'appairage sous Windows n'a pas de droits restreints au-delà du dossier de l'utilisateur.
