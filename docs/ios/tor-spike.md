# Spike Tor sur iPhone (étape 1)

Document interne. Créé le 2026-11-10.

> **Mise à jour :** l'app de test `ios/TorSpike` et son script `test-onion/run.sh` ont été retirés (branche
> `ios-unified-app`). Arti est maintenant dans l'app ONA (onglet Tor). Ils restent dans l'historique git (commit
> `2ef5dfe`). Pour un `.onion` de test : `ios/MockComputer/run_onion.sh`. Les mesures ci-dessous ont été faites avec
> l'ancienne app de test.

## Ce qui existe

| Chemin | Rôle |
|---|---|
| `ios/ArtiBridge/` | Crate Rust `arti-bridge` : interface C autour d'`arti-client` 0.48.0, compilée en bibliothèque statique (`ArtiBridge.xcframework`, iPhone + simulateur Apple Silicon). |
| `ios/ArtiBridge/examples/smoke.rs` | Test de l'interface C sur le Mac : démarrage d'Arti puis GET HTTP à travers Tor. |
| `ios/TorSpike/` | App SwiftUI de test : démarre Arti, interroge un `.onion`, journal des mesures en mémoire, export par la feuille de partage. |
| `ios/TorSpike/test-onion/run.sh` | Serveur `.onion` de test sur le Mac (C Tor + `python3 -m http.server`). La clé du service reste hors du dépôt. |

Interface du pont (`ios/ArtiBridge/include/ArtiBridge.h`) : `bootstrap`, `status`, `http_get`, `set_dormant`,
`shutdown`, `version`. Les réponses sont du JSON ; les appels bloquants passent par une file série côté Swift.

## Lancer

```bash
ios/ArtiBridge/build-xcframework.sh          # ~5 min la première fois
cp ios/TorSpike/Config/Local.xcconfig.example ios/TorSpike/Config/Local.xcconfig   # puis remplir
ios/TorSpike/test-onion/run.sh               # affiche l'adresse .onion
open ios/TorSpike/TorSpike.xcodeproj         # cible TorSpike, iPhone de test
```

Test sur le Mac, sans iPhone :

```bash
cd ios/ArtiBridge && cargo run --release --example smoke -- <adresse>.onion
```

Dans l'app : « Démarrage à froid » efface le cache d'Arti avant de démarrer ; sans cette case, un cache présent donne
un démarrage à chaud. Le journal note le réseau (Wi-Fi / cellulaire), les passages arrière-plan / premier plan (Arti
passe en mode dormant en arrière-plan) et une requête automatique au retour. « Sonde toutes les 30 s » sert au test
de changement de réseau.

## Choix faits (à relire)

- **Contrôle des permissions d'Arti désactivé** (`fs-mistrust`, `dangerously_trust_everyone`). Le bac à sable iOS
  isole déjà l'app, et l'app ne maîtrise pas les permissions des dossiers parents du conteneur. Non testé avec le
  contrôle activé.
- **Cache et état d'Arti dans `Library/Caches/arti`** : exclus des sauvegardes, iOS peut les purger. C'est ce qui
  permet le démarrage à chaud. Contredit « rien sur le disque à part l'appairage » : question ouverte n° 1 de
  `notes.md`, toujours à trancher.
- **Correctif local de `sysinfo` 0.38.4** (`ios/ArtiBridge/patches/`) : la version exigée par `tor-memquota` 0.48.0 ne
  compile pas pour iOS (`proc_pidinfo` absent de `libc` pour iOS). Le correctif fait renvoyer `None` à `open_files`
  sur iOS. Détails dans `patches/sysinfo-0.38.4/ONA-PATCH.md`.
- TLS des liens Tor : `native-tls` (Security.framework d'Apple), pas de copie d'OpenSSL embarquée.
- SQLite embarqué (`static-sqlite`) plutôt que celui du système.

## Constats du 2026-11-10

Mac sous macOS 27.2, Xcode 27.0 bêta (27A5194q), Rust 1.97.1, arti-client 0.48.0, C Tor 0.4.9.16 (Homebrew,
OpenSSL 4.1.0).

| Constat | Détail |
|---|---|
| Compilation | Le pont compile pour `aarch64-apple-ios` et `aarch64-apple-ios-sim` (avec le correctif `sysinfo`). L'app compile pour le simulateur et pour l'iPhone (Release, non signée). |
| Simulateur | L'app se lance sur un simulateur iPhone 17 ; l'appel Swift → Rust (`version`) fonctionne. Démarrage de Tor non essayé dans le simulateur. |
| Tailles (Mac, pas une mesure de « taille ajoutée ») | `libarti_bridge.a` iOS release : 18 519 800 octets. Exécutable `TorSpike` Release arm64 non signé, avec Arti : 9 842 512 octets. Pas encore de build de référence sans Arti pour calculer la différence. |
| **Réseau du Mac : Tor bloqué** | C Tor reste à 10 % (« connections died … handshaking (TLS) », CONNECTRESET, NOROUTE) ; Arti via `smoke` échoue pareil (« TLS error in TLS negotiation », délais dépassés). HTTPS ordinaire fonctionne. Deux implémentations, deux piles TLS différentes, même échec : le réseau utilisé (Ethernet, pas de Wi-Fi associé) semble filtrer Tor. Pas encore réessayé sur un autre réseau. |
| Signature | Xcode 27 bêta n'a aucun compte Apple configuré : impossible de signer pour l'iPhone en ligne de commande. |

### Plus tard le 2026-11-10, sur un autre réseau (Mac, pas iPhone)

Tor passe. `smoke` (Arti 0.48.0 sur le Mac, cache vide) : démarrage en 14 300 ms, puis GET vers example.com réussi
deux fois. Vers le `.onion` de test (C Tor 0.4.9.16 sur le même Mac) : 1re requête connexion 7 169 ms / total
7 757 ms, 2e requête connexion 446 ms / total 1 004 ms (HTTP 200, 214 octets). Une seule série : à refaire avant
d'en tirer un chiffre.

### Taille (2026-11-10, Xcode 27.0 bêta, Release arm64, arti-client 0.48.0)

Exécutable `TorSpike` non signé : 9 843 136 octets. Carte de liaison (`-Wl,-map`) : les symboles venant de
`libarti_bridge.a` font 4 822 292 octets, le reste du code (Swift de l'app, stubs) 247 038 octets ; les ~4,8 Mo
restants (en-têtes, tables de déroulement, `__LINKEDIT`) ne sont pas attribués par la carte. Taille ajoutée par
Arti : entre 4,8 et 9,6 Mo d'exécutable non compressé, selon l'attribution du reste. Taille de téléchargement
(compressée) non mesurée.

### iPhone 16 (iOS 27.2, build 24B5089g)

App installée et lancée le 2026-11-10 (Release, signée avec un compte gratuit).

Incident côté Mac, 15:36 : le réseau du Mac coupe ~112 s. Ensuite le service `.onion` (C Tor 0.4.9.16) ne répond plus,
ni à l'iPhone (requête expirée après 60 s) ni à Arti sur le Mac (expirée après 120 s), alors qu'Arti joint encore
example.com. Redémarrer C Tor règle le problème (requête OK à 15:47). Une seule observation, cause non établie.
À transmettre pour `ona-core` : le service onion de l'ordinateur doit être vérifié après une coupure réseau.

Journal exporté de l'app, 2026-11-10 vers 15:49 heure de Paris (le journal note l'heure en UTC), iPhone en
cellulaire, une seule série :

| Mesure | Valeur |
|---|---|
| Démarrage à chaud (cache présent, app relancée) | 714 ms (Rust), 716 ms vu de Swift |
| Cache Arti sur le disque après démarrage | 10,8 Mo |
| 1re requête vers le `.onion` après démarrage | connexion 3 013 ms, total 3 317 ms |
| Requête au retour d'un passage en arrière-plan de ~1 s | connexion 350 ms, total 633 ms |
| Bilan | 2 requêtes OK, 0 échec |

Le cache de 10,8 Mo est le prix du démarrage à chaud : à verser à la question ouverte n° 1 de `notes.md`.

Reste à mesurer sur l'iPhone :

- démarrage à froid (aucun relevé) ;
- changement de réseau Wi-Fi ↔ cellulaire pendant la sonde 30 s (aucun relevé) ;
- arrière-plan long (2 et 10 minutes) : le seul passage relevé dure ~1 s ;
- répétitions : une seule série pour l'instant.

## Conséquence possible pour ONA (à vérifier)

Si un réseau bloque Tor, il faut des ponts (obfs4, Snowflake…). Sur ordinateur, Arti lance un transport enfichable
comme processus séparé ; une app iOS ne peut pas lancer de processus fils. Il faudrait donc un transport intégré à
l'app (des bibliothèques existent, non évaluées). À noter dans les limites si la télécommande doit marcher sur ce
genre de réseau.

## Reste à faire pour l'étape 1

1. Compléter les mesures iPhone listées plus haut (froid, changement de réseau, arrière-plan long, répétitions).
2. Taille de téléchargement (app compressée), si l'équipe en a besoin.
