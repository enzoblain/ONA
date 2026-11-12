# App iOS ONA — étapes 2 à 4 (écrans, appairage, signatures, Tor)

Document interne. Créé le 2026-11-10.

## Ce qui existe

| Chemin | Rôle |
|---|---|
| `ios/ONA/` | App SwiftUI « ONA » (iOS 18+) : appairage par QR, suivi de mission, trois confirmations signées, relevé d'exposition, transport par Tor (Arti embarqué) quand le QR donne une adresse `.onion`. |
| `ios/ONA/ONA/Tor/` | `ArtiTor` (pont Rust `ios/ArtiBridge`) et `TorComputerLink` : le protocole en HTTP/1.0 vers le port 80 du service onion de l'ordinateur. Dans l'app seulement, pas dans `Package.swift`. |
| `ios/ONA/ONATests/` | Tests unitaires (Swift Testing) : paiement, messages, appairage, octets signés, signatures, Trousseau simulé. |
| `ios/ONA/Package.swift` | Fait tourner la partie sans interface (`Protocol/`, `Pairing/`, `Remote/`) et ses tests sur le Mac : `cd ios/ONA && swift test`. |
| `ios/MockComputer/mock_computer.py` | Faux ordinateur (Python, bibliothèque standard seulement), suit `protocol-draft.md`. Tout ce qu'il renvoie porte `mode: mock`. |
| `ios/MockComputer/pairing.py`, `p256.py` | Appairage et vérification des signatures du faux ordinateur. `p256.py` : P-256 en Python pur, **pour le faux ordinateur seulement** (ni revu, ni à temps constant). |
| `ios/MockComputer/pairing_qr.swift` | Affiche le QR d'appairage en image (`--qr`). |
| `ios/MockComputer/run_onion.sh` | Étape 4 : le faux ordinateur joignable seulement par Tor (service onion C Tor, clé hors du dépôt), QR avec l'adresse `.onion`. |
| `ios/MockComputer/test_*.py` | Tests du faux ordinateur. |
| `docs/ios/protocol-draft.md` | Brouillon du protocole téléphone ↔ ordinateur, à valider avec Hugo. |

## Lancer

```bash
ios/ArtiBridge/build-xcframework.sh                         # une fois : Arti pour l'app (~5 min)
ios/MockComputer/run_onion.sh --qr                          # étape 4 : faux ordinateur derrière un .onion
python3 ios/MockComputer/mock_computer.py --qr              # sans Tor, simulateur iOS ; ouvre aussi le QR en image
python3 ios/MockComputer/mock_computer.py --host 0.0.0.0 --qr   # iPhone sur le même réseau
open ios/ONA/ONA.xcodeproj
```

Le terminal du faux ordinateur affiche le texte du QR (usage unique) et, après l'appairage, le code à 6 chiffres.
Sur iPhone : scanner le QR. Dans le simulateur (pas de caméra) : bouton « Coller », ou au lancement
`xcrun simctl launch <simulateur> org.ona.remote -ONAPairingText 'ona-pair:…'` (Debug + simulateur seulement, absent
des builds pour iPhone). Un nouveau QR : `curl -X POST http://127.0.0.1:8790/v0/mock/unpair`.

## Interface

Barre d'onglets en bas (Liquid Glass à partir d'iOS 26) :

- **Accueil** : appairage (scan du QR, ou coller son texte), puis **liste des conversations** avec l'agent (bouton
  « + » en haut à droite, suppression par balayage, appui long ou menu « … »). Une conversation ressemble à Claude ou
  ChatGPT : messages, étapes de l'agent groupées et repliables (« 3 étapes »), ligne « en cours », cartes de
  confirmation en Liquid Glass, relevé d'exposition à la fin, champ de saisie flottant (texte seulement). Un badge
  sur l'onglet compte les conversations qui attendent une confirmation. Cible : iOS 26.
- **Tor** : état de Tor (arrêté, démarrage avec progression, connecté, erreur avec « Détails »), démarrer / arrêter,
  données Tor gardées sur le téléphone et bouton pour les effacer (remplace le « démarrage à froid » de l'ancienne app
  de test), version d'Arti.
- **Réglages** : ordinateur appairé et « Oublier cet ordinateur », données gardées sur le téléphone, version de l'app.
  Les boutons de simulation n'apparaissent qu'avec un ordinateur simulé.

Les messages d'erreur sont en français et sans détail technique ; le détail d'une erreur Tor est dans « Détails ».
Les journaux d'Arti ne sont activés qu'en Debug.

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
  imprimée par `ona demo` (branche `main`) : `a43ba249…fa31`. (Ce condensé v0 n'existe plus depuis le protocole v1 :
  voir « Protocole v1 » plus bas.) Le relevé d'exposition a les mêmes valeurs que celui
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

### Étape 4 (Tor), état le 2026-11-10

- Code : le QR peut donner une adresse `.onion` au lieu d'une adresse locale ; l'app passe alors tout le protocole
  (appairage, état, confirmations signées) par Arti 0.48.0. Le pont Rust gagne une requête HTTP générique (GET/POST,
  réponse ≤ 1 Mio) et une limite de 120 s au démarrage de Tor. Arti passe en mode dormant quand l'app passe en
  arrière-plan.
- Tests : 3 tests Rust (lecture de la réponse HTTP, refus d'injection d'en-têtes), 34 tests Swift (dont le choix
  `.onion` / adresse locale et un appairage `.onion`), 19 tests Python. Tous passés.
- **Bout en bout par Tor : réussi une fois le 2026-11-10 (soir)**, dans le simulateur iPhone 17, contre le faux
  ordinateur joignable seulement par son `.onion` (`run_onion.sh`) : appairage (code 537 645 des deux côtés), suivi
  « Connecté par Tor », confirmation signée du plan acceptée (`POST /v0/confirm -> 200`). Les deux premiers essais
  d'appairage ont expiré (60 s) juste après un effacement des données Tor ; le troisième a réussi. Depuis le Mac, le
  même `.onion` répondait en 9,3 s puis 0,7 s. Une seule série, sur un réseau qui laissait passer Tor ce soir-là.
- Plus tôt le même jour : **pas réussi.** Sur le Wi-Fi de l'école (10.2.x.x), C Tor a fini par démarrer après
  de nombreuses coupures TLS, mais Arti n'a obtenu aucun circuit vers le `.onion` du faux ordinateur (« Failed to
  obtain hidden service circuit », 4 essais depuis le Mac). Dans le simulateur, l'app démarre Arti (cache écrit) mais
  n'aboutit pas sur ce réseau. À refaire sur un réseau qui laisse passer Tor (partage de connexion).
- Vérifié : sur ce réseau, avec un cache Arti vide, le démarrage de Tor s'arrête au bout de 120 s et l'app affiche
  « bootstrap timed out after 120 s (is Tor blocked on this network?) » (simulateur et Mac). Une première version de
  cette limite faisait paniquer le pont (minuteur Tokio créé hors du runtime) ; la panique était rattrapée et
  affichée, elle est corrigée.
- Pas encore fait : autorisation client Tor (restricted discovery) pour que seul le téléphone appairé puisse joindre
  le `.onion` ; côté ordinateur réel dans `ona-core`.

## Protocole v1, 2026-11-11

Passage de l'app et du faux ordinateur au protocole v1 (`docs/ios/protocol-draft.md`), après l'inspection de sécurité
des apps bureau (constats F-01 à F-17). Ce qui change sur le téléphone :

- **Réponses signées (F-04).** Toutes les requêtes en `POST /v1/…` avec un aléa ; chaque réponse est vérifiée avec la
  clé de l'ordinateur du QR **avant** d'être lue (`ComputerClient`). Sinon : « Ordinateur non authentifié ».
- **Appairage avec engagement (F-02).** Engagement sur la clé, puis révélation ; code à 6 chiffres sur les deux aléas.
  QR `v: 1` avec `expires_at`. L'appairage n'est enregistré qu'après « Les codes sont identiques » (F-17) ; ensuite le
  téléphone attend la confirmation sur l'ordinateur (403 `not paired` affiché comme une attente, pas une erreur).
- **Lectures avec jeton (F-03), écritures avec compteur (F-01).** Jeton et compteur dans le Trousseau ; le compteur est
  pris et enregistré avant la signature, jamais réutilisé ; écritures une par une. Signatures toujours low-s (F-16).
- **Signer ce qui est affiché (F-05).** Le téléphone recalcule le condensé du plan, des offres ou du paiement à partir
  de ce qu'il montre et le signe ; il ne reprend jamais `content`.
- **Paiement v2 (F-01, F-14).** Condensé `ona/pay/v2` (réseau, contrat, mission, aléa, destinataire, montant),
  `digest_version` 2 obligatoire ; le destinataire n'est affiché que s'il a la forme d'un compte NEAR.
- **F-07.** Adresse `http://` du QR acceptée seulement en Debug ; `NSAllowsLocalNetworking` seulement dans
  l'`Info.plist` de Debug (`Config/Info-Release.plist` en Release, vérifié sur le binaire Release).
- **F-17.** Clé logicielle refusée sur un iPhone (simulateur et tests seulement) ; état de Tor (Arti) sous
  Application Support, exclu des sauvegardes (le cache réseau reste dans Library/Caches) ; un appairage v0 enregistré
  est oublié (refaire l'appairage).

Limites (F-15) : un ordinateur compromis fait ce qu'il veut, la signature du téléphone est vérifiée par l'app bureau,
pas par `ona-core` ni par la chaîne. Un téléphone volé déverrouillé lit les conversations ; chaque écriture demande
encore Face ID ou le code de l'appareil (pas encore vérifié sur un vrai iPhone).

Vérifié le 2026-11-11 (macOS, Xcode 27.0 bêta, simulateur iPhone 17 iOS 27.0) :

- `swift test` : 47 tests passés, dont tous les vecteurs v1 communs avec les apps bureau, la signature Rust de
  référence vérifiée par CryptoKit, le refus des signatures high-s, le refus d'une réponse falsifiée ou signée pour une
  autre requête, et un faux ordinateur v1 en Swift (engagement, jeton, compteurs, signatures).
- Faux ordinateur : 24 tests Python passés (mêmes vecteurs, mission complète par HTTP avec vérification de chaque
  réponse, rejeu refusé, confirmation sur un autre plan refusée).
- Bout en bout, réseau local : app iPhone (simulateur) ↔ app Tauri (branche `fix/inspection`) ↔ `ona-core`. Appairage
  v1, conversation, plan, cabinet-b, paiement de 0,6 NEAR vérifié en v2 puis confirmé, relevé reçu. Un appairage v0
  restant dans le Trousseau du simulateur a été oublié comme prévu.
- **Par Tor, le 2026-11-11** (même Mac, réseau de l'école) : app iPhone (simulateur, Arti 0.48.0) ↔ `.onion` de l'app
  Tauri en mode Tor (serveur sur 127.0.0.1 seulement) ↔ `ona-core`. Mission complète : appairage v1, conversation, plan,
  cabinet-b, paiement de 0,6 NEAR vérifié en v2 puis confirmé, relevé reçu. Une seule série.
  - **Premières connexions lentes.** Deux appairages sur trois ont expiré (« L'ordinateur n'a pas répondu à temps »,
    limite de 60 s par requête) avant que le troisième passe. Reproduit sur le Mac avec le pont Arti seul : la première
    requête vers le `.onion` a attendu plus de 60 s, la suivante a répondu en 2 s ; un autre essai, 11 s puis 1 à 2 s. La
    requête n'arrive pas à l'ordinateur pendant cette attente : le code d'appairage n'est pas consommé, on peut réessayer.
    Piste : une limite plus courte pour l'ouverture du circuit et un nouvel essai automatique (pas fait).
  - **Côté app bureau.** Au premier lancement de la soirée, l'app a affiché son QR alors que le service n'était pas
    encore publié sur Tor : un client Tor du Mac obtenait « No more HSDir available » pendant au moins 5 minutes. L'app
    considère l'adresse publiée dès que le fichier `hostname` existe, et ce fichier reste d'une session à l'autre.
    Relancé, le service répondait en moins de 20 s.
- **Avec l'app Mac, le 2026-11-11** (réseau local) : même mission complète, signatures CryptoKit des deux côtés.
- **Nouvel essai par Tor (même jour).** Le pont Arti donne 20 s à chaque tentative d'ouverture du flux et en relance une
  autre, dans la limite de 60 s ; si le flux ne s'est toujours pas ouvert (rien n'a été envoyé), l'app renvoie la
  requête une fois. Mesure sur le Mac avec le pont seul, première requête d'un Arti neuf vers le `.onion` de l'app
  Tauri : 19 réussites sur 21 (dont deux à environ 32 s, sauvées par une nouvelle tentative), deux échecs après 60 s
  (dont un « flux non ouvert »). Sans ces tentatives, le même jour : 3 premières requêtes sur 5 avaient expiré (2 dans
  l'app, 1 avec le pont seul). Peu d'essais, un seul réseau. Le renvoi côté app n'a pas été observé en vrai.
- **Rescanner.** Quand l'ordinateur ne reconnaît plus ce téléphone (`not paired` après le délai, `unknown pairing`,
  `missing or wrong token`), l'accueil propose « Rescanner le code de l'ordinateur ». Testé par les tests unitaires,
  pas à l'écran.
- **Limites (F-15)** dans Réglages : ordinateur compromis, téléphone volé déverrouillé.
- Pas vérifié : sur un vrai iPhone (Secure Enclave, Face ID).

## Onglet Pool (lecture seule), 2026-11-12

Onglet « Pool » à côté d'Accueil, présenté comme un portefeuille : la valeur totale en haut, puis une ligne pour le cash
et une par vault, avec sa valeur (flocon pour un vault gelé, petite horloge quand une opération est en cours). Données lues par
`POST /v1/pool/portfolio` (réponse signée, jeton). Aucune action sur le téléphone : les opérations du pool se confirment
sur l'ordinateur, comme le prévoit `docs/desktop/pool-commands.md`.

- Apps bureau : la route renvoie le `pool_portfolio` d'un `ona-core` dédié au pool. Tant que le pont n'a pas de
  portefeuille de pool (pas encore fait côté bureau), elle répond `no pool wallet configured`, que l'app affiche
  « Le pool n'est pas encore configuré sur l'ordinateur ».
- Faux ordinateur : un portefeuille inventé (étiqueté `mock`) pour essayer l'écran.
- Vérifié : tests Swift (lecture, décodage, montants, refus), Rust et Swift côté bureau (jeton exigé, refus signé sans
  portefeuille), Python ; à l'écran dans le simulateur contre le faux ordinateur. Pas vérifié avec un vrai pool (aucun
  ne tourne encore sur une chaîne).

## Pas encore fait

- iPhone réel : app installée et lancée le 2026-11-10 (étape 2), mais aucune requête n'est arrivée au faux ordinateur.
  Le Wi-Fi utilisé (réseau d'école, 10.2.x.x) isole probablement les appareils entre eux. À refaire avec le Mac sur le
  partage de connexion de l'iPhone ; ce sera aussi le premier essai du Secure Enclave et de Face ID.
- Côté ordinateur réel : afficher le QR, montrer le code à 6 chiffres, garder la clé du téléphone (questions pour Hugo).
- Étape 4 (Tor) : `onion` dans le QR, autorisation client Tor.
