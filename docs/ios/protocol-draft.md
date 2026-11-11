# Protocole téléphone ↔ ordinateur — version 1

Document interne. Version 1 du 2026-11-11 : remplace la version 0 (2026-11-10), après l'inspection de sécurité
(rejeu, code à 6 chiffres sans engagement, lectures ouvertes, ordinateur non authentifié, signatures incomplètes).
Implémentée par les apps bureau (`desktop/tauri/src-tauri/src/{protocol,pairing,router}.rs`,
`desktop/ONADesktop/Core/`). **L'app iPhone et le faux ordinateur (`ios/MockComputer`) parlent encore la version 0** :
ils ne peuvent plus joindre les apps bureau tant qu'ils ne sont pas passés à la version 1.

Elle calque les trois confirmations humaines d'`ona-core` : `accept_plan`, `confirm_recipient`, `confirm_payment`.

## Principes

- Le téléphone **interroge** l'ordinateur (pas de push). Il ne garde rien sur le disque hors du Trousseau.
- Le téléphone ne voit que ce qu'il doit afficher : l'avancement, les offres à départager, l'écran de paiement.
- Chaque réponse porte `"mode"` : `"mock"` tant que modèle et paiements sont faux, `"real"` sinon.
- Transport : HTTP/1.0 + JSON, **toutes les requêtes en `POST`** avec un corps JSON (le pont Tor de l'app ne sait
  envoyer ni en-têtes ni `DELETE`). Par Tor (`.onion` de l'ordinateur). Le mode « réseau local » (HTTP en clair)
  n'existe que dans les versions de développement des apps bureau.
- L'ordinateur refuse : un en-tête `Host` absent, vide, répété ou autre que son adresse `.onion` (ou
  `127.0.0.1:port`, ou son adresse locale en mode réseau local) ; toute requête qui porte `Origin`, `Sec-Fetch-Site`,
  `Sec-Fetch-Mode` ou `Sec-Fetch-Dest`, même avec une valeur vide (navigateur) ; toute méthode autre que `POST` ; les
  routes `/v0/…`.
- Limites côté ordinateur : 16 connexions simultanées, 10 s pour envoyer une requête et recevoir sa réponse, en-têtes
  et corps de 16 Kio au plus.

## Encodage `champs(…)`

Pour chaque champ : sa longueur en u32 petit-boutiste, puis ses octets (texte en UTF-8, clés en octets bruts, champ
absent = longueur 0). Les nombres (compteur, statut HTTP, prix…) sont écrits en texte décimal ASCII. Les aléas
(`nonce`) sont 16 octets aléatoires écrits en 32 caractères hexadécimaux minuscules. Les condensés sont SHA-256 en
64 caractères hexadécimaux minuscules.

Signatures : ECDSA P-256 avec SHA-256, encodage DER, en base64 standard. **Forme « low-s » obligatoire** (s ≤ n/2) :
une signature dont s > n/2 est refusée, des deux côtés. CryptoKit en produit une fois sur deux : remplacer s par n − s
avant l'envoi. Clés publiques : X9.63 non compressée, 65 octets commençant par `04`.

## Réponses signées par l'ordinateur

Chaque requête porte un champ `"nonce"` (32 hex, nouveau à chaque requête). Chaque réponse de l'ordinateur a ce
corps :

```json
{ "reply": "<le JSON de la réponse, sous forme de texte>", "signature": "<base64, ECDSA DER>" }
```

`signature` porte sur `champs("ona/reply/v1", nonce, méthode, chemin, statut_http, reply)` (méthode et chemin de la
requête, par exemple `POST` et `/v1/chats/list`) et se vérifie avec `computer_key` du QR. Le téléphone vérifie la
signature **sur la valeur exacte de `reply` obtenue après décodage du JSON** (ne jamais ré-encoder : l'app Mac échappe
`/` en `\/`), avec son propre `nonce`, sa méthode et son chemin, **avant** de lire `reply`. Il rejette toute réponse
non signée ou mal signée : un programme qui aurait pris le port de l'ordinateur, ou un relais, ne peut ni fabriquer
une réponse, ni rejouer une ancienne (le `nonce` change), ni faire passer la réponse d'une requête pour celle d'une
autre.

Seules réponses **sans signature** : 400, 413 et 431 quand la requête HTTP elle-même est illisible ou trop grande
(avant toute lecture du JSON), et 503 (ordinateur en train de s'arrêter). Une réponse non signée est toujours un échec ;
le téléphone ne lit pas son corps et ne la montre pas comme venant de l'ordinateur. Toutes les autres réponses,
erreurs comprises (y compris un 400 « body is not a JSON object »), sont signées.

## Appairage

1. L'ordinateur affiche un QR : `ona-pair:` suivi de base64url (sans `=`) d'un JSON :

   ```json
   { "v": 1, "name": "Mon ordinateur", "address": null, "onion": "<adresse v3>.onion",
     "computer_key": "<base64, X9.63, 65 octets>", "code": "<base64url, 16 octets aléatoires>",
     "expires_at": 1762790600 }
   ```

   Le code ne sert qu'une fois et expire au bout de 10 minutes (un nouveau QR s'affiche). Après 5 codes faux, il est
   remplacé. Le téléphone refuse un QR dont `v` n'est pas 1.
2. Le téléphone crée sa clé P-256 (Secure Enclave) et un aléa `phone_nonce`, puis **s'engage** :

   ```json
   POST /v1/pair
   { "code": "<code du QR>", "commitment": "<hex>", "nonce": "<hex>" }
   ```

   `commitment = SHA-256(champs("ona/pair-commit/v1", phone_key, phone_nonce))`. Le code est consommé ici, quoi qu'il
   arrive ensuite. Réponse : `{"ok": true, "pairing_id": "p-<32 hex>", "computer_nonce": "<32 hex>", "mode": …}`.
3. Le téléphone **révèle** sa clé :

   ```json
   POST /v1/pair/reveal
   { "pairing_id": "p-…", "phone_key": "<base64, X9.63>", "phone_nonce": "<hex>", "signature": "<base64>",
     "nonce": "<hex>" }
   ```

   `signature` (clé du téléphone) porte sur
   `champs("ona/pair/v1", pairing_id, code, phone_key, computer_key, phone_nonce, computer_nonce)`. L'ordinateur
   vérifie l'engagement et la signature : une seule tentative ; en cas d'échec, nouveau QR. L'engagement doit arriver
   au plus 2 minutes avant la révélation. Réponse : `{"ok": true, "pairing_id": "p-…", "token": "<base64url, 32 octets>"}`.
4. Les deux côtés affichent le **code de vérification** à 6 chiffres :
   `SHA-256(champs("ona/sas/v1", computer_key, phone_key, code, phone_nonce, computer_nonce))`, 4 premiers octets en
   entier gros-boutiste, modulo 1 000 000, sur 6 chiffres. La clé du téléphone est fixée (engagement) avant que
   `computer_nonce` existe : un intermédiaire ne peut plus chercher une clé qui donne le même code (une chance sur un
   million par QR). L'ordinateur n'enregistre le téléphone qu'après la confirmation de la personne, qui a 5 minutes
   (au-delà, nouveau QR). Entre la révélation et ce clic, toute requête reçoit 403 `not paired` : le téléphone
   affiche le code et attend. L'écran de l'ordinateur dit de refuser si le téléphone n'affiche aucun code.
5. Le téléphone garde dans le Trousseau (cet appareil seulement) : `pairing_id`, `onion`, `computer_key`, `name`,
   `token`, son compteur, la référence de sa clé Secure Enclave.

## Lectures (jeton)

- `POST /v1/chats/list` `{"token", "nonce"}` → `{"mode", "chats": [{"id", "title", "updated_at", "preview",
  "status": "idle | working | waiting"}]}`, la plus récente d'abord.
- `POST /v1/chats/{id}/view` `{"token", "nonce"}` → `{"mode", "chat": {"id", "title", "status",
  "working": {"tool", "text"} | null, "items": [...]}}`. Éléments : `user` / `agent` (`text`), `activity` (`tool`,
  `text`), `confirmation` (`pending`, `state` : `pending | accepted | rejected | expired`), `exposure`. Un `kind`
  inconnu est ignoré.

Sans le bon jeton : 403 `missing or wrong token`. Le jeton ne voyage que dans le flux Tor chiffré.

## Écritures (jeton + signature du téléphone + compteur)

Chaque écriture porte `token`, `pairing_id`, `counter` (entier JSON sans partie décimale, de 1 à 2^53 − 1 =
9007199254740991, strictement croissant pour cet appairage ; `1.0`, `"1"` ou `true` sont refusés) et `signature` (clé du téléphone, donc Face ID ou code de l'appareil). L'ordinateur enregistre le dernier compteur
accepté **avant** d'exécuter la requête, y compris après redémarrage : une requête rejouée, ou un compteur qui ne
monte pas, est refusée (`replayed request`). Le téléphone envoie ses écritures une par une.

- `POST /v1/chats` `{"text", …}` → `{"ok", "chat_id": "chat-<32 hex>"}`.
  Signature : `champs("ona/message/v1", pairing_id, counter, "", text)`.
- `POST /v1/chats/{id}/messages` `{"text", …}`. Signature : `champs("ona/message/v1", pairing_id, counter, chat_id, text)`.
- `POST /v1/chats/{id}/delete` `{…}`. Signature : `champs("ona/delete/v1", pairing_id, counter, chat_id)`.
- Texte : 1 à 2 000 caractères. Identifiants de conversation aléatoires, jamais réutilisés.

## Confirmations

`pending` (au plus une par conversation) porte `id` (`c-<32 hex>`, aléatoire, émis par l'ordinateur, jamais réutilisé)
et `content`, le condensé de ce qui est montré :

```json
{ "id": "c-…", "kind": "plan", "plan": ["search", "read", "…"], "content": "<hex>" }
{ "id": "c-…", "kind": "recipient", "content": "<hex>",
  "offers": [ { "firm_id": "cabinet-b", "price_cents": 60000, "delay_days": 10,
                "source_spans": ["Forfait 600 euros, sous 10 jours"] } ] }
{ "id": "c-…", "kind": "payment", "content": "<hex>",
  "payment": { "to": "cabinet-b.testnet", "amount": "1000000000000000000000000",
               "screen": "Pay 1000000000000000000000000 yoctoNEAR to cabinet-b.testnet",
               "digest": "<hex>", "digest_version": 2, "network": "testnet", "contract": "…",
               "mission_id": "…", "nonce": "<32 hex>" } }
```

Condensés, **recalculés par le téléphone à partir de ce qu'il affiche** (jamais repris de `content`) :

- plan : `SHA-256(champs("ona/plan/v1", id, nombre_d_étapes, étape_1, …, étape_n))` ;
- offres : `SHA-256(champs("ona/offers/v1", id, nombre_d_offres, puis pour chaque offre : firm_id, price_cents,
  delay_days, nombre_d_extraits, extrait_1, …))` ;
- paiement (v2, commun avec `ona-core`) :
  `digest = SHA-256(champs("ona/pay/v2", network, contract, mission_id, nonce, to, amount))`, et `content = digest`.
  Ce sont les octets du garde-fou d'`ona-core` : l'app bureau reprend les six champs de la réponse de
  `prepare_payment`, vérifie le condensé et les transmet tels quels avec `screen`. `to` et `amount` doivent être ceux
  de `screen`. Le montant est calculé par `ona-core` (prix de l'offre choisie × taux de la politique), pas par l'app.
  L'ancien condensé (`to` et `amount` seuls, version 0) n'existe plus : `digest_version` vaut toujours 2, le téléphone
  refuse toute autre valeur. `to` doit avoir la forme d'un compte NEAR (2 à 64 caractères `a-z 0-9 . _ -`).

```json
POST /v1/confirm
{ "id": "c-…", "decision": "accept | reject", "firm": "cabinet-b", "digest": "<hex>",
  "token": "…", "pairing_id": "p-…", "counter": 12, "signature": "<base64>", "nonce": "<hex>" }
```

- `firm` : obligatoire pour `recipient` accepté ; `digest` : obligatoire pour `payment` accepté.
- `signature` : `champs("ona/confirm/v1", pairing_id, counter, id, decision, firm, digest, content)`, où `content`
  est le condensé recalculé par le téléphone. L'ordinateur met à sa place le condensé de ce qu'il a demandé : si le
  téléphone a affiché autre chose (autre plan, autres prix), la signature ne vérifie pas.
- L'ordinateur refuse une confirmation dont `id` n'est plus attendue (`stale confirmation`), un `id` déjà exécuté
  (`replayed request`, même après redémarrage) et un compteur qui ne monte pas. Une réponse refusée par l'agent (par
  exemple une empreinte fausse) ne bloque pas la confirmation : le téléphone peut répondre à nouveau, avec un
  nouveau compteur.

**Correction de la version 0** : le brouillon v0 affirmait qu'une signature ne pouvait pas être rejouée. C'était faux :
les identifiants `chat-N-c-M` repartaient de 1 à chaque mission et à chaque redémarrage, aucune requête n'avait de
compteur, et l'empreinte du paiement ne dépendait que du destinataire et du montant. Une mission entière, paiement
compris, pouvait être rejouée.

## Limites connues

- Un ordinateur compromis fait ce qu'il veut : la signature du téléphone est vérifiée par l'app bureau, pas par
  `ona-core` ni par la chaîne. Un téléphone volé déverrouillé lit tout ; chaque écriture demande encore Face ID ou le
  code de l'appareil.
- En mode réseau local (développement), le jeton et les requêtes passent en clair.
- Qui copie la clé du service onion peut publier la même adresse ; il ne peut pas signer les réponses (clé de
  l'ordinateur), mais il voit les requêtes du téléphone (chiffrées par Tor jusqu'à lui).
