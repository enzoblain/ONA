# Protocole téléphone ↔ ordinateur — brouillon v0

Document interne, 2026-11-10. **Brouillon côté iOS, pas encore validé par Hugo.** Il calque les trois confirmations
humaines d'`ona-core` (branche `main`, `crates/ona-core/src/lib.rs`) : `accept_plan`, `confirm_recipient`,
`confirm_payment`. Le faux ordinateur `ios/MockComputer/mock_computer.py` le suit.

## Principes

- Le téléphone **interroge** l'ordinateur (pas de push). Il ne garde rien sur le disque.
- Le téléphone ne voit que ce qu'il doit afficher : l'avancement, les offres à départager, l'écran de paiement. Pas de
  jetons, pas de table de pseudonymes, pas de clé.
- Chaque réponse porte `"mode"` : `"mock"` pour le faux ordinateur (et pour `ona-core` tant que le modèle est faux),
  `"real"` sinon. L'app affiche « Simulation » dès qu'une réponse dit `"mock"`.
- Transport : HTTP/1.1 + JSON. Sur le réseau local pour l'étape 2 ; via Tor (`.onion` de l'ordinateur) à l'étape 4.
- Étape 3 : chaque confirmation est signée par la clé P-256 du Secure Enclave du téléphone appairé.

## `GET /v0/state`

```json
{
  "mode": "mock",
  "computer": { "name": "Ordinateur simulé" },
  "mission": {
    "id": "m-1",
    "title": "Trouver un avocat en droit du travail",
    "phase": "plan_proposed | running | waiting | closed | cancelled",
    "steps": [ { "step": "search", "status": "done | current | pending" } ],
    "events": [ { "at": 1762790000, "text": "Recherche : 2 résultats" } ],
    "pending": null,
    "exposure": null
  }
}
```

`mission` vaut `null` s'il n'y a pas de mission. `steps[].step` reprend les noms d'`ona-core` (`search`, `read`,
`compare`, `confirm_recipient`, `contact`, `prepare_payment`, `confirm_payment`, `pay`).

`pending` (une confirmation attendue, au plus une à la fois) :

```json
{ "id": "c-1", "kind": "plan", "plan": ["search", "read", "…"] }
{ "id": "c-2", "kind": "recipient",
  "offers": [ { "firm_id": "cabinet-b", "price_cents": 60000, "delay_days": 10,
                "source_spans": ["Forfait 600 euros, sous 10 jours"] } ] }
{ "id": "c-3", "kind": "payment",
  "payment": { "to": "cabinet-b.testnet", "amount": "1000000000000000000000000",
               "screen": "Pay 1000000000000000000000000 yoctoNEAR to cabinet-b.testnet",
               "digest": "<sha256 hex>" } }
```

`exposure` (mission terminée) : même forme que `exposure_report` d'`ona-core` (`outputs`, `refused_by_gate`,
`firms_contacted`, `payments`, `model_calls`, `mode`).

## Appairage (étape 3)

1. L'ordinateur affiche un QR qui contient le texte `ona-pair:` suivi de base64url (sans `=`) d'un JSON :

   ```json
   { "v": 0, "name": "Ordinateur simulé", "address": "http://192.168.1.20:8790", "onion": null,
     "computer_key": "<base64, clé publique P-256, X9.63 non compressée, 65 octets>",
     "code": "<base64url, 16 octets aléatoires, usage unique>" }
   ```

   `address` sert à l'étape 2 (réseau local). À l'étape 4, `onion` (adresse v3 en `.onion`) la remplace : le téléphone
   parle alors HTTP/1.0 au port 80 du service onion, par Tor. Quand les deux sont présents, `onion` l'emporte.
2. Le téléphone crée une clé P-256 dans le Secure Enclave (utilisation protégée par Face ID ou le code) et envoie :

   ```json
   POST /v0/pair
   { "code": "<code du QR>", "phone_key": "<base64, X9.63, 65 octets>", "signature": "<base64, ECDSA DER>" }
   ```

   `signature` porte sur `champs("ona/pair/v0", code, phone_key, computer_key)` (voir plus bas) : elle prouve que le
   téléphone détient la clé. Réponse : `{"ok": true, "pairing_id": "p-…", "mode": "mock"}`. Le code ne sert qu'une
   fois.
3. Les deux côtés affichent un **code de vérification** à 6 chiffres, à comparer à l'œil :
   `SHA-256(champs("ona/sas/v0", computer_key, phone_key, code))`, 4 premiers octets en entier gros-boutiste,
   modulo 1 000 000, sur 6 chiffres. Sur un vrai ordinateur, l'appairage n'est accepté qu'après cette comparaison ;
   le faux ordinateur l'écrit dans son terminal et accepte tout seul.
4. Le téléphone garde dans le Trousseau (cet appareil seulement, pas de synchronisation iCloud) : `pairing_id`,
   `address` / `onion`, `computer_key`, `name`, et la référence chiffrée de sa clé Secure Enclave. Rien d'autre.

**Encodage `champs(…)`** : pour chaque champ, sa longueur en u32 petit-boutiste puis ses octets (texte en UTF-8, clés
en octets bruts, champ absent = longueur 0). Signature ECDSA P-256 avec SHA-256, encodage DER, en base64.

## `POST /v0/confirm`

```json
{ "id": "c-3", "decision": "accept | reject", "firm": "cabinet-b", "digest": "<sha256 hex>",
  "pairing_id": "p-…", "signature": "<base64, ECDSA DER>" }
```

- `firm` : obligatoire pour `recipient` accepté.
- `digest` : obligatoire pour `payment` accepté. **Le téléphone recalcule le condensé** à partir de `to` et `amount`
  (même octets qu'`ona-core` : longueur de `to` en u32 petit-boutiste, `to` en UTF-8, `amount` en u128
  petit-boutiste, puis SHA-256) et refuse d'afficher un paiement dont le condensé ne correspond pas.
- `signature` (étape 3) : sur `champs("ona/confirm/v0", pairing_id, id, decision, firm, digest)`, avec la clé du
  téléphone appairé. L'ordinateur refuse une confirmation non signée, mal signée, ou d'un appairage inconnu.
  Chaque signature demande Face ID (ou le code) sur le téléphone.
- Réponse : `{"ok": true, "mode": "mock"}` ou `{"ok": false, "error": "…", "mode": "mock"}`. Une confirmation dont
  `id` n'est plus celle attendue est refusée (`"stale confirmation"`) : une signature ne peut pas être rejouée sur
  une autre confirmation.

## Conversations (branche `ios-chat`)

Le téléphone peut aussi **demander** quelque chose à l'agent, sous forme de conversation. Les conversations vivent
sur l'ordinateur ; le téléphone les affiche et n'en garde rien sur son disque.

- `GET /v0/chats` → `{"mode", "chats": [{"id", "title", "updated_at", "preview", "status": "idle | working | waiting"}]}`,
  la plus récente d'abord.
- `GET /v0/chats/{id}` → `{"mode", "chat": {"id", "title", "status", "working": {"tool", "text"} | null, "items": [...]}}`.
  Chaque élément a `id`, `at`, `kind` :
  `user` / `agent` (`text`), `activity` (`tool` : `think`, `search`, `read`, `compare`, `contact`, `prepare_payment`,
  `pay` ; `text`), `confirmation` (`pending` comme plus haut, `state` : `pending | accepted | rejected | expired`),
  `exposure` (`exposure` comme plus haut). Un `kind` inconnu est ignoré par l'app.
- `POST /v0/chats` `{"text", "pairing_id", "signature"}` → `{"ok", "chat_id"}` : nouvelle conversation.
- `POST /v0/chats/{id}/messages` `{"text", "pairing_id", "signature"}` : message dans une conversation.
- `POST /v0/chats/{id}/delete` `{"pairing_id", "signature"}` : suppression (POST plutôt que DELETE, pour le pont Tor).
- Signatures : `champs("ona/message/v0", pairing_id, chat_id, text)` (`chat_id` vide pour une nouvelle conversation) et
  `champs("ona/delete/v0", pairing_id, chat_id)`. Texte : 1 à 2 000 caractères, sans fichier ni image.
- Les confirmations d'une conversation passent par `POST /v0/confirm` comme avant ; leurs `id` sont uniques sur
  toutes les conversations.

Le faux ordinateur rejoue la mission de démonstration (avocat) pour **toute** demande : c'est une simulation de
l'affichage, pas un agent.

## Routes du faux ordinateur seulement

- `POST /v0/mock/start` : démarre une mission de démonstration.
- `POST /v0/mock/reset` : efface la mission.
- `GET /v0/mock/pairing` : le texte du QR d'appairage (pour le coller dans le simulateur, qui n'a pas de caméra).

## Questions pour Hugo

1. Le téléphone parle-t-il à `ona-core` à travers `dispatch(json)` (mêmes commandes) ou à une API dédiée comme
   celle-ci ? Ici, l'ordinateur garde la main sur l'ordre des étapes et le téléphone ne fait que confirmer.
2. Qui avance la mission entre deux confirmations : `ona-core` seul, ou faut-il un « continuer » du téléphone ?
3. Montant en yoctoNEAR (chaîne décimale) : l'app affiche aussi la valeur en NEAR. D'accord ?
4. Signature et appairage (étape 3) : d'accord avec les octets signés et le code de vérification ci-dessus ?
   Côté ordinateur, il faut afficher le QR, montrer le code à 6 chiffres et garder la clé du téléphone.
5. `GET /v0/state` n'est pas encore authentifié : à l'étape 4, l'autorisation client Tor (restricted discovery)
   limiterait l'accès au `.onion` au téléphone appairé. À confirmer.
