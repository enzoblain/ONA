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
- Étape 3 : chaque confirmation sera signée par la clé P-256 du Secure Enclave (champ `signature` réservé).

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

## `POST /v0/confirm`

```json
{ "id": "c-3", "decision": "accept | reject", "firm": "cabinet-b", "digest": "<sha256 hex>", "signature": null }
```

- `firm` : obligatoire pour `recipient` accepté.
- `digest` : obligatoire pour `payment` accepté. **Le téléphone recalcule le condensé** à partir de `to` et `amount`
  (même octets qu'`ona-core` : longueur de `to` en u32 petit-boutiste, `to` en UTF-8, `amount` en u128
  petit-boutiste, puis SHA-256) et refuse d'afficher un paiement dont le condensé ne correspond pas.
- Réponse : `{"ok": true, "mode": "mock"}` ou `{"ok": false, "error": "…", "mode": "mock"}`. Une confirmation dont
  `id` n'est plus celle attendue est refusée (`"stale confirmation"`).

## Routes du faux ordinateur seulement

- `POST /v0/mock/start` : démarre une mission de démonstration.
- `POST /v0/mock/reset` : efface la mission.

## Questions pour Hugo

1. Le téléphone parle-t-il à `ona-core` à travers `dispatch(json)` (mêmes commandes) ou à une API dédiée comme
   celle-ci ? Ici, l'ordinateur garde la main sur l'ordre des étapes et le téléphone ne fait que confirmer.
2. Qui avance la mission entre deux confirmations : `ona-core` seul, ou faut-il un « continuer » du téléphone ?
3. Montant en yoctoNEAR (chaîne décimale) : l'app affiche aussi la valeur en NEAR. D'accord ?
4. Signature (étape 3) : sur quels octets ? Proposition : `id`, `decision`, puis `firm` ou `digest`.
