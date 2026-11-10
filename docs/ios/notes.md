# Notes iOS — état, questions ouvertes

Document interne. Dernière mise à jour : 2026-11-10 (après début du spike Tor).

## Environnement constaté (2026-11-10)

| | État |
|---|---|
| Mac | macOS 27.2 |
| Xcode | Seul Xcode-beta 27.0 (27A5194q) est installé. |
| iPhone de test | iPhone 16 (iPhone17,3), déjà appairé avec Xcode |
| Rust | rustc / cargo 1.97.1, cibles `aarch64-apple-ios` et `aarch64-apple-ios-sim` installées |
| C Tor | 0.4.9.16 (Homebrew), pour le `.onion` de test |
| Compte Apple dans Xcode bêta | Ajouté ; `xcode-select` pointe sur Xcode bêta ; Mode développeur activé sur l'iPhone. |
| Réseau | Un réseau utilisé le 2026-11-10 semblait bloquer Tor ; un autre le laisse passer (voir `tor-spike.md`). |

Limite : un Xcode bêta ne permet pas d'envoyer sur TestFlight. Il faudra la version stable avant.

## Brouillon de réponses au brief (non envoyé)

**Q1.** Oui : Mac avec Xcode 27 bêta, iPhone 16 de test. Je commence avec un compte gratuit.

**Q2.** Oui pour la télécommande (le README liste déjà « l'ordinateur doit être allumé » parmi les limites).

**Q3.** Plutôt oui, mais après le test Tor : si Arti ne tient pas sur iPhone, la partie iOS grossit. Il faut aussi une
définition du « simulateur de foule » (absent du README). Le journal est dans `ona-core` (Rust) : interface à fixer avec
Hugo.

## Questions ouvertes à régler avec l'équipe

1. **Démarrage de Tor à chaque ouverture.** Sans push et avec la suspension en arrière-plan, Tor redémarre presque à
   chaque ouverture. Garder le cache d'Arti (consensus, descripteurs) accélère le démarrage, mais c'est un fichier sur
   le disque, alors que la règle dit « rien sur le disque à part l'appairage ». À trancher.
2. **Clé du téléphone à l'appairage.** Le QR va de l'ordinateur vers le téléphone. Comment l'ordinateur reçoit-il la
   clé publique Secure Enclave du téléphone ? Proposition : à la première connexion Tor, avec un code de vérification
   affiché des deux côtés. À mettre dans la spec du protocole.
3. **Accès restreint au .onion.** Proposition : autorisation client Tor (restricted discovery) pour que seul le téléphone
   appairé puisse joindre l'onion. La clé correspondante ferait partie de l'appairage (Keychain).
4. **Repli QR seul.** Si le téléphone répond par QR, l'ordinateur a besoin d'une caméra ; sinon, un code court à
   recopier.
5. **.onion de test pour l'étape 1.** Peut être monté sur le Mac avec C Tor, sans attendre `ona-core`.

## Affirmations de recherche non vérifiées

- Arti est dit expérimental sur iOS.
- Tor.framework serait revenu à C Tor en avril 2026.
- BitChat embarquerait Arti.
- Vérifié le 2026-11-10 : `arti-client` 0.48.0 compile pour iOS, à condition de corriger `sysinfo` 0.38.4.

## Spike Tor (étape 1) : en cours

Code, choix et constats : `tor-spike.md`. Le 2026-11-10, l'iPhone 16 a joint le `.onion` de test en cellulaire avec
Arti embarqué (démarrage à chaud 714 ms, cache 10,8 Mo, une seule série). Manquent : démarrage à froid, changement
de réseau, arrière-plan long.

## Mesures

Voir `tor-spike.md` (une seule série sur l'iPhone le 2026-11-10).
