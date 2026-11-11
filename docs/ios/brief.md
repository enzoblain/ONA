# Brief iOS (reçu le 2026-11-10)

> Copie du brief transmis à Enzo pour la partie iOS. Document interne.

Salut ! Voici le brief pour ONA, notre projet pour la track Privacy du NEAR Hackathon. Le README est joint.

## ONA en deux phrases
Un agent IA qui tourne sur l'ordinateur de l'utilisateur pour des tâches sensibles (ex. trouver un avocat sans dire qui
on est). À la fin de chaque mission, il montre le relevé exact de qui a vu quoi.

## Où on en est
Rien n'est codé, il n'y a pas encore de dépôt. On a fait la recherche et un plan. Attention : les chiffres sont des
estimations, et plusieurs points techniques n'ont pas encore été testés. Pas de date butoir : si ce n'est pas prêt le
14/11, on finit après et on ne soumet pas. La charge totale est estimée à 41-71 jours-personne, donc la soumission au
hackathon est très improbable.

## Comment ça marche
- L'agent, le portefeuille et tous les secrets sont sur l'ordinateur (cœur en Rust).
- Le wallet NEAR ne sert qu'une fois, pour recharger. À l'envoi d'une mission, on confirme dans l'app, sans transaction :
  les jetons se dépensent en local.
- Un petit serveur en enclave fait relais vers NEAR AI, et deux contrats NEAR gèrent la réserve et le registre.

## Ta partie : l'app iOS
L'iPhone est une télécommande de l'ordinateur, via Tor : suivi de la mission et confirmations (choix du destinataire,
paiement).
Il ne contient ni agent, ni wallet, ni jetons, ni table de pseudonymes. Rien sur le disque à part l'appairage.
Pas de notifications push (un jeton APNs serait un identifiant stable) : l'app interroge l'ordinateur, et on découvre
les confirmations en l'ouvrant. Pas d'App Store en V1 : développement sur ton iPhone, puis éventuellement TestFlight.

## Dans l'ordre
1. Tester Tor sur un vrai iPhone, avant le reste. Connecter l'iPhone à une adresse .onion avec Arti (Tor en Rust)
   embarqué. C'est le plus gros risque de ta partie. D'après des extraits de recherche à revérifier, Arti sur iOS est dit
   expérimental, Tor.framework est revenu à C Tor en avril 2026, et BitChat embarque Arti. Note le temps de démarrage,
   la taille ajoutée au binaire, et si ça tient en usage réel.
2. Les écrans sur un serveur simulé : suivi de mission et confirmations. Je fournirai la spec du protocole et le serveur
   simulé. Tout ce qui vient du simulé doit être affiché « simulation » dans l'app.
3. L'appairage par QR : le QR contient l'adresse onion et la clé publique de l'ordinateur. Les confirmations sont signées
   avec une clé P-256 du Secure Enclave (CryptoKit).
4. Le pilotage réel via Tor. Si Tor sur iPhone reste instable, repli : l'iPhone sert seulement à valider par QR, sans
   réseau.

## Proposition à valider
Hugo a beaucoup plus de charge sur le backend (33 à 56 jours estimés). Si tu as de la marge, tu pourrais prendre aussi le
journal de mission et le simulateur de foule : ils ne demandent ni clé NEAR AI ni contrat.

## Règles
- Aucune clé ni secret dans le code ou une conversation. Tu n'as pas besoin de la clé NEAR AI.
- Versions figées, et les libs utilisées notées au fur et à mesure.
- Dans le texte public, on n'affirme rien sans test.
- Pas encore de git : on l'ouvrira plus tard, il faudra un historique réel.

## Questions posées
1. Ta machine est bien un Mac avec Xcode, et tu as un iPhone de test ? (Un compte Apple gratuit suffit pour commencer :
   3 appareils, profils de 7 jours. Le compte à 99 $/an seulement si on passe à TestFlight.)
2. Ça te va, l'iPhone en télécommande ? Le prix à payer : sans ordinateur allumé, ça ne marche pas.
3. OK ou non pour le journal et le simulateur ?
