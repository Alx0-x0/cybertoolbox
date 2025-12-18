# Changelog

## [released] - 2024-12-19

### ✨ Nouveautés
- **VirusTotal Scanner** : Nouvel outil pour analyser Fichiers (Hash), URLs, Domaines et IPs via l'API VirusTotal.
  - Support du Drag & Drop pour calcul automatique du SHA-256 localement.
  - Visualisation du score de risque avec jauge animée.
- **Swiss Knife** : Ajout de 4 nouveaux onglets :
  - **JWT Decoder** : Décodage de tokens sans envoi serveur.
  - **Timestamp Converter** : Conversion Unix Timestamp <-> Date.
  - **CIDR Calculator** : Calcul de plages IP et masques de sous-réseau.
  - **User Agent Parser** : Analyse détaillée des navigateurs/OS.
- **Geo IP** : Ajout d'un bouton pour détecter et localiser automatiquement votre IP publique.
- **Password Creator** : Ajout d'une estimation du temps de craquage par un supercalculateur.
- **DNS Analyser** :
  - Choix du résolveur DNS (Google DNS ou Cloudflare).
  - Rafraîchissement automatique lors du changement de fournisseur.
  - Support amélioré pour l'analyse SPF/DMARC avec Cloudflare.

### 🎨 Interface & UX
- **Transitions** : Ajout d'animations fluides entre les pages (`transition.js`).
- **Header** : Ajout d'un indicateur visuel "Télécharge moi" pointant vers le lien GitHub.
- **Design** : Améliorations globales du style (Cyberpunk/Terminal), animations de chargement.

### 🐛 Correctifs
- Correction de l'affichage des sélecteurs dans l'outil DNS.
- Gestion des guillemets dans les réponses TXT de Cloudflare.