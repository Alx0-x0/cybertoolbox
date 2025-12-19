# 🛡️ CyberToolBox
![CyberToolBox]([image-url](https://github.com/Alx0-x0/cybertoolbox/blob/main/screen/CYBERTOOLBOX-LOGO.png))

**CyberToolBox** est une suite d'outils d'analyse réseau et de cybersécurité fonctionnant entièrement dans votre navigateur (Client-Side). Conçu pour les développeurs, les administrateurs système et les passionnés de sécurité, avec une interface inspirée des terminaux "Cyberpunk".

## 🚀 Fonctionnalités

Le site regroupe 5 outils essentiels :

### 1. 🌐 DNS Analyser
Analysez les enregistrements DNS de n'importe quel domaine en temps réel.
- **Enregistrements supportés** : A, AAAA, MX, TXT, CNAME, NS, SOA.
- **Sécurité** : Analyse automatique et validation des protocoles **SPF**, **DKIM** et **DMARC**.
- **Géolocalisation** : Enrichissement automatique des IPs trouvées (A records).
- **Multi-Provider** : Choix entre Google DNS et Cloudflare.

### 2. 🌍 Geo IP
Localisez géographiquement une adresse IP.
- **Détails** : Pays, Région, Ville, FAI (ISP), ASN, Timezone.
- **Carte interactive** : Visualisation sur une carte (via Leaflet).
- **Mon IP** : Détection automatique de votre adresse IP publique.
- **Redondance** : Utilise plusieurs APIs pour garantir le résultat.

### 3. 📧 Header Analyser
Inspectez les en-têtes d'emails pour détecter le phishing et les problèmes de configuration.
- **Authentification** : Vérification visuelle de SPF, DKIM et DMARC.
- **Cheminement (Hops)** : Visualisation de la route prise par l'email avec détection des délais anormaux.
- **Score de Risque** : Calcul automatique d'un score de suspicion basé sur plusieurs critères techniques.

### 4. 🔑 Password Creator
Générez et auditez vos mots de passe.
- **Générateur** : Longueur personnalisable (1-256), symboles, exclusion de caractères similaires.
- **Audit de Force** : Calcul d'entropie et estimation du temps de craquage (Supercalculateur).
- **Vérification de Fuite** : Vérifie si le mot de passe est compromis via l'API *Have I Been Pwned* (méthode sécurisée k-Anonymity).

### 5. 🛠️ Swiss Knife
La boîte à outils du développeur.
- **Encodeurs/Décodeurs** : Base64, URL, JWT (JSON Web Token).
- **Réseau** : Calculateur CIDR (Sous-réseaux), Analyseur User-Agent.
- **Utilitaires** : Convertisseur Timestamp / Date, JSON Formatter/Minifier.
- **Cryptographie** : Hachage (SHA-256, SHA-512), Chiffrement AES-GCM (compatible WebCrypto & CryptoJS).
- **Markdown** : Éditeur avec prévisualisation en temps réel.

### 6. 🦠 VirusTotal Scanner
Analysez la réputation de fichiers et liens.
- **Scan** : Fichiers (Hash calculé localement), URLs, Domaines, IPs.
- **Interface** : Visualisation claire du score de risque et des détections antivirus.
- **API** : Utilisation de votre propre clé API VirusTotal (stockée localement).

## 💻 Installation & Utilisation

Ce projet est un site statique. Il ne nécessite **aucun serveur backend** (PHP, Node.js, Python, etc.).

1. **Cloner le dépôt** :
   ```bash
   git clone https://github.com/Alx0-x0/cybertoolbox.git
   ```
2. **Ouvrir le site** :
   - Double-cliquez simplement sur le fichier `index.html` à la racine.
   - Ou servez-le via un serveur local (ex: Live Server sur VS Code) pour une meilleure expérience.

## 🛠️ Technologies Utilisées

- **Frontend** : HTML5, CSS3 (Variables, Grid/Flexbox), JavaScript (ES6+).
- **Design** : Police *Share Tech Mono* (Google Fonts), Thème sombre "Terminal".
- **Librairies Externes (CDN)** :
  - FontAwesome (Icônes)
  - Leaflet (Cartes)
  - Marked (Markdown parsing)
  - CryptoJS (Fallback cryptographique pour HTTP)

## 🔗 APIs Utilisées

Ce projet repose sur des APIs publiques gratuites :
- **DNS** : Google DNS over HTTPS
- **GeoIP** : ipwho.is, ipapi.co, geojs.io
- **Fuites** : Have I Been Pwned API (Pwned Passwords)
- **Proxy CORS** : CodeTabs (pour VirusTotal)

## 👤 Auteur

Développé par **Alx0**.

---

*N'hésitez pas à mettre une étoile ⭐ sur le repo si cet outil vous est utile !*

