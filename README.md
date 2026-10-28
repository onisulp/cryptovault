# CryptoVault — Projet Intégrateur de Cryptographie Moderne

Système complet de messagerie chiffrée de bout en bout (E2EE), coffre-fort de fichiers hybride et laboratoire d'attaques cryptographiques.

> **Règle fondamentale du projet :** Réimplémentation mathématique intégrale « from scratch » des algorithmes fondamentaux (arithmétique modulaire, Euclide étendu, CRT, Miller-Rabin, RSA-OAEP, Diffie-Hellman, ECDH/ECDSA NIST P-256, HMAC, HKDF, PBKDF2, arbre de Merkle, PRNG et PKI).  
> Seuls les blocs bas niveau AES et le hachage SHA-256 standard s'appuient sur `cryptography` conformément aux consignes.

---

## 1. Arborescence du Projet

```
cryptovault/
├── cryptolib/         # Bibliothèque de primitives cryptographiques (codées from scratch)
│   ├── hashing.py     # Module 1 : Fonctions de hachage, HMAC RFC 2104, PBKDF2, Arbre de Merkle
│   ├── numtheory.py   # Module 2 : Euclide étendu, CRT, Miller-Rabin (k=40), premiers
│   ├── rsa.py         # Module 3 : RSA (clés 1024/2048, CRT speedup, OAEP SHA-256, signatures)
│   ├── dh.py          # Module 4 : Diffie-Hellman MODP 2048 (RFC 3526), HKDF (RFC 5869), Auth-DH
│   ├── ecc.py         # Module 5 : Weierstrass F_p, NIST P-256, ECDH, ECDSA (RFC 6979)
│   ├── symmetric.py   # Module 6 : César, Vigenère (cryptanalyse), OTP, AES (GCM, CBC, CTR, ECB)
│   ├── pki.py         # Module 7 : Certificats X.509, Root CA, Inter-CA, CRL, Keystore, Shamir (k,n)
│   └── prng.py        # Module 8 : LCG, Mersenne Twister MT19937, HMAC_DRBG NIST SP 800-90A
├── app/               # Module 9 : Application finale intégrée
│   ├── server.py      # Serveur passerelle, autorité intermédiaire, relais sécurisé
│   ├── client.py      # Client CLI, KeyStore chiffré, handshake TLS, anti-rejeu
│   ├── vault.py       # Coffre-fort de fichiers, enveloppe hybride, intégrité Merkle par blocs
│   ├── gui.py         # Interface Web interactive (Flask) et terminal CLI intégré
│   └── templates/     # Templates HTML / CSS pour l'interface visuelle
│       └── index.html
├── lab/               # Laboratoire d'attaques pédagogiques et benchmarks
│   ├── attack_collision_birthday.py   # Attaque d'anniversaire sur SHA-256 tronqué
│   ├── benchmark_numtheory.py         # Exp_mod vs pow(), piège de Carmichael vs Miller-Rabin
│   ├── attack_rsa_lab.py              # Pollard-rho, malléabilité, petit exposant e=3, facteurs partagés
│   ├── attack_dh_mitm.py              # Attaque Man-in-the-Middle de Mallory sur Diffie-Hellman
│   ├── attack_dh_bsgs.py              # Résolution du logarithme discret par Baby-Step Giant-Step
│   ├── attack_ecc_nonce.py            # Extraction de clé privée par réutilisation de nonce ECDSA
│   ├── attack_symmetric_lab.py        # Fuite visuelle ECB sur image BMP et bit-flipping CBC
│   ├── demo_pki_lab.py                # Démonstration rejets PKI & partage de secret de Shamir (3,5)
│   └── attack_prng_lab.py             # Prédiction LCG et clonage d'état du Mersenne Twister
├── tests/             # Suite complète de 65 tests unitaires et d'intégration
│   ├── test_hashing.py
│   ├── test_numtheory.py
│   ├── test_rsa.py
│   ├── test_dh.py
│   ├── test_ecc.py
│   ├── test_symmetric.py
│   ├── test_pki.py
│   ├── test_prng.py
│   └── test_integration_app.py
├── report/            # Rapport d'audit de sécurité officiel, présentations et diaporama
│   ├── CryptoVault — Rapport d'analyse de sécurité et d'audit cryptographique.pdf
│   ├── CryptoVault_Presentation.pptx
│   ├── CryptoVault_Presentation.odp
│   ├── slideshow.html
│   └── notes_de_soutenance_et_diapositives.md
├── requirements.txt   # Dépendances requises (cryptography, Flask)
├── .gitignore         # Fichiers et dossiers exclus du suivi Git
└── README.md
```

---

## 2. Prérequis et Installation

- **Python** : Version 3.10 ou supérieure (testé et validé sous Python 3.10, 3.11, 3.12, 3.13 et 3.14).
- **Système** : Linux, macOS ou Windows.

### Installation rapide :

```bash
# 1. Cloner ou décompresser le projet
cd cryptovault

# 2. Créer un environnement virtuel (recommandé)
python3 -m venv venv
source venv/bin/activate       # Sous Linux/macOS
# ou : venv\Scripts\activate   # Sous Windows

# 3. Installer les dépendances
pip install -r requirements.txt
```

---

## 3. Exécution de la Suite de Tests (65/65 validés)

Une seule commande lance l'ensemble des 65 tests validant chaque module unitaire, les vecteurs de référence officiels (RFC 4231, RFC 5869, RFC 3526, RFC 6979, NIST SP 800-90A) ainsi que l'intégration applicative de bout en bout :

```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```

---

## 4. Laboratoire d'Attaques Pédagogiques (`lab/`)

Chaque script reproduit une attaque concrète et illustre sa contre-mesure :

```bash
# 1. Collision d'anniversaire sur SHA-256 tronqué (Module 1)
python3 lab/attack_collision_birthday.py

# 2. Benchmark exp_mod et piège des nombres de Carmichael (Module 2)
python3 lab/benchmark_numtheory.py

# 3. Attaques sur RSA (Pollard-rho, homomorphisme, e=3, facteurs partagés) (Module 3)
python3 lab/attack_rsa_lab.py

# 4. Attaque Man-in-the-Middle de Mallory sur Diffie-Hellman (Module 4)
python3 lab/attack_dh_mitm.py

# 5. Attaque Baby-Step Giant-Step sur le logarithme discret (Module 4)
python3 lab/attack_dh_bsgs.py

# 6. Extraction de clé privée par réutilisation de nonce ECDSA (Module 5)
python3 lab/attack_ecc_nonce.py

# 7. Fuite visuelle du mode ECB sur image BMP et bit-flipping CBC (Module 6)
python3 lab/attack_symmetric_lab.py

# 8. Rejets stricts de la PKI et Partage de secret de Shamir (3 sur 5) (Module 7)
python3 lab/demo_pki_lab.py

# 9. Prédiction LCG et clonage d'état du Mersenne Twister MT19937 (Module 8)
python3 lab/attack_prng_lab.py
```

---

## 5. Utilisation de l'Application CryptoVault en Ligne de Commande (`app/`)

### A. Initialisation et supervision du serveur
```bash
# Initialiser la racine PKI et les certificats du serveur
python3 app/server.py init --data-dir .server_data

# Afficher l'état du serveur et la liste des utilisateurs enregistrés
python3 app/server.py status --data-dir .server_data
```

### B. Client de messagerie sécurisée (Handshake TLS éphémère & Anti-rejeu)
```bash
# Inscription d'un utilisateur et création de son KeyStore chiffré
python3 app/client.py register --username alice --password "SecretAlice123!" --keystore alice_ks.json

# Établissement de session éphémère ECDHE P-256 et envoi de message authentifié AES-GCM
python3 app/client.py test-session --username alice --password "SecretAlice123!" --keystore alice_ks.json --message "Bonjour CryptoVault !"
```

### C. Coffre-fort de fichiers chiffré (Arbre de Merkle & Multi-destinataires)
```bash
# 1. Ajouter et signer un fichier dans le coffre (avec découpage en blocs et arbre de Merkle)
python3 app/vault.py add --file document.pdf --user alice --keystore alice_ks.json --password "SecretAlice123!"

# 2. Lister les fichiers stockés dans le coffre
python3 app/vault.py list

# 3. Partager l'accès à un fichier avec Bob
python3 app/vault.py share --file document.pdf --user alice --keystore alice_ks.json --password "SecretAlice123!" --recipient-user bob --recipient-cert bob_cert.json

# 4. Extraire, déchiffrer et vérifier l'intégrité Merkle et la signature d'auteur
python3 app/vault.py get --file document.pdf --user bob --keystore bob_ks.json --password "SecretBob123!" --out document_recupere.pdf
```

---

## 6. Interface Visuelle (GUI Web) & Terminal Intégré

CryptoVault intègre une interface utilisateur moderne et réactive accessible directement via votre navigateur Web :

```bash
python3 app/gui.py
```
*Le serveur Web démarre et ouvre automatiquement http://127.0.0.1:5000 dans votre navigateur.*

### Fonctionnalités de l'interface visuelle :
- **Dashboard & PKI** : Visualisation dynamique de la hiérarchie de certificats (Root CA, Intermediate CA, certificats émis).
- **Messagerie E2EE** : Création d'utilisateurs, handshake TLS/ECDHE, chiffrement AES-256-GCM et simulation d'attaques par rejeu bloquées.
- **Coffre-fort Hybride** : Dépôt et partage de fichiers avec visualisation en direct de l'Arbre de Merkle (feuilles, nœuds intermédiaires, racine d'intégrité).
- **Terminal CLI Interactif** : Console intégrée permettant de tester n'importe quelle commande CryptoVault en direct.
- **Laboratoire d'Attaques** : Déclencheur des 9 scripts de tests d'intrusion avec affichage dynamique des résultats cryptanalytiques.

---

## 7. Rapports d'Audit, Soutenance et Outils de Présentation

Tous les documents officiels pour l'évaluation et la soutenance sont réunis dans le dossier `report/` :

1. **Rapport d'Audit & Sécurité Officiel** :
   - Fichier PDF complet : `report/CryptoVault — Rapport d'analyse de sécurité et d'audit cryptographique.pdf`

2. **Présentation de Soutenance (Diapositives)** :
   - Présentation PowerPoint officielle : `report/CryptoVault_Presentation.pptx`
   - Présentation OpenDocument : `report/CryptoVault_Presentation.odp`

3. **Diaporama Interactif Autonome & Notes de Soutenance** :
   - Diaporama HTML autonome : `report/slideshow.html` (ouvrable directement dans Firefox, Chrome ou Edge sans aucune dépendance).
   - Notes orales détaillées : `report/notes_de_soutenance_et_diapositives.md` (guide de présentation mot à mot pour l'orateur).

---

## 8. Fichiers et Données Sensibles Exclus du Dépôt

Le projet applique une politique stricte d'exclusion (via `.gitignore`) afin de garantir la propreté du dépôt et la confidentialité des secrets locaux :

- `.keystores/` et `*_ks.json` : Stockage des clés privées générées localement.
- `.server_data/` : Base de données runtime locale du serveur (mots de passe, certificats émis).
- `.vault_storage/` : Fichiers chiffrés locaux déposés dans le coffre-fort.
- `__pycache__/` et `*.pyc` : Fichiers de bytecode Python compilés.
- `lab/demo_*.bmp` / `lab/demo_*.png` : Fichiers d'images temporaires générés lors des démonstrations d'attaques.
