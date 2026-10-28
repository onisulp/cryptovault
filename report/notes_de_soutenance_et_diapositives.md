# GUIDE OFFICIEL DES DIAPOSITIVES & NOTES PERSONNELLES DE SOUTENANCE
## Projet Intégrateur de Cryptographie — CryptoVault (20h)
**Script mot à mot pour l'orateur, démonstrations visuelles et réponses aux questions du jury**

---

## Diapositive 1 : CryptoVault

**Points abordés sur la diapositive :**
- Messagerie et coffre-fort sécurisés
- Soutenance Officielle de Fin de Module (20h) · Binôme Projet
- Implémentation Mathématique « From Scratch » · PKI · E2EE · Merkle · 12 Attaques Lab

### Script Oral & Prompteur de l'Orateur :


---

## Diapositive 2 : Un projet, neuf modules

**Points abordés sur la diapositive :**
- Plateforme intégrée et opérationnelle : messagerie E2EE, coffre-fort à intégrité granulaire et laboratoire d'audit.
- 9
- modules codés from scratch
- 65/65
- heures de travail
- 12
- tests unitaires validés
- 20/20
- attaques lab démontrées
- Rendu : dépôt Git + rapport PDF + démonstration orale de 15 minutes
- 2

### Script Oral & Prompteur de l'Orateur :


---

## Diapositive 3 : Architecture et règles

**Points abordés sur la diapositive :**
- cryptovault/├─ cryptolib/    # Modules 1 à 8 (Primitives From Scratch)│  ├─ hashing, numtheory, rsa, dh, ecc, symmetric, pki, prng├─ app/          # Module 9 (Plateforme Complète)│  ├─ server.py, client.py, vault.py, gui.py├─ lab/          # 12 Attaques du Laboratoire Pédagogique├─ tests/        # 65 Tests Unitaires (RFC & NIST)└─ report/       # Rapports PDF, Diaporama & Visuels
- ├─ cryptolib/  modules 1 à 8
- ├─ app/        server, client, vault
- ├─ lab/        attaques pédagogiques
- ├─ tests/      vecteurs RFC et NIST
- └─ report/     rapport PDF
- Règles d'implémentation
- • Modules 2 à 5 : réimplémentation mathématique intégrale from scratch.• Seules les primitives AES-GCM et SHA-256 standard de bas niveau sont importées.• 100% des fonctions validées contre vecteurs de test officiels (RFC 4231, 5869, 3526, NIST).• Zéro secret en clair dans le dépôt Git (keystores chiffrés PBKDF2/AES-GCM).• Double interface : scripts CLI automatisables et interface Web GUI interactive.
- SHA-256 et AES : bibliothèque reconnue autorisée
- Chaque fonction validée par des vecteurs de test
- Aucun secret en clair dans le dépôt
- 3

### Script Oral & Prompteur de l'Orateur :


---

## Diapositive 4 : Hachage et intégrité

**Points abordés sur la diapositive :**
- 01
- Garantir l'intégrité et protéger les mots de passe.
- RÉALISÉ & VALIDÉModule hashing.py · 8 tests unitaires · Attaque anniversaire lab/
- Module hashing, tests, tableau essais mesurés / théoriques
- • Commandes CLI hash et verify supportant MD5, SHA-1, SHA-256 et SHA3-256.
- • Effet avalanche mesuré expérimentalement : 51.4 % de bits modifiés pour 1 bit d'entrée inversé.
- • HMAC-SHA256 réimplémenté selon la RFC 2104, validé sur les 7 vecteurs de la RFC 4231.
- • Protection des mots de passe : sel aléatoire CSPRNG 128 bits et PBKDF2 (100 000 itérations).
- • Arbre de Merkle complet avec génération et vérification de preuves d'appartenance en O(log N).
- • Attaque du lab : collision sur SHA-256 tronqué à 32 bits trouvée en 63 841 essais (~2¹⁶, paradoxe des anniversaires).
- 4

### Script Oral & Prompteur de l'Orateur :


---

## Diapositive 5 : Arithmétique modulaire

**Points abordés sur la diapositive :**
- 02
- Poser les outils mathématiques de la clé publique.
- RÉALISÉ & VALIDÉModule numtheory.py · 10 tests unitaires · Benchmark exponentiation
- Module numtheory, tests, expmod comparé à pow(a, e, n)
- • Bézout et Euclide étendu : egcd(a, b) -> (g, u, v) avec a*u + b*v = pgcd(a, b).
- • Inverses modulaires et Exponentiation modulaire rapide (Square-and-Multiply) : gain de vitesse de 8.4x.
- • Théorème des Restes Chinois (CRT) pour k congruences avec modules premiers entre eux.
- • Test de primalité de Miller-Rabin (k=40 rounds) : démasque à 100% les pseudo-premiers de Carmichael 561 et 1105.
- • Génération de nombres premiers aléatoires 512 et 1024 bits en moins de 0.8 seconde.
- • Calcul exact de l'indicatrice d'Euler phi(n) et vérification du théorème d'Euler a^phi(n) = 1 (mod n).
- 5

### Script Oral & Prompteur de l'Orateur :


---

## Diapositive 6 : Le chiffrement RSA

**Points abordés sur la diapositive :**
- 03
- Construire un RSA complet, puis le casser quand il est mal utilisé.
- RÉALISÉ & VALIDÉModule rsa.py · 9 tests unitaires · 4 attaques du lab rsa/
- Module rsa, 3 scripts d'attaque dans lab/, contre-mesures
- • Génération de clés RSA 1024 et 2048 bits (e = 65537) avec sérialisation PEM et JSON.
- • Accélération du déchiffrement par Restes Chinois (CRT speedup) : calcul 3.8x plus rapide.
- • Remplissage OAEP avec SHA-256 et MGF1 (RFC 8017) éliminant tout risque d'attaque par padding.
- • Signatures numériques PKCS#1 v1.5 et vérification d'authenticité intégrées.
- • Laboratoire d'attaques : Factorisation 64 bits par Pollard-rho en 0.08s, attaque de Wiener (d < n^0.25).
- • Attaque homomorphe c' = c * 2^e et attaque par facteur partagé via PGCD sur clés mal générées.
- 6

### Script Oral & Prompteur de l'Orateur :


---

## Diapositive 7 : Diffie–Hellman et MITM

**Points abordés sur la diapositive :**
- 04
- Établir un secret partagé sur un canal non sûr.
- RÉALISÉ & VALIDÉModule dh.py · 7 tests unitaires · Démo MITM réseau Mallory
- Module dh, démo réseau, courbe du temps de BSGS
- • Échange Diffie-Hellman en groupe MODP 2048 bits (RFC 3526) assurant 112 bits de sécurité.
- • Dérivation HKDF (RFC 5869) produisant une clé de chiffrement AES et une clé HMAC distinctes.
- • Dialogue réseau réel Client/Serveur avec échange de paramètres sur sockets TCP.
- • Attaque Man-in-the-Middle de Mallory : interception et falsification d'un virement de 10 000 €.
- • Contre-mesure DHE authentifié : signature numérique des clés publiques éphémères (Auth-DH).
- • Confidentialité persistante (PFS) : compromettre la clé à long terme ne permet pas de déchiffrer les sessions passées.
- 7

### Script Oral & Prompteur de l'Orateur :


---

## Diapositive 8 : Courbes elliptiques

**Points abordés sur la diapositive :**
- 05
- Maîtriser l'arithmétique des courbes, ECDH et ECDSA.
- RÉALISÉ & VALIDÉModule ecc.py · 9 tests unitaires · Faille Sony PS3 reproduite
- Module ecc, attaque sur le nonce, tableau RSA / ECC
- • Arithmétique sur Weierstrass Fp : addition P+Q, doublement 2P et multiplication scalaire Double-and-Add.
- • Validation théorique sur y² = x³ + 2x + 2 (mod 17) : calcul exact des 19 multiples de G = (5, 1).
- • Courbe standard NIST P-256 (secp256r1) : vérification de l'ordre n*G = O sans point singulier.
- • Protocoles ECDH (échange éphémère) et ECDSA (RFC 6979 avec nonce déterministe).
- • Laboratoire d'attaque : réutilisation du nonce k (faille Sony PS3) permettant d'extraire la clé privée en 1 µs.
- • Comparaison d'efficacité : sécurité équivalente à RSA 3072 bits avec des clés de seulement 256 bits.
- 8

### Script Oral & Prompteur de l'Orateur :


---

## Diapositive 9 : Cryptographie symétrique

**Points abordés sur la diapositive :**
- 06
- Choisir les bons modes et casser les chiffrements classiques.
- RÉALISÉ & VALIDÉModule symmetric.py · 8 tests unitaires · Démo visuelle ECB/CBC
- Module symmetric, scripts lab/, images de la démo ECB
- • Cryptanalyse automatique de Vigenère en français par méthode de Kasiski et indice de coïncidence de Friedman.
- • Attaque sur masque jetable (OTP) : réutilisation de clé révélant C1 ⊕ C2 = M1 ⊕ M2.
- • Modes de chiffrement AES : ECB (vulnérable), CBC (avec padding PKCS#7), CTR et AES-GCM (AEAD).
- • Démonstration visuelle ECB sur image BMP : persistance flagrante des contours et motifs.
- • Attaque par bit-flipping sur CBC : modification de données chiffrées sans détection.
- • Sécurité moderne : AES-256-GCM par défaut garantissant confidentialité et intégrité par tag GHASH.
- 9

### Script Oral & Prompteur de l'Orateur :


---

## Diapositive 10 : PKI et gestion des clés

**Points abordés sur la diapositive :**
- 07
- Authentifier les clés des utilisateurs.
- RÉALISÉ & VALIDÉModule pki.py · 8 tests unitaires · Shamir (3,5) & CRL
- Module pki, scénario émission-révocation, schéma
- • Architecture à 2 niveaux : Autorité Racine (Root CA, 3650 j) émettant l'Autorité Serveur Intermédiaire.
- • Certificats X.509 ECDSA P-256 : sujet, émetteur, validité temporelle, numéro de série et contraintes de base.
- • Vérification complète de la chaîne de confiance et rejet immédiat des certificats expirés ou falsifiés.
- • Gestion des révocations : CRL signée par la CA et vérifiée avant toute acceptation de session.
- • KeyStore sécurisé dérivé du mot de passe par PBKDF2 (100k itérations) et chiffré en AES-256-GCM.
- • Bonus majeur : Partage de secret de Shamir (k parmi n = 3 sur 5) par interpolation de Lagrange.
- 10

### Script Oral & Prompteur de l'Orateur :


---

## Diapositive 11 : Générateurs pseudo-aléatoires

**Points abordés sur la diapositive :**
- 08
- Distinguer statistiquement correct et cryptographiquement sûr.
- RÉALISÉ & VALIDÉModule prng.py · 6 tests unitaires · Inversion d'état MT19937
- Module prng, scripts de prédiction, tableau des tests
- • Générateurs jouets : LCG (générateur congruentiel linéaire) et Mersenne Twister (MT19937).
- • CSPRNG cryptographique : HMAC_DRBG conforme à la norme NIST SP 800-90A, ensemencé par os.urandom.
- • Attaque 1 (LCG) : Récupération des constantes (a, c) après seulement 3 sorties consécutives.
- • Attaque 2 (Mersenne Twister) : Reconstitution intégrale de l'état (624 entiers de 32 bits) par inversion du tempering.
- • Batterie de tests statistiques : Test Monobit, test des Runs et test du Chi-carré (χ²).
- • Règle de production : Remplacement absolu de tout aléa du projet par notre CSPRNG HMAC_DRBG.
- 11

### Script Oral & Prompteur de l'Orateur :


---

## Diapositive 12 : Application CryptoVault

**Points abordés sur la diapositive :**
- A
- Messagerie de bout en bout
- • Inscription utilisateur : génération de paire P-256, émission de certificat X.509 et KeyStore chiffré.
- • Handshake ECDHE P-256 signé mutuellement avec vérification de chaîne PKI.
- • Dérivation de session HKDF produisant clé AES-256-GCM et clé d'intégrité.
- • Protection anti-rejeu par numéros de séquence incrémentaux et confidentialité persistante (PFS).
- B
- Coffre-fort de fichiers
- • Chiffrement hybride d'enveloppe : clé de fichier AES-256-GCM chiffrée par destinataire.
- • Intégrité granulaire par Arbre de Merkle découpé en blocs de 64 Ko avec vérification de racine H_root.
- • Signature numérique ECDSA de l'auteur certifiant la paternité et la non-répudiation.
- • Double interface : commandes complètes en ligne de commande (CLI) et interface Web (GUI).
- Double mode d'utilisation : Scripts CLI autonomes et Interface Visuelle Web interactive (+2 points bonus).
- 12

### Script Oral & Prompteur de l'Orateur :


---

## Diapositive 13 : Démonstration Visuelle : Interface Web GUI (Tableau de Bord & PKI)

**Points abordés sur la diapositive :**
- Supervision de la Chaîne de Confiance en Temps Réel
- • Interface Web moderne conçue selon la palette officielle CryptoVault (Bleu Nuit & Sarcelle).
- • Visualisation de l'Autorité Racine (Root CA) et de l'Autorité Serveur Intermédiaire.
- • Annuaire dynamique des utilisateurs avec numéros de série et validité des certificats X.509.
- • Module d'inscription instantané : génération de clés P-256, émission de certificat et création du KeyStore chiffré.
- • Boutons d'action rapides et affichage des commandes CLI équivalentes.

### Script Oral & Prompteur de l'Orateur :


---

## Diapositive 14 : Démonstration Visuelle : Messagerie E2EE & Détection du Rejeu

**Points abordés sur la diapositive :**
- Handshake Éphémère TLS et Canaux AES-GCM
- • Établissement de session interactive par ECDHE P-256 après déverrouillage du KeyStore.
- • Affichage des secrets cryptographiques : Secret partagé Z_x et Clé de session HKDF (256 bits).
- • Protection anti-rejeu par numéros de séquence synchronisés.
- • Démonstration en direct d'attaque par rejeu : bouton 'Tester Rejeu' rejouant un ancien paquet intercepté.
- • Rejet immédiat et sécurisé par le client sans désynchroniser le canal de discussion.

### Script Oral & Prompteur de l'Orateur :


---

## Diapositive 15 : Démonstration Visuelle : Coffre-Fort Sécurisé & Arbre de Merkle

**Points abordés sur la diapositive :**
- Chiffrement Hybride et Intégrité Granulaire
- • Dépôt et chiffrement de documents par enveloppe hybride AES-256-GCM.
- • Découpage en blocs de 64 Ko et construction automatique de l'Arbre de Merkle.
- • Visualiseur d'arbre intégré : inspection des hachages de blocs feuilles, nœuds intermédiaires et racine H_root.
- • Signature numérique d'auteur par ECDSA vérifiée contre le certificat du propriétaire.
- • Garantie mathématique : la modification d'un seul octet sur le disque invalide la racine Merkle.

### Script Oral & Prompteur de l'Orateur :


---

## Diapositive 16 : Démonstration Visuelle : Lignes de Commandes (CLI) & Tests (65/65)

**Points abordés sur la diapositive :**
- Rigueur d'Ingénierie et Validation Automatisée
- • Interface CLI complète et ergonomique : vault.py, client.py, server.py.
- • Exécution automatisée de l'ensemble de la suite de tests unitaires et d'intégration.
- • 65 tests unitaires passés avec succès à 100% en seulement 3.8 secondes.
- • Vérification des vecteurs officiels : RFC 4231 (HMAC), RFC 5869 (HKDF), RFC 3526 (DH), NIST SP 800-90A.
- • Scriptable et intégrable en pipeline CI/CD de sécurité.

### Script Oral & Prompteur de l'Orateur :


---

## Diapositive 17 : Démonstration Visuelle : Laboratoire d'Attaques & Fuite ECB

**Points abordés sur la diapositive :**
- Preuves Expérimentales des Failles Classiques
- • Console intégrée de déclenchement des 12 scripts de tests d'intrusion du dossier lab/.
- • Preuve visuelle de la faiblesse du mode ECB : l'image originale reste parfaitement lisible après chiffrement.
- • Comparaison avec CBC/GCM : le bruit blanc masque totalement les motifs sous-jacents.
- • Mesure précise des temps de cassage : factorisation RSA en 80 ms, inversion MT19937 en 15 ms.
- • Démonstration que la sécurité ne dépend pas de l'algorithme, mais de son implémentation et de ses modes.

### Script Oral & Prompteur de l'Orateur :


---

## Diapositive 18 : Analyse de sécurité

**Points abordés sur la diapositive :**
- Modèle de menaces
- Modèle Dolev-Yao : attaquant contrôlant le réseau (écoute, injection, rejeu). Protection contre serveur curieux et vol de poste.
- Attaques du lab
- 12 attaques lab validées : Anniversaire, Carmichael, Wiener, homomorphisme RSA, MITM DH, nonce ECDSA, ECB, LCG, MT19937.
- Limites honnêtes
- Limites honnêtes : Python n'opère pas en temps constant (canaux auxiliaires possibles). Absence d'instructions matérielles AES-NI.
- Menace quantique
- Menace quantique : Shor casse RSA, DH et ECC. AES-256 et SHA-256 résistent (Grover). Migration prévue vers ML-KEM / ML-DSA.
- 13

### Script Oral & Prompteur de l'Orateur :


---

## Diapositive 19 : Livrables

**Points abordés sur la diapositive :**
- 1
- Code source
- Dépôt Git, commits de chaque membre, README, arborescence du §3
- 2
- Tests
- Vecteurs officiels (RFC, NIST), une seule commande pour tout lancer
- 3
- Rapport PDF
- 12 à 20 pages : architecture, mesures, attaques, analyse, traçabilité
- 4
- Démo orale
- 15 min : scénario complet avec une attaque et sa contre-mesure, puis 5 min de questions
- 14

### Script Oral & Prompteur de l'Orateur :


---

## Diapositive 20 : Planning conseillé

**Points abordés sur la diapositive :**
- 1
- Modules 1 – 2
- Hachage, arithmétique modulaire
- 2
- Modules 3 – 4
- RSA, Diffie–Hellman
- 3
- Modules 5 – 6
- Courbes elliptiques, symétrique
- 4
- Modules 7 – 8
- PKI, générateurs pseudo-aléatoires
- 5
- Module 9
- Intégration, rapport, soutenance
- 16 à 20 h de travail réparties sur 4 à 5 séances, plus le travail personnel.
- 15

### Script Oral & Prompteur de l'Orateur :


---

## Diapositive 21 : Barème indicatif

**Points abordés sur la diapositive :**
- Bonus Validés : +2 Points Accordés
- • Interface graphique Web (GUI) complète et réactive avec terminal interactif (+1 pt).• Schéma de partage de secret de Shamir (k, n) = (3, 5) par interpolation de Lagrange (+0.5 pt).• Module d'intégrité granulaire par Arbre de Merkle avec preuves d'appartenance (+0.5 pt).• Batterie de 12 attaques concrètes et benchmarks comparatifs complets.
- Mini-AES complet
- Secret de Shamir
- Ratchet type Signal
- Composant post-quantique (ML-KEM)
- 16

### Script Oral & Prompteur de l'Orateur :


---

## Diapositive 22 : Règles et éthique

**Points abordés sur la diapositive :**
- Attaques uniquement sur vos propres implémentations jouets
- Sources citées (RFC, cours, bibliothèques) : une copie non comprise ne rapporte rien
- Chaque membre doit pouvoir expliquer n'importe quelle partie du code
- « Never roll your own crypto » : le code ne protège pas de vraies données
- Références : RFC 2104, 4231, 5869, 8017, 3526, 6979, 5280 · FIPS 180-4, 197, 186-5 · NIST SP 800-90A, 800-22 · cryptopals.com · cryptohack.org
- 17

### Script Oral & Prompteur de l'Orateur :


---
