"""
Laboratoire d'Attaques - Module 3 : Faiblesses et Attaques contre RSA mal employé
Démontre 4 attaques réelles sur RSA :
1. Factorisation d'un module 64 bits par l'algorithme rho de Pollard.
2. Malléabilité multiplicative du RSA scolaire (sans padding).
3. Attaque par racine cubique entière sur e = 3 sans padding (m^3 < n).
4. Attaque par facteur premier partagé via PGCD (faille d'entropie type Heninger 2012).
"""

import sys
import os
import math
import time
import secrets

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cryptolib.numtheory import (
    gcd,
    mod_inverse,
    exp_mod,
    generate_prime,
)
from cryptolib.rsa import (
    RSAPublicKey,
    RSAPrivateKey,
    generate_keypair,
    rsa_encrypt_int,
    rsa_decrypt_int_crt,
    rsa_encrypt,
    rsa_decrypt,
)

# 1. Attaque (a) : Factorisation Pollard-Rho d'un module RSA 64 bits

def pollard_rho(n: int) -> int:
    """Algorithme rho de Pollard pour la factorisation d'entiers."""
    if n % 2 == 0:
        return 2

    x = 2
    y = 2
    c = 1
    d = 1

    f = lambda val: (val * val + c) % n

    while d == 1:
        x = f(x)
        y = f(f(y))
        d = gcd(abs(x - y), n)
        if d == n:
            # Recommencer avec une constante différente
            c += 1
            x = 2
            y = 2
            d = 1

    return d


def attack_pollard_rho():
    print("=" * 75)
    print(" ATTAQUE (A) : FACTORISATION D'UN MODULE RSA 64 BITS (POLLARD-RHO)")
    print("=" * 75)

    # Création d'une clé RSA faible de 64 bits (p et q de 32 bits)
    p, _ = generate_prime(32)
    q, _ = generate_prime(32)
    while p == q:
        q, _ = generate_prime(32)

    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    d = mod_inverse(e, phi)
    secret_message = 123456789
    c = exp_mod(secret_message, e, n)

    print(f"Module RSA cible n (64 bits) : {n}")
    print(f"Exposant public e            : {e}")
    print(f"Message chiffré intercepté c  : {c}")

    t0 = time.perf_counter()
    factor_p = pollard_rho(n)
    elapsed = time.perf_counter() - t0

    factor_q = n // factor_p
    phi_recovered = (factor_p - 1) * (factor_q - 1)
    d_recovered = mod_inverse(e, phi_recovered)
    decrypted_msg = exp_mod(c, d_recovered, n)

    print(f"\n Factorisation réussie en {elapsed:.4f} secondes !")
    print(f"  Facteur premier p trouvé : {factor_p}")
    print(f"  Facteur premier q trouvé : {factor_q}")
    print(f"  Clé privée d retrouvée   : {d_recovered} (Authentique: {d == d_recovered})")
    print(f"  Message secret déchiffré : {decrypted_msg} (Authentique: {decrypted_msg == secret_message})")
    print("\nContre-mesure : Utiliser des modules n d'au moins 2048 bits (sécurité 112 bits)")
    print("ou 3072 bits (sécurité 128 bits), rendant Pollard-rho et le crible NFS impraticables.")

# 2. Attaque (b) : Malléabilité du RSA scolaire (sans padding)

def attack_malleability():
    print("\n" + "=" * 75)
    print(" ATTAQUE (B) : MALLÉABILITÉ DU RSA SCOLAIRE SANS PADDING")
    print("=" * 75)
    pub, priv = generate_keypair(bits=512)

    # Scénario : Alice chiffre un montant de virement m1 = 100 €
    m1 = 100
    c1 = rsa_encrypt_int(m1, pub)

    # L'attaquant intercepte c1. Il ne connaît pas la clé privée d.
    # Il souhaite multiplier secrètement le virement par 5 !
    factor = 5
    c_factor = rsa_encrypt_int(factor, pub)  # Chiffre 5 avec la clé publique

    # Par homomorphisme multiplicatif : c' = c1 * c_factor mod n
    c_tampered = (c1 * c_factor) % pub.n

    # La banque déchiffre c'
    m_decrypted = rsa_decrypt_int_crt(c_tampered, priv)

    print(f"Montant initial Alice            : {m1} €")
    print(f"Facteur malveillant injecté       : ×{factor}")
    print(f"Montant déchiffré par la banque  : {m_decrypted} €")
    print(f"Résultat altéré avec succès       : {m_decrypted == m1 * factor} (100 * 5 = 500 €)")
    print("\nContre-mesure : Le remplissage OAEP (Optimal Asymmetric Encryption Padding) !")
    print("OAEP rend le chiffrement aléatoire et non-malléable (sécurité IND-CCA2).")


# 3. Attaque (c) : Petit message et petit exposant e = 3 sans padding

def integer_cube_root(n: int) -> int:
    """Calcule la racine cubique entière exacte par dichotomie."""
    low = 0
    high = n
    while low <= high:
        mid = (low + high) // 2
        cube = mid * mid * mid
        if cube == n:
            return mid
        elif cube < n:
            low = mid + 1
        else:
            high = mid - 1
    return high


def attack_small_e():
    print("\n" + "=" * 75)
    print(" ATTAQUE (C) : RACINE CUBIQUE DIRECTE SUR e = 3 SANS PADDING")
    print("=" * 75)
    # Clé publique de 1024 bits avec e = 3
    pub, _ = generate_keypair(bits=1024, e=3)

    # Message court (ex: clé AES de 16 octets = 128 bits)
    secret_text = "CryptoKey128bits"
    m = int.from_bytes(secret_text.encode("utf-8"), "big")

    # Comme m < 2^128, m^3 < 2^384 << n (1024 bits) : AUCUNE RÉDUCTION MODULO N !
    c = exp_mod(m, 3, pub.n)

    print(f"Longueur du module n       : {pub.bit_length} bits")
    print(f"Longueur de m              : {m.bit_length()} bits")
    print(f"Longueur de m^3 (sans mod) : {(m**3).bit_length()} bits (< {pub.bit_length} bits)")

    # Attaque : simple racine cubique entière sur c !
    t0 = time.perf_counter()
    m_recovered = integer_cube_root(c)
    elapsed = time.perf_counter() - t0

    recovered_text = m_recovered.to_bytes((m_recovered.bit_length() + 7) // 8, "big").decode("utf-8")

    print(f"\n Message intercepté et cassé en {elapsed * 1000:.3f} ms sans clé privée !")
    print(f"  Texte retrouvé : '{recovered_text}' (Authentique: {recovered_text == secret_text})")
    print("\nContre-mesure : Utiliser e = 65537 (Fermat F4) et TOUJOURS appliquer OAEP.")


# 4. Attaque (d) : Facteur premier partagé via PGCD (Heninger et al. 2012)

def attack_shared_prime():
    print("\n" + "=" * 75)
    print(" ATTAQUE (D) : FACTEUR PREMIER PARTAGÉ PAR MAUVAIS ALÉA (PGCD)")
    print("=" * 75)

    # Deux entités (ex: deux routeurs IoT rebootés sans entropie) partagent un facteur p
    shared_p, _ = generate_prime(512)
    q1, _ = generate_prime(512)
    q2, _ = generate_prime(512)

    n1 = shared_p * q1
    n2 = shared_p * q2
    e = 65537

    print(f"Clé publique Routeur 1 : n1 = {n1.bit_length()} bits")
    print(f"Clé publique Routeur 2 : n2 = {n2.bit_length()} bits")

    # Attaque : calcul du PGCD entre les deux modules publics
    t0 = time.perf_counter()
    recovered_p = gcd(n1, n2)
    elapsed = time.perf_counter() - t0

    recovered_q1 = n1 // recovered_p
    phi1 = (recovered_p - 1) * (recovered_q1 - 1)
    d1 = mod_inverse(e, phi1)

    print(f"\n Facteur commun extrait par PGCD en {elapsed * 1000:.3f} ms !")
    print(f"  Facteur partagé p : {recovered_p == shared_p}")
    print(f"  Clé privée Routeur 1 reconstruite instantanément !")
    print("\nContre-mesure : Générateurs pseudo-aléatoires cryptographiques (CSPRNG)")
    print("correctement ensemencés (Module 8).")


def main():
    attack_pollard_rho()
    attack_malleability()
    attack_small_e()
    attack_shared_prime()


if __name__ == "__main__":
    main()
