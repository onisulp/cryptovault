"""
Laboratoire d'Attaques - Module 4 : Résolution du Logarithme Discret (Baby-Step Giant-Step)
Objectif : Casser Diffie–Hellman sur de petits nombres premiers (20 à 40 bits)
par l'algorithme des Pas de Bébé / Pas de Géant (Shanks, BSGS).
Mesure du temps d'exécution et comparaison avec la complexité théorique O(sqrt(p)).
"""

import sys
import os
import math
import time
import secrets

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cryptolib.numtheory import exp_mod, mod_inverse, generate_prime


def baby_step_giant_step(g: int, h: int, p: int) -> int:
    """
    Résout le problème du logarithme discret g^x ≡ h (mod p) via Shanks BSGS.
    Complexité temporelle : O(sqrt(p)) multiplications
    Complexité spatiale  : O(sqrt(p)) éléments en table de hachage
    """
    m = math.isqrt(p) + 1

    # 1. Pas de bébé (Baby steps) : table des g^j mod p pour 0 <= j < m
    table = {}
    cur = 1
    for j in range(m):
        table[cur] = j
        cur = (cur * g) % p

    # 2. Facteur géant : g^(-m) mod p
    # g^m mod p
    g_m = exp_mod(g, m, p)
    factor = mod_inverse(g_m, p)

    # 3. Pas de géant (Giant steps) : recherche de h * (g^-m)^i dans la table
    gamma = h
    for i in range(m):
        if gamma in table:
            j = table[gamma]
            return i * m + j
        gamma = (gamma * factor) % p

    raise ValueError("Aucun logarithme discret trouvé (h n'est pas dans le sous-groupe engendré par g).")


def main():
    print("=" * 80)
    print(" ATTAQUE SUR LE LOGARITHME DISCRET : BABY-STEP GIANT-STEP (SHANKS)")
    print("=" * 80)
    print("Résolution de g^x ≡ h mod p pour retrouver l'exposant secret x.")
    print("Complexité théorique : O(√p) = O(2^(k/2)) au lieu de O(p) = O(2^k).")
    print("-" * 80)
    print(f"{'Taille p (bits)':<15} | {'m = ceil(√p)':<15} | {'Temps mesuré (s)':<18} | {'Vérification'}")
    print("-" * 80)

    bit_sizes = [20, 24, 28, 32, 36, 40]
    g = 2

    for bits in bit_sizes:
        # Générer un premier p
        p, _ = generate_prime(bits)
        # Choisir un secret aléatoire x dans [2, p - 2]
        secret_x = secrets.randbelow(p - 3) + 2
        # Clé publique h = g^x mod p
        h = exp_mod(g, secret_x, p)

        m_val = math.isqrt(p) + 1

        t0 = time.perf_counter()
        recovered_x = baby_step_giant_step(g, h, p)
        elapsed = time.perf_counter() - t0

        verified = (exp_mod(g, recovered_x, p) == h)
        print(f"{bits:<15} | {m_val:<15,} | {elapsed:<18.4f} | {'SUCCÈS ' if verified else 'ÉCHEC'}")

    print("=" * 80)
    print("SYNTHÈSE DE L'ATTAQUE :")
    print("Pour p = 40 bits : la recherche exhaustive prendrait 2^40 ≈ 1 100 milliards d'opérations.")
    print("BSGS ramène l'effort à √p ≈ 2^20 ≈ 1 million d'opérations, résolu en ~0.5 seconde !")
    print("C'est pourquoi la RFC 3526 impose p >= 2048 bits (rendant √p = 2^1024 infaisable).")
    print("=" * 80)


if __name__ == "__main__":
    main()
