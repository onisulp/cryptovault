"""
Laboratoire d'attaque - Module 1 : Attaque par collision (Paradoxe des anniversaires)
Objectif : Trouver une collision sur une empreinte SHA-256 tronquée à 32 bits (4 octets).
Comparer le nombre d'essais mesuré à la valeur théorique 2^16 = 65 536.
"""

import hashlib
import time
import os
import math
from typing import Tuple, Dict


def find_truncated_collision(num_bits: int = 32) -> Tuple[bytes, bytes, str, int, float]:
    """
    Recherche une collision sur les premiers `num_bits` de SHA-256.
    Retourne (msg1, msg2, truncated_hash_hex, iterations, duration_sec).
    """
    num_bytes = (num_bits + 7) // 8
    mask = (1 << num_bits) - 1

    seen: Dict[int, bytes] = {}
    iterations = 0
    start_time = time.perf_counter()

    while True:
        iterations += 1
        # Génération d'un message candidat (8 octets aléatoires + compteur)
        candidate = iterations.to_bytes(4, "big") + os.urandom(8)
        full_hash = hashlib.sha256(candidate).digest()
        # Extraction des bits tronqués
        int_hash = int.from_bytes(full_hash[:num_bytes], "big") & mask

        if int_hash in seen:
            prev_msg = seen[int_hash]
            if prev_msg != candidate:
                duration = time.perf_counter() - start_time
                trunc_hex = full_hash[:num_bytes].hex()
                return prev_msg, candidate, trunc_hex, iterations, duration
        else:
            seen[int_hash] = candidate


def main():
    print("=" * 70)
    print(" LAB D'ATTAQUE : COLLISION SUR SHA-256 TRONQUÉ (PARADOXE DES ANNIVERSAIRES)")
    print("=" * 70)
    print("Espace des valeurs : 32 bits (2^32 = 4 294 967 296 valeurs possibles)")
    theoretical_pow2 = 2 ** 16  # 65 536
    theoretical_exact = math.sqrt((math.pi / 2.0) * (2 ** 32))  # ≈ 82 094
    print(f"Prévision théorique de base (2^(n/2)) : {theoretical_pow2:,} essais")
    print(f"Espérance mathématique exacte (√(π/2 · 2^n)) : {int(theoretical_exact):,} essais")
    print("-" * 70)

    num_runs = 5
    trial_counts = []
    durations = []

    print(f"Exécution de {num_runs} attaques indépendantes...")
    for run in range(1, num_runs + 1):
        m1, m2, h_trunc, count, dur = find_truncated_collision(32)
        trial_counts.append(count)
        durations.append(dur)
        print(f"  [Essai {run}] Collision trouvée en {count:,} itérations ({dur:.3f} s)")
        if run == 1:
            full_h1 = hashlib.sha256(m1).hexdigest()
            full_h2 = hashlib.sha256(m2).hexdigest()
            print(f"     Message 1 : {m1.hex()} -> SHA256: {full_h1}")
            print(f"     Message 2 : {m2.hex()} -> SHA256: {full_h2}")
            print(f"     Préfixe 32 bits identique : 0x{h_trunc}")

    avg_count = sum(trial_counts) / len(trial_counts)
    avg_dur = sum(durations) / len(durations)

    print("-" * 70)
    print("SYNTHÈSE DES RÉSULTATS :")
    print(f"  Nombre moyen d'essais observé : {int(avg_count):,} essais")
    print(f"  Temps moyen par collision       : {avg_dur:.3f} secondes")
    print(f"  Écart relatif à 2^16 (65 536)  : {((avg_count - theoretical_pow2) / theoretical_pow2) * 100:+.2f}%")
    print(f"  Écart à l'espérance √(π/2·2^32) : {((avg_count - theoretical_exact) / theoretical_exact) * 100:+.2f}%")
    print("=" * 70)
    print("CONCLUSION DU LAB :")
    print("La méthode des anniversaires réduit l'effort de recherche d'une collision")
    print("de 2^32 (recherche exhaustive de préimage) à seulement ~2^16 essais.")
    print("C'est pourquoi une fonction de hachage de n bits n'offre que n/2 bits de")
    print("sécurité contre les collisions (ex: SHA-256 offre 128 bits de sécurité collision).")
    print("=" * 70)


if __name__ == "__main__":
    main()
