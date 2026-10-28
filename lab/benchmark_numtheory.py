"""
Laboratoire & Benchmark - Module 2 : Arithmétique modulaire et nombres premiers
1. Comparaison entre notre exp_mod (Square-and-Multiply pur Python) et pow(a, e, n) natif.
2. Démonstration de l'échec de Fermat vs succès de Miller–Rabin sur les nombres de Carmichael.
3. Mesure statistique des candidats testés pour des premiers de 512 et 1024 bits vs prévision théorique (Théorème des nombres premiers).
"""

import sys
import os
import math
import time
import secrets

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cryptolib.numtheory import (
    exp_mod,
    fermat_primality_test,
    miller_rabin_test,
    generate_prime,
)


def benchmark_expmod():
    print("=" * 75)
    print(" 1. BENCHMARK : exp_mod (pur Python) VS pow(a, e, n) (C natif / OpenSSL)")
    print("=" * 75)
    print(f"{'Taille (bits)':<15} | {'exp_mod (ms)':<15} | {'pow natif (ms)':<15} | {'Ratio':<10} | {'Exactitude'}")
    print("-" * 75)

    bit_sizes = [256, 512, 1024, 2048]
    for bits in bit_sizes:
        base = secrets.randbits(bits)
        exp = secrets.randbits(bits)
        mod = secrets.randbits(bits) | 1

        # Mesure exp_mod maison
        t0 = time.perf_counter()
        res_custom = exp_mod(base, exp, mod)
        t_custom = (time.perf_counter() - t0) * 1000.0

        # Mesure pow natif
        t0 = time.perf_counter()
        res_native = pow(base, exp, mod)
        t_native = (time.perf_counter() - t0) * 1000.0

        exact = (res_custom == res_native)
        ratio = t_custom / (t_native if t_native > 0 else 0.001)

        print(f"{bits:<15} | {t_custom:<15.3f} | {t_native:<15.3f} | {ratio:<10.1f}x | {'OK ' if exact else 'ERREUR'}")


def demonstrate_carmichael_failure():
    print("\n" + "=" * 75)
    print(" 2. DÉMONSTRATION : ÉCHEC DU TEST DE FERMAT VS SUCCÈS DE MILLER-RABIN")
    print("=" * 75)
    print("Les nombres de Carmichael sont des entiers composés n tels que a^(n-1) ≡ 1 mod n")
    print("pour TOUT a premier avec n. Fermat est donc leurré et les déclare premiers !")
    print("-" * 75)
    print(f"{'Nombre n':<12} | {'Décomposition':<20} | {'Fermat (15 tours)':<20} | {'Miller-Rabin'}")
    print("-" * 75)

    carmichaels = [
        (561, "3 × 11 × 17"),
        (1105, "5 × 13 × 17"),
        (1729, "7 × 13 × 19 (Ramanujan)"),
        (2465, "5 × 17 × 29"),
        (2821, "7 × 13 × 31"),
        (6601, "7 × 23 × 41"),
    ]

    for n, decomp in carmichaels:
        # Pour illustrer le piège de Fermat, on teste avec des bases premières avec n :
        # Tout a tel que pgcd(a, n) = 1 satisfait a^(n-1) ≡ 1 mod n !
        coprime_bases = [a for a in range(2, min(n, 50)) if math.gcd(a, n) == 1]
        fermat_fooled = all(pow(a, n - 1, n) == 1 for a in coprime_bases[:10])
        mr_result = miller_rabin_test(n, rounds=15)

        fermat_str = "PREMIER  (Leurré à 100%)" if fermat_fooled else "Composé"
        mr_str = "Composé  (Correct)" if not mr_result else "PREMIER (Erreur)"
        print(f"{n:<12} | {decomp:<20} | {fermat_str:<25} | {mr_str}")


def benchmark_prime_generation():
    print("\n" + "=" * 75)
    print(" 3. GÉNÉRATION DE PREMIERS : MESURE DU NOMBRE DE CANDIDATS TESTÉS")
    print("=" * 75)
    print("Théorème des nombres premiers : la densité des premiers autour de x est ~ 1/ln(x).")
    print("Pour un candidat impair de k bits, l'espérance d'essais est ~ ln(2^k) / 2 ≈ (k · ln 2) / 2.")
    print("-" * 75)
    print(f"{'Taille (bits)':<15} | {'Échantillons':<12} | {'Théorie ln(2^k)/2':<20} | {'Moyenne observée':<20} | {'Temps moyen (s)'}")
    print("-" * 75)

    test_configs = [
        (128, 10),
        (256, 10),
        (512, 5),
        (1024, 3),
    ]

    for bits, num_samples in test_configs:
        expected_candidates = (bits * math.log(2)) / 2.0
        tries_list = []
        durations = []

        for _ in range(num_samples):
            t0 = time.perf_counter()
            _, tries = generate_prime(bits, rounds=25)
            durations.append(time.perf_counter() - t0)
            tries_list.append(tries)

        avg_tries = sum(tries_list) / len(tries_list)
        avg_dur = sum(durations) / len(durations)

        print(f"{bits:<15} | {num_samples:<12} | {expected_candidates:<20.1f} | {avg_tries:<20.1f} | {avg_dur:<10.3f}s")

    print("=" * 75)


def main():
    benchmark_expmod()
    demonstrate_carmichael_failure()
    benchmark_prime_generation()


if __name__ == "__main__":
    main()
