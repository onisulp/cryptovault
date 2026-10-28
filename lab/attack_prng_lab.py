"""
Laboratoire d'Attaques - Module 8 : Faiblesses des PRNG et Comparaison Statistique
Démontre :
1. La reconstruction mathématique complète des paramètres d'un LCG à partir de 3 sorties.
2. Le clonage d'état et la prédiction future à 100% de Mersenne Twister (MT19937) après 624 sorties.
3. Le tableau comparatif des tests statistiques NIST (Monobit, Runs, Chi-deux) et l'explication
   du paradoxe de Mersenne Twister.
"""

import sys
import os
import time
import secrets

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cryptolib.prng import (
    LCG,
    MersenneTwister19937,
    clone_mt19937,
    HMAC_DRBG,
    monobit_frequency_test,
    runs_test,
    chi2_byte_uniformity_test,
)
from cryptolib.numtheory import mod_inverse, gcd


# 1. Attaque 1 : Reconstruction des paramètres d'un LCG

def attack_lcg_reconstruction():
    print("=" * 80)
    print(" 1. ATTAQUE : RECONSTRUCTION ANALYTIQUE DES PARAMÈTRES D'UN LCG")
    print("=" * 80)
    print("Pour X_{n+1} = (a * X_n + c) mod m avec m connu :")
    print("3 sorties consécutives suffisent pour retrouver a et c de façon déterministe !")
    print("-" * 80)

    # Paramètres secrets du générateur
    secret_a = 1664525        # Multiplicateur standard (Numerical Recipes)
    secret_c = 1013904223     # Incrément standard
    m = 2**31                 # Module 2^31

    # On s'assure d'un écart inversible pour la démonstration
    lcg = LCG(a=secret_a, c=secret_c, m=m, seed=secrets.randbelow(m))
    while True:
        x0 = lcg.next()
        x1 = lcg.next()
        x2 = lcg.next()
        diff1 = (x1 - x0) % m
        if gcd(diff1, m) == 1:
            break

    print(f"Sorties consécutives observées :")
    print(f"  X0 = {x0}, X1 = {x1}, X2 = {x2}")

    #   RÉSOLUTION MATHÉMATIQUE 
    # X2 - X1 ≡ a * (X1 - X0) (mod m)
    # => a ≡ (X2 - X1) * (X1 - X0)^(-1) (mod m)
    diff2 = (x2 - x1) % m
    inv_diff1 = mod_inverse(diff1, m)
    recovered_a = (diff2 * inv_diff1) % m

    # c ≡ X1 - a * X0 (mod m)
    recovered_c = (x1 - recovered_a * x0) % m

    print(f"\n Paramètres retrouvés :")
    print(f"  Multiplicateur 'a' retrouvé : {recovered_a} (Authentique: {recovered_a == secret_a})")
    print(f"  Incrément      'c' retrouvé : {recovered_c} (Authentique: {recovered_c == secret_c})")

    # Prédiction des 5 sorties suivantes
    actual_next = [lcg.next() for _ in range(5)]
    predicted_next = []
    cur = x2
    for _ in range(5):
        cur = (recovered_a * cur + recovered_c) % m
        predicted_next.append(cur)

    print(f"  Prédiction des 5 valeurs suivantes : {predicted_next == actual_next} (100% exactes !) [SUCCES]")

# 2. Attaque 2 : Clonage d'état complet de Mersenne Twister (MT19937)

def attack_mt19937_cloning():
    print("\n" + "=" * 80)
    print(" 2. ATTAQUE : CLONAGE INTÉGRAL DE MERSENNE TWISTER (MT19937)")
    print("=" * 80)
    print("Mersenne Twister n'est PAS cryptographique : sa fonction de masquage (tempering)")
    print("est bijective et inversible bit à bit. Observer 624 sorties permet de cloner")
    print("l'état interne en mémoire et de prédire l'avenir avec certitude absolue !")
    print("-" * 80)

    # Générateur cible (ex: serveur de jetons d'authentification réinitialisation de mdp)
    target_prng = MersenneTwister19937(seed=987654321)

    print("[Victime] Génère une séquence continue de nombres...")
    observed = [target_prng.extract_number() for _ in range(624)]
    print(f"[Pirate]  Intercepte les 624 premières sorties (de {observed[0]} à {observed[-1]})...")

    t0 = time.perf_counter()
    # Clonage d'état par inversion (untemper)
    clone = clone_mt19937(observed)
    elapsed = time.perf_counter() - t0

    print(f"[Pirate]  État interne reconstitué en {elapsed * 1000:.3f} ms !")

    # Prédiction des 1 000 prochains nombres
    target_future = [target_prng.extract_number() for _ in range(1000)]
    clone_predicted = [clone.extract_number() for _ in range(1000)]

    matches = sum(1 for a, b in zip(target_future, clone_predicted) if a == b)
    print(f"[Test]    1 000 prochaines valeurs générées par la victime :")
    print(f"  Prédictions exactes du pirate : {matches}/1000 ({matches/10:.1f}%) [SUCCES]")
    print("\nConclusion : Mersenne Twister ne doit JAMAIS être utilisé pour générer des clés,")
    print("des jetons de session, des sels ou des nonces.")

# 3. Batterie de Tests Statistiques et Paradoxe

def benchmark_statistical_tests():
    print("\n" + "=" * 80)
    print(" 3. COMPARATIF STATISTIQUE : LCG VS MERSENNE TWISTER VS HMAC_DRBG")
    print("=" * 80)

    sample_size = 4096  # 4 Ko de données testées pour chaque générateur

    generators = {
        "LCG (Faible)": LCG(a=1664525, c=1013904223, m=2**32, seed=42).next_bytes(sample_size),
        "Mersenne Twister (MT19937)": MersenneTwister19937(seed=42).next_bytes(sample_size),
        "HMAC_DRBG (CSPRNG NIST)": HMAC_DRBG().generate(sample_size),
    }

    print(f"{'Générateur':<28} | {'Monobit (p-val)':<18} | {'Runs (p-val)':<18} | {'Chi-deux (stat)'}")
    print("-" * 80)

    for name, data in generators.items():
        pass_mono, _, p_mono = monobit_frequency_test(data)
        pass_runs, _, p_runs = runs_test(data)
        pass_chi2, chi2_stat, _ = chi2_byte_uniformity_test(data)

        mono_str = f"{p_mono:.4f} {'[OK]' if pass_mono else '[FAIL]'}"
        runs_str = f"{p_runs:.4f} {'[OK]' if pass_runs else '[FAIL]'}"
        chi2_str = f"{chi2_stat:.1f} {'[OK]' if pass_chi2 else '[FAIL]'}"

        print(f"{name:<28} | {mono_str:<18} | {runs_str:<18} | {chi2_str}")

    print("=" * 80)
    print("LE PARADOXE FONDAMENTAL :")
    print("Mersenne Twister passe TOUS les tests statistiques avec d'excellentes p-valeurs,")
    print("pourtant son état interne est clonable en 624 sorties.")
    print("-> Un test statistique ne prouve JAMAIS la sécurité cryptographique !")
    print("Seuls les CSPRNG (HMAC_DRBG, os.urandom) garantissent l'imprévisibilité mathématique.")
    print("=" * 80)


def main():
    attack_lcg_reconstruction()
    attack_mt19937_cloning()
    benchmark_statistical_tests()


if __name__ == "__main__":
    main()
