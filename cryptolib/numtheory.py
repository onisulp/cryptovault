"""
Module 2 : Arithmétique modulaire et nombres premiers
Toutes les opérations sont codées sans bibliothèque externe spécialisée.
"""

import os
import secrets
import math
import time
from typing import Tuple, List, Optional


# 1. Divisibilité, PGCD et Algorithme d'Euclide Étendu (Bézout)

def gcd(a: int, b: int) -> int:
    """Calcule le Plus Grand Commun Diviseur (PGCD) par l'algorithme d'Euclide classique."""
    a, b = abs(a), abs(b)
    while b != 0:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Algorithme d'Euclide étendu :
    Trouve (g, u, v) tels que a*u + b*v = g = pgcd(a, b).
    Garantit que g >= 0.
    """
    if b == 0:
        if a < 0:
            return -a, -1, 0
        return a, 1, 0

    u0, u1 = 1, 0
    v0, v1 = 0, 1
    r0, r1 = a, b

    while r1 != 0:
        q = r0 // r1
        r0, r1 = r1, r0 - q * r1
        u0, u1 = u1, u0 - q * u1
        v0, v1 = v1, v0 - q * v1

    if r0 < 0:
        return -r0, -u0, -v0
    return r0, u0, v0


def mod_inverse(a: int, m: int) -> int:
    """
    Calcule l'inverse modulaire de a modulo m, tel que (a * x) % m == 1.
    Lève une ValueError si a n'est pas inversible modulo m (c-à-d pgcd(a, m) != 1).
    """
    if m <= 0:
        raise ValueError(f"Le module m doit être strictement positif (reçu: {m}).")
    
    g, u, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"{a} n'est pas inversible modulo {m} car pgcd({a}, {m}) = {g} != 1.")
    
    return u % m


# 2. Exponentiation Modulaire Rapide (Square-and-Multiply)

def exp_mod(base: int, exp: int, mod: int) -> int:
    """
    Calcule (base ** exp) % mod par l'algorithme d'exponentiation rapide
    (Square-and-Multiply de droite à gauche).
    N'utilise PAS la fonction built-in pow() à 3 arguments.
    """
    if mod <= 0:
        raise ValueError(f"Le module mod doit être strictement positif (reçu: {mod}).")
    if mod == 1:
        return 0
    if exp < 0:
        # Gestion des exposants négatifs via l'inverse modulaire
        base = mod_inverse(base, mod)
        exp = -exp

    result = 1
    current = base % mod

    while exp > 0:
        # Multiply si le bit de poids faible est 1
        if exp & 1:
            result = (result * current) % mod
        # Square à chaque étape
        current = (current * current) % mod
        exp >>= 1

    return result


# 3. Théorème des Restes Chinois (CRT)

def chinese_remainder_theorem(remainders: List[int], moduli: List[int]) -> int:
    """
    Résout le système de congruences par le théorème des restes chinois :
        x ≡ remainders[i] (mod moduli[i]) pour i = 0..k-1.
    Les moduli[i] doivent être deux à deux premiers entre eux.
    Retourne la solution unique x modulo M = prod(moduli), telle que 0 <= x < M.
    """
    if len(remainders) != len(moduli) or len(remainders) == 0:
        raise ValueError("Les listes de restes et de modules doivent avoir la même longueur non nulle.")

    # Vérification que les modules sont premiers entre eux deux à deux
    k = len(moduli)
    for i in range(k):
        for j in range(i + 1, k):
            if gcd(moduli[i], moduli[j]) != 1:
                raise ValueError(f"Les modules {moduli[i]} et {moduli[j]} ne sont pas premiers entre eux.")

    # M = produit de tous les modules
    M = 1
    for m in moduli:
        M *= m

    x = 0
    for a_i, m_i in zip(remainders, moduli):
        M_i = M // m_i
        y_i = mod_inverse(M_i, m_i)
        x = (x + a_i * M_i * y_i) % M

    return x % M


# 4. Tests de Primalité : Fermat vs Miller–Rabin

# Petits nombres premiers pour le pré-filtrage rapide par division
SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
    157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
    239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
    331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
    421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
    509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607,
    613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
    709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811,
    821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911,
    919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997
]


def fermat_primality_test(n: int, rounds: int = 10) -> bool:
    """
    Test de primalité naïf de Fermat :
    Vérifie si a^(n-1) ≡ 1 (mod n) pour 'rounds' bases aléatoires.
    Attention : ce test accepte à tort les nombres de Carmichael !
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2  # a dans [2, n-2]
        if gcd(a, n) != 1:
            return False
        if exp_mod(a, n - 1, n) != 1:
            return False
    return True


def miller_rabin_test(n: int, rounds: int = 40) -> bool:
    """
    Test de primalité de Miller–Rabin :
    1. Écrit n - 1 = 2^s * d avec d impair.
    2. Pour chaque témoin aléatoire a dans [2, n - 2] :
       - Calcule x = a^d mod n
       - Si x == 1 ou x == n - 1, passe au tour suivant
       - Répète s - 1 fois : x = x^2 mod n ; si x == n - 1, témoin validé
       - Si x != n - 1, n est définitivement COMPOSÉ.
    Probabilité d'erreur après k tours <= (1/4)^k (<= 2^-80 pour rounds=40).
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # Pré-filtrage par les petits nombres premiers
    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    # Écriture n - 1 = 2^s * d avec d impair
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    # Répétition des tests avec 'rounds' témoins
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2  # a dans [2, n - 2]
        x = exp_mod(a, d, n)

        if x == 1 or x == n - 1:
            continue

        composite = True
        for _ in range(s - 1):
            x = exp_mod(x, 2, n)
            if x == n - 1:
                composite = False
                break

        if composite:
            return False

    return True


# 5. Génération de Grands Nombres Premiers

def generate_prime_candidate(bits: int) -> int:
    """
    Génère un entier impair aléatoire de exactement 'bits' bits.
    Fixe le bit de poids fort (pour garantir la taille) et le bit de poids faible (impair).
    """
    if bits < 2:
        raise ValueError("Le nombre de bits doit être au moins 2.")
    candidate = secrets.randbits(bits)
    # Bit de poids fort à 1 et bit de poids faible à 1
    candidate |= (1 << (bits - 1)) | 1
    return candidate


def generate_prime(bits: int, rounds: int = 40) -> Tuple[int, int]:
    """
    Génère un nombre premier aléatoire de 'bits' bits à l'aide de Miller–Rabin.
    Retourne un tuple (premier, nombre_candidats_testes).
    """
    if bits == 2:
        return secrets.choice([2, 3]), 1

    candidates_tested = 0
    while True:
        candidate = generate_prime_candidate(bits)
        candidates_tested += 1
        if miller_rabin_test(candidate, rounds=rounds):
            return candidate, candidates_tested


# 6. Indicatrice d'Euler

def euler_phi(n: int) -> int:
    """
    Calcule l'indicatrice d'Euler phi(n) par décomposition en facteurs premiers.
    Adapté pour les entiers de taille modeste.
    Formule : phi(n) = n * prod(1 - 1/p) pour tous les p premiers divisant n.
    """
    if n <= 0:
        raise ValueError("n doit être strictement positif.")
    if n == 1:
        return 1

    result = n
    p = 2
    temp = n
    while p * p <= temp:
        if temp % p == 0:
            while temp % p == 0:
                temp //= p
            result -= result // p
        p += 1
    if temp > 1:
        result -= result // temp

    return result
