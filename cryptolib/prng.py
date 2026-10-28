"""
Module 8 : Générateurs Pseudo-Aléatoires (PRNG et CSPRNG)
- Générateur Congruentiel Linéaire (LCG)
- Mersenne Twister (MT19937) complet from scratch et fonction d'inversion untemper
- CSPRNG HMAC_DRBG (NIST SP 800-90A)
- Batterie de tests statistiques (Monobit, Runs, Chi-deux sur octets)
"""

import os
import sys
import math
import time
from typing import List, Tuple, Dict, Any, Optional

from cryptolib.hashing import custom_hmac
from cryptolib.numtheory import mod_inverse


# 1. Générateur Congruentiel Linéaire (LCG)

class LCG:
    """
    Générateur Congruentiel Linéaire :
    X_{n+1} = (a * X_n + c) mod m
    À ne JAMAIS utiliser en cryptographie (parfaitement prévisible).
    """

    def __init__(self, a: int, c: int, m: int, seed: int):
        self.a = a
        self.c = c
        self.m = m
        self.state = seed % m

    def next(self) -> int:
        self.state = (self.a * self.state + self.c) % self.m
        return self.state

    def next_bytes(self, length: int) -> bytes:
        out = bytearray()
        while len(out) < length:
            val = self.next()
            # Extraction des octets utiles
            out.extend(val.to_bytes((val.bit_length() + 7) // 8 or 1, "big"))
        return bytes(out[:length])


# 2. Mersenne Twister (MT19937 - 32 bits)

# Constantes normalisées du standard MT19937
MT_W = 32
MT_N = 624
MT_M = 397
MT_R = 31
MT_A = 0x9908B0DF
MT_U = 11
MT_D = 0xFFFFFFFF
MT_S = 7
MT_B = 0x9D2C5680
MT_T = 15
MT_C = 0xEFC60000
MT_L = 18
MT_F = 1812433253

LOWER_MASK = (1 << MT_R) - 1            # 0x7FFFFFFF (31 bits de poids faible)
UPPER_MASK = (~LOWER_MASK) & 0xFFFFFFFF # 0x80000000 (bit de poids fort)


def temper(x: int) -> int:
    """Applique la fonction de masquage (tempering) de MT19937 sur un entier 32 bits."""
    y = x & 0xFFFFFFFF
    y ^= ((y >> MT_U) & MT_D)
    y ^= ((y << MT_S) & MT_B)
    y ^= ((y << MT_T) & MT_C)
    y ^= (y >> MT_L)
    return y & 0xFFFFFFFF


def untemper(y: int) -> int:
    """
    Inverse mathématiquement la fonction de masquage (tempering) de MT19937.
    Permet de retrouver l'état interne original exact à partir d'un nombre généré.
    """
    y = y & 0xFFFFFFFF

    # 1. Inversion de : y = x ^ (x >> 18)
    # Comme MT_L = 18 >= 16 (la moitié de 32 bits), l'inversion est directe :
    x = y ^ (y >> MT_L)

    # 2. Inversion de : y = x ^ ((x << 15) & 0xEFC60000)
    # MT_T = 15 : inversion par reconstruction de tranche
    x ^= ((x << MT_T) & MT_C) & 0xFFFFFFFF

    # 3. Inversion de : y = x ^ ((x << 7) & 0x9D2C5680)
    # MT_S = 7 : 7 bits à la fois
    temp = x
    for _ in range(32 // MT_S + 1):
        temp = x ^ ((temp << MT_S) & MT_B) & 0xFFFFFFFF
    x = temp

    # 4. Inversion de : y = x ^ ((x >> 11) & 0xFFFFFFFF)
    # MT_U = 11 : 11 bits à la fois
    temp = x
    for _ in range(32 // MT_U + 1):
        temp = x ^ ((temp >> MT_U) & MT_D)
    x = temp

    return x & 0xFFFFFFFF


class MersenneTwister19937:
    """
    Générateur pseudo-aléatoire Mersenne Twister (MT19937).
    Période : 2^19937 - 1.
    Statistiquement excellent, mais cryptographiquement nul (vulnérable au clonage d'état).
    """

    def __init__(self, seed: int = 5489):
        self.MT = [0] * MT_N
        self.index = MT_N
        self.seed = seed
        self._initialize(seed)

    def _initialize(self, seed: int):
        self.MT[0] = seed & 0xFFFFFFFF
        for i in range(1, MT_N):
            self.MT[i] = (MT_F * (self.MT[i - 1] ^ (self.MT[i - 1] >> (MT_W - 2))) + i) & 0xFFFFFFFF
        self.index = MT_N

    def _twist(self):
        """Mélange matriciel périodique de l'état interne."""
        for i in range(MT_N):
            x = (self.MT[i] & UPPER_MASK) + (self.MT[(i + 1) % MT_N] & LOWER_MASK)
            xA = x >> 1
            if x % 2 != 0:
                xA ^= MT_A
            self.MT[i] = self.MT[(i + MT_M) % MT_N] ^ xA
        self.index = 0

    def extract_number(self) -> int:
        """Extrait un entier pseudo-aléatoire de 32 bits."""
        if self.index >= MT_N:
            self._twist()
        y = self.MT[self.index]
        self.index += 1
        return temper(y)

    def next_bytes(self, length: int) -> bytes:
        out = bytearray()
        while len(out) < length:
            num = self.extract_number()
            out.extend(num.to_bytes(4, "big"))
        return bytes(out[:length])


def clone_mt19937(outputs_624: List[int]) -> MersenneTwister19937:
    """
    Reconstruit un clone parfait du générateur Mersenne Twister à partir de
    l'observation de 624 sorties consécutives de 32 bits (inversion d'état).
    """
    if len(outputs_624) != MT_N:
        raise ValueError(f"Exactement {MT_N} sorties sont nécessaires pour cloner l'état.")

    cloned = MersenneTwister19937(seed=0)
    # Inversion de chaque sortie pour reconstituer l'état MT[0..623]
    for i in range(MT_N):
        cloned.MT[i] = untemper(outputs_624[i])

    cloned.index = MT_N  # Prêt à twister ou continuer la séquence
    return cloned


# 3. CSPRNG HMAC_DRBG (NIST SP 800-90A)

class HMAC_DRBG:
    """
    CSPRNG standardisé par le NIST (SP 800-90A) fondé sur HMAC-SHA256.
    Garantit l'imprévisibilité cryptographique et la résistance avant/arrière.
    """

    def __init__(self, entropy_source: Optional[bytes] = None, personalization: bytes = b"CryptoVault-DRBG"):
        if entropy_source is None:
            # Réensemencement cryptographique matériel système
            entropy_source = os.urandom(32)

        self.K = b"\x00" * 32
        self.V = b"\x01" * 32
        self.reseed_counter = 1

        seed_material = entropy_source + personalization
        self._update(seed_material)

    def _update(self, provided_data: Optional[bytes] = None):
        """Met à jour l'état interne (K, V) selon le standard NIST."""
        data_to_hash = self.V + b"\x00" + (provided_data if provided_data else b"")
        self.K = custom_hmac(self.K, data_to_hash, "sha256")
        self.V = custom_hmac(self.K, self.V, "sha256")

        if provided_data:
            data_to_hash = self.V + b"\x01" + provided_data
            self.K = custom_hmac(self.K, data_to_hash, "sha256")
            self.V = custom_hmac(self.K, self.V, "sha256")

    def reseed(self, additional_entropy: Optional[bytes] = None):
        """Réensemence le générateur avec de la nouvelle entropie."""
        if additional_entropy is None:
            additional_entropy = os.urandom(32)
        self._update(additional_entropy)
        self.reseed_counter = 1

    def generate(self, num_bytes: int, additional_input: Optional[bytes] = None) -> bytes:
        """Génère 'num_bytes' octets cryptographiquement sûrs."""
        # Réensemencement périodique automatique (toutes les 10 000 requêtes)
        if self.reseed_counter > 10_000:
            self.reseed()

        if additional_input:
            self._update(additional_input)

        out = bytearray()
        while len(out) < num_bytes:
            self.V = custom_hmac(self.K, self.V, "sha256")
            out.extend(self.V)

        self._update(additional_input)
        self.reseed_counter += 1
        return bytes(out[:num_bytes])


# 4. Batterie de Tests Statistiques (NIST SP 800-22)

def monobit_frequency_test(data: bytes) -> Tuple[bool, float, float]:
    """
    Test de fréquence monobit (NIST SP 800-22 Section 2.1).
    Vérifie l'équilibre entre les 0 et les 1.
    Retourne (success, proportion_ones, p_value).
    """
    total_bits = len(data) * 8
    if total_bits == 0:
        return False, 0.0, 0.0

    ones = 0
    for byte in data:
        ones += bin(byte).count("1")

    # S_n = sum(2*b_i - 1)
    s_n = 2 * ones - total_bits
    s_obs = abs(s_n) / math.sqrt(total_bits)
    # p_value = erfc(s_obs / sqrt(2))
    p_value = math.erfc(s_obs / math.sqrt(2))
    success = (p_value >= 0.01)

    return success, ones / total_bits, p_value


def runs_test(data: bytes) -> Tuple[bool, float, float]:
    """
    Test des séquences / runs (NIST SP 800-22 Section 2.3).
    Vérifie que l'alternance de 0 et de 1 consécutifs est statistiquement plausible.
    """
    total_bits = len(data) * 8
    if total_bits < 100:
        return True, 0.5, 1.0

    # Conversion en chaîne de bits
    bits = "".join(f"{b:08b}" for b in data)
    ones = bits.count("1")
    pi = ones / total_bits

    # Pré-requis NIST : |pi - 0.5| < 2 / sqrt(n)
    if abs(pi - 0.5) >= (2 / math.sqrt(total_bits)):
        return False, pi, 0.0

    # Calcul du nombre de runs (transitions)
    v_obs = 1
    for i in range(total_bits - 1):
        if bits[i] != bits[i + 1]:
            v_obs += 1

    numerator = abs(v_obs - 2 * total_bits * pi * (1 - pi))
    denominator = 2 * math.sqrt(2 * total_bits) * pi * (1 - pi)
    p_value = math.erfc(numerator / denominator)
    success = (p_value >= 0.01)

    return success, pi, p_value


def chi2_byte_uniformity_test(data: bytes) -> Tuple[bool, float, float]:
    """
    Test du chi-deux d'uniformité sur les 256 octets possibles (0 à 255).
    Retourne (success, chi2_stat, p_value_approx).
    """
    if len(data) < 1280:  # Au moins 5 occurrences par case en moyenne (256 * 5 = 1280)
        return True, 0.0, 1.0

    counts = [0] * 256
    for b in data:
        counts[b] += 1

    expected = len(data) / 256.0
    chi2_stat = sum(((c - expected) ** 2) / expected for c in counts)

    # Pour 255 degrés de liberté, la moyenne est 255 et l'écart-type est sqrt(2*255) ≈ 22.58
    # On rejette si chi2 est trop extrême (ex: chi2 > 310 pour alpha=0.01)
    # Approximation par loi normale : z = (chi2 - 255) / sqrt(510)
    z = (chi2_stat - 255.0) / math.sqrt(510.0)
    p_value = 0.5 * math.erfc(z / math.sqrt(2))
    success = (chi2_stat < 310.0 and chi2_stat > 200.0)

    return success, chi2_stat, p_value
