"""
Module 6 : Cryptographie Symétrique
- Chiffres classiques (César, Vigenère) et cryptanalyse automatique (Indice de Coïncidence)
- Masque jetable (One-Time Pad - Vernam)
- Padding PKCS#7
- AES (128/256 bits) dans les modes ECB, CBC, CTR et GCM (AEAD par défaut)
- Réseau de Feistel jouet à 4 tours (bonus pédagogique)
"""

import os
import sys
import math
from typing import Tuple, List, Optional, Dict
from collections import Counter

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


# 1. Chiffres Classiques : César et Vigenère

def caesar_encrypt(text: str, shift: int) -> str:
    """Chiffre un texte avec le chiffre de César (décalage de shift positions)."""
    res = []
    shift = shift % 26
    for ch in text:
        if "A" <= ch <= "Z":
            res.append(chr((ord(ch) - ord("A") + shift) % 26 + ord("A")))
        elif "a" <= ch <= "z":
            res.append(chr((ord(ch) - ord("a") + shift) % 26 + ord("a")))
        else:
            res.append(ch)
    return "".join(res)


def caesar_decrypt(text: str, shift: int) -> str:
    """Déchiffre un texte chiffré par César."""
    return caesar_encrypt(text, -shift)


def vigenere_encrypt(text: str, key: str) -> str:
    """Chiffre un texte avec le chiffre polyalphabétique de Vigenère."""
    if not key:
        raise ValueError("La clé ne peut pas être vide.")
    key_shifts = [ord(k.upper()) - ord("A") for k in key if k.isalpha()]
    if not key_shifts:
        raise ValueError("La clé doit contenir au moins une lettre alphabétique.")

    res = []
    key_idx = 0
    for ch in text:
        if ch.isalpha():
            shift = key_shifts[key_idx % len(key_shifts)]
            if ch.isupper():
                res.append(chr((ord(ch) - ord("A") + shift) % 26 + ord("A")))
            else:
                res.append(chr((ord(ch) - ord("a") + shift) % 26 + ord("a")))
            key_idx += 1
        else:
            res.append(ch)
    return "".join(res)


def vigenere_decrypt(text: str, key: str) -> str:
    """Déchiffre un texte chiffré par Vigenère."""
    if not key:
        raise ValueError("La clé ne peut pas être vide.")
    key_shifts = [-(ord(k.upper()) - ord("A")) for k in key if k.isalpha()]
    if not key_shifts:
        raise ValueError("La clé doit contenir au moins une lettre alphabétique.")

    res = []
    key_idx = 0
    for ch in text:
        if ch.isalpha():
            shift = key_shifts[key_idx % len(key_shifts)]
            if ch.isupper():
                res.append(chr((ord(ch) - ord("A") + shift) % 26 + ord("A")))
            else:
                res.append(chr((ord(ch) - ord("a") + shift) % 26 + ord("a")))
            key_idx += 1
        else:
            res.append(ch)
    return "".join(res)


# 2. Cryptanalyse Automatique : Indice de Coïncidence & Fréquences

# Fréquences théoriques des lettres en langue française (somme ≈ 1.0)
FRENCH_FREQ = {
    "A": 0.0815, "B": 0.0090, "C": 0.0335, "D": 0.0367, "E": 0.1715,
    "F": 0.0107, "G": 0.0087, "H": 0.0074, "I": 0.0758, "J": 0.0061,
    "K": 0.0007, "L": 0.0546, "M": 0.0297, "N": 0.0709, "O": 0.0581,
    "P": 0.0252, "Q": 0.0136, "R": 0.0655, "S": 0.0795, "T": 0.0724,
    "U": 0.0638, "V": 0.0184, "W": 0.0017, "X": 0.0043, "Y": 0.0028,
    "Z": 0.0015
}


def index_of_coincidence(text: str) -> float:
    """
    Calcule l'Indice de Coïncidence (IC) de Friedman :
    IC = sum(f_i * (f_i - 1)) / (N * (N - 1))
    Pour le français : IC ≈ 0.0778. Pour un texte aléatoire : IC ≈ 0.0385.
    """
    letters = [ch.upper() for ch in text if "A" <= ch.upper() <= "Z"]
    N = len(letters)
    if N <= 1:
        return 0.0

    counts = Counter(letters)
    numerator = sum(count * (count - 1) for count in counts.values())
    return numerator / (N * (N - 1))


def find_vigenere_key_length(ciphertext: str, max_len: int = 16) -> int:
    """
    Détermine la longueur probable de la clé de Vigenère en analysant l'IC moyen
    des sous-textes pour des longueurs de clé variant de 1 à max_len.
    """
    letters = [ch.upper() for ch in ciphertext if "A" <= ch.upper() <= "Z"]
    if len(letters) < 20:
        return 1

    best_len = 1
    best_diff = float("inf")

    # IC moyen attendu en français : 0.0778
    target_ic = 0.0778

    for L in range(1, min(max_len + 1, len(letters) // 5)):
        # Découpage en L sous-textes
        avg_ic = 0.0
        for i in range(L):
            subtext = "".join(letters[j] for j in range(i, len(letters), L))
            avg_ic += index_of_coincidence(subtext)
        avg_ic /= L

        diff = abs(avg_ic - target_ic)
        if diff < best_diff:
            best_diff = diff
            best_len = L

    return best_len


def break_caesar_mono(subtext: str) -> int:
    """
    Casse un chiffre de César monoalphabétique en minimisant la distance du chi-deux
    par rapport aux fréquences théoriques de la langue française.
    Retourne le décalage le plus probable (0 à 25).
    """
    letters = [ch.upper() for ch in subtext if "A" <= ch.upper() <= "Z"]
    N = len(letters)
    if N == 0:
        return 0

    best_shift = 0
    best_chi2 = float("inf")

    for shift in range(26):
        # Appliquer le déchiffrement avec ce décalage
        shifted = [chr((ord(ch) - ord("A") - shift) % 26 + ord("A")) for ch in letters]
        counts = Counter(shifted)

        # Calcul du chi-deux : sum((observe - attendu)^2 / attendu)
        chi2 = 0.0
        for char, prob in FRENCH_FREQ.items():
            expected = N * prob
            observed = counts.get(char, 0)
            chi2 += ((observed - expected) ** 2) / expected

        if chi2 < best_chi2:
            best_chi2 = chi2
            best_shift = shift

    return best_shift


def break_vigenere(ciphertext: str, max_key_len: int = 16) -> Tuple[str, str]:
    """
    Cryptanalyse automatique complète d'un texte chiffré par Vigenère :
    1. Trouve la longueur de clé L par l'Indice de Coïncidence.
    2. Pour chaque position de 0 à L-1, trouve la lettre par analyse de fréquence.
    3. Reconstruit la clé et retourne (clé_trouvée, texte_déchiffré).
    """
    letters = [ch.upper() for ch in ciphertext if "A" <= ch.upper() <= "Z"]
    key_len = find_vigenere_key_length(ciphertext, max_len=max_key_len)

    recovered_key_chars = []
    for i in range(key_len):
        subtext = "".join(letters[j] for j in range(i, len(letters), key_len))
        shift = break_caesar_mono(subtext)
        recovered_key_chars.append(chr(ord("A") + shift))

    recovered_key = "".join(recovered_key_chars)
    decrypted_text = vigenere_decrypt(ciphertext, recovered_key)
    return recovered_key, decrypted_text


# 3. Masque Jetable (One-Time Pad - Vernam)

def otp_encrypt(data: bytes, key: bytes) -> bytes:
    """Chiffrement par masque jetable : C = M XOR K (longueur égale)."""
    if len(data) != len(key):
        raise ValueError(f"La clé doit avoir exactement la même longueur que les données ({len(data)} octets).")
    return bytes(x ^ y for x, y in zip(data, key))


def otp_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Déchiffrement par masque jetable : M = C XOR K."""
    return otp_encrypt(ciphertext, key)


# 4. Remplissage PKCS#7 (pour modes par blocs comme CBC / ECB)

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Ajoute le padding PKCS#7 à une séquence d'octets."""
    if not (1 <= block_size <= 255):
        raise ValueError("Taille de bloc invalide pour PKCS#7 (doit être entre 1 et 255).")
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(padded_data: bytes, block_size: int = 16) -> bytes:
    """Vérifie et retire le padding PKCS#7. Lève ValueError si invalide."""
    if not padded_data:
        raise ValueError("Données vides.")
    if len(padded_data) % block_size != 0:
        raise ValueError("Les données ne sont pas un multiple de la taille de bloc.")

    pad_len = padded_data[-1]
    if pad_len == 0 or pad_len > block_size:
        raise ValueError("Padding PKCS#7 invalide (longueur de padding hors limites).")

    # Vérification en temps constant de tous les octets de padding
    padding = padded_data[-pad_len:]
    expected = bytes([pad_len] * pad_len)
    if padding != expected:
        raise ValueError("Padding PKCS#7 corrompu ou falsifié.")

    return padded_data[:-pad_len]


# 5. AES Moderne Multi-Modes (ECB, CBC, CTR, GCM)

VALID_KEY_SIZES = {16, 24, 32}  # AES-128, AES-192, AES-256


def aes_encrypt(data: bytes, key: bytes, mode: str = "GCM", iv: Optional[bytes] = None, aad: Optional[bytes] = None) -> bytes:
    """
    Chiffre des données avec AES.
    Modes disponibles :
      - 'GCM' (Défaut, AEAD) : paquet = [nonce 12 octets][tag 16 octets][ciphertext]
      - 'CBC' (avec PKCS#7)   : paquet = [iv 16 octets][ciphertext]
      - 'CTR'                 : paquet = [nonce 16 octets][ciphertext]
      - 'ECB' (Dangereux)     : paquet = [ciphertext]
    """
    if len(key) not in VALID_KEY_SIZES:
        raise ValueError(f"Taille de clé AES invalide : {len(key)} octets (attendu 16, 24 ou 32 octets).")

    mode_clean = mode.upper()

    if mode_clean == "GCM":
        nonce = iv if iv is not None else os.urandom(12)
        aesgcm = AESGCM(key)
        # AESGCM retourne ciphertext + tag (16 octets à la fin)
        ct_with_tag = aesgcm.encrypt(nonce, data, aad)
        tag = ct_with_tag[-16:]
        ct = ct_with_tag[:-16]
        return nonce + tag + ct

    elif mode_clean == "CBC":
        init_vector = iv if iv is not None else os.urandom(16)
        padded = pkcs7_pad(data, 16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(init_vector))
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded) + encryptor.finalize()
        return init_vector + ct

    elif mode_clean == "CTR":
        nonce = iv if iv is not None else os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
        encryptor = cipher.encryptor()
        ct = encryptor.update(data) + encryptor.finalize()
        return nonce + ct

    elif mode_clean == "ECB":
        padded = pkcs7_pad(data, 16)
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        encryptor = cipher.encryptor()
        return encryptor.update(padded) + encryptor.finalize()

    else:
        raise ValueError(f"Mode non supporté: {mode}. Modes supportés : GCM, CBC, CTR, ECB.")


def aes_decrypt(package: bytes, key: bytes, mode: str = "GCM", aad: Optional[bytes] = None) -> bytes:
    """
    Déchiffre un paquet produit par aes_encrypt selon le mode choisi.
    """
    if len(key) not in VALID_KEY_SIZES:
        raise ValueError(f"Taille de clé AES invalide : {len(key)} octets.")

    mode_clean = mode.upper()

    if mode_clean == "GCM":
        if len(package) < 28:
            raise ValueError("Paquet GCM trop court (nécessite au moins 12 octets nonce + 16 octets tag).")
        nonce = package[:12]
        tag = package[12:28]
        ct = package[28:]
        aesgcm = AESGCM(key)
        # En cryptographie hazmat, GCM attend ciphertext + tag
        return aesgcm.decrypt(nonce, ct + tag, aad)

    elif mode_clean == "CBC":
        if len(package) < 16:
            raise ValueError("Paquet CBC trop court (nécessite au moins 16 octets IV).")
        init_vector = package[:16]
        ct = package[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(init_vector))
        decryptor = cipher.decryptor()
        padded = decryptor.update(ct) + decryptor.finalize()
        return pkcs7_unpad(padded, 16)

    elif mode_clean == "CTR":
        if len(package) < 16:
            raise ValueError("Paquet CTR trop court (nécessite au moins 16 octets nonce).")
        nonce = package[:16]
        ct = package[16:]
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
        decryptor = cipher.decryptor()
        return decryptor.update(ct) + decryptor.finalize()

    elif mode_clean == "ECB":
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        decryptor = cipher.decryptor()
        padded = decryptor.update(package) + decryptor.finalize()
        return pkcs7_unpad(padded, 16)

    else:
        raise ValueError(f"Mode non supporté: {mode}.")


# 6. Réseau de Feistel Jouet à 4 Tours (Bonus Cours)

def feistel_round_function(r_bytes: bytes, round_key: int) -> bytes:
    """Fonction de tour jouet F(R, K_i) mixant R avec la sous-clé de tour."""
    int_r = int.from_bytes(r_bytes, "big")
    mixed = (int_r * 31 + round_key * 17) & 0xFFFFFFFF
    return mixed.to_bytes(4, "big")


def feistel_encrypt(block: bytes, round_keys: List[int]) -> bytes:
    """
    Chiffre un bloc de 8 octets avec un réseau de Feistel à N tours :
    L_{i+1} = R_i
    R_{i+1} = L_i XOR F(R_i, K_i)
    """
    if len(block) != 8:
        raise ValueError("Le bloc Feistel doit mesurer exactement 8 octets (64 bits).")

    L = block[:4]
    R = block[4:]

    for k in round_keys:
        f_out = feistel_round_function(R, k)
        new_R = bytes(x ^ y for x, y in zip(L, f_out))
        L = R
        R = new_R

    # Inversion finale des moitiés
    return R + L


def feistel_decrypt(block: bytes, round_keys: List[int]) -> bytes:
    """
    Déchiffre un bloc Feistel en appliquant exactement le même algorithme
    avec les sous-clés inversées (propriété fondamentale de Feistel !).
    """
    return feistel_encrypt(block, list(reversed(round_keys)))
