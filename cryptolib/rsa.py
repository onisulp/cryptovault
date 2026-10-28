"""
Module 3 : Le chiffrement RSA
- Génération de clés RSA (1024/2048 bits)
- Chiffrement et Déchiffrement avec accélération CRT (Théorème des restes chinois)
- Remplissage OAEP (Optimal Asymmetric Encryption Padding) avec MGF1-SHA256
- Signature et vérification (PKCS#1 v1.5 / PSS)
- Chiffrement hybride de fichiers (RSA + AES-GCM)
"""

import os
import sys
import json
import hashlib
import hmac
import math
import time
from typing import Tuple, Dict, Any, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Import des fonctions arithmétiques du Module 2
from cryptolib.numtheory import (
    gcd,
    mod_inverse,
    exp_mod,
    generate_prime,
)


# 1. Structures de Clés Publique et Privée

class RSAPublicKey:
    """Clé publique RSA : (n, e)"""

    def __init__(self, n: int, e: int = 65537):
        self.n = n
        self.e = e
        self.bit_length = n.bit_length()
        self.byte_length = (self.bit_length + 7) // 8

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "RSA_PUBLIC_KEY",
            "bit_length": self.bit_length,
            "n": hex(self.n),
            "e": hex(self.e),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RSAPublicKey":
        return cls(n=int(data["n"], 16), e=int(data["e"], 16))

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> "RSAPublicKey":
        return cls.from_dict(json.loads(json_str))


class RSAPrivateKey:
    """Clé privée RSA avec pré-calcul des paramètres CRT pour accélération."""

    def __init__(self, n: int, e: int, d: int, p: int, q: int, dp: int, dq: int, qinv: int):
        self.n = n
        self.e = e
        self.d = d
        self.p = p
        self.q = q
        self.dp = dp
        self.dq = dq
        self.qinv = qinv
        self.bit_length = n.bit_length()
        self.byte_length = (self.bit_length + 7) // 8

    @property
    def public_key(self) -> RSAPublicKey:
        return RSAPublicKey(self.n, self.e)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "RSA_PRIVATE_KEY",
            "bit_length": self.bit_length,
            "n": hex(self.n),
            "e": hex(self.e),
            "d": hex(self.d),
            "p": hex(self.p),
            "q": hex(self.q),
            "dp": hex(self.dp),
            "dq": hex(self.dq),
            "qinv": hex(self.qinv),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RSAPrivateKey":
        return cls(
            n=int(data["n"], 16),
            e=int(data["e"], 16),
            d=int(data["d"], 16),
            p=int(data["p"], 16),
            q=int(data["q"], 16),
            dp=int(data["dp"], 16),
            dq=int(data["dq"], 16),
            qinv=int(data["qinv"], 16),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> "RSAPrivateKey":
        return cls.from_dict(json.loads(json_str))


# 2. Génération de Clés RSA

def generate_keypair(bits: int = 1024, e: int = 65537) -> Tuple[RSAPublicKey, RSAPrivateKey]:
    """
    Génère une paire de clés RSA de taille 'bits' (1024 ou 2048) avec exposant e.
    Pré-calcule les composantes CRT pour le déchiffrement ultra-rapide.
    """
    if bits < 128:
        raise ValueError("La taille de clé doit être d'au moins 128 bits.")

    half_bits = bits // 2

    while True:
        # Génération de deux premiers distincts p et q
        p, _ = generate_prime(half_bits)
        q, _ = generate_prime(half_bits)
        if p == q:
            continue
        # Convention : s'assurer p > q pour Garner
        if p < q:
            p, q = q, p

        phi = (p - 1) * (q - 1)
        if gcd(e, phi) == 1:
            try:
                d = mod_inverse(e, phi)
                n = p * q
                # Paramètres CRT (formule de Garner)
                dp = d % (p - 1)
                dq = d % (q - 1)
                qinv = mod_inverse(q, p)

                pub = RSAPublicKey(n=n, e=e)
                priv = RSAPrivateKey(n=n, e=e, d=d, p=p, q=q, dp=dp, dq=dq, qinv=qinv)
                return pub, priv
            except ValueError:
                continue


# 3. Primitives de Chiffrement / Déchiffrement Élémentaires (Textbook)

def rsa_encrypt_int(m: int, pub: RSAPublicKey) -> int:
    """Chiffrement RSA scolaire d'un entier : c = m^e mod n."""
    if m < 0 or m >= pub.n:
        raise ValueError("Le message entier m doit vérifier 0 <= m < n.")
    return exp_mod(m, pub.e, pub.n)


def rsa_decrypt_int_raw(c: int, priv: RSAPrivateKey) -> int:
    """Déchiffrement RSA standard direct sans CRT : m = c^d mod n."""
    if c < 0 or c >= priv.n:
        raise ValueError("Le chiffré entier c doit vérifier 0 <= c < n.")
    return exp_mod(c, priv.d, priv.n)


def rsa_decrypt_int_crt(c: int, priv: RSAPrivateKey) -> int:
    """
    Déchiffrement RSA accéléré par le théorème des restes chinois (formule de Garner) :
    m1 = c^dp mod p
    m2 = c^dq mod q
    h = qinv * (m1 - m2) mod p
    m = m2 + h * q
    Gain théorique : facteur ~4 en vitesse par rapport à c^d mod n.
    """
    if c < 0 or c >= priv.n:
        raise ValueError("Le chiffré entier c doit vérifier 0 <= c < n.")

    m1 = exp_mod(c, priv.dp, priv.p)
    m2 = exp_mod(c, priv.dq, priv.q)

    h = (priv.qinv * (m1 - m2)) % priv.p
    m = m2 + h * priv.q
    return m


# 4. Fonction de Masquage MGF1 et Remplissage OAEP (RFC 8017)

def mgf1(seed: bytes, mask_len: int, hash_name: str = "sha256") -> bytes:
    """
    Mask Generation Function 1 (MGF1) selon la RFC 8017 / PKCS#1 v2.2.
    """
    hasher_func = getattr(hashlib, hash_name)
    h_len = hasher_func().digest_size
    t = bytearray()
    counter = 0

    while len(t) < mask_len:
        c = counter.to_bytes(4, "big")
        t.extend(hasher_func(seed + c).digest())
        counter += 1

    return bytes(t[:mask_len])


def xor_bytes(b1: bytes, b2: bytes) -> bytes:
    """Effectue un XOR octet par octet entre deux séquences de même longueur."""
    return bytes(x ^ y for x, y in zip(b1, b2))


def oaep_pad(message: bytes, k: int, label: bytes = b"", hash_name: str = "sha256") -> bytes:
    """
    Remplissage OAEP (Optimal Asymmetric Encryption Padding) pour RSA.
    - k : taille en octets du module n (ex: 128 pour RSA 1024, 256 pour RSA 2048).
    - label : étiquette optionnelle (vide par défaut).
    Structure : 0x00 || maskedSeed || maskedDB
    """
    hasher_func = getattr(hashlib, hash_name)
    h_len = hasher_func().digest_size
    m_len = len(message)

    if m_len > k - 2 * h_len - 2:
        raise ValueError(f"Message trop long pour le chiffrement RSA-OAEP (max: {k - 2*h_len - 2} octets).")

    # 1. Calcul du haché du label
    l_hash = hasher_func(label).digest()

    # 2. Construction du bloc de données DB = lHash || PS || 0x01 || M
    # où PS est une suite d'octets 0x00 de longueur k - mLen - 2*hLen - 2
    ps_len = k - m_len - 2 * h_len - 2
    ps = b"\x00" * ps_len
    db = l_hash + ps + b"\x01" + message

    # 3. Génération d'une graine aléatoire de hLen octets
    seed = os.urandom(h_len)

    # 4. Masquage DB : maskedDB = DB ^ MGF1(seed, k - hLen - 1)
    db_mask = mgf1(seed, k - h_len - 1, hash_name)
    masked_db = xor_bytes(db, db_mask)

    # 5. Masquage Seed : maskedSeed = seed ^ MGF1(maskedDB, hLen)
    seed_mask = mgf1(masked_db, h_len, hash_name)
    masked_seed = xor_bytes(seed, seed_mask)

    # 6. Concaténation : 0x00 || maskedSeed || maskedDB
    em = b"\x00" + masked_seed + masked_db
    return em


def oaep_unpad(em: bytes, k: int, label: bytes = b"", hash_name: str = "sha256") -> bytes:
    """
    Dé-remplissage et vérification OAEP selon la RFC 8017.
    Lève une ValueError si le padding est invalide ou corrompu.
    """
    hasher_func = getattr(hashlib, hash_name)
    h_len = hasher_func().digest_size

    if len(em) != k or k < 2 * h_len + 2:
        raise ValueError("Longueur de bloc de déchiffrement invalide.")

    # Vérification du premier octet 0x00
    first_byte = em[0]
    masked_seed = em[1 : 1 + h_len]
    masked_db = em[1 + h_len :]

    # 1. Récupération de la graine
    seed_mask = mgf1(masked_db, h_len, hash_name)
    seed = xor_bytes(masked_seed, seed_mask)

    # 2. Récupération de DB
    db_mask = mgf1(seed, k - h_len - 1, hash_name)
    db = xor_bytes(masked_db, db_mask)

    # 3. Séparation et validation de DB = lHash' || PS || 0x01 || M
    l_hash = hasher_func(label).digest()
    l_hash_prime = db[:h_len]

    # Vérification de conformité de lHash
    lhash_ok = hmac.compare_digest(l_hash, l_hash_prime)
    first_byte_ok = (first_byte == 0)

    # Recherche du séparateur 0x01 après PS
    idx = h_len
    while idx < len(db) and db[idx] == 0:
        idx += 1

    if idx >= len(db) or db[idx] != 1 or not lhash_ok or not first_byte_ok:
        raise ValueError("Erreur de déchiffrement OAEP (padding altéré ou invalide).")

    # Le message M suit le séparateur 0x01
    return db[idx + 1 :]


# 5. Chiffrement et Déchiffrement Haut Niveau (OAEP + CRT)

def rsa_encrypt(message: bytes, pub: RSAPublicKey, hash_name: Optional[str] = None) -> bytes:
    """
    Chiffre un message avec RSA-OAEP.
    Utilise SHA-256 pour les clés >= 1024 bits et SHA-1 pour les clés de 512 bits.
    """
    if hash_name is None:
        hash_name = "sha1" if pub.byte_length < 128 else "sha256"

    em = oaep_pad(message, pub.byte_length, hash_name=hash_name)
    m_int = int.from_bytes(em, "big")
    c_int = rsa_encrypt_int(m_int, pub)
    return c_int.to_bytes(pub.byte_length, "big")


def rsa_decrypt(ciphertext: bytes, priv: RSAPrivateKey, use_crt: bool = True, hash_name: Optional[str] = None) -> bytes:
    """
    Déchiffre un bloc RSA-OAEP avec accélération CRT (par défaut).
    """
    if len(ciphertext) != priv.byte_length:
        raise ValueError(f"Le chiffré doit mesurer exactement {priv.byte_length} octets.")

    if hash_name is None:
        hash_name = "sha1" if priv.byte_length < 128 else "sha256"

    c_int = int.from_bytes(ciphertext, "big")
    if use_crt:
        m_int = rsa_decrypt_int_crt(c_int, priv)
    else:
        m_int = rsa_decrypt_int_raw(c_int, priv)

    em = m_int.to_bytes(priv.byte_length, "big")
    return oaep_unpad(em, priv.byte_length, hash_name=hash_name)


# 6. Signature et Vérification RSA (PKCS#1 v1.5)

# Préfixe ASN.1 DigestInfo pour SHA-256 selon la RFC 8017
SHA256_ASN1_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def rsa_sign(message: bytes, priv: RSAPrivateKey) -> bytes:
    """
    Signe un message en utilisant le schéma RSA PKCS#1 v1.5 avec SHA-256.
    Structure du bloc émis : 0x00 || 0x01 || PS (0xFF...) || 0x00 || T
    où T = DigestInfo(SHA256) || SHA256(message).
    """
    h = hashlib.sha256(message).digest()
    t = SHA256_ASN1_PREFIX + h
    k = priv.byte_length

    if len(t) + 11 > k:
        raise ValueError("Taille de clé insuffisante pour la signature.")

    ps = b"\xff" * (k - len(t) - 3)
    em = b"\x00\x01" + ps + b"\x00" + t

    m_int = int.from_bytes(em, "big")
    # Signature par calcul CRT : s = m^d mod n
    s_int = rsa_decrypt_int_crt(m_int, priv)
    return s_int.to_bytes(k, "big")


def rsa_verify(message: bytes, signature: bytes, pub: RSAPublicKey) -> bool:
    """
    Vérifie une signature RSA PKCS#1 v1.5 avec la clé publique.
    """
    if len(signature) != pub.byte_length:
        return False

    s_int = int.from_bytes(signature, "big")
    # Vérification : em' = s^e mod n
    m_int = rsa_encrypt_int(s_int, pub)
    em = m_int.to_bytes(pub.byte_length, "big")

    # Reconstitution du bloc attendu
    h = hashlib.sha256(message).digest()
    t = SHA256_ASN1_PREFIX + h
    k = pub.byte_length
    ps = b"\xff" * (k - len(t) - 3)
    expected_em = b"\x00\x01" + ps + b"\x00" + t

    return hmac.compare_digest(em, expected_em)


# 7. Chiffrement Hybride de Fichiers (RSA-OAEP + AES-GCM)

def encrypt_file_hybrid(input_path: str, output_path: str, pub: RSAPublicKey) -> None:
    """
    Chiffre un fichier volumineux avec un schéma hybride :
    1. Génère une clé de session aléatoire de 256 bits.
    2. Chiffre le fichier avec AES-256-GCM.
    3. Chiffre la clé symétrique avec RSA-OAEP.
    Format du fichier chiffré :
    [2 octets : taille_cle_rsa_chiffree][cle_rsa_chiffree][12 octets : nonce][donnees_chiffrees + tag]
    """
    session_key = os.urandom(32)  # Clé AES-256
    nonce = os.urandom(12)         # Nonce AES-GCM standard

    with open(input_path, "rb") as f:
        plaintext = f.read()

    aesgcm = AESGCM(session_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    # Chiffrement de la clé de session avec RSA-OAEP
    encrypted_key = rsa_encrypt(session_key, pub)

    with open(output_path, "wb") as f:
        f.write(len(encrypted_key).to_bytes(2, "big"))
        f.write(encrypted_key)
        f.write(nonce)
        f.write(ciphertext)


def decrypt_file_hybrid(input_path: str, output_path: str, priv: RSAPrivateKey) -> None:
    """
    Déchiffre un fichier chiffré en mode hybride avec la clé privée RSA.
    """
    with open(input_path, "rb") as f:
        key_len = int.from_bytes(f.read(2), "big")
        encrypted_key = f.read(key_len)
        nonce = f.read(12)
        ciphertext = f.read()

    # Déchiffrement de la clé de session RSA-OAEP
    session_key = rsa_decrypt(encrypted_key, priv)

    aesgcm = AESGCM(session_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    with open(output_path, "wb") as f:
        f.write(plaintext)
