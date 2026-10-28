"""
Module 4 : Protocole de Diffie–Hellman et Dérivation HKDF
- Échange de clés Diffie–Hellman (RFC 3526 - Groupe MODP 2048 bits et groupe 512 bits)
- Dérivation de clés HKDF (RFC 5869) basée sur notre HMAC (Module 1)
- Validation rigoureuse des clés publiques reçues
- Échange Diffie–Hellman authentifié par signatures RSA (Module 3)
"""

import os
import sys
import secrets
from typing import Tuple, Optional

# Import des briques du Module 1 (HMAC) et Module 2 (Arithmétique)
from cryptolib.hashing import custom_hmac
from cryptolib.numtheory import exp_mod
from cryptolib.rsa import RSAPublicKey, RSAPrivateKey, rsa_sign, rsa_verify


# 1. Groupes Diffie–Hellman Standardisés (RFC 3526)

# Groupe MODP 2048 bits (RFC 3526, Groupe 14)
# p = 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }
# Premier sûr : p = 2q + 1, g = 2
RFC3526_2048_MODP_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)

# Groupe 512 bits pour les tests rapides et le laboratoire
TEST_512_MODP_HEX = (
    "D6031998D1B3BBFEBF597E554B417567D780B7363025163DD82340E8809E4857"
    "36F1D0297056088A37F0C00E6CE69CE772F9523C643BF4F2D0A282063A521747"
)


class DHGroup:
    """Paramètres d'un groupe Diffie–Hellman (p, g)."""

    def __init__(self, p: int, g: int = 2, name: str = "custom"):
        self.p = p
        self.g = g
        self.name = name
        self.bit_length = p.bit_length()
        self.byte_length = (self.bit_length + 7) // 8

    @classmethod
    def rfc3526_2048(cls) -> "DHGroup":
        return cls(p=int(RFC3526_2048_MODP_HEX, 16), g=2, name="RFC3526-2048")

    @classmethod
    def test_512(cls) -> "DHGroup":
        return cls(p=int(TEST_512_MODP_HEX, 16), g=2, name="TEST-512")


# 2. Clé Éphémère et Calcul du Secret Partagé

class DHEphemeral:
    """
    Session Diffie–Hellman éphémère (DHE) pour garantir la Perfect Forward Secrecy.
    """

    def __init__(self, group: Optional[DHGroup] = None):
        if group is None:
            group = DHGroup.rfc3526_2048()
        self.group = group

        # Génération d'un exposant secret x dans [2, p - 2]
        # Pour 2048 bits, un exposant aléatoire de 256 à 320 bits est suffisant et sécurisé
        exp_bits = min(320, self.group.bit_length - 2)
        self.private_key = secrets.randbits(exp_bits) | 1

        # Calcul de la clé publique éphémère : X = g^x mod p
        self.public_key = exp_mod(self.group.g, self.private_key, self.group.p)

    def compute_shared_secret(self, peer_public_key: int) -> int:
        """
        Calcule le secret partagé brut K = Y^x mod p.
        Vérifie rigoureusement la validité de la clé publique distante pour éviter
        les attaques par sous-groupes invalides (interdit 1, p - 1, <= 0 ou >= p).
        """
        if not (2 <= peer_public_key <= self.group.p - 2):
            raise ValueError(f"Clé publique distante invalide pour Diffie–Hellman (reçu: {peer_public_key}).")

        # K = peer_public_key ^ x mod p
        shared_secret = exp_mod(peer_public_key, self.private_key, self.group.p)

        # Vérification supplémentaire : K ne doit pas être 1 ou p - 1
        if shared_secret in (1, self.group.p - 1):
            raise ValueError("Secret partagé trivial détecté (attaque possible).")

        return shared_secret


# 3. Fonction de Dérivation de Clés HKDF (RFC 5869)

def hkdf_extract(salt: Optional[bytes], ikm: bytes, hash_name: str = "sha256") -> bytes:
    """
    Étape HKDF-Extract : PRK = HMAC-Hash(salt, IKM)
    Si le sel n'est pas fourni, un sel de zéros de la taille du haché est utilisé.
    """
    hash_len = 32 if hash_name == "sha256" else 20
    if not salt:
        salt = b"\x00" * hash_len
    return custom_hmac(salt, ikm, hash_name)


def hkdf_expand(prk: bytes, info: bytes, length: int, hash_name: str = "sha256") -> bytes:
    """
    Étape HKDF-Expand : OKM = T(1) || T(2) || ... || T(N)
    T(1) = HMAC-Hash(PRK, info || 0x01)
    T(2) = HMAC-Hash(PRK, T(1) || info || 0x02)
    """
    hash_len = len(prk)
    n = (length + hash_len - 1) // hash_len
    if n > 255:
        raise ValueError("Longueur de sortie HKDF trop grande (max 255 * hash_len).")

    okm = bytearray()
    t = b""
    for i in range(1, n + 1):
        t = custom_hmac(prk, t + info + bytes([i]), hash_name)
        okm.extend(t)

    return bytes(okm[:length])


def hkdf(ikm: bytes, length: int, salt: Optional[bytes] = None, info: bytes = b"", hash_name: str = "sha256") -> bytes:
    """Fonction complète HKDF (Extract and Expand)."""
    prk = hkdf_extract(salt, ikm, hash_name)
    return hkdf_expand(prk, info, length, hash_name)


def derive_session_keys(shared_secret_int: int, salt: bytes = b"", info: bytes = b"CryptoVault-DH-Session") -> Tuple[bytes, bytes]:
    """
    Convertit le secret partagé entier K en octets et dérive deux clés symétriques indépendantes :
    - key_enc : clé de chiffrement AES-256 (32 octets)
    - key_mac : clé d'authentification HMAC-SHA256 (32 octets)
    """
    # Conversion du secret entier en octets (big-endian)
    secret_bytes = shared_secret_int.to_bytes((shared_secret_int.bit_length() + 7) // 8, "big")
    derived_material = hkdf(secret_bytes, length=64, salt=salt, info=info, hash_name="sha256")
    key_enc = derived_material[:32]
    key_mac = derived_material[32:64]
    return key_enc, key_mac


# 4. Échange Diffie–Hellman Authentifié (Contre-mesure MITM)

def sign_dh_public_key(dh_pub: int, priv_rsa: RSAPrivateKey) -> bytes:
    """
    Signe une clé publique Diffie–Hellman éphémère avec la clé RSA à long terme de l'émetteur.
    """
    pub_bytes = dh_pub.to_bytes((dh_pub.bit_length() + 7) // 8, "big")
    return rsa_sign(pub_bytes, priv_rsa)


def verify_dh_public_key(dh_pub: int, signature: bytes, pub_rsa: RSAPublicKey) -> bool:
    """
    Vérifie l'authenticité de la clé publique DH éphémère avec la clé publique RSA de l'interlocuteur.
    """
    pub_bytes = dh_pub.to_bytes((dh_pub.bit_length() + 7) // 8, "big")
    return rsa_verify(pub_bytes, signature, pub_rsa)
