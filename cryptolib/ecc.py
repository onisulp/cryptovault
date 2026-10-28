"""
Module 5 : Courbes Elliptiques, ECDH et ECDSA
- Arithmétique complète sur les courbes de Weierstrass sur F_p
- Courbe jouet F_17 et courbe standard NIST P-256 (secp256r1)
- Échange de clés ECDH (Elliptic Curve Diffie–Hellman)
- Signature numérique ECDSA (Elliptic Curve Digital Signature Algorithm)
- Génération déterministe de nonce k selon la RFC 6979
"""

import os
import sys
import hashlib
import hmac
import secrets
from typing import Tuple, Optional, Dict, Any

from cryptolib.numtheory import exp_mod, mod_inverse


# 1. Représentation d'un Point et d'une Courbe de Weierstrass

class ECPoint:
    """Représente un point sur une courbe elliptique (x, y) ou le point à l'infini O."""

    def __init__(self, x: Optional[int], y: Optional[int], is_infinity: bool = False):
        self.is_infinity = is_infinity
        self.x = None if is_infinity else x
        self.y = None if is_infinity else y

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, ECPoint):
            return False
        if self.is_infinity and other.is_infinity:
            return True
        if self.is_infinity != other.is_infinity:
            return False
        return self.x == other.x and self.y == other.y

    def __repr__(self) -> str:
        if self.is_infinity:
            return "Point(∞)"
        return f"Point({self.x}, {self.y})"

    @classmethod
    def infinity(cls) -> "ECPoint":
        return cls(None, None, is_infinity=True)


class EllipticCurve:
    """
    Courbe elliptique de Weierstrass sous forme courte :
    y^2 ≡ x^3 + a*x + b (mod p)
    avec 4*a^3 + 27*b^2 != 0 (mod p).
    """

    def __init__(self, p: int, a: int, b: int, G: ECPoint, n: int, h: int = 1, name: str = "custom"):
        self.p = p
        self.a = a % p
        self.b = b % p
        self.G = G
        self.n = n  # Ordre du générateur G
        self.h = h  # Cofacteur
        self.name = name

        # Vérification du discriminant : 4*a^3 + 27*b^2 != 0 (mod p)
        disc = (4 * pow(self.a, 3, p) + 27 * pow(self.b, 2, p)) % p
        if disc == 0:
            raise ValueError("Discriminant nul : la courbe est singulière.")

        # Vérifier que le point générateur G est bien sur la courbe
        if not self.is_on_curve(G):
            raise ValueError(f"Le générateur G {G} n'appartient pas à la courbe.")

    def is_on_curve(self, pt: ECPoint) -> bool:
        """Vérifie si le point pt vérifie l'équation de Weierstrass modulo p."""
        if pt.is_infinity:
            return True
        lhs = pow(pt.y, 2, self.p)
        rhs = (pow(pt.x, 3, self.p) + self.a * pt.x + self.b) % self.p
        return lhs == rhs

    def point_neg(self, pt: ECPoint) -> ECPoint:
        """Retourne l'opposé d'un point : -(x, y) = (x, -y mod p)."""
        if pt.is_infinity:
            return pt
        return ECPoint(pt.x, (-pt.y) % self.p)

    def point_add(self, P: ECPoint, Q: ECPoint) -> ECPoint:
        """
        Addition de deux points P + Q selon la loi de groupe géométrique/algébrique.
        """
        # 1. Éléments neutres
        if P.is_infinity:
            return Q
        if Q.is_infinity:
            return P

        # 2. P + (-P) = O
        if P.x == Q.x and (P.y + Q.y) % self.p == 0:
            return ECPoint.infinity()

        # 3. Calcul de la pente lambda
        if P == Q:
            # Doublement : 2P (tangente)
            if P.y == 0:
                return ECPoint.infinity()
            inv_2y = mod_inverse((2 * P.y) % self.p, self.p)
            slope = ((3 * pow(P.x, 2, self.p) + self.a) * inv_2y) % self.p
        else:
            # Addition de deux points distincts (sécante)
            inv_dx = mod_inverse((Q.x - P.x) % self.p, self.p)
            slope = ((Q.y - P.y) * inv_dx) % self.p

        # 4. Coordonnées du point résultant
        x3 = (pow(slope, 2, self.p) - P.x - Q.x) % self.p
        y3 = (slope * (P.x - x3) - P.y) % self.p

        return ECPoint(x3, y3)

    def scalar_mult(self, k: int, P: ECPoint) -> ECPoint:
        """
        Multiplication scalaire k * P par l'algorithme Double-and-Add.
        """
        if P.is_infinity or k == 0:
            return ECPoint.infinity()
        if k < 0:
            return self.scalar_mult(-k, self.point_neg(P))

        result = ECPoint.infinity()
        addend = P

        while k > 0:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_add(addend, addend)
            k >>= 1

        return result


# 2. Courbes Standardisées : Toy Curve F17 et NIST P-256

# Courbe jouet du cours (Chapitre 5) : y^2 = x^3 + 2x + 2 sur F_17, G = (5, 1), ordre n = 19
CURVE_TOY_F17 = EllipticCurve(
    p=17,
    a=2,
    b=2,
    G=ECPoint(5, 1),
    n=19,
    h=1,
    name="Toy-F17",
)

# Courbe standardisée NIST P-256 (secp256r1)
P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_A = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

NIST_P256 = EllipticCurve(
    p=P256_P,
    a=P256_A,
    b=P256_B,
    G=ECPoint(P256_GX, P256_GY),
    n=P256_N,
    h=1,
    name="NIST-P256",
)


# 3. Paires de Clés ECC

class ECPublicKey:
    """Clé publique ECC : point Q = d * G sur la courbe."""

    def __init__(self, Q: ECPoint, curve: EllipticCurve = NIST_P256):
        self.Q = Q
        self.curve = curve

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "EC_PUBLIC_KEY",
            "curve": self.curve.name,
            "x": hex(self.Q.x) if self.Q.x is not None else None,
            "y": hex(self.Q.y) if self.Q.y is not None else None,
        }


class ECPrivateKey:
    """Clé privée ECC : entier secret d dans [1, n - 1]."""

    def __init__(self, d: int, curve: EllipticCurve = NIST_P256):
        self.d = d
        self.curve = curve
        self.public_key = ECPublicKey(curve.scalar_mult(d, curve.G), curve)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "EC_PRIVATE_KEY",
            "curve": self.curve.name,
            "d": hex(self.d),
            "public_key": self.public_key.to_dict(),
        }


def generate_ecc_keypair(curve: EllipticCurve = NIST_P256) -> Tuple[ECPublicKey, ECPrivateKey]:
    """Génère une paire de clés ECC aléatoire."""
    d = secrets.randbelow(curve.n - 1) + 1
    priv = ECPrivateKey(d, curve)
    return priv.public_key, priv


# 4. Échange de Clés ECDH (Elliptic Curve Diffie–Hellman)

def ecdh(priv: ECPrivateKey, peer_pub: ECPublicKey) -> bytes:
    """
    Calcule le secret partagé ECDH : S = priv.d * peer_pub.Q.
    Retourne le haché SHA-256 de la coordonnée S.x (32 octets).
    """
    if priv.curve.name != peer_pub.curve.name:
        raise ValueError("Les clés doivent appartenir à la même courbe.")

    # Calcul du point secret partagé
    S = priv.curve.scalar_mult(priv.d, peer_pub.Q)
    if S.is_infinity:
        raise ValueError("Le secret partagé obtenu est le point à l'infini (attaque détectée).")

    # Encodage de la coordonnée x en 32 octets
    byte_len = (priv.curve.p.bit_length() + 7) // 8
    x_bytes = S.x.to_bytes(byte_len, "big")
    return hashlib.sha256(x_bytes).digest()


# 5. Nonce Déterministe RFC 6979

def rfc6979_generate_k(msg_hash: bytes, priv_d: int, order: int) -> int:
    """
    Génère un nonce k cryptographiquement sûr et déterministe selon la RFC 6979 (Section 3.2).
    Élimine définitivement le risque de réutilisation de nonce.
    """
    qlen = order.bit_length()
    hlen = len(msg_hash) * 8
    order_bytes = (qlen + 7) // 8

    x_bytes = priv_d.to_bytes(order_bytes, "big")
    # Tronquer ou ajuster h1
    h1 = msg_hash[:order_bytes]

    # Étape a : V = 0x01...01 (32 octets)
    V = b"\x01" * 32
    # Étape b : K = 0x00...00 (32 octets)
    K = b"\x00" * 32

    # Étape c : K = HMAC_K(V || 0x00 || x || h1)
    K = hmac.new(K, V + b"\x00" + x_bytes + h1, hashlib.sha256).digest()
    # Étape d : V = HMAC_K(V)
    V = hmac.new(K, V, hashlib.sha256).digest()
    # Étape e : K = HMAC_K(V || 0x01 || x || h1)
    K = hmac.new(K, V + b"\x01" + x_bytes + h1, hashlib.sha256).digest()
    # Étape f : V = HMAC_K(V)
    V = hmac.new(K, V, hashlib.sha256).digest()

    # Étape g : boucle de génération
    while True:
        T = b""
        while len(T) < order_bytes:
            V = hmac.new(K, V, hashlib.sha256).digest()
            T += V

        k = int.from_bytes(T[:order_bytes], "big")
        if 1 <= k < order:
            return k

        K = hmac.new(K, V + b"\x00", hashlib.sha256).digest()
        V = hmac.new(K, V, hashlib.sha256).digest()


# 6. Signature et Vérification ECDSA

def ecdsa_sign(message: bytes, priv: ECPrivateKey, k_custom: Optional[int] = None) -> Tuple[int, int]:
    """
    Signe un message avec ECDSA.
    Si k_custom n'est pas spécifié, utilise un nonce déterministe selon la RFC 6979.
    Retourne la signature (r, s).
    """
    curve = priv.curve
    msg_hash = hashlib.sha256(message).digest()
    e = int.from_bytes(msg_hash, "big")

    while True:
        if k_custom is not None:
            k = k_custom
        else:
            k = rfc6979_generate_k(msg_hash, priv.d, curve.n)

        # 1. Calcul du point R = k * G = (x1, y1)
        R = curve.scalar_mult(k, curve.G)
        if R.is_infinity:
            if k_custom is not None:
                raise ValueError("k invalide (produit le point à l'infini).")
            continue

        # 2. r = x1 mod n
        r = R.x % curve.n
        if r == 0:
            if k_custom is not None:
                raise ValueError("k invalide (r = 0 mod n).")
            continue

        # 3. s = k^(-1) * (e + r * d) mod n
        k_inv = mod_inverse(k, curve.n)
        s = (k_inv * (e + r * priv.d)) % curve.n
        if s == 0:
            if k_custom is not None:
                raise ValueError("k invalide (s = 0 mod n).")
            continue

        return r, s


def ecdsa_verify(message: bytes, signature: Tuple[int, int], pub: ECPublicKey) -> bool:
    """
    Vérifie une signature ECDSA (r, s) avec la clé publique.
    """
    r, s = signature
    curve = pub.curve

    # 1. Vérification que r et s sont dans [1, n - 1]
    if not (1 <= r < curve.n and 1 <= s < curve.n):
        return False

    # 2. e = H(m)
    msg_hash = hashlib.sha256(message).digest()
    e = int.from_bytes(msg_hash, "big")

    # 3. w = s^(-1) mod n
    w = mod_inverse(s, curve.n)

    # 4. u1 = e * w mod n, u2 = r * w mod n
    u1 = (e * w) % curve.n
    u2 = (r * w) % curve.n

    # 5. R' = u1 * G + u2 * Q
    pt1 = curve.scalar_mult(u1, curve.G)
    pt2 = curve.scalar_mult(u2, pub.Q)
    R_prime = curve.point_add(pt1, pt2)

    if R_prime.is_infinity:
        return False

    # 6. Vérifier si x(R') mod n == r
    return (R_prime.x % curve.n) == r
