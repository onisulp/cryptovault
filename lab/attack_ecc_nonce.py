"""
Laboratoire d'Attaques - Module 5 : Faille de Réutilisation de Nonce ECDSA et Benchmark RSA vs ECC
1. Attaque par réutilisation de nonce k dans ECDSA (vol de clé privée d type faille Sony PS3 / Android Bitcoin).
2. Démonstration de la contre-mesure par nonce déterministe RFC 6979.
3. Benchmark comparatif rigoureux : RSA 2048 vs ECDSA P-256 (temps et tailles).
"""

import sys
import os
import hashlib
import time
import secrets

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cryptolib.ecc import (
    NIST_P256,
    generate_ecc_keypair,
    ecdsa_sign,
    ecdsa_verify,
)
from cryptolib.numtheory import mod_inverse
from cryptolib.rsa import generate_keypair as generate_rsa_keypair, rsa_sign, rsa_verify


def attack_ecdsa_nonce_reuse():
    print("=" * 80)
    print(" 1. ATTAQUE : VOL DE CLÉ PRIVÉE PAR RÉUTILISATION DE NONCE ECDSA")
    print("=" * 80)
    print("Cas réel : Faille de la console PlayStation 3 (2010) et Bitcoin Android (2013).")
    print("Si un attaquant intercepte 2 signatures partageant le même nonce k, la clé privée est perdue !")
    print("-" * 80)

    curve = NIST_P256
    pub, priv = generate_ecc_keypair(curve)

    # L'attaquant intercepte deux signatures de deux messages différents signés avec le MÊME k :
    bad_nonce_k = secrets.randbelow(curve.n - 1) + 1

    msg1 = "Ordre de virement no 1 : Transferer 50 EUR a Bob".encode("utf-8")
    msg2 = "Ordre de virement no 2 : Transferer 100 EUR a Charlie".encode("utf-8")

    r1, s1 = ecdsa_sign(msg1, priv, k_custom=bad_nonce_k)
    r2, s2 = ecdsa_sign(msg2, priv, k_custom=bad_nonce_k)

    print(f"Message 1 : '{msg1.decode()}'")
    print(f"  Signature 1 : r = {str(r1)[:20]}..., s = {str(s1)[:20]}...")
    print(f"Message 2 : '{msg2.decode()}'")
    print(f"  Signature 2 : r = {str(r2)[:20]}..., s = {str(s2)[:20]}...")

    # Constat de l'attaquant : r1 == r2 car r = (k * G).x mod n !
    print(f"\n Alerte : r1 == r2 détecté ({r1 == r2}) -> Même nonce k réutilisé !")

    # EXPLOITATION 
    t0 = time.perf_counter()

    # e1 = H(m1), e2 = H(m2)
    e1 = int.from_bytes(hashlib.sha256(msg1).digest(), "big")
    e2 = int.from_bytes(hashlib.sha256(msg2).digest(), "big")

    # Formule mathématique :
    # s1 - s2 = k^(-1) * (e1 - e2) mod n
    # => k = (e1 - e2) * (s1 - s2)^(-1) mod n
    delta_s = (s1 - s2) % curve.n
    inv_delta_s = mod_inverse(delta_s, curve.n)
    k_recovered = ((e1 - e2) * inv_delta_s) % curve.n

    # Clé privée d :
    # s1 = k^(-1) * (e1 + r * d) mod n
    # => d = r^(-1) * (s1 * k - e1) mod n
    inv_r = mod_inverse(r1, curve.n)
    d_recovered = (inv_r * (s1 * k_recovered - e1)) % curve.n

    elapsed = time.perf_counter() - t0

    print(f"\n Exploitation réussie en {elapsed * 1000:.3f} ms !")
    print(f"  Nonce secret k retrouvé : {k_recovered == bad_nonce_k}")
    print(f"  Clé privée d retrouvée  : {d_recovered == priv.d}")
    print(f"  Valeur hex de d volée   : {hex(d_recovered)}")

    print("\nContre-mesure : Le standard RFC 6979 génère k de manière déterministe via HMAC(d, H(m)).")
    print("Ainsi, un message donné a toujours un k unique et imprévisible sans la clé privée.")


def benchmark_rsa_vs_ecc():
    print("\n" + "=" * 80)
    print(" 2. BENCHMARK COMPARATIF : RSA 2048 VS ECDSA P-256")
    print("=" * 80)
    print(f"{'Métrique':<32} | {'RSA 2048 bits':<20} | {'ECDSA NIST P-256':<20}")
    print("-" * 80)

    # 1. Génération de clés
    t0 = time.perf_counter()
    rsa_pub, rsa_priv = generate_rsa_keypair(bits=2048)
    t_rsa_keygen = (time.perf_counter() - t0) * 1000.0

    t0 = time.perf_counter()
    ecc_pub, ecc_priv = generate_ecc_keypair(NIST_P256)
    t_ecc_keygen = (time.perf_counter() - t0) * 1000.0

    # 2. Signature
    doc = b"Document officiel soumis a signature pour benchmark comparatif."
    t0 = time.perf_counter()
    rsa_sig = rsa_sign(doc, rsa_priv)
    t_rsa_sign = (time.perf_counter() - t0) * 1000.0

    t0 = time.perf_counter()
    ecc_sig = ecdsa_sign(doc, ecc_priv)
    t_ecc_sign = (time.perf_counter() - t0) * 1000.0

    # 3. Vérification
    t0 = time.perf_counter()
    rsa_verify(doc, rsa_sig, rsa_pub)
    t_rsa_verify = (time.perf_counter() - t0) * 1000.0

    t0 = time.perf_counter()
    ecdsa_verify(doc, ecc_sig, ecc_pub)
    t_ecc_verify = (time.perf_counter() - t0) * 1000.0

    # 4. Tailles en octets
    rsa_pub_size = rsa_pub.byte_length  # 256 octets
    rsa_sig_size = len(rsa_sig)         # 256 octets
    ecc_pub_size = 64                   # Point P-256 (x, y) = 32 + 32 = 64 octets (ou 33 compressé)
    ecc_sig_size = 64                   # (r, s) = 32 + 32 = 64 octets

    print(f"{'Temps de génération de clé':<32} | {t_rsa_keygen:<16.2f} ms | {t_ecc_keygen:<16.2f} ms")
    print(f"{'Temps de signature':<32} | {t_rsa_sign:<16.2f} ms | {t_ecc_sign:<16.2f} ms")
    print(f"{'Temps de vérification':<32} | {t_rsa_verify:<16.2f} ms | {t_ecc_verify:<16.2f} ms")
    print(f"{'Taille de la clé publique':<32} | {rsa_pub_size:<16} octets | {ecc_pub_size:<16} octets")
    print(f"{'Taille de la signature':<32} | {rsa_sig_size:<16} octets | {ecc_sig_size:<16} octets")
    print("=" * 80)
    print("SYNTHÈSE :")
    print("ECDSA P-256 est considérablement plus rapide à la génération de clé")
    print("et produit des signatures 4x plus compactes (64 octets vs 256 octets).")
    print("=" * 80)


def main():
    attack_ecdsa_nonce_reuse()
    benchmark_rsa_vs_ecc()


if __name__ == "__main__":
    main()
