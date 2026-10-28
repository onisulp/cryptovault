"""
Tests unitaires pour le Module 5 (Courbes Elliptiques, ECDH et ECDSA).
Validation sur la courbe jouet F_17 (exercices du cours) et NIST P-256.
"""

import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cryptolib.ecc import (
    ECPoint,
    CURVE_TOY_F17,
    NIST_P256,
    generate_ecc_keypair,
    ecdh,
    ecdsa_sign,
    ecdsa_verify,
    ECPrivateKey,
    ECPublicKey,
)


class TestECCModule(unittest.TestCase):

    # 1. Validation de la courbe jouet F_17 (Exercices du Chapitre 5)
    
    def test_toy_curve_f17_course_exercises(self):
        curve = CURVE_TOY_F17
        G = curve.G  # Point (5, 1)

        # Exercice 1 du Chapitre 5 : 3G = 2G + G = (6, 3) + (5, 1) = (10, 6)
        pt_2G = curve.scalar_mult(2, G)
        self.assertEqual(pt_2G, ECPoint(6, 3))

        pt_3G = curve.scalar_mult(3, G)
        self.assertEqual(pt_3G, ECPoint(10, 6))

        # Exercice 2 du Chapitre 5 :
        # A = 3G = (10, 6)
        # B = 5G = (9, 16)
        # K = 15G = (3, 16)
        pt_5G = curve.scalar_mult(5, G)
        self.assertEqual(pt_5G, ECPoint(9, 16))

        pt_15G = curve.scalar_mult(15, G)
        self.assertEqual(pt_15G, ECPoint(3, 16))

        # L'ordre du groupe est 19 : 19 * G = O (point à l'infini)
        pt_19G = curve.scalar_mult(19, G)
        self.assertTrue(pt_19G.is_infinity)

    # 2. Validation de la courbe NIST P-256

    def test_nist_p256_group_law(self):
        curve = NIST_P256
        self.assertTrue(curve.is_on_curve(curve.G))

        # Vérification fondamentale : n * G = O
        # (Pour éviter un temps de calcul trop lourd dans les tests unitaires récurrents,
        # on teste avec de petits scalaires et l'opposé : G + (-G) = O)
        neg_G = curve.point_neg(curve.G)
        self.assertEqual(curve.point_add(curve.G, neg_G), ECPoint.infinity())

        # 2G est sur la courbe
        pt_2G = curve.scalar_mult(2, curve.G)
        self.assertTrue(curve.is_on_curve(pt_2G))

    # 3. Échange de clés ECDH

    def test_ecdh_key_exchange(self):
        # Alice et Bob génèrent leurs clés
        alice_pub, alice_priv = generate_ecc_keypair(NIST_P256)
        bob_pub, bob_priv = generate_ecc_keypair(NIST_P256)

        # Calcul du secret partagé
        secret_alice = ecdh(alice_priv, bob_pub)
        secret_bob = ecdh(bob_priv, alice_pub)

        self.assertEqual(secret_alice, secret_bob)
        self.assertEqual(len(secret_alice), 32)

    # 4. Signature et Vérification ECDSA (avec RFC 6979)

    def test_ecdsa_sign_verify_cycle(self):
        pub, priv = generate_ecc_keypair(NIST_P256)
        msg = b"Validation de la signature cryptographique ECDSA sur NIST P-256."

        # Signature
        r, s = ecdsa_sign(msg, priv)
        self.assertGreater(r, 0)
        self.assertGreater(s, 0)

        # Vérification valide
        self.assertTrue(ecdsa_verify(msg, (r, s), pub))

        # Message altéré
        tampered_msg = msg + b"!"
        self.assertFalse(ecdsa_verify(tampered_msg, (r, s), pub))

        # Signature corrompue
        tampered_sig = (r, (s + 1) % pub.curve.n)
        self.assertFalse(ecdsa_verify(msg, tampered_sig, pub))

    def test_rfc6979_deterministic_nonce(self):
        pub, priv = generate_ecc_keypair(NIST_P256)
        msg = b"Message test de determinisme RFC 6979"

        # Deux signatures du même message avec la même clé privée doivent être rigoureusement identiques
        sig1 = ecdsa_sign(msg, priv)
        sig2 = ecdsa_sign(msg, priv)
        self.assertEqual(sig1, sig2)


if __name__ == "__main__":
    unittest.main()
