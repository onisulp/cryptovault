"""
Tests unitaires pour le Module 4 (Protocole de Diffie–Hellman et HKDF).
Validation par les exercices du cours, le groupe 2048 bits de la RFC 3526,
et les vecteurs officiels HKDF-SHA256 de la RFC 5869.
"""

import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cryptolib.dh import (
    DHGroup,
    DHEphemeral,
    hkdf_extract,
    hkdf_expand,
    hkdf,
    derive_session_keys,
    sign_dh_public_key,
    verify_dh_public_key,
)
from cryptolib.rsa import generate_keypair
from cryptolib.numtheory import exp_mod


class TestDHModule(unittest.TestCase):

    # 1. Exercice 1 du Chapitre 4 du cours
    
    def test_course_exercise_dh_numerical(self):
        # Paramètres de l'exercice : p = 17, g = 3
        p = 17
        g = 3
        a = 5
        b = 7

        # Calcul d'Alice : A = g^a mod p = 3^5 mod 17 = 5
        A = exp_mod(g, a, p)
        self.assertEqual(A, 5)

        # Calcul de Bob : B = g^b mod p = 3^7 mod 17 = 11
        B = exp_mod(g, b, p)
        self.assertEqual(B, 11)

        # Secret partagé : K = B^a mod p = A^b mod p = 10
        K_alice = exp_mod(B, a, p)
        K_bob = exp_mod(A, b, p)
        self.assertEqual(K_alice, 10)
        self.assertEqual(K_bob, 10)

    # 2. Échange Diffie–Hellman réel (RFC 3526 Groupe 14 - 2048 bits)

    def test_rfc3526_2048_key_exchange(self):
        group = DHGroup.rfc3526_2048()
        alice = DHEphemeral(group)
        bob = DHEphemeral(group)

        # Alice reçoit B et Bob reçoit A
        k_alice = alice.compute_shared_secret(bob.public_key)
        k_bob = bob.compute_shared_secret(alice.public_key)

        # Le secret partagé doit être rigoureusement identique
        self.assertEqual(k_alice, k_bob)
        self.assertGreater(k_alice.bit_length(), 100)

    # 3. Validation des clés publiques distantes (Défense sous-groupes)

    def test_invalid_peer_public_keys_rejected(self):
        group = DHGroup.test_512()
        alice = DHEphemeral(group)

        # Clés interdites : 0, 1, p - 1, p, au-delà de p
        for bad_key in [0, 1, group.p - 1, group.p, group.p + 10]:
            with self.assertRaises(ValueError):
                alice.compute_shared_secret(bad_key)

    # 4. Vecteurs de Test Officiels HKDF-SHA256 (RFC 5869)

    def test_rfc5869_case1(self):
        # RFC 5869 Test Case 1
        ikm = bytes.fromhex("0b" * 22)
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        l = 42

        expected_prk = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        expected_okm = (
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"
        )

        prk = hkdf_extract(salt, ikm, hash_name="sha256")
        self.assertEqual(prk.hex(), expected_prk)

        okm = hkdf_expand(prk, info, l, hash_name="sha256")
        self.assertEqual(okm.hex(), expected_okm)

        # Test fonction unifiée hkdf
        okm_direct = hkdf(ikm, l, salt=salt, info=info, hash_name="sha256")
        self.assertEqual(okm_direct.hex(), expected_okm)

    def test_rfc5869_case2(self):
        # RFC 5869 Test Case 2 : IKM et Salt longs (80 octets)
        ikm = bytes(range(80))
        salt = bytes(range(96, 176))
        info = bytes(range(176, 256))
        l = 82

        expected_okm = (
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
            "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
            "cc30c58179ec3e87c14c01d5c1f3434f1d87"
        )

        okm = hkdf(ikm, l, salt=salt, info=info, hash_name="sha256")
        self.assertEqual(okm.hex(), expected_okm)

    # 5. Dérivation de clés de session

    def test_derive_session_keys(self):
        shared_secret = 1234567890987654321
        k_enc, k_mac = derive_session_keys(shared_secret)
        self.assertEqual(len(k_enc), 32)
        self.assertEqual(len(k_mac), 32)
        self.assertNotEqual(k_enc, k_mac)


    # 6. Échange Authentifié avec Signatures RSA

    def test_authenticated_dh_exchange(self):
        # Alice et Bob ont chacun une paire de clés RSA long-terme
        alice_rsa_pub, alice_rsa_priv = generate_keypair(bits=1024)
        bob_rsa_pub, bob_rsa_priv = generate_keypair(bits=1024)

        group = DHGroup.test_512()
        alice_dh = DHEphemeral(group)
        bob_dh = DHEphemeral(group)

        # Alice signe sa clé publique DH
        sig_alice = sign_dh_public_key(alice_dh.public_key, alice_rsa_priv)
        # Bob vérifie la signature d'Alice
        self.assertTrue(verify_dh_public_key(alice_dh.public_key, sig_alice, alice_rsa_pub))

        # Bob signe sa clé publique DH
        sig_bob = sign_dh_public_key(bob_dh.public_key, bob_rsa_priv)
        # Alice vérifie la signature de Bob
        self.assertTrue(verify_dh_public_key(bob_dh.public_key, sig_bob, bob_rsa_pub))

        # Tentative d'injection d'une clé publique falsifiée par Mallory
        tampered_key = alice_dh.public_key + 2
        self.assertFalse(verify_dh_public_key(tampered_key, sig_alice, alice_rsa_pub))


if __name__ == "__main__":
    unittest.main()
