"""
Tests unitaires pour le Module 3 (Chiffrement RSA).
Valide la génération de clés, le chiffrement OAEP, l'accélération CRT,
la signature PKCS#1 v1.5 et le chiffrement hybride de fichiers.
"""

import unittest
import tempfile
import os
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cryptolib.rsa import (
    RSAPublicKey,
    RSAPrivateKey,
    generate_keypair,
    rsa_encrypt_int,
    rsa_decrypt_int_raw,
    rsa_decrypt_int_crt,
    oaep_pad,
    oaep_unpad,
    rsa_encrypt,
    rsa_decrypt,
    rsa_sign,
    rsa_verify,
    encrypt_file_hybrid,
    decrypt_file_hybrid,
)


class TestRSAModule(unittest.TestCase):

    # 1. Exercices numériques du Chapitre 3 du cours
    
    def test_course_exercise_numerical(self):
        # Exercice 1 : n = 143 (p=11, q=13), phi(n) = 120, e = 7, d = 103
        pub = RSAPublicKey(n=143, e=7)
        # CRT params : dp = 103 % 10 = 3, dq = 103 % 12 = 7, qinv = 13^-1 mod 11 = 2^-1 mod 11 = 6
        priv = RSAPrivateKey(n=143, e=7, d=103, p=11, q=13, dp=3, dq=7, qinv=6)

        # Exercice 2 : Chiffrement de m = 9 -> c = 9^7 mod 143 = 48
        c = rsa_encrypt_int(9, pub)
        self.assertEqual(c, 48)

        # Déchiffrement direct : 48^103 mod 143 = 9
        m_raw = rsa_decrypt_int_raw(c, priv)
        self.assertEqual(m_raw, 9)

    # 2. Génération de clés et sérialisation JSON

    def test_key_generation_and_json(self):
        pub, priv = generate_keypair(bits=512)
        self.assertGreaterEqual(pub.bit_length, 510)
        self.assertEqual(pub.n, priv.n)
        self.assertEqual(pub.e, priv.e)

        # Sérialisation et rechargement
        pub_json = pub.to_json()
        pub_reloaded = RSAPublicKey.from_json(pub_json)
        self.assertEqual(pub.n, pub_reloaded.n)
        self.assertEqual(pub.e, pub_reloaded.e)

        priv_json = priv.to_json()
        priv_reloaded = RSAPrivateKey.from_json(priv_json)
        self.assertEqual(priv.d, priv_reloaded.d)
        self.assertEqual(priv.p, priv_reloaded.p)

    # 3. Accélération par le Théorème des Restes Chinois (CRT)

    def test_crt_speedup_and_correctness(self):
        pub, priv = generate_keypair(bits=512)
        message_int = 12345678901234567890

        c = rsa_encrypt_int(message_int, pub)
        m_raw = rsa_decrypt_int_raw(c, priv)
        m_crt = rsa_decrypt_int_crt(c, priv)

        self.assertEqual(m_raw, message_int)
        self.assertEqual(m_crt, message_int)

    # 4. Remplissage OAEP
    def test_oaep_pad_unpad(self):
        msg = b"Confidentiel CryptoVault 2026"
        k = 128  # 1024 bits = 128 octets
        em = oaep_pad(msg, k, hash_name="sha256")
        self.assertEqual(len(em), k)

        unpadded = oaep_unpad(em, k, hash_name="sha256")
        self.assertEqual(unpadded, msg)

    def test_oaep_corrupted_padding_fails(self):
        msg = b"Message secret"
        k = 128
        em = bytearray(oaep_pad(msg, k, hash_name="sha256"))
        # Corruption d'un octet
        em[50] ^= 0xFF
        with self.assertRaises(ValueError):
            oaep_unpad(bytes(em), k, hash_name="sha256")

    # 5. Chiffrement et Déchiffrement Complet (OAEP + CRT)
    
    def test_rsa_encrypt_decrypt_cycle(self):
        pub, priv = generate_keypair(bits=1024)
        plaintext = b"Test complet du chiffrement asymetrique RSA-OAEP."

        ciphertext = rsa_encrypt(plaintext, pub)
        self.assertEqual(len(ciphertext), pub.byte_length)

        decrypted = rsa_decrypt(ciphertext, priv, use_crt=True)
        self.assertEqual(decrypted, plaintext)

    # 6. Signature et Vérification PKCS#1 v1.5

    def test_rsa_signature_and_verification(self):
        pub, priv = generate_keypair(bits=1024)
        doc = b"Contrat officiel signe electroniquement via CryptoVault."

        signature = rsa_sign(doc, priv)
        self.assertEqual(len(signature), pub.byte_length)

        # Vérification valide
        self.assertTrue(rsa_verify(doc, signature, pub))

        # Altération du document
        altered_doc = doc + b" Clause pirate !"
        self.assertFalse(rsa_verify(altered_doc, signature, pub))

    # 7. Chiffrement Hybride de Fichiers

    def test_hybrid_file_encryption(self):
        pub, priv = generate_keypair(bits=1024)
        original_data = os.urandom(32768)  # 32 Ko

        with tempfile.NamedTemporaryFile(delete=False) as f_in:
            f_in.write(original_data)
            in_path = f_in.name

        enc_path = in_path + ".enc"
        dec_path = in_path + ".dec"

        try:
            # Chiffrement
            encrypt_file_hybrid(in_path, enc_path, pub)
            self.assertTrue(os.path.exists(enc_path))

            # Déchiffrement
            decrypt_file_hybrid(enc_path, dec_path, priv)
            with open(dec_path, "rb") as f_dec:
                decrypted_data = f_dec.read()

            self.assertEqual(decrypted_data, original_data)
        finally:
            for p in [in_path, enc_path, dec_path]:
                if os.path.exists(p):
                    os.remove(p)


if __name__ == "__main__":
    unittest.main()
