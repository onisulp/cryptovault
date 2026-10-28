"""
Tests unitaires pour le Module 6 (Cryptographie symétrique).
Valide César, Vigenère, la cryptanalyse automatique par Indice de Coïncidence,
le masque jetable, PKCS#7, les 4 modes AES et le réseau de Feistel.
"""

import unittest
import os
import sys

from cryptography.exceptions import InvalidTag

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cryptolib.symmetric import (
    caesar_encrypt,
    caesar_decrypt,
    vigenere_encrypt,
    vigenere_decrypt,
    index_of_coincidence,
    break_vigenere,
    otp_encrypt,
    otp_decrypt,
    pkcs7_pad,
    pkcs7_unpad,
    aes_encrypt,
    aes_decrypt,
    feistel_encrypt,
    feistel_decrypt,
)


class TestSymmetricModule(unittest.TestCase):

    # 1. Chiffres Classiques : César et Vigenère

    def test_caesar_course_exercise(self):
        # Exercice 1 du Chapitre 6 : HELLO avec décalage 5 -> MJQQT
        ct = caesar_encrypt("HELLO", 5)
        self.assertEqual(ct, "MJQQT")
        pt = caesar_decrypt(ct, 5)
        self.assertEqual(pt, "HELLO")

    def test_vigenere_cycle(self):
        text = "L'attaque surprise aura lieu demain a l'aube sur les positions nord !"
        key = "SECRET"
        encrypted = vigenere_encrypt(text, key)
        decrypted = vigenere_decrypt(encrypted, key)
        self.assertEqual(decrypted, text)

    # 2. Cryptanalyse Automatique Vigenère (IC & Fréquences)

    def test_vigenere_cryptanalysis_automatic(self):
        # Texte français représentatif de longueur suffisante
        french_corpus = (
            "La cryptographie moderne est la science des codes secrets et de la securite "
            "des communications. Elle permet de proteger la confidentialite et l'integrite "
            "des informations transmises a travers des canaux ouverts et non securises comme "
            "internet. L'emploi d'algorithmes robustes et standardises garantit que seuls les "
            "destinataires legitimes possedant la cle privee peuvent dechiffrer les messages."
        )
        key = "CYBER"
        ciphertext = vigenere_encrypt(french_corpus, key)

        recovered_key, decrypted_text = break_vigenere(ciphertext, max_key_len=10)
        self.assertEqual(recovered_key, key)
        self.assertEqual(decrypted_text, french_corpus)

    # 3. Masque Jetable (One-Time Pad)

    def test_otp_cycle(self):
        data = b"Coordonnees GPS sensibles : 48.8566 N, 2.3522 E"
        key = os.urandom(len(data))
        ct = otp_encrypt(data, key)
        self.assertNotEqual(ct, data)
        self.assertEqual(otp_decrypt(ct, key), data)

        # Rejet si la clé n'est pas de même longueur
        with self.assertRaises(ValueError):
            otp_encrypt(data, key[:-1])

    # 4. Remplissage PKCS#7

    def test_pkcs7_padding_and_unpadding(self):
        # Longueur non multiple de 16
        data = b"Donnees de test"  # 15 octets -> 1 octet de 0x01 attendu
        padded = pkcs7_pad(data, 16)
        self.assertEqual(len(padded), 16)
        self.assertEqual(padded[-1], 1)
        self.assertEqual(pkcs7_unpad(padded, 16), data)

        # Longueur déjà multiple de 16 -> bloc plein de 16 octets 0x10
        data16 = b"1234567890123456"
        padded16 = pkcs7_pad(data16, 16)
        self.assertEqual(len(padded16), 32)
        self.assertEqual(padded16[-1], 16)
        self.assertEqual(pkcs7_unpad(padded16, 16), data16)

        # Padding corrompu
        bad_padded = bytearray(padded)
        bad_padded[-1] = 0  # 0 est interdit en PKCS#7
        with self.assertRaises(ValueError):
            pkcs7_unpad(bytes(bad_padded), 16)

    # 5. Modes Opératoires AES (GCM, CBC, CTR, ECB)

    def test_aes_modes_cycle(self):
        key = os.urandom(32)  # AES-256
        data = b"Charge utile confidentielle a proteger avec differents modes AES."

        for mode in ["GCM", "CBC", "CTR", "ECB"]:
            package = aes_encrypt(data, key, mode=mode)
            decrypted = aes_decrypt(package, key, mode=mode)
            self.assertEqual(decrypted, data, f"Échec sur le mode {mode}")

    def test_aes_gcm_authenticated_data_aad(self):
        key = os.urandom(32)
        data = b"Fonds transferes : 50 000 USD"
        aad = b"Header: ID-Compte=987654321"

        package = aes_encrypt(data, key, mode="GCM", aad=aad)
        # Déchiffrement avec le bon AAD
        decrypted = aes_decrypt(package, key, mode="GCM", aad=aad)
        self.assertEqual(decrypted, data)

        # Déchiffrement avec un AAD falsifié -> Doit lever InvalidTag !
        with self.assertRaises(InvalidTag):
            aes_decrypt(package, key, mode="GCM", aad=b"Header: ID-Compte=PIRATE")

    # 6. Réseau de Feistel Jouet à 4 Tours
    
    def test_feistel_cipher_cycle(self):
        block = b"ABCDEFGH"  # 8 octets
        round_keys = [0x12345678, 0x9ABCDEF0, 0x13579BDF, 0x2468ACE0]

        ciphertext = feistel_encrypt(block, round_keys)
        self.assertEqual(len(ciphertext), 8)
        self.assertNotEqual(ciphertext, block)

        decrypted = feistel_decrypt(ciphertext, round_keys)
        self.assertEqual(decrypted, block)


if __name__ == "__main__":
    unittest.main()
