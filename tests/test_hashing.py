"""
Tests unitaires pour le Module 1 (Hachage, HMAC, Mots de passe, Arbre de Merkle).
Validation par les vecteurs officiels de la RFC 4231 (HMAC-SHA256).
"""

import unittest
import tempfile
import os
import sys
import hashlib

# Permettre l'import de cryptolib quel que soit le dossier d'exécution
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cryptolib.hashing import (
    hash_bytes,
    hash_file,
    hash_all_algos,
    verify_hash,
    test_avalanche_effect,
    custom_hmac,
    verify_hmac,
    hash_password,
    verify_password,
    MerkleTree,
)


class TestHashingModule(unittest.TestCase):

    def setUp(self):
        # Création d'un fichier temporaire de test
        self.test_content = b"Contenu de test pour CryptoVault 2026 !"
        self.tmp_file = tempfile.NamedTemporaryFile(delete=False)
        self.tmp_file.write(self.test_content)
        self.tmp_file.close()

    def tearDown(self):
        if os.path.exists(self.tmp_file.name):
            os.remove(self.tmp_file.name)

    # 1. Tests de hachage de fichier et d'intégrité
    
    def test_hash_file_and_verification(self):
        expected_sha256 = hashlib.sha256(self.test_content).hexdigest()
        computed = hash_file(self.tmp_file.name, "sha256")
        self.assertEqual(computed, expected_sha256)
        self.assertTrue(verify_hash(self.tmp_file.name, expected_sha256, "sha256"))
        self.assertFalse(verify_hash(self.tmp_file.name, "0" * 64, "sha256"))

    def test_hash_all_algos(self):
        all_h = hash_all_algos(self.tmp_file.name)
        self.assertIn("md5", all_h)
        self.assertIn("sha1", all_h)
        self.assertIn("sha256", all_h)
        self.assertIn("sha3_256", all_h)
        self.assertEqual(all_h["md5"], hashlib.md5(self.test_content).hexdigest())

    # 2. Test de l'effet avalanche

    def test_avalanche_effect(self):
        diff, total, pct, h1, h2 = test_avalanche_effect(b"Message secret pour analyse avalanche", "sha256")
        self.assertEqual(total, 256)
        # L'effet avalanche sur une bonne fonction de hachage doit être proche de 50% (entre 35% et 65%)
        self.assertGreaterEqual(pct, 35.0)
        self.assertLessEqual(pct, 65.0)

    # 3. Tests HMAC avec vecteurs officiels RFC 4231

    def test_rfc4231_case1(self):
        # Test Case 1
        key = bytes.fromhex("0b" * 20)
        data = b"Hi There"
        expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        mac = custom_hmac(key, data, "sha256")
        self.assertEqual(mac.hex(), expected)
        self.assertTrue(verify_hmac(key, data, bytes.fromhex(expected), "sha256"))

    def test_rfc4231_case2(self):
        # Test Case 2 (Clé 'Jefe')
        key = b"Jefe"
        data = b"what do ya want for nothing?"
        expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        mac = custom_hmac(key, data, "sha256")
        self.assertEqual(mac.hex(), expected)

    def test_rfc4231_case3(self):
        # Test Case 3
        key = bytes.fromhex("aa" * 20)
        data = bytes.fromhex("dd" * 50)
        expected = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        mac = custom_hmac(key, data, "sha256")
        self.assertEqual(mac.hex(), expected)

    def test_rfc4231_case4(self):
        # Test Case 4
        key = bytes.fromhex("0102030405060708090a0b0c0d0e0f10111213141516171819")
        data = bytes.fromhex("cd" * 50)
        expected = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
        mac = custom_hmac(key, data, "sha256")
        self.assertEqual(mac.hex(), expected)

    def test_rfc4231_case6_large_key(self):
        # Test Case 6 : Clé > taille de bloc (131 octets > 64 octets)
        key = bytes.fromhex("aa" * 131)
        data = b"Test Using Larger Than Block-Size Key - Hash Key First"
        expected = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        mac = custom_hmac(key, data, "sha256")
        self.assertEqual(mac.hex(), expected)

    def test_rfc4231_case7_large_key_and_data(self):
        # Test Case 7
        key = bytes.fromhex("aa" * 131)
        data = (
            b"This is a test using a larger than block-size key and a larger "
            b"than block-size data. The key needs to be hashed before being "
            b"used by the HMAC algorithm."
        )
        expected = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
        mac = custom_hmac(key, data, "sha256")
        self.assertEqual(mac.hex(), expected)

    # 4. Hachage sécurisé de mot de passe

    def test_password_hashing_and_verification(self):
        pwd = "MotDePasseTresRobuste!#2026"
        res = hash_password(pwd, iterations=50_000)
        self.assertTrue(verify_password(pwd, res["hash_hex"], res["salt_hex"], iterations=50_000))
        # Mauvais mot de passe
        self.assertFalse(verify_password("MauvaisMotDePasse", res["hash_hex"], res["salt_hex"], iterations=50_000))

    # 5. Arbre de Merkle et Preuves

    def test_merkle_tree_proofs(self):
        blocks = [f"Bloc de donnees {i}".encode("utf-8") for i in range(8)]
        tree = MerkleTree(blocks)
        root = tree.get_root()
        self.assertEqual(len(root), 32)

        # Vérifier la preuve pour chaque bloc
        for idx in range(len(blocks)):
            proof = tree.get_proof(idx)
            self.assertTrue(MerkleTree.verify_proof(blocks[idx], proof, root))

        # Vérifier qu'un bloc altéré est rejeté
        fake_block = b"Bloc falsifie !"
        proof0 = tree.get_proof(0)
        self.assertFalse(MerkleTree.verify_proof(fake_block, proof0, root))

    def test_merkle_tree_odd_blocks(self):
        # Arbre avec nombre impair de blocs (ex: 5)
        blocks = [f"Bloc impair {i}".encode("utf-8") for i in range(5)]
        tree = MerkleTree(blocks)
        root = tree.get_root()

        for idx in range(len(blocks)):
            proof = tree.get_proof(idx)
            self.assertTrue(MerkleTree.verify_proof(blocks[idx], proof, root))


if __name__ == "__main__":
    unittest.main()
