"""
Tests d'intégration de bout en bout pour le Module 9 (Application CryptoVault).
Valide :
1. Le scénario de messagerie sécurisée E2E (inscription, handshake ECDHE mutuel, dérivation HKDF, AES-GCM et anti-rejeu).
2. Le scénario du coffre-fort de fichiers (chiffrement hybride, arbre de Merkle, partage multi-destinataires et signature d'auteur).
"""

import unittest
import os
import sys
import shutil
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.server import CryptoVaultServer
from app.client import CryptoVaultClient
from app.vault import FileVault


class TestIntegrationCryptoVault(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.server_data_dir = os.path.join(self.test_dir, "server_data")
        self.vault_data_dir = os.path.join(self.test_dir, "vault_data")

        # Initialisation du serveur
        self.server = CryptoVaultServer(data_dir=self.server_data_dir)

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    # 1. Scénario A : Messagerie Sécurisée de Bout en Bout

    def test_messaging_e2e_flow_and_anti_replay(self):
        # 1. Inscription d'Alice
        alice_ks = os.path.join(self.test_dir, "alice_keystore.json")
        client_alice = CryptoVaultClient("alice", alice_ks)
        client_alice.register("MotDePasseAlice123!", self.server)
        self.assertTrue(os.path.exists(alice_ks))

        # 2. Authentification et Handshake TLS simplifié
        client_alice.login("MotDePasseAlice123!", self.server)
        self.assertIsNotNone(client_alice.session_key)

        # 3. Envoi de messages chiffrés
        msg1_package = client_alice.send_secure_message("Bonjour serveur, premier message !")
        msg2_package = client_alice.send_secure_message("Deuxième message confidentiel !")

        # Réception côté destinataire / serveur
        decrypted_1 = client_alice.receive_secure_message(msg1_package)
        self.assertEqual(decrypted_1["content"], "Bonjour serveur, premier message !")
        self.assertEqual(decrypted_1["seq"], 0)

        decrypted_2 = client_alice.receive_secure_message(msg2_package)
        self.assertEqual(decrypted_2["content"], "Deuxième message confidentiel !")
        self.assertEqual(decrypted_2["seq"], 1)

        # 4. Test d'Attaque par Rejeu : rejouer le paquet 1 (seq=0)
        with self.assertRaises(ValueError) as ctx:
            client_alice.receive_secure_message(msg1_package)
        self.assertIn("rejeu", str(ctx.exception).lower())

    # 2. Scénario B : Coffre-Fort de Fichiers (Vault)
    
    def test_vault_e2e_flow_and_merkle_verification(self):
        vault = FileVault(vault_dir=self.vault_data_dir)

        # Inscription d'Alice et Bob
        alice_ks = os.path.join(self.test_dir, "alice_ks.json")
        client_alice = CryptoVaultClient("alice", alice_ks)
        client_alice.register("PwdAlice#2026", self.server)

        bob_ks = os.path.join(self.test_dir, "bob_ks.json")
        client_bob = CryptoVaultClient("bob", bob_ks)
        client_bob.register("PwdBob#2026", self.server)

        # Fichier original à protéger (16 Ko)
        sample_doc_path = os.path.join(self.test_dir, "rapport_secret.pdf")
        original_bytes = os.urandom(16384)
        with open(sample_doc_path, "wb") as f:
            f.write(original_bytes)

        # Alice ajoute le fichier dans le coffre (avec signature)
        filename = vault.add_file(
            filepath=sample_doc_path,
            owner_username="alice",
            owner_priv_key=client_alice.priv_key,
            owner_cert=client_alice.cert,
            owner_chain=[self.server.server_ca.cert],
            sign=True,
            block_size=2048,
        )

        # Bob ne peut pas encore lire le fichier
        retrieved_path_bob = os.path.join(self.test_dir, "bob_output.pdf")
        with self.assertRaises(PermissionError):
            vault.get_file(filename, "bob", client_bob.priv_key, retrieved_path_bob)

        # Alice partage le fichier avec Bob
        vault.share_file(
            filename=filename,
            owner_username="alice",
            owner_priv_key=client_alice.priv_key,
            recipient_username="bob",
            recipient_cert=client_bob.cert,
        )

        # Maintenant Bob déchiffre et vérifie le fichier
        valid_auth, msg = vault.get_file(
            filename=filename,
            username="bob",
            user_priv_key=client_bob.priv_key,
            output_filepath=retrieved_path_bob,
            trusted_roots=[self.server.root_ca.cert],
        )

        self.assertTrue(valid_auth, f"Échec d'authentification : {msg}")
        self.assertTrue(os.path.exists(retrieved_path_bob))

        with open(retrieved_path_bob, "rb") as f:
            self.assertEqual(f.read(), original_bytes)

        # Vérification du listing
        files = vault.list_files()
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0]["author"], "alice")
        self.assertIn("bob", files[0]["recipients"])


if __name__ == "__main__":
    unittest.main()
