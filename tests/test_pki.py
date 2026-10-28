"""
Tests unitaires pour le Module 7 (PKI, Gestion de clés et Partage de Shamir).
Valide la hiérarchie Root CA -> Inter CA -> User, la validation de chaîne,
la révocation par CRL, le Keystore sécurisé et le partage de secret de Shamir (k parmi n).
"""

import unittest
import os
import sys
import tempfile
import time
from cryptography.exceptions import InvalidTag

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cryptolib.pki import (
    Certificate,
    CertificateAuthority,
    verify_certificate_chain,
    KeyStore,
    shamir_split_secret,
    shamir_reconstruct_secret,
)
from cryptolib.rsa import generate_keypair as generate_rsa_keypair


class TestPKIModule(unittest.TestCase):

    def setUp(self):
        # 1. Création de la Root CA
        self.root_subject = {"CN": "CryptoVault Root CA", "O": "CryptoVault Inc", "C": "FR"}
        self.root_ca = CertificateAuthority.create_root(self.root_subject, key_type="RSA", validity_days=365)

        # 2. Création de l'Intermediate CA signée par Root
        self.inter_subject = {"CN": "CryptoVault Intermediate CA", "O": "CryptoVault Inc", "C": "FR"}
        _, inter_priv = generate_rsa_keypair(bits=1024)
        inter_cert = self.root_ca.issue_certificate(
            subject=self.inter_subject,
            subject_public_key_dict=inter_priv.public_key.to_dict(),
            is_ca=True,
            validity_days=180,
        )
        self.inter_ca = CertificateAuthority(inter_cert, inter_priv)

        # 3. Création du certificat utilisateur feuille (Alice)
        self.alice_subject = {"CN": "Alice Dupont", "O": "CryptoVault User", "C": "FR"}
        _, self.alice_priv = generate_rsa_keypair(bits=1024)
        self.alice_cert = self.inter_ca.issue_certificate(
            subject=self.alice_subject,
            subject_public_key_dict=self.alice_priv.public_key.to_dict(),
            is_ca=False,
            validity_days=90,
        )

    # 1. Validation de la Chaîne Complète
    
    def test_certificate_chain_valid(self):
        valid, msg = verify_certificate_chain(
            target_cert=self.alice_cert,
            intermediate_certs=[self.inter_ca.cert],
            trusted_roots=[self.root_ca.cert],
        )
        self.assertTrue(valid, f"Échec de validation de chaîne: {msg}")

    # 2. Détection de Falsification et d'Expiration

    def test_tampered_certificate_rejected(self):
        # Modification pirate du sujet sans recalcul de signature
        fake_cert_dict = self.alice_cert.to_dict()
        fake_cert_dict["subject"]["CN"] = "Alice Hacker"
        fake_cert = Certificate.from_dict(fake_cert_dict)

        valid, msg = verify_certificate_chain(
            target_cert=fake_cert,
            intermediate_certs=[self.inter_ca.cert],
            trusted_roots=[self.root_ca.cert],
        )
        self.assertFalse(valid)
        self.assertIn("invalide", msg.lower())

    def test_expired_certificate_rejected(self):
        # Simulation d'un contrôle dans le futur (au-delà de 90 jours)
        future_time = time.time() + (100 * 86400)
        valid, msg = verify_certificate_chain(
            target_cert=self.alice_cert,
            intermediate_certs=[self.inter_ca.cert],
            trusted_roots=[self.root_ca.cert],
            current_time=future_time,
        )
        self.assertFalse(valid)
        self.assertIn("expiré", msg.lower())

    def test_leaf_cannot_sign_certificates(self):
        # Alice (qui a is_ca=False) essaie d'émettre un certificat pour Bob
        alice_as_ca = CertificateAuthority(self.alice_cert, self.alice_priv)
        bob_subject = {"CN": "Bob", "C": "FR"}
        _, bob_priv = generate_rsa_keypair(bits=1024)

        with self.assertRaises(PermissionError):
            alice_as_ca.issue_certificate(bob_subject, bob_priv.public_key.to_dict())

    # 3. Révocation par CRL

    def test_revocation_via_crl(self):
        # L'intermédiaire révoque le certificat d'Alice
        self.inter_ca.revoke_certificate(self.alice_cert.serial_number)
        crl = self.inter_ca.generate_crl()

        self.assertTrue(crl.is_revoked(self.alice_cert.serial_number))

        # La vérification de la chaîne doit échouer à cause de la révocation
        valid, msg = verify_certificate_chain(
            target_cert=self.alice_cert,
            intermediate_certs=[self.inter_ca.cert],
            trusted_roots=[self.root_ca.cert],
            crl=crl,
        )
        self.assertFalse(valid)
        self.assertIn("révoqué", msg.lower())

    # 4. Magasin de Clés (KeyStore) Chiffré et Rotation

    def test_keystore_save_load_and_rotation(self):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            keystore_path = tmp.name

        try:
            password = "MonMotDePasseMaitre123!#"
            KeyStore.save(
                filepath=keystore_path,
                password=password,
                private_key_dict=self.alice_priv.to_dict(),
                certificate=self.alice_cert,
                trusted_roots=[self.root_ca.cert],
            )

            # Rechargement avec le bon mot de passe
            loaded = KeyStore.load(keystore_path, password)
            self.assertEqual(loaded["private_key"]["n"], hex(self.alice_priv.n))
            self.assertEqual(loaded["certificate"]["serial_number"], self.alice_cert.serial_number)

            # Rechargement avec un mauvais mot de passe -> Doit lever InvalidTag
            with self.assertRaises(InvalidTag):
                KeyStore.load(keystore_path, "MauvaisMotDePasse")

            # Rotation de mot de passe
            new_password = "NouveauMotDePasseUltraSur2026!"
            KeyStore.rotate_password(keystore_path, password, new_password)

            # L'ancien mot de passe échoue
            with self.assertRaises(InvalidTag):
                KeyStore.load(keystore_path, password)

            # Le nouveau mot de passe réussit
            reloaded = KeyStore.load(keystore_path, new_password)
            self.assertEqual(reloaded["private_key"]["d"], hex(self.alice_priv.d))

        finally:
            if os.path.exists(keystore_path):
                os.remove(keystore_path)

    # 5. Partage de Secret de Shamir (k parmi n)

    def test_shamir_secret_sharing(self):
        # Secret de 32 octets (ex: clé maîtresse de Root CA)
        master_secret = os.urandom(32)
        k, n = 3, 5  # Schéma 3 parmi 5

        shares = shamir_split_secret(master_secret, k=k, n=n)
        self.assertEqual(len(shares), 5)

        # Reconstitution avec 3 parts quelconques (ex: parts 1, 3, 5)
        subset_shares = [shares[0], shares[2], shares[4]]
        recovered = shamir_reconstruct_secret(subset_shares)
        self.assertEqual(recovered, master_secret)

        # Reconstitution avec 4 parts
        recovered_4 = shamir_reconstruct_secret(shares[:4])
        self.assertEqual(recovered_4, master_secret)

        # Avec seulement 2 parts (k-1), la reconstruction ne donne PAS le secret original
        recovered_2 = shamir_reconstruct_secret([shares[0], shares[1]])
        self.assertNotEqual(recovered_2, master_secret)


if __name__ == "__main__":
    unittest.main()
