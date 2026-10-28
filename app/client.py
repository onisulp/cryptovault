"""
Module 9 (Application) : Client de Messagerie Sécurisée CryptoVault
Gère :
- La génération locale de clés et le stockage dans le KeyStore chiffré
- L'inscription et la connexion auprès du serveur
- Le Handshake TLS 1.3 simplifié (ECDHE + validation de certificat)
- L'envoi et la réception de messages avec numéros de séquence anti-rejeu
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import json
import time
import argparse
from typing import Dict, Any, Optional, Tuple

from cryptolib.ecc import (
    NIST_P256,
    generate_ecc_keypair,
    ecdh,
    ecdsa_sign,
    ecdsa_verify,
    ECPublicKey,
    ECPrivateKey,
    ECPoint,
)
from cryptolib.dh import derive_session_keys
from cryptolib.pki import (
    Certificate,
    KeyStore,
    verify_certificate_chain,
)
from cryptolib.symmetric import aes_encrypt, aes_decrypt
from app.server import CryptoVaultServer


class CryptoVaultClient:
    """Client de messagerie sécurisée CryptoVault."""

    def __init__(self, username: str, keystore_path: str):
        self.username = username
        self.keystore_path = keystore_path
        self.priv_key: Optional[ECPrivateKey] = None
        self.cert: Optional[Certificate] = None
        self.trusted_roots: list = []

        # Session de communication active
        self.session_key: Optional[bytes] = None
        self.seq_out = 0
        self.seq_in = 0

    def register(self, password: str, server: CryptoVaultServer) -> None:
        """Inscrit l'utilisateur auprès du serveur et initialise son Keystore."""
        # 1. Génération de la paire de clés long-terme P-256
        pub, priv = generate_ecc_keypair(NIST_P256)

        # 2. Inscription auprès du serveur et obtention du certificat
        cert = server.register_user(self.username, password, pub.to_dict())

        # 3. Sauvegarde chiffrée dans le KeyStore local
        KeyStore.save(
            filepath=self.keystore_path,
            password=password,
            private_key_dict=priv.to_dict(),
            certificate=cert,
            trusted_roots=[server.root_ca.cert],
        )
        self.priv_key = priv
        self.cert = cert
        self.trusted_roots = [server.root_ca.cert]

    def login(self, password: str, server: CryptoVaultServer) -> None:
        """Déverrouille le KeyStore et établit la session sécurisée avec le serveur."""
        # 1. Déverrouillage du Keystore
        data = KeyStore.load(self.keystore_path, password)
        self.priv_key = ECPrivateKey(int(data["private_key"]["d"], 16), NIST_P256)
        self.cert = Certificate.from_dict(data["certificate"])
        self.trusted_roots = [Certificate.from_dict(r) for r in data["trusted_roots"]]

        # 2. Handshake TLS éphémère (ECDHE)
        client_eph_pub, client_eph_priv = generate_ecc_keypair(NIST_P256)
        tbs_bytes = f"{client_eph_pub.Q.x}:{client_eph_pub.Q.y}".encode("utf-8")
        r, s = ecdsa_sign(tbs_bytes, self.priv_key)
        sig_str = f"{hex(r)}:{hex(s)}"

        # 3. Envoi au serveur et réponse du serveur
        srv_cert_dict, srv_eph_pub_dict, srv_sig_str, srv_derived_k = server.perform_server_handshake(
            client_cert_dict=self.cert.to_dict(),
            client_ephemeral_pub_dict=client_eph_pub.to_dict(),
            client_signature_str=sig_str,
        )

        # 4. Vérification du certificat du serveur
        srv_cert = Certificate.from_dict(srv_cert_dict)
        valid, msg = verify_certificate_chain(
            target_cert=srv_cert,
            intermediate_certs=[server.server_ca.cert],
            trusted_roots=self.trusted_roots,
        )
        if not valid:
            raise PermissionError(f"Le certificat du serveur est invalide : {msg}")

        # 5. Vérification de la signature du serveur sur sa clé éphémère
        srv_eph_pub = ECPublicKey(
            ECPoint(int(srv_eph_pub_dict["x"], 16), int(srv_eph_pub_dict["y"], 16)),
            NIST_P256,
        )
        srv_pub_obj = srv_cert.get_public_key_object()
        srv_tbs = f"{srv_eph_pub.Q.x}:{srv_eph_pub.Q.y}".encode("utf-8")
        r_srv_str, s_srv_str = srv_sig_str.split(":")
        if not ecdsa_verify(srv_tbs, (int(r_srv_str, 16), int(s_srv_str, 16)), srv_pub_obj):
            raise PermissionError("Signature du serveur invalide (attaque MITM détectée !).")

        # 6. Calcul du secret partagé côté client et dérivation
        shared_secret_bytes = ecdh(client_eph_priv, srv_eph_pub)
        shared_int = int.from_bytes(shared_secret_bytes, "big")
        k_client, _ = derive_session_keys(shared_int, info=b"CryptoVault-E2E-Session")

        if k_client != srv_derived_k:
            raise ValueError("Divergence de clé de session entre client et serveur.")

        self.session_key = k_client
        self.seq_out = 0
        self.seq_in = 0

    def send_secure_message(self, content: str) -> bytes:
        """Chiffre un message avec AES-256-GCM et le numéro de séquence anti-rejeu."""
        if not self.session_key:
            raise PermissionError("Aucune session sécurisée active.")

        payload = {
            "seq": self.seq_out,
            "timestamp": time.time(),
            "sender": self.username,
            "content": content,
        }
        self.seq_out += 1
        payload_bytes = json.dumps(payload).encode("utf-8")
        return aes_encrypt(payload_bytes, self.session_key, mode="GCM")

    def receive_secure_message(self, encrypted_package: bytes) -> Dict[str, Any]:
        """Déchiffre un message et vérifie le numéro de séquence anti-rejeu."""
        if not self.session_key:
            raise PermissionError("Aucune session sécurisée active.")

        decrypted_bytes = aes_decrypt(encrypted_package, self.session_key, mode="GCM")
        payload = json.loads(decrypted_bytes.decode("utf-8"))

        # Contrôle anti-rejeu strict
        msg_seq = payload["seq"]
        if msg_seq < self.seq_in:
            raise ValueError(f"Attaque par rejeu détectée ! Séquence reçue: {msg_seq}, attendue >= {self.seq_in}")

        self.seq_in = msg_seq + 1
        return payload


def main():
    parser = argparse.ArgumentParser(description="CryptoVault - Client de messagerie sécurisée")
    parser.add_argument("--server-dir", default=".server_data", help="Répertoire de données du serveur")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: register
    p_reg = subparsers.add_parser("register", help="Inscrire un nouvel utilisateur et créer son Keystore")
    p_reg.add_argument("--username", required=True, help="Nom d'utilisateur")
    p_reg.add_argument("--password", required=True, help="Mot de passe du compte / Keystore")
    p_reg.add_argument("--keystore", required=True, help="Fichier de sortie pour le Keystore")

    # Subcommand: test-session
    p_test = subparsers.add_parser("test-session", help="Tester le handshake TLS ECDHE et l'envoi d'un message")
    p_test.add_argument("--username", required=True, help="Nom d'utilisateur")
    p_test.add_argument("--password", required=True, help="Mot de passe du Keystore")
    p_test.add_argument("--keystore", required=True, help="Fichier du Keystore")
    p_test.add_argument("--message", default="Bonjour CryptoVault !", help="Message à chiffrer et envoyer")

    args = parser.parse_args()
    server = CryptoVaultServer(data_dir=args.server_dir)

    if args.command == "register":
        client = CryptoVaultClient(args.username, args.keystore)
        client.register(args.password, server)
        print(f"[+] Utilisateur '{args.username}' inscrit avec succès.")
        print(f"[+] KeyStore sécurisé enregistré dans : {args.keystore}")
        print(f"    Certificat émis - N° de série : {client.cert.serial_number}")

    elif args.command == "test-session":
        client = CryptoVaultClient(args.username, args.keystore)
        print(f"[*] Connexion et Handshake TLS ECDHE en cours...")
        client.login(args.password, server)
        print(f"[+] Handshake ECDHE réussi ! Clé de session dérivée via HKDF : {client.session_key.hex()[:32]}...")

        print(f"[*] Envoi du message chiffré : '{args.message}'")
        pkg = client.send_secure_message(args.message)
        print(f"    Paquet chiffré AES-256-GCM (taille: {len(pkg)} octets) : {pkg.hex()[:40]}...")

        dec = client.receive_secure_message(pkg)
        print(f"[+] Réception et déchiffrement réussi !")
        print(f"    Expéditeur: {dec['sender']}, Seq: {dec['seq']}, Contenu: {dec['content']}")


if __name__ == "__main__":
    main()

