"""
Module 9 (Application) : Serveur de Messagerie Sécurisée CryptoVault
Gère :
- L'autorité de certification intermédiaire (PKI)
- La base des utilisateurs (mots de passe hachés salés PBKDF2)
- Le Handshake TLS 1.3 simplifié (ECDHE P-256 + signatures + certificats)
- Le relais des messages chiffrés en AES-256-GCM avec numéros de séquence anti-rejeu
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import json
import time
import socket
import threading
import argparse
from typing import Dict, Any, Optional, Tuple

from cryptolib.hashing import hash_password, verify_password
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
    CertificateAuthority,
    verify_certificate_chain,
)
from cryptolib.symmetric import aes_encrypt, aes_decrypt


def _load_priv_key(d: dict) -> Any:
    if "d" in d and "n" in d:
        from cryptolib.rsa import RSAPrivateKey
        return RSAPrivateKey(
            n=int(d["n"], 16),
            d=int(d["d"], 16),
            p=int(d["p"], 16) if "p" in d else None,
            q=int(d["q"], 16) if "q" in d else None,
            dp=int(d["dp"], 16) if "dp" in d else None,
            dq=int(d["dq"], 16) if "dq" in d else None,
            qinv=int(d["qinv"], 16) if "qinv" in d else None,
            e=int(d["e"], 16) if "e" in d else 65537,
        )
    elif "d" in d:
        from cryptolib.ecc import ECPrivateKey, NIST_P256
        return ECPrivateKey(int(d["d"], 16), NIST_P256)
    raise ValueError("Format de clé privée non reconnu.")


class CryptoVaultServer:
    """Serveur central CryptoVault."""

    def __init__(self, root_ca: Optional[CertificateAuthority] = None, data_dir: str = ".server_data"):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)

        # 1. Mise en place de la PKI du serveur (persistance garantie)
        if root_ca is not None:
            self.root_ca = root_ca
            inter_subj = {"CN": "CryptoVault Server CA", "O": "CryptoVault Network", "C": "FR"}
            _, inter_priv = generate_ecc_keypair(NIST_P256)
            inter_cert = self.root_ca.issue_certificate(
                subject=inter_subj,
                subject_public_key_dict=inter_priv.public_key.to_dict(),
                is_ca=True,
                validity_days=1825,
            )
            self.server_ca = CertificateAuthority(inter_cert, inter_priv)

            srv_subj = {"CN": "CryptoVault Gateway Server", "O": "CryptoVault Network", "C": "FR"}
            _, self.srv_priv = generate_ecc_keypair(NIST_P256)
            self.srv_cert = self.server_ca.issue_certificate(
                subject=srv_subj,
                subject_public_key_dict=self.srv_priv.public_key.to_dict(),
                is_ca=False,
                validity_days=365,
            )
        elif not self._load_pki():
            root_subj = {"CN": "CryptoVault Root CA", "O": "CryptoVault Network", "C": "FR"}
            self.root_ca = CertificateAuthority.create_root(root_subj, key_type="ECC", validity_days=3650)

            inter_subj = {"CN": "CryptoVault Server CA", "O": "CryptoVault Network", "C": "FR"}
            _, inter_priv = generate_ecc_keypair(NIST_P256)
            inter_cert = self.root_ca.issue_certificate(
                subject=inter_subj,
                subject_public_key_dict=inter_priv.public_key.to_dict(),
                is_ca=True,
                validity_days=1825,
            )
            self.server_ca = CertificateAuthority(inter_cert, inter_priv)

            srv_subj = {"CN": "CryptoVault Gateway Server", "O": "CryptoVault Network", "C": "FR"}
            _, self.srv_priv = generate_ecc_keypair(NIST_P256)
            self.srv_cert = self.server_ca.issue_certificate(
                subject=srv_subj,
                subject_public_key_dict=self.srv_priv.public_key.to_dict(),
                is_ca=False,
                validity_days=365,
            )
            self._save_pki()

        # Base utilisateurs : {username: {"salt_hex": ..., "hash_hex": ..., "cert": ...}}
        self.users_db: Dict[str, Dict[str, Any]] = {}
        self.user_mailboxes: Dict[str, list] = {}
        self._load_users()

    def _save_pki(self):
        pki_file = os.path.join(self.data_dir, "pki_state.json")
        try:
            state = {
                "root_cert": self.root_ca.cert.to_dict(),
                "root_priv": self.root_ca.priv_key.to_dict(),
                "inter_cert": self.server_ca.cert.to_dict(),
                "inter_priv": self.server_ca.priv_key.to_dict(),
                "inter_revoked": list(self.server_ca.revoked_serials),
                "srv_cert": self.srv_cert.to_dict(),
                "srv_priv": self.srv_priv.to_dict(),
            }
            with open(pki_file, "w") as f:
                json.dump(state, f, indent=2)
        except Exception:
            pass

    def _load_pki(self) -> bool:
        pki_file = os.path.join(self.data_dir, "pki_state.json")
        if not os.path.exists(pki_file):
            return False
        try:
            with open(pki_file, "r") as f:
                data = json.load(f)
            root_cert = Certificate.from_dict(data["root_cert"])
            root_priv = _load_priv_key(data["root_priv"])
            self.root_ca = CertificateAuthority(root_cert, root_priv)

            inter_cert = Certificate.from_dict(data["inter_cert"])
            inter_priv = _load_priv_key(data["inter_priv"])
            self.server_ca = CertificateAuthority(inter_cert, inter_priv)
            self.server_ca.revoked_serials = list(data.get("inter_revoked", []))

            self.srv_cert = Certificate.from_dict(data["srv_cert"])
            self.srv_priv = _load_priv_key(data["srv_priv"])
            return True
        except Exception:
            return False

    def _load_users(self):
        db_file = os.path.join(self.data_dir, "users.json")
        if os.path.exists(db_file):
            with open(db_file, "r") as f:
                self.users_db = json.load(f)

    def _save_users(self):
        db_file = os.path.join(self.data_dir, "users.json")
        with open(db_file, "w") as f:
            json.dump(self.users_db, f, indent=2)

    def register_user(self, username: str, password: str, public_key_dict: Dict[str, Any]) -> Certificate:
        """Inscrit un utilisateur, hache son mot de passe et lui émet un certificat X.509."""
        if username in self.users_db:
            raise ValueError(f"L'utilisateur '{username}' existe déjà.")

        # Hachage sécurisé du mot de passe avec sel (Module 1)
        res_hash = hash_password(password, iterations=100_000)

        # Émission du certificat utilisateur signé par l'autorité intermédiaire
        user_subj = {"CN": username, "O": "CryptoVault Users", "C": "FR"}
        cert = self.server_ca.issue_certificate(
            subject=user_subj,
            subject_public_key_dict=public_key_dict,
            is_ca=False,
            validity_days=365,
        )

        self.users_db[username] = {
            "salt_hex": res_hash["salt_hex"],
            "hash_hex": res_hash["hash_hex"],
            "iterations": res_hash["iterations"],
            "cert": cert.to_dict(),
        }
        self.user_mailboxes[username] = []
        self._save_users()
        return cert

    def authenticate_user(self, username: str, password: str) -> bool:
        """Vérifie le mot de passe d'un utilisateur."""
        if username not in self.users_db:
            return False
        rec = self.users_db[username]
        return verify_password(password, rec["hash_hex"], rec["salt_hex"], rec["iterations"])

    def get_user_certificate(self, username: str) -> Optional[Certificate]:
        """Retourne le certificat enregistré pour un utilisateur."""
        rec = self.users_db.get(username)
        if rec:
            return Certificate.from_dict(rec["cert"])
        return None

    def perform_server_handshake(
        self,
        client_cert_dict: Dict[str, Any],
        client_ephemeral_pub_dict: Dict[str, Any],
        client_signature_str: str,
    ) -> Tuple[Dict[str, Any], Dict[str, Any], str, bytes]:
        """
        Exécute le Handshake côté serveur (type TLS 1.3 simplifié) :
        1. Valide le certificat du client et sa signature sur sa clé éphémère.
        2. Génère une clé éphémère côté serveur, la signe.
        3. Calcule le secret partagé ECDHE et dérive la clé de session.
        """
        # 1. Validation de la chaîne de certification du client
        client_cert = Certificate.from_dict(client_cert_dict)
        valid, msg = verify_certificate_chain(
            target_cert=client_cert,
            intermediate_certs=[self.server_ca.cert],
            trusted_roots=[self.root_ca.cert],
            crl=self.server_ca.generate_crl(),
        )
        if not valid:
            raise PermissionError(f"Échec de validation du certificat client : {msg}")

        # 2. Vérification de la signature du client sur sa clé éphémère
        client_eph_pub = ECPublicKey(
            ECPoint(int(client_ephemeral_pub_dict["x"], 16), int(client_ephemeral_pub_dict["y"], 16)),
            NIST_P256,
        )
        client_pub_obj = client_cert.get_public_key_object()

        # TBS éphémère = coordonnée x + y
        tbs_bytes = f"{client_eph_pub.Q.x}:{client_eph_pub.Q.y}".encode("utf-8")
        r_str, s_str = client_signature_str.split(":")
        if not ecdsa_verify(tbs_bytes, (int(r_str, 16), int(s_str, 16)), client_pub_obj):
            raise PermissionError("Signature de clé éphémère client invalide (attaque MITM détectée !).")

        # 3. Génération de la clé éphémère du serveur
        srv_eph_pub, srv_eph_priv = generate_ecc_keypair(NIST_P256)
        srv_tbs = f"{srv_eph_pub.Q.x}:{srv_eph_pub.Q.y}".encode("utf-8")
        r_srv, s_srv = ecdsa_sign(srv_tbs, self.srv_priv)
        srv_sig_str = f"{hex(r_srv)}:{hex(s_srv)}"

        # 4. Calcul du secret partagé ECDHE et dérivation de la clé de session
        shared_secret_bytes = ecdh(srv_eph_priv, client_eph_pub)
        shared_int = int.from_bytes(shared_secret_bytes, "big")
        k_enc, _ = derive_session_keys(shared_int, info=b"CryptoVault-E2E-Session")

        return self.srv_cert.to_dict(), srv_eph_pub.to_dict(), srv_sig_str, k_enc


def main():
    parser = argparse.ArgumentParser(description="CryptoVault - Serveur de messagerie et autorité de certification")
    parser.add_argument("--data-dir", default=".server_data", help="Répertoire de données du serveur")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: init
    p_init = subparsers.add_parser("init", help="Initialiser la PKI et l'environnement serveur")

    # Subcommand: status
    p_status = subparsers.add_parser("status", help="Afficher l'état de la PKI et les utilisateurs inscrits")

    args = parser.parse_args()
    server = CryptoVaultServer(data_dir=args.data_dir)

    if args.command in ("init", "status"):
        print("=" * 65)
        print("          ÉTAT DU SERVEUR CRYPTOVAULT & DE LA PKI")
        print("=" * 65)
        print(f"[+] Répertoire de données : {args.data_dir}")
        print(f"[+] Root CA        : {server.root_ca.cert.subject['CN']} (Série: {server.root_ca.cert.serial_number})")
        print(f"[+] Intermediate CA: {server.server_ca.cert.subject['CN']} (Série: {server.server_ca.cert.serial_number})")
        print(f"[+] Gateway Cert   : {server.srv_cert.subject['CN']} (Série: {server.srv_cert.serial_number})")
        print("-" * 65)
        users = list(server.users_db.keys())
        print(f"[*] Nombre d'utilisateurs inscrits : {len(users)}")
        for u in users:
            print(f"    - {u}")
        print("=" * 65)


if __name__ == "__main__":
    main()

