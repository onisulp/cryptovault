"""
Module 9 (Application) : Coffre-Fort de Fichiers CryptoVault
Gère :
- Le chiffrement symétrique des fichiers en AES-256-GCM
- Le chiffrement hybride multi-destinataires de la clé de fichier
- La vérification d'intégrité granulaire par Arbre de Merkle (Module 1)
- La signature électronique de l'auteur et la validation de son certificat (Modules 3, 5, 7)
- Les commandes CLI : add, get, list, share
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import json
import hashlib
import argparse
from typing import Dict, List, Any, Optional, Tuple

from cryptolib.hashing import MerkleTree
from cryptolib.symmetric import aes_encrypt, aes_decrypt
from cryptolib.rsa import (
    RSAPublicKey,
    RSAPrivateKey,
    rsa_encrypt,
    rsa_decrypt,
    rsa_sign,
    rsa_verify,
)
from cryptolib.ecc import (
    ECPublicKey,
    ECPrivateKey,
    ecdh,
    ecdsa_sign,
    ecdsa_verify,
    NIST_P256,
)
from cryptolib.pki import (
    Certificate,
    KeyStore,
    verify_certificate_chain,
)


class FileVault:
    """Gestionnaire de coffre-fort de fichiers chiffrés."""

    def __init__(self, vault_dir: str = ".vault_storage"):
        self.vault_dir = vault_dir
        os.makedirs(vault_dir, exist_ok=True)
        self.index_file = os.path.join(vault_dir, "vault_index.json")
        self.index: Dict[str, Dict[str, Any]] = {}
        self._load_index()

    def _load_index(self):
        if os.path.exists(self.index_file):
            with open(self.index_file, "r") as f:
                self.index = json.load(f)

    def _save_index(self):
        with open(self.index_file, "w") as f:
            json.dump(self.index, f, indent=2)

    def _encrypt_file_key_for_user(self, file_key: bytes, user_pub_key: Any) -> Dict[str, str]:
        """Chiffre la clé symétrique du fichier avec la clé publique du destinataire."""
        if isinstance(user_pub_key, RSAPublicKey):
            enc = rsa_encrypt(file_key, user_pub_key)
            return {"algo": "RSA-OAEP", "key_hex": enc.hex()}
        elif isinstance(user_pub_key, ECPublicKey):
            # Schéma ECIES simplifié : clé éphémère ECC + AES-GCM
            from cryptolib.ecc import generate_ecc_keypair
            eph_pub, eph_priv = generate_ecc_keypair(NIST_P256)
            shared_secret = ecdh(eph_priv, user_pub_key)
            enc = aes_encrypt(file_key, shared_secret, mode="GCM")
            return {
                "algo": "ECDH-AES-GCM",
                "eph_pub": eph_pub.to_dict(),
                "key_hex": enc.hex(),
            }
        else:
            raise ValueError("Type de clé publique non supporté.")

    def _decrypt_file_key_by_user(self, enc_dict: Dict[str, Any], user_priv_key: Any) -> bytes:
        """Déchiffre la clé symétrique du fichier avec la clé privée de l'utilisateur."""
        algo = enc_dict["algo"]
        enc_bytes = bytes.fromhex(enc_dict["key_hex"])

        if algo == "RSA-OAEP":
            if not isinstance(user_priv_key, RSAPrivateKey):
                raise ValueError("Clé RSA attendue pour ce déchiffrement.")
            return rsa_decrypt(enc_bytes, user_priv_key)
        elif algo == "ECDH-AES-GCM":
            if not isinstance(user_priv_key, ECPrivateKey):
                raise ValueError("Clé ECC attendue pour ce déchiffrement.")
            from cryptolib.ecc import ECPoint
            eph_dict = enc_dict["eph_pub"]
            pt = ECPoint(int(eph_dict["x"], 16), int(eph_dict["y"], 16))
            eph_pub = ECPublicKey(pt, NIST_P256)
            shared_secret = ecdh(user_priv_key, eph_pub)
            return aes_decrypt(enc_bytes, shared_secret, mode="GCM")
        else:
            raise ValueError(f"Algorithme inconnu : {algo}")

    def add_file(
        self,
        filepath: str,
        owner_username: str,
        owner_priv_key: Any,
        owner_cert: Certificate,
        owner_chain: Optional[List[Certificate]] = None,
        sign: bool = True,
        block_size: int = 4096,
        co_recipients: Optional[List[Tuple[str, Certificate]]] = None,
    ) -> str:
        """
        Ajoute et chiffre un fichier dans le coffre-fort :
        1. Découpage en blocs de 4 Ko et calcul de l'arbre de Merkle.
        2. Génération d'une clé AES-256 aléatoire unique pour ce fichier.
        3. Chiffrement du fichier avec AES-256-GCM.
        4. Chiffrement de la clé de fichier pour le propriétaire et les co-propriétaires.
        5. Signature électronique du fichier par son auteur.
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Fichier '{filepath}' introuvable.")

        filename = os.path.basename(filepath)
        with open(filepath, "rb") as f:
            content = f.read()

        # 1. Arbre de Merkle sur les blocs de 4 Ko
        chunks = [content[i : i + block_size] for i in range(0, len(content), block_size)] or [b""]
        merkle_tree = MerkleTree(chunks)
        merkle_root_hex = merkle_tree.get_root_hex()

        # 2. Clé symétrique aléatoire AES-256
        file_key = os.urandom(32)

        # 3. Chiffrement du contenu en AES-256-GCM
        encrypted_content = aes_encrypt(content, file_key, mode="GCM")
        storage_filename = f"{filename}_{merkle_root_hex[:12]}.vault"
        storage_path = os.path.join(self.vault_dir, storage_filename)
        with open(storage_path, "wb") as f:
            f.write(encrypted_content)

        # 4. Chiffrement de la clé pour le propriétaire principal et les co-propriétaires
        owner_pub = owner_cert.get_public_key_object()
        enc_key_dict = self._encrypt_file_key_for_user(file_key, owner_pub)

        authorized_dict = {
            owner_username: enc_key_dict
        }
        owners_list = [owner_username]
        if co_recipients:
            for recip_username, recip_cert in co_recipients:
                if recip_username not in authorized_dict:
                    recip_pub = recip_cert.get_public_key_object()
                    authorized_dict[recip_username] = self._encrypt_file_key_for_user(file_key, recip_pub)
                    owners_list.append(recip_username)

        # 5. Signature de l'auteur
        signature_str = ""
        if sign:
            if isinstance(owner_priv_key, RSAPrivateKey):
                signature_str = rsa_sign(content, owner_priv_key).hex()
            elif isinstance(owner_priv_key, ECPrivateKey):
                r, s = ecdsa_sign(content, owner_priv_key)
                signature_str = f"{hex(r)}:{hex(s)}"

        # Enregistrement dans l'index
        self.index[filename] = {
            "storage_file": storage_filename,
            "size_bytes": len(content),
            "block_size": block_size,
            "merkle_root": merkle_root_hex,
            "author": owner_username,
            "owners": owners_list,
            "author_cert": owner_cert.to_dict(),
            "author_chain": [c.to_dict() for c in (owner_chain or [])],
            "signature": signature_str,
            "authorized_recipients": authorized_dict,
        }
        self._save_index()
        return filename

    def share_file(
        self,
        filename: str,
        owner_username: str,
        owner_priv_key: Any,
        recipient_username: str,
        recipient_cert: Certificate,
    ) -> None:
        """Partage un fichier existant avec un destinataire en chiffrant la clé du fichier pour lui."""
        if filename not in self.index:
            raise KeyError(f"Fichier '{filename}' non trouvé dans le coffre.")

        entry = self.index[filename]
        if owner_username not in entry["authorized_recipients"]:
            raise PermissionError(f"'{owner_username}' n'a pas accès à la clé de ce fichier.")

        # Déchiffrement de la clé de fichier par le propriétaire
        owner_enc = entry["authorized_recipients"][owner_username]
        file_key = self._decrypt_file_key_by_user(owner_enc, owner_priv_key)

        # Chiffrement pour le destinataire
        recip_pub = recipient_cert.get_public_key_object()
        recip_enc = self._encrypt_file_key_for_user(file_key, recip_pub)

        entry["authorized_recipients"][recipient_username] = recip_enc
        self._save_index()

    def get_file(
        self,
        filename: str,
        username: str,
        user_priv_key: Any,
        output_filepath: str,
        trusted_roots: Optional[List[Certificate]] = None,
    ) -> Tuple[bool, str]:
        """
        Extrait et vérifie un fichier du coffre-fort :
        1. Déchiffre la clé symétrique et le contenu.
        2. Recalcule l'arbre de Merkle et vérifie la racine.
        3. Valide la signature de l'auteur et son certificat.
        """
        if filename not in self.index:
            raise KeyError(f"Fichier '{filename}' non trouvé dans le coffre.")

        entry = self.index[filename]
        if username not in entry["authorized_recipients"]:
            raise PermissionError(f"Utilisateur '{username}' non autorisé pour ce fichier.")

        # 1. Déchiffrement de la clé symétrique
        enc_dict = entry["authorized_recipients"][username]
        file_key = self._decrypt_file_key_by_user(enc_dict, user_priv_key)

        # Déchiffrement du contenu
        storage_path = os.path.join(self.vault_dir, entry["storage_file"])
        with open(storage_path, "rb") as f:
            encrypted_data = f.read()

        plaintext = aes_decrypt(encrypted_data, file_key, mode="GCM")

        # 2. Vérification par Arbre de Merkle
        block_size = entry["block_size"]
        chunks = [plaintext[i : i + block_size] for i in range(0, len(plaintext), block_size)] or [b""]
        tree = MerkleTree(chunks)
        if tree.get_root_hex() != entry["merkle_root"]:
            raise ValueError("Échec de vérification d'intégrité : Arbre de Merkle altéré !")

        # 3. Vérification de la signature de l'auteur
        sig_str = entry.get("signature", "")
        author_valid = True
        if sig_str:
            author_cert = Certificate.from_dict(entry["author_cert"])
            author_chain = [Certificate.from_dict(c) for c in entry.get("author_chain", [])]
            if trusted_roots:
                valid_chain, _ = verify_certificate_chain(author_cert, author_chain, trusted_roots)
                if not valid_chain:
                    author_valid = False

            author_pub = author_cert.get_public_key_object()
            if isinstance(author_pub, RSAPublicKey):
                author_valid = author_valid and rsa_verify(plaintext, bytes.fromhex(sig_str), author_pub)
            elif isinstance(author_pub, ECPublicKey):
                r_str, s_str = sig_str.split(":")
                author_valid = author_valid and ecdsa_verify(plaintext, (int(r_str, 16), int(s_str, 16)), author_pub)

        # Sauvegarde
        with open(output_filepath, "wb") as f:
            f.write(plaintext)

        status_msg = "Intégrité Merkle validée " + ("et Signature Auteur authentifiée " if author_valid else "mais Signature douteuse ")
        return author_valid, status_msg

    def list_files(self, username: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Liste les fichiers présents dans le coffre.
        Si username est fourni (et différent de 'all'), filtre strictement pour ne
        retourner QUE les fichiers dont l'utilisateur est l'auteur, un co-propriétaire,
        ou un destinataire autorisé ayant reçu une clé d'enveloppe chiffrée.
        """
        items = []
        for name, meta in self.index.items():
            author = meta.get("author", "")
            owners = meta.get("owners", [author])
            recipients = list(meta.get("authorized_recipients", {}).keys())

            user_role = "viewer"
            if username and username.lower() != "all":
                is_author = (username == author)
                is_owner = (username in owners)
                is_recipient = (username in recipients)

                if not (is_author or is_owner or is_recipient):
                    continue

                if is_author:
                    user_role = "author"
                elif is_owner:
                    user_role = "co-owner"
                elif is_recipient:
                    user_role = "recipient"

            items.append({
                "filename": name,
                "size_bytes": meta["size_bytes"],
                "author": author,
                "owners": owners,
                "recipients": recipients,
                "merkle_root": meta["merkle_root"],
                "signed": bool(meta.get("signature")),
                "user_role": user_role,
            })
        return items

    def delete_file(self, filename: str, requester_username: str) -> bool:
        """Supprime un fichier du coffre si le demandeur en est l'auteur ou un (co-)propriétaire."""
        if filename not in self.index:
            raise KeyError(f"Fichier '{filename}' non trouvé dans le coffre.")

        entry = self.index[filename]
        allowed_deleters = set([entry.get("author", "")] + entry.get("owners", []) + list(entry.get("authorized_recipients", {}).keys()))
        if requester_username not in allowed_deleters:
            raise PermissionError(f"Seul le propriétaire ou un co-propriétaire peut supprimer '{filename}'.")

        # Supprimer le fichier de stockage chiffré sur le disque
        storage_path = os.path.join(self.vault_dir, entry["storage_file"])
        if os.path.exists(storage_path):
            try:
                os.remove(storage_path)
            except Exception:
                pass

        del self.index[filename]
        self._save_index()
        return True


def _load_private_key_from_dict(d: dict) -> Any:
    if "d" in d and "n" in d:
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
        return ECPrivateKey(int(d["d"], 16), NIST_P256)
    raise ValueError("Format de clé privée non reconnu.")


def main():
    parser = argparse.ArgumentParser(description="CryptoVault - Coffre-fort de fichiers sécurisé")
    parser.add_argument("--vault-dir", default=".vault_storage", help="Répertoire de stockage du coffre")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: add
    p_add = subparsers.add_parser("add", help="Ajouter un fichier dans le coffre-fort")
    p_add.add_argument("--file", required=True, help="Chemin du fichier source")
    p_add.add_argument("--user", required=True, help="Nom d'utilisateur propriétaire")
    p_add.add_argument("--keystore", required=True, help="Chemin du KeyStore de l'utilisateur")
    p_add.add_argument("--password", required=True, help="Mot de passe du KeyStore")
    p_add.add_argument("--no-sign", action="store_true", help="Ne pas signer le fichier")

    # Subcommand: get
    p_get = subparsers.add_parser("get", help="Récupérer et vérifier un fichier du coffre-fort")
    p_get.add_argument("--file", required=True, help="Nom du fichier dans le coffre")
    p_get.add_argument("--user", required=True, help="Nom d'utilisateur destinataire")
    p_get.add_argument("--keystore", required=True, help="Chemin du KeyStore de l'utilisateur")
    p_get.add_argument("--password", required=True, help="Mot de passe du KeyStore")
    p_get.add_argument("--out", required=True, help="Chemin du fichier de sortie déchiffré")

    # Subcommand: list
    p_list = subparsers.add_parser("list", help="Lister les fichiers du coffre-fort")

    # Subcommand: share
    p_share = subparsers.add_parser("share", help="Partager l'accès à un fichier avec un autre utilisateur")
    p_share.add_argument("--file", required=True, help="Nom du fichier dans le coffre")
    p_share.add_argument("--user", required=True, help="Nom d'utilisateur du propriétaire actuel")
    p_share.add_argument("--keystore", required=True, help="Chemin du KeyStore du propriétaire")
    p_share.add_argument("--password", required=True, help="Mot de passe du KeyStore du propriétaire")
    p_share.add_argument("--recipient-user", required=True, help="Nom du destinataire")
    p_share.add_argument("--recipient-cert", required=True, help="Chemin du certificat JSON du destinataire")

    args = parser.parse_args()
    vault = FileVault(vault_dir=args.vault_dir)

    if args.command == "add":
        ks_data = KeyStore.load(args.keystore, args.password)
        priv_key = _load_private_key_from_dict(ks_data["private_key"])
        cert = Certificate.from_dict(ks_data["certificate"])
        roots = [Certificate.from_dict(r) for r in ks_data.get("trusted_roots", [])]

        name = vault.add_file(
            filepath=args.file,
            owner_username=args.user,
            owner_priv_key=priv_key,
            owner_cert=cert,
            owner_chain=[],
            sign=not args.no_sign,
        )
        print(f"[+] Fichier '{args.file}' ajouté au coffre sous le nom : '{name}'")
        print(f"    Racine de Merkle : {vault.index[name]['merkle_root']}")

    elif args.command == "get":
        ks_data = KeyStore.load(args.keystore, args.password)
        priv_key = _load_private_key_from_dict(ks_data["private_key"])
        roots = [Certificate.from_dict(r) for r in ks_data.get("trusted_roots", [])]

        valid, msg = vault.get_file(
            filename=args.file,
            username=args.user,
            user_priv_key=priv_key,
            output_filepath=args.out,
            trusted_roots=roots,
        )
        print(f"[*] Résultat de l'extraction : {msg}")
        print(f"[+] Fichier déchiffré extrait avec succès vers : '{args.out}'")

    elif args.command == "list":
        files = vault.list_files()
        print(f"{'Fichier':<25} {'Taille (octets)':<16} {'Auteur':<12} {'Signé':<8} {'Destinataires'}")
        print("-" * 80)
        for f in files:
            print(f"{f['filename']:<25} {f['size_bytes']:<16} {f['author']:<12} {str(f['signed']):<8} {', '.join(f['recipients'])}")

    elif args.command == "share":
        ks_data = KeyStore.load(args.keystore, args.password)
        priv_key = _load_private_key_from_dict(ks_data["private_key"])

        with open(args.recipient_cert, "r") as f:
            recip_cert_dict = json.load(f)
        recip_cert = Certificate.from_dict(recip_cert_dict)

        vault.share_file(
            filename=args.file,
            owner_username=args.user,
            owner_priv_key=priv_key,
            recipient_username=args.recipient_user,
            recipient_cert=recip_cert,
        )
        print(f"[+] Fichier '{args.file}' partagé avec succès avec '{args.recipient_user}'.")


if __name__ == "__main__":
    main()

