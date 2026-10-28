"""
Module 7 : Infrastructure de Gestion de Clés (PKI)
- Certificats numériques (format canonique structuré avec signatures RSA ou ECDSA)
- Hiérarchie d'autorités de certification (Root CA -> Intermediate CA -> Leaf User)
- Moteur de validation rigoureuse de chaîne de confiance (Signatures, Dates, Usages, CA constraints)
- Liste de révocation de certificats (CRL) signée
- Magasin de clés sécurisé (Keystore) chiffré en AES-256-GCM avec clé dérivée du mot de passe (PBKDF2)
- Partage de secret de Shamir (k parmi n) pour la protection de la clé racine (Bonus)
"""

import os
import sys
import json
import time
import secrets
from typing import Dict, List, Tuple, Optional, Any, Union

from cryptolib.hashing import hash_bytes
from cryptolib.symmetric import aes_encrypt, aes_decrypt
from cryptolib.rsa import (
    RSAPublicKey,
    RSAPrivateKey,
    rsa_sign,
    rsa_verify,
    generate_keypair as generate_rsa_keypair,
)
from cryptolib.ecc import (
    ECPublicKey,
    ECPrivateKey,
    ecdsa_sign,
    ecdsa_verify,
    generate_ecc_keypair,
    NIST_P256,
)
from cryptolib.numtheory import exp_mod, mod_inverse


# 1. Structure de Certificat Numérique

class Certificate:
    """
    Certificat numérique liant une identité (Subject) à une clé publique.
    Signé par une autorité émettrice (Issuer).
    """

    def __init__(
        self,
        serial_number: int,
        subject: Dict[str, str],
        issuer: Dict[str, str],
        valid_from: float,
        valid_to: float,
        public_key_dict: Dict[str, Any],
        is_ca: bool = False,
        key_usage: Optional[List[str]] = None,
        signature_algorithm: str = "RSA-SHA256",
        signature: str = "",
    ):
        self.serial_number = serial_number
        self.subject = subject
        self.issuer = issuer
        self.valid_from = valid_from
        self.valid_to = valid_to
        self.public_key_dict = public_key_dict
        self.is_ca = is_ca
        self.key_usage = key_usage or (["keyCertSign", "cRLSign"] if is_ca else ["digitalSignature", "keyEncipherment"])
        self.signature_algorithm = signature_algorithm
        self.signature = signature

    def get_tbs_dict(self) -> Dict[str, Any]:
        """Retourne le dictionnaire des champs à signer (To-Be-Signed)."""
        return {
            "serial_number": self.serial_number,
            "subject": self.subject,
            "issuer": self.issuer,
            "valid_from": self.valid_from,
            "valid_to": self.valid_to,
            "public_key": self.public_key_dict,
            "is_ca": self.is_ca,
            "key_usage": sorted(self.key_usage),
            "signature_algorithm": self.signature_algorithm,
        }

    def get_tbs_bytes(self) -> bytes:
        """Produit une représentation canonique déterministe (JSON ordonné) des données à signer."""
        tbs = self.get_tbs_dict()
        return json.dumps(tbs, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def to_dict(self) -> Dict[str, Any]:
        d = self.get_tbs_dict()
        d["signature"] = self.signature
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Certificate":
        return cls(
            serial_number=data["serial_number"],
            subject=data["subject"],
            issuer=data["issuer"],
            valid_from=data["valid_from"],
            valid_to=data["valid_to"],
            public_key_dict=data["public_key"],
            is_ca=data.get("is_ca", False),
            key_usage=data.get("key_usage"),
            signature_algorithm=data.get("signature_algorithm", "RSA-SHA256"),
            signature=data.get("signature", ""),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "Certificate":
        return cls.from_dict(json.loads(json_str))

    def is_valid_at_time(self, timestamp: Optional[float] = None) -> bool:
        """Vérifie si le certificat est dans sa plage de validité temporelle."""
        t = time.time() if timestamp is None else timestamp
        return self.valid_from <= t <= self.valid_to

    def get_public_key_object(self) -> Union[RSAPublicKey, ECPublicKey]:
        """Reconstitue l'objet clé publique natif (RSA ou ECC)."""
        pk = self.public_key_dict
        if pk["type"] == "RSA_PUBLIC_KEY":
            return RSAPublicKey.from_dict(pk)
        elif pk["type"] == "EC_PUBLIC_KEY":
            from cryptolib.ecc import ECPoint
            x = int(pk["x"], 16) if pk["x"] else None
            y = int(pk["y"], 16) if pk["y"] else None
            pt = ECPoint(x, y, is_infinity=(x is None))
            return ECPublicKey(pt, NIST_P256)
        else:
            raise ValueError(f"Type de clé publique inconnu : {pk.get('type')}")


# 2. Liste de Révocation de Certificats (CRL)

class CRL:
    """Liste de révocation de certificats signée par l'autorité."""

    def __init__(
        self,
        issuer: Dict[str, str],
        this_update: float,
        next_update: float,
        revoked_serials: List[int],
        signature: str = "",
    ):
        self.issuer = issuer
        self.this_update = this_update
        self.next_update = next_update
        self.revoked_serials = set(revoked_serials)
        self.signature = signature

    def get_tbs_bytes(self) -> bytes:
        d = {
            "issuer": self.issuer,
            "this_update": self.this_update,
            "next_update": self.next_update,
            "revoked_serials": sorted(list(self.revoked_serials)),
        }
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def is_revoked(self, serial: int) -> bool:
        return serial in self.revoked_serials


# 3. Autorité de Certification (Certificate Authority)

class CertificateAuthority:
    """Autorité de certification capable d'émettre et révoquer des certificats."""

    def __init__(self, cert: Certificate, priv_key: Union[RSAPrivateKey, ECPrivateKey]):
        self.cert = cert
        self.priv_key = priv_key
        self.revoked_serials: List[int] = []

    @classmethod
    def create_root(
        cls,
        subject: Dict[str, str],
        priv_key: Optional[Union[RSAPrivateKey, ECPrivateKey]] = None,
        key_type: str = "RSA",
        validity_days: int = 3650,
    ) -> "CertificateAuthority":
        """Crée une autorité racine (Root CA) avec un certificat auto-signé."""
        if priv_key is None:
            if key_type == "RSA":
                _, priv_key = generate_rsa_keypair(bits=1024)
            else:
                _, priv_key = generate_ecc_keypair(NIST_P256)

        now = time.time()
        pub_dict = priv_key.public_key.to_dict()
        sig_algo = "RSA-SHA256" if isinstance(priv_key, RSAPrivateKey) else "ECDSA-P256"

        cert = Certificate(
            serial_number=1,
            subject=subject,
            issuer=subject,  # Auto-signé : Issuer == Subject
            valid_from=now - 60,
            valid_to=now + validity_days * 86400,
            public_key_dict=pub_dict,
            is_ca=True,
            key_usage=["keyCertSign", "cRLSign", "digitalSignature"],
            signature_algorithm=sig_algo,
        )

        tbs = cert.get_tbs_bytes()
        if isinstance(priv_key, RSAPrivateKey):
            sig_bytes = rsa_sign(tbs, priv_key)
            cert.signature = sig_bytes.hex()
        else:
            r, s = ecdsa_sign(tbs, priv_key)
            cert.signature = f"{hex(r)}:{hex(s)}"

        return cls(cert, priv_key)

    def issue_certificate(
        self,
        subject: Dict[str, str],
        subject_public_key_dict: Dict[str, Any],
        is_ca: bool = False,
        validity_days: int = 365,
        serial_number: Optional[int] = None,
    ) -> Certificate:
        """Émet un nouveau certificat signé par cette autorité."""
        if not self.cert.is_ca:
            raise PermissionError("Cette entité n'est pas autorisée à émettre des certificats (is_ca=False).")

        now = time.time()
        if serial_number is None:
            serial_number = secrets.randbits(64)

        sig_algo = "RSA-SHA256" if isinstance(self.priv_key, RSAPrivateKey) else "ECDSA-P256"
        key_usage = ["keyCertSign", "cRLSign"] if is_ca else ["digitalSignature", "keyEncipherment"]

        cert = Certificate(
            serial_number=serial_number,
            subject=subject,
            issuer=self.cert.subject,
            valid_from=now - 60,
            valid_to=now + validity_days * 86400,
            public_key_dict=subject_public_key_dict,
            is_ca=is_ca,
            key_usage=key_usage,
            signature_algorithm=sig_algo,
        )

        tbs = cert.get_tbs_bytes()
        if isinstance(self.priv_key, RSAPrivateKey):
            sig_bytes = rsa_sign(tbs, self.priv_key)
            cert.signature = sig_bytes.hex()
        else:
            r, s = ecdsa_sign(tbs, self.priv_key)
            cert.signature = f"{hex(r)}:{hex(s)}"

        return cert

    def revoke_certificate(self, serial_number: int):
        """Ajoute un numéro de série à la liste de révocation."""
        if serial_number not in self.revoked_serials:
            self.revoked_serials.append(serial_number)

    def generate_crl(self, validity_days: int = 7) -> CRL:
        """Génère et signe une CRL."""
        now = time.time()
        crl = CRL(
            issuer=self.cert.subject,
            this_update=now,
            next_update=now + validity_days * 86400,
            revoked_serials=list(self.revoked_serials),
        )
        tbs = crl.get_tbs_bytes()
        if isinstance(self.priv_key, RSAPrivateKey):
            crl.signature = rsa_sign(tbs, self.priv_key).hex()
        else:
            r, s = ecdsa_sign(tbs, self.priv_key)
            crl.signature = f"{hex(r)}:{hex(s)}"
        return crl


# 4. Moteur de Validation de Chaîne de Confiance

def verify_single_signature(cert: Certificate, issuer_pub_key: Union[RSAPublicKey, ECPublicKey]) -> bool:
    """Vérifie la signature cryptographique d'un certificat."""
    tbs = cert.get_tbs_bytes()
    if cert.signature_algorithm == "RSA-SHA256":
        if not isinstance(issuer_pub_key, RSAPublicKey):
            return False
        sig_bytes = bytes.fromhex(cert.signature)
        return rsa_verify(tbs, sig_bytes, issuer_pub_key)
    elif cert.signature_algorithm == "ECDSA-P256":
        if not isinstance(issuer_pub_key, ECPublicKey):
            return False
        parts = cert.signature.split(":")
        if len(parts) != 2:
            return False
        r, s = int(parts[0], 16), int(parts[1], 16)
        return ecdsa_verify(tbs, (r, s), issuer_pub_key)
    return False


def verify_certificate_chain(
    target_cert: Certificate,
    intermediate_certs: List[Certificate],
    trusted_roots: List[Certificate],
    crl: Optional[CRL] = None,
    current_time: Optional[float] = None,
) -> Tuple[bool, str]:
    """
    Vérifie la chaîne de certification complète depuis le certificat feuille jusqu'à une racine de confiance.
    Contrôles effectués :
      1. Dates de validité temporelle de chaque maillon.
      2. Non-révocation par la CRL.
      3. Contraintes CA (seule une CA peut signer un autre certificat).
      4. Correspondance Sujet <-> Émetteur.
      5. Validité cryptographique de chaque signature.
      6. Ancrage sur une racine de confiance reconnue.
    """
    # 1. Vérification temporelle et révocation du certificat cible
    if not target_cert.is_valid_at_time(current_time):
        return False, "Le certificat cible a expiré ou n'est pas encore valide."

    if crl and crl.is_revoked(target_cert.serial_number):
        return False, f"Le certificat cible (série {target_cert.serial_number}) est RÉVOQUÉ."

    # Pool des certificats de recherche
    pool = {c.subject["CN"]: c for c in intermediate_certs + trusted_roots}
    trusted_cns = {r.subject["CN"]: r for r in trusted_roots}

    current = target_cert
    depth = 0
    max_depth = 10

    while depth < max_depth:
        depth += 1
        issuer_cn = current.issuer.get("CN")
        if not issuer_cn or issuer_cn not in pool:
            return False, f"Autorité émettrice '{issuer_cn}' inconnue ou introuvable dans la chaîne."

        issuer_cert = pool[issuer_cn]

        # Vérification temporelle de l'émetteur
        if not issuer_cert.is_valid_at_time(current_time):
            return False, f"Le certificat de l'autorité émettrice '{issuer_cn}' a expiré."

        # Révocation de l'autorité
        if crl and crl.is_revoked(issuer_cert.serial_number):
            return False, f"L'autorité émettrice '{issuer_cn}' a été révoquée."

        # Vérification que l'émetteur est autorisé à signer des certificats
        if not issuer_cert.is_ca:
            return False, f"L'émetteur '{issuer_cn}' n'a pas la contrainte CA requise (is_ca=False)."
        if "keyCertSign" not in issuer_cert.key_usage:
            return False, f"L'émetteur '{issuer_cn}' ne possède pas l'usage 'keyCertSign'."

        # Vérification cryptographique de la signature
        issuer_pub_key = issuer_cert.get_public_key_object()
        if not verify_single_signature(current, issuer_pub_key):
            return False, f"Signature cryptographique invalide sur le certificat émis par '{issuer_cn}'."

        # Si l'émetteur est dans les racines de confiance
        if issuer_cn in trusted_cns and issuer_cert.issuer.get("CN") == issuer_cn:
            # Vérification de l'auto-signature de la racine
            if not verify_single_signature(issuer_cert, issuer_pub_key):
                return False, f"La racine de confiance '{issuer_cn}' a une auto-signature invalide."
            return True, "Chaîne de confiance validée avec succès."

        # Remonter la chaîne
        current = issuer_cert

    return False, "Profondeur de chaîne de certification maximale dépassée."


# 5. Magasin de Clés Sécurisé (KeyStore)

class KeyStore:
    """
    Magasin sécurisé pour stocker la clé privée d'un utilisateur,
    chiffrée en AES-256-GCM avec une clé dérivée de son mot de passe.
    """

    @staticmethod
    def save(
        filepath: str,
        password: str,
        private_key_dict: Dict[str, Any],
        certificate: Certificate,
        trusted_roots: List[Certificate],
        iterations: int = 100_000,
    ) -> None:
        import hashlib
        salt = os.urandom(16)
        # Dérivation d'une clé AES-256 à partir du mot de passe
        derived_key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)

        payload = {
            "private_key": private_key_dict,
            "certificate": certificate.to_dict(),
            "trusted_roots": [r.to_dict() for r in trusted_roots],
        }
        payload_bytes = json.dumps(payload).encode("utf-8")

        # Chiffrement AES-GCM (Module 6)
        encrypted_package = aes_encrypt(payload_bytes, derived_key, mode="GCM")

        keystore_dict = {
            "version": 1,
            "salt_hex": salt.hex(),
            "iterations": iterations,
            "data_hex": encrypted_package.hex(),
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(keystore_dict, f, indent=2)

    @staticmethod
    def load(filepath: str, password: str) -> Dict[str, Any]:
        import hashlib
        with open(filepath, "r", encoding="utf-8") as f:
            keystore_dict = json.load(f)

        salt = bytes.fromhex(keystore_dict["salt_hex"])
        iterations = keystore_dict["iterations"]
        encrypted_package = bytes.fromhex(keystore_dict["data_hex"])

        derived_key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)
        # Déchiffrement AES-GCM (lèvera InvalidTag si mauvais mot de passe)
        payload_bytes = aes_decrypt(encrypted_package, derived_key, mode="GCM")
        return json.loads(payload_bytes.decode("utf-8"))

    @staticmethod
    def rotate_password(filepath: str, old_password: str, new_password: str) -> None:
        """Permet à l'utilisateur de changer son mot de passe de protection de clé."""
        data = KeyStore.load(filepath, old_password)
        priv_dict = data["private_key"]
        cert = Certificate.from_dict(data["certificate"])
        roots = [Certificate.from_dict(r) for r in data["trusted_roots"]]
        KeyStore.save(filepath, new_password, priv_dict, cert, roots)


# 6. Partage de Secret de Shamir (k parmi n) [Bonus]

# Grand nombre premier supérieur à 2^256 pour l'arithmétique dans le corps fini F_p
SHAMIR_PRIME = (1 << 256) - 189  # Premier de 256 bits


def shamir_split_secret(secret_bytes: bytes, k: int, n: int) -> List[Tuple[int, bytes]]:
    """
    Découpe un secret de 32 octets en n parts selon le schéma de Shamir (k parmi n).
    Polynôme P(x) = secret + a_1 * x + a_2 * x^2 + ... + a_{k-1} * x^{k-1} mod p.
    """
    if k > n or k <= 1:
        raise ValueError("Paramètres invalides pour le partage de Shamir (doit vérifier 1 < k <= n).")

    secret_int = int.from_bytes(secret_bytes, "big")
    if secret_int >= SHAMIR_PRIME:
        raise ValueError("Secret trop grand pour le corps fini choisi.")

    # Génération des coefficients aléatoires a_1 ... a_{k-1}
    coeffs = [secret_int] + [secrets.randbelow(SHAMIR_PRIME) for _ in range(k - 1)]

    shares = []
    for x in range(1, n + 1):
        # Évaluation du polynôme P(x) mod p (règle de Horner)
        y = 0
        for coeff in reversed(coeffs):
            y = (y * x + coeff) % SHAMIR_PRIME
        shares.append((x, y.to_bytes(32, "big")))

    return shares


def shamir_reconstruct_secret(shares: List[Tuple[int, bytes]]) -> bytes:
    """
    Reconstitue le secret à partir d'au moins k parts par interpolation de Lagrange en x = 0 :
    P(0) = sum_{j=0}^{k-1} y_j * l_j(0) mod p
    où l_j(0) = prod_{m != j} (-x_m) / (x_j - x_m) mod p.
    """
    k = len(shares)
    if k < 2:
        raise ValueError("Au moins 2 parts sont nécessaires pour la reconstruction.")

    xs = [s[0] for s in shares]
    ys = [int.from_bytes(s[1], "big") for s in shares]

    secret = 0
    for j in range(k):
        num = 1
        den = 1
        for m in range(k):
            if m == j:
                continue
            num = (num * (-xs[m])) % SHAMIR_PRIME
            den = (den * (xs[j] - xs[m])) % SHAMIR_PRIME

        lagrange_coeff = (num * mod_inverse(den % SHAMIR_PRIME, SHAMIR_PRIME)) % SHAMIR_PRIME
        secret = (secret + ys[j] * lagrange_coeff) % SHAMIR_PRIME

    return (secret % SHAMIR_PRIME).to_bytes(32, "big")
