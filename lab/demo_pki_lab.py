"""
Laboratoire & Démonstration - Module 7 : PKI, Révocation et Protection de la Clé Racine (Shamir)
Démontre :
1. La création d'une hiérarchie complète de PKI (Root CA -> Intermediate CA -> Leaf User).
2. Le rejet systématique des certificats anormaux (expirés, falsifiés, révoqués, racine inconnue).
3. La sauvegarde de la clé racine par Partage de Secret de Shamir (k=3 parmi n=5 administrateurs).
"""

import sys
import os
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cryptolib.pki import (
    Certificate,
    CertificateAuthority,
    verify_certificate_chain,
    shamir_split_secret,
    shamir_reconstruct_secret,
)
from cryptolib.rsa import generate_keypair as generate_rsa_keypair


def demo_pki_hierarchy_and_security():
    print("=" * 80)
    print(" 1. DÉPLOIEMENT DE LA HIÉRARCHIE PKI & TESTS DE SÉCURITÉ DE CHAÎNE")
    print("=" * 80)

    # 1. Root CA
    root_subject = {"CN": "CryptoVault Root CA", "O": "CryptoVault Security Corp", "C": "FR"}
    root_ca = CertificateAuthority.create_root(root_subject, key_type="RSA", validity_days=3650)
    print(f"[Root CA]         Créée : '{root_subject['CN']}' (Auto-signée, 10 ans)")

    # 2. Intermediate CA
    inter_subject = {"CN": "CryptoVault Intermediate CA", "O": "CryptoVault Security Corp", "C": "FR"}
    _, inter_priv = generate_rsa_keypair(bits=1024)
    inter_cert = root_ca.issue_certificate(
        subject=inter_subject,
        subject_public_key_dict=inter_priv.public_key.to_dict(),
        is_ca=True,
        validity_days=1825,
    )
    inter_ca = CertificateAuthority(inter_cert, inter_priv)
    print(f"[Intermediate CA] Émise par Root CA : '{inter_subject['CN']}' (5 ans)")

    # 3. Certificats feuilles
    alice_subject = {"CN": "Alice (Client Messagerie)", "O": "CryptoVault Users", "C": "FR"}
    _, alice_priv = generate_rsa_keypair(bits=1024)
    alice_cert = inter_ca.issue_certificate(
        subject=alice_subject,
        subject_public_key_dict=alice_priv.public_key.to_dict(),
        is_ca=False,
        validity_days=365,
    )
    print(f"[Certificat Leaf] Émis pour '{alice_subject['CN']}' (1 an)")

    # --- Test 1 : Chaîne légitime ---
    valid, msg = verify_certificate_chain(
        target_cert=alice_cert,
        intermediate_certs=[inter_cert],
        trusted_roots=[root_ca.cert],
    )
    print(f"\n[Test 1] Validation de la chaîne légitime (Alice -> Inter -> Root) :")
    print(f"  Résultat : {valid}  ({msg})")

    # --- Test 2 : Certificat expiré ---
    future_time = time.time() + (400 * 86400)
    valid_exp, msg_exp = verify_certificate_chain(
        target_cert=alice_cert,
        intermediate_certs=[inter_cert],
        trusted_roots=[root_ca.cert],
        current_time=future_time,
    )
    print(f"\n[Test 2] Vérification avec certificat expiré (+400 jours) :")
    print(f"  Résultat : {valid_exp}  Rejeté ({msg_exp})")

    # --- Test 3 : Certificat falsifié par un attaquant ---
    fake_dict = alice_cert.to_dict()
    fake_dict["subject"]["CN"] = "Mallory Pirate"
    fake_cert = Certificate.from_dict(fake_dict)
    valid_fake, msg_fake = verify_certificate_chain(
        target_cert=fake_cert,
        intermediate_certs=[inter_cert],
        trusted_roots=[root_ca.cert],
    )
    print(f"\n[Test 3] Vérification d'un certificat au sujet falsifié (signature invalide) :")
    print(f"  Résultat : {valid_fake}  Rejeté ({msg_fake})")

    # --- Test 4 : Révocation par CRL ---
    inter_ca.revoke_certificate(alice_cert.serial_number)
    crl = inter_ca.generate_crl()
    valid_crl, msg_crl = verify_certificate_chain(
        target_cert=alice_cert,
        intermediate_certs=[inter_cert],
        trusted_roots=[root_ca.cert],
        crl=crl,
    )
    print(f"\n[Test 4] Vérification d'un certificat révoqué par la CRL de l'autorité :")
    print(f"  Résultat : {valid_crl}  Rejeté ({msg_crl})")


def demo_shamir_root_protection():
    print("\n" + "=" * 80)
    print(" 2. PROTECTION DE LA CLÉ RACINE : PARTAGE DE SECRET DE SHAMIR (3 parmi 5)")
    print("=" * 80)
    print("Pour éviter qu'un seul individu ne détienne la clé maîtresse de la Root CA,")
    print("elle est scindée en 5 parts réparties entre 5 officiers de sécurité (DSI, RSSI, etc.).")
    print("Au moins 3 officiers doivent coopérer pour reconstituer la clé (seuil k=3).")
    print("-" * 80)

    # Clé privée maître de 32 octets (256 bits)
    root_master_seed = os.urandom(32)
    print(f"Clé maître secrète Root CA : {root_master_seed.hex()}")

    shares = shamir_split_secret(root_master_seed, k=3, n=5)
    officers = [
        "1. Directeur Sécurité (RSSI)",
        "2. Administrateur Systèmes",
        "3. Responsable Cryptographie",
        "4. Directeur Général",
        "5. Auditeur Externe",
    ]

    print("\nParts émises pour chaque officier :")
    for (x, share_bytes), name in zip(shares, officers):
        print(f"  Officier {name:<32} -> Part x={x} : {share_bytes.hex()[:24]}...")

    # Scénario A : 2 officiers se présentent (insuffisant)
    print("\n[Scénario A] 2 officiers seulement se présentent (RSSI + Admin) :")
    recovered_2 = shamir_reconstruct_secret([shares[0], shares[1]])
    print(f"  Reconstruction avec 2 parts : {recovered_2 == root_master_seed}  (Clé corrompue, seuil k=3 non atteint !)")

    # Scénario B : 3 officiers se présentent (suffisant)
    print("\n[Scénario B] 3 officiers coopèrent (RSSI + Crypto + Auditeur) :")
    recovered_3 = shamir_reconstruct_secret([shares[0], shares[2], shares[4]])
    print(f"  Reconstruction avec 3 parts : {recovered_3 == root_master_seed}  (Clé maîtresse restaurée à l'identique !)")
    print("=" * 80)


def main():
    demo_pki_hierarchy_and_security()
    demo_shamir_root_protection()


if __name__ == "__main__":
    main()
