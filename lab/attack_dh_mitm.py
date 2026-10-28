"""
Laboratoire d'Attaques - Module 4 : Attaque de l'Homme du Milieu (MITM) sur Diffie–Hellman
Démontre :
1. L'attaque MITM active par « Mallory » sur un échange DH non authentifié (interception et altération).
2. La contre-mesure par signatures RSA (DH Authentifié) qui détecte et bloque Mallory.
3. L'illustration de la Confidentialité Persistante (PFS) avec DHE.
"""

import sys
import os
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cryptolib.dh import (
    DHGroup,
    DHEphemeral,
    derive_session_keys,
    sign_dh_public_key,
    verify_dh_public_key,
)
from cryptolib.rsa import generate_keypair


def simulate_unauthenticated_dh_mitm():
    print("=" * 75)
    print(" 1. ATTAQUE MITM ACTIVE : INTERCEPTION ET MODIFICATION DU FLUX (SANS AUTH)")
    print("=" * 75)

    group = DHGroup.test_512()

    # 1. Alice prépare son échange
    alice = DHEphemeral(group)
    print(f"[Alice]   Génère sa clé publique DH A : {str(alice.public_key)[:25]}...")

    # Mallory intercepte le message d'Alice destiné à Bob !
    mallory_for_alice = DHEphemeral(group)
    mallory_for_bob = DHEphemeral(group)
    print("[Mallory] Intercepte la clé publique A d'Alice.")
    print(f"[Mallory] Substitue sa propre clé publique M1 vers Bob : {str(mallory_for_bob.public_key)[:25]}...")

    # 2. Bob reçoit M1 en croyant que c'est la clé d'Alice
    bob = DHEphemeral(group)
    print(f"[Bob]     Reçoit la clé M1 et génère sa clé publique B : {str(bob.public_key)[:25]}...")

    # Mallory intercepte le retour de Bob destiné à Alice !
    print("[Mallory] Intercepte la clé publique B de Bob.")
    print(f"[Mallory] Substitue sa propre clé publique M2 vers Alice : {str(mallory_for_alice.public_key)[:25]}...")

    # 3. Calculs des secrets partagés
    k_alice = alice.compute_shared_secret(mallory_for_alice.public_key)
    k_bob = bob.compute_shared_secret(mallory_for_bob.public_key)

    k_mallory_alice = mallory_for_alice.compute_shared_secret(alice.public_key)
    k_mallory_bob = mallory_for_bob.compute_shared_secret(bob.public_key)

    print(f"\n[Vérification Clés]")
    print(f"  Secret Alice   == Mallory(Alice) : {k_alice == k_mallory_alice} ")
    print(f"  Secret Bob     == Mallory(Bob)   : {k_bob == k_mallory_bob} ")
    print(f"  Secret Alice   == Bob            : {k_alice == k_bob} [ECHEC] (Aucun secret direct !)")

    # 4. Transmission de message chiffré : Alice envoie un ordre bancaire
    enc_key_am, _ = derive_session_keys(k_alice)
    enc_key_mb, _ = derive_session_keys(k_mallory_bob)

    original_order = b"VIREMENT: 10 000 EUR vers COMPTE-ALICE-FR76"
    nonce = os.urandom(12)
    aes_am = AESGCM(enc_key_am)
    c_alice = aes_am.encrypt(nonce, original_order, None)
    print(f"\n[Alice]   Envoie message chiffré : '{original_order.decode()}'")

    # 5. Mallory intercepte, déchiffre, altère et ré-émet vers Bob !
    aes_mallory_read = AESGCM(k_mallory_alice.to_bytes((k_mallory_alice.bit_length() + 7) // 8, "big")[:32])
    # En utilisant la clé dérivée exacte :
    decrypted_by_mallory = AESGCM(enc_key_am).decrypt(nonce, c_alice, None)
    print(f"[Mallory] Déchiffre en clair : '{decrypted_by_mallory.decode()}'")

    tampered_order = b"VIREMENT: 10 000 EUR vers COMPTE-MALLORY-PIRATE"
    nonce_mb = os.urandom(12)
    c_mallory = AESGCM(enc_key_mb).encrypt(nonce_mb, tampered_order, None)
    print(f"[Mallory] Ré-émet après falsification : '{tampered_order.decode()}'")

    # 6. Bob déchiffre
    received_by_bob = AESGCM(enc_key_mb).decrypt(nonce_mb, c_mallory, None)
    print(f"[Bob]     Reçoit et valide : '{received_by_bob.decode()}'")
    print(f" Falsification réussie à 100% sans que ni Alice ni Bob ne s'en aperçoivent !")


def simulate_authenticated_dh():
    print("\n" + "=" * 75)
    print(" 2. CONTRE-MESURE : DIFFIE–HELLMAN AUTHENTIFIÉ PAR SIGNATURE RSA")
    print("=" * 75)

    group = DHGroup.test_512()
    # Clés d'identité RSA long-terme
    alice_pub_rsa, alice_priv_rsa = generate_keypair(bits=1024)
    bob_pub_rsa, bob_priv_rsa = generate_keypair(bits=1024)
    mallory_pub_rsa, mallory_priv_rsa = generate_keypair(bits=1024)

    # 1. Alice génère sa clé DH éphémère et la signe avec sa clé RSA
    alice = DHEphemeral(group)
    sig_alice = sign_dh_public_key(alice.public_key, alice_priv_rsa)
    print("[Alice]   Émet (Clé DH A, Signature RSA Alice)")

    # 2. Mallory tente de remplacer la clé A par sa propre clé M
    mallory = DHEphemeral(group)
    print("[Mallory] Tente d'injecter sa propre clé DH M vers Bob...")

    # Cas A : Mallory transmet M avec l'ancienne signature d'Alice
    valid_with_old_sig = verify_dh_public_key(mallory.public_key, sig_alice, alice_pub_rsa)
    print(f"  [Test 1] Bob vérifie la clé de Mallory avec la signature d'Alice : {valid_with_old_sig} [ECHEC]")

    # Cas B : Mallory signe M avec sa propre clé RSA de pirate
    sig_mallory = sign_dh_public_key(mallory.public_key, mallory_priv_rsa)
    valid_with_mallory_sig = verify_dh_public_key(mallory.public_key, sig_mallory, alice_pub_rsa)
    print(f"  [Test 2] Bob vérifie la signature de Mallory avec la clé publique d'Alice : {valid_with_mallory_sig} [ECHEC]")

    print("\n Succès de la contre-mesure :")
    print("Bob rejette la connexion et alerte d'une tentative d'usurpation MITM !")


def explain_pfs():
    print("\n" + "=" * 75)
    print(" 3. ILLUSTRATION : CONFIDENTIALITÉ PERSISTANTE (PERFECT FORWARD SECRECY)")
    print("=" * 75)
    print("Scénario classique sans PFS (RSA statique ou DH statique) :")
    print("  - Un espion enregistre tous les flux réseau chiffrés pendant 2 ans.")
    print("  - Si le serveur est perquisitionné ou sa clé privée RSA volée 2 ans plus tard,")
    print("    TOUTES les sessions passées peuvent être déchiffrées rétroactivement.")
    print("\nScénario moderne avec PFS (DHE / ECDHE) :")
    print("  - À chaque session, Alice et Bob tirent des exposants aléatoires 'a' et 'b' neufs,")
    print("    puis les effacent de la mémoire RAM dès la fin du handshake.")
    print("  - La clé RSA ne sert QU'À SIGNER l'échange de clés, jamais à chiffrer le secret.")
    print("  - Compromettre la clé RSA 2 ans plus tard ne donne AUCUN moyen de recalculer")
    print("    les secrets éphémères K = g^(ab) mod p passés.")
    print("=" * 75)


def main():
    simulate_unauthenticated_dh_mitm()
    simulate_authenticated_dh()
    explain_pfs()


if __name__ == "__main__":
    main()
