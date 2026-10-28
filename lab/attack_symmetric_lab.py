"""
Laboratoire d'Attaques - Module 6 : Faiblesses et Attaques en Cryptographie Symétrique
Démontre :
1. La fuite visuelle critique du mode ECB sur une image Bitmap (BMP) vs CBC.
2. L'attaque par retournement de bits (Bit-Flipping) sur AES-CBC non authentifié (admin=0 -> admin=1) vs détection par AES-GCM (AEAD).
3. L'attaque par réutilisation de clé sur le Masque Jetable (C1 ^ C2 = M1 ^ M2) et crib-dragging.
"""

import sys
import os
import struct
from cryptography.exceptions import InvalidTag

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cryptolib.symmetric import (
    aes_encrypt,
    aes_decrypt,
    otp_encrypt,
)


# 1. Démonstration de Fuite Visuelle en Mode ECB (Image BMP)

def generate_sample_bmp(width: int = 128, height: int = 128) -> bytes:
    """
    Génère une image Bitmap 24-bit non compressée avec un logo géométrique
    (fond blanc avec un carré/cadenas noir au centre).
    """
    row_bytes = (width * 3 + 3) & ~3  # Alignement sur 4 octets
    pixel_data_size = row_bytes * height
    file_size = 54 + pixel_data_size

    # En-tête BMP (14 octets)
    bmp_header = struct.pack(
        "<2sIHHI",
        b"BM",
        file_size,
        0, 0,
        54  # Offset vers les pixels
    )

    # En-tête DIB / BITMAPINFOHEADER (40 octets)
    dib_header = struct.pack(
        "<IiiHHIIiiII",
        40, width, height, 1, 24, 0,
        pixel_data_size, 2835, 2835, 0, 0
    )

    # Génération des pixels : fond blanc (0xFFFFFF), motif central noir (0x000000)
    pixel_rows = []
    center_min_x, center_max_x = width // 4, 3 * width // 4
    center_min_y, center_max_y = height // 4, 3 * height // 4

    for y in range(height):
        row = bytearray()
        for x in range(width):
            if center_min_x <= x <= center_max_x and center_min_y <= y <= center_max_y:
                # Noir (B, G, R)
                row.extend(b"\x00\x00\x00")
            else:
                # Blanc (B, G, R)
                row.extend(b"\xff\xff\xff")
        # Padding de fin de ligne pour alignement sur 4 octets
        row.extend(b"\x00" * (row_bytes - width * 3))
        pixel_rows.append(row)

    return bmp_header + dib_header + b"".join(pixel_rows)


def demo_ecb_visual_leakage():
    print("=" * 80)
    print(" 1. DÉMONSTRATION VISUELLE DU MODE ECB SUR IMAGE BITMAP (BMP)")
    print("=" * 80)
    print("Le mode ECB chiffre chaque bloc de 16 octets isolément sans chaînage.")
    print("Des blocs clairs identiques (pixels blancs ou noirs) produisent des blocs chiffrés identiques !")
    print("-" * 80)

    bmp_raw = generate_sample_bmp(128, 128)
    header = bmp_raw[:54]
    pixels = bmp_raw[54:]

    key = os.urandom(32)  # Clé AES-256

    # Chiffrement ECB des données de pixels (on conserve l'en-tête pour que l'image reste lisible)
    ecb_cipher = aes_encrypt(pixels, key, mode="ECB")
    bmp_ecb = header + ecb_cipher[:len(pixels)]

    # Chiffrement CBC
    cbc_package = aes_encrypt(pixels, key, mode="CBC")
    # cbc_package contient 16 octets d'IV puis le chiffré
    bmp_cbc = header + cbc_package[16:16 + len(pixels)]

    lab_dir = os.path.dirname(__file__)
    orig_path = os.path.join(lab_dir, "demo_original.bmp")
    ecb_path = os.path.join(lab_dir, "demo_ecb_leakage.bmp")
    cbc_path = os.path.join(lab_dir, "demo_cbc_secure.bmp")

    with open(orig_path, "wb") as f:
        f.write(bmp_raw)
    with open(ecb_path, "wb") as f:
        f.write(bmp_ecb)
    with open(cbc_path, "wb") as f:
        f.write(bmp_cbc)

    print(f"  [Original] Image générée : {orig_path}")
    print(f"  [ECB]      Image chiffrée ECB (MOTIF TOUJOURS VISIBLE) : {ecb_path}")
    print(f"  [CBC]      Image chiffrée CBC (BRUIT ALÉATOIRE COMPLET) : {cbc_path}")
    print("\nConclusion : Le mode ECB ne garantit PAS la confidentialité sémantique.")


# 2. Attaque Bit-Flipping sur CBC vs Détection par GCM (AEAD)

def attack_bit_flipping():
    print("\n" + "=" * 80)
    print(" 2. ATTAQUE BIT-FLIPPING SUR AES-CBC SANS AUTHENTIFICATION")
    print("=" * 80)
    print("En mode CBC : M_i = D_k(C_i) XOR C_{i-1}.")
    print("Modifier un bit dans C_{i-1} inverse directement le bit correspondant dans M_i !")
    print("-" * 80)

    key = os.urandom(32)  # Clé AES-256 secrète du serveur

    # Cookie de session d'un utilisateur ordinaire : 31 octets
    cookie_clair = b"user_id=1042;role=guest;admin=0"
    print(f"[Client]   Cookie émis par le serveur : '{cookie_clair.decode()}'")

    # ==================== CBC SANS MAC ====================
    # Paquet CBC = [IV : 16 octets] [Bloc 1 : 16 octets] [Bloc 2 : 16 octets avec padding]
    cbc_package = bytearray(aes_encrypt(cookie_clair, key, mode="CBC"))

    # 'admin=0' se trouve dans le Bloc 2 (index 14 du bloc 2, soit index 16 + 14 = 30 du clair)
    # Pour altérer l'octet 14 du Bloc 2, l'attaquant modifie l'octet 14 du Bloc 1 (ou de l'IV) !
    # Dans cookie_clair :
    # Bloc 1 (octets 0 à 15) : 'user_id=1042;rol'
    # Bloc 2 (octets 16 à 31) : 'e=guest;admin=0\x01'
    # L'octet '0' est à l'offset 14 dans le Bloc 2.
    # On altère l'octet 14 du Bloc 1 (index 16 (IV) + 14 = 30 dans cbc_package) :
    target_offset_in_prev_block = 16 + 14
    cbc_package[target_offset_in_prev_block] ^= (ord("0") ^ ord("1"))

    # Le serveur déchiffre le cookie falsifié
    decrypted_cbc = aes_decrypt(bytes(cbc_package), key, mode="CBC")
    print(f"\n[Attaque CBC]")
    print(f"  Cookie déchiffré par le serveur : '{decrypted_cbc}'")
    is_admin = b"admin=1" in decrypted_cbc
    print(f"  Élévation de privilèges réussie : {is_admin}  (admin=1 injecté sans la clé !)")

    # ==================== GCM (AEAD) ====================
    print(f"\n[Contre-mesure AES-GCM]")
    gcm_package = bytearray(aes_encrypt(cookie_clair, key, mode="GCM"))
    # L'attaquant tente la même modification dans le paquet GCM :
    gcm_package[20] ^= 0x01  # Inversion d'un bit de chiffré

    try:
        aes_decrypt(bytes(gcm_package), key, mode="GCM")
        print("  GCM a accepté le paquet (ÉCHEC DE SÉCURITÉ)")
    except InvalidTag:
        print("  Exception InvalidTag levée immédiatement par GCM ! ")
        print("  Altération détectée : le paquet est rejeté avant tout traitement.")


# 3. Attaque par Réutilisation de Clé Masque Jetable (OTP)

def attack_otp_key_reuse():
    print("\n" + "=" * 80)
    print(" 3. ATTAQUE SUR LA RÉUTILISATION DE CLÉ DU MASQUE JETABLE (OTP)")
    print("=" * 80)
    print("C1 XOR C2 = (M1 XOR K) XOR (M2 XOR K) = M1 XOR M2")
    print("La clé s'annule complètement, exposant le XOR direct des deux textes clairs !")
    print("-" * 80)

    m1 = b"Attaque nocturne a l'aube sur le fort!"
    m2 = b"Repli strategique vers la base arriere"
    key = os.urandom(len(m1))

    c1 = otp_encrypt(m1, key)
    c2 = otp_encrypt(m2, key)

    c1_xor_c2 = bytes(x ^ y for x, y in zip(c1, c2))

    # Crib-dragging : supposons que l'attaquant devine le mot "Attaque " dans M1
    crib = b"Attaque "
    revealed_in_m2 = bytes(c1_xor_c2[i] ^ crib[i] for i in range(len(crib)))

    print(f"Crib testé sur M1        : '{crib.decode()}'")
    print(f"Texte déduit dans M2     : '{revealed_in_m2.decode()}' (Correspond à 'Repli st' !) [SUCCES]")
    print("\nConclusion : Une clé OTP ne doit JAMAIS être réutilisée plus d'une fois.")


def main():
    demo_ecb_visual_leakage()
    attack_bit_flipping()
    attack_otp_key_reuse()


if __name__ == "__main__":
    main()
