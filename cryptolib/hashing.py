"""
Module 1 : Hachage, HMAC, Mots de passe et Arbre de Merkle
"""

import os
import sys
import hashlib
import hmac
import argparse
import time
from typing import List, Tuple, Optional, Dict, Any


# 1. Fonctions de Hachage et Vérification d'Intégrité

SUPPORTED_ALGOS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha3_256": hashlib.sha3_256,
    "sha512": hashlib.sha512,
}

BLOCK_SIZES = {
    "md5": 64,
    "sha1": 64,
    "sha256": 64,
    "sha3_256": 136,
    "sha512": 128,
}


def get_hasher(algo: str):
    """Retourne une instance de fonction de hachage selon l'algorithme demandé."""
    algo_clean = algo.lower().replace("-", "_")
    if algo_clean not in SUPPORTED_ALGOS:
        raise ValueError(f"Algorithme non supporté: {algo}. Algorithmes supportés: {list(SUPPORTED_ALGOS.keys())}")
    return SUPPORTED_ALGOS[algo_clean]()


def hash_bytes(data: bytes, algo: str = "sha256") -> str:
    """Calcule l'empreinte hexadécimale de données brutes."""
    hasher = get_hasher(algo)
    hasher.update(data)
    return hasher.hexdigest()


def hash_file(filepath: str, algo: str = "sha256", chunk_size: int = 65536) -> str:
    """Calcule l'empreinte hexadécimale d'un fichier par lecture par blocs."""
    hasher = get_hasher(algo)
    with open(filepath, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()


def hash_all_algos(filepath: str) -> Dict[str, str]:
    """Calcule simultanément MD5, SHA-1, SHA-256 et SHA3-256 d'un fichier."""
    hashers = {
        "md5": hashlib.md5(),
        "sha1": hashlib.sha1(),
        "sha256": hashlib.sha256(),
        "sha3_256": hashlib.sha3_256(),
    }
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            for h in hashers.values():
                h.update(chunk)
    return {name: h.hexdigest() for name, h in hashers.items()}


def verify_hash(filepath: str, expected_hash: str, algo: str = "sha256") -> bool:
    """Vérifie si l'empreinte d'un fichier correspond à celle attendue (temps constant)."""
    computed = hash_file(filepath, algo)
    return hmac.compare_digest(computed.lower(), expected_hash.strip().lower())


# 2. Effet Avalanche

def hamming_distance_bits(b1: bytes, b2: bytes) -> int:
    """Calcule la distance de Hamming (nombre de bits différents) entre deux séquences d'octets."""
    if len(b1) != len(b2):
        raise ValueError("Les deux séquences d'octets doivent avoir la même longueur.")
    diff = 0
    for byte1, byte2 in zip(b1, b2):
        diff += bin(byte1 ^ byte2).count("1")
    return diff


def test_avalanche_effect(message: bytes, algo: str = "sha256", bit_to_flip: int = 0) -> Tuple[int, int, float, str, str]:
    """
    Modifie un seul bit dans le message et mesure le nombre de bits changés dans le condensat.
    Retourne (bits_modifies, total_bits, pourcentage, hash_original, hash_modifie).
    """
    if len(message) == 0:
        message = b"Securite et Cryptographie 2026"

    # Calcul du haché original
    h_orig = get_hasher(algo)
    h_orig.update(message)
    digest_orig = h_orig.digest()

    # Inversion du bit spécifié
    msg_mutated = bytearray(message)
    byte_idx = (bit_to_flip // 8) % len(msg_mutated)
    bit_idx = bit_to_flip % 8
    msg_mutated[byte_idx] ^= (1 << bit_idx)

    # Calcul du haché muté
    h_mutated = get_hasher(algo)
    h_mutated.update(bytes(msg_mutated))
    digest_mutated = h_mutated.digest()

    diff_bits = hamming_distance_bits(digest_orig, digest_mutated)
    total_bits = len(digest_orig) * 8
    percentage = (diff_bits / total_bits) * 100.0

    return diff_bits, total_bits, percentage, digest_orig.hex(), digest_mutated.hex()


# 3. HMAC from scratch (RFC 2104)

def custom_hmac(key: bytes, message: bytes, algo: str = "sha256") -> bytes:
    """
    Implémentation exacte de HMAC selon la RFC 2104 :
    HMAC(K, M) = H((K' ^ opad) || H((K' ^ ipad) || M))
    """
    algo_clean = algo.lower().replace("-", "_")
    if algo_clean not in SUPPORTED_ALGOS:
        raise ValueError(f"Algorithme {algo} non supporté.")

    block_size = BLOCK_SIZES.get(algo_clean, 64)

    # 1. Ajustement de la clé K'
    if len(key) > block_size:
        # Si la clé est plus longue que la taille de bloc, on la hache
        hasher_key = SUPPORTED_ALGOS[algo_clean]()
        hasher_key.update(key)
        key_prime = hasher_key.digest()
    else:
        key_prime = key

    # Compléter avec des zéros à droite jusqu'à la taille de bloc
    key_padded = key_prime + b"\x00" * (block_size - len(key_prime))

    # 2. Définition des masques ipad (0x36) et opad (0x5C)
    ipad = bytes((b ^ 0x36) for b in key_padded)
    opad = bytes((b ^ 0x5C) for b in key_padded)

    # 3. Calcul intérieur : H(ipad || message)
    inner_hasher = SUPPORTED_ALGOS[algo_clean]()
    inner_hasher.update(ipad)
    inner_hasher.update(message)
    inner_digest = inner_hasher.digest()

    # 4. Calcul extérieur : H(opad || inner_digest)
    outer_hasher = SUPPORTED_ALGOS[algo_clean]()
    outer_hasher.update(opad)
    outer_hasher.update(inner_digest)
    return outer_hasher.digest()


def verify_hmac(key: bytes, message: bytes, expected_mac: bytes, algo: str = "sha256") -> bool:
    """Vérifie un code HMAC en temps constant."""
    computed_mac = custom_hmac(key, message, algo)
    return hmac.compare_digest(computed_mac, expected_mac)


# 4. Hachage sécurisé de mots de passe

def hash_password(password: str, salt: Optional[bytes] = None, iterations: int = 100_000, pepper: bytes = b"") -> Dict[str, Any]:
    """
    Hache un mot de passe en utilisant PBKDF2-HMAC-SHA256 avec sel cryptographique et poivre optionnel.
    """
    if salt is None:
        salt = os.urandom(16)

    # Application du poivre (secret serveur) et du sel
    salted_pwd = password.encode("utf-8") + pepper
    key = hashlib.pbkdf2_hmac("sha256", salted_pwd, salt, iterations, dklen=32)

    return {
        "algo": "pbkdf2_hmac_sha256",
        "iterations": iterations,
        "salt_hex": salt.hex(),
        "hash_hex": key.hex(),
    }


def verify_password(password: str, stored_hash_hex: str, salt_hex: str, iterations: int = 100_000, pepper: bytes = b"") -> bool:
    """Vérifie un mot de passe contre son haché stocké (temps constant)."""
    salt = bytes.fromhex(salt_hex)
    salted_pwd = password.encode("utf-8") + pepper
    computed_key = hashlib.pbkdf2_hmac("sha256", salted_pwd, salt, iterations, dklen=32)
    return hmac.compare_digest(computed_key.hex(), stored_hash_hex.lower())


def benchmark_password_hashing(password: str = "MotDePasseSecret123!", iteration_levels: Optional[List[int]] = None) -> List[Tuple[int, float]]:
    """Mesure le temps d'exécution en fonction du nombre d'itérations de hachage."""
    if iteration_levels is None:
        iteration_levels = [1_000, 10_000, 50_000, 100_000, 200_000]
    
    salt = os.urandom(16)
    results = []
    for iters in iteration_levels:
        t0 = time.perf_counter()
        hash_password(password, salt=salt, iterations=iters)
        elapsed = time.perf_counter() - t0
        results.append((iters, elapsed))
    return results


# 5. Arbre de Merkle (Merkle Tree)

class MerkleTree:
    """
    Implémentation d'un Arbre de Merkle binaire pour la vérification d'intégrité de blocs.
    Pour éviter les attaques par extension ou seconde préimage, on préfixe les feuilles par 0x00
    et les nœuds internes par 0x01 (standard RFC 6962).
    """

    def __init__(self, data_blocks: List[bytes]):
        if not data_blocks:
            raise ValueError("L'arbre de Merkle nécessite au moins un bloc de données.")
        self.data_blocks = data_blocks
        self.levels: List[List[bytes]] = []
        self._build_tree()

    @staticmethod
    def _hash_leaf(data: bytes) -> bytes:
        h = hashlib.sha256()
        h.update(b"\x00" + data)
        return h.digest()

    @staticmethod
    def _hash_nodes(left: bytes, right: bytes) -> bytes:
        h = hashlib.sha256()
        h.update(b"\x01" + left + right)
        return h.digest()

    def _build_tree(self):
        """Construit les niveaux de l'arbre jusqu'à la racine."""
        current_level = [self._hash_leaf(block) for block in self.data_blocks]
        self.levels = [current_level]

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    # Si nombre impair d'éléments, on duplique le dernier
                    right = left
                next_level.append(self._hash_nodes(left, right))
            self.levels.append(next_level)
            current_level = next_level

    def get_root(self) -> bytes:
        """Retourne la racine de Merkle (32 octets)."""
        return self.levels[-1][0]

    def get_root_hex(self) -> str:
        """Retourne la racine de Merkle sous forme hexadécimale."""
        return self.get_root().hex()

    def get_proof(self, index: int) -> List[Tuple[str, bytes]]:
        """
        Produit le chemin d'authentification (preuve de Merkle) pour le bloc d'indice donné.
        Chaque élément de la preuve est un tuple ('left' | 'right', sibling_hash).
        """
        if index < 0 or index >= len(self.data_blocks):
            raise IndexError("Index de bloc hors limites.")

        proof = []
        curr_idx = index
        for level in self.levels[:-1]:
            is_odd = (curr_idx % 2 == 1)
            if is_odd:
                sibling_idx = curr_idx - 1
                proof.append(("left", level[sibling_idx]))
            else:
                if curr_idx + 1 < len(level):
                    sibling_idx = curr_idx + 1
                    proof.append(("right", level[sibling_idx]))
                else:
                    # Dernier nœud impair dupliqué avec lui-même
                    proof.append(("right", level[curr_idx]))
            curr_idx //= 2
        return proof

    @classmethod
    def verify_proof(cls, leaf_data: bytes, proof: List[Tuple[str, bytes]], expected_root: bytes) -> bool:
        """
        Vérifie qu'une feuille appartient à l'arbre de Merkle avec la preuve fournie.
        """
        current_hash = cls._hash_leaf(leaf_data)
        for direction, sibling_hash in proof:
            if direction == "left":
                current_hash = cls._hash_nodes(sibling_hash, current_hash)
            elif direction == "right":
                current_hash = cls._hash_nodes(current_hash, sibling_hash)
            else:
                return False
        return hmac.compare_digest(current_hash, expected_root)


# 6. Interface en Ligne de Commande (CLI)

def main():
    parser = argparse.ArgumentParser(description="CryptoVault - Module 1 : Hachage et intégrité")
    subparsers = parser.add_subparsers(dest="command", help="Commandes disponibles")

    # Commande hash
    hash_parser = subparsers.add_parser("hash", help="Calcule les empreintes d'un fichier")
    hash_parser.add_argument("file", help="Chemin du fichier")
    hash_parser.add_argument("--algo", default=None, help="Algorithme spécifique (md5, sha1, sha256, sha3_256)")

    # Commande verify
    verify_parser = subparsers.add_parser("verify", help="Vérifie l'empreinte d'un fichier")
    verify_parser.add_argument("file", help="Chemin du fichier")
    verify_parser.add_argument("expected", help="Empreinte attendue (hex)")
    verify_parser.add_argument("--algo", default="sha256", help="Algorithme (défaut: sha256)")

    # Commande avalanche
    avalanche_parser = subparsers.add_parser("avalanche", help="Démontre l'effet avalanche")
    avalanche_parser.add_argument("text", nargs="?", default="Cryptographie Moderne 2026", help="Texte source")

    # Commande merkle
    merkle_parser = subparsers.add_parser("merkle", help="Génère un arbre de Merkle pour un fichier")
    merkle_parser.add_argument("file", help="Chemin du fichier")
    merkle_parser.add_argument("--block-size", type=int, default=1024, help="Taille des blocs en octets (défaut: 1024)")

    args = parser.parse_args()

    if args.command == "hash":
        if not os.path.exists(args.file):
            print(f"Erreur : fichier non trouvé '{args.file}'", file=sys.stderr)
            sys.exit(1)
        if args.algo:
            h = hash_file(args.file, args.algo)
            print(f"{args.algo.upper()}: {h}")
        else:
            all_hashes = hash_all_algos(args.file)
            print(f"Fichier : {args.file}")
            for name, val in all_hashes.items():
                print(f"  {name.upper():<10}: {val}")

    elif args.command == "verify":
        if not os.path.exists(args.file):
            print(f"Erreur : fichier non trouvé '{args.file}'", file=sys.stderr)
            sys.exit(1)
        ok = verify_hash(args.file, args.expected, args.algo)
        if ok:
            print(f" SUCCÈS : L'empreinte {args.algo.upper()} correspond parfaitement.")
        else:
            print(f" ÉCHEC : L'empreinte ne correspond PAS !", file=sys.stderr)
            sys.exit(1)

    elif args.command == "avalanche":
        diff, total, pct, h1, h2 = test_avalanche_effect(args.text.encode("utf-8"))
        print(f"Texte : '{args.text}'")
        print(f"Hash 1 (original) : {h1}")
        print(f"Hash 2 (1 bit inversé) : {h2}")
        print(f"Effet avalanche : {diff}/{total} bits inversés ({pct:.2f}%) [Attendu ~50%]")

    elif args.command == "merkle":
        if not os.path.exists(args.file):
            print(f"Erreur : fichier non trouvé '{args.file}'", file=sys.stderr)
            sys.exit(1)
        blocks = []
        with open(args.file, "rb") as f:
            while chunk := f.read(args.block_size):
                blocks.append(chunk)
        if not blocks:
            blocks = [b""]
        tree = MerkleTree(blocks)
        print(f"Arbre de Merkle pour {args.file} ({len(blocks)} blocs de {args.block_size} octets) :")
        print(f"  Merkle Root: {tree.get_root_hex()}")
        # Démonstration preuve bloc 0
        proof = tree.get_proof(0)
        valid = MerkleTree.verify_proof(blocks[0], proof, tree.get_root())
        print(f"  Vérification de preuve pour bloc 0: {'VALIDE ' if valid else 'INVALIDE '}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
