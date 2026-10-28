"""
Tests unitaires pour le Module 2 (Arithmétique modulaire et nombres premiers).
Validation basée sur les exercices et formules du Chapitre 2 du cours.
"""

import unittest
import os
import sys
import secrets

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cryptolib.numtheory import (
    gcd,
    extended_gcd,
    mod_inverse,
    exp_mod,
    chinese_remainder_theorem,
    fermat_primality_test,
    miller_rabin_test,
    generate_prime,
    euler_phi,
)


class TestNumTheoryModule(unittest.TestCase):

    # 1. PGCD et Identité de Bézout

    def test_gcd_and_extended_gcd(self):
        # Exercice 1 du Chapitre 2 : pgcd(1071, 462) = 21
        a, b = 1071, 462
        g = gcd(a, b)
        self.assertEqual(g, 21)

        g_ext, u, v = extended_gcd(a, b)
        self.assertEqual(g_ext, 21)
        self.assertEqual(a * u + b * v, g_ext)
        # Vérification des coefficients Bézout du cours : 1071*(-3) + 462*7 = 21
        self.assertEqual(1071 * (-3) + 462 * 7, 21)

    def test_extended_gcd_edge_cases(self):
        # Nombres négatifs et cas limites
        g, u, v = extended_gcd(-12, 18)
        self.assertEqual(g, 6)
        self.assertEqual(-12 * u + 18 * v, 6)

        g, u, v = extended_gcd(17, 0)
        self.assertEqual(g, 17)
        self.assertEqual(17 * u + 0 * v, 17)

    # 2. Inversion modulaire

    def test_mod_inverse(self):
        # Exercice 2 du Chapitre 2 : 17^-1 mod 3120 = 2753
        inv = mod_inverse(17, 3120)
        self.assertEqual(inv, 2753)
        self.assertEqual((17 * inv) % 3120, 1)

        # Élément non inversible
        with self.assertRaises(ValueError):
            mod_inverse(6, 9)

    # 3. Exponentiation modulaire (Square-and-Multiply)

    def test_exp_mod_course_exercises(self):
        # Exercice 5 : 7^2026 mod 13 = 4
        self.assertEqual(exp_mod(7, 2026, 13), 4)

        # Exercice 6 : 5^23 mod 11 = 4
        self.assertEqual(exp_mod(5, 23, 11), 4)

    def test_exp_mod_vs_native_pow(self):
        # Comparaison stricte avec pow() de Python sur des entiers de grande taille
        for _ in range(20):
            base = secrets.randbits(256)
            exp = secrets.randbits(256)
            mod = secrets.randbits(256) | 1  # impair et > 0
            self.assertEqual(exp_mod(base, exp, mod), pow(base, exp, mod))

    # 4. Théorème des Restes Chinois (CRT)

    def test_chinese_remainder_theorem(self):
        # Exercice 4 du Chapitre 2 :
        # x ≡ 1 (mod 4)
        # x ≡ 2 (mod 5)
        # x ≡ 3 (mod 7)
        # Solution attendue : x ≡ 17 (mod 140)
        remainders = [1, 2, 3]
        moduli = [4, 5, 7]
        x = chinese_remainder_theorem(remainders, moduli)
        self.assertEqual(x, 17)
        self.assertEqual(x % 4, 1)
        self.assertEqual(x % 5, 2)
        self.assertEqual(x % 7, 3)

    def test_crt_invalid_moduli(self):
        # Modules non premiers entre eux (4 et 6 ne sont pas premiers entre eux)
        with self.assertRaises(ValueError):
            chinese_remainder_theorem([1, 2], [4, 6])

    # 5. Tests de primalité et Nombres de Carmichael

    def test_carmichael_numbers_rejected_by_miller_rabin(self):
        # Nombres de Carmichael célèbres : 561 (3*11*17), 1105 (5*13*17), 1729 (7*13*19)
        carmichael_numbers = [561, 1105, 1729]
        for c in carmichael_numbers:
            # Miller-Rabin doit catégoriquement les déclarer composés (False)
            self.assertFalse(miller_rabin_test(c, rounds=20), f"Échec : {c} aurait dû être rejeté par Miller-Rabin !")

    def test_known_primes_accepted(self):
        primes = [2, 3, 5, 7, 13, 101, 1009, 104729]
        for p in primes:
            self.assertTrue(miller_rabin_test(p, rounds=20))

        composites = [4, 9, 15, 25, 91, 100, 1000]
        for c in composites:
            self.assertFalse(miller_rabin_test(c, rounds=20))

    # 6. Génération de nombres premiers

    def test_generate_prime(self):
        for bits in [64, 128, 256]:
            p, tries = generate_prime(bits, rounds=25)
            self.assertTrue(p.bit_length() == bits)
            self.assertTrue(p % 2 == 1)
            self.assertTrue(miller_rabin_test(p, rounds=30))
            self.assertGreaterEqual(tries, 1)

    # 7. Indicatrice d'Euler

    def test_euler_phi(self):
        # phi(36) = 12
        # phi(77) = 60
        # phi(101) = 100
        self.assertEqual(euler_phi(36), 12)
        self.assertEqual(euler_phi(77), 60)
        self.assertEqual(euler_phi(101), 100)

        # Théorème d'Euler : a^phi(n) ≡ 1 mod n pour pgcd(a, n) = 1
        n = 77
        phi_n = euler_phi(n)
        for a in [2, 3, 5, 9, 10]:
            self.assertEqual(exp_mod(a, phi_n, n), 1)


if __name__ == "__main__":
    unittest.main()
