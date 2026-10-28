"""
Tests unitaires pour le Module 8 (Générateurs pseudo-aléatoires et CSPRNG).
Valide le LCG du cours, l'inversion d'état de Mersenne Twister (untemper),
le clonage MT19937, HMAC_DRBG et les tests statistiques NIST.
"""

import unittest
import os
import sys
import secrets

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cryptolib.prng import (
    LCG,
    MersenneTwister19937,
    temper,
    untemper,
    clone_mt19937,
    HMAC_DRBG,
    monobit_frequency_test,
    runs_test,
    chi2_byte_uniformity_test,
)


class TestPRNGModule(unittest.TestCase):

    # 1. Exercice 1 du Chapitre 8 du cours (LCG)
    
    def test_lcg_course_exercise(self):
        # Exercice 1 : X_{n+1} = (5*X_n + 3) mod 16 avec X_0 = 2
        lcg = LCG(a=5, c=3, m=16, seed=2)
        # Sorties calculées dans le corrigé du cours :
        # X1 = 13, X2 = 4, X3 = 7, X4 = 6, X5 = 1
        expected = [13, 4, 7, 6, 1]
        actual = [lcg.next() for _ in range(5)]
        self.assertEqual(actual, expected)

    # 2. Inversion de la fonction de masquage (untemper)

    def test_untemper_bijection(self):
        # Vérification sur 1000 entiers 32 bits aléatoires
        for _ in range(1000):
            orig = secrets.randbits(32)
            tempered = temper(orig)
            recovered = untemper(tempered)
            self.assertEqual(recovered, orig)

    # 3. Clonage de Mersenne Twister (Attaque de l'état interne)

    def test_mt19937_state_cloning(self):
        # Générateur cible avec une graine quelconque
        target = MersenneTwister19937(seed=123456789)

        # L'attaquant intercepte 624 sorties consécutives
        observed_outputs = [target.extract_number() for _ in range(624)]

        # L'attaquant clone le générateur
        clone = clone_mt19937(observed_outputs)

        # Vérification : les 200 sorties suivantes du clone doivent être
        # EXACTEMENT identiques à celles du générateur cible avec 100% de précision !
        for i in range(200):
            expected = target.extract_number()
            predicted = clone.extract_number()
            self.assertEqual(predicted, expected, f"Prédiction échouée à l'itération {i}")

    # 4. CSPRNG HMAC_DRBG (NIST SP 800-90A)

    def test_hmac_drbg_generation(self):
        drbg = HMAC_DRBG(entropy_source=b"EntropieInitialeDeHauteQualite32B", personalization=b"Client-1")
        chunk1 = drbg.generate(32)
        chunk2 = drbg.generate(32)

        self.assertEqual(len(chunk1), 32)
        self.assertEqual(len(chunk2), 32)
        self.assertNotEqual(chunk1, chunk2)

    # 5. Tests Statistiques NIST

    def test_statistical_tests_on_csprng(self):
        drbg = HMAC_DRBG(entropy_source=b"DeterministicSampleEntropyTest32Bytes!")
        sample = drbg.generate(2048)  # 2 Ko de données

        # Test Monobit
        pass_mono, prop, p_val_mono = monobit_frequency_test(sample)
        self.assertTrue(pass_mono, f"Échec monobit : prop={prop}, p={p_val_mono}")
        self.assertAlmostEqual(prop, 0.5, delta=0.05)

        # Test Runs
        pass_runs, pi, p_val_runs = runs_test(sample)
        self.assertTrue(pass_runs, f"Échec runs : pi={pi}, p={p_val_runs}")

        # Test Chi-deux
        pass_chi2, chi2_val, p_val_chi2 = chi2_byte_uniformity_test(sample)
        self.assertTrue(pass_chi2, f"Échec chi2 : stat={chi2_val}")


if __name__ == "__main__":
    unittest.main()
