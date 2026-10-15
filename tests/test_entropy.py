"""Entropy and randomness measurement."""

from __future__ import annotations

import unittest

from revkit import entropy
from revkit.io import Range

from helpers import build_packed_blob


class ShannonTests(unittest.TestCase):
    def test_constant_data_has_zero_entropy(self):
        self.assertAlmostEqual(entropy.shannon(b"\x00" * 1000), 0.0)

    def test_two_values_half_entropy(self):
        # Two symbols in equal proportion is 1 bit per symbol.
        data = b"\x00\x01" * 512
        self.assertAlmostEqual(entropy.shannon(data), 1.0, places=4)

    def test_flat_distribution_near_eight(self):
        data = bytes(range(256)) * 16
        self.assertAlmostEqual(entropy.shannon(data), 8.0, places=2)

    def test_empty_is_zero(self):
        self.assertEqual(entropy.shannon(b""), 0.0)

    def test_order_does_not_matter(self):
        a = entropy.shannon(b"aaaabbbbccccdddd")
        b = entropy.shannon(b"ddddccccbbbbaaaa")
        self.assertAlmostEqual(a, b)


class RandomnessTests(unittest.TestCase):
    def test_chi_square_of_perfectly_uniform_data_is_near_zero(self):
        # Exactly equal counts is too regular to be random, so the statistic
        # collapses. Real random data lands around 255.
        data = bytes(range(256)) * 8
        self.assertLess(entropy.chi_square(data), 5)

    def test_chi_square_of_random_data_is_around_255(self):
        import random

        rng = random.Random(1234)
        data = rng.randbytes(20000)
        self.assertLess(abs(entropy.chi_square(data) - 255), 40)

    def test_chi_square_of_constant_data_is_huge(self):
        self.assertGreater(entropy.chi_square(b"\x00" * 4096), 1_000_000)

    def test_monte_carlo_of_random_data_is_pi(self):
        import random

        rng = random.Random(99)
        pi = entropy.monte_carlo_pi(rng.randbytes(60000))
        self.assertLess(abs(pi - 3.14159), 0.1)

    def test_monte_carlo_of_constant_data_is_far_from_pi(self):
        # Every point lands inside the circle, so the estimate saturates at 4.0.
        self.assertGreater(entropy.monte_carlo_pi(b"\x00" * 4096), 3.5)


class ProfileTests(unittest.TestCase):
    def test_hot_blocks_merge_adjacent(self):
        data = b"\x00" * 1024 + bytes(range(256)) * 16
        profile = entropy.entropy_profile(data, block_size=256)
        hot = entropy.hot_blocks(profile, threshold=7.5)
        self.assertEqual(len(hot), 1)
        self.assertEqual(hot[0].start, 1024)

    def test_hot_blocks_split_when_separated(self):
        data = bytes(range(256)) * 4 + b"\x00" * 1024 + bytes(range(256)) * 4
        profile = entropy.entropy_profile(data, block_size=256)
        hot = entropy.hot_blocks(profile, threshold=7.5)
        self.assertEqual(len(hot), 2)

    def test_high_entropy_regions_ignores_tiny_blocks(self):
        regions = entropy.high_entropy_regions(b"\x00" * 64 + bytes(range(256)) * 4)
        self.assertTrue(all(len(r) >= 64 for r in regions))


class PackedDetectionTests(unittest.TestCase):
    def test_plain_text_is_not_packed(self):
        self.assertFalse(entropy.looks_packed(b"the quick brown fox " * 200))

    def test_random_data_is_packed(self):
        import random

        rng = random.Random(7)
        self.assertTrue(entropy.looks_packed(rng.randbytes(8192)))

    def test_compressed_payload_has_higher_entropy_than_its_source(self):
        payload = b"secret configuration data " * 50
        self.assertGreater(entropy.shannon(build_packed_blob(payload)), entropy.shannon(payload))

    def test_stats_report_all_keys(self):
        stats = entropy.entropy_stats(b"hello world " * 50)
        for key in ("entropy", "chi_square", "monte_carlo_pi", "size"):
            self.assertIn(key, stats)

    def test_range_len_and_overlap(self):
        a = Range(0, 10)
        b = Range(5, 15)
        c = Range(20, 30)
        self.assertEqual(len(a), 10)
        self.assertTrue(a.overlaps(b))
        self.assertFalse(a.overlaps(c))

    def test_inverted_range_rejected(self):
        with self.assertRaises(ValueError):
            Range(10, 5)


if __name__ == "__main__":
    unittest.main()
