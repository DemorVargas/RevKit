"""Deobfuscation: XOR, RC4, compression, base64."""

from __future__ import annotations

import base64
import unittest
import zlib

from revkit import crypto

from helpers import build_packed_blob, build_xor_blob


class XorTests(unittest.TestCase):
    def test_single_byte_roundtrip(self):
        plain = b"the quick brown fox jumps over the lazy dog"
        cipher = crypto.xor_single(plain, 0x42)
        self.assertNotEqual(cipher, plain)
        self.assertEqual(crypto.xor_single(cipher, 0x42), plain)

    def test_repeating_key_roundtrip(self):
        plain = b"a much longer piece of text so the key repeats several times"
        key = b"KEY"
        self.assertEqual(crypto.xor_repeat(crypto.xor_repeat(plain, key), key), plain)

    def test_repeating_key_rejects_empty_key(self):
        with self.assertRaises(ValueError):
            crypto.xor_repeat(b"data", b"")

    def test_brute_finds_single_byte_key(self):
        plain = b"http://malicious.example.invalid/payload.exe"
        for key in (0x00, 0x13, 0x41, 0x7F, 0xFF):
            hits = crypto.xor_brute(build_xor_blob(plain, key), limit=1)
            self.assertEqual(hits[0].key, f"0x{key:02x}", f"failed for key {key:#x}")
            self.assertEqual(hits[0].plaintext, plain)

    def test_brute_returns_nothing_for_random_data(self):
        import random

        rng = random.Random(3)
        hits = crypto.xor_brute(rng.randbytes(512))
        self.assertEqual(hits, [])

    def test_brute_finds_a_string_buried_in_padding(self):
        # The case the brute force actually exists for: a string hidden in a
        # binary with NUL padding around it. Scoring the whole blob let the
        # padding outvote the string, so this found the padding's key instead.
        plain = b"http://evil.example/c2.php\x00"
        blob = b"\x00" * 64 + crypto.xor_single(plain, 0x5A)
        hits = crypto.xor_brute(blob, limit=1)
        self.assertEqual(hits[0].key, "0x5a")
        self.assertIn(b"http://evil.example/c2.php", hits[0].plaintext)

    def test_a_run_of_one_byte_does_not_outscore_real_text(self):
        # A run of identical bytes scored higher than an English sentence, which
        # is how padding used to win. Strip it and it scores nothing at all.
        text = b"the quick brown fox jumps over the lazy dog and keeps running"
        self.assertLess(crypto.score_candidate(b"E" * 64), crypto.score_candidate(text))

    def test_decode_all_includes_the_xor_brute(self):
        # decode_all used to skip xor-brute, so `revkit decode` never ran the one
        # decoder the README leads with.
        plain = b"http://malicious.example.invalid/payload.exe"
        blob = b"\x00" * 32 + crypto.xor_single(plain, 0x37)
        methods = [h.method for h in crypto.decode_all(blob)]
        self.assertIn("xor-single", methods)

    def test_known_plaintext_recovers_key(self):
        cipher = build_xor_blob(b"GET /secret HTTP/1.1\r\n", 0x5A)
        hit = crypto.xor_known_plaintext(cipher, b"GET ")
        self.assertIsNotNone(hit)
        # The recovered key is one byte per known plaintext byte, so a 4-byte
        # sample yields a 4-byte key that repeats.
        self.assertEqual(hit.key, "5a5a5a5a")
        self.assertEqual(hit.plaintext, b"GET /secret HTTP/1.1\r\n")
        self.assertIn("4 bytes", hit.note)

    def test_known_plaintext_out_of_range(self):
        self.assertIsNone(crypto.xor_known_plaintext(b"abc", b"toolong"))

    def test_repeat_key_length_gives_up_on_short_input(self):
        self.assertIsNone(crypto.repeat_key_length(b"short"))

    def test_repeat_key_length_returns_a_plausible_answer(self):
        # It is a heuristic, so the contract is only that it returns a length in
        # range, not that the length is correct.
        import random

        rng = random.Random(5)
        alphabet = b"abcdefghijklmnopqrstuvwxyz    "
        cipher = crypto.xor_repeat(bytes(rng.choice(alphabet) for _ in range(2000)), b"abcd")
        answer = crypto.repeat_key_length(cipher, max_len=16)
        self.assertIsNotNone(answer)
        self.assertGreaterEqual(answer, 1)
        self.assertLessEqual(answer, 16)

    def test_candidates_are_sorted_best_first(self):
        import random

        rng = random.Random(5)
        cipher = crypto.xor_repeat(rng.randbytes(2000), b"key")
        candidates = crypto.key_length_candidates(cipher, max_len=12)
        self.assertEqual(len(candidates), 11)
        distances = [d for _, d in candidates]
        self.assertEqual(distances, sorted(distances))

    def test_xor_break_key_recovers_the_key(self):
        import random

        rng = random.Random(31)
        alphabet = b"abcdefghijklmnopqrstuvwxyz    "
        plain = bytes(rng.choice(alphabet) for _ in range(6000))
        for key in (b"abcd", b"secret", b"k3y"):
            cipher = crypto.xor_repeat(plain, key)
            self.assertEqual(crypto.xor_break_key(cipher, len(key)), key)

    def test_xor_break_key_rejects_bad_length(self):
        self.assertIsNone(crypto.xor_break_key(b"abcdef", 0))
        self.assertIsNone(crypto.xor_break_key(b"abcdef", 100))

    def test_xor_break_key_roundtrips_through_decrypt(self):
        import random

        rng = random.Random(8)
        plain = b"the configuration block is hidden here and should come back whole " * 60
        cipher = crypto.xor_repeat(plain, b"hunter2")
        key = crypto.xor_break_key(cipher, 7)
        self.assertEqual(crypto.xor_repeat(cipher, key), plain)


class Rc4Tests(unittest.TestCase):
    def test_roundtrip(self):
        key = b"secret key"
        data = b"some data that needs obscuring " * 10
        self.assertEqual(crypto.rc4(crypto.rc4(data, key), key), data)

    def test_different_keys_give_different_output(self):
        data = b"hello world, this is a test of rc4"
        self.assertNotEqual(crypto.rc4(data, b"key1"), crypto.rc4(data, b"key2"))

    def test_empty_key_rejected(self):
        with self.assertRaises(ValueError):
            crypto.rc4(b"data", b"")

    def test_matches_known_vector(self):
        # RFC 6229 test vector: key "Key", plaintext "Plaintext".
        self.assertEqual(crypto.rc4(b"Plaintext", b"Key").hex(), "bbf316e8d940af0ad3")


class CompressionTests(unittest.TestCase):
    def test_zlib_roundtrip(self):
        data = b"payload " * 200
        self.assertEqual(crypto.try_zlib(zlib.compress(data)), data)

    def test_zlib_accepts_raw_deflate(self):
        data = b"raw deflate without the zlib header " * 20
        compressor = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -zlib.MAX_WBITS)
        raw = compressor.compress(data) + compressor.flush()
        self.assertEqual(crypto.try_zlib(raw), data)

    def test_zlib_returns_none_on_garbage(self):
        self.assertIsNone(crypto.try_zlib(b"not compressed data at all"))

    def test_gzip_roundtrip(self):
        import gzip

        data = b"gzipped payload " * 100
        self.assertEqual(crypto.try_gzip(gzip.compress(data)), data)

    def test_bzip2_roundtrip(self):
        import bz2

        data = b"bzipped payload " * 100
        self.assertEqual(crypto.try_bzip2(bz2.compress(data)), data)

    def test_lzma_roundtrip(self):
        import lzma

        data = b"lzma payload " * 100
        self.assertEqual(crypto.try_lzma(lzma.compress(data)), data)

    def test_try_zlib_handles_empty(self):
        self.assertIsNone(crypto.try_zlib(b""))


class Base64Tests(unittest.TestCase):
    def test_decodes_standard(self):
        self.assertEqual(crypto.b64_decode(b"aGVsbG8="), b"hello")

    def test_tolerates_missing_padding(self):
        self.assertEqual(crypto.b64_decode(b"aGVsbG8"), b"hello")

    def test_tolerates_whitespace(self):
        self.assertEqual(crypto.b64_decode(b"aGVs bG8=\n"), b"hello")

    def test_rejects_garbage(self):
        self.assertIsNone(crypto.b64_decode(b"!!!not base64!!!"))

    def test_hash_file_gives_three_digests(self):
        hashes = crypto.hash_file(b"abc")
        self.assertEqual(hashes["md5"], "900150983cd24fb0d6963f7d28e17f72")
        self.assertEqual(hashes["sha1"], "a9993e364706816aba3e25717850c26c9cd0d89d")
        self.assertEqual(len(hashes["sha256"]), 64)


class ChecksumTests(unittest.TestCase):
    def test_crc32_matches_zlib(self):
        self.assertEqual(crypto.crc32(b"hello world"), zlib.crc32(b"hello world") & 0xFFFFFFFF)

    def test_adler32_matches_zlib(self):
        self.assertEqual(crypto.adler32(b"hello world"), zlib.adler32(b"hello world") & 0xFFFFFFFF)

    def test_fnv1a_known_value(self):
        # FNV-1a 32 of the empty string is the offset basis.
        self.assertEqual(crypto.fnv1a(b""), 0x811C9DC5)
        self.assertEqual(crypto.fnv1a(b"a"), 0xE40C292C)


class DecodeAllTests(unittest.TestCase):
    def test_packed_payload_is_found(self):
        hits = crypto.decode_all(build_packed_blob(b"hidden config " * 50))
        self.assertTrue(any(h.method == "zlib" for h in hits))

    def test_base64_is_found(self):
        encoded = base64.b64encode(b"base64 hidden payload " * 20)
        hits = crypto.decode_all(encoded, ["base64"])
        self.assertEqual(hits[0].plaintext, b"base64 hidden payload " * 20)

    def test_scorer_separates_text_from_random(self):
        text = b"the quick brown fox jumps over the lazy dog and keeps on running"
        self.assertGreater(crypto.score_english(text), 0.3)
        import random

        rng = random.Random(3)
        self.assertEqual(crypto.score_english(rng.randbytes(512)), 0.0)

    def test_english_bits_per_char_is_meaningful(self):
        text = crypto.english_bits_per_char(b"the quick brown fox jumps over the lazy dog")
        random_bits = crypto.english_bits_per_char(bytes(range(256)) * 16)
        self.assertLess(text, 6.0)
        self.assertGreater(random_bits, 7.0)

    def test_unknown_method_is_ignored(self):
        self.assertEqual(crypto.decode_all(b"data", ["nope"]), [])

    def test_results_sorted_by_score(self):
        hits = crypto.decode_all(build_packed_blob(b"x" * 500))
        scores = [h.score for h in hits]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_empty_input_yields_no_hits(self):
        self.assertEqual(crypto.decode_all(b""), [])


if __name__ == "__main__":
    unittest.main()
