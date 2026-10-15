"""String extraction."""

from __future__ import annotations

import unittest

from revkit import strings

from helpers import build_zip_with_file


class AsciiTests(unittest.TestCase):
    def test_extracts_printable_runs(self):
        data = b"\x00\x01hello world\x00\x02\x03"
        hits = strings.extract_ascii(data, min_len=4)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].value, "hello world")
        self.assertEqual(hits[0].offset, 2)

    def test_min_length_filters_short_strings(self):
        data = b"ab\x00abcd\x00"
        self.assertEqual(strings.extract_ascii(data, min_len=4)[0].value, "abcd")

    def test_empty_data(self):
        self.assertEqual(strings.extract_ascii(b""), [])

    def test_offset_is_added(self):
        hits = strings.extract_ascii(b"hello world", min_len=4, offset=0x1000)
        self.assertEqual(hits[0].offset, 0x1000)

    def test_trailing_string_without_nul(self):
        hits = strings.extract_ascii(b"\x00hello", min_len=4)
        self.assertEqual(hits[0].value, "hello")

    def test_control_characters_are_excluded(self):
        data = b"abc\x01defgh"
        self.assertEqual(strings.extract_ascii(data, min_len=4)[0].value, "defgh")


class Utf16Tests(unittest.TestCase):
    def test_extracts_wide_strings(self):
        data = "hello world".encode("utf-16-le") + b"\x00\x00"
        hits = strings.extract_utf16(data, min_len=4)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].value, "hello world")

    def test_ignores_binary_with_high_bytes(self):
        # Random bytes almost always have a nonzero high byte, so requiring the
        # high byte to be zero is what keeps false positives down.
        data = bytes(range(200))
        self.assertEqual(strings.extract_utf16(data, min_len=4), [])

    def test_utf16_le_flag_roundtrip(self):
        data = "abc".encode("utf-16-le")
        hits = strings.extract_utf16(data, min_len=3)
        self.assertEqual(hits[0].encoding, "utf-16le")


class CombinedTests(unittest.TestCase):
    def test_both_encodings_sorted_by_offset(self):
        # The ASCII part is padded to an even length so the wide string starts on
        # a UTF-16 character boundary; otherwise the last ASCII byte pairs up
        # with the following NUL and produces a bogus one-character hit.
        ascii_part = b"first\x00\x00\x00"
        wide_part = "second".encode("utf-16-le")
        hits = strings.extract_strings(ascii_part + wide_part, min_len=4)
        self.assertEqual([h.value for h in hits], ["first", "second"])

    def test_suspicious_patterns_found(self):
        data = b"http://evil.example.invalid/payload.exe\x00"
        found = strings.find_suspicious(data, min_len=4)
        self.assertTrue(any("evil.example" in f.value for f in found))

    def test_suspicious_finds_registry_persistence(self):
        data = b"Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
        found = strings.find_suspicious(data, min_len=4)
        self.assertTrue(len(found) >= 1)


class PatternTests(unittest.TestCase):
    def test_find_pattern_returns_offsets(self):
        data = b"abXYcdXYef"
        self.assertEqual(strings.find_pattern(data, r"XY"), [2, 6])

    def test_find_pattern_supports_precompiled(self):
        import re

        data = b"abXYcdXYef"
        self.assertEqual(strings.find_pattern(data, re.compile(b"XY")), [2, 6])


class Base64HeuristicTests(unittest.TestCase):
    def test_flags_real_base64(self):
        self.assertTrue(strings.looks_like_base64("Q2hpbGwgTW9ycmlzIGlzIGEgZ3JlYXQgZHJ1bW1lcg=="))

    def test_rejects_plain_words(self):
        self.assertFalse(strings.looks_like_base64("hello world"))

    def test_rejects_short_input(self):
        self.assertFalse(strings.looks_like_base64("YWJj"))

    def test_rejects_bad_characters(self):
        self.assertFalse(strings.looks_like_base64("!!!!not base64!!!!"))


class ZipCarvingStringsTests(unittest.TestCase):
    """A ZIP inside a blob should yield its file names as strings."""
    def test_zip_member_name_is_extracted(self):
        data = build_zip_with_file("config.txt", b"hello from inside")
        hits = strings.extract_strings(data, min_len=4)
        self.assertTrue(any("config.txt" in h.value for h in hits))


if __name__ == "__main__":
    unittest.main()
