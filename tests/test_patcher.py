"""Byte-level patching."""

from __future__ import annotations

import os
import tempfile
import unittest

from revkit import patcher

import helpers


class ParseArgTests(unittest.TestCase):
    def test_hex_pairs(self):
        self.assertEqual(patcher.parse_bytes_arg("90 90 c3"), b"\x90\x90\xc3")

    def test_hex_with_commas(self):
        self.assertEqual(patcher.parse_bytes_arg("0x90, 0x90, 0xc3"), b"\x90\x90\xc3")

    def test_escaped_hex(self):
        self.assertEqual(patcher.parse_bytes_arg("\\x90\\x90\\xc3"), b"\x90\x90\xc3")

    def test_literal_text(self):
        self.assertEqual(patcher.parse_bytes_arg("hello"), b"hello")

    def test_empty_rejected(self):
        with self.assertRaises(Exception):
            patcher.parse_bytes_arg("")

    def test_bad_escape_rejected(self):
        with self.assertRaises(Exception):
            patcher.parse_bytes_arg("\\xZZ")

    def test_offset_hex(self):
        self.assertEqual(patcher.parse_offset("0x1040"), 0x1040)

    def test_offset_decimal(self):
        self.assertEqual(patcher.parse_offset("4160"), 4160)

    def test_offset_octal(self):
        self.assertEqual(patcher.parse_offset("0o101000"), 0o101000)

    def test_bad_offset_rejected(self):
        with self.assertRaises(Exception):
            patcher.parse_offset("not a number")


class PatchTests(unittest.TestCase):
    def test_patch_writes_at_offset(self):
        data = b"ABCDEFGH"
        patched, result = patcher.apply_patch(data, 2, b"xy")
        self.assertEqual(patched, b"ABxyEFGH")
        self.assertEqual(result.old, b"CD")
        self.assertEqual(result.new, b"xy")

    def test_patch_out_of_range_rejected(self):
        with self.assertRaises(Exception):
            patcher.apply_patch(b"abc", 1, b"toolong")

    def test_negative_offset_rejected(self):
        with self.assertRaises(Exception):
            patcher.apply_patch(b"abc", -1, b"x")

    def test_identical_patch_reports_no_change(self):
        patched, result = patcher.apply_patch(b"abc", 1, b"b")
        self.assertFalse(result.changed)

    def test_in_memory_patch_writes_nothing_to_disk(self):
        patched, result = patcher.apply_patch(b"abc", 0, b"z", path="<memory>")
        self.assertIsNone(result.backup)


class PatchFileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "target.bin")
        with open(self.path, "wb") as fh:
            fh.write(b"ABCDEFGH")

    def test_default_writes_a_new_file(self):
        _, result = patcher.patch_file(self.path, 1, b"zz")
        self.assertEqual(result.path, self.path + ".patched")
        self.assertTrue(os.path.exists(result.path))
        # The original is untouched.
        with open(self.path, "rb") as fh:
            self.assertEqual(fh.read(), b"ABCDEFGH")

    def test_in_place_overwrites_and_backs_up(self):
        _, result = patcher.patch_file(self.path, 1, b"zz", in_place=True)
        self.assertEqual(result.path, self.path)
        self.assertEqual(result.backup, self.path + ".bak")
        with open(self.path, "rb") as fh:
            self.assertEqual(fh.read(), b"AzzDEFGH")
        with open(self.path + ".bak", "rb") as fh:
            self.assertEqual(fh.read(), b"ABCDEFGH")

    def test_no_backup_when_asked(self):
        _, result = patcher.patch_file(self.path, 1, b"zz", in_place=True, backup=False)
        self.assertIsNone(result.backup)
        self.assertFalse(os.path.exists(self.path + ".bak"))


class NopTests(unittest.TestCase):
    def test_nops_a_run(self):
        self.assertEqual(patcher.patch_nops(b"\x74\x05\x90", 0, 2), b"\x90\x90\x90")

    def test_custom_nop_byte(self):
        self.assertEqual(patcher.patch_nops(b"abcdef", 2, 3, nop=0xCC), b"ab\xcc\xcc\xccf")


class FindBytesTests(unittest.TestCase):
    def test_finds_all_offsets(self):
        self.assertEqual(patcher.find_bytes(b"abXYcdXY", b"XY"), [2, 6])

    def test_no_match(self):
        self.assertEqual(patcher.find_bytes(b"abcdef", b"zz"), [])

    def test_overlapping_matches(self):
        self.assertEqual(patcher.find_bytes(b"aaaa", b"aa"), [0, 1, 2])


class ChecksumTests(unittest.TestCase):
    def test_pe_checksum_is_deterministic(self):
        pe = helpers.build_pe()
        self.assertEqual(patcher.pe_checksum(pe), patcher.pe_checksum(pe))

    def test_fixing_the_checksum_does_not_change_it(self):
        pe = helpers.build_pe()
        fixed = patcher.fix_pe_checksum(pe)
        self.assertEqual(patcher.pe_checksum(fixed), patcher.pe_checksum(pe))

    def test_short_data_is_handled(self):
        self.assertEqual(patcher.pe_checksum(b"MZ"), 0)
        self.assertEqual(patcher.fix_pe_checksum(b"MZ"), b"MZ")


class BackupTests(unittest.TestCase):
    def test_backup_refuses_to_clobber(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "f.bin")
            with open(path, "wb") as fh:
                fh.write(b"data")
            with open(path + ".bak", "wb") as fh:
                fh.write(b"existing")
            with self.assertRaises(Exception):
                patcher.write_backup(path, b"data")


if __name__ == "__main__":
    unittest.main()
