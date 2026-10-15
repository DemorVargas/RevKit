"""Low level reading helpers."""

from __future__ import annotations

import unittest

from revkit.io import FormatError, Reader, align_up, cstr_at, iter_chunks, rva_to_offset, u16le, u32le


class ReaderTests(unittest.TestCase):
    def test_reads_little_endian(self):
        self.assertEqual(Reader(b"\x01").u8(), 0x01)
        self.assertEqual(Reader(b"\x02\x01").u16(), 0x0102)
        self.assertEqual(Reader(b"\x04\x03\x02\x01").u32(), 0x01020304)
        self.assertEqual(Reader(b"\x08\x07\x06\x05\x04\x03\x02\x01").u64(), 0x0102030405060708)

    def test_sequential_reads_advance_the_cursor(self):
        r = Reader(b"\x01\x02\x03\x04\x05\x06\x07\x08")
        self.assertEqual(r.u16(), 0x0201)
        self.assertEqual(r.u16(), 0x0403)
        self.assertEqual(r.tell(), 4)

    def test_seek_and_tell(self):
        r = Reader(b"abcdef")
        r.seek(3)
        self.assertEqual(r.tell(), 3)
        self.assertEqual(r.read(2), b"de")

    def test_base_adds_to_reported_offset(self):
        r = Reader(b"abcdef", base=0x1000)
        r.seek(2)
        self.assertEqual(r.off(), 0x1002)

    def test_read_past_end_raises(self):
        r = Reader(b"abc")
        with self.assertRaises(FormatError):
            r.read(10)

    def test_negative_read_rejected(self):
        with self.assertRaises(ValueError):
            Reader(b"abc").read(-1)

    def test_cstring_stops_at_nul(self):
        r = Reader(b"hello\x00world")
        self.assertEqual(r.read_cstring(), "hello")
        self.assertEqual(r.read_cstring(), "world")

    def test_cstring_respects_max_len(self):
        r = Reader(b"hello\x00world")
        self.assertEqual(r.read_cstring(max_len=3), "hel")


class HelperTests(unittest.TestCase):
    def test_cstr_at(self):
        self.assertEqual(cstr_at(b"abc\x00def", 0), "abc")
        self.assertEqual(cstr_at(b"abc\x00def", 4), "def")
        self.assertEqual(cstr_at(b"abc", 10), "")

    def test_align_up(self):
        self.assertEqual(align_up(0, 16), 0)
        self.assertEqual(align_up(1, 16), 16)
        self.assertEqual(align_up(16, 16), 16)
        self.assertEqual(align_up(17, 16), 32)
        self.assertEqual(align_up(5, 1), 5)

    def test_iter_chunks(self):
        self.assertEqual(list(iter_chunks(b"abcdef", 2)), [b"ab", b"cd", b"ef"])
        self.assertEqual(list(iter_chunks(b"abcde", 2)), [b"ab", b"cd", b"e"])

    def test_le_helpers(self):
        self.assertEqual(u16le(b"\x34\x12"), 0x1234)
        self.assertEqual(u32le(b"\x78\x56\x34\x12"), 0x12345678)


class RvaTests(unittest.TestCase):
    def test_rva_maps_inside_section(self):
        sections = [{"virtual_address": 0x1000, "virtual_size": 0x100, "pointer_to_raw_data": 0x400, "size_of_raw_data": 0x100}]
        self.assertEqual(rva_to_offset(0x1000, sections), 0x400)
        self.assertEqual(rva_to_offset(0x1050, sections), 0x450)

    def test_rva_outside_returns_none(self):
        sections = [{"virtual_address": 0x1000, "virtual_size": 0x100, "pointer_to_raw_data": 0x400, "size_of_raw_data": 0x100}]
        self.assertIsNone(rva_to_offset(0x2000, sections))

    def test_rva_past_raw_size_returns_none(self):
        # A section can have a bigger virtual size than raw size, and the tail of
        # it has no file bytes.
        sections = [{"virtual_address": 0x1000, "virtual_size": 0x200, "pointer_to_raw_data": 0x400, "size_of_raw_data": 0x100}]
        self.assertIsNone(rva_to_offset(0x1150, sections))


if __name__ == "__main__":
    unittest.main()
