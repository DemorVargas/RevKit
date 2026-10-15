"""The memory space and register file."""

from __future__ import annotations

import unittest

from revkit.emulator.decoder import Machine
from revkit.emulator.errors import MemError
from revkit.emulator.memory import Memory


class MemoryTests(unittest.TestCase):
    def test_roundtrip_across_pages(self):
        mem = Memory(page_bits=12)
        mem.write(0x1000, b"hello")
        mem.write(0x1FFC, b"abcdefgh")
        self.assertEqual(mem.read(0x1000, 5), b"hello")
        self.assertEqual(mem.read(0x1FFC, 8), b"abcdefgh")

    def test_read_spans_a_page_boundary(self):
        mem = Memory(page_bits=8)
        mem.write(0x1000, b"x" * 40)
        self.assertEqual(len(mem.read(0x1000, 40)), 40)

    def test_write_spans_a_page_boundary(self):
        mem = Memory(page_bits=8)
        mem.write(0x1005, b"a" * 30)
        self.assertEqual(mem.read(0x1005, 30), b"a" * 30)

    def test_lazily_allocates_pages(self):
        mem = Memory(page_bits=12)
        self.assertEqual(mem.pages_touched(), 0)
        mem.read(0x5000, 1)
        self.assertEqual(mem.pages_touched(), 1)

    def test_typed_reads_and_writes(self):
        mem = Memory(page_bits=12)
        mem.write_u64(0x1000, 0x1122334455667788)
        mem.write_u32(0x2000, 0xAABBCCDD)
        mem.write_u16(0x3000, 0xBEEF)
        mem.write_u8(0x4000, 0x42)
        self.assertEqual(mem.read_u64(0x1000), 0x1122334455667788)
        self.assertEqual(mem.read_u32(0x2000), 0xAABBCCDD)
        self.assertEqual(mem.read_u16(0x3000), 0xBEEF)
        self.assertEqual(mem.read_u8(0x4000), 0x42)

    def test_negative_address_rejected(self):
        with self.assertRaises(MemError):
            Memory(page_bits=12).read(-1, 1)

    def test_negative_size_rejected(self):
        with self.assertRaises(MemError):
            Memory(page_bits=12).read(0, -1)

    def test_cstring_stops_at_nul(self):
        mem = Memory(page_bits=12)
        mem.write(0x1000, b"hello\x00world")
        self.assertEqual(mem.read_cstring(0x1000), "hello")

    def test_cstring_without_nul_reads_max(self):
        mem = Memory(page_bits=12)
        mem.write(0x1000, b"abc")
        self.assertEqual(mem.read_cstring(0x1000, max_len=3), "abc")

    def test_wstring_decodes_utf16le(self):
        mem = Memory(page_bits=12)
        mem.write(0x1000, "wide".encode("utf-16-le") + b"\x00\x00")
        self.assertEqual(mem.read_wstring(0x1000), "wide")

    def test_pages_are_zero_initialised(self):
        mem = Memory(page_bits=12)
        self.assertEqual(mem.read(0x9999, 16), b"\x00" * 16)

    def test_clear_resets_the_space(self):
        mem = Memory(page_bits=12)
        mem.write(0x1000, b"data")
        mem.clear()
        self.assertEqual(mem.read(0x1000, 4), b"\x00\x00\x00\x00")


class MachineTests(unittest.TestCase):
    def test_defaults_include_a_stack(self):
        m = Machine()
        self.assertEqual(m.r("rsp"), 0x7FFFFFF0)
        self.assertTrue(m.r("rbp") == 0)

    def test_64_bit_registers(self):
        m = Machine(bits=64)
        m.write_reg(0, 64, 0xFFFFFFFFFFFFFFFF)
        self.assertEqual(m.read_reg(0, 64), 0xFFFFFFFFFFFFFFFF)

    def test_writing_32_bit_zeroes_the_upper_half(self):
        m = Machine(bits=64)
        m.w("rax", 0xFFFFFFFFFFFFFFFF)
        m.write_reg(0, 32, 0x1234)
        self.assertEqual(m.r("rax"), 0x1234)

    def test_writing_16_bit_preserves_the_upper_half(self):
        m = Machine(bits=64)
        m.w("rax", 0xFFFFFFFFFFFFFFFF)
        m.write_reg(0, 16, 0x1234)
        self.assertEqual(m.r("rax"), 0xFFFFFFFFFFFF1234)

    def test_writing_8_bit_preserves_the_upper_half(self):
        m = Machine(bits=64)
        m.w("rax", 0xFFFFFFFFFFFFFFFF)
        m.write_reg(0, 8, 0xAB)
        self.assertEqual(m.r("rax"), 0xFFFFFFFFFFFFFFAB)

    def test_register_names_by_width(self):
        m = Machine()
        self.assertEqual(m.name_for(0, 64), "rax")
        self.assertEqual(m.name_for(0, 32), "eax")
        self.assertEqual(m.name_for(0, 16), "ax")
        self.assertEqual(m.name_for(0, 8), "al")
        self.assertEqual(m.name_for(7, 64), "rdi")

    def test_bad_width_raises(self):
        with self.assertRaises(Exception):
            Machine.name_for(0, 24)

    def test_default_flags_have_interrupts_enabled(self):
        self.assertTrue(Machine().flags & (1 << 9))


if __name__ == "__main__":
    unittest.main()
