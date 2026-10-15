"""ELF parsing."""

from __future__ import annotations

import os
import unittest

from revkit.elf import parse_elf, parse_elf_file

import helpers


class HeaderTests(unittest.TestCase):
    def test_elf64_headers(self):
        elf = helpers.build_elf(bits=64, machine=62)
        parsed = parse_elf(elf, "sample")
        self.assertTrue(parsed.is_64bit)
        self.assertEqual(parsed.machine_name, "x86-64")
        self.assertEqual(parsed.bits, 64)
        self.assertEqual(parsed.endian, "little-endian")
        self.assertEqual(parsed.osabi, "SYSV")
        self.assertEqual(parsed.type_name, "EXEC (executable)")

    def test_elf32_headers(self):
        elf = helpers.build_elf(bits=32, machine=3)
        parsed = parse_elf(elf, "sample")
        self.assertFalse(parsed.is_64bit)
        self.assertEqual(parsed.bits, 32)
        self.assertEqual(parsed.machine_name, "x86")

    def test_entry_point(self):
        parsed = parse_elf(helpers.build_elf(), "a.out")
        self.assertEqual(parsed.entry_point, 0x1000)

    def test_big_endian_flagged(self):
        parsed = parse_elf(helpers.build_elf(little=False), "be")
        self.assertEqual(parsed.endian, "big-endian")

    def test_not_elf_rejected(self):
        from revkit.io import FormatError

        with self.assertRaises(FormatError):
            parse_elf(b"MZ" + b"\x00" * 100, "x")

    def test_bad_ei_class_rejected(self):
        from revkit.io import FormatError

        data = bytearray(helpers.build_elf())
        data[4] = 9
        with self.assertRaises(FormatError):
            parse_elf(bytes(data), "x")


class SectionTests(unittest.TestCase):
    def test_sections_parsed_with_names(self):
        parsed = parse_elf(helpers.build_elf(), "a.out")
        names = [s.name for s in parsed.sections]
        self.assertIn(".text", names)
        self.assertIn(".rodata", names)
        self.assertIn(".shstrtab", names)

    def test_section_flags(self):
        parsed = parse_elf(helpers.build_elf(), "a.out")
        text = next(s for s in parsed.sections if s.name == ".text")
        self.assertTrue(text.executable)
        self.assertFalse(text.writable)

    def test_section_types_named(self):
        parsed = parse_elf(helpers.build_elf(), "a.out")
        text = next(s for s in parsed.sections if s.name == ".text")
        self.assertEqual(text.type_name, "PROGBITS")

    def test_section_sizes(self):
        parsed = parse_elf(helpers.build_elf(), "a.out")
        text = next(s for s in parsed.sections if s.name == ".text")
        self.assertEqual(text.size, 64)


class RealBinaryTests(unittest.TestCase):
    """Parse an actual system binary, so the parser is checked against something
    a linker really produced rather than only our own builder."""

    BINARY = "/bin/ls"

    def setUp(self):
        if not os.path.exists(self.BINARY):
            self.skipTest(f"{self.BINARY} not available")

    def test_parses_a_real_elf(self):
        parsed = parse_elf_file(self.BINARY)
        self.assertTrue(parsed.is_64bit)
        self.assertEqual(parsed.machine_name, "x86-64")
        self.assertTrue(len(parsed.sections) > 5)

    def test_interpreter_found(self):
        parsed = parse_elf_file(self.BINARY)
        self.assertIn("ld-linux", parsed.interpreter)

    def test_build_id_found(self):
        parsed = parse_elf_file(self.BINARY)
        self.assertTrue(len(parsed.build_id) >= 8)

    def test_imports_are_undefined_symbols(self):
        parsed = parse_elf_file(self.BINARY)
        imports = parsed.imports()
        self.assertTrue(len(imports) > 10)
        self.assertTrue(all(s.section_index == 0 for s in imports))
        self.assertTrue(all(s.name for s in imports))

    def test_summary_has_no_warnings(self):
        parsed = parse_elf_file(self.BINARY)
        self.assertEqual(parsed.warnings, [])

    def test_load_segments_cover_the_file(self):
        parsed = parse_elf_file(self.BINARY)
        loads = [s for s in parsed.segments if s.type_name == "LOAD"]
        self.assertTrue(len(loads) >= 2)
        for seg in loads:
            self.assertLessEqual(seg.offset + seg.file_size, len(parsed.data))

    def test_rwx_flags_present(self):
        parsed = parse_elf_file(self.BINARY)
        codes = [s for s in parsed.segments if s.executable]
        self.assertTrue(codes)
        self.assertTrue(all("x" in s.rwx for s in codes))


class SymbolTests(unittest.TestCase):
    def setUp(self):
        if not os.path.exists("/bin/ls"):
            self.skipTest("/bin/ls not available")

    def test_dynsym_has_entries(self):
        parsed = parse_elf_file("/bin/ls")
        self.assertTrue(len(parsed.dynsym) > 0)

    def test_bind_and_type_reported(self):
        parsed = parse_elf_file("/bin/ls")
        binds = {s.bind for s in parsed.dynsym}
        self.assertIn("GLOBAL", binds)


if __name__ == "__main__":
    unittest.main()
