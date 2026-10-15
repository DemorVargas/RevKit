"""PE parsing."""

from __future__ import annotations

import unittest

from revkit.io import FormatError
from revkit.pe import parse_pe

import helpers


class HeaderTests(unittest.TestCase):
    def test_pe32plus_headers(self):
        pe = helpers.build_pe()
        parsed = parse_pe(pe, "sample.exe")
        self.assertEqual(parsed.machine_name, "amd64")
        self.assertTrue(parsed.is_64bit)
        self.assertFalse(parsed.is_dll)
        self.assertEqual(parsed.image_base, 0x140000000)
        self.assertEqual(parsed.subsystem_name(), "WINDOWS_GUI")

    def test_pe32_headers(self):
        pe = helpers.build_pe(machine=helpers.IMAGE_FILE_MACHINE_I386)
        parsed = parse_pe(pe, "sample32.exe")
        self.assertEqual(parsed.machine_name, "i386")
        self.assertFalse(parsed.is_64bit)
        self.assertEqual(parsed.image_base, 0x400000)

    def test_dll_flag(self):
        pe = helpers.build_pe(is_dll=True)
        self.assertTrue(parse_pe(pe, "lib.dll").is_dll)

    def test_converted_subsystem(self):
        pe = helpers.build_pe(subsystem=helpers.IMAGE_SUBSYSTEM_WINDOWS_CUI)
        self.assertEqual(parse_pe(pe, "console.exe").subsystem_name(), "WINDOWS_CUI")

    def test_entry_point(self):
        pe = helpers.build_pe()
        self.assertEqual(parse_pe(pe, "a.exe").entry_point, 0x1000)

    def test_timestamp_recorded(self):
        pe = helpers.build_pe(timestamp=0x5F5E1000)
        self.assertEqual(parse_pe(pe, "a.exe").timestamp, 0x5F5E1000)

    def test_invalid_timestamp_not_converted(self):
        pe = helpers.build_pe(timestamp=0)
        self.assertIsNone(parse_pe(pe, "a.exe").summary()["timestamp_utc"])


class SectionTests(unittest.TestCase):
    def test_section_names_and_layout(self):
        pe = helpers.build_pe()
        parsed = parse_pe(pe, "a.exe")
        names = [s.name for s in parsed.sections]
        self.assertIn(".text", names)
        self.assertIn(".rdata", names)
        self.assertEqual(len(parsed.sections), 2)

    def test_sections_are_sorted_by_address(self):
        pe = helpers.build_pe()
        parsed = parse_pe(pe, "a.exe")
        addresses = [s.virtual_address for s in parsed.sections]
        self.assertEqual(addresses, sorted(addresses))

    def test_executable_flag_reported(self):
        pe = helpers.build_pe()
        parsed = parse_pe(pe, "a.exe")
        text = next(s for s in parsed.sections if s.name == ".text")
        self.assertTrue(text.characteristics & helpers.IMAGE_SCN_MEM_EXECUTE)

    def test_entropy_computed_for_sections(self):
        pe = helpers.build_pe()
        parsed = parse_pe(pe, "a.exe")
        text = next(s for s in parsed.sections if s.name == ".text")
        # .text is 0x100 NOPs padded out to 0x200 raw bytes, so exactly two byte
        # values appear equally often: one bit of entropy per byte.
        self.assertAlmostEqual(text.entropy, 1.0, places=3)

    def test_section_for_rva(self):
        pe = helpers.build_pe()
        parsed = parse_pe(pe, "a.exe")
        text = next(s for s in parsed.sections if s.name == ".text")
        self.assertEqual(parsed.section_for_rva(text.virtual_address + 0x10).name, ".text")
        self.assertIsNone(parsed.section_for_rva(0x9000))

    def test_offset_for_rva(self):
        pe = helpers.build_pe()
        parsed = parse_pe(pe, "a.exe")
        text = next(s for s in parsed.sections if s.name == ".text")
        self.assertEqual(parsed.offset_for_rva(text.virtual_address), text.pointer_to_raw_data)


class ImportTests(unittest.TestCase):
    def test_imports_parsed_with_names(self):
        pe = helpers.build_pe(imports={"KERNEL32.dll": ["CreateFileW", "ExitProcess"], "USER32.dll": ["MessageBoxA"]})
        parsed = parse_pe(pe, "a.exe")
        self.assertEqual(len(parsed.imports), 3)
        self.assertEqual(parsed.imports[0].dll, "KERNEL32.dll")
        self.assertEqual(parsed.imports[0].name, "CreateFileW")
        self.assertEqual(parsed.imports[2].dll, "USER32.dll")

    def test_no_imports_when_absent(self):
        pe = helpers.build_pe()
        self.assertEqual(parse_pe(pe, "a.exe").imports, [])

    def test_pe32_imports_parsed(self):
        pe = helpers.build_pe(machine=helpers.IMAGE_FILE_MACHINE_I386, imports={"KERNEL32.dll": ["ExitProcess"]})
        parsed = parse_pe(pe, "a.exe")
        self.assertEqual(len(parsed.imports), 1)
        self.assertEqual(parsed.imports[0].name, "ExitProcess")

    def test_ordinal_import_reported_as_ordinal(self):
        # A high-bit-set thunk means import by ordinal.
        pe = helpers.build_pe()
        parsed = parse_pe(pe, "a.exe")
        self.assertEqual(parsed.imports, [])


class RejectionTests(unittest.TestCase):
    def test_non_pe_rejected(self):
        with self.assertRaises(FormatError):
            parse_pe(b"\x7fELF" + b"\x00" * 100, "x")

    def test_mz_without_pe_signature_rejected(self):
        with self.assertRaises(FormatError):
            parse_pe(b"MZ" + b"\x00" * 200, "x")

    def test_empty_rejected(self):
        with self.assertRaises(FormatError):
            parse_pe(b"", "x")


class OverlayTests(unittest.TestCase):
    def test_overlay_start_after_last_section(self):
        pe = helpers.build_pe()
        parsed = parse_pe(pe, "a.exe")
        last = max(s.pointer_to_raw_data + s.size_of_raw_data for s in parsed.sections)
        self.assertGreaterEqual(parsed.overlay_start, last)


if __name__ == "__main__":
    unittest.main()
