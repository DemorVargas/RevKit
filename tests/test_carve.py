"""Carving embedded files and sections."""

from __future__ import annotations

import unittest

from revkit import carve

import helpers


class MagicCarvingTests(unittest.TestCase):
    def test_finds_zip_inside_a_blob(self):
        blob = b"\x00" * 64 + helpers.build_zip_with_file("payload.bin", b"data" * 100)
        found = carve.carve_by_magic(blob)
        zips = [f for f in found if f.kind == "zip"]
        self.assertEqual(len(zips), 1)
        self.assertEqual(zips[0].offset, 64)

    def test_finds_elf(self):
        found = carve.carve_by_magic(helpers.build_elf())
        self.assertTrue(any(f.kind == "elf" for f in found))

    def test_finds_png(self):
        png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64 + b"IEND\xaeB`\x82"
        found = carve.carve_by_magic(png)
        pngs = [f for f in found if f.kind == "png"]
        self.assertEqual(len(pngs), 1)
        # The known tail caps the carved region at the real end of the image.
        self.assertEqual(pngs[0].end, len(png))

    def test_multiple_hits_reported(self):
        blob = helpers.build_zip_with_file("a.txt", b"a" * 32) + b"\x00" * 32 + helpers.build_zip_with_file("b.txt", b"b" * 32)
        zips = [f for f in carve.carve_by_magic(blob) if f.kind == "zip"]
        self.assertEqual(len(zips), 2)

    def test_want_filters_kinds(self):
        blob = helpers.build_zip_with_file("a.txt", b"a" * 32)
        found = carve.carve_by_magic(blob, want=["elf"])
        self.assertEqual(found, [])

    def test_empty_input(self):
        self.assertEqual(carve.carve_by_magic(b""), [])

    def test_carved_object_reports_strings(self):
        blob = helpers.build_zip_with_file("hello.txt", b"a" * 32)
        found = carve.carve_by_magic(blob)
        zip_hit = next(f for f in found if f.kind == "zip")
        self.assertTrue(any("hello.txt" in s.value for s in zip_hit.strings))

    def test_entropy_reported(self):
        import random

        rng = random.Random(2)
        # Random bytes carry no signature of their own, so wrap them in a stored
        # ZIP to give the carver something to find.
        blob = helpers.build_zip_with_file("blob.bin", rng.randbytes(4096), compressed=False)
        found = carve.carve_by_magic(blob)
        zip_hit = next(f for f in found if f.kind == "zip")
        self.assertGreater(zip_hit.entropy, 6.0)


class SectionCarvingTests(unittest.TestCase):
    def test_carves_sections_from_a_pe(self):
        pe = helpers.build_pe()
        from revkit.pe import parse_pe

        parsed = parse_pe(pe, "a.exe")
        found = carve.carve_sections(pe, [s.to_dict() for s in parsed.sections])
        self.assertEqual(len(found), len(parsed.sections))
        names = [f.description for f in found]
        self.assertIn(".text", names)

    def test_carved_section_content_matches(self):
        pe = helpers.build_pe()
        from revkit.pe import parse_pe

        parsed = parse_pe(pe, "a.exe")
        found = carve.carve_sections(pe, [s.to_dict() for s in parsed.sections])
        text = next(f for f in found if f.description == ".text")
        self.assertTrue(pe[text.offset : text.end].startswith(b"\x90"))

    def test_skips_sections_past_the_end(self):
        pe = helpers.build_pe()
        sections = [{"pointer_to_raw_data": 0, "size_of_raw_data": 999999, "name": ".bogus"}]
        self.assertEqual(carve.carve_sections(pe, sections), [])


class OverlayTests(unittest.TestCase):
    def test_overlay_detected_after_sections(self):
        # The builder emits no overlay, so append one to have something to find.
        pe = helpers.build_pe() + b"trailing overlay data"
        from revkit.pe import parse_pe

        parsed = parse_pe(pe, "a.exe")
        overlay = carve.find_overlay(pe, parsed.overlay_start)
        self.assertIsNotNone(overlay)
        self.assertEqual(overlay.kind, "overlay")
        self.assertEqual(overlay.offset, parsed.overlay_start)

    def test_no_overlay_when_nothing_follows(self):
        self.assertIsNone(carve.find_overlay(b"abc", 3))
        self.assertIsNone(carve.find_overlay(b"abc", 0))


class FirmwareCarvingTests(unittest.TestCase):
    def test_finds_android_marker(self):
        blob = b"ANDROID!" + b"\x00" * 512
        found = carve.carve_firmware(blob)
        self.assertTrue(any(f.kind == "android-boot" for f in found))

    def test_no_markers_in_plain_data(self):
        self.assertEqual(carve.carve_firmware(b"\x00" * 4096), [])


class HighEntropyTests(unittest.TestCase):
    def test_finds_random_region(self):
        import random

        rng = random.Random(9)
        blob = b"\x00" * 2048 + rng.randbytes(2048)
        regions = carve.high_entropy_regions(blob, block=512)
        self.assertTrue(regions)
        self.assertGreaterEqual(regions[0].start, 2048)

    def test_none_in_constant_data(self):
        self.assertEqual(carve.high_entropy_regions(b"\x00" * 8192), [])


class EndDetectionTests(unittest.TestCase):
    def test_zip_ends_at_central_directory(self):
        blob = helpers.build_zip_with_file("a.txt", b"x" * 100) + b"trailing junk"
        found = carve.carve_by_magic(blob)
        zip_hit = next(f for f in found if f.kind == "zip")
        # The known tail is honoured even with data after it.
        self.assertLess(zip_hit.end, len(blob))

    def test_next_signature_bounds_the_region(self):
        blob = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64 + b"\x7fELF" + b"\x00" * 32
        found = carve.carve_by_magic(blob)
        pngs = [f for f in found if f.kind == "png"]
        self.assertTrue(pngs)
        self.assertEqual(pngs[0].end, len(blob) - 36)


if __name__ == "__main__":
    unittest.main()
