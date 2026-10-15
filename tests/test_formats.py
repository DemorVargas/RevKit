"""Format identification and dispatch."""

from __future__ import annotations

import unittest

from revkit import formats

import helpers


class SniffTests(unittest.TestCase):
    def test_elf(self):
        fmt, hits = formats.sniff(helpers.build_elf())
        self.assertEqual(fmt, "elf")
        self.assertIn("elf", hits)

    def test_pe(self):
        fmt, hits = formats.sniff(helpers.build_pe())
        self.assertEqual(fmt, "pe")

    def test_zip(self):
        fmt, _ = formats.sniff(helpers.build_zip_with_file("a.txt", b"hello"))
        self.assertEqual(fmt, "zip")

    def test_gzip(self):
        import gzip

        fmt, _ = formats.sniff(gzip.compress(b"hello world" * 20))
        self.assertEqual(fmt, "gzip")

    def test_png(self):
        png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        self.assertEqual(formats.sniff(png)[0], "png")

    def test_unknown(self):
        fmt, hits = formats.sniff(b"\x00" * 100)
        self.assertEqual(fmt, "unknown")
        self.assertEqual(hits, [])

    def test_empty_is_unknown(self):
        self.assertEqual(formats.sniff(b""), ("unknown", []))


class IdentifyTests(unittest.TestCase):
    def test_info_fields(self):
        info = formats.identify(helpers.build_elf(), "a.out")
        self.assertEqual(info.format, "elf")
        self.assertEqual(info.size, len(helpers.build_elf()))
        self.assertEqual(info.extension_hint, ".elf")
        self.assertTrue(info.description)

    def test_embedded_signatures_listed(self):
        # A ZIP containing a PNG should report both. The ZIP must be stored
        # uncompressed, because a deflated member hides the inner signature.
        png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
        zip_with_png = helpers.build_zip_with_file("image.png", png, compressed=False)
        info = formats.identify(zip_with_png, "bundle.zip")
        self.assertEqual(info.format, "zip")
        self.assertIn("png", info.embedded)

    def test_mz_without_pe_warns(self):
        info = formats.identify(b"MZ" + b"\x00" * 200, "stub.exe")
        self.assertTrue(info.warnings)

    def test_executable_formats(self):
        self.assertTrue(formats.is_executable_format("elf"))
        self.assertTrue(formats.is_executable_format("pe"))
        self.assertFalse(formats.is_executable_format("zip"))
        self.assertFalse(formats.is_executable_format("unknown"))


class ParseAnyTests(unittest.TestCase):
    def test_elf_detail_included(self):
        out = formats.parse_any(helpers.build_elf(), "a.out")
        self.assertEqual(out["format"], "elf")
        self.assertIn("machine", out["detail"])
        self.assertTrue(out["sections"])

    def test_elf_imports_reach_the_parsed_dict(self):
        # The PE branch always carried imports through; the ELF branch reported an
        # import_count and then handed back nothing, so `revkit file` printed an
        # empty list. Assert through parse_any, which is what the CLI reads, not
        # on the parser object sitting underneath it.
        import os

        if not os.path.exists("/bin/ls"):
            self.skipTest("/bin/ls not available")
        with open("/bin/ls", "rb") as fh:
            out = formats.parse_any(fh.read(), "/bin/ls")
        self.assertTrue(out["imports"])
        self.assertTrue(all(i["name"] for i in out["imports"]))
        self.assertTrue(out["exports"])

    def test_pe_detail_included(self):
        out = formats.parse_any(helpers.build_pe(imports={"KERNEL32.dll": ["ExitProcess"]}), "a.exe")
        self.assertEqual(out["format"], "pe")
        self.assertTrue(out["imports"])
        self.assertEqual(out["imports"][0]["name"], "ExitProcess")

    def test_unknown_format_carves_instead(self):
        out = formats.parse_any(b"\x00" * 64 + helpers.build_zip_with_file("a.txt", b"x" * 32), "blob")
        self.assertEqual(out["format"], "unknown")
        self.assertTrue(any("no structural parser" in w for w in out["warnings"]))
        self.assertTrue(out["carved"])


class FirmwareTests(unittest.TestCase):
    def test_elf_is_not_firmware(self):
        self.assertFalse(formats.looks_like_firmware(helpers.build_elf()))

    def test_pe_is_not_firmware(self):
        self.assertFalse(formats.looks_like_firmware(helpers.build_pe()))

    def test_marker_plus_high_entropy_is_firmware(self):
        import random

        rng = random.Random(4)
        blob = b"ANDROID!" + rng.randbytes(4096) * 4
        self.assertTrue(formats.looks_like_firmware(blob))

    def test_plain_data_is_not_firmware(self):
        self.assertFalse(formats.looks_like_firmware(b"\x00" * 4096))


class UtilityTests(unittest.TestCase):
    def test_human_size(self):
        self.assertEqual(formats.human_size(512), "512B")
        self.assertEqual(formats.human_size(2048), "2.0KB")
        self.assertEqual(formats.human_size(5 * 1024 * 1024), "5.0MB")

    def test_descriptions_cover_known_formats(self):
        for fmt in ("elf", "pe", "zip", "unknown"):
            self.assertIn(fmt, formats.DESCRIPTIONS)


if __name__ == "__main__":
    unittest.main()
