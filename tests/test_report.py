"""Report building."""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from revkit import report

import helpers


class AnalyzeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def _write(self, name: str, data: bytes) -> str:
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def test_analyzes_a_pe(self):
        path = self._write("sample.exe", helpers.build_pe(imports={"KERNEL32.dll": ["ExitProcess"]}))
        result = report.analyze(path)
        self.assertEqual(result.info.format, "pe")
        self.assertTrue(result.imports)
        self.assertTrue(result.sections)

    def test_analyzes_an_elf(self):
        path = self._write("sample.elf", helpers.build_elf())
        result = report.analyze(path)
        self.assertEqual(result.info.format, "elf")
        self.assertTrue(result.sections)

    def test_analyzes_unknown_data_without_crashing(self):
        path = self._write("blob.bin", b"\x00" * 64 + helpers.build_zip_with_file("a.txt", b"x" * 32))
        result = report.analyze(path)
        self.assertEqual(result.info.format, "unknown")
        self.assertTrue(result.warnings)

    def test_findings_are_collected(self):
        path = self._write(
            "noisy.exe",
            b"http://evil.example.invalid/payload.exe\x00"
            b"Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
            b"powershell.exe -enc AAAA\x00"
            b"VirtualAllocEx\x00",
        )
        result = report.analyze(path)
        self.assertTrue(result.hits)
        rules = {h["rule"] for h in result.hits}
        self.assertIn("process_injection", rules)
        self.assertIn("registry_run", rules)

    def test_missing_file_raises(self):
        with self.assertRaises(OSError):
            report.analyze(os.path.join(self.tmp, "nope.bin"))

    def test_real_binary_analysis(self):
        if not os.path.exists("/bin/ls"):
            self.skipTest("/bin/ls not available")
        result = report.analyze("/bin/ls")
        self.assertEqual(result.info.format, "elf")
        self.assertTrue(result.imports)
        self.assertTrue(result.detail["interpreter"])

    def test_elf_sections_carry_real_entropy(self):
        # The section table has offsets but no entropy, so the report has to
        # compute it; otherwise every section prints 0.00.
        if not os.path.exists("/bin/ls"):
            self.skipTest("/bin/ls not available")
        result = report.analyze("/bin/ls")
        scored = [s["entropy"] for s in result.sections if s.get("size")]
        self.assertTrue(scored)
        self.assertTrue(any(e > 0.5 for e in scored))

    def test_markdown_shows_entropy_not_zero(self):
        path = self._write("sample.elf", helpers.build_elf())
        result = report.analyze(path)
        md = report.to_markdown(result)
        self.assertNotIn("| .text | 0x1000 | 64 | 0.00 |", md)


class OutputTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "sample.exe")
        with open(self.path, "wb") as fh:
            fh.write(helpers.build_pe(imports={"KERNEL32.dll": ["ExitProcess"]}))
        self.result = report.analyze(self.path)

    def test_json_output_parses(self):
        parsed = json.loads(report.to_json(self.result))
        self.assertEqual(parsed["info"]["format"], "pe")
        self.assertIn("sections", parsed)
        self.assertIn("warnings", parsed)

    def test_json_output_is_deterministic(self):
        self.assertEqual(report.to_json(self.result), report.to_json(self.result))

    def test_markdown_output_has_headings(self):
        md = report.to_markdown(self.result)
        self.assertIn("# Analysis:", md)
        self.assertIn("## Sections", md)

    def test_markdown_reports_import_count(self):
        md = report.to_markdown(self.result)
        self.assertIn("Imports (1)", md)

    def test_markdown_mentions_format(self):
        md = report.to_markdown(self.result)
        self.assertIn("pe", md)

    def test_dict_output_has_all_sections(self):
        d = self.result.to_dict()
        for key in ("path", "size", "info", "detail", "sections", "imports", "strings",
                    "suspicious_strings", "carved", "signatures", "decode_candidates", "entropy", "warnings"):
            self.assertIn(key, d)

    def test_markdown_handles_empty_analysis(self):
        empty = report.Analysis(path="x", data=b"")
        md = report.to_markdown(empty)
        self.assertIn("Identification failed", md)


if __name__ == "__main__":
    unittest.main()
