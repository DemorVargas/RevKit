"""Command line interface."""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest

from revkit import cli

import helpers


class CliTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._stdout = io.StringIO()
        self._stderr = io.StringIO()

    def run_cli(self, *args) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main([str(a) for a in args])
        return code, out.getvalue(), err.getvalue()

    def write(self, name: str, data: bytes) -> str:
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as fh:
            fh.write(data)
        return path


class VersionAndHelpTests(CliTestCase):
    def test_version(self):
        # argparse exits the process after printing, which is what we want here.
        with self.assertRaises(SystemExit) as ctx:
            self.run_cli("--version")
        self.assertEqual(ctx.exception.code, 0)

    def test_help_lists_subcommands(self):
        with self.assertRaises(SystemExit) as ctx:
            self.run_cli("--help")
        self.assertEqual(ctx.exception.code, 0)

    def test_no_subcommand_is_an_error(self):
        with self.assertRaises(SystemExit):
            self.run_cli()


class FileCommandTests(CliTestCase):
    def test_identifies_an_elf(self):
        path = self.write("a.elf", helpers.build_elf())
        code, out, _ = self.run_cli("file", path)
        self.assertEqual(code, 0)
        self.assertIn("elf", out)
        self.assertIn("x86-64", out)

    def test_identifies_a_pe(self):
        path = self.write("a.exe", helpers.build_pe(imports={"KERNEL32.dll": ["ExitProcess"]}))
        code, out, _ = self.run_cli("file", path)
        self.assertEqual(code, 0)
        self.assertIn("amd64", out)
        self.assertIn("ExitProcess", out)

    def test_missing_file_is_a_clean_error(self):
        code, _, err = self.run_cli("file", os.path.join(self.tmp, "nope"))
        self.assertNotEqual(code, 0)
        self.assertIn("no such file", err)


class ScanCommandTests(CliTestCase):
    def test_markdown_report(self):
        path = self.write("a.exe", helpers.build_pe())
        code, out, _ = self.run_cli("scan", path)
        self.assertEqual(code, 0)
        self.assertIn("# Analysis:", out)

    def test_json_report(self):
        path = self.write("a.exe", helpers.build_pe(imports={"KERNEL32.dll": ["ExitProcess"]}))
        code, out, _ = self.run_cli("scan", path, "--json")
        self.assertEqual(code, 0)
        parsed = json.loads(out)
        self.assertEqual(parsed["info"]["format"], "pe")
        self.assertTrue(parsed["imports"])


class StringsCommandTests(CliTestCase):
    def test_prints_strings(self):
        path = self.write("a.bin", b"\x00hello world\x00")
        code, out, _ = self.run_cli("strings", path)
        self.assertEqual(code, 0)
        self.assertIn("hello world", out)

    def test_offsets_flag(self):
        path = self.write("a.bin", b"\x00\x00\x00hello")
        code, out, _ = self.run_cli("strings", path, "--offsets")
        self.assertEqual(code, 0)
        self.assertIn("00000003", out)

    def test_encoding_filter(self):
        path = self.write("a.bin", "wide".encode("utf-16-le") + b"\x00\x00")
        code, out, _ = self.run_cli("strings", path, "--encoding", "utf16")
        self.assertEqual(code, 0)
        self.assertIn("wide", out)


class EntropyCommandTests(CliTestCase):
    def test_reports_entropy(self):
        path = self.write("a.bin", b"\x00" * 4096)
        code, out, _ = self.run_cli("entropy", path)
        self.assertEqual(code, 0)
        self.assertIn("entropy", out)
        self.assertIn("chi-square", out)

    def test_flags_high_entropy(self):
        import random

        path = self.write("rand.bin", random.Random(1).randbytes(8192))
        code, out, _ = self.run_cli("entropy", path)
        self.assertIn("packed or encrypted", out)


class DecodeCommandTests(CliTestCase):
    def test_xor_with_key(self):
        from revkit.crypto import xor_single

        path = self.write("a.bin", xor_single(b"hello world", 0x42))
        code, out, _ = self.run_cli("decode", path, "--method", "xor", "--key", "42")
        self.assertEqual(code, 0)
        self.assertIn("hello world", out)

    def test_brute_finds_the_key(self):
        from revkit.crypto import xor_single

        path = self.write("a.bin", xor_single(b"http://hidden.example.invalid/x", 0x13))
        code, out, _ = self.run_cli("decode", path, "--method", "xor-brute")
        self.assertEqual(code, 0)
        self.assertIn("0x13", out)

    def test_rc4_roundtrip(self):
        from revkit.crypto import rc4

        path = self.write("a.bin", rc4(b"rc4 payload here", b"key"))
        code, out, _ = self.run_cli("decode", path, "--method", "rc4", "--key", "key")
        self.assertEqual(code, 0)
        self.assertIn("rc4 payload here", out)

    def test_nothing_decodable(self):
        path = self.write("a.bin", b"\x00" * 64)
        code, out, _ = self.run_cli("decode", path, "--method", "base64")
        self.assertEqual(code, 0)
        self.assertIn("nothing decodable", out)


class ExtractCommandTests(CliTestCase):
    def test_carves_a_zip_to_disk(self):
        path = self.write("bundle.bin", b"\x00" * 32 + helpers.build_zip_with_file("payload.txt", b"x" * 64))
        outdir = os.path.join(self.tmp, "out")
        code, out, _ = self.run_cli("extract", path, "-o", outdir)
        self.assertEqual(code, 0)
        self.assertTrue(os.path.isdir(outdir))
        self.assertTrue(os.listdir(outdir))
        self.assertIn("zip", out)


class PatchCommandTests(CliTestCase):
    def test_patches_and_reports(self):
        path = self.write("a.bin", b"ABCDEFGH")
        code, out, _ = self.run_cli("patch", path, "0x1", "7a 7a")
        self.assertEqual(code, 0)
        self.assertIn("wrote 2 bytes", out)
        self.assertIn("patched", out)

    def test_writes_a_new_file_by_default(self):
        path = self.write("a.bin", b"ABCDEFGH")
        self.run_cli("patch", path, "0x1", "7a 7a")
        with open(path + ".patched", "rb") as fh:
            self.assertEqual(fh.read(), b"AzzDEFGH")

    def test_in_place_creates_backup(self):
        path = self.write("a.bin", b"ABCDEFGH")
        self.run_cli("patch", path, "0x1", "7a 7a", "--in-place")
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(), b"AzzDEFGH")
        with open(path + ".bak", "rb") as fh:
            self.assertEqual(fh.read(), b"ABCDEFGH")

    def test_bad_offset_is_a_clean_error(self):
        path = self.write("a.bin", b"ABCDEFGH")
        code, _, err = self.run_cli("patch", path, "notanumber", "7a")
        self.assertNotEqual(code, 0)
        self.assertIn("error", err)


class FindCommandTests(CliTestCase):
    def test_finds_offsets(self):
        path = self.write("a.bin", b"abXYcdXY")
        code, out, _ = self.run_cli("find", path, "58 59")
        self.assertEqual(code, 0)
        self.assertIn("0x2", out)
        self.assertIn("0x6", out)

    def test_not_found(self):
        path = self.write("a.bin", b"abcdef")
        code, out, _ = self.run_cli("find", path, "7a")
        self.assertEqual(code, 1)
        self.assertIn("not found", out)


class YaraCommandTests(CliTestCase):
    def test_reports_hits(self):
        path = self.write("a.bin", b"powershell.exe -enc AAAA")
        code, out, _ = self.run_cli("yara", path)
        self.assertEqual(code, 0)
        self.assertIn("powershell", out)

    def test_json_output(self):
        path = self.write("a.bin", b"VirtualAllocEx")
        code, out, _ = self.run_cli("yara", path, "--json")
        self.assertEqual(code, 0)
        parsed = json.loads(out)
        self.assertEqual(parsed[0]["rule"], "process_injection")

    def test_custom_pattern(self):
        path = self.write("a.bin", b"xx needle42 yy")
        code, out, _ = self.run_cli("yara", path, "--rule", "mine", "--pattern", r"needle\d+")
        self.assertEqual(code, 0)
        self.assertIn("mine", out)

    def test_no_hits(self):
        path = self.write("a.bin", b"nothing to see here at all")
        code, out, _ = self.run_cli("yara", path)
        self.assertEqual(code, 0)
        self.assertIn("no hits", out)


class ShellCommandTests(CliTestCase):
    def test_missing_capstone_is_a_clean_error(self):
        try:
            import capstone  # noqa: F401

            self.skipTest("capstone is installed")
        except ImportError:
            pass
        code, _, err = self.run_cli("shell", "--hex-bytes", "9090c3")
        self.assertNotEqual(code, 0)
        self.assertIn("pip install", err)


class EmulateCommandTests(CliTestCase):
    EXIT_64 = "48c7c03c00000048c7c7400000000f05"
    WRITE_13 = ("48c7c00100000048c7c70100000048c7c60020000048c7c20d0000000f05"
                "48c7c03c0000004831ff0f05")
    # lea rdi,[rip+0x1c] -> 0x1023, open it, exit. The caller appends the path.
    OPEN_PATH = bytes.fromhex(
        "488d3d1c000000" "48c7c002000000" "48c7c600000000" "0f05"
        "48c7c03c000000" "4831ff" "0f05"
    )

    def test_reports_the_exit_code(self):
        code, out, _ = self.run_cli("emulate", "--hex-bytes", self.EXIT_64)
        self.assertEqual(code, 0)
        self.assertIn("exit:       64", out)

    def test_captures_output(self):
        _, out, _ = self.run_cli("emulate", "--hex-bytes", self.WRITE_13)
        self.assertIn("output:     13 bytes", out)
        self.assertIn("write(0x1, 0x2000, 0xd) = 13", out)

    def test_needs_a_path_or_hex(self):
        code, _, err = self.run_cli("emulate")
        self.assertNotEqual(code, 0)
        self.assertIn("hex-bytes", err)

    def test_a_host_path_is_not_visible_to_the_guest(self):
        # The guest filesystem is the VFS, so /etc/shadow being on this machine
        # does not make it openable through the emulator.
        blob = self.OPEN_PATH + b"/etc/shadow\x00"
        path = self.write("openit.bin", blob)
        _, out, _ = self.run_cli("emulate", path)
        self.assertIn("open(0x1023, 0x0, 0x0) = -2", out)

    def test_mount_puts_a_file_in_the_guest(self):
        blob = self.OPEN_PATH + b"/tmp/target\x00"
        path = self.write("openit.bin", blob)
        payload = self.write("payload.bin", b"hello")
        _, out, _ = self.run_cli("emulate", path, "--mount", f"/tmp/target={payload}")
        self.assertIn("open(0x1023, 0x0, 0x0) = 3", out)

    def test_bad_mount_spec_is_a_clean_error(self):
        path = self.write("openit.bin", self.OPEN_PATH + b"/tmp/target\x00")
        code, _, err = self.run_cli("emulate", path, "--mount", "noequalsign")
        self.assertNotEqual(code, 0)
        self.assertIn("PATH=FILE", err)

    def test_captured_traffic_is_reported(self):
        # A C2 beacon should hand over its address and its payload, and nothing
        # should leave the machine to get them.
        blob = helpers.build_beacon("203.0.113.9", 4444, b"GET /gate.php HTTP/1.1\r\n")
        path = self.write("beacon.bin", blob)
        _, out, _ = self.run_cli("emulate", path)
        self.assertIn("captured traffic:", out)
        self.assertIn("-> 203.0.113.9:4444", out)
        self.assertIn("GET /gate.php HTTP/1.1", out)


if __name__ == "__main__":
    unittest.main()
