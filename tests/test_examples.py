"""Every example script runs.

The README points at these as working examples, and 01_identify.py sat broken on
every ELF binary for want of anyone running it. Check them all.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BINARY = "/bin/ls"


def run_example(script: str, *args: str) -> subprocess.CompletedProcess:
    """Run an example in a child interpreter with the repo root importable."""
    env = dict(os.environ, PYTHONPATH=ROOT)
    return subprocess.run(
        [sys.executable, os.path.join(ROOT, "examples", script), *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=300,
    )


@unittest.skipUnless(os.path.exists(BINARY), f"{BINARY} not available")
class ExampleTests(unittest.TestCase):
    def test_01_identify(self):
        # Used to crash on any ELF: it indexed imp["dll"], which only PE imports
        # have, and ELF imports never reached it until parse_any started passing
        # them through.
        result = run_example("01_identify.py", BINARY)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("imports", result.stdout)

    def test_02_entropy(self):
        result = run_example("02_entropy.py", BINARY)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_03_strings(self):
        result = run_example("03_strings.py", BINARY)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_04_deobfuscate(self):
        # A small XOR blob rather than the binary: the brute force is 256 passes
        # and the example calls it directly, with no size cap.
        blob = b"\x00" * 64 + bytes(b ^ 0x5A for b in b"http://evil.example/c2.php\x00")
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "xor.bin")
            with open(path, "wb") as fh:
                fh.write(blob)
            result = run_example("04_deobfuscate.py", path)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_05_carve(self):
        with tempfile.TemporaryDirectory() as out:
            result = run_example("05_carve.py", BINARY, out)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_06_report(self):
        result = run_example("06_report.py", BINARY)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_07_patch(self):
        # Patch a copy, because the patcher writes a .bak next to its target.
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "copy.bin")
            shutil.copy(BINARY, target)
            result = run_example("07_patch.py", target, "0x1000", "90 90 c3")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_08_disassemble(self):
        try:
            import capstone  # noqa: F401
        except ImportError:
            self.skipTest("capstone not installed")
        result = run_example("08_disassemble.py", BINARY)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_09_real_binary(self):
        result = run_example("09_real_binary.py")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_10_emulate(self):
        result = run_example("10_emulate.py", "--hex", "48c7c03c00000048c7c7400000000f05")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("exit:     64", result.stdout)


if __name__ == "__main__":
    unittest.main()
