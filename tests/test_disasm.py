"""Disassembly, with and without capstone installed."""

from __future__ import annotations

import unittest

from revkit import disasm

from helpers import build_shellcode

try:
    import capstone  # noqa: F401

    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False


class SyscallTableTests(unittest.TestCase):
    def test_x86_64_table_has_core_calls(self):
        names = disasm.syscall_names(64)
        self.assertEqual(names[1], "write")
        self.assertEqual(names[59], "execve")
        self.assertEqual(names[60], "exit")

    def test_x86_32_table_has_core_calls(self):
        names = disasm.syscall_names(32)
        self.assertEqual(names[1], "exit")
        self.assertEqual(names[4], "write")
        self.assertEqual(names[11], "execve")


class CallTargetTests(unittest.TestCase):
    def _ins(self, address, mnemonic, operands):
        return disasm.Instruction(address=address, mnemonic=mnemonic, operands=operands, size=4, bytes=b"\x00" * 4)

    def test_resolves_relative_targets(self):
        ins = [
            self._ins(0x1000, "mov", "eax, 1"),
            self._ins(0x1005, "call", "0x2000"),
            self._ins(0x100A, "jmp", "0x1500"),
            self._ins(0x100F, "push", "rbp"),
        ]
        targets = disasm.call_targets(ins)
        self.assertEqual(len(targets), 2)
        self.assertEqual(targets[0]["target"], 0x2000)
        self.assertEqual(targets[1]["mnemonic"], "jmp")

    def test_ignores_non_control_flow(self):
        ins = [self._ins(0x1000, "mov", "eax, 0x2000")]
        self.assertEqual(disasm.call_targets(ins), [])

    def test_skips_unparseable_operands(self):
        ins = [self._ins(0x1000, "jmp", "qword ptr [rip+0x10]")]
        self.assertEqual(disasm.call_targets(ins), [])


class ApiResolutionTests(unittest.TestCase):
    def test_finds_getprocaddress_reference(self):
        ins = [disasm.Instruction(address=0x1000, mnemonic="push", operands="VirtualAlloc", size=5, bytes=b"\x00" * 5)]
        found = disasm.find_api_resolution(ins)
        self.assertEqual(found[0]["api"], "VirtualAlloc")

    def test_case_insensitive(self):
        ins = [disasm.Instruction(address=0x1000, mnemonic="push", operands="getprocaddress", size=5, bytes=b"\x00" * 5)]
        self.assertTrue(disasm.find_api_resolution(ins))

    def test_nothing_found(self):
        ins = [disasm.Instruction(address=0x1000, mnemonic="mov", operands="eax, ebx", size=2, bytes=b"\x00" * 2)]
        self.assertEqual(disasm.find_api_resolution(ins), [])


@unittest.skipUnless(HAS_CAPSTONE, "capstone not installed")
class DisassemblyTests(unittest.TestCase):
    def test_disassembles_a_stub(self):
        ins = disasm.disassemble(build_shellcode(), base=0x1000, bits=64)
        self.assertTrue(ins)
        mnemonics = {i.mnemonic for i in ins}
        self.assertIn("syscall", mnemonics)
        self.assertIn("mov", mnemonics)

    def test_addresses_start_at_base(self):
        ins = disasm.disassemble(b"\x90", base=0x400000, bits=64)
        self.assertEqual(ins[0].address, 0x400000)

    def test_limit_is_respected(self):
        ins = disasm.disassemble(build_shellcode(), bits=64, limit=2)
        self.assertEqual(len(ins), 2)

    def test_32_bit_mode(self):
        ins = disasm.disassemble(b"\x90\x90", base=0, bits=32)
        self.assertEqual(len(ins), 2)

    def test_syscall_annotation(self):
        ins = disasm.disassemble(build_shellcode(), bits=64)
        rows = disasm.annotate_syscalls(ins, 64)
        syscalls = [r for r in rows if r.get("syscall")]
        self.assertTrue(syscalls)
        self.assertIn("write", [r["syscall"] for r in syscalls])
        self.assertIn("exit", [r["syscall"] for r in syscalls])

    def test_empty_input(self):
        self.assertEqual(disasm.disassemble(b""), [])


class MissingDependencyTests(unittest.TestCase):
    def test_error_mentions_the_install_command(self):
        err = disasm.MissingDependency("capstone", "disasm", "disassembly")
        self.assertIn("capstone", str(err))
        self.assertIn("[disasm]", str(err))

    def test_error_is_an_import_error(self):
        self.assertIsInstance(disasm.MissingDependency("capstone", "disasm", "x"), ImportError)


if __name__ == "__main__":
    unittest.main()
