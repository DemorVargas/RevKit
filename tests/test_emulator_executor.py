"""Executing code: the CPU loop, syscalls, flags and control flow.

Two conventions keep this file readable:

- Every test that wants a value out of the machine copies it into rbx first.
  rax and rdi are both clobbered by the standard exit sequence, and a test that
  reads a clobbered register looks like an emulator bug when it is not.
- ``hex_()`` joins its arguments, so a sequence of hex strings and a trailing
  KEEP_* constant combine without fragile implicit concatenation.
"""

from __future__ import annotations

import unittest

from revkit.emulator.errors import ExecuteError
from revkit.emulator.executor import Executor, Hooks
from revkit.emulator.runner import emulate, load_shellcode

import helpers

CF = 1 << 0
ZF = 1 << 6
SF = 1 << 7
OF = 1 << 11

# Each KEEP_* copies a register into rbx, then exits cleanly.
KEEP_RAX = "4889c3" "48c7c03c000000" "4831ff" "0f05"  # mov rbx, rax ; exit
KEEP_RDI = "4889fb" "48c7c03c000000" "4831ff" "0f05"  # mov rbx, rdi ; exit
KEEP_RSI = "4889f3" "48c7c03c000000" "4831ff" "0f05"  # mov rbx, rsi ; exit
KEEP_RCX = "4889cb" "48c7c03c000000" "4831ff" "0f05"  # mov rbx, rcx ; exit
EXIT = "48c7c03c000000" "4831ff" "0f05"

# open(path at 0x2000) then read 18 bytes into 0x3000, using whatever VFS the run
# was given. Shared by the filesystem tests below.
OPEN_READ = (
    "488d3df90f0000",  # lea rdi, [rip+0xff9] -> 0x2000, the path
    "48c7c002000000",  # mov rax, 2 (open)
    "48c7c600000000",  # mov rsi, 0 (O_RDONLY)
    "4831d2",          # xor rdx, rdx
    "0f05",
    "4889c7",          # mov rdi, rax, the fd
    "488d35dc1f0000",  # lea rsi, [rip+0x1fdc] -> 0x3000, the buffer
    "48c7c212000000",  # mov rdx, 18
    "48c7c000000000",  # mov rax, 0 (read)
    "0f05",
)


def hex_(*parts) -> bytes:
    """Join hex strings and KEEP_* constants into one byte string."""
    return bytes.fromhex("".join(parts))


def run(*parts, **kwargs):
    """Emulate a code blob built from hex strings and KEEP_* constants."""
    code = parts[0] if len(parts) == 1 else hex_(*parts)
    if isinstance(code, str):
        code = hex_(code)
    return emulate(code, **kwargs)


class OutputTests(unittest.TestCase):
    WRITE = "48c7c001000000" "48c7c701000000" "48c7c600200000" "48c7c20d000000" "0f05"

    def test_write_and_exit(self):
        code = hex_(self.WRITE, EXIT)
        machine = load_shellcode(code)
        machine.mem.write(0x2000, b"hello, world!")
        result = run(code, machine=machine)
        self.assertEqual(result.output, b"hello, world!")
        self.assertEqual(result.exit_code, 0)
        self.assertEqual([s.name for s in result.syscalls], ["write", "exit"])

    def test_write_to_stderr_is_captured_too(self):
        code = hex_(
            "48c7c001000000",  # mov rax, 1
            "48c7c702000000",  # mov rdi, 2
            "48c7c600200000",  # mov rsi, 0x2000
            "48c7c204000000",  # mov rdx, 4
            "0f05",
            EXIT,
        )
        machine = load_shellcode(code)
        machine.mem.write(0x2000, b"err!")
        self.assertEqual(run(code, machine=machine).output, b"err!")

    def test_write_returns_the_count(self):
        self.assertEqual(run(self.WRITE, EXIT).syscalls[0].result, 13)

    def test_result_str_reports_the_shape(self):
        text = str(run(self.WRITE, EXIT))
        for fragment in ("steps:", "syscalls:", "exit:", "write"):
            self.assertIn(fragment, text)


class ArithmeticTests(unittest.TestCase):
    def test_add(self):
        self.assertEqual(run("b805000000", "83c003", KEEP_RAX).registers["rbx"], 8)

    def test_sub_sets_zero_flag(self):
        result = run("b805000000", "83e805", KEEP_RAX)
        self.assertTrue(result.flags & ZF)
        self.assertEqual(result.registers["rbx"], 0)

    def test_sub_sets_carry_when_borrowing(self):
        result = run("b800000000", "83e801", KEEP_RAX)
        # Stop after the sub: the exit sequence's xor would rewrite the flags.
        flags = run("b800000000", "83e801", max_steps=2).flags
        self.assertTrue(flags & CF)
        self.assertTrue(flags & SF)
        self.assertEqual(result.registers["rbx"], 0xFFFFFFFF)

    def test_cmp_does_not_write_its_result(self):
        code = hex_(
            "48c7c70a000000",  # mov rdi, 10
            "48c7c614000000",  # mov rsi, 20
            "4839f7",          # cmp rdi, rsi
            KEEP_RDI,
        )
        self.assertEqual(run(code).registers["rbx"], 10)

    def test_cmp_sets_sign_flag(self):
        code = hex_("48c7c70a000000", "48c7c614000000", "4839f7")
        self.assertTrue(run(code, max_steps=3).flags & SF)

    def test_and_clears_flags(self):
        result = run("b800000000", "21c0", KEEP_RAX)
        self.assertFalse(result.flags & CF)
        self.assertFalse(result.flags & OF)
        self.assertTrue(result.flags & ZF)

    def test_xor_clears_the_register(self):
        result = run("48c7c02a000000", "4831c0", KEEP_RAX)
        self.assertEqual(result.registers["rbx"], 0)
        self.assertTrue(result.flags & ZF)

    def test_inc_and_dec_are_inverses(self):
        result = run("48c7c005000000", "48ffc0", "48ffc8", KEEP_RAX)
        self.assertEqual(result.registers["rbx"], 5)

    def test_neg(self):
        result = run("48c7c005000000", "f7d8", KEEP_RAX)
        self.assertEqual(result.registers["rbx"], 0xFFFFFFFB)

    def test_not(self):
        result = run("48c7c000000000", "48f7d0", KEEP_RAX)
        self.assertEqual(result.registers["rbx"], (1 << 64) - 1)

    def test_shl(self):
        self.assertEqual(run("48c7c010000000", "48c1e004", KEEP_RAX).registers["rbx"], 0x100)

    def test_shr(self):
        # rax = 0x1000000, shifted right by 16, leaves 0x100.
        self.assertEqual(run("48b80000000100000000", "48c1e810", KEEP_RAX).registers["rbx"], 0x100)

    def test_sar_preserves_the_sign(self):
        code = hex_(
            "48c7c000000000",  # mov rax, 0
            "4883e810",        # sub rax, 0x10
            "48c1f804",        # sar rax, 4
            KEEP_RAX,
        )
        self.assertEqual(run(code).registers["rbx"], (1 << 64) - 1)

    def test_mul(self):
        code = hex_(
            "48c7c00a000000",  # mov rax, 10
            "48c7c203000000",  # mov rdx, 3
            "48f7e2",          # mul rdx
            KEEP_RAX,
        )
        self.assertEqual(run(code).registers["rbx"], 30)

    def test_imul_three_operand(self):
        code = hex_(
            "48c7c00a000000",  # mov rax, 10
            "48c7c203000000",  # mov rdx, 3
            "480fafc2",        # imul rax, rdx
            KEEP_RAX,
        )
        self.assertEqual(run(code).registers["rbx"], 30)

    def test_div(self):
        code = hex_(
            "48c7c01e000000",  # mov rax, 30
            "48c7c203000000",  # mov rdx, 3
            "48f7f2",          # div rdx -> rax = 10
            KEEP_RAX,
        )
        self.assertEqual(run(code).registers["rbx"], 10)

    def test_division_by_zero_is_reported(self):
        code = hex_("48c7c001000000", "48c7c200000000", "48f7f2", KEEP_RAX)
        result = run(code)
        self.assertTrue(result.errors)
        self.assertIn("division by zero", result.errors[0])

    def test_bswap(self):
        # mov rax, 0x0102030405060708 ; bswap rax -> 0x0807060504030201
        code = hex_("48b80807060504030201", "480fc8", KEEP_RAX)
        self.assertEqual(run(code).registers["rbx"], 0x0807060504030201)

    def test_movzx_zero_extends(self):
        code = hex_("48c7c0ffffffff", "0fb6c0", KEEP_RAX)  # movzx eax, al
        self.assertEqual(run(code).registers["rbx"], 0xFF)

    def test_movsx_sign_extends(self):
        code = hex_("48c7c0ffffffff", "480fbfc0", KEEP_RAX)  # movsx rax, al
        self.assertEqual(run(code).registers["rbx"], 0xFFFFFFFFFFFFFFFF)


class ControlFlowTests(unittest.TestCase):
    def test_loop_counts_down(self):
        code = hex_(
            "48c7c105000000",  # mov rcx, 5
            "48c7c000000000",  # mov rax, 0
            "48ffc0",          # inc rax
            "48ffc9",          # dec rcx
            "75f8",            # jnz -8
            KEEP_RAX,
        )
        self.assertEqual(run(code).registers["rbx"], 5)

    def test_jrcxz_taken_when_rcx_is_zero(self):
        code = hex_(
            "48c7c001000000",  # mov rax, 1
            "4831c9",          # xor rcx, rcx
            "e303",            # jrcxz +3
            "48ffc0",          # inc rax  (skipped)
            KEEP_RAX,
        )
        self.assertEqual(run(code).registers["rbx"], 1)

    def test_jrcxz_not_taken(self):
        code = hex_(
            "48c7c001000000",  # mov rax, 1
            "48c7c101000000",  # mov rcx, 1
            "e303",            # jrcxz +3
            "48ffc0",          # inc rax
            KEEP_RAX,
        )
        self.assertEqual(run(code).registers["rbx"], 2)

    def test_call_and_ret(self):
        code = hex_(
            "48c7c000000000",  # 0x1000  mov rax, 0
            "e81b000000",      # 0x1007  call 0x1027
            KEEP_RAX,          # 0x100c  where the call returns to
            EXIT,              # 0x101b
            "4883c064",        # 0x1027  add rax, 100
            "c3",              # 0x102b  ret
        )
        self.assertEqual(run(code).registers["rbx"], 100)

    def test_ret_pops_the_return_address(self):
        code = hex_(
            "48c7c005000000",  # mov rax, 5
            "50",              # push rax
            "4883c001",        # add rax, 1
            "58",              # pop rax
            KEEP_RAX,
        )
        self.assertEqual(run(code).registers["rbx"], 5)

    def test_push_and_pop_roundtrip(self):
        self.assertEqual(run("68efbeadde", "5f", KEEP_RDI).registers["rbx"], 0xDEADBEEF)

    def test_jump_forward_skips_instructions(self):
        code = hex_(
            "eb0c",            # jmp +12
            "48ffc0", "48ffc0", "48ffc0", "48ffc0",  # four incs, all skipped
            KEEP_RAX,
        )
        self.assertEqual(run(code).registers["rbx"], 0)

    def test_infinite_loop_hits_the_step_limit(self):
        code = hex_("48c7c000000000", "ebfe")  # jmp $
        result = run(code, max_steps=500)
        self.assertTrue(result.errors)
        self.assertIn("step limit", result.errors[0])


class MemoryAccessTests(unittest.TestCase):
    def test_store_and_load_through_a_pointer(self):
        code = hex_(
            "48c7c000300000",  # mov rax, 0x3000
            "48c7c72a000000",  # mov rdi, 42
            "488938",          # mov [rax], rdi
            "488b30",          # mov rsi, [rax]
            KEEP_RSI,
        )
        self.assertEqual(run(code).registers["rbx"], 42)

    def test_rip_relative_load(self):
        code = hex_("488d3520000000", "8a06", KEEP_RAX)  # lea rsi,[rip+0x20]; mov al,[rsi]
        machine = load_shellcode(code)
        # The lea is 7 bytes, so rip+0x20 lands clear of the rest of the code.
        machine.mem.write(0x1000 + 7 + 0x20, b"\x42")
        self.assertEqual(run(code, machine=machine).registers["rbx"], 0x42)

    def test_byte_store_only_touches_one_byte(self):
        code = hex_(
            "48c7c000300000",  # mov rax, 0x3000
            "48c700ffffffff",  # mov qword [rax], -1
            "c60000",          # mov byte [rax], 0
            "488b30",          # mov rsi, [rax]
            KEEP_RSI,
        )
        self.assertEqual(run(code).registers["rbx"], 0xFFFFFFFFFFFFFF00)

    def test_scaled_index_addressing(self):
        code = hex_(
            "48c7c700300000",  # mov rdi, 0x3000
            "48c7c101000000",  # mov rcx, 1
            "488b7c0f08",      # mov rdi, [rdi + rcx + 8]
            KEEP_RDI,
        )
        machine = load_shellcode(code)
        machine.mem.write_u64(0x3000 + 1 + 8, 0xAB)
        self.assertEqual(run(code, machine=machine).registers["rbx"], 0xAB)

    def test_negative_displacement(self):
        code = hex_(
            "48c7c700300000",    # mov rdi, 0x3000
            "48c747f82a000000",  # mov [rdi-8], 42
            "488b47f8",          # mov rax, [rdi-8]
            KEEP_RAX,
        )
        self.assertEqual(run(code).registers["rbx"], 42)


class DecodeLoopTests(unittest.TestCase):
    def test_xor_decode_loop(self):
        code = hex_(
            "48c7c108000000",  # mov rcx, 8
            "48c7c600300000",  # mov rsi, 0x3000
            "803642",          # xor byte [rsi], 0x42
            "48ffc6",          # inc rsi
            "48ffc9",          # dec rcx
            "75f5",            # jnz -11
            EXIT,
        )
        machine = load_shellcode(code)
        machine.mem.write(0x3000, b"top secret")
        run(code, machine=machine)
        decoded = machine.mem.read(0x3000, 11)
        self.assertEqual(decoded[:8], bytes(a ^ 0x42 for a in b"top secret"[:8]))
        self.assertEqual(decoded[8:], b"et\x00")

    def test_loop_writes_a_string(self):
        code = hex_(
            "48c7c108000000",  # mov rcx, 8
            "48c7c600300000",  # mov rsi, 0x3000
            "c60641",          # mov byte [rsi], 'A'
            "48ffc6",          # inc rsi
            "48ffc9",          # dec rcx
            "75f5",            # jnz -11
            "48c7c001000000",  # mov rax, 1 (write)
            "48c7c701000000",  # mov rdi, 1
            "48c7c600300000",  # mov rsi, 0x3000
            "48c7c208000000",  # mov rdx, 8
            "0f05",
            EXIT,
        )
        self.assertEqual(run(code).output, b"A" * 8)

    def test_string_is_decoded_before_being_written(self):
        code = hex_(
            "48c7c105000000",  # mov rcx, 5
            "48c7c600300000",  # mov rsi, 0x3000
            "80365a",          # xor byte [rsi], 0x5a
            "48ffc6", "48ffc9", "75f5",
            "48c7c001000000", "48c7c701000000", "48c7c600300000", "48c7c205000000", "0f05",
            EXIT,
        )
        machine = load_shellcode(code)
        machine.mem.write(0x3000, bytes(a ^ 0x5A for a in b"hello"))
        self.assertEqual(run(code, machine=machine).output, b"hello")


class SyscallTests(unittest.TestCase):
    def test_exit_code_is_captured(self):
        result = run("48c7c03c000000", "48c7c740000000", "0f05")
        self.assertEqual(result.exit_code, 0x40)

    def test_exit_group_works_too(self):
        result = run("48c7c0e7000000", "48c7c72a000000", "0f05")
        self.assertEqual(result.exit_code, 42)

    def test_identity_syscalls_return_something(self):
        code = hex_(
            "b827000000", "0f05",  # getpid
            "b866000000", "0f05",  # getuid
            "b869000000", "0f05",  # getppid
            EXIT,
        )
        result = run(code)
        for call in result.syscalls[:3]:
            self.assertGreaterEqual(call.result, 0)

    def test_mmap_gives_a_writable_region(self):
        code = hex_(
            "48c7c009000000",  # mov rax, 9 (mmap)
            "4831ff",          # xor rdi, rdi
            "48c7c600100000",  # mov rsi, 0x1000
            "48c7c203000000",  # mov rdx, 3
            "49c7c222000000",  # mov r10, 0x22
            "49c7c0ffffffff",  # mov r8, -1
            "49c7c1ffffffff",  # mov r9, -1
            "0f05",
            "4889c6",          # mov rsi, rax
            "48c7062a000000",  # mov qword [rsi], 42
            "488b06",          # mov rax, [rsi]
            KEEP_RAX,
        )
        result = run(code)
        self.assertEqual(result.syscalls[0].name, "mmap")
        self.assertGreater(result.syscalls[0].result, 0)
        self.assertEqual(result.registers["rbx"], 42)

    def test_mmap_is_zero_filled(self):
        code = hex_(
            "48c7c009000000", "4831ff", "48c7c600100000", "48c7c203000000",
            "49c7c222000000", "49c7c0ffffffff", "49c7c1ffffffff", "0f05",
            "488b00",  # mov rax, [rax]
            KEEP_RAX,
        )
        self.assertEqual(run(code).registers["rbx"], 0)

    def test_blocked_syscall_returns_enosys(self):
        code = hex_("b827000000", "0f05", EXIT)
        machine = load_shellcode(code)
        executor = Executor(machine)
        executor.block_syscall(39)  # getpid
        executor.run()
        self.assertEqual(executor.syscalls[0].result, -38)

    def test_blocked_mnemonic_stops_the_run(self):
        code = hex_("cc", EXIT)
        machine = load_shellcode(code)
        executor = Executor(machine)
        executor.block_mnemonic("int3")
        with self.assertRaises(ExecuteError):
            executor.run()

    def test_read_comes_from_the_vfs(self):
        from revkit.emulator.vfs import Vfs

        code = hex_(*OPEN_READ, EXIT)
        machine = load_shellcode(code)
        machine.mem.write(0x2000, b"/tmp/payload.bin\x00")
        machine.mem.write(0x3000, b"\x00" * 32)
        fs = Vfs.default()
        fs.add("/tmp/payload.bin", b"file contents here")
        result = run(code, machine=machine, vfs=fs)
        read_call = [s for s in result.syscalls if s.name == "read"]
        self.assertTrue(read_call)
        self.assertEqual(read_call[0].result, 18)
        self.assertEqual(machine.mem.read(0x3000, 18), b"file contents here")

    def test_a_host_path_is_not_reachable(self):
        # The point of the VFS. /etc/shadow exists on this machine and must stay
        # invisible to the guest; this used to open and read the real file.
        import os

        if not os.path.exists("/etc/shadow"):
            self.skipTest("no /etc/shadow on this machine")
        code = hex_(*OPEN_READ, EXIT)
        machine = load_shellcode(code)
        machine.mem.write(0x2000, b"/etc/shadow\x00")
        result = run(code, machine=machine)
        self.assertEqual(result.syscalls[0].name, "open")
        self.assertEqual(result.syscalls[0].result, -2)

    def test_a_write_lands_in_the_vfs(self):
        # A dropper writing a file must leave something to look at afterwards.
        from revkit.emulator.vfs import Vfs

        code = hex_(
            "488d3df90f0000",  # lea rdi, [rip+0xff9] -> 0x2000, the path
            "48c7c002000000",  # mov rax, 2 (open)
            "48c7c641000000",  # mov rsi, 0x41 (O_WRONLY|O_CREAT)
            "48c7c21a040000",  # mov rdx, 0x41a (mode)
            "0f05",
            "4889c7",          # mov rdi, rax, the fd
            "488d35d81f0000",  # lea rsi, [rip+0x1fd8] -> 0x3000, the data
            "48c7c204000000",  # mov rdx, 4
            "48c7c001000000",  # mov rax, 1 (write)
            "0f05",
            EXIT,
        )
        machine = load_shellcode(code)
        machine.mem.write(0x2000, b"/tmp/dropped\x00")
        machine.mem.write(0x3000, b"evil")
        fs = Vfs.default()
        run(code, machine=machine, vfs=fs)
        self.assertEqual(fs.read("/tmp/dropped", 16), b"evil")

    def test_read_advances_instead_of_restarting(self):
        # Reading used to start at offset zero on every call, so a stub looping on
        # read was handed the same bytes forever. Three 4-byte reads of a 10-byte
        # file must come back 4, 4, 2.
        from revkit.emulator.vfs import Vfs

        code = hex_(
            "488d3df90f0000",  # lea rdi, [rip+0xff9] -> 0x2000, the path
            "48c7c002000000",  # mov rax, 2 (open)
            "48c7c600000000",  # mov rsi, 0
            "4831d2",          # xor rdx, rdx
            "0f05",
            "4889c7",          # mov rdi, rax, the fd
            "48c7c103000000",  # mov rcx, 3
            "488d35d51f0000",  # 0x1024  lea rsi, [rip+0x1fd5] -> 0x3000
            "48c7c204000000",  # mov rdx, 4
            "48c7c000000000",  # mov rax, 0 (read)
            "0f05",
            "48ffc9",          # dec rcx
            "75e4",            # jnz 0x1024
            EXIT,
        )
        machine = load_shellcode(code)
        machine.mem.write(0x2000, b"/tmp/ten\x00")
        fs = Vfs.default()
        fs.add("/tmp/ten", b"0123456789")
        result = run(code, machine=machine, vfs=fs)
        reads = [s.result for s in result.syscalls if s.name == "read"]
        self.assertEqual(reads, [4, 4, 2])

    def test_uname_fills_the_buffer(self):
        # The buffer has to sit clear of the code, which runs to about 0x1013.
        buf = 0x2000
        code = hex_(
            "48bf" + buf.to_bytes(8, "little").hex(),  # mov rdi, 0x2000
            "48c7c03f000000",  # mov rax, 63 (uname)
            "0f05",
            KEEP_RAX,
        )
        machine = load_shellcode(code)
        machine.mem.write(buf, b"\x00" * 400)
        result = run(code, machine=machine)
        self.assertEqual(result.syscalls[0].name, "uname")
        self.assertEqual(machine.mem.read_cstring(buf), "Linux")


class NetworkTests(unittest.TestCase):
    """The sinkhole: connects succeed, sends are captured, nothing leaves."""

    def test_sockaddr_in_renders_as_ip_and_port(self):
        import struct

        from revkit.emulator.memory import Memory
        from revkit.emulator.net import parse_sockaddr

        mem = Memory()
        sa = struct.pack("<H", 2) + struct.pack("!H", 4444) + bytes([203, 0, 113, 9]) + b"\x00" * 8
        mem.write(0x2000, sa)
        self.assertEqual(parse_sockaddr(mem, 0x2000, len(sa)), "203.0.113.9:4444")

    def test_sockaddr_in6_renders_too(self):
        import struct

        from revkit.emulator.memory import Memory
        from revkit.emulator.net import parse_sockaddr

        mem = Memory()
        sa = struct.pack("<H", 10) + struct.pack("!H", 443) + struct.pack("!I", 0) + bytes(range(16))
        mem.write(0x2000, sa)
        self.assertTrue(parse_sockaddr(mem, 0x2000, len(sa)).endswith("]:443"))

    def test_a_missing_address_does_not_raise(self):
        from revkit.emulator.memory import Memory
        from revkit.emulator.net import parse_sockaddr

        self.assertEqual(parse_sockaddr(Memory(), 0, 0), "?")

    def test_connect_succeeds_and_remembers_the_peer(self):
        from revkit.emulator.net import Network

        net = Network()
        self.assertEqual(net.connect(3, "1.2.3.4:80"), 0)
        self.assertEqual(net.peers[3], "1.2.3.4:80")

    def test_send_is_captured_against_the_peer(self):
        from revkit.emulator.net import Network

        net = Network()
        net.connect(3, "1.2.3.4:80")
        self.assertEqual(net.send(3, b"GET / HTTP/1.0\r\n"), 16)
        self.assertEqual(net.flows[0].peer, "1.2.3.4:80")
        self.assertEqual(net.flows[0].data, b"GET / HTTP/1.0\r\n")

    def test_a_beacon_gets_its_traffic_captured(self):
        # socket, connect, then write to the socket. glibc sends through write()
        # on a connected socket, so that is the path a payload really travels.
        code = helpers.build_beacon("203.0.113.9", 4444, b"ping")
        result = run(code)

        self.assertEqual(result.syscalls[1].name, "connect")
        self.assertEqual(result.syscalls[1].result, 0)  # the sinkhole accepts
        self.assertEqual(len(result.traffic), 1)
        self.assertEqual(result.traffic[0].peer, "203.0.113.9:4444")
        self.assertEqual(result.traffic[0].data, b"ping")

    def test_sendto_captures_the_payload_and_the_peer(self):
        # sendto carries the address itself, which is how a stub that never
        # connects, a DNS lookup or a UDP beacon, gets its traffic recorded.
        import struct

        code = hex_(
            "48c7c029000000",  # mov rax, 41 (socket)
            "48c7c702000000",  # mov rdi, 2 (AF_INET)
            "48c7c602000000",  # mov rsi, 2 (SOCK_DGRAM)
            "4831d2",          # xor rdx, rdx
            "0f05",
            "4989c4",          # mov r12, rax, keep the fd
            "4c89e7",          # mov rdi, r12
            "488d35d90f0000",  # 0x1020  lea rsi, [rip+0xfd9] -> 0x2000, the payload
            "48c7c204000000",  # mov rdx, 4
            "49c7c200000000",  # mov r10, 0 (flags)
            "49c7c020200000",  # mov r8, 0x2020, the sockaddr
            "49c7c110000000",  # mov r9, 16, its length
            "48c7c02c000000",  # mov rax, 44 (sendto)
            "0f05",
            EXIT,
        )
        machine = load_shellcode(code)
        sa = struct.pack("<H", 2) + struct.pack("!H", 53) + bytes([8, 8, 8, 8]) + b"\x00" * 8
        machine.mem.write(0x2000, b"\xde\xad\xbe\xef")
        machine.mem.write(0x2020, sa)
        result = run(code, machine=machine)

        self.assertEqual(len(result.traffic), 1)
        self.assertEqual(result.traffic[0].peer, "8.8.8.8:53")
        self.assertEqual(result.traffic[0].data, b"\xde\xad\xbe\xef")


class ErrorTests(unittest.TestCase):
    def test_step_limit_stops_the_run(self):
        result = run("ebfe", max_steps=100)  # jmp $
        self.assertTrue(result.errors)
        self.assertIn("step limit", result.errors[0])

    def test_unimplemented_opcode_stops_with_a_reason(self):
        result = run(bytes.fromhex("06"))
        self.assertTrue(result.errors)
        self.assertIn("not implemented", result.errors[0])

    def test_int3_reports_through_the_error_list(self):
        result = run("cc")
        self.assertTrue(result.errors)
        self.assertIn("int3", result.errors[0])

    def test_execve_is_refused(self):
        result = run("b83b000000", "0f05")
        self.assertTrue(result.errors)
        self.assertIn("execve", result.errors[0])

    def test_decode_failure_names_the_address(self):
        result = run(bytes.fromhex("06"), max_steps=10)
        self.assertTrue(result.errors)
        self.assertIn("0x", result.errors[0])


class TraceAndHooksTests(unittest.TestCase):
    def test_trace_records_each_instruction(self):
        result = run("48c7c001000000", "4831ff", "48c7c03c000000", "4831ff", "0f05", trace=True)
        mnemonics = [e.mnemonic for e in result.trace]
        self.assertIn("mov", mnemonics)
        self.assertIn("syscall", mnemonics)

    def test_trace_entry_carries_the_text_form(self):
        result = run("48c7c001000000", EXIT, trace=True)
        self.assertEqual(result.trace[0].mnemonic, "mov")
        self.assertIn("mov", result.trace[0].text)

    def test_hook_sees_syscalls(self):
        seen = []

        class Recorder(Hooks):
            def on_syscall(self, machine, number, name, args):
                seen.append(name)

        run("b827000000", "0f05", EXIT, hooks=Recorder())
        self.assertEqual(seen, ["getpid", "exit"])

    def test_hook_sees_memory_writes(self):
        writes = []

        class Recorder(Hooks):
            def on_write(self, machine, addr, data):
                writes.append((addr, data))

        run("48c7c000300000", "48c7c72a000000", "488938", EXIT, hooks=Recorder())
        self.assertIn((0x3000, (42).to_bytes(8, "little")), writes)

    def test_hook_can_block_a_syscall_by_raising(self):
        class Blocker(Hooks):
            def on_syscall(self, machine, number, name, args):
                if name == "getpid":
                    raise ExecuteError("blocked by hook", pc=machine.rip)

        result = run("b827000000", "0f05", hooks=Blocker())
        self.assertTrue(result.errors)
        self.assertIn("blocked by hook", result.errors[0])


class StackLayoutTests(unittest.TestCase):
    def test_argv_is_laid_out_for_the_stub(self):
        machine = load_shellcode(b"\xc3", argv=["prog", "arg1"], envp={"PATH": "/bin"})
        argc = machine.mem.read_u64(machine.r("rsp"))
        self.assertEqual(argc, 2)
        first = machine.mem.read_u64(machine.r("rsp") + 8)
        self.assertEqual(machine.mem.read_cstring(first), "prog")

    def test_envp_is_laid_out(self):
        machine = load_shellcode(b"\xc3", argv=["prog"], envp={"FOO": "bar"})
        argc = machine.mem.read_u64(machine.r("rsp"))
        env_ptr = machine.mem.read_u64(machine.r("rsp") + 8 * (argc + 2))
        self.assertEqual(machine.mem.read_cstring(env_ptr), "FOO=bar")

    def test_rdi_holds_argc(self):
        self.assertEqual(load_shellcode(b"\xc3", argv=["a", "b", "c"]).r("rdi"), 3)

    def test_stack_grows_down_from_the_requested_top(self):
        machine = load_shellcode(b"\xc3", stack=0x9000, argv=["x"])
        self.assertLess(machine.r("rsp"), 0x9000)

    def test_entry_defaults_to_base(self):
        self.assertEqual(load_shellcode(b"\xc3").rip, 0x1000)

    def test_stub_can_read_argc_from_the_stack(self):
        # mov rbx, [rsp] picks up argc; the exit sequence never touches rbx.
        result = run("488b1c24", EXIT, argv=["prog", "arg1"])
        self.assertEqual(result.registers["rbx"], 2)


class SnapshotHooksTests(unittest.TestCase):
    def test_captures_changes_in_a_region(self):
        from revkit.emulator.runner import SnapshotHooks

        hooks = SnapshotHooks(regions=[(0x3000, 0x3010)])
        run("48c7c000300000", "48c7c72a000000", "488938", EXIT, hooks=hooks)
        self.assertTrue(hooks.changes)
        self.assertEqual(hooks.changes[0][1], (42).to_bytes(8, "little"))

    def test_ignores_writes_outside_the_region(self):
        from revkit.emulator.runner import SnapshotHooks

        hooks = SnapshotHooks(regions=[(0x9000, 0x9010)])
        run("48c7c000300000", "48c7c72a000000", "488938", EXIT, hooks=hooks)
        self.assertEqual(hooks.changes, [])


if __name__ == "__main__":
    unittest.main()
