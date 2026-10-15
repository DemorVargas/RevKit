"""The CPU. Decoded instructions go in, machine state comes out.

`run()` is the loop. `decode()` raises on anything it does not know, so an
unimplemented opcode stops the run with a reason instead of quietly corrupting
state.

Syscalls are modelled, not real: `write` appends to a buffer you can read back,
`mmap` hands out addresses in a synthetic space, and the filesystem is a dict in
`vfs.py` rather than yours. Nothing here reaches the host, so it is safe to point
at code you do not trust.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field

from .decoder import AF, CF, DF, IF, OF, PF, SF, ZF, Decoder, Insn, Machine, Operand
from .errors import ExecuteError
from .net import Network, parse_sockaddr
from .vfs import Vfs

# Where synthetic mmap regions are handed out from, well clear of anything a
# stub would place itself.
MMAP_BASE = 0x10000000
MMAP_LIMIT = 0x7F000000
BRK_START = 0x400000

SYSCALL_NAMES = {
    0: "read", 1: "write", 2: "open", 3: "close", 4: "stat", 5: "fstat", 6: "lstat",
    7: "poll", 8: "lseek", 9: "mmap", 10: "mprotect", 11: "munmap", 12: "brk",
    13: "rt_sigaction", 14: "rt_sigprocmask", 15: "rt_sigreturn", 16: "ioctl",
    20: "writev", 21: "access", 22: "pipe", 32: "dup", 33: "dup2", 35: "nanosleep",
    39: "getpid", 41: "socket", 42: "connect", 43: "accept", 44: "sendto", 45: "recvfrom",
    46: "sendmsg", 47: "recvmsg", 48: "shutdown", 49: "bind", 50: "listen",
    51: "getsockname", 52: "getpeername", 56: "clone", 57: "fork", 58: "vfork",
    59: "execve", 60: "exit", 61: "wait4", 62: "kill", 63: "uname", 72: "fcntl",
    78: "getdents", 79: "getcwd", 80: "chdir", 82: "rename", 83: "mkdir", 84: "rmdir",
    85: "creat", 87: "unlink", 89: "readlink", 90: "chmod", 92: "chown", 95: "umask",
    96: "gettimeofday", 97: "getrlimit", 102: "getuid", 104: "getgid", 105: "setuid",
    106: "setgid", 107: "geteuid", 108: "getegid", 109: "setpgid", 110: "getppid",
    111: "getpgrp", 158: "arch_prctl", 186: "gettid", 201: "time", 217: "getdents64",
    218: "set_tid_address", 231: "exit_group", 234: "tgkill", 257: "openat",
    262: "newfstatat", 273: "set_robust_list", 302: "prlimit64", 318: "getrandom",
    332: "statx", 334: "rseq",
}

SYSCALL_ARGC = {
    0: 3, 1: 3, 2: 3, 3: 1, 4: 2, 5: 2, 9: 6, 10: 3, 11: 2, 12: 1, 13: 4, 14: 4,
    16: 3, 20: 3, 21: 2, 22: 1, 32: 1, 33: 2, 35: 1, 39: 0, 41: 3, 42: 3, 43: 3,
    44: 6, 45: 6, 46: 3, 47: 3, 48: 2, 49: 3, 50: 2, 51: 3, 52: 3, 56: 4, 57: 0,
    58: 0, 59: 3, 60: 1, 61: 4, 62: 2, 63: 1, 72: 3, 78: 3, 79: 2, 80: 1, 82: 2,
    83: 2, 84: 1, 85: 2, 87: 1, 89: 2, 90: 2, 92: 3, 95: 1, 96: 2, 97: 2, 102: 0,
    104: 0, 105: 1, 106: 1, 107: 0, 108: 0, 109: 2, 110: 0, 111: 0, 158: 2,
    186: 0, 201: 1, 217: 3, 218: 1, 231: 1, 234: 3, 257: 4, 262: 4, 273: 2,
    302: 4, 318: 3, 332: 5, 334: 1,
}

COND_NAMES = {
    "jo": OF, "jno": OF, "jb": CF, "jae": CF, "je": ZF, "jne": ZF, "jbe": CF | ZF,
    "ja": CF | ZF, "js": SF, "jns": SF, "jp": PF, "jnp": PF, "jl": SF | OF,
    "jge": SF | OF, "jle": ZF | SF | OF, "jg": ZF | SF | OF,
}


@dataclass
class SyscallRecord:
    number: int
    name: str
    args: tuple
    result: int
    pc: int


@dataclass
class TraceEntry:
    pc: int
    mnemonic: str
    text: str
    regs_before: dict = field(default_factory=dict)


class Hooks:
    """Callbacks around execution. All of them are optional and all of them may
    raise to stop the emulation."""

    def before_insn(self, machine: Machine, insn: Insn) -> None:
        pass

    def after_insn(self, machine: Machine, insn: Insn) -> None:
        pass

    def on_syscall(self, machine: Machine, number: int, name: str, args: tuple) -> None:
        pass

    def on_read(self, machine: Machine, addr: int, size: int) -> None:
        pass

    def on_write(self, machine: Machine, addr: int, data: bytes) -> None:
        pass


class Executor:
    """Runs instructions against a Machine until it stops or hits a limit."""

    def __init__(self, machine: Machine, *, trace: bool = False, hooks: Hooks | None = None,
                 vfs: Vfs | None = None):
        self.machine = machine
        self.decoder = Decoder(machine.mem, machine.bits)
        self.trace = trace
        self.hooks = hooks or Hooks()
        self.syscalls: list[SyscallRecord] = []
        self.trace_log: list[TraceEntry] = []
        self.output = bytearray()
        self.errors: list[str] = []
        self.exit_code: int | None = None
        self.mmaps: dict[int, int] = {}
        self._next_mmap = MMAP_BASE
        self._brk = BRK_START
        self._files: dict[int, str] = {}
        self._offsets: dict[int, int] = {}
        self._next_fd = 3
        # The guest sees this and nothing else. No host path is ever opened.
        self.fs = vfs if vfs is not None else Vfs.default()
        # Nothing leaves the machine either. Connects succeed, sends are captured.
        self.net = Network()
        self._blocked: set[str] = set()
        self._blocked_syscalls: set[int] = set()

    # --- blocking ---------------------------------------------------------

    def block_syscall(self, number: int) -> None:
        """Refuse a syscall number. Useful for stopping a stub from calling
        something you do not want modelled."""
        self._blocked_syscalls.add(number)

    def block_mnemonic(self, mnemonic: str) -> None:
        self._blocked.add(mnemonic)

    # --- operand access ---------------------------------------------------

    def _addr_of(self, op: Operand, next_rip: int) -> int:
        if op.kind != "mem":
            raise ExecuteError(f"expected a memory operand, got {op.kind}")
        addr = op.disp
        if op.base is not None:
            addr += self.machine.read_reg(op.base, 64)
        if op.index is not None:
            addr += self.machine.read_reg(op.index, 64) * op.scale
        if op.rip_rel:
            addr += next_rip
        return addr & 0xFFFFFFFFFFFFFFFF

    def read_op(self, op, next_rip: int) -> int:
        """Value of an operand. Immediates arrive as bare ints in the list."""
        if isinstance(op, int):
            return op
        if op.kind == "reg":
            return self.machine.read_reg(op.reg, op.size)
        if op.kind == "mem":
            addr = self._addr_of(op, next_rip)
            self.hooks.on_read(self.machine, addr, op.size // 8)
            return int.from_bytes(self.machine.mem.read(addr, op.size // 8), "little")
        raise ExecuteError(f"bad operand kind {op.kind}")

    def write_op(self, op, value: int, next_rip: int) -> None:
        if isinstance(op, int):
            raise ExecuteError("cannot write to an immediate")
        if op.kind == "reg":
            self.machine.write_reg(op.reg, op.size, value)
            return
        if op.kind == "mem":
            addr = self._addr_of(op, next_rip)
            data = (value & ((1 << op.size) - 1)).to_bytes(op.size // 8, "little")
            self.hooks.on_write(self.machine, addr, data)
            self.machine.mem.write(addr, data)
            return
        raise ExecuteError(f"cannot write to a {op.kind} operand")

    # --- flags ------------------------------------------------------------

    def _set_flags(self, result: int, size: int, carry: int, overflow: int) -> None:
        bits = size
        mask = (1 << bits) - 1
        sign = 1 << (bits - 1)
        self.machine.flags &= ~(ZF | SF | CF | OF | PF | AF)
        if (result & mask) == 0:
            self.machine.flags |= ZF
        if result & sign:
            self.machine.flags |= SF
        if carry:
            self.machine.flags |= CF
        if overflow:
            self.machine.flags |= OF
        if bin(result & 0xFF).count("1") % 2 == 0:
            self.machine.flags |= PF

    def _cond(self, name: str) -> bool:
        if name == "jrcxz":
            return self.machine.r("rcx") == 0
        if name.startswith("cmov") or name.startswith("set"):
            name = name[2:] if name.startswith("cmov") else name[3:]
        bits = COND_NAMES.get(name)
        if bits is None:
            raise ExecuteError(f"unknown condition {name}")
        flags = self.machine.flags
        # Conditions that test a single flag, and the ones that combine.
        if name in ("jo",):
            return bool(flags & OF)
        if name in ("jno",):
            return not (flags & OF)
        if name in ("jb", "jc"):
            return bool(flags & CF)
        if name in ("jae", "jnb"):
            return not (flags & CF)
        if name in ("je", "jz"):
            return bool(flags & ZF)
        if name in ("jne", "jnz"):
            return not (flags & ZF)
        if name in ("js",):
            return bool(flags & SF)
        if name in ("jns",):
            return not (flags & SF)
        if name in ("jp",):
            return bool(flags & PF)
        if name in ("jnp",):
            return not (flags & PF)
        if name in ("jbe",):
            return bool(flags & (CF | ZF))
        if name in ("ja",):
            return not (flags & (CF | ZF))
        if name in ("jl",):
            return bool((flags & SF) != (flags & OF))
        if name in ("jge",):
            return (flags & SF) == (flags & OF)
        if name in ("jle",):
            return bool(flags & ZF) or ((flags & SF) != (flags & OF))
        if name in ("jg",):
            return not (flags & ZF) and ((flags & SF) == (flags & OF))
        return False

    # --- run loop ---------------------------------------------------------

    def run(self, start: int | None = None, *, max_steps: int | None = None) -> Machine:
        m = self.machine
        if start is not None:
            m.rip = start
        m.running = True
        limit = max_steps if max_steps is not None else m.max_steps

        while m.running:
            if m.steps >= limit:
                raise ExecuteError(f"step limit of {limit} reached at {m.rip:#x}", pc=m.rip)
            pc = m.rip
            try:
                insn = self.decoder.decode(pc)
            except Exception as exc:
                raise ExecuteError(f"decode failed at {pc:#x}: {exc}", pc=pc) from exc

            if insn.mnemonic in self._blocked:
                raise ExecuteError(f"{insn.mnemonic} is blocked at {pc:#x}", pc=pc)

            if self.trace:
                self.trace_log.append(
                    TraceEntry(pc=pc, mnemonic=insn.mnemonic, text=self.disasm_text(insn),
                               regs_before=dict(m.regs))
                )

            self.hooks.before_insn(m, insn)
            next_rip = self._execute(insn)
            self.hooks.after_insn(m, insn)
            m.rip = next_rip
            m.steps += 1

        return m

    def disasm_text(self, insn: Insn) -> str:
        parts = []
        for op in insn.operands:
            if isinstance(op, int):
                parts.append(f"{op:#x}")
            elif op.kind == "reg":
                parts.append(self.machine.name_for(op.reg, op.size))
            elif op.kind == "mem":
                inner = ""
                if op.base is not None:
                    inner += self.machine.name_for(op.base, 64)
                if op.index is not None:
                    inner += ("+" if inner else "") + self.machine.name_for(op.index, 64)
                    if op.scale != 1:
                        inner += f"*{op.scale}"
                if op.disp or not inner:
                    inner += ("+" if inner and op.disp >= 0 else "") + f"{op.disp:#x}"
                parts.append("[" + inner + "]")
            else:
                parts.append(str(op))
        return f"{insn.mnemonic} " + ", ".join(parts) if parts else insn.mnemonic

    # --- one instruction --------------------------------------------------

    def _execute(self, insn: Insn) -> int:
        m = self.machine
        name = insn.mnemonic
        ops = insn.operands
        nxt = insn.next_rip

        # Stack
        if name == "push":
            value = self.read_op(ops[0], nxt)
            m.w("rsp", m.r("rsp") - 8)
            m.mem.write_u64(m.r("rsp"), value)
            return nxt
        if name == "pop":
            value = m.mem.read_u64(m.r("rsp"))
            m.w("rsp", m.r("rsp") + 8)
            self.write_op(ops[0], value, nxt)
            return nxt
        if name == "call":
            target = self.read_op(ops[0], nxt)
            m.w("rsp", m.r("rsp") - 8)
            m.mem.write_u64(m.r("rsp"), nxt)
            return target & 0xFFFFFFFFFFFFFFFF
        if name == "ret":
            target = m.mem.read_u64(m.r("rsp"))
            m.w("rsp", m.r("rsp") + 8 + (ops[0] if ops and isinstance(ops[0], int) else 0))
            return target & 0xFFFFFFFFFFFFFFFF

        # Jumps
        if name == "jmp":
            return self.read_op(ops[0], nxt) & 0xFFFFFFFFFFFFFFFF
        if name.startswith("j") or name == "jrcxz":
            return self.read_op(ops[0], nxt) if self._cond(name) else nxt
        if name == "jrcxz":
            return nxt

        # Data movement
        if name == "mov":
            self.write_op(ops[0], self.read_op(ops[1], nxt), nxt)
            return nxt
        if name == "movsxd":
            value = self.read_op(ops[1], nxt)
            if value & 0x80000000:
                value -= 1 << 32
            self.write_op(ops[0], value, nxt)
            return nxt
        if name == "movzx":
            self.write_op(ops[0], self.read_op(ops[1], nxt), nxt)
            return nxt
        if name == "movsx":
            value = self.read_op(ops[1], nxt)
            src_bits = ops[1].size
            if value & (1 << (src_bits - 1)):
                value -= 1 << src_bits
            self.write_op(ops[0], value, nxt)
            return nxt
        if name == "lea":
            op = ops[1]
            if op.kind != "mem":
                raise ExecuteError("lea needs a memory operand")
            self.write_op(ops[0], self._addr_of(op, nxt), nxt)
            return nxt
        if name == "xchg":
            a = self.read_op(ops[0], nxt)
            b = self.read_op(ops[1], nxt)
            self.write_op(ops[0], b, nxt)
            self.write_op(ops[1], a, nxt)
            return nxt

        # Arithmetic
        if name in ("add", "adc", "sub", "sbb", "and", "or", "xor", "cmp"):
            return self._arith(name, ops, nxt)
        if name in ("inc", "dec"):
            value = self.read_op(ops[0], nxt)
            size = ops[0].size
            mask = (1 << size) - 1
            if name == "inc":
                result = (value + 1) & mask
            else:
                result = (value - 1) & mask
            self._set_flags(result, size, 0, 0)
            self.write_op(ops[0], result, nxt)
            return nxt
        if name in ("not", "neg"):
            value = self.read_op(ops[0], nxt)
            size = ops[0].size
            mask = (1 << size) - 1
            result = (~value if name == "not" else (-value)) & mask
            self._set_flags(result, size, 1 if name == "neg" and result else 0, 0)
            self.write_op(ops[0], result, nxt)
            return nxt
        if name == "mul":
            return self._mul(ops, nxt, signed=False)
        if name == "imul":
            if len(ops) == 3:
                # imul r, r/m, imm
                a = self.read_op(ops[1], nxt)
                b = self.read_op(ops[2], nxt)
                self.write_op(ops[0], a * b, nxt)
                return nxt
            if len(ops) == 2:
                # imul r, r/m: the two-operand form.
                a = self.read_op(ops[0], nxt)
                b = self.read_op(ops[1], nxt)
                self.write_op(ops[0], a * b, nxt)
                return nxt
            return self._mul(ops, nxt, signed=True)
        if name in ("div", "idiv"):
            return self._div(ops, nxt, signed=(name == "idiv"))
        if name in ("shl", "shr", "sar", "rol", "ror", "rcl", "rcr"):
            return self._shift(name, ops, nxt)
        if name == "test":
            a = self.read_op(ops[0], nxt)
            b = self.read_op(ops[1], nxt)
            result = a & b
            size = ops[0].size
            self._set_flags(result, size, 0, 0)
            return nxt
        if name in ("bsf", "bsr"):
            value = self.read_op(ops[1], nxt)
            size = ops[1].size
            if value == 0:
                m.flags |= ZF
                return nxt
            m.flags &= ~ZF
            if name == "bsf":
                index = (value & -value).bit_length() - 1
            else:
                index = value.bit_length() - 1
            self.write_op(ops[0], index, nxt)
            return nxt
        if name == "bswap":
            value = self.read_op(ops[0], nxt)
            width = ops[0].size // 8
            self.write_op(ops[0], int.from_bytes(value.to_bytes(width, "little"), "big"), nxt)
            return nxt
        if name == "bt":
            value = self.read_op(ops[1], nxt)
            bit = self.read_op(ops[0], nxt)
            m.flags = (m.flags & ~CF) | (CF if (value >> (bit % ops[1].size)) & 1 else 0)
            return nxt
        if name in ("bts", "btr", "btc"):
            value = self.read_op(ops[1], nxt)
            bit = self.read_op(ops[0], nxt) % ops[1].size
            m.flags = (m.flags & ~CF) | (CF if (value >> bit) & 1 else 0)
            if name == "bts":
                value |= 1 << bit
            elif name == "btr":
                value &= ~(1 << bit)
            else:
                value ^= 1 << bit
            self.write_op(ops[1], value, nxt)
            return nxt
        if name == "xadd":
            a = self.read_op(ops[0], nxt)
            b = self.read_op(ops[1], nxt)
            self.write_op(ops[1], a, nxt)
            self.write_op(ops[0], a + b, nxt)
            return nxt
        if name == "cmpxchg":
            a = self.read_op(ops[0], nxt)
            b = self.read_op(ops[1], nxt)
            acc = m.r("rax")
            if acc == a:
                m.flags |= ZF
                self.write_op(ops[1], b, nxt)
            else:
                m.flags &= ~ZF
                m.w("rax", a)
            return nxt
        if name == "bswap":
            value = self.read_op(ops[0], nxt)
            size = ops[0].size // 8
            self.write_op(ops[0], int.from_bytes(value.to_bytes(size, "little"), "big"), nxt)
            return nxt
        if name == "cdqe":
            value = m.r("eax")
            if value & 0x80000000:
                value -= 1 << 32
            m.w("rax", value)
            return nxt
        if name == "cqo":
            m.w("rdx", 0xFFFFFFFFFFFFFFFF if m.r("rax") & (1 << 63) else 0)
            return nxt
        if name == "cdq":
            m.w("edx", 0xFFFFFFFF if m.r("eax") & (1 << 31) else 0)
            return nxt
        if name == "cbw":
            value = m.r("ax")
            if value & 0x80:
                value |= 0xFF00
            m.w("ax", value)
            return nxt

        # Flags and misc
        if name in ("clc", "stc", "cmc", "cld", "std", "cli", "sti"):
            bit = {"clc": (CF, 0), "stc": (CF, 1), "cld": (DF, 0), "std": (DF, 1),
                   "cli": (IF, 0), "sti": (IF, 1)}[name]
            if bit[1]:
                m.flags |= bit[0]
            else:
                m.flags &= ~bit[0]
            if name == "cmc":
                m.flags ^= CF
            return nxt
        if name == "pushfq":
            m.w("rsp", m.r("rsp") - 8)
            m.mem.write_u64(m.r("rsp"), m.flags)
            return nxt
        if name == "popfq":
            m.flags = m.mem.read_u64(m.r("rsp")) & 0x00000000000003F7
            m.w("rsp", m.r("rsp") + 8)
            return nxt

        # String operations
        if name.startswith(("movs", "stos", "lods", "cmps", "scas")):
            return self._string_op(name, insn)

        # Syscall and control
        if name == "syscall":
            return self._syscall(nxt)
        if name == "int3":
            raise ExecuteError("int3 hit", pc=nxt)
        if name == "ud2":
            raise ExecuteError("ud2 hit", pc=nxt)
        if name == "hlt":
            m.running = False
            return nxt
        if name == "cpuid":
            m.w("rax", 0)
            m.w("rbx", 0)
            m.w("rcx", 0)
            m.w("rdx", 0)
            return nxt
        if name == "rdtsc":
            value = int(time.monotonic() * 1_000_000_000) & 0xFFFFFFFFFFFFFFFF
            m.w("rax", value & 0xFFFFFFFF)
            m.w("rdx", value >> 32)
            return nxt
        if name == "nop":
            return nxt

        raise ExecuteError(f"{name} is not implemented", pc=nxt)

    # --- arithmetic helpers ----------------------------------------------

    def _arith(self, name: str, ops: list, nxt: int) -> int:
        m = self.machine
        size = ops[0].size
        mask = (1 << size) - 1
        a = self.read_op(ops[0], nxt)
        b = self.read_op(ops[1], nxt)
        result = 0

        if name == "add":
            raw = a + b
            result = raw & mask
            carry = 1 if raw > mask else 0
            overflow = 1 if ((a ^ result) & (b ^ result) & (1 << (size - 1))) else 0
            self._set_flags(result, size, carry, overflow)
        elif name == "adc":
            carry_in = 1 if m.flags & CF else 0
            raw = a + b + carry_in
            result = raw & mask
            self._set_flags(result, size, 1 if raw > mask else 0,
                            1 if ((a ^ result) & (b ^ result) & (1 << (size - 1))) else 0)
        elif name in ("sub", "cmp"):
            # cmp is a sub that throws the result away, so it shares this path
            # and only skips the store at the bottom.
            raw = a - b
            result = raw & mask
            self._set_flags(result, size, 1 if a < b else 0,
                            1 if ((a ^ b) & (a ^ result) & (1 << (size - 1))) else 0)
        elif name == "sbb":
            carry_in = 1 if m.flags & CF else 0
            raw = a - b - carry_in
            result = raw & mask
            self._set_flags(result, size, 1 if (a - carry_in) < b else 0, 0)
        elif name == "and":
            result = (a & b) & mask
            self._set_flags(result, size, 0, 0)
        elif name == "or":
            result = (a | b) & mask
            self._set_flags(result, size, 0, 0)
        elif name == "xor":
            result = (a ^ b) & mask
            self._set_flags(result, size, 0, 0)

        if name != "cmp":
            self.write_op(ops[0], result, nxt)
        return nxt

    def _mul(self, ops: list, nxt: int, signed: bool) -> int:
        m = self.machine
        if len(ops) == 1:
            # The one-operand form: the accumulator is implicit, so the product
            # lands across rdx:rax (or dx:ax).
            size = ops[0].size
            a = m.r("rax") & ((1 << size) - 1)
            b = self.read_op(ops[0], nxt)
            product = a * b
            if size == 8:
                m.w("ax", product & 0xFFFF)
            elif size == 16:
                m.w("dx", (product >> 16) & 0xFFFF)
                m.w("ax", product & 0xFFFF)
            elif size == 32:
                m.w("edx", (product >> 32) & 0xFFFFFFFF)
                m.w("eax", product & 0xFFFFFFFF)
            else:
                m.w("rdx", (product >> 64) & 0xFFFFFFFFFFFFFFFF)
                m.w("rax", product & 0xFFFFFFFFFFFFFFFF)
            return nxt
        return nxt

    def _div(self, ops: list, nxt: int, signed: bool) -> int:
        m = self.machine
        size = ops[0].size
        mask = (1 << size) - 1
        divisor = self.read_op(ops[0], nxt) & mask
        if divisor == 0:
            raise ExecuteError("division by zero", pc=nxt)
        if size == 8:
            dividend = m.r("ax")
            quotient, remainder = divmod(dividend, divisor)
            m.w("al", quotient & 0xFF)
            m.w("ah", remainder & 0xFF)
        elif size == 16:
            dividend = (m.r("dx") << 16) | m.r("ax")
            quotient, remainder = divmod(dividend, divisor)
            m.w("ax", quotient & 0xFFFF)
            m.w("dx", remainder & 0xFFFF)
        elif size == 32:
            dividend = (m.r("edx") << 32) | m.r("eax")
            quotient, remainder = divmod(dividend, divisor)
            m.w("eax", quotient & 0xFFFFFFFF)
            m.w("edx", remainder & 0xFFFFFFFF)
        else:
            dividend = (m.r("rdx") << 64) | m.r("rax")
            quotient, remainder = divmod(dividend, divisor)
            m.w("rax", quotient & 0xFFFFFFFFFFFFFFFF)
            m.w("rdx", remainder & 0xFFFFFFFFFFFFFFFF)
        return nxt

    def _shift(self, name: str, ops: list, nxt: int) -> int:
        m = self.machine
        size = ops[0].size
        mask = (1 << size) - 1
        value = self.read_op(ops[0], nxt) & mask
        count = ops[1] if isinstance(ops[1], int) else (m.r("cl") & 0x3F)
        if ops[1] is None or (not isinstance(ops[1], int)):
            count = m.r("cl") & 0x3F
        count %= size or 1
        sign_bit = 1 << (size - 1)

        if name == "shl":
            result = (value << count) & mask
            m.flags = (m.flags & ~CF) | (CF if (value >> (size - count)) & 1 else 0)
        elif name == "shr":
            result = value >> count
            m.flags = (m.flags & ~CF) | (CF if (value >> (count - 1)) & 1 else 0)
        elif name == "sar":
            sign = value & sign_bit
            result = (value >> count) | (mask << (size - count) if sign else 0)
            result &= mask
            m.flags = (m.flags & ~CF) | (CF if (value >> (count - 1)) & 1 else 0)
        elif name == "rol":
            result = ((value << count) | (value >> (size - count))) & mask
            m.flags = (m.flags & ~CF) | (CF if result & 1 else 0)
        elif name == "ror":
            result = ((value >> count) | (value << (size - count))) & mask
            m.flags = (m.flags & ~CF) | (CF if result & sign_bit else 0)
        elif name == "rcl":
            carry = 1 if m.flags & CF else 0
            result = ((value << count) | (carry << (count - 1)) | (value >> (size - count + 1))) & mask
            m.flags = (m.flags & ~CF) | (CF if (value >> (size - count)) & 1 else 0)
        else:  # rcr
            carry = 1 if m.flags & CF else 0
            result = ((value >> count) | (carry << (size - count)) | (value << (size - count + 1))) & mask
            m.flags = (m.flags & ~CF) | (CF if value & 1 else 0)

        self._set_flags(result, size, 1 if m.flags & CF else 0, 0)
        self.write_op(ops[0], result, nxt)
        return nxt

    # --- string operations -------------------------------------------------

    def _string_op(self, name: str, insn: Insn) -> int:
        m = self.machine
        size = 1 if name.endswith("b") else (8 if m.bits == 64 else 4)
        step = -size if m.flags & DF else size
        count = m.r("rcx") if m.bits == 64 else m.r("ecx")
        ops = insn.operands

        if name.startswith("movs"):
            for _ in range(count):
                src = m.r("rsi")
                dst = m.r("rdi")
                data = m.mem.read(src, size)
                m.mem.write(dst, data)
                m.w("rsi", src + step)
                m.w("rdi", dst + step)
            m.w("rcx", 0)
        elif name.startswith("stos"):
            value = m.r("rax") & ((1 << (size * 8)) - 1)
            for _ in range(count):
                m.mem.write(m.r("rdi"), value.to_bytes(size, "little"))
                m.w("rdi", m.r("rdi") + step)
            m.w("rcx", 0)
        elif name.startswith("lods"):
            for _ in range(count):
                m.w("rax", int.from_bytes(m.mem.read(m.r("rsi"), size), "little"))
                m.w("rsi", m.r("rsi") + step)
            m.w("rcx", 0)
        elif name.startswith("cmps"):
            for _ in range(count):
                a = int.from_bytes(m.mem.read(m.r("rsi"), size), "little")
                b = int.from_bytes(m.mem.read(m.r("rdi"), size), "little")
                result = (a - b) & ((1 << (size * 8)) - 1)
                self._set_flags(result, size * 8, 1 if a < b else 0, 0)
                m.w("rsi", m.r("rsi") + step)
                m.w("rdi", m.r("rdi") + step)
            m.w("rcx", 0)
        elif name.startswith("scas"):
            for _ in range(count):
                a = m.r("rax") & ((1 << (size * 8)) - 1)
                b = int.from_bytes(m.mem.read(m.r("rdi"), size), "little")
                result = (a - b) & ((1 << (size * 8)) - 1)
                self._set_flags(result, size * 8, 1 if a < b else 0, 0)
                m.w("rdi", m.r("rdi") + step)
            m.w("rcx", 0)
        return insn.next_rip

    # --- syscalls -----------------------------------------------------------

    def _syscall(self, nxt: int) -> int:
        m = self.machine
        number = m.r("rax") & 0xFFFFFFFF
        name = SYSCALL_NAMES.get(number, f"syscall_{number}")
        regs = ["rdi", "rsi", "rdx", "r10", "r8", "r9"]
        argc = SYSCALL_ARGC.get(number, 6)
        args = tuple(m.r(regs[i]) for i in range(min(argc, 6)))

        self.hooks.on_syscall(m, number, name, args)

        if number in self._blocked_syscalls:
            result = -38  # -ENOSYS
        else:
            result = self._dispatch_syscall(number, name, args)
        m.w("rax", result)
        self.syscalls.append(SyscallRecord(number=number, name=name, args=args, result=result, pc=m.rip))
        return nxt

    def _dispatch_syscall(self, number: int, name: str, args: tuple) -> int:
        m = self.machine
        arg = lambda i: args[i] if i < len(args) else 0

        # --- process control -------------------------------------------------
        if number in (60, 231):  # exit, exit_group
            self.exit_code = arg(0) & 0xFF
            m.running = False
            return 0
        if number == 39:  # getpid
            return 1234
        if number == 186:  # gettid
            return 1234
        if number == 110:  # getppid
            return 1000
        if number == 102:  # getuid
            return 1000
        if number == 104:  # getgid
            return 1000
        if number == 107:  # geteuid
            return 1000
        if number == 108:  # getegid
            return 1000
        if number == 105:  # setuid
            return 0
        if number == 106:  # setgid
            return 0
        if number in (57, 58, 56):  # fork, vfork, clone
            # Single-process model: report the child as a failure so a stub does
            # not spin forever waiting for a child that will never exist.
            return -38
        if number == 61:  # wait4
            return -10  # -ECHILD: nothing to wait for
        if number == 62:  # kill
            return 0
        if number == 59:  # execve
            raise ExecuteError(f"execve is not modelled: {name}({', '.join(hex(a) for a in args)})", pc=m.rip)
        if number == 13 or number == 14:  # rt_sigaction, rt_sigprocmask
            return 0
        if number == 15:  # rt_sigreturn
            return 0
        if number == 234:  # tgkill
            return 0
        if number == 158:  # arch_prctl
            return 0
        if number == 218:  # set_tid_address
            return 1234
        if number == 273:  # set_robust_list
            return 0
        if number == 334:  # rseq
            return 0
        if number == 95:  # umask
            return 0o022
        if number == 109:  # setpgid
            return 0
        if number == 111:  # getpgrp
            return 1234

        # --- time -------------------------------------------------------------
        if number == 96:  # gettimeofday
            secs = int(time.time())
            usecs = int((time.time() - secs) * 1_000_000)
            if arg(0):
                m.mem.write_u64(arg(0), secs)
                m.mem.write_u64(arg(0) + 8, usecs)
            return 0
        if number == 201:  # time
            value = int(time.time())
            if arg(0):
                m.mem.write_u64(arg(0), value)
            return value
        if number == 35:  # nanosleep
            return 0
        if number == 318:  # getrandom
            import random as _random

            rng = _random.Random(0xC0FFEE)
            size = arg(1)
            m.mem.write(arg(0), bytes(rng.randrange(256) for _ in range(size)))
            return size

        # --- memory -----------------------------------------------------------
        if number == 12:  # brk
            target = arg(0)
            if target == 0:
                return self._brk
            if target > self._brk:
                self.machine.mem.write(target - 1, b"\x00")
            self._brk = target
            return self._brk
        if number == 9:  # mmap
            length = arg(1)
            if length == 0:
                return -22
            aligned = (length + 0xFFF) & ~0xFFF
            addr = self._next_mmap
            if addr + aligned > MMAP_LIMIT:
                return -12  # -ENOMEM
            for page in range(aligned // 0x1000):
                self.machine.mem.page_for(addr + page * 0x1000)
            self.mmaps[addr] = aligned
            self._next_mmap = addr + aligned + 0x1000
            return addr
        if number == 11:  # munmap
            addr = arg(0)
            length = arg(1)
            self.mmaps.pop(addr, None)
            for page in range((length + 0xFFF) // 0x1000):
                self.machine.mem._pages.pop((addr + page * 0x1000) >> self.machine.mem.page_bits, None)
            return 0
        if number == 10:  # mprotect
            return 0

        # --- files ------------------------------------------------------------
        if number == 2:  # open
            return self._open(arg(0), arg(1))
        if number == 257:  # openat
            return self._open(arg(1), arg(2))
        if number == 85:  # creat
            return self._open(arg(0), 0x241)  # O_WRONLY|O_CREAT|O_TRUNC
        if number == 3:  # close
            self._files.pop(arg(0), None)
            self._offsets.pop(arg(0), None)
            return 0
        if number == 0:  # read
            fd, buf, count = arg(0), arg(1), arg(2)
            path = self._files.get(fd)
            if not path or path == "<socket>":
                return 0
            # Track the offset, so a stub that reads in a loop makes progress
            # instead of being handed the same bytes forever.
            offset = self._offsets.get(fd, 0)
            data = self.fs.read(path, count, offset)
            if data:
                self.machine.mem.write(buf, data)
            self._offsets[fd] = offset + len(data)
            return len(data)
        if number == 1:  # write
            fd, buf, count = arg(0), arg(1), arg(2)
            data = self.machine.mem.read(buf, count)
            if fd in (1, 2):
                self.output += data
                return len(data)
            path = self._files.get(fd)
            if path == "<socket>":
                # glibc sends through write() on a connected socket, so this is
                # where a fair amount of C2 traffic actually turns up.
                return self.net.send(fd, data)
            if path:
                # A file write lands in the VFS, so a dropper's output is still
                # there to look at after the run instead of vanishing.
                self.fs.write(path, data, append=True)
                self._offsets[fd] = self._offsets.get(fd, 0) + len(data)
            return len(data)
        if number == 8:  # lseek
            return 0
        if number in (4, 5, 6):  # stat, fstat, lstat
            return self._stat(arg(0), arg(1))
        if number in (262,):  # newfstatat
            return self._stat(arg(1), arg(2))
        if number == 21:  # access
            path = self.machine.mem.read_cstring(arg(0))
            return 0 if self.fs.exists(path) else -2
        if number == 79:  # getcwd
            cwd = b"/"
            self.machine.mem.write(arg(0), cwd[: arg(1)])
            return len(cwd)
        if number == 80:  # chdir
            return 0
        if number == 83:  # mkdir
            return 0
        if number == 84:  # rmdir
            return 0
        if number == 87:  # unlink
            return 0
        if number == 82:  # rename
            return 0
        if number == 90:  # chmod
            return 0
        if number == 92:  # chown
            return 0
        if number == 89:  # readlink
            link = b"/proc/self/exe"
            self.machine.mem.write(arg(0), link[: arg(1)])
            return min(len(link), arg(1))
        if number == 78 or number == 217:  # getdents, getdents64
            return 0
        if number == 16:  # ioctl
            return 0
        if number == 72:  # fcntl
            return 0
        if number == 97:  # getrlimit
            if arg(1):
                self.machine.mem.write_u64(arg(1), 0xFFFFFFFFFFFFFFFF)
                self.machine.mem.write_u64(arg(1) + 8, 0xFFFFFFFFFFFFFFFF)
            return 0
        if number == 302:  # prlimit64
            return 0
        if number == 63:  # uname
            return self._uname(arg(0))

        # --- sockets ----------------------------------------------------------
        if 41 <= number <= 55:
            return self._socket_syscall(number, args)

        if number == 32:  # dup
            return arg(0)
        if number == 33:  # dup2
            return arg(1)
        if number == 22:  # pipe
            fds = [self._next_fd, self._next_fd + 1]
            self._next_fd += 2
            self.machine.mem.write_u32(arg(0), fds[0])
            self.machine.mem.write_u32(arg(0) + 4, fds[1])
            return 0
        if number == 20:  # writev
            return arg(2)
        if number == 7:  # poll
            return 0
        if number == 332:  # statx
            return self._stat(arg(1), arg(4))

        return -38  # -ENOSYS

    def _socket_syscall(self, number: int, args: tuple) -> int:
        """A sinkhole. Sockets exist, connects succeed, sends are captured.

        A beacon that reaches this far believes it phoned home, which is the
        point: it keeps going down its C2 path and you get to watch it. Nothing
        is ever answered, so a sample that waits on a command sees EOF.
        """
        m = self.machine
        arg = lambda i: args[i] if i < len(args) else 0

        if number == 41:  # socket
            fd = self._next_fd
            self._next_fd += 1
            self._files[fd] = "<socket>"
            return fd
        if number == 42:  # connect
            return self.net.connect(arg(0), parse_sockaddr(m.mem, arg(1), arg(2)))
        if number == 44:  # sendto
            # A NULL address means the fd is already connected, so keep the peer
            # from connect() rather than replacing it with a parse of nothing.
            if arg(4):
                self.net.peers.setdefault(arg(0), parse_sockaddr(m.mem, arg(4), arg(5)))
            return self.net.send(arg(0), m.mem.read(arg(1), arg(2)))
        if number == 46:  # sendmsg
            return self.net.send(arg(0), self._gather_iov(arg(1)))
        if number == 43:  # accept
            return -11  # -EAGAIN: nothing is ever listening
        return 0

    def _gather_iov(self, msghdr: int) -> bytes:
        """Collect a sendmsg's iovec into one buffer."""
        if not msghdr:
            return b""
        iov = self.machine.mem.read_u64(msghdr + 16)
        count = self.machine.mem.read_u64(msghdr + 24)
        out = bytearray()
        for i in range(min(count, 64)):
            base = self.machine.mem.read_u64(iov + i * 16)
            size = self.machine.mem.read_u64(iov + i * 16 + 8)
            out += self.machine.mem.read(base, size)
        return bytes(out)

    def _open(self, path_addr: int, flags: int) -> int:
        """Look the path up in the VFS. Nothing here reaches the host."""
        path = self.machine.mem.read_cstring(path_addr & 0xFFFFFFFFFFFFFFFF)
        if not self.fs.exists(path):
            if not flags & 0x40:  # O_CREAT
                return -2  # -ENOENT
            self.fs.add(path, b"")
        elif flags & 0x200:  # O_TRUNC
            self.fs.write(path, b"")
        fd = self._next_fd
        self._next_fd += 1
        self._files[fd] = path
        self._offsets[fd] = 0
        return fd

    def _stat(self, addr: int, buf: int) -> int:
        if addr == 0 or buf == 0:
            return -22
        path = self.machine.mem.read_cstring(addr)
        if not self.fs.exists(path):
            return -2
        size = self.fs.size(path)
        mode = 0o040755 if self.fs.is_dir(path) else 0o100644
        # A rough stat64, just enough for a stub to take the success path.
        fields = struct.pack(
            "<QQQIIIIQQQQQQQQ",
            0, 0, size, mode, 1, 0, 0,
            size, 0, 0, 0, 0, 0, 0,
        )
        self.machine.mem.write(buf, fields[:144])
        return 0

    def _uname(self, buf: int) -> int:
        if buf == 0:
            return -22
        for offset, value in ((0, b"Linux"), (65, b"emulator"), (130, b"5.15.0-emulator"),
                              (195, b"x86_64"), (260, b"(none)")):
            self.machine.mem.write(buf + offset, value.ljust(65, b"\x00"))
        return 0
