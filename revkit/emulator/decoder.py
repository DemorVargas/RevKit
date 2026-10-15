"""x86 register file, flags and the instruction decoder.

Covers the subset shellcode and CTF stubs actually use: general purpose
registers, RIP-relative addressing, ModR/M and SIB, the common stack and string
instructions, and the condition codes. It is not a complete x86 implementation,
and it raises on anything it does not know instead of guessing, because a wrong
instruction corrupts the run silently.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .errors import DecodeError
from .memory import Memory

# EFLAGS bits. Only the arithmetic, direction and interrupt flags are modelled,
# which is every flag shellcode reads or writes.
CF = 1 << 0
PF = 1 << 2
AF = 1 << 4
ZF = 1 << 6
SF = 1 << 7
TF = 1 << 8
IF = 1 << 9
DF = 1 << 10
OF = 1 << 11

EFLAGS_MASK = CF | PF | AF | ZF | SF | TF | IF | DF | OF

# 64-bit general purpose registers, in the order the REX encoding expects. The
# second half is the REX.B/REX.R extended set, which shellcode uses constantly
# for the syscall argument registers.
REGISTERS64 = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
]

# Same registers at narrower widths. Index 4-7 at 8 bits need REX to address the
# low halves (spl, bpl, sil, dil) instead of ah/ch/dh/bh, but shellcode that
# cares uses REX consistently and this keeps the common case simple.
NAMES32 = [
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
]
NAMES16 = [
    "ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
    "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
]
NAMES8 = [
    "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
    "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
]


@dataclass
class Machine:
    """Registers, flags and a memory space.

    Plain mutable state. The executor pokes registers and flags directly, so
    there is no point hiding them behind accessors.
    """

    mem: Memory = field(default_factory=Memory)
    regs: dict = field(default_factory=dict)
    rip: int = 0
    bits: int = 64
    flags: int = IF
    running: bool = False
    steps: int = 0
    max_steps: int = 1_000_000

    def __post_init__(self):
        if not self.regs:
            self.regs = {name: 0 for name in REGISTERS64}
            # A stub that pushes before setting a stack still needs somewhere to
            # push to, so give it a sane top of stack.
            self.regs["rsp"] = 0x7FFFFFF0
            self.regs["rbp"] = 0

    # --- register access -------------------------------------------------

    def r(self, name: str) -> int:
        return self.regs.get(name, 0)

    def w(self, name: str, value: int) -> None:
        limit = 0xFFFFFFFFFFFFFFFF if self.bits == 64 else 0xFFFFFFFF
        self.regs[name] = value & limit

    def read_reg(self, index: int, size: int) -> int:
        """Read a register at a specific width.

        The register file is keyed by 64-bit names, so every width reads the
        same slot and masks it down.
        """
        return self.r(REGISTERS64[index]) & ((1 << size) - 1)

    def write_reg(self, index: int, size: int, value: int) -> None:
        """Write a register at a specific width.

        The register file is keyed by 64-bit names, so every width writes the
        same slot. A 32-bit write zeroes the upper half, by definition; narrower
        writes leave it alone.
        """
        base = REGISTERS64[index]
        value &= (1 << size) - 1
        if size in (32, 64):
            self.w(base, value)
            return
        current = self.r(base)
        if size == 16:
            self.w(base, (current & 0xFFFFFFFFFFFF0000) | value)
        elif size == 8:
            self.w(base, (current & 0xFFFFFFFFFFFFFF00) | value)
        else:
            raise DecodeError(f"bad register width {size}")

    @staticmethod
    def name_for(index: int, size: int) -> str:
        if size == 64:
            return REGISTERS64[index]
        if size == 32:
            return NAMES32[index]
        if size == 16:
            return NAMES16[index]
        if size == 8:
            return NAMES8[index]
        raise DecodeError(f"bad register width {size}")


@dataclass
class Operand:
    """Where an instruction reads from or writes to."""

    kind: str  # "reg" | "mem" | "imm"
    size: int
    reg: int | None = None
    index: int | None = None
    base: int | None = None
    scale: int = 1
    disp: int = 0
    rip_rel: bool = False


@dataclass
class Insn:
    mnemonic: str
    operands: list
    next_rip: int
    size: int = 1
    imm: int = 0
    imm_size: int = 0
    rep: int = 0


class Decoder:
    """Bytes to instructions, one at a time."""

    def __init__(self, mem: Memory, bits: int = 64):
        self.mem = mem
        self.bits = bits

    # --- ModR/M and SIB --------------------------------------------------

    def _modrm(self, code: bytes, pos: int, modrm: int, rex: int) -> tuple[Operand, int, int]:
        """Decode a ModR/M byte. Returns (rm operand, reg field, bytes consumed)."""
        mod = (modrm >> 6) & 0x03
        reg_field = ((modrm >> 3) & 0x07) | ((rex & 0x04) << 1)
        rm = modrm & 0x07

        if mod == 3:
            # Register direct. REX.B extends the register index.
            index = rm | ((rex & 0x01) << 3)
            return Operand(kind="reg", size=0, reg=index), reg_field, 0

        consumed = 0
        base = None
        index = None
        scale = 1
        disp = 0

        if rm == 4:
            # SIB byte follows.
            if pos >= len(code):
                raise DecodeError("truncated SIB byte")
            sib = code[pos]
            consumed += 1
            scale = 1 << ((sib >> 6) & 0x03)
            index = ((sib >> 3) & 0x07) | ((rex & 0x02) << 2)
            base_reg = (sib & 0x07) | ((rex & 0x01) << 3)
            # Index 4 means "no index register", unless REX.X extends it to r12.
            if index == 4 and not (rex & 0x02):
                index = None
            if (sib & 0x07) == 5 and mod == 0:
                # No base, disp32 instead.
                disp = int.from_bytes(code[pos + consumed : pos + consumed + 4], "little", signed=True)
                consumed += 4
                base_reg = None
            base = base_reg
        else:
            base = rm | ((rex & 0x01) << 3)
            if base == 4:
                # RSP/R12 as a base with mod==0 needs a SIB byte, handled above.
                pass

        if mod == 1:
            disp = int.from_bytes(code[pos + consumed : pos + consumed + 1], "little", signed=True)
            consumed += 1
        elif mod == 2:
            disp = int.from_bytes(code[pos + consumed : pos + consumed + 4], "little", signed=True)
            consumed += 4
        elif mod == 0 and base == 5:
            # [RIP + disp32] in 64-bit mode; in 32-bit mode it is a bare disp32.
            disp = int.from_bytes(code[pos + consumed : pos + consumed + 4], "little", signed=True)
            consumed += 4
            base = None

        # In 64-bit mode a memory operand with no base and no index is
        # RIP-relative, which the executor resolves against the next instruction.
        rip_rel = self.bits == 64 and base is None and index is None and mod != 3

        return (
            Operand(kind="mem", size=0, base=base, index=index, scale=scale, disp=disp, rip_rel=rip_rel),
            reg_field,
            consumed,
        )

    # --- top level -------------------------------------------------------

    def decode(self, addr: int) -> Insn:
        start = addr
        code = self.mem.read(addr, 15)  # longest possible instruction
        if not code:
            raise DecodeError(f"no bytes at {addr:#x}")

        pos = 0
        rex = 0
        has_rex = False
        opsize_override = False
        rep = 0

        # Legacy prefixes.
        while pos < len(code):
            b = code[pos]
            if b == 0x66:
                opsize_override = True
                pos += 1
            elif b in (0xF2, 0xF3):
                rep = b
                pos += 1
            elif b in (0x67, 0xF0, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65):
                # Address-size override, lock and segment prefixes: all no-ops in a
                # flat memory space.
                pos += 1
            else:
                break

        if self.bits == 64 and 0x40 <= code[pos] <= 0x4F:
            rex = code[pos]
            has_rex = True
            pos += 1

        if pos >= len(code):
            raise DecodeError(f"prefix-only instruction at {start:#x}")

        opcode = code[pos]
        pos += 1

        # REX.W promotes a 32-bit operation to 64-bit, and 0x66 demotes the
        # default to 16-bit.
        if has_rex and (rex & 0x08):
            operand_size = 64
        elif opsize_override:
            operand_size = 16
        else:
            operand_size = 32

        # Opcodes whose operand width is fixed regardless of prefixes.
        fixed_size = self._fixed_operand_size(opcode)

        modrm_ops = {
            0x00: "add", 0x01: "add", 0x02: "add", 0x03: "add",
            0x08: "or", 0x09: "or", 0x0A: "or", 0x0B: "or",
            0x10: "adc", 0x11: "adc", 0x12: "adc", 0x13: "adc",
            0x18: "sbb", 0x19: "sbb", 0x1A: "sbb", 0x1B: "sbb",
            0x20: "and", 0x21: "and", 0x22: "and", 0x23: "and",
            0x28: "sub", 0x29: "sub", 0x2A: "sub", 0x2B: "sub",
            0x30: "xor", 0x31: "xor", 0x32: "xor", 0x33: "xor",
            0x38: "cmp", 0x39: "cmp", 0x3A: "cmp", 0x3B: "cmp",
            0x84: "test", 0x85: "test",
            0x86: "xchg", 0x87: "xchg",
            0x88: "mov", 0x89: "mov", 0x8A: "mov", 0x8B: "mov",
            0x8D: "lea",
            0x63: "movsxd",
            0x69: "imul", 0x6B: "imul",
            0x80: "grp1", 0x81: "grp1", 0x83: "grp1",
            0x8F: "grp1", 0xFF: "grp1",
            0xC6: "mov", 0xC7: "mov",
            0xC1: "shift_grp", 0xD1: "shift_grp", 0xD3: "shift_grp",
            0xF7: "grp3", 0xFE: "grp4",
        }

        if opcode in modrm_ops:
            size = fixed_size or operand_size
            modrm = code[pos]
            pos += 1
            rm, reg_field, consumed = self._modrm(code, pos, modrm, rex)
            pos += consumed
            rm.size = size

            mnemonic = modrm_ops[opcode]
            operands = []
            direction = opcode & 0x02  # 0 = to r/m, 2 = from r/m

            if opcode == 0xFF:
                # Group 5: the reg field picks the operation.
                mnemonic = ["inc", "dec", "call", "callf", "jmp", "jmpf", "push", "invalid"][reg_field & 7]
                if reg_field & 7 == 7:
                    raise DecodeError(f"opcode ff /7 at {start:#x} is not valid")
                operands = [rm]
                return Insn(mnemonic=mnemonic, operands=operands, next_rip=start + pos, size=pos, rep=rep)
            if opcode == 0xFE:
                # Group 4: only /0 and /1 are valid, both on 8-bit operands.
                if reg_field & 7 > 1:
                    raise DecodeError(f"opcode fe /{reg_field & 7} at {start:#x} is not valid")
                rm.size = 8
                return Insn(mnemonic="inc" if reg_field & 7 == 0 else "dec", operands=[rm],
                            next_rip=start + pos, size=pos, rep=rep)
            if opcode == 0x8F:
                operands = [rm]
                mnemonic = "pop"
            elif opcode in (0x80, 0x81, 0x83):
                # Group 1: add, or, adc, sbb, and, sub, xor, cmp with an immediate.
                # 0x80 and 0x83 take a 1-byte immediate, 0x81 takes 16 or 32 bits.
                rm.size = 8 if opcode == 0x80 else size
                if opcode in (0x80, 0x83):
                    imm_size = 1
                elif size == 16:
                    imm_size = 2
                else:
                    imm_size = 4
                imm = int.from_bytes(code[pos : pos + imm_size], "little", signed=(opcode == 0x83))
                if opcode == 0x81 and size == 64 and imm & 0x80000000:
                    imm -= 1 << 32
                pos += imm_size
                mnemonic = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"][reg_field & 7]
                return Insn(mnemonic=mnemonic, operands=[rm, imm], next_rip=start + pos,
                            size=pos, rep=rep)
            elif opcode in (0x8D, 0x63):
                operands = [self._reg_operand(reg_field, size), rm]
            elif opcode in (0xC1, 0xD1, 0xD3):
                count = code[pos] if opcode == 0xC1 else (1 if opcode == 0xD1 else None)
                if opcode == 0xC1:
                    pos += 1
                operands = [rm, count]
                mnemonic = self._shift_name(reg_field)
            elif opcode == 0xF7:
                operands: list = [rm]
                mnemonic = self._group3_name(reg_field, size)
                if reg_field & 7 in (0, 1):
                    # TEST r/m, imm: the immediate is part of the instruction.
                    imm_size = 2 if size == 16 else 4
                    operands.append(int.from_bytes(code[pos : pos + imm_size], "little"))
                    pos += imm_size
            elif opcode in (0x69, 0x6B):
                imm_size = 4 if opcode == 0x69 else 1
                imm = int.from_bytes(code[pos : pos + imm_size], "little", signed=(opcode == 0x6B))
                pos += imm_size
                operands = [self._reg_operand(reg_field, size), rm, imm]
            elif opcode in (0xC6, 0xC7):
                imm_size = 1 if opcode == 0xC6 else 4
                imm = int.from_bytes(code[pos : pos + imm_size], "little")
                if opcode == 0xC7 and size == 64 and imm & 0x80000000:
                    # A 64-bit mov from a 32-bit immediate sign-extends it.
                    imm -= 1 << 32
                pos += imm_size
                operands = [rm, imm]
            elif opcode in (0x84, 0x86):
                operands = [rm, self._reg_operand(reg_field, size)]
            elif direction == 0:
                operands = [rm, self._reg_operand(reg_field, size)]
            else:
                operands = [self._reg_operand(reg_field, size), rm]

            return Insn(mnemonic=mnemonic, operands=operands, next_rip=start + pos, size=pos, rep=rep)

        return self._decode_no_modrm(opcode, code, pos, operand_size, start, rex, rep)

    @staticmethod
    def _reg_operand(index: int, size: int) -> Operand:
        return Operand(kind="reg", size=size, reg=index)

    @staticmethod
    def _fixed_operand_size(opcode: int) -> int | None:
        """Operand width implied by the opcode alone, or None if prefixes decide."""
        if opcode in (0x00, 0x02, 0x08, 0x0A, 0x10, 0x12, 0x18, 0x1A, 0x20, 0x22,
                      0x28, 0x2A, 0x30, 0x32, 0x38, 0x3A, 0x84, 0x86, 0x88, 0x8A,
                      0xC6):
            return 8
        return None

    @staticmethod
    def _shift_name(reg_field: int) -> str:
        return ["rol", "ror", "rcl", "rcr", "shl", "shr", "shl", "sar"][reg_field & 7]

    @staticmethod
    def _group3_name(reg_field: int, size: int) -> str:
        """0xF7 group: the reg field selects the operation."""
        names = ["test", "test", "not", "neg", "mul", "imul", "div", "idiv"]
        return names[reg_field & 7]

    def _decode_no_modrm(self, opcode: int, code: bytes, pos: int, operand_size: int, start: int, rex: int, rep: int) -> Insn:
        """Opcodes with no ModR/M byte: immediates, jumps, stack and string ops."""
        if opcode == 0x0F:
            return self._decode_two_byte(code, pos, operand_size, start, rex, rep)

        if 0x50 <= opcode <= 0x57:
            index = (opcode - 0x50) | ((rex & 0x01) << 3)
            return Insn("push", [Operand(kind="reg", size=64, reg=index)], start + pos, size=pos, rep=rep)
        if 0x58 <= opcode <= 0x5F:
            index = (opcode - 0x58) | ((rex & 0x01) << 3)
            return Insn("pop", [Operand(kind="reg", size=64, reg=index)], start + pos, size=pos, rep=rep)

        if opcode == 0x90:
            return Insn("nop", [], start + pos, size=pos, rep=rep)
        if opcode == 0x6A:
            return Insn("push", [code[pos]], start + pos + 1, size=pos + 1,
                        imm=code[pos], imm_size=1, rep=rep)
        if opcode == 0x68:
            imm = int.from_bytes(code[pos : pos + 4], "little")
            return Insn("push", [imm], start + pos + 4, size=pos + 4,
                        imm=imm, imm_size=4, rep=rep)
        if opcode == 0xF4:
            return Insn("hlt", [], start + pos, size=pos, rep=rep)
        if opcode == 0xCC:
            return Insn("int3", [], start + pos, size=pos, rep=rep)
        if opcode == 0xC3:
            return Insn("ret", [], start + pos, size=pos, rep=rep)
        if opcode == 0xC2:
            imm = int.from_bytes(code[pos : pos + 2], "little")
            return Insn("ret", [imm], start + pos + 2, size=pos + 2, imm=imm, imm_size=2, rep=rep)

        if opcode == 0xEB:
            rel = int.from_bytes(code[pos : pos + 1], "little", signed=True)
            target = start + pos + 1 + rel
            return Insn("jmp", [target], start + pos + 1, size=pos + 1, rep=rep)

        if 0x70 <= opcode <= 0x7F:
            rel = int.from_bytes(code[pos : pos + 1], "little", signed=True)
            names = ["jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
                     "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"]
            return Insn(names[opcode - 0x70], [start + pos + 1 + rel], start + pos + 1, size=pos + 1, rep=rep)

        if opcode == 0xE8:
            rel = int.from_bytes(code[pos : pos + 4], "little", signed=True)
            return Insn("call", [start + pos + 4 + rel], start + pos + 4, size=pos + 4, rep=rep)

        if opcode == 0xE9:
            rel = int.from_bytes(code[pos : pos + 4], "little", signed=True)
            return Insn("jmp", [start + pos + 4 + rel], start + pos + 4, size=pos + 4, rep=rep)

        if opcode == 0xE3:
            rel = int.from_bytes(code[pos : pos + 1], "little", signed=True)
            return Insn("jrcxz", [start + pos + 1 + rel], start + pos + 1, size=pos + 1, rep=rep)

        if 0xB0 <= opcode <= 0xB7:
            index = (opcode - 0xB0) | ((rex & 0x01) << 3)
            return Insn("mov", [self._reg_operand(index, 8), code[pos]], start + pos + 1, size=pos + 1, rep=rep)

        if 0xB8 <= opcode <= 0xBF:
            index = (opcode - 0xB8) | ((rex & 0x01) << 3)
            if rex & 0x08:
                imm = int.from_bytes(code[pos : pos + 8], "little")
                return Insn("mov", [self._reg_operand(index, 64), imm], start + pos + 8,
                            size=pos + 8, imm=imm, imm_size=8, rep=rep)
            if operand_size == 16:
                imm = int.from_bytes(code[pos : pos + 2], "little")
                return Insn("mov", [self._reg_operand(index, 16), imm], start + pos + 2,
                            size=pos + 2, imm=imm, imm_size=2, rep=rep)
            imm = int.from_bytes(code[pos : pos + 4], "little")
            return Insn("mov", [self._reg_operand(index, 32), imm], start + pos + 4,
                        size=pos + 4, imm=imm, imm_size=4, rep=rep)

        if opcode in (0xA4, 0xA5):
            return Insn("movs" + ("b" if opcode == 0xA4 else ("q" if operand_size == 64 else "d")),
                        [], start + pos, size=pos, rep=rep)
        if opcode in (0xA6, 0xA7):
            return Insn("cmpsb" if opcode == 0xA6 else "cmps", [], start + pos, size=pos, rep=rep)
        if opcode == 0xAA:
            return Insn("stosb", [], start + pos, size=pos, rep=rep)
        if opcode in (0xAB, 0xAD):
            return Insn("stos" + ("b" if opcode == 0xAA else ("q" if operand_size == 64 else "d")),
                        [], start + pos, size=pos, rep=rep)
        if opcode in (0xAC, 0xAE):
            return Insn("lodsb", [], start + pos, size=pos, rep=rep)
        if opcode == 0x9C:
            return Insn("pushfq", [], start + pos, size=pos, rep=rep)
        if opcode == 0x9D:
            return Insn("popfq", [], start + pos, size=pos, rep=rep)
        if opcode == 0x98:
            return Insn("cdqe" if operand_size == 32 else "cbw", [], start + pos, size=pos, rep=rep)
        if opcode == 0x99:
            return Insn("cqo" if operand_size == 64 else "cdq", [], start + pos, size=pos, rep=rep)
        if opcode == 0xCB:
            return Insn("retf", [], start + pos, size=pos, rep=rep)

        raise DecodeError(f"opcode {opcode:#04x} at {start:#x} is not implemented")

    # --- two-byte (0F xx) opcodes ---------------------------------------

    def _decode_two_byte(self, code: bytes, pos: int, operand_size: int, start: int, rex: int, rep: int) -> Insn:
        if pos >= len(code):
            raise DecodeError(f"truncated two-byte opcode at {start:#x}")
        second = code[pos]
        pos += 1

        if second == 0x05:
            return Insn("syscall", [], start + pos, size=pos, rep=rep)
        if second == 0x0B:
            return Insn("ud2", [], start + pos, size=pos, rep=rep)
        if second == 0x31:
            return Insn("rdtsc", [], start + pos, size=pos, rep=rep)
        if second == 0xA2:
            return Insn("cpuid", [], start + pos, size=pos, rep=rep)
        if second == 0x34:
            return Insn("sysenter", [], start + pos, size=pos, rep=rep)
        if second == 0x35:
            return Insn("sysexit", [], start + pos, size=pos, rep=rep)

        # Conditional jumps, rel32.
        if 0x80 <= second <= 0x8F:
            names = ["jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
                     "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"]
            rel = int.from_bytes(code[pos : pos + 4], "little", signed=True)
            return Insn(names[second - 0x80], [start + pos + 4 + rel], start + pos + 4,
                        size=pos + 4, rep=rep)

        # Conditional moves and setcc both need a ModR/M byte.
        modrm_ops = {
            0x40: "cmovo", 0x41: "cmovno", 0x42: "cmovb", 0x43: "cmovae",
            0x44: "cmove", 0x45: "cmovne", 0x46: "cmovbe", 0x47: "cmova",
            0x48: "cmovs", 0x49: "cmovns", 0x4A: "cmovp", 0x4B: "cmovnp",
            0x4C: "cmovl", 0x4D: "cmovge", 0x4E: "cmovle", 0x4F: "cmovg",
            0xAF: "imul",
            0xB6: "movzx", 0xB7: "movzx",
            0xBE: "movsx", 0xBF: "movsx",
            0xBC: "bsf", 0xBD: "bsr",
            0xB0: "cmpxchg", 0xB1: "cmpxchg",
            0xA3: "bt", 0xAB: "bts", 0xB3: "btr", 0xBB: "btc",
            0xA4: "shld", 0xA5: "shld",
            0xAC: "shrd", 0xAD: "shrd",
            0xC0: "xadd", 0xC1: "xadd",
        }
        if second in modrm_ops:
            size = operand_size
            if second in (0xB6, 0xBE):
                size = 8
            elif second in (0xB7, 0xBF):
                size = 16
            modrm = code[pos]
            pos += 1
            rm, reg_field, consumed = self._modrm(code, pos, modrm, rex)
            pos += consumed
            rm.size = size
            operands: list = [self._reg_operand(reg_field, operand_size), rm]
            if second in (0xA4, 0xA5, 0xAC, 0xAD):
                if second in (0xA4, 0xAC):
                    operands.append(code[pos])
                    pos += 1
                else:
                    operands.append(None)  # count comes from cl
            return Insn(modrm_ops[second], operands, start + pos, size=pos, rep=rep)

        if 0x90 <= second <= 0x9F:
            # setcc r/m8
            names = ["seto", "setno", "setb", "setae", "sete", "setne", "setbe", "seta",
                     "sets", "setns", "setp", "setnp", "setl", "setge", "setle", "setg"]
            modrm = code[pos]
            pos += 1
            rm, _reg, consumed = self._modrm(code, pos, modrm, rex)
            pos += consumed
            rm.size = 8
            return Insn(names[second - 0x90], [rm], start + pos, size=pos, rep=rep)

        if 0xC8 <= second <= 0xCF:
            index = (second - 0xC8) | ((rex & 0x01) << 3)
            return Insn("bswap", [self._reg_operand(index, operand_size)], start + pos,
                        size=pos, rep=rep)

        if second == 0x1F:
            # Multi-byte NOP, usually padding before a function.
            modrm = code[pos]
            pos += 1
            _rm, _reg, consumed = self._modrm(code, pos, modrm, rex)
            pos += consumed
            return Insn("nop", [], start + pos, size=pos, rep=rep)

        raise DecodeError(f"two-byte opcode 0f {second:#04x} at {start:#x} is not implemented")
