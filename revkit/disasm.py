"""Disassembly of raw code blobs.

capstone is optional and imported lazily, so the rest of the package works on a
bare machine. Without it you get a clean error telling you the exact install
command, not a traceback.
"""

from __future__ import annotations

from dataclasses import dataclass


class MissingDependency(ImportError):
    """Raised when an optional dependency is not installed."""

    def __init__(self, package: str, extra: str, purpose: str):
        self.package = package
        self.extra = extra
        self.purpose = purpose
        super().__init__(
            f"{package} is required for {purpose}. Install it with: pip install -e '.[{extra}]'"
        )


def _capstone():
    try:
        import capstone  # type: ignore
    except ImportError as exc:
        raise MissingDependency("capstone", "disasm", "disassembly") from exc
    return capstone


@dataclass
class Instruction:
    address: int
    mnemonic: str
    operands: str
    size: int
    bytes: bytes

    def __str__(self) -> str:
        if self.operands:
            return f"{self.mnemonic} {self.operands}"
        return self.mnemonic

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "mnemonic": self.mnemonic,
            "operands": self.operands,
            "size": self.size,
            "bytes": self.bytes.hex(),
        }


def disassemble(
    data: bytes,
    base: int = 0,
    *,
    bits: int = 64,
    limit: int = 0,
    stop_on_ret: bool = False,
) -> list[Instruction]:
    """Disassemble a raw blob. `base` is the address the blob would be loaded at,
    which is what you want for reading relative jumps."""
    cs = _capstone()
    mode = cs.CS_MODE_64 if bits == 64 else cs.CS_MODE_32
    md = cs.Cs(cs.CS_ARCH_X86, mode)
    md.detail = False

    out: list[Instruction] = []
    for ins in md.disasm(data, base):
        out.append(
            Instruction(
                address=ins.address,
                mnemonic=ins.mnemonic,
                operands=ins.op_str,
                size=ins.size,
                bytes=ins.bytes,
            )
        )
        if limit and len(out) >= limit:
            break
        if stop_on_ret and ins.mnemonic in ("ret", "retf", "int3", "hlt"):
            break
    return out


def syscall_names(bits: int = 64) -> dict[int, str]:
    """x86-64 and x86-32 syscall numbers for the common ones. Reading `rax`
    before a `syscall` is the fastest way to know what a shellcode stub does."""
    if bits == 64:
        return {
            0: "read", 1: "write", 2: "open", 3: "close", 9: "mmap", 10: "mprotect",
            11: "munmap", 12: "brk", 21: "access", 39: "getpid", 57: "fork",
            59: "execve", 60: "exit", 61: "wait4", 62: "kill", 102: "getuid",
            104: "getgid", 105: "setuid", 106: "setgid", 107: "geteuid",
            131: "sigaltstack", 158: "arch_prctl", 186: "gettid", 201: "time",
            217: "getdents64", 231: "exit_group", 257: "openat", 262: "newfstatat",
            318: "getrandom", 332: "statx", 334: "rseq", 435: "clone3",
        }
    return {
        1: "exit", 3: "read", 4: "write", 5: "open", 6: "close", 11: "execve",
        12: "chdir", 13: "time", 20: "getpid", 33: "access", 39: "mkdir",
        41: "dup", 42: "pipe", 45: "brk", 54: "ioctl", 85: "readlink",
        90: "mmap", 91: "munmap", 106: "lstat", 114: "wait4", 120: "clone",
        122: "uname", 125: "mprotect", 140: "llseek", 146: "writev",
        192: "mmap2", 197: "fstat64", 221: "fcntl64", 334: "set_thread_area",
    }


def annotate_syscalls(instructions: list[Instruction], bits: int = 64) -> list[dict]:
    """Mark instructions that set up a syscall and say which one it is.

    Looks back a few instructions for `mov rax, N` / `mov eax, N`, which is how
    nearly every stub does it.
    """
    names = syscall_names(bits)
    out = []
    for i, ins in enumerate(instructions):
        entry = ins.to_dict()
        if ins.mnemonic in ("syscall", "sysenter", "int"):
            syscall_no = None
            for prev in reversed(instructions[max(0, i - 6) : i]):
                if prev.mnemonic in ("mov", "lea") and ("rax" in prev.operands or "eax" in prev.operands):
                    try:
                        syscall_no = int(prev.operands.split(",")[-1].strip(), 0)
                    except ValueError:
                        continue
                    break
            entry["syscall"] = names.get(syscall_no) if syscall_no is not None else None
            entry["syscall_number"] = syscall_no
        out.append(entry)
    return out


def call_targets(instructions: list[Instruction]) -> list[dict]:
    """Relative calls and jumps with their resolved targets. The first thing to
    look at in any shellcode, since it shows the shape of the code."""
    out = []
    for ins in instructions:
        if not ins.mnemonic.startswith(("call", "jmp", "je", "jne", "jz", "jnz", "loop")):
            continue
        try:
            target = int(ins.operands.split()[0], 0)
        except (ValueError, IndexError):
            continue
        out.append({"address": ins.address, "mnemonic": ins.mnemonic, "target": target, "ins": str(ins)})
    return out


def find_api_resolution(instructions: list[Instruction]) -> list[dict]:
    """Spot the classic GetProcAddress / LoadLibrary pattern, which is how
    position-independent shellcode finds the functions it wants."""
    interesting = ("VirtualAlloc", "VirtualProtect", "LoadLibrary", "GetProcAddress",
                   "CreateProcess", "WinExec", "ShellExecute", "InternetOpen",
                   "URLDownloadToFile", "CreateRemoteThread", "RegSetValue")
    out = []
    for ins in instructions:
        for name in interesting:
            if name.lower() in ins.operands.lower():
                out.append({"address": ins.address, "api": name, "ins": str(ins)})
    return out
