"""High level entry points: load a blob, run it, read what it did.

The entry points you actually call.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .decoder import Machine
from .errors import EmulatorError, ExecuteError
from .executor import Executor, Hooks, SyscallRecord
from .memory import Memory
from .vfs import Vfs

# Where a raw blob is loaded and entered, unless you say otherwise.
DEFAULT_BASE = 0x1000
DEFAULT_STACK = 0x7FFFFFF0


@dataclass
class RunResult:
    """What a run did, in the shape you want it."""

    exit_code: int | None
    steps: int
    syscalls: list[SyscallRecord]
    output: bytes
    registers: dict
    flags: int
    trace: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    traffic: list = field(default_factory=list)

    @property
    def syscall_names(self) -> list[str]:
        return [s.name for s in self.syscalls]

    def writes(self) -> int:
        return sum(1 for s in self.syscalls if s.name == "write")

    def __str__(self) -> str:
        out = []
        out.append(f"steps:     {self.steps}")
        out.append(f"exit:      {self.exit_code}")
        out.append(f"syscalls:  {len(self.syscalls)}")
        if self.output:
            preview = self.output[:64].decode("latin-1", "replace")
            out.append(f"output:    {len(self.output)} bytes  {preview!r}")
        if self.syscalls:
            out.append("calls:     " + ", ".join(f"{s.name}{tuple(hex(a) for a in s.args[:3])}" for s in self.syscalls[:12]))
        if self.traffic:
            peers = sorted({f.peer for f in self.traffic})
            total = sum(len(f.data) for f in self.traffic)
            out.append(f"traffic:   {total} bytes to {', '.join(peers)}")
        return "\n".join(out)


def load_shellcode(
    code: bytes,
    *,
    base: int = DEFAULT_BASE,
    entry: int | None = None,
    stack: int = DEFAULT_STACK,
    argv: list[str] | None = None,
    envp: dict[str, str] | None = None,
    bits: int = 64,
    max_steps: int = 1_000_000,
) -> Machine:
    """Place a raw code blob in memory with a stack and the usual entry state.

    Flat loader, not a PE loader: no imports are resolved and no relocations are
    applied. That is usually fine, since the interesting shellcode resolves its
    own imports at runtime anyway.
    """
    machine = Machine(mem=Memory(), bits=bits, max_steps=max_steps)
    machine.mem.write(base, code)
    machine.w("rsp", stack)

    # Strings go below the stack, then the pointer arrays above them, and argc
    # on top of that. A stub that reads its arguments will find them where a real
    # kernel would have put them. The gap is kept small enough that a low stack
    # top still lands below it.
    string_base = stack - 0x1000
    if string_base <= base + len(code) + 0x100:
        string_base = base + len(code) + 0x100
    if string_base >= stack:
        raise ValueError(f"stack {stack:#x} is too low to lay out argv below it")
    argv_offsets: list[int] = []
    cursor = string_base
    for value in argv or []:
        argv_offsets.append(cursor)
        cursor += len(value.encode("latin-1")) + 1

    envp_offsets: list[int] = []
    for key, value in (envp or {}).items():
        envp_offsets.append(cursor)
        cursor += len(key) + len(value) + 2

    ptr_base = cursor + 0x100
    machine.mem.write(string_base, b"\x00" * (ptr_base - string_base))
    for offset, value in zip(argv_offsets, argv or []):
        machine.mem.write(offset, value.encode("latin-1") + b"\x00")
    for offset, (key, value) in zip(envp_offsets, (envp or {}).items()):
        machine.mem.write(offset, f"{key}={value}".encode("latin-1") + b"\x00")

    ptr = ptr_base
    for offset in argv_offsets:
        machine.mem.write_u64(ptr, offset)
        ptr += 8
    machine.mem.write_u64(ptr, 0)
    ptr += 8
    for offset in envp_offsets:
        machine.mem.write_u64(ptr, offset)
        ptr += 8
    machine.mem.write_u64(ptr, 0)

    # Build the stack top down: envp pointers, NULL, argv pointers, NULL, argc.
    rsp = stack

    def push(value: int) -> None:
        nonlocal rsp
        rsp -= 8
        machine.mem.write_u64(rsp, value)

    push(0)
    for offset in reversed(envp_offsets):
        push(offset)
    push(0)
    for offset in reversed(argv_offsets):
        push(offset)
    push(len(argv or []))

    machine.w("rsp", rsp)
    machine.w("rdi", len(argv or []))
    machine.rip = entry if entry is not None else base
    return machine


def emulate(
    code: bytes,
    *,
    base: int = DEFAULT_BASE,
    entry: int | None = None,
    stack: int = DEFAULT_STACK,
    argv: list[str] | None = None,
    envp: dict[str, str] | None = None,
    bits: int = 64,
    max_steps: int = 1_000_000,
    trace: bool = False,
    hooks: Hooks | None = None,
    vfs: Vfs | None = None,
    stdin: bytes = b"",
    machine: Machine | None = None,
) -> RunResult:
    """Load and run a code blob, returning what it did.

    Pass `machine` to reuse a prepared one, which is how you pre-load data at an
    address the stub will read. Pass `vfs` to control the filesystem the guest
    sees; without one it gets a small fake root and no access to yours.
    """
    if machine is None:
        machine = load_shellcode(
            code, base=base, entry=entry, stack=stack, argv=argv, envp=envp, bits=bits, max_steps=max_steps
        )
    if stdin:
        machine.mem.write(0x7FFFFF00, stdin)

    executor = Executor(machine, trace=trace, hooks=hooks, vfs=vfs)
    errors: list[str] = []
    try:
        executor.run(entry if entry is not None else base)
    except ExecuteError as exc:
        errors.append(str(exc))
    except EmulatorError as exc:
        errors.append(str(exc))

    return RunResult(
        exit_code=executor.exit_code,
        steps=machine.steps,
        syscalls=list(executor.syscalls),
        output=bytes(executor.output),
        registers=dict(machine.regs),
        flags=machine.flags,
        trace=list(executor.trace_log),
        errors=errors,
        traffic=list(executor.net.flows),
    )


class TraceHooks(Hooks):
    """Prints each instruction as it executes. Slow, but it is how you find
    where a stub goes wrong."""

    def __init__(self, limit: int = 500, out=print):
        self.limit = limit
        self.out = out
        self.count = 0

    def before_insn(self, machine: Machine, insn) -> None:
        if self.count >= self.limit:
            return
        self.count += 1
        self.out(f"{machine.rip:08x}  {insn.mnemonic}")


class SnapshotHooks(Hooks):
    """Records memory writes so you can see what the stub built.

    Usually pointed at the region where a loader assembles a string or a decoded
    buffer.
    """

    def __init__(self, regions: list[tuple[int, int]] | None = None):
        self.regions = regions or []
        self.changes: list[tuple[int, bytes]] = []

    def on_write(self, machine: Machine, addr: int, data: bytes) -> None:
        for start, end in self.regions:
            if start <= addr < end:
                self.changes.append((addr, data))
