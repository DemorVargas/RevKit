#!/usr/bin/env python3
"""Run a raw code blob in the emulator and show what it did.

Usage: python examples/10_emulate.py <path>
       python examples/10_emulate.py --hex 48c7c03c00000048c7c7400000000f05
"""

from __future__ import annotations

import sys

from revkit.emulator import runner
from revkit.emulator.executor import Executor
from revkit.io import read_file

# Syscalls whose handlers reach the real filesystem. The emulator's read and stat
# paths call open() and os.stat() on the host, so block them unless you trust the
# blob. Blocked calls are still recorded, so the behaviour trail survives.
FILE_SYSCALLS = (2, 257, 85, 4, 5, 6, 262, 332)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2

    if argv[1] == "--hex":
        blob = bytes.fromhex(argv[2])
    else:
        blob = read_file(argv[1])

    machine = runner.load_shellcode(blob)
    executor = Executor(machine)
    for number in FILE_SYSCALLS:
        executor.block_syscall(number)

    try:
        executor.run()
    except Exception as exc:
        print(f"stopped:  {exc}")

    print(f"steps:    {machine.steps}")
    print(f"exit:     {executor.exit_code}")

    if executor.output:
        print(f"output:   {executor.output[:200]!r}")

    for call in executor.syscalls:
        args = ", ".join(hex(a) for a in call.args[:3])
        print(f"  {call.name}({args}) = {call.result}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
