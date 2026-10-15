#!/usr/bin/env python3
"""Disassemble a raw code blob. Needs capstone.

Usage: python examples/08_disassemble.py <path> [offset]
       python examples/08_disassemble.py --hex 48c7c03c0000000f05
"""

from __future__ import annotations

import sys

from revkit import disasm
from revkit.io import read_file


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2

    if argv[1] == "--hex":
        blob = bytes.fromhex(argv[2])
        base = 0
    else:
        path = argv[1]
        blob = read_file(path)
        base = 0
        if len(argv) > 2:
            from revkit.patcher import parse_offset

            base = parse_offset(argv[2])
            blob = blob[base:]

    try:
        ins = disasm.disassemble(blob, base=base, bits=64)
    except disasm.MissingDependency as exc:
        print(exc)
        return 1

    if not ins:
        print("no instructions decoded")
        return 0

    for i in ins[:200]:
        print(f"  0x{i.address:08x}  {i.bytes.hex():20}  {i}")

    syscalls = [r for r in disasm.annotate_syscalls(ins) if r.get("syscall")]
    if syscalls:
        print("\nsyscalls:")
        for row in syscalls:
            print(f"  0x{row['address']:08x}  {row['syscall']} ({row['syscall_number']})")

    targets = disasm.call_targets(ins)
    if targets:
        print(f"\n{len(targets)} control transfer(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
