#!/usr/bin/env python3
"""Carving: pull embedded files and sections out to disk.

Usage: python examples/05_carve.py <path> [outdir]
"""

from __future__ import annotations

import os
import sys

from revkit import carve, elf, formats, pe


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    path = argv[1]
    outdir = argv[2] if len(argv) > 2 else "carved"

    data = open(path, "rb").read()
    print(f"file: {path} ({len(data)} bytes)\n")

    found = carve.carve_by_magic(data)

    # Sections need a section table, so use the real parsers where we have them.
    if data[:4] == b"\x7fELF":
        found += carve.carve_sections(data, [s.to_dict() for s in elf.parse_elf(data, path).sections])
    elif data[:2] == b"MZ":
        parsed = pe.parse_pe(data, path)
        found += carve.carve_sections(data, [s.to_dict() for s in parsed.sections])
        overlay = carve.find_overlay(data, parsed.overlay_start)
        if overlay:
            found.append(overlay)

    if not found:
        print("nothing carved")
        return 0

    os.makedirs(outdir, exist_ok=True)
    seen: set[tuple[int, int]] = set()
    written = 0
    for obj in found:
        if (obj.offset, obj.end) in seen:
            continue
        seen.add((obj.offset, obj.end))
        name = f"{written:03d}_{obj.offset:08x}_{obj.kind}.bin"
        with open(os.path.join(outdir, name), "wb") as fh:
            fh.write(data[obj.offset : obj.end])
        print(f"{name:44} {obj.size:8d} bytes  {obj.description}")
        written += 1

    print(f"\n{written} object(s) written to {outdir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
