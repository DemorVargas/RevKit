#!/usr/bin/env python3
"""Worked example: analyse a real binary on this machine.

No arguments, no sample files. Picks the first ELF it can find and walks through
identification, structure, imports, strings and signatures.

Usage: python examples/09_real_binary.py
"""

from __future__ import annotations

import os

from revkit import carve, elf, entropy, report, signatures, strings

CANDIDATES = ["/bin/ls", "/usr/bin/python3", "/bin/sh", "/usr/bin/git"]


def pick_binary() -> str:
    for path in CANDIDATES:
        if os.path.isfile(path):
            return path
    raise SystemExit("no candidate binary found; edit CANDIDATES in this script")


def main() -> int:
    path = pick_binary()
    data = open(path, "rb").read()

    print(f"=== {path} ({len(data)} bytes) ===\n")

    parsed = elf.parse_elf(data, path)
    summary = parsed.summary()
    for key in ("machine", "type", "bits", "endian", "entry_point", "interpreter", "build_id"):
        if summary.get(key):
            print(f"{key:14} {summary[key]}")

    print(f"\nsections:   {len(parsed.sections)}")
    print(f"segments:   {len(parsed.segments)}")
    print(f"imports:    {len(parsed.imports())}")

    print("\nsegments:")
    for seg in parsed.segments:
        if seg.type_name == "LOAD":
            print(f"  {seg.rwx}  vaddr 0x{seg.virtual_address:08x}  file 0x{seg.offset:08x}  {seg.file_size} bytes")

    imports = parsed.imports()
    if imports:
        print(f"\nfirst imports:")
        for sym in imports[:8]:
            print(f"  {sym.name}")

    wide = strings.extract_utf16(data, 6)
    if wide:
        print(f"\nwide strings ({len(wide)}), first few:")
        for hit in wide[:5]:
            print(f"  0x{hit.offset:08x}  {hit.value}")

    hits = signatures.scan(data, signatures.default_rules(), max_hits=20)
    if hits:
        print(f"\nsignature hits ({len(hits)}):")
        for hit in hits[:8]:
            print(f"  [{hit.severity:8}] {hit.rule:20} {hit.matched[:48]!r}")
    else:
        print("\nno signature hits")

    regions = carve.high_entropy_regions(data, block=4096, threshold=7.5)
    print(f"\nhigh-entropy regions: {len(regions)}")
    for region in regions[:5]:
        print(f"  0x{region.start:08x} - 0x{region.end:08x}  {len(region)} bytes")

    print("\nfull report:")
    print(report.to_markdown(report.analyze(path))[:2000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
