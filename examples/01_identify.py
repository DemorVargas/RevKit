#!/usr/bin/env python3
"""Identify a file: what is it, how big, how random.

Usage: python examples/01_identify.py <path>
"""

from __future__ import annotations

import sys

from revkit import formats


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    path = argv[1]

    info = formats.identify_file(path)
    print(f"path:     {info.path}")
    print(f"format:   {info.format} ({info.description})")
    print(f"size:     {formats.human_size(info.size)}")
    print(f"entropy:  {info.entropy:.4f} / 8.0")
    print(f"suggest:  {info.extension_hint}")
    if info.embedded:
        print(f"embedded: {', '.join(info.embedded)}")
    for warning in info.warnings:
        print(f"warning:  {warning}")

    parsed = formats.parse_file(path)
    detail = parsed.get("detail", {})
    if detail:
        print("\nstructure:")
        for key, value in detail.items():
            if isinstance(value, (list, dict)):
                continue
            if isinstance(value, bool):
                value = "yes" if value else "no"
            print(f"  {key:16} {value}")

    if parsed.get("imports"):
        print(f"\nimports ({len(parsed['imports'])}):")
        for imp in parsed["imports"][:15]:
            name = imp.get("name") or f"ordinal {imp.get('ordinal')}"
            # PE imports name the DLL they come from; ELF imports do not have one.
            dll = imp.get("dll")
            print(f"  {dll:24} {name}" if dll else f"  {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
