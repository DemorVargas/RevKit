#!/usr/bin/env python3
"""Strings: pull the readable text out and flag the suspicious bits.

Usage: python examples/03_strings.py <path> [min_length]
"""

from __future__ import annotations

import sys

from revkit import formats, strings


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    path = argv[1]
    min_len = int(argv[2]) if len(argv) > 2 else 4

    data = open(path, "rb").read()

    ascii_hits = strings.extract_ascii(data, min_len)
    wide_hits = strings.extract_utf16(data, min_len)
    print(f"ascii strings:    {len(ascii_hits)}")
    print(f"utf-16 strings:   {len(wide_hits)}")

    if wide_hits:
        print("\nwide strings (the ones people forget to obfuscate):")
        for hit in wide_hits[:10]:
            print(f"  0x{hit.offset:08x}  {hit.value}")

    suspicious = strings.find_suspicious(data, min_len)
    if suspicious:
        print(f"\nsuspicious ({len(suspicious)}):")
        for hit in suspicious[:15]:
            print(f"  0x{hit.offset:08x}  {hit.value[:80]}")
    else:
        print("\nnothing suspicious in the strings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
