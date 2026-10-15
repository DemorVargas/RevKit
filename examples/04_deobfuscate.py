#!/usr/bin/env python3
"""Deobfuscation: XOR, RC4, compression, base64.

Usage: python examples/04_deobfuscate.py <path> [method]

method is one of: all, xor-brute, xor, rc4, zlib, gzip, bzip2, lzma, base64
"""

from __future__ import annotations

import sys

from revkit import crypto


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    path = argv[1]
    method = argv[2] if len(argv) > 2 else "all"

    data = open(path, "rb").read()
    print(f"file: {path} ({len(data)} bytes)\n")

    if method == "xor":
        print("brute forcing a single-byte XOR key:")
        for hit in crypto.xor_brute(data, limit=5):
            print(f"  key {hit.key}  score {hit.score:.3f}")
            print(f"    {hit.plaintext[:96].decode('latin-1', 'replace')}")
        return 0

    if method == "rc4":
        key = input("key: ").encode()
        plain = crypto.rc4(data, key)
        print(plain[:2000].decode("latin-1", "replace"))
        return 0

    if method == "xor-key":
        key = bytes.fromhex(input("hex key: ").replace(" ", ""))
        print(crypto.xor_repeat(data, key)[:2000].decode("latin-1", "replace"))
        return 0

    hits = crypto.decode_all(data, None if method == "all" else [method])
    if not hits:
        print("nothing decodable found")
        return 0

    print(f"{len(hits)} candidate(s):")
    for hit in hits[:5]:
        print(f"\n  method {hit.method}  score {hit.score:.3f}  key {hit.key or '-'}")
        print(f"  {hit.plaintext[:200].decode('latin-1', 'replace')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
