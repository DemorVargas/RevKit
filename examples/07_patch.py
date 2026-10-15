#!/usr/bin/env python3
"""Patching: write bytes at an offset, with a backup.

Usage: python examples/07_patch.py <path> <offset> <bytes>

offset is 0x1040 or 4160. bytes is "90 90 c3" or "\\x90\\x90\\xc3".
"""

from __future__ import annotations

import shutil
import sys

from revkit import patcher


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        print(__doc__)
        return 2
    path, offset_spec, byte_spec = argv[1], argv[2], argv[3]

    # Work on a copy so running the example does not touch the original.
    scratch = path + ".example"
    shutil.copyfile(path, scratch)

    offset = patcher.parse_offset(offset_spec)
    new_bytes = patcher.parse_bytes_arg(byte_spec)

    print(f"file:   {scratch}")
    print(f"offset: 0x{offset:x}")
    print(f"bytes:  {new_bytes.hex()}")

    with open(scratch, "rb") as fh:
        original = fh.read()
    print(f"before: {original[offset:offset + len(new_bytes)].hex()}")

    patched, result = patcher.patch_file(scratch, offset, new_bytes, in_place=True, backup=False)

    print(f"after:  {patched[offset:offset + len(new_bytes)].hex()}")
    print(f"wrote:  {result.path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
