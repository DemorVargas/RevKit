"""Patching binaries: offset writes, PE checksum fixup, section edits.

Every write goes to a copy by default. `--in-place` exists, but it always leaves
a `.bak` behind, because a patch you cannot undo is a bad day.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass

from .io import FormatError, read_file


@dataclass
class PatchResult:
    path: str
    backup: str | None
    offset: int
    old: bytes
    new: bytes
    note: str = ""

    @property
    def changed(self) -> bool:
        return self.old != self.new

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "backup": self.backup,
            "offset": self.offset,
            "old": self.old[:64].hex(),
            "new": self.new[:64].hex(),
            "changed": self.changed,
            "note": self.note,
        }


def apply_patch(
    data: bytes,
    offset: int,
    new_bytes: bytes,
    path: str = "<memory>",
    backup_path: str | None = None,
) -> tuple[bytes, PatchResult]:
    """Write new_bytes at offset into a copy of data and write it to disk.

    Returns (new_data, result). The original bytes on disk are untouched unless
    the caller asked for an in-place write, and even then a .bak is written.
    """
    if offset < 0:
        raise FormatError(f"negative offset {offset}")
    if offset + len(new_bytes) > len(data):
        raise FormatError(
            f"patch at 0x{offset:x} with {len(new_bytes)} bytes runs past the end of a {len(data)} byte file"
        )

    old = data[offset : offset + len(new_bytes)]
    patched = data[:offset] + new_bytes + data[offset + len(new_bytes) :]
    if patched == data:
        return data, PatchResult(path=path, backup=backup_path, offset=offset, old=old, new=new_bytes)

    if backup_path is None and path != "<memory>":
        backup_path = path + ".bak"

    if path != "<memory>":
        if backup_path:
            with open(backup_path, "wb") as fh:
                fh.write(data)
        with open(path, "wb") as fh:
            fh.write(patched)

    return patched, PatchResult(
        path=path,
        backup=backup_path,
        offset=offset,
        old=old,
        new=new_bytes,
    )


def patch_file(
    path: str,
    offset: int,
    new_bytes: bytes,
    *,
    in_place: bool = False,
    backup: bool = True,
) -> tuple[bytes, PatchResult]:
    """Read a file, patch it, and write the result.

    Default behaviour writes `<name>.patched` and leaves the original alone.
    Pass in_place=True to overwrite the original (a .bak is still written unless
    backup=False).
    """
    data = read_file(path)
    if in_place:
        target = path
    else:
        target = path + ".patched"

    old = data[offset : offset + len(new_bytes)]
    patched = data[:offset] + new_bytes + data[offset + len(new_bytes) :]

    backup_path = path + ".bak" if in_place and backup else None
    if backup_path:
        with open(backup_path, "wb") as fh:
            fh.write(data)

    with open(target, "wb") as fh:
        fh.write(patched)

    return patched, PatchResult(path=target, backup=backup_path, offset=offset, old=old, new=new_bytes)


def patch_nops(data: bytes, offset: int, length: int, nop: int = 0x90) -> bytes:
    """Overwrite a run of bytes with NOPs, which is how you disable a check."""
    return data[:offset] + bytes([nop]) * length + data[offset + length :]


def parse_bytes_arg(spec: str) -> bytes:
    """Accept several ways of writing bytes on the command line.

    `90 90 c3`, `0x90,0x90,0xc3`, and `\\x90\\x90\\xc3` all work, because nobody
    wants to guess which one a tool accepts.
    """
    s = spec.strip()
    if not s:
        raise FormatError("empty byte string")

    # \x90\x90 style
    if "\\x" in s:
        out = bytearray()
        i = 0
        while i < len(s):
            if s[i] == "\\" and s[i + 1 : i + 2] == "x":
                out.append(int(s[i + 2 : i + 4], 16))
                i += 4
            elif s[i] in " \t,":
                i += 1
            else:
                raise FormatError(f"bad escape at position {i} in {spec!r}")
        return bytes(out)

    # hex text like "90 90 c3", with optional 0x prefixes and separators
    cleaned = s.replace(",", " ").replace("\t", " ")
    if all(c in "0123456789abcdefABCDEF xX" for c in cleaned):
        tokens = []
        for token in cleaned.split():
            if token.lower().startswith("0x"):
                token = token[2:]
            tokens.append(token)
        if tokens:
            try:
                return bytes(int(t, 16) for t in tokens)
            except ValueError as exc:
                raise FormatError(f"bad hex byte in {spec!r}: {exc}") from exc

    # otherwise treat it as literal text
    return spec.encode("latin-1")


def parse_offset(spec: str) -> int:
    """0x1040, 4160 and 0o101000 all mean the same thing here."""
    s = spec.strip().lower()
    try:
        if s.startswith("0x"):
            return int(s, 16)
        if s.startswith("0o"):
            return int(s, 8)
        if s.startswith("0b"):
            return int(s, 2)
        return int(s, 10)
    except ValueError as exc:
        raise FormatError(f"cannot parse offset {spec!r}") from exc


def pe_checksum(data: bytes) -> int:
    """PE checksum per the spec. Used to fix up a file after patching, since
    Windows loader ignores a wrong one but plenty of other tools do not."""
    if len(data) < 0x40:
        return 0
    # CheckSum field is at offset 0x58 in the optional header, i.e. pe_off + 4 + 60.
    pe_off = int.from_bytes(data[0x3C:0x40], "little")
    checksum_at = pe_off + 4 + 60
    if checksum_at + 4 > len(data):
        return 0

    # Zero the checksum field, then sum 16-bit words with carry folded back in.
    buf = bytearray(data)
    buf[checksum_at : checksum_at + 4] = b"\x00\x00\x00\x00"
    if len(buf) % 2:
        buf.append(0)

    total = 0
    for i in range(0, len(buf), 2):
        total += int.from_bytes(buf[i : i + 2], "little")
        total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (total + len(buf)) & 0xFFFFFFFF


def fix_pe_checksum(data: bytes) -> bytes:
    """Return data with a correct PE checksum written in."""
    pe_off = int.from_bytes(data[0x3C:0x40], "little")
    checksum_at = pe_off + 4 + 60
    if checksum_at + 4 > len(data):
        return data
    checksum = pe_checksum(data)
    return data[:checksum_at] + checksum.to_bytes(4, "little") + data[checksum_at + 4 :]


def find_bytes(data: bytes, needle: bytes, start: int = 0) -> list[int]:
    """Every offset where needle appears. Used to locate the bytes to patch."""
    out = []
    pos = data.find(needle, start)
    while pos != -1:
        out.append(pos)
        pos = data.find(needle, pos + 1)
    return out


def write_backup(path: str, data: bytes) -> str:
    """Copy the current contents of path to path.bak, refusing to clobber an
    existing backup."""
    backup = path + ".bak"
    if os.path.exists(backup):
        raise FormatError(f"{backup} already exists, not overwriting it")
    with open(path, "rb") as src, open(backup, "wb") as dst:
        shutil.copyfileobj(src, dst)
    return backup
