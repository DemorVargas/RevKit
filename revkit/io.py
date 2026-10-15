"""Reading things out of files on disk.

Pretty much every module here takes a path, so this is the one that owns all the
bit-fiddling: pulling bytes out, reading little-endian integers, walking table
offsets.  Keeping it in one place means the format parsers above can stay boring.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Iterator


class FormatError(Exception):
    """Raised when a file does not look like the format we asked for."""


def read_file(path: str | os.PathLike) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def iter_chunks(data: bytes, chunk_size: int = 65536) -> Iterator[bytes]:
    """Yield data in chunks, so a 400MB firmware dump does not need 400MB of RAM."""
    for i in range(0, len(data), chunk_size):
        yield data[i : i + chunk_size]


class Reader:
    """A little cursor over a byte string.  Always little-endian, because
    everything we care about (PE, ELF, x86) is."""

    def __init__(self, data: bytes, base: int = 0):
        self.data = data
        self.pos = 0
        # base is added to every offset we report.  Useful for section-relative
        # reads, where a file offset is still what you want to see.
        self.base = base

    def seek(self, off: int) -> None:
        self.pos = off

    def tell(self) -> int:
        return self.pos

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def read(self, n: int) -> bytes:
        if n < 0:
            raise ValueError("negative read")
        if self.pos + n > len(self.data):
            raise FormatError(f"wanted {n} bytes at {self.base + self.pos}, only {self.remaining()} left")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def read_cstring(self, max_len: int | None = None) -> str:
        """Read up to the next NUL.  Used for import names, section names, the lot."""
        end = self.data.find(b"\x00", self.pos)
        if end == -1:
            end = len(self.data)
        if max_len is not None:
            end = min(end, self.pos + max_len)
        raw = self.data[self.pos : end]
        self.pos = end + 1
        return raw.decode("latin-1")

    def u8(self) -> int:
        return self.read(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.read(2), "little")

    def u32(self) -> int:
        return int.from_bytes(self.read(4), "little")

    def u64(self) -> int:
        return int.from_bytes(self.read(8), "little")

    def off(self) -> int:
        """Current position as a real file offset."""
        return self.base + self.pos


def rva_to_offset(rva: int, sections) -> int | None:
    """Turn an RVA into a file offset using a section table.

    Returns None when the RVA falls outside every section, which happens with
    things like resource-only images.  Callers decide if that matters.
    """
    for sec in sections:
        start = sec.get("virtual_address", 0)
        size = sec.get("virtual_size", sec.get("size_of_raw_data", 0))
        if start <= rva < start + size:
            delta = rva - start
            raw = sec.get("pointer_to_raw_data", 0)
            raw_size = sec.get("size_of_raw_data", 0)
            if delta >= raw_size:
                return None
            return raw + delta
    return None


@dataclass
class Range:
    """Half-open byte range [start, end).  Entropy and carving both want these."""

    start: int
    end: int

    def __post_init__(self):
        if self.end < self.start:
            raise ValueError(f"range ends before it starts: {self}")

    def __len__(self) -> int:
        return self.end - self.start

    def slice(self, data: bytes) -> bytes:
        return data[self.start : self.end]

    def overlaps(self, other: "Range") -> bool:
        return self.start < other.end and other.start < self.end


def u16le(b: bytes) -> int:
    return int.from_bytes(b[:2], "little")


def u32le(b: bytes) -> int:
    return int.from_bytes(b[:4], "little")


def cstr_at(data: bytes, off: int, max_len: int = 260) -> str:
    """NUL-terminated string at an absolute offset."""
    if off >= len(data):
        return ""
    end = data.find(b"\x00", off)
    if end == -1 or end - off > max_len:
        end = min(off + max_len, len(data))
    return data[off:end].decode("latin-1")


def align_up(value: int, alignment: int) -> int:
    if alignment <= 1:
        return value
    return (value + alignment - 1) // alignment * alignment

