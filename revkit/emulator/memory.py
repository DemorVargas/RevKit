"""Flat memory for an emulated machine.

Addresses are plain offsets into a sparse set of 4K pages. No paging, no
permission checks.
"""

from __future__ import annotations

from .errors import MemError

PAGE_BITS = 12
PAGE_SIZE = 1 << PAGE_BITS


class Memory:
    """Sparse memory: a dict of pages, allocated on first touch."""

    def __init__(self, page_bits: int = PAGE_BITS):
        self.page_bits = page_bits
        self.page_size = 1 << page_bits
        self.mask = self.page_size - 1
        self._pages: dict[int, bytearray] = {}

    def page_for(self, addr: int) -> tuple[int, bytearray]:
        if addr < 0:
            raise MemError(f"negative address {addr:#x}")
        pno = addr >> self.page_bits
        page = self._pages.get(pno)
        if page is None:
            page = bytearray(self.page_size)
            self._pages[pno] = page
        return pno, page

    def read(self, addr: int, size: int) -> bytes:
        if size < 0:
            raise MemError(f"negative read size {size}")
        out = bytearray()
        while len(out) < size:
            pno, page = self.page_for(addr + len(out))
            off = (addr + len(out)) & self.mask
            take = min(self.page_size - off, size - len(out))
            out += page[off : off + take]
        return bytes(out)

    def write(self, addr: int, data: bytes) -> None:
        view = memoryview(data)
        done = 0
        while done < len(view):
            _, page = self.page_for(addr + done)
            off = (addr + done) & self.mask
            take = min(self.page_size - off, len(view) - done)
            page[off : off + take] = view[done : done + take]
            done += take

    def read_u64(self, addr: int) -> int:
        return int.from_bytes(self.read(addr, 8), "little")

    def read_u32(self, addr: int) -> int:
        return int.from_bytes(self.read(addr, 4), "little")

    def read_u16(self, addr: int) -> int:
        return int.from_bytes(self.read(addr, 2), "little")

    def read_u8(self, addr: int) -> int:
        return self.read(addr, 1)[0]

    def write_u64(self, addr: int, value: int) -> None:
        self.write(addr, (value & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little"))

    def write_u32(self, addr: int, value: int) -> None:
        self.write(addr, (value & 0xFFFFFFFF).to_bytes(4, "little"))

    def write_u16(self, addr: int, value: int) -> None:
        self.write(addr, (value & 0xFFFF).to_bytes(2, "little"))

    def write_u8(self, addr: int, value: int) -> None:
        self.write(addr, bytes([value & 0xFF]))

    def read_cstring(self, addr: int, max_len: int = 4096) -> str:
        """NUL-terminated string, stopping at the first zero byte."""
        out = bytearray()
        while len(out) < max_len:
            chunk = self.read(addr + len(out), 64)
            zero = chunk.find(b"\x00")
            if zero != -1:
                out += chunk[:zero]
                break
            out += chunk
        return out.decode("latin-1")

    def read_wstring(self, addr: int, max_len: int = 4096) -> str:
        """NUL-terminated UTF-16LE string."""
        out = bytearray()
        while len(out) < max_len * 2:
            chunk = self.read(addr + len(out), 128)
            pair = bytearray()
            i = 0
            done = False
            while i + 1 < len(chunk):
                if chunk[i] == 0 and chunk[i + 1] == 0:
                    done = True
                    break
                pair += chunk[i : i + 2]
                i += 2
            out += pair
            if done:
                break
        return out.decode("utf-16-le", errors="ignore")

    def dump(self, addr: int, size: int) -> str:
        return self.read(addr, size).hex()

    def pages_touched(self) -> int:
        return len(self._pages)

    def clear(self) -> None:
        self._pages.clear()
