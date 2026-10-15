"""Carving: pulling sections, embedded files and firmware partitions out of an image.

The idea is simple. Do not try to understand the whole thing at once, slice the
file into regions and name them. Once you have regions you can score entropy and
hunt strings in each one independently.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .entropy import shannon
from .io import Range
from .strings import extract_strings

# Signatures for embedded files. Long and distinctive, so random code bytes do
# not set them off.
MAGIC = [
    (b"\x7fELF", "elf", "Executable and Linkable Format"),
    (b"MZ", "pe", "DOS/PE executable"),
    (b"\xca\xfe\xba\xbe", "macho-fat", "Mach-O fat binary"),
    (b"\xfe\xed\xfa\xce", "macho-32", "Mach-O 32-bit (big endian)"),
    (b"\xce\xfa\xed\xfe", "macho-32le", "Mach-O 32-bit"),
    (b"\xfe\xed\xfa\xcf", "macho-64", "Mach-O 64-bit (big endian)"),
    (b"\xcf\xfa\xed\xfe", "macho-64le", "Mach-O 64-bit"),
    (b"\x1f\x8b\x08", "gzip", "gzip archive"),
    (b"BZh", "bzip2", "bzip2 archive"),
    (b"\xfd7zXZ", "xz", "xz archive"),
    (b"\x28\xb5\x2f\xfd", "zstd", "zstandard"),
    (b"PK\x03\x04", "zip", "ZIP archive"),
    (b"Rar!\x1a\x07", "rar", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7z", "7-Zip archive"),
    (b"\x37\x7a\xbc\xaf", "7z", "7-Zip archive (alt)"),
    (b"ustar", "tar", "tar archive"),
    (b"\xd0\x0d\xfe\xed", "deb", "Debian package"),
    (b"!<arch>", "ar", "ar archive"),
    (b"\x1a\x45\xdf\xa3", "matroska", "Matroska / WebM"),
    (b"\x00\x00\x00\x18ftyp", "mp4", "MP4 container"),
    (b"OggS", "ogg", "Ogg container"),
    (b"ID3", "mp3", "MP3 with ID3 tag"),
    (b"\xff\xfb", "mp3", "MP3 frame"),
    (b"RIFF", "riff", "RIFF container"),
    (b"\x89PNG\r\n\x1a\n", "png", "PNG image"),
    (b"\xff\xd8\xff", "jpeg", "JPEG image"),
    (b"GIF87a", "gif", "GIF image"),
    (b"GIF89a", "gif", "GIF image"),
    (b"BM", "bmp", "BMP image"),
    (b"%PDF", "pdf", "PDF document"),
    (b"\x25\x21PS", "postscript", "PostScript"),
    (b"SQLite format 3\x00", "sqlite", "SQLite database"),
]

# Tails that let us find where an embedded file actually ends.
TAIL_MAGIC = {
    "zip": b"PK\x05\x06",
    "png": b"IEND\xaeB`\x82",
    "jpeg": b"\xff\xd9",
    "pdf": b"%%EOF",
}

# Headers that in a firmware image mean "a partition starts here".
FIRMWARE_MARKERS = [
    (b"ANDROID!", "android-boot"),
    (b"RKIMAGE", "rockchip"),
    (b"u-boot", "uboot"),
    (b"UBI#", "ubi"),
    (b"\x55\xaa", "mbr"),
    (b"HDRS", "tplink"),
    (b"TP-LINK", "tplink"),
    (b"\x27\x05\x19\x56", "uimage"),
    (b"UBI!", "ubi-vol"),
    (b"ext4", "ext4"),
]


# Signatures that are so common in binary data that they only mean something at
# offset zero. Everything else is searched for anywhere in the file.
AT_ZERO_ONLY = {b"MZ", b"BM", b"ID3", b"\xff\xfb", b"RIFF", b"\xef\xbb\xbf", b"\x1a\x45\xdf\xa3", b"\x25\x21PS"}


@dataclass
class CarvedFile:
    """One carved object."""

    offset: int
    end: int
    kind: str
    description: str
    entropy: float
    size: int
    strings: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "offset": self.offset,
            "end": self.end,
            "size": self.size,
            "kind": self.kind,
            "description": self.description,
            "entropy": round(self.entropy, 4),
            "strings": [s.value for s in self.strings[:20]],
        }


def carve_by_magic(data: bytes, want: list[str] | None = None) -> list[CarvedFile]:
    """Scan the whole file for signatures and return one object per hit.

    The end is the next same-kind signature, or the known tail if we have one.
    That is why a ZIP buried in a binary gets carved as a ZIP, not as half the
    file.
    """
    found: list[CarvedFile] = []
    for magic, kind, description in MAGIC:
        if want and kind not in want:
            continue
        if magic in AT_ZERO_ONLY:
            # Too common to trust away from the start of the file.
            if not data.startswith(magic):
                continue
            pos = 0
        else:
            pos = data.find(magic)
        while pos != -1:
            end = _find_end(data, pos, kind)
            chunk = data[pos:end]
            if len(chunk) > 4:
                found.append(
                    CarvedFile(
                        offset=pos,
                        end=end,
                        kind=kind,
                        description=description,
                        entropy=shannon(chunk) if len(chunk) >= 16 else 0.0,
                        size=len(chunk),
                        strings=extract_strings(chunk, 5)[:20],
                    )
                )
            if magic in AT_ZERO_ONLY and pos == 0:
                # Only meaningful at the start of the file, so one hit is all there is.
                break
            nxt = data.find(magic, pos + 1)
            if nxt == pos:
                break
            pos = nxt
    found.sort(key=lambda f: f.offset)
    return found


def _find_end(data: bytes, start: int, kind: str) -> int:
    """Guess where an object stops."""
    tail = TAIL_MAGIC.get(kind)
    if tail:
        rel = data.find(tail, start + 1)
        if rel != -1:
            return rel + len(tail)
    # The next signature of any kind is a sane upper bound.
    nxt = len(data)
    for magic, other, _ in MAGIC:
        if other == kind:
            continue
        rel = data.find(magic, start + 1)
        if rel != -1:
            nxt = min(nxt, rel)
    return nxt


def carve_sections(data: bytes, sections: list[dict], names: bool = True) -> list[CarvedFile]:
    """Carve sections straight off a section table (PE or ELF), so each piece can
    be worked on on its own."""
    out = []
    for sec in sections:
        start = sec.get("pointer_to_raw_data", sec.get("offset", 0))
        size = sec.get("size_of_raw_data", sec.get("size", 0))
        if size <= 0 or start + size > len(data):
            continue
        chunk = data[start : start + size]
        out.append(
            CarvedFile(
                offset=start,
                end=start + size,
                kind="section",
                description=sec.get("name", "?"),
                entropy=shannon(chunk),
                size=size,
                strings=extract_strings(chunk, 5)[:20] if names else [],
            )
        )
    return out


def carve_firmware(data: bytes) -> list[CarvedFile]:
    """Look for firmware partition headers and hand them back as objects.

    Deliberately crude. Firmware has no single format, every vendor ships its own
    binary blob, so this just shows you where something partition-like starts and
    leaves the judging to you.
    """
    out = []
    for marker, kind in FIRMWARE_MARKERS:
        pos = data.find(marker)
        while pos != -1:
            chunk = data[pos : pos + 512]
            out.append(
                CarvedFile(
                    offset=pos,
                    end=pos + len(chunk),
                    kind=kind,
                    description=f"{kind} partition header",
                    entropy=shannon(chunk),
                    size=len(chunk),
                    strings=extract_strings(chunk, 4),
                )
            )
            nxt = data.find(marker, pos + 1)
            if nxt == pos:
                break
            pos = nxt
    out.sort(key=lambda f: f.offset)
    return out


def find_overlay(data: bytes, overlay_start: int) -> CarvedFile | None:
    """Anything after the last section. In PE this is the classic place for a
    second packed block."""
    if overlay_start <= 0 or overlay_start >= len(data):
        return None
    chunk = data[overlay_start:]
    return CarvedFile(
        offset=overlay_start,
        end=len(data),
        kind="overlay",
        description="data after the section table",
        entropy=shannon(chunk),
        size=len(chunk),
        strings=extract_strings(chunk, 5)[:20],
    )


def high_entropy_regions(data: bytes, block: int = 512, threshold: float = 7.5) -> list[Range]:
    """Backwards-compatible alias; the real implementation lives in entropy."""
    from .entropy import high_entropy_regions as _impl

    return _impl(data, block, threshold)
