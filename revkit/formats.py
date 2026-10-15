"""Format identification and dispatch.

This is the front door. It looks at the first few bytes and says what it is,
then hands off to the right parser. Everything else in the package is reachable
through `identify()` and `parse_any()`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import carve, elf, pe
from .io import FormatError, read_file

# Ordered by how distinctive the signature is. Short ones go last so a real ELF
# is not misread as something else.
SIGNATURES = [
    (b"\x7fELF", "elf"),
    (b"\xca\xfe\xba\xbe", "macho-fat"),
    (b"\xfe\xed\xfa\xce", "macho-32"),
    (b"\xce\xfa\xed\xfe", "macho-32le"),
    (b"\xfe\xed\xfa\xcf", "macho-64"),
    (b"\xcf\xfa\xed\xfe", "macho-64le"),
    (b"\x1f\x8b\x08", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ", "xz"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"PK\x03\x04", "zip"),
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"ustar", "tar"),
    (b"\xd0\x0d\xfe\xed", "deb"),
    (b"!<arch>", "ar"),
    (b"SQLite format 3\x00", "sqlite"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"%PDF", "pdf"),
    (b"\x00\x00\x00\x18ftyp", "mp4"),
    (b"OggS", "ogg"),
    (b"\x1a\x45\xdf\xa3", "matroska"),
    (b"MZ", "pe"),
    (b"\x50\x4b\x05\x06", "zip-empty"),
]


@dataclass
class FileInfo:
    """What we know about a file before we parse anything deeply."""

    path: str
    size: int
    format: str
    description: str
    extension_hint: str
    signatures: list[str] = field(default_factory=list)
    entropy: float = 0.0
    embedded: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "size": self.size,
            "format": self.format,
            "description": self.description,
            "extension_hint": self.extension_hint,
            "signatures": self.signatures,
            "entropy": round(self.entropy, 4),
            "embedded": self.embedded,
            "warnings": self.warnings,
        }


DESCRIPTIONS = {
    "elf": "ELF executable or shared object",
    "pe": "PE executable (DOS/Windows)",
    "macho-fat": "Mach-O universal binary",
    "macho-32": "Mach-O 32-bit",
    "macho-32le": "Mach-O 32-bit",
    "macho-64": "Mach-O 64-bit",
    "macho-64le": "Mach-O 64-bit",
    "gzip": "gzip compressed data",
    "bzip2": "bzip2 compressed data",
    "xz": "xz compressed data",
    "zstd": "zstandard compressed data",
    "zip": "ZIP archive",
    "rar": "RAR archive",
    "7z": "7-Zip archive",
    "tar": "tar archive",
    "deb": "Debian package",
    "ar": "ar archive",
    "sqlite": "SQLite database",
    "png": "PNG image",
    "jpeg": "JPEG image",
    "gif": "GIF image",
    "pdf": "PDF document",
    "mp4": "MP4 container",
    "ogg": "Ogg container",
    "matroska": "Matroska / WebM container",
    "shellcode": "raw x86 code",
    "firmware": "firmware image",
    "unknown": "unknown format",
}

EXTENSIONS = {
    "elf": ".elf",
    "pe": ".exe",
    "macho-fat": ".macho",
    "macho-32": ".macho",
    "macho-32le": ".macho",
    "macho-64": ".macho",
    "macho-64le": ".macho",
    "gzip": ".gz",
    "bzip2": ".bz2",
    "xz": ".xz",
    "zstd": ".zst",
    "zip": ".zip",
    "rar": ".rar",
    "7z": ".7z",
    "tar": ".tar",
    "deb": ".deb",
    "ar": ".a",
    "sqlite": ".sqlite",
    "png": ".png",
    "jpeg": ".jpg",
    "gif": ".gif",
    "pdf": ".pdf",
    "mp4": ".mp4",
    "ogg": ".ogg",
    "matroska": ".mkv",
    "shellcode": ".bin",
    "firmware": ".bin",
    "unknown": ".bin",
}


def sniff(data: bytes) -> tuple[str, list[str]]:
    """Return (primary format, all signature hits). Hits are every signature that
    matched anywhere in the file, which is what tells you a binary has something
    embedded in it."""
    if not data:
        return "unknown", []

    hits = []
    primary = None
    for sig, name in SIGNATURES:
        pos = data.find(sig)
        if pos == -1:
            continue
        hits.append(name)
        # The first match at offset zero wins as the primary format.
        if pos == 0 and primary is None:
            primary = name

    if primary is None:
        return "unknown", hits
    return primary, hits


def _is_truncated_pe(data: bytes) -> bool:
    """MZ at offset zero with no PE\\0\\0 where e_lfanew points. Either a DOS stub
    or a PE whose headers were stripped."""
    if not data.startswith(b"MZ"):
        return False
    if len(data) < 0x40:
        return True
    pe_off = int.from_bytes(data[0x3C:0x40], "little")
    if pe_off + 4 > len(data):
        return True
    return data[pe_off : pe_off + 4] != b"PE\x00\x00"


def identify(data: bytes, path: str = "<memory>") -> FileInfo:
    """Quick identification: format, size, entropy, embedded signatures."""
    from .entropy import shannon

    fmt, hits = sniff(data)
    info = FileInfo(
        path=path,
        size=len(data),
        format=fmt,
        description=DESCRIPTIONS.get(fmt, "unknown format"),
        extension_hint=EXTENSIONS.get(fmt, ".bin"),
        signatures=hits,
        entropy=shannon(data) if len(data) >= 256 else 0.0,
        embedded=[h for h in hits if h != fmt],
    )
    if _is_truncated_pe(data):
        info.warnings.append("MZ header present but no PE signature found: DOS stub or stripped PE")
    return info


def parse_any(data: bytes, path: str = "<memory>") -> dict:
    """Identify and fully parse. Returns a dict with the format-specific detail
    merged in. Never raises on a malformed file, the problem goes in warnings."""
    info = identify(data, path)
    out = info.to_dict()

    if info.format == "elf":
        try:
            parsed = elf.parse_elf(data, path)
            out["detail"] = parsed.summary()
            out["sections"] = [s.to_dict() for s in parsed.sections]
            out["segments"] = [s.to_dict() for s in parsed.segments]
            out["imports"] = [s.to_dict() for s in parsed.imports()]
            out["exports"] = [s.to_dict() for s in parsed.exports()]
        except FormatError as exc:
            out["warnings"].append(f"ELF parse failed: {exc}")
    elif info.format == "pe":
        try:
            parsed = pe.parse_pe(data, path)
            out["detail"] = parsed.summary()
            out["sections"] = [s.to_dict() for s in parsed.sections]
            out["imports"] = [i.to_dict() for i in parsed.imports]
            out["exports"] = [e.to_dict() for e in parsed.exports]
        except FormatError as exc:
            out["warnings"].append(f"PE parse failed: {exc}")
    else:
        # Not a fully parsed format, but carving still applies.
        carved = carve.carve_by_magic(data)
        out["carved"] = [c.to_dict() for c in carved]
        out["warnings"].append(
            f"{info.format} is identified by signature only; no structural parser yet"
        )

    return out


def identify_file(path: str) -> FileInfo:
    return identify(read_file(path), path)


def parse_file(path: str) -> dict:
    return parse_any(read_file(path), path)


def is_executable_format(fmt: str) -> bool:
    """Whether a format is something you would run rather than open."""
    return fmt in ("elf", "pe", "macho-fat", "macho-32", "macho-32le", "macho-64", "macho-64le", "shellcode")


def looks_like_firmware(data: bytes) -> bool:
    """A firmware image usually has no known executable header but carries
    vendor markers and a big block of high-entropy data."""
    fmt, _ = sniff(data)
    if fmt in ("elf", "pe"):
        return False
    markers = carve.carve_firmware(data)
    if not markers:
        return False
    regions = carve.high_entropy_regions(data)
    covered = sum(len(r) for r in regions)
    return len(markers) > 0 and covered > len(data) * 0.1


def human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f}{unit}" if unit != "B" else f"{n}B"
        n /= 1024
    return f"{n}B"

