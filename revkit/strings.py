"""String extraction.

ASCII and UTF-16LE, because those are the two you hit constantly in Windows
binaries, and wide strings are what malware authors forget to obfuscate.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class StringHit:
    offset: int
    value: str
    encoding: str
    length: int  # length in characters, not bytes


DEFAULT_MIN = 4


def _is_printable_ascii(b: int) -> bool:
    return 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D)


def extract_ascii(data: bytes, min_len: int = DEFAULT_MIN, offset: int = 0) -> list[StringHit]:
    """Runs of printable ASCII terminated by a non-printable byte."""
    hits: list[StringHit] = []
    start = None
    for i, b in enumerate(data):
        if _is_printable_ascii(b):
            if start is None:
                start = i
        elif start is not None:
            if i - start >= min_len:
                hits.append(
                    StringHit(
                        offset=offset + start,
                        value=data[start:i].decode("latin-1"),
                        encoding="ascii",
                        length=i - start,
                    )
                )
            start = None
    if start is not None and len(data) - start >= min_len:
        hits.append(
            StringHit(
                offset=offset + start,
                value=data[start:].decode("latin-1"),
                encoding="ascii",
                length=len(data) - start,
            )
        )
    return hits


def extract_utf16(data: bytes, min_len: int = DEFAULT_MIN, offset: int = 0) -> list[StringHit]:
    """Little-endian wide strings, which in practice means ASCII chars with a
    NUL between them.  Requiring the high byte to be zero cuts the false
    positives from 90% to nothing."""
    hits: list[StringHit] = []
    start = None
    for i in range(0, len(data) - 1, 2):
        lo, hi = data[i], data[i + 1]
        if hi == 0 and _is_printable_ascii(lo):
            if start is None:
                start = i
        elif start is not None:
            if (i - start) // 2 >= min_len:
                raw = data[start:i]
                hits.append(
                    StringHit(
                        offset=offset + start,
                        value=raw.decode("utf-16-le", errors="ignore"),
                        encoding="utf-16le",
                        length=len(raw) // 2,
                    )
                )
            start = None
    if start is not None and (len(data) - start) // 2 >= min_len:
        raw = data[start:]
        hits.append(
            StringHit(
                offset=offset + start,
                value=raw.decode("utf-16-le", errors="ignore"),
                encoding="utf-16le",
                length=len(raw) // 2,
            )
        )
    return hits


def extract_strings(data: bytes, min_len: int = DEFAULT_MIN, offset: int = 0) -> list[StringHit]:
    """Both encodings, sorted by offset so the output reads like a hex editor."""
    hits = extract_ascii(data, min_len, offset) + extract_utf16(data, min_len, offset)
    hits.sort(key=lambda h: (h.offset, -h.length))
    return hits


def find_pattern(data: bytes, pattern: str | re.Pattern, offset: int = 0) -> list[int]:
    """Regex over the raw bytes.  Handles the case where you want a string that
    also happens to be valid UTF-16."""
    if isinstance(pattern, str):
        pattern = re.compile(pattern.encode("latin-1"), re.DOTALL)
    return [m.start() + offset for m in pattern.finditer(data)]


def looks_like_base64(s: str) -> bool:
    """Cheap heuristic, not a validator.  Meant for flagging strings worth a
    decode attempt, not for proving anything."""
    stripped = "".join(s.split())
    if len(stripped) < 8 or len(stripped) % 4:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", stripped):
        return False
    # Real base64 of binary data has no long lowercase runs and plenty of
    # uppercase; real words are the opposite.
    upper = sum(1 for c in stripped if c.isupper())
    lower = sum(1 for c in stripped if c.islower())
    return upper + lower > 0 and (upper + lower) / len(stripped) > 0.4 and lower < upper * 4


SUSPICIOUS = [
    r"https?://[^\s\"']{6,}",
    r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    r"[A-Za-z]:\\[^\s\"']{4,}",
    r"\b(?:cmd|powershell|rundll32|regsvr32|wscript|cscript)\.exe\b",
    r"VirtualAlloc|VirtualProtect|WriteProcessMemory|CreateRemoteThread",
    r"RunOnce|CurrentVersion\\Run|CurrentVersion\\RunOnce",
    r"Software\\Microsoft\\Windows\\CurrentVersion",
    r"/c\s+(?:powershell|cmd|certutil|bitsadmin)",
    r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
]


def find_suspicious(data: bytes, min_len: int = DEFAULT_MIN) -> list[StringHit]:
    """Regex sweep over the extracted strings.  False positives are expected and
    fine; this is a triage tool, not a verdict."""
    out: list[StringHit] = []
    for hit in extract_strings(data, min_len):
        for pat in SUSPICIOUS:
            if re.search(pat, hit.value, re.IGNORECASE):
                out.append(hit)
                break
    return out
