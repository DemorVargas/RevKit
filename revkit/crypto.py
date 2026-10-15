"""Crypto and unpacking helpers: XOR, RC4, zlib and friends.

The useful one here is frequency-scored single-byte XOR brute force. One-byte
XOR is how malware hides a URL in a binary, and a plain letter-frequency table
breaks it with no dictionary and no guessing.
"""

from __future__ import annotations

import base64
import bz2
import hashlib
import lzma
import math
import string
import zlib
from collections import Counter
from dataclasses import dataclass

from .io import FormatError

# Rough English character probabilities. Space and lowercase dominate, and that
# is exactly what a single-byte key falls over. Digits and punctuation get small
# but non-zero weights because URLs and paths are full of them.
_ENGLISH_FREQ = {
    " ": 0.17, "e": 0.10, "t": 0.072, "a": 0.065, "o": 0.062, "i": 0.058,
    "n": 0.057, "s": 0.051, "r": 0.049, "h": 0.046, "l": 0.033, "d": 0.032,
    "c": 0.025, "u": 0.023, "m": 0.021, "f": 0.019, "w": 0.018, "g": 0.017,
    "y": 0.016, "p": 0.015, "b": 0.012, "v": 0.009, "k": 0.006, "j": 0.0015,
    "x": 0.0014, "q": 0.0009, "z": 0.0006,
    "0": 0.010, "1": 0.010, "2": 0.006, "3": 0.005, "4": 0.004,
    "5": 0.004, "6": 0.003, "7": 0.003, "8": 0.002, "9": 0.002,
    ".": 0.030, ",": 0.020, "/": 0.008, "-": 0.007, "_": 0.005,
    ":": 0.004, "\\": 0.004, '"': 0.003, "'": 0.003, "=": 0.002,
    "+": 0.002, "%": 0.002, "@": 0.002, "#": 0.001,
}

# Anything else that is still printable, and anything that is not printable at
# all. Control bytes are heavily penalised, which is what separates text from
# random or compressed data.
_OTHER_PRINTABLE = 0.001
_CONTROL = 0.00002

# What counts as printable when scoring a candidate. Digits and punctuation are
# fine, control bytes are not.
_PRINTABLE = set(string.printable.encode("ascii"))

# English text lands around 4.5 bits per character; uniform random data is 8.0.
# This is the score a real English sentence gets, and the threshold sits below it.
_GOOD_SCORE = 0.25


def _bits_table() -> list[float]:
    """Cost in bits of each byte value under the model above.

    Precomputed because the XOR brute force scores 256 candidates over the whole
    input, and a math.log2 call per byte is most of what that costs.
    """
    table = []
    for b in range(256):
        if b in _PRINTABLE:
            p = _ENGLISH_FREQ.get(chr(b).lower(), _OTHER_PRINTABLE)
        else:
            p = _CONTROL
        table.append(-math.log2(p))
    return table


_BITS = _bits_table()


def english_bits_per_char(data: bytes) -> float:
    """Average bits of surprise per byte. About 4.5 for English, 8.0 for random.

    This is the honest number behind score_english, and the one worth printing.
    """
    if not data:
        return 8.0
    return sum(_BITS[b] for b in data) / len(data)


def score_english(data: bytes) -> float:
    """How much these bytes look like text, 0.0 to 1.0.

    Log-likelihood per byte, rescaled so that uniform random data scores 0 and
    ordinary English scores roughly 0.45. Garbage scores near zero, which is why
    the cutoff in xor_brute is what it is.
    """
    if not data:
        return 0.0
    bits = english_bits_per_char(data)
    return round(max(0.0, (8.0 - bits) / 8.0), 4)


def _strip_padding(data: bytes, max_repeat: int = 4) -> bytes:
    """Drop any stretch of one byte longer than max_repeat.

    XOR padding lands on a printable byte for most keys, so a run of NULs becomes a
    run of 'Z' and gets scored as though it were text. Sixty-four of them outvote
    the string they were padding and drag its score to zero. A long stretch of a
    single byte is padding, so take it out and leave everything else alone.
    """
    out = bytearray()
    i = 0
    while i < len(data):
        b = data[i]
        j = i
        while j < len(data) and data[j] == b:
            j += 1
        if (j - i) <= max_repeat:
            out.extend(data[i:j])
        i = j
    return bytes(out)


def _repetition_penalty(data: bytes) -> float:
    """Damp a candidate where a single byte dominates, 0.0 to 1.0.

    The unigram model above rewards repetition: a hundred 'e' bytes look like very
    English text to it, and score higher than a real sentence does. Real text never
    has one byte past about a quarter of it, so anything beyond that is scaled back.
    """
    if not data:
        return 0.0
    share = Counter(data).most_common(1)[0][1] / len(data)
    if share <= 0.25:
        return 1.0
    return 0.25 / share


def score_candidate(data: bytes, min_len: int = 8) -> float:
    """Score a blob for the XOR brute force, 0.0 to 1.0.

    score_english over the blob with long homogeneous padding stripped out. Without
    the strip, the padding decides the winner instead of the string underneath it.
    """
    trimmed = _strip_padding(data)
    if len(trimmed) < min_len:
        return 0.0
    return round(score_english(trimmed) * _repetition_penalty(trimmed), 4)


@dataclass
class DecodeHit:
    """One candidate that looked like it might mean something."""

    method: str
    key: str
    plaintext: bytes
    score: float
    offset: int = 0
    note: str = ""

    @property
    def text(self) -> str:
        return self.plaintext.decode("utf-8", errors="replace")


def xor_single(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def xor_repeat(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("empty key")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def rc4(data: bytes, key: bytes) -> bytes:
    """RC4, a.k.a. ARC4. Not in the stdlib, and needed constantly."""
    if not key:
        raise ValueError("empty key for RC4")
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]

    out = bytearray(len(data))
    i = j = 0
    for n, b in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out[n] = b ^ s[(s[i] + s[j]) & 0xFF]
    return bytes(out)


def xor_brute(data: bytes, limit: int = 5) -> list[DecodeHit]:
    """Try all 256 single-byte keys, sorted by how plausible the result is.

    This is what breaks strings like `http://...` hidden in a binary with one
    XOR pass. Candidates are scored with the padding stripped, so a run of NULs
    around the string cannot outvote the string itself.
    """
    # A homogeneous run survives single-byte XOR as a homogeneous run, so the
    # padding sits in the same place for every key. Strip it once, not 256 times.
    trimmed = _strip_padding(data)
    if len(trimmed) < 8:
        return []

    hits = []
    for key in range(256):
        plain = xor_single(trimmed, key)
        score = round(score_english(plain) * _repetition_penalty(plain), 4)
        if score < _GOOD_SCORE:
            continue
        # Report what the whole blob decodes to, not the trimmed view of it.
        hits.append(DecodeHit(method="xor-single", key=f"0x{key:02x}",
                              plaintext=xor_single(data, key), score=score))
    hits.sort(key=lambda h: h.score, reverse=True)
    return hits[:limit]


def xor_known_plaintext(data: bytes, known: bytes, offset: int = 0) -> DecodeHit | None:
    """Recover the key from known plaintext: if you know the start, the key is
    visible immediately."""
    if offset + len(known) > len(data):
        return None
    key = bytes(a ^ b for a, b in zip(data[offset : offset + len(known)], known))
    return DecodeHit(
        method="xor-known-plaintext",
        key=key.hex(),
        plaintext=xor_repeat(data[offset:], key),
        score=1.0,
        offset=offset,
        note=f"key repeats every {len(key)} bytes",
    )


def repeat_key_length(data: bytes, max_len: int = 32, sample: int = 4096) -> int | None:
    """Guess the length of a repeating XOR key. Best-effort, not a guarantee.

    Compares the ciphertext against itself shifted by k bytes. At the true key
    length the key cancels out of the XOR, which lowers the average Hamming
    distance. Multiples of the true length also cancel, so they score well too
    and the smallest one is returned.

    This is a heuristic with real failure modes: on short input, on data with a
    flat character distribution, or with a long key, it can return the wrong
    answer. When it matters, try every candidate from `key_length_candidates`
    and see which one decrypts to something readable, or just use
    `xor_break_key` with a length you already know.
    """
    if len(data) < 128:
        return None

    limit = min(sample, len(data) - 1)
    distances: list[tuple[float, int]] = []
    for klen in range(1, max_len + 1):
        if klen >= len(data) - 1:
            break
        n = min(limit, len(data) - klen)
        total = 0
        for i in range(n):
            total += bin(data[i] ^ data[i + klen]).count("1")
        distances.append((total / n, klen))

    if not distances:
        return None
    best = min(d for d, _ in distances)
    for dist, klen in distances:
        if dist <= best + 0.2:
            return klen
    return distances[0][1]


def key_length_candidates(data: bytes, max_len: int = 24) -> list[tuple[int, float]]:
    """Ranked candidate key lengths, best first. For when the guess is not enough.

    Returns (length, average_hamming_distance) pairs so you can try several and
    keep the one that decrypts to readable text.
    """
    if len(data) < 128:
        return []
    out = []
    for klen in range(2, max_len + 1):
        if klen >= len(data) - 1:
            break
        n = min(len(data) - klen, 4096)
        total = 0
        for i in range(n):
            total += bin(data[i] ^ data[i + klen]).count("1")
        out.append((klen, total / n))
    out.sort(key=lambda t: t[1])
    return out


def xor_break_key(data: bytes, key_len: int) -> bytes | None:
    """Recover a repeating XOR key when the length is known.

    Each column of the ciphertext (bytes at stride key_len) was XORed with a
    single key byte, so a single-byte brute force per column recovers the key.
    This is reliable where guessing the length is not.

    Returns the key, or None if no key length makes the result readable.
    """
    if key_len <= 0 or key_len > len(data):
        return None
    key = bytearray()
    for i in range(key_len):
        column = data[i::key_len]
        if len(column) < 4:
            return None
        hits = xor_brute(column, limit=1)
        if not hits:
            return None
        key.append(int(hits[0].key, 16))
    return bytes(key)


def try_zlib(data: bytes) -> bytes | None:
    """Inflate zlib/deflate, tolerating raw deflate with no header."""
    for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
        try:
            return zlib.decompress(data, wbits)
        except zlib.error:
            continue
    return None


def try_gzip(data: bytes) -> bytes | None:
    try:
        return zlib.decompress(data, 16 + zlib.MAX_WBITS)
    except zlib.error:
        return None


def try_bzip2(data: bytes) -> bytes | None:
    try:
        return bz2.decompress(data)
    except OSError:
        return None


def try_lzma(data: bytes) -> bytes | None:
    try:
        return lzma.decompress(data)
    except lzma.LZMAError:
        return None


def b64_decode(data: bytes) -> bytes | None:
    """base64, forgiving of whitespace, newlines and missing padding."""
    cleaned = bytes(c for c in data if c not in b" \t\r\n")
    cleaned += b"=" * (-len(cleaned) % 4)
    try:
        return base64.b64decode(cleaned, validate=True)
    except (ValueError, base64.binascii.Error):
        return None


def hash_file(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def adler32(data: bytes) -> int:
    return zlib.adler32(data) & 0xFFFFFFFF


def fnv1a(data: bytes) -> int:
    """FNV-1a, 32 bit. Handy for hash-based import lookup in formats that do not
    store names."""
    h = 0x811C9DC5
    for b in data:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


# xor_brute costs 256 passes over whatever it is given, so decode_all only feeds
# it the front of a large blob. A string hidden in a firmware image is nearly
# always near the start, and this keeps `revkit scan` on a big file quick.
XOR_SAMPLE = 1 << 16


DECODERS = {
    "xor-brute": lambda d: xor_brute(d),
    "zlib": lambda d: [DecodeHit("zlib", "", try_zlib(d), 1.0)] if try_zlib(d) else [],
    "gzip": lambda d: [DecodeHit("gzip", "", try_gzip(d), 1.0)] if try_gzip(d) else [],
    "bzip2": lambda d: [DecodeHit("bzip2", "", try_bzip2(d), 1.0)] if try_bzip2(d) else [],
    "lzma": lambda d: [DecodeHit("lzma", "", try_lzma(d), 1.0)] if try_lzma(d) else [],
    "base64": lambda d: [DecodeHit("base64", "", b64_decode(d), 1.0)] if b64_decode(d) else [],
}


def decode_all(data: bytes, methods: list[str] | None = None) -> list[DecodeHit]:
    """Run the requested decoders and drop empty results.

    Passing 'all' runs everything, so the CLI only needs one flag.
    """
    if methods is None or "all" in methods:
        methods = list(DECODERS)
    out: list[DecodeHit] = []
    for name in methods:
        fn = DECODERS.get(name)
        if fn is None:
            continue
        # xor_brute is 256 passes over its input, so cap what it is fed. A string
        # buried in a firmware image is nearly always near the front, and without
        # this `revkit scan` on a large blob takes all afternoon.
        sample = data[:XOR_SAMPLE] if name == "xor-brute" else data
        try:
            out.extend(fn(sample))
        except (ValueError, FormatError):
            continue
    out.sort(key=lambda h: h.score, reverse=True)
    return out
