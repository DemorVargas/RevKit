"""Entropy and randomness stats.

High entropy means packed or encrypted.  That is the single most useful signal
you get from a binary without running it, and it is also the thing people get
wrong, so the block version here reports deltas rather than just an average.
"""

from __future__ import annotations

import math
from collections import Counter

from .io import Range

# What counts as "probably compressed or encrypted".  Real data sits around
# 6.0-7.0; packers push whole sections up past 7.8.
HIGH_ENTROPY = 7.5
VERY_HIGH_ENTROPY = 7.9


def shannon(data: bytes) -> float:
    """Bits of entropy per byte, 0.0 (all one value) to 8.0 (perfectly flat)."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def chi_square(data: bytes) -> float:
    """Chi-square statistic against a uniform distribution.

    Zero means every byte value appears exactly equally often, which is too
    regular to be random. Around 255 (the degrees of freedom) is what real
    random data produces. Far above that means structured or repetitive data,
    which is the interesting case.
    """
    if not data:
        return 0.0
    total = len(data)
    expected = total / 256
    counts = Counter(data)
    return sum((counts.get(i, 0) - expected) ** 2 / expected for i in range(256))


def monte_carlo_pi(data: bytes) -> float:
    """Monte Carlo estimate of pi from the bytes. Genuine random data lands on pi;
    constant data lands on 4.0 because every point falls inside the circle."""
    if len(data) < 8:
        return 0.0
    inside = 0
    samples = 0
    for i in range(0, len(data) - 8, 8):
        x = int.from_bytes(data[i : i + 4], "big") / 0x100000000
        y = int.from_bytes(data[i + 4 : i + 8], "big") / 0x100000000
        samples += 1
        if x * x + y * y <= 1.0:
            inside += 1
    if not samples:
        return 0.0
    return 4.0 * inside / samples


def high_entropy_regions(data: bytes, block: int = 512, threshold: float = 7.5) -> list[Range]:
    """Runs of blocks above an entropy threshold, i.e. candidates for packed or
    encrypted content."""
    regions = []
    for off in range(0, len(data), block):
        chunk = data[off : off + block]
        if len(chunk) < 64:
            continue
        if shannon(chunk) >= threshold:
            if regions and regions[-1].end == off:
                regions[-1].end = off + len(chunk)
            else:
                regions.append(Range(off, off + len(chunk)))
    return regions


def entropy_profile(data: bytes, block_size: int = 256) -> list[tuple[Range, float]]:
    """Entropy per block.  A packed section jumps out as a flat run of high values."""
    blocks = []
    for off in range(0, len(data), block_size):
        chunk = data[off : off + block_size]
        if not chunk:
            break
        blocks.append((Range(off, off + len(chunk)), shannon(chunk)))
    return blocks


def hot_blocks(profile: list[tuple[Range, float]], threshold: float = HIGH_ENTROPY) -> list[Range]:
    """Blocks above the threshold, merged into runs so you get regions not noise."""
    regions: list[Range] = []
    for rng, ent in profile:
        if ent < threshold:
            continue
        if regions and regions[-1].end == rng.start:
            regions[-1].end = rng.end
        else:
            regions.append(Range(rng.start, rng.end))
    return regions


def entropy_stats(data: bytes) -> dict:
    """The headline numbers.  Deliberately small, the report builder wants dicts."""
    if not data:
        return {"entropy": 0.0, "chi_square": 0.0, "monte_carlo_pi": 0.0, "size": 0}
    return {
        "entropy": round(shannon(data), 4),
        "chi_square": round(chi_square(data), 2),
        "monte_carlo_pi": round(monte_carlo_pi(data), 4),
        "size": len(data),
    }


def looks_packed(data: bytes, threshold: float = HIGH_ENTROPY) -> bool:
    """One-liner for the common question.  Whole-file only, use the profile for
    anything you actually care about."""
    return bool(data) and shannon(data) >= threshold
