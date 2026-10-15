#!/usr/bin/env python3
"""Entropy: find the packed or encrypted parts of a file.

Usage: python examples/02_entropy.py <path>
"""

from __future__ import annotations

import sys

from revkit import entropy, formats


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    path = argv[1]

    data = open(path, "rb").read()

    stats = entropy.entropy_stats(data)
    print(f"file:        {path}")
    print(f"size:        {stats['size']}")
    print(f"entropy:     {stats['entropy']:.4f} / 8.0")
    print(f"chi-square:  {stats['chi_square']:.1f}")
    print(f"monte-carlo: {stats['monte_carlo_pi']:.4f}   (pi = 3.14159)")

    if stats["entropy"] >= entropy.HIGH_ENTROPY:
        print("verdict:     packed or encrypted as a whole")
    elif stats["entropy"] >= 7.0:
        print("verdict:     mixed, worth looking at block by block")
    else:
        print("verdict:     mostly plain data")

    regions = entropy.high_entropy_regions(data, block=512, threshold=entropy.HIGH_ENTROPY)
    if regions:
        print(f"\nhigh-entropy regions ({len(regions)}):")
        for region in regions[:10]:
            chunk = data[region.start : region.end]
            print(
                f"  0x{region.start:08x} - 0x{region.end:08x}  "
                f"{len(region):8d} bytes  entropy {entropy.shannon(chunk):.2f}"
            )
    else:
        print("\nno high-entropy regions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
