#!/usr/bin/env python3
"""Full report: every analyzer at once, as JSON or markdown.

Usage: python examples/06_report.py <path> [--json] [--out FILE]
"""

from __future__ import annotations

import sys

from revkit import report


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if not a.startswith("--")]
    if not args:
        print(__doc__)
        return 2
    path = args[0]
    as_json = "--json" in argv
    out_path = None
    if "--out" in argv:
        out_path = argv[argv.index("--out") + 1]

    result = report.analyze(path)
    text = report.to_json(result) if as_json else report.to_markdown(result)

    if out_path:
        with open(out_path, "w") as fh:
            fh.write(text)
        print(f"wrote {out_path}")
    else:
        print(text)

    # A quick verdict so the example says something useful on its own.
    if not as_json:
        d = result.detail
        print("\n--- summary ---")
        print(f"format:     {result.info.format}")
        print(f"size:       {result.info.size}")
        print(f"sections:   {len(result.sections)}")
        print(f"imports:    {len(result.imports)}")
        print(f"strings:    {len(result.strings_found)}")
        print(f"carved:     {len(result.carved)}")
        print(f"signatures: {len(result.hits)}")
        if d.get("machine"):
            print(f"machine:    {d['machine']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
