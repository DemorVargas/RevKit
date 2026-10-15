"""Building a report out of everything the analyzers found.

Two output formats on purpose: JSON for tooling, markdown for reading. The
markdown one is what you paste into a writeup, so it says what matters first and
does not dump raw tables at the top.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from . import carve, crypto, elf, entropy, formats, pe, signatures, strings
from .io import read_file


@dataclass
class Analysis:
    """Everything we know about one file, gathered on demand."""

    path: str
    data: bytes
    info: formats.FileInfo | None = None
    detail: dict = field(default_factory=dict)
    sections: list = field(default_factory=list)
    segments: list = field(default_factory=list)
    imports: list = field(default_factory=list)
    exports: list = field(default_factory=list)
    strings_found: list = field(default_factory=list)
    suspicious: list = field(default_factory=list)
    carved: list = field(default_factory=list)
    hits: list = field(default_factory=list)
    decode_candidates: list = field(default_factory=list)
    warnings: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "size": len(self.data),
            "info": self.info.to_dict() if self.info else {},
            "detail": self.detail,
            "sections": self.sections,
            "segments": self.segments,
            "imports": self.imports,
            "exports": self.exports,
            "strings": [s.value for s in self.strings_found],
            "suspicious_strings": [s.value for s in self.suspicious],
            "carved": self.carved,
            "signatures": self.hits,
            "decode_candidates": self.decode_candidates,
            "entropy": entropy.entropy_stats(self.data),
            "warnings": self.warnings,
        }


def analyze(
    path: str,
    *,
    min_string_len: int = 4,
    max_strings: int = 5000,
    run_signatures: bool = True,
    run_decode: bool = True,
    carve_embedded: bool = True,
) -> Analysis:
    """Run the whole toolkit against one file. Each stage is guarded so a
    failure in one analyzer does not lose the rest of the report."""
    data = read_file(path)
    result = Analysis(path=path, data=data)

    try:
        result.info = formats.identify(data, path)
    except Exception as exc:  # identification should never be fatal
        result.warnings.append(f"identification failed: {exc}")
        result.info = formats.FileInfo(path=path, size=len(data), format="unknown", description="unknown", extension_hint=".bin")

    fmt = result.info.format
    if fmt == "pe":
        _analyze_pe(data, path, result)
    elif fmt == "elf":
        _analyze_elf(data, path, result)
    else:
        result.warnings.append(f"{fmt} has no structural parser yet; reported from signatures and carving")

    try:
        result.strings_found = strings.extract_strings(data, min_string_len)[:max_strings]
    except Exception as exc:
        result.warnings.append(f"string extraction failed: {exc}")

    try:
        result.suspicious = strings.find_suspicious(data, min_string_len)[:200]
    except Exception as exc:
        result.warnings.append(f"suspicious string scan failed: {exc}")

    if run_signatures:
        try:
            hits = signatures.scan(data, signatures.default_rules(), max_hits=200)
            result.hits = [h.to_dict() for h in hits]
        except Exception as exc:
            result.warnings.append(f"signature scan failed: {exc}")

    if carve_embedded:
        try:
            found = carve.carve_by_magic(data)
            if fmt == "pe" and result.sections:
                found += carve.carve_sections(data, result.sections, names=False)
            if fmt == "elf" and result.sections:
                found += carve.carve_sections(data, result.sections, names=False)
            result.carved = [c.to_dict() for c in found]
        except Exception as exc:
            result.warnings.append(f"carving failed: {exc}")

    if run_decode:
        try:
            # Decode attempts go on the whole file plus any high-entropy region,
            # which is where a hidden payload usually sits.
            candidates = crypto.decode_all(data)
            for region in carve.high_entropy_regions(data, threshold=7.0)[:3]:
                candidates += crypto.decode_all(data[region.start : region.end])
            result.decode_candidates = [
                c.__dict__ for c in candidates[:10]
            ]
        except Exception as exc:
            result.warnings.append(f"decode pass failed: {exc}")

    return result


def _analyze_pe(data: bytes, path: str, result: Analysis) -> None:
    try:
        parsed = pe.parse_pe(data, path)
    except Exception as exc:
        result.warnings.append(f"PE parse failed: {exc}")
        return
    result.detail = parsed.summary()
    result.sections = [s.to_dict() for s in parsed.sections]
    result.imports = [i.to_dict() for i in parsed.imports]
    result.exports = [e.to_dict() for e in parsed.exports]
    overlay = carve.find_overlay(data, parsed.overlay_start)
    if overlay:
        result.carved.append(overlay.to_dict())


def _analyze_elf(data: bytes, path: str, result: Analysis) -> None:
    try:
        parsed = elf.parse_elf(data, path)
    except Exception as exc:
        result.warnings.append(f"ELF parse failed: {exc}")
        return
    result.detail = parsed.summary()
    # The section table carries offsets and sizes, not entropy, so score each
    # section here. Without this the report shows 0.00 for every section.
    from .entropy import shannon

    sections = []
    for sec in parsed.sections:
        info = sec.to_dict()
        if sec.size and sec.offset + sec.size <= len(data):
            info["entropy"] = round(shannon(data[sec.offset : sec.offset + sec.size]), 4)
        else:
            info["entropy"] = 0.0
        sections.append(info)
    result.sections = sections
    result.segments = [s.to_dict() for s in parsed.segments]
    result.imports = [s.to_dict() for s in parsed.imports()]


def to_json(result: Analysis, indent: int = 2) -> str:
    return json.dumps(result.to_dict(), indent=indent, ensure_ascii=False, default=str)


def to_markdown(result: Analysis) -> str:
    """Human-readable report. Numbers come from the analysis, not from the
    README, so they cannot drift."""
    info = result.info
    lines: list[str] = []
    lines.append(f"# Analysis: {result.path}")
    lines.append("")
    if info is None:
        lines.append("Identification failed.")
        return "\n".join(lines)

    lines.append(f"**Format:** {info.format} - {info.description}")
    lines.append(f"**Size:** {formats.human_size(info.size)}")
    lines.append(f"**Entropy:** {info.entropy:.4f}")
    if info.embedded:
        lines.append(f"**Embedded signatures:** {', '.join(info.embedded)}")
    lines.append("")

    d = result.detail
    if d:
        lines.append("## Structure")
        lines.append("")
        for key in ("machine", "type", "bits", "endian", "subsystem", "entry_point", "image_base",
                    "interpreter", "soname", "build_id", "section_count", "segment_count",
                    "import_count", "export_count", "timestamp_utc", "overlay_size"):
            if key in d:
                lines.append(f"- **{key}:** {d[key]}")
        lines.append("")

    if result.sections:
        lines.append("## Sections")
        lines.append("")
        lines.append("| name | address | size | entropy | flags |")
        lines.append("| --- | --- | --- | --- | --- |")
        for s in result.sections[:60]:
            flags = "r"
            if s.get("writable"):
                flags += "w"
            if s.get("executable"):
                flags += "x"
            lines.append(
                f"| {s.get('name', '?')} | {s.get('address', s.get('virtual_address', 0)):#x} | "
                f"{s.get('size', s.get('size_of_raw_data', 0))} | {s.get('entropy', 0):.2f} | {flags} |"
            )
        lines.append("")

    if result.imports:
        lines.append(f"## Imports ({len(result.imports)})")
        lines.append("")
        shown = result.imports[:40]
        for imp in shown:
            name = imp.get("name") or (f"ordinal {imp['ordinal']}" if imp.get("ordinal") else "?")
            lines.append(f"- `{imp.get('dll', '?')}` - {name}")
        if len(result.imports) > len(shown):
            lines.append(f"- ... and {len(result.imports) - len(shown)} more")
        lines.append("")

    if result.hits:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for h in result.hits:
            counts[h["severity"]] = counts.get(h["severity"], 0) + 1
        lines.append(f"## Signature hits ({len(result.hits)})")
        lines.append("")
        lines.append(
            f"severity: {counts['critical']} critical, {counts['high']} high, "
            f"{counts['medium']} medium, {counts['low']} low, {counts['info']} info"
        )
        lines.append("")
        for h in result.hits[:30]:
            lines.append(f"- `{h['rule']}` ({h['severity']}) at 0x{h['offset']:x} - {h.get('matched_text', '')[:60]}")
        lines.append("")

    if result.carved:
        lines.append(f"## Carved objects ({len(result.carved)})")
        lines.append("")
        lines.append("| offset | size | kind | entropy |")
        lines.append("| --- | --- | --- | --- |")
        for c in result.carved[:40]:
            lines.append(f"| 0x{c['offset']:x} | {c['size']} | {c['kind']} | {c.get('entropy', 0):.2f} |")
        lines.append("")

    if result.decode_candidates:
        lines.append("## Decode candidates")
        lines.append("")
        for c in result.decode_candidates[:10]:
            text = c["plaintext"]
            if isinstance(text, bytes):
                text = text[:60].decode("latin-1", "replace")
            lines.append(f"- {c['method']} (score {c['score']}): `{str(text)[:80]}`")
        lines.append("")

    if result.warnings:
        lines.append("## Warnings")
        lines.append("")
        for w in result.warnings:
            lines.append(f"- {w}")
        lines.append("")

    return "\n".join(lines)
