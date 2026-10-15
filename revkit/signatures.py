"""A small signature engine that does not need yara-python.

Regex patterns and byte needles, evaluated in one pass, with counts and
offsets. Not a YARA replacement: no modules, no loops, no magic. But it covers
the case where you want to drop a handful of indicators into a script and get
hits back without installing anything.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .io import FormatError


@dataclass
class Rule:
    """One named indicator."""

    name: str
    description: str = ""
    patterns: list[str] = field(default_factory=list)  # regex, matched on raw bytes
    needles: list[bytes] = field(default_factory=list)  # literal byte sequences
    tags: list[str] = field(default_factory=list)
    severity: str = "info"  # info | low | medium | high | critical
    _compiled: list = field(default_factory=list, repr=False)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "patterns": self.patterns,
            "needles": [n.hex() for n in self.needles],
            "tags": self.tags,
            "severity": self.severity,
        }


@dataclass
class Hit:
    rule: str
    description: str
    severity: str
    offset: int
    matched: bytes
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "description": self.description,
            "severity": self.severity,
            "offset": self.offset,
            "matched": self.matched[:64].hex(),
            "matched_text": self.matched[:64].decode("latin-1", "replace"),
            "tags": self.tags,
        }


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def compile_rule(rule: Rule) -> Rule:
    """Pre-compile the regex patterns so a scan over a big file does not pay the
    compilation cost per offset."""
    compiled = []
    for pat in rule.patterns:
        try:
            compiled.append(re.compile(pat.encode("latin-1"), re.DOTALL))
        except re.error as exc:
            raise FormatError(f"rule {rule.name!r} has a bad pattern {pat!r}: {exc}") from exc
    rule._compiled = compiled
    return rule


def scan(data: bytes, rules: list[Rule], max_hits: int = 100) -> list[Hit]:
    """Run every rule over the data and collect hits, most severe first."""
    hits: list[Hit] = []
    for rule in rules:
        if not rule._compiled:
            compile_rule(rule)
        for pat in rule._compiled:
            for m in pat.finditer(data):
                hits.append(
                    Hit(
                        rule=rule.name,
                        description=rule.description,
                        severity=rule.severity,
                        offset=m.start(),
                        matched=m.group(0),
                        tags=list(rule.tags),
                    )
                )
                if len(hits) >= max_hits:
                    break
        for needle in rule.needles:
            pos = data.find(needle)
            while pos != -1:
                hits.append(
                    Hit(
                        rule=rule.name,
                        description=rule.description,
                        severity=rule.severity,
                        offset=pos,
                        matched=needle,
                        tags=list(rule.tags),
                    )
                )
                if len(hits) >= max_hits:
                    break
                pos = data.find(needle, pos + 1)
        if len(hits) >= max_hits:
            break
    hits.sort(key=lambda h: (-SEVERITY_ORDER.get(h.severity, 0), h.offset))
    return hits[:max_hits]


def count_by_severity(hits: list[Hit]) -> dict[str, int]:
    out = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    for h in hits:
        out[h.severity] = out.get(h.severity, 0) + 1
    return out


def highest_severity(hits: list[Hit]) -> str:
    """Worst severity present. 'info' when nothing matched at all."""
    if not hits:
        return "info"
    return max(hits, key=lambda h: SEVERITY_ORDER.get(h.severity, 0)).severity


# Some starting rules. Deliberately small: these are the things that show up in
# almost every triage, and you can add your own on top.
DEFAULT_RULES = [
    Rule(
        name="network_url",
        description="http/https URL embedded in the file",
        patterns=[r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{8,}"],
        tags=["network", "ioc"],
        severity="info",
    ),
    Rule(
        name="ipv4",
        description="IPv4 address literal",
        patterns=[r"\b(?:\d{1,3}\.){3}\d{1,3}\b"],
        tags=["network", "ioc"],
        severity="info",
    ),
    Rule(
        name="base64_blob",
        description="Long base64-looking run",
        patterns=[r"[A-Za-z0-9+/]{200,}={0,2}"],
        tags=["obfuscation"],
        severity="low",
    ),
    Rule(
        name="powershell",
        description="PowerShell invocation",
        patterns=[r"(?i)powershell(?:\.exe)?\s+(?:-[a-z]+\s+)*[^\r\n]{4,}"],
        needles=[b"powershell.exe", b"-enc ", b"-EncodedCommand"],
        tags=["script", "suspicious"],
        severity="high",
    ),
    Rule(
        name="rundll32",
        description="rundll32 or regsvr32 execution",
        patterns=[r"(?i)rundll32\.exe\s+\S+", r"(?i)regsvr32\.exe\s+\S+"],
        tags=["suspicious", "execution"],
        severity="medium",
    ),
    Rule(
        name="registry_run",
        description="Registry Run key persistence",
        patterns=[r"(?i)Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
        tags=["persistence"],
        severity="high",
    ),
    Rule(
        name="process_injection",
        description="Classic process injection API sequence",
        needles=[
            b"VirtualAllocEx",
            b"WriteProcessMemory",
            b"CreateRemoteThread",
            b"NtUnmapViewOfSection",
        ],
        tags=["injection", "suspicious"],
        severity="high",
    ),
    Rule(
        name="crypto_wallet",
        description="Cryptocurrency wallet address",
        patterns=[r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b", r"\b0x[a-fA-F0-9]{40}\b"],
        tags=["financial"],
        severity="low",
    ),
    Rule(
        name="private_key",
        description="PEM private key block",
        patterns=[r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"],
        tags=["credential", "exfil"],
        severity="critical",
    ),
    Rule(
        name="debug_path",
        description="Compiler debug path left in the binary",
        patterns=[r"[A-Za-z]:\\(?:Users|src|home|build|workspace)\\[^\x00\r\n]{4,80}\.pdb"],
        tags=["dev", "info-leak"],
        severity="low",
    ),
]


def default_rules() -> list[Rule]:
    """A fresh copy each call, so callers can mutate without touching the module."""
    return [
        Rule(
            name=r.name,
            description=r.description,
            patterns=list(r.patterns),
            needles=list(r.needles),
            tags=list(r.tags),
            severity=r.severity,
        )
        for r in DEFAULT_RULES
    ]
