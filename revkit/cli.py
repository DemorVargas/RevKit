"""Command line interface.

Subcommands over the library, one per thing you actually want to do. Missing
optional dependencies produce the install command, not a traceback.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__, carve, crypto, disasm, entropy, formats, patcher, report, signatures, strings
from .io import read_file


def _print(msg: str) -> None:
    print(msg)


def _die(msg: str, code: int = 1) -> int:
    print(f"error: {msg}", file=sys.stderr)
    return code


def _hexdump(data: bytes, base: int = 0, width: int = 16) -> str:
    """Classic hexdump, because you cannot avoid wanting one."""
    out = []
    for off in range(0, len(data), width):
        chunk = data[off : off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        hexpart = hexpart.ljust(width * 3 - 1)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{base + off:08x}  {hexpart}  |{text}|")
    return "\n".join(out)


def cmd_file(args) -> int:
    """Identity plus structure: what is this thing."""
    path = args.path
    if not os.path.isfile(path):
        return _die(f"{path}: no such file")
    data = read_file(path)
    info = formats.identify(data, path)
    _print(f"path:          {info.path}")
    _print(f"format:        {info.format} ({info.description})")
    _print(f"size:          {formats.human_size(info.size)}")
    _print(f"entropy:       {info.entropy:.4f}")
    _print(f"sha256:        {crypto.hash_file(data)['sha256']}")
    if info.embedded:
        _print(f"embedded:      {', '.join(info.embedded)}")
    if info.signatures:
        _print(f"signatures:    {', '.join(info.signatures)}")

    detail = formats.parse_any(data, path)
    d = detail.get("detail", {})
    if d:
        _print("")
        _print("structure:")
        for key, value in d.items():
            if key in ("path", "warnings", "characteristics"):
                continue
            if isinstance(value, bool):
                value = "yes" if value else "no"
            _print(f"  {key:16} {value}")
    if detail.get("warnings"):
        _print("")
        _print("warnings:")
        for w in detail["warnings"]:
            _print(f"  ! {w}")

    imports = detail.get("imports", [])
    if imports:
        _print("")
        _print(f"imports ({len(imports)}):")
        for imp in imports[: args.limit]:
            name = imp.get("name") or (f"ordinal {imp['ordinal']}" if imp.get("ordinal") else "?")
            dll = imp.get("dll")
            _print(f"  {dll:24} {name}" if dll else f"  {name}")
        if len(imports) > args.limit:
            _print(f"  ... and {len(imports) - args.limit} more")

    exports = detail.get("exports", [])
    if exports:
        _print("")
        _print(f"exports ({len(exports)}):")
        for exp in exports[: args.limit]:
            _print(f"  {exp.get('name') or exp.get('ordinal')}")
    return 0


def cmd_scan(args) -> int:
    """Everything at once: structure, strings, signatures, carving, decodes."""
    if not os.path.isfile(args.path):
        return _die(f"{args.path}: no such file")
    result = report.analyze(
        args.path,
        min_string_len=args.min_len,
        run_signatures=not args.no_signatures,
        run_decode=not args.no_decode,
        carve_embedded=not args.no_carve,
    )
    if args.json:
        sys.stdout.write(report.to_json(result))
        _print("")
        return 0
    _print(report.to_markdown(result))
    return 0


def cmd_strings(args) -> int:
    if not os.path.isfile(args.path):
        return _die(f"{args.path}: no such file")
    with open(args.path, "rb") as fh:
        data = fh.read()
    encoding = args.encoding
    if encoding == "ascii":
        found = strings.extract_ascii(data, args.min_len)
    elif encoding == "utf16":
        found = strings.extract_utf16(data, args.min_len)
    else:
        found = strings.extract_strings(data, args.min_len)
    found = found[: args.limit]
    for hit in found:
        if args.offsets:
            _print(f"{hit.offset:08x}  {hit.encoding:8}  {hit.value}")
        else:
            _print(hit.value)
    _print(f"\n{len(found)} strings")
    return 0


def cmd_entropy(args) -> int:
    if not os.path.isfile(args.path):
        return _die(f"{args.path}: no such file")
    with open(args.path, "rb") as fh:
        data = fh.read()
    stats = entropy.entropy_stats(data)
    _print(f"file:        {args.path}")
    _print(f"size:        {stats['size']}")
    _print(f"entropy:     {stats['entropy']:.4f} / 8.0")
    _print(f"chi-square:  {stats['chi_square']:.1f}")
    _print(f"monte-carlo: {stats['monte_carlo_pi']:.4f} (pi = 3.14159)")
    if stats["entropy"] >= entropy.HIGH_ENTROPY:
        _print("verdict:     looks packed or encrypted")
    elif stats["entropy"] >= 7.0:
        _print("verdict:     partly compressed, worth a closer look")
    else:
        _print("verdict:     mostly plain data")

    profile = entropy.entropy_profile(data, args.block)
    hot = entropy.hot_blocks(profile, args.threshold)
    if hot:
        _print("")
        _print(f"high-entropy regions (block {args.block}, threshold {args.threshold}):")
        # Range is mutable because hot_blocks extends regions[-1].end as it merges,
        # so it cannot be a dict key. Index the blocks by their start offset.
        by_start = {rng.start: ent for rng, ent in profile}
        for rng in hot[: args.limit]:
            ent = by_start.get(rng.start, 0.0)
            _print(f"  0x{rng.start:08x} - 0x{rng.end:08x}  {len(rng):8d} bytes  entropy {ent:.2f}")
    return 0


def cmd_decode(args) -> int:
    """Try every deobfuscator against the file, or just one."""
    if not os.path.isfile(args.path):
        return _die(f"{args.path}: no such file")
    with open(args.path, "rb") as fh:
        data = fh.read()

    if args.hex:
        try:
            data = bytes.fromhex(args.hex.replace(" ", "").replace("\n", ""))
        except ValueError as exc:
            return _die(f"bad hex input: {exc}")

    if args.method == "rc4":
        if not args.key:
            return _die("--key is required for rc4")
        key = args.key.encode("latin-1")
        plain = crypto.rc4(data, key)
        _print(_hexdump(plain, 0, args.width))
        _print("")
        _print(plain.decode("latin-1", "replace"))
        return 0

    if args.method == "xor":
        if not args.key:
            return _die("--key is required for xor (hex, e.g. 41 or 414243)")
        key = bytes.fromhex(args.key)
        plain = crypto.xor_repeat(data, key)
        _print(_hexdump(plain, 0, args.width))
        return 0

    methods = [args.method] if args.method != "all" else None
    hits = crypto.decode_all(data, methods)
    if not hits:
        _print("nothing decodable found")
        return 0
    for hit in hits[: args.limit]:
        _print(f"{hit.method:20} key={hit.key:12} score={hit.score:.3f}")
        preview = hit.plaintext[:120].decode("latin-1", "replace")
        _print(f"  {preview}")
        _print("")
    return 0


def cmd_extract(args) -> int:
    """Carve embedded files and sections out to a directory."""
    if not os.path.isfile(args.path):
        return _die(f"{args.path}: no such file")
    with open(args.path, "rb") as fh:
        data = fh.read()

    outdir = args.outdir
    os.makedirs(outdir, exist_ok=True)
    found = carve.carve_by_magic(data)

    # Section carving needs the section table, so try the format parsers first.
    try:
        if data[:4] == b"\x7fELF":
            from . import elf

            sections = elf.parse_elf(data, args.path).sections
            found += carve.carve_sections(data, [s.to_dict() for s in sections])
        elif data[:2] == b"MZ":
            from . import pe

            parsed = pe.parse_pe(data, args.path)
            found += carve.carve_sections(data, [s.to_dict() for s in parsed.sections])
            overlay = carve.find_overlay(data, parsed.overlay_start)
            if overlay:
                found.append(overlay)
    except Exception as exc:
        _print(f"note: section carving skipped ({exc})", file=sys.stderr)

    seen: set[tuple[int, int]] = set()
    written = 0
    for obj in found:
        key = (obj.offset, obj.end)
        if key in seen:
            continue
        seen.add(key)
        name = f"{written:03d}_{obj.offset:08x}_{obj.kind}.bin"
        with open(os.path.join(outdir, name), "wb") as fh:
            fh.write(data[obj.offset : obj.end])
        _print(f"{name:44} {obj.size:8d} bytes  {obj.description}")
        written += 1
    _print(f"\n{written} objects written to {outdir}")
    return 0


def cmd_patch(args) -> int:
    """Write bytes at an offset, with a backup unless told not to."""
    if not os.path.isfile(args.path):
        return _die(f"{args.path}: no such file")
    try:
        offset = patcher.parse_offset(args.offset)
        new_bytes = patcher.parse_bytes_arg(args.bytes)
    except Exception as exc:
        return _die(str(exc))

    try:
        _, result = patcher.patch_file(
            args.path, offset, new_bytes, in_place=args.in_place, backup=not args.no_backup
        )
    except Exception as exc:
        return _die(str(exc))

    _print(f"wrote {len(new_bytes)} bytes at 0x{offset:x}")
    _print(f"  old: {result.old.hex()}")
    _print(f"  new: {result.new.hex()}")
    _print(f"  file: {result.path}")
    if result.backup:
        _print(f"  backup: {result.backup}")
    return 0


def cmd_find(args) -> int:
    """Locate a byte pattern and show its offsets."""
    if not os.path.isfile(args.path):
        return _die(f"{args.path}: no such file")
    with open(args.path, "rb") as fh:
        data = fh.read()
    try:
        needle = patcher.parse_bytes_arg(args.pattern)
    except Exception as exc:
        return _die(str(exc))
    offsets = patcher.find_bytes(data, needle)
    if not offsets:
        _print("not found")
        return 1
    for off in offsets[: args.limit]:
        _print(f"0x{off:x}")
    _print(f"\n{len(offsets)} match(es)")
    return 0


def cmd_shell(args) -> int:
    """Disassemble a raw code blob. Needs capstone."""
    try:
        if args.path:
            if not os.path.isfile(args.path):
                return _die(f"{args.path}: no such file")
            blob = read_file(args.path)
            if args.offset:
                blob = blob[patcher.parse_offset(args.offset) :]
        else:
            if not args.hex_bytes:
                return _die("give a file path or --hex-bytes")
            blob = bytes.fromhex(args.hex_bytes)
        ins = disasm.disassemble(blob, base=args.base, bits=args.bits, limit=args.limit)
    except disasm.MissingDependency as exc:
        return _die(str(exc))
    except Exception as exc:
        return _die(str(exc))

    if args.syscalls:
        rows = disasm.annotate_syscalls(ins, args.bits)
        for row in rows:
            marker = ""
            if row.get("syscall"):
                marker = f"   <== {row['syscall']} ({row['syscall_number']})"
            _print(f"0x{row['address']:08x}  {row['bytes']:20}  {row['mnemonic']:10} {row['operands']}{marker}")
        return 0

    for ins in ins:
        _print(f"0x{ins.address:08x}  {ins.bytes.hex():20}  {ins}")
    return 0


def cmd_emulate(args) -> int:
    """Run a raw code blob in the emulator and report what it did.

    The guest only ever sees the VFS, so nothing it does here reaches this
    machine, and its file behaviour is visible afterwards instead of being
    blocked and hidden.
    """
    from .emulator import runner
    from .emulator.executor import Executor
    from .emulator.vfs import Vfs

    try:
        if args.path:
            if not os.path.isfile(args.path):
                return _die(f"{args.path}: no such file")
            blob = read_file(args.path)
            if args.offset:
                blob = blob[patcher.parse_offset(args.offset) :]
        else:
            if not args.hex_bytes:
                return _die("give a file path or --hex-bytes")
            blob = bytes.fromhex(args.hex_bytes.replace(" ", ""))
    except ValueError as exc:
        return _die(f"bad hex input: {exc}")

    if not blob:
        return _die("nothing to run")

    fs = Vfs.default()
    before = set(fs.paths())
    for spec in args.mount:
        target, sep, source = spec.partition("=")
        if not sep:
            return _die(f"--mount wants PATH=FILE, got {spec!r}")
        try:
            fs.add(target, read_file(source))
        except OSError as exc:
            return _die(f"{source}: {exc}")

    machine = runner.load_shellcode(
        blob, base=args.base, bits=args.bits, max_steps=args.max_steps, argv=args.argv or None
    )
    hooks = runner.TraceHooks(limit=args.limit) if args.trace else None
    executor = Executor(machine, trace=args.trace, hooks=hooks, vfs=fs)

    errors = []
    try:
        executor.run(args.base)
    except Exception as exc:
        errors.append(str(exc))

    _print(f"steps:      {machine.steps}")
    _print(f"exit:       {executor.exit_code}")
    _print(f"syscalls:   {len(executor.syscalls)}")
    if executor.output:
        preview = executor.output[:200].decode("latin-1", "replace")
        _print(f"output:     {len(executor.output)} bytes")
        _print(preview)
    if executor.syscalls:
        _print("")
        _print("calls:")
        for call in executor.syscalls[: args.limit]:
            rendered = ", ".join(hex(a) for a in call.args[:3])
            _print(f"  {call.name}({rendered}) = {call.result}")
    dropped = [p for p in fs.paths() if p not in before]
    if dropped:
        _print("")
        _print("files the guest created:")
        for path in dropped:
            _print(f"  {path}  {fs.size(path)} bytes")
    if executor.net.flows:
        _print("")
        _print("captured traffic:")
        for flow in executor.net.flows[: args.limit]:
            preview = flow.data[:200].decode("latin-1", "replace")
            _print(f"  -> {flow.peer}  {len(flow.data)} bytes")
            _print(f"     {preview!r}")
    if args.registers:
        _print("")
        _print("registers:")
        for name, value in machine.regs.items():
            if value:
                _print(f"  {name:6} 0x{value:016x}")
    if errors:
        _print("")
        for err in errors:
            _print(f"stopped: {err}")
    return 0


def cmd_yara(args) -> int:
    """Run signature rules over a file."""
    if not os.path.isfile(args.path):
        return _die(f"{args.path}: no such file")
    with open(args.path, "rb") as fh:
        data = fh.read()
    rules = signatures.default_rules()
    if args.rule:
        rules.append(
            signatures.Rule(name=args.rule, patterns=[args.pattern], severity=args.severity, description="command line rule")
        )
    hits = signatures.scan(data, rules, max_hits=args.limit)
    if args.json:
        sys.stdout.write(json.dumps([h.to_dict() for h in hits], indent=2))
        _print("")
        return 0
    if not hits:
        _print("no hits")
        return 0
    counts = signatures.count_by_severity(hits)
    _print(f"{len(hits)} hits: " + ", ".join(f"{v} {k}" for k, v in counts.items() if v))
    _print("")
    for hit in hits:
        _print(f"[{hit.severity:8}] {hit.rule:20} 0x{hit.offset:08x}  {hit.matched[:60]!r}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="revkit",
        description="Reverse engineering toolkit for binaries and firmware.",
    )
    parser.add_argument("--version", action="version", version=f"revkit {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("file", help="identify a file and dump its structure")
    p.add_argument("path")
    p.add_argument("--limit", type=int, default=40, help="max imports or exports to list")
    p.set_defaults(func=cmd_file)

    p = sub.add_parser("scan", help="run every analyzer and print a report")
    p.add_argument("path")
    p.add_argument("--json", action="store_true", help="emit JSON instead of markdown")
    p.add_argument("--min-len", type=int, default=4, help="minimum string length")
    p.add_argument("--no-signatures", action="store_true")
    p.add_argument("--no-decode", action="store_true")
    p.add_argument("--no-carve", action="store_true")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("strings", help="extract ASCII and UTF-16 strings")
    p.add_argument("path")
    p.add_argument("--min-len", type=int, default=4)
    p.add_argument("--encoding", choices=["both", "ascii", "utf16"], default="both")
    p.add_argument("--limit", type=int, default=200)
    p.add_argument("--offsets", action="store_true", help="include file offsets")
    p.set_defaults(func=cmd_strings)

    p = sub.add_parser("entropy", help="entropy stats and packed-region detection")
    p.add_argument("path")
    p.add_argument("--block", type=int, default=256)
    p.add_argument("--threshold", type=float, default=entropy.HIGH_ENTROPY)
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(func=cmd_entropy)

    p = sub.add_parser("decode", help="try deobfuscators (xor, rc4, zlib, base64)")
    p.add_argument("path")
    p.add_argument("--method", default="all",
                   choices=["all", "xor", "rc4", "xor-brute", "zlib", "gzip", "bzip2", "lzma", "base64"])
    p.add_argument("--key", help="key for xor (hex) or rc4")
    p.add_argument("--hex", help="read hex from the argument instead of the file")
    p.add_argument("--limit", type=int, default=5)
    p.add_argument("--width", type=int, default=16)
    p.set_defaults(func=cmd_decode)

    p = sub.add_parser("extract", help="carve embedded files and sections to disk")
    p.add_argument("path")
    p.add_argument("-o", "--outdir", default="out")
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser("patch", help="write bytes at an offset")
    p.add_argument("path")
    p.add_argument("offset", help="0x1040 or 4160")
    p.add_argument("bytes", help='"90 90 c3" or "\\x90\\x90\\xc3"')
    p.add_argument("--in-place", action="store_true", help="overwrite the original")
    p.add_argument("--no-backup", action="store_true", help="do not write a .bak")
    p.set_defaults(func=cmd_patch)

    p = sub.add_parser("find", help="find offsets of a byte pattern")
    p.add_argument("path")
    p.add_argument("pattern")
    p.add_argument("--limit", type=int, default=50)
    p.set_defaults(func=cmd_find)

    p = sub.add_parser("shell", help="disassemble a raw code blob (needs capstone)")
    p.add_argument("path", nargs="?")
    p.add_argument("--hex-bytes", dest="hex_bytes", default=b"", help="hex blob to disassemble")
    p.add_argument("--offset", help="start at this offset in the file")
    p.add_argument("--base", type=lambda s: int(s, 0), default=0)
    p.add_argument("--bits", type=int, choices=[32, 64], default=64)
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--syscalls", action="store_true", help="annotate syscall instructions")
    p.set_defaults(func=cmd_shell)

    p = sub.add_parser("emulate", help="run a raw code blob in the emulator")
    p.add_argument("path", nargs="?")
    p.add_argument("--hex-bytes", dest="hex_bytes", default="", help="hex blob to run")
    p.add_argument("--offset", help="start at this offset in the file")
    p.add_argument("--base", type=lambda s: int(s, 0), default=0x1000)
    p.add_argument("--bits", type=int, choices=[32, 64], default=64)
    p.add_argument("--max-steps", dest="max_steps", type=int, default=100_000)
    p.add_argument("--limit", type=int, default=20, help="max syscalls or trace lines to show")
    p.add_argument("--argv", nargs="*", default=[], help="arguments to lay out on the stack")
    p.add_argument("--trace", action="store_true", help="print each instruction as it runs")
    p.add_argument("--registers", action="store_true", help="dump the non-zero registers")
    p.add_argument("--mount", action="append", default=[], metavar="PATH=FILE",
                   help="put a host file into the guest filesystem (repeatable)")
    p.set_defaults(func=cmd_emulate)

    p = sub.add_parser("yara", help="run signature rules over a file")
    p.add_argument("path")
    p.add_argument("--rule", help="rule name for --pattern")
    p.add_argument("--pattern", help="regex pattern to search for")
    p.add_argument("--severity", default="medium",
                   choices=["info", "low", "medium", "high", "critical"])
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_yara)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
