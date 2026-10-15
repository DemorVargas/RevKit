# Analyzer reference

Every module, what it does, and what it deliberately does not do.

## `revkit.io`

Byte-level reading. `Reader` is a little-endian cursor with a `base` offset, so a
section-relative read still reports a real file offset. `rva_to_offset` converts
RVAs using a section table.

Errors are `FormatError`. Truncated files raise rather than returning partial
data, because silently returning less than you asked for is how you misread a
binary.

## `revkit.formats`

`sniff()` returns the primary format plus every signature that matched anywhere.
`identify()` adds size, entropy and extension hints. `parse_any()` dispatches to
a full parser where one exists and otherwise falls back to carving.

Formats with a structural parser: PE, ELF. Everything else is identified by
signature and carved. That is a deliberate limit, not an oversight.

## `revkit.pe`

Header, sections, imports, exports, Rich header, TLS callbacks, load config,
overlay. Import-by-ordinal is reported as an ordinal instead of being dropped.

`overlay_start` is the end of the last section with real data, rounded up to the
file alignment. Anything past it is overlay, which in PE is the usual place for a
second packed block.

Known limits: no resource tree parsing, no authenticode verification, no delay
import bound-import handling. Section entropy comes from the raw bytes actually
present, so a truncated section scores on what it has.

## `revkit.elf`

Header, program and section headers, `.symtab` and `.dynsym`, dynamic table,
notes, interpreter, soname, rpath, build id.

When there is no section table (a stripped PIE), the dynamic segment is used
instead and `.dynsym` is walked from `DT_SYMTAB` with virtual addresses
translated through the LOAD segments. `imports()` returns undefined symbols in
`.dynsym`.

## `revkit.entropy`

Shannon entropy, block profile, chi-square, Monte Carlo pi.

Two things people get wrong here, both documented in the code:

- Chi-square is a deviation statistic. Perfectly uniform data scores near zero,
  real random data scores near 255 (the degrees of freedom), and repetitive data
  scores far above that.
- Monte Carlo pi saturates at 4.0 for constant data, because every point falls
  inside the circle. It is a sanity check, not a proof.

`HIGH_ENTROPY` is 7.5 and `VERY_HIGH_ENTROPY` is 7.9. Whole-file entropy is a
blunt instrument; the block profile is what finds a packed section inside an
otherwise normal binary.

## `revkit.strings`

ASCII and UTF-16LE. UTF-16 requires the high byte to be zero, which is what keeps
false positives from random data down to nothing.

`looks_like_base64` is a heuristic for flagging strings worth a decode attempt,
not a validator.

## `revkit.crypto`

XOR (single byte, repeating key, known plaintext), RC4, zlib/gzip/bzip2/lzma,
base64, CRC32, Adler32, FNV-1a, file hashes.

`score_english` is a per-byte log-likelihood against an English character
distribution, rescaled so uniform random data scores 0 and ordinary English
scores about 0.45. `english_bits_per_char` is the underlying number and the one
worth printing.

Two functions with deliberately different claims:

- `repeat_key_length` is a heuristic and can be wrong. It is honest about it.
- `xor_break_key` recovers a key when the length is known, and is reliable.
  Each column of the ciphertext was XORed with a single key byte, so a
  single-byte brute force per column recovers the key.

`xor_known_plaintext` returns a key one byte per known plaintext byte. Give it
four known bytes and you get a four-byte repeating key.

## `revkit.signatures`

A small rule engine: regex patterns and literal needles, one pass, hits sorted by
severity then offset. This is not YARA. There are no modules, loops or magic
keywords.

`default_rules()` returns a fresh copy each call, so callers can add their own
without mutating the module.

## `revkit.carve`

Magic-signature carving, section carving, firmware partition markers, overlay
detection, high-entropy regions.

Signatures that are too common to trust away from offset zero (MZ, BM, ID3,
RIFF) are only matched at the start of the file. Everything else is searched for
anywhere. A deflated ZIP member hides the signature of whatever is inside it, so
carving inside compressed archives will find nothing.

## `revkit.patcher`

Offset writes with backups, PE checksum fixup, NOP filling, byte-pattern search.

`parse_bytes_arg` accepts `90 90 c3`, `0x90,0x90,0xc3` and `\x90\x90\xc3`.
`parse_offset` accepts `0x1040`, `4160` and `0o101000`.

Default behaviour writes a new file and leaves the original alone. `--in-place`
still writes a `.bak` unless you pass `--no-backup`, and `write_backup` refuses to
clobber an existing backup.

## `revkit.emulator`

An x86 / x86-64 emulator for raw code blobs. `load_shellcode()` places the bytes
and lays out a stack, `emulate()` runs them and hands back a result object with
the exit code, modelled syscalls, captured output and any error. Pure stdlib.

It is a subset machine. The decoder raises on any instruction it does not know
rather than guessing, so an unimplemented opcode stops the run with the address
and the opcode in the message instead of quietly corrupting state. Real compiler
output will hit that quickly; hand-written shellcode usually will not.

Syscalls are modelled, not executed: `write` appends to a buffer you read back,
`mmap` hands out addresses in a synthetic space, and `execve` refuses outright.
Nothing forks and nothing touches the host. The filesystem is `vfs.Vfs`, a dict
of paths to bytes starting from a small fake root, so a sample that opens
`/etc/shadow` gets what you put there or nothing. Seed your own with
`Vfs.default()` and `add()`, then pass it as `emulate(vfs=fs)`.

The network is a sinkhole in `net.Network`. `connect` always succeeds and every
byte the sample sends is recorded, so a C2 beacon believes it phoned home and
keeps going down its C2 path while you collect the address, the headers and the
exfil format. No socket is opened and no packet leaves. Nothing is ever answered,
so a sample waiting on a command sees EOF. `sendto` and `sendmsg` are captured
too, which covers a stub doing its own DNS. The flows come back on
`RunResult.traffic`, and `revkit emulate` prints them.

A sample that writes a file lands it in the VFS, which is how you see what a
dropper dropped. `block_syscall` and `block_mnemonic` are still there and still
record what they refused, for when you want a call to fail on purpose.

`Hooks` gives you `before_insn`, `after_insn`, `on_syscall`, `on_read` and
`on_write`; `SnapshotHooks` records writes inside a region so you can dump what a
stub built. `revkit emulate` drives all of this from the command line, and
`--mount PATH=FILE` seeds the guest filesystem.

## `revkit.report`

`analyze()` runs every analyzer with each stage guarded, so one failing analyzer
costs you that analyzer and not the whole report. `to_json()` for tooling,
`to_markdown()` for reading. The markdown numbers come from the analysis, not
from documentation, so they cannot drift.

## `revkit.disasm`

Wraps capstone, imported lazily. Without capstone you get a clean message naming
the install command, not a traceback.

`annotate_syscalls` looks back a few instructions for `mov rax, N` before a
syscall, which is how nearly every stub does it. `call_targets` resolves relative
control transfers. `find_api_resolution` flags references to functions a stub
typically resolves at runtime.

## `revkit.cli`

Subcommands over the library. Every subcommand checks its input file exists and
returns a non-zero exit code with a one-line error rather than a traceback.
