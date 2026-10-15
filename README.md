# revkit

A reverse engineering toolkit for binaries, firmware images and memory blobs. It
answers the first five minutes of an engagement: what *is* this thing, what does
it *do*, what is it *hiding*, and how do I *change* it.

The core is pure stdlib, so `import revkit` works on Python 3.10+ with nothing
installed. Capstone disassembly is an optional extra, imported lazily.

```
revkit file    firmware.bin           # identity, sections, entropy, imports
revkit scan    suspicious.exe         # every analyzer at once, JSON to stdout
revkit extract firmware.bin -o out/   # carve sections and embedded files
revkit decode  sample.bin             # brute-force XOR / RC4 / zlib / base64
revkit patch   target.bin 0x1040 "90 90"  # write bytes at an offset, with backup
revkit shell   shellcode.bin          # disassemble x86-64 (needs capstone)
revkit emulate shellcode.bin          # run x86-64 in a synthetic machine
```

## Install

```bash
pip install -e ".[disasm]"   # capstone, for `revkit shell`
pip install -e ".[dev]"      # pytest, to run the suite
```

No required dependencies. Linux, macOS and Windows.

## What it does

- **Identify** PE, ELF, Mach-O and firmware containers, with full PE and ELF
  parsing: headers, sections, imports, exports, Rich header, TLS callbacks,
  symbols, dynamic table, build id, interpreter, overlay.
- **Measure** Shannon entropy, block profile, chi-square and Monte Carlo pi, to
  find packed sections and encrypted blobs.
- **Extract** strings, embedded files, firmware partitions, overlays and
  high-entropy regions.
- **Decode** single-byte and repeating-key XOR, known plaintext, RC4, zlib, gzip,
  bzip2, lzma, Base64, and the common hashes and checksums.
- **Emulate** raw x86 / x86-64 shellcode in a synthetic machine: modelled
  syscalls, an in-memory filesystem, a sinkhole network, no host contact.
- **Patch** bytes at an offset with a backup, PE checksum fixup, NOP filling.
- **Report** everything as JSON or markdown.

As a library:

```python
from revkit import formats, report

print(formats.identify_file("sample.exe").format)
print(report.to_markdown(report.analyze("sample.exe")))
```

## Safety

`revkit` reads binaries; it does not run them. The emulator is the only thing
that executes, and it runs in a synthetic machine with no real syscalls, no
network and no process of its own: its filesystem is a dict, and its network is a
sinkhole that records what a sample tried to send without opening a socket. It is
not a sandbox for whole programs, and it is not a debugger.

Analyse only software you own or are authorised to analyse. Patching a binary you
do not own may breach its licence. The patcher always writes a `.bak`.

## Docs and tests

`docs/` covers every analyzer, the triage workflow, and PE and ELF format traps.
`examples/` has ten runnable scripts, none needing a sample download. The test
suite needs no sample files either:

```bash
python -m pytest -q
```

## License

MIT. See `LICENSE`.
