# Triage workflow

The order that works. Each step narrows what the next one has to look at.

## 1. What is it

```bash
revkit file sample.bin
```

Format, size, entropy, hashes. If the format is unknown, the file is either
something you have not seen or a container you need to unpack first.

A DOS `MZ` header with no PE signature behind it is either a DOS stub or a PE
whose headers were stripped. `revkit` warns about both.

## 2. How random is it

```bash
revkit entropy sample.bin
```

Whole-file entropy tells you whether the file is packed. Block entropy tells you
*where*. A binary at 6.0 overall with a region at 7.9 has one packed section, and
that is the section to work on.

Entropy is a screen, not a verdict. Compressed media and encrypted containers
both score high for good reasons.

## 3. What does it say

```bash
revkit strings sample.bin --offsets
```

Read the strings before you read the code. URLs, registry keys, file paths and
API names tell you more in thirty seconds than an hour of disassembly.

UTF-16 strings are the ones people forget to obfuscate. On a Windows target they
are often the fastest route to something useful.

## 4. What is it hiding

```bash
revkit decode sample.bin --method xor-brute
revkit extract sample.bin -o carved/
```

Try the deobfuscators against the whole file and against each high-entropy
region. Then carve: a ZIP, an embedded PE, a second stage appended after the
last section.

If the file is a ZIP or another container, unpack it and start again at step 1
with the contents.

## 5. What does it do

```bash
revkit shell shellcode.bin --syscalls
revkit scan sample.bin --json > report.json
```

For raw code, the syscall list is the fastest shape of the thing. `write`, then
`open`, then `execve` is a different program from `socket`, `connect`, `send`.

## 6. Change it

```bash
revkit find sample.bin "74 05"
revkit patch sample.bin 0x1234 "eb 05"
```

`find` locates the bytes you want to change, `patch` writes the replacement. A
backup is written unless you say otherwise. A conditional jump flipped from
`74` to `eb` turns a check into an unconditional branch, which is the classic
way to disable one.

## Things that waste time

- Staring at disassembly before reading the strings.
- Treating whole-file entropy as a verdict.
- Assuming a file is packed because it looks random, without checking whether
  the high-entropy region lines up with a section boundary.
- Patching in place without a backup, then having to re-download the sample.

## Safety

`revkit` reads binaries; it does not run them. The emulator in `revkit.emulator`
is the one place that executes anything, and it executes in a synthetic machine
with no real syscalls, no network and no process of its own. Its filesystem is a
dict in `revkit/emulator/vfs.py`, so a sample that opens `/etc/shadow` gets
whatever you mounted there, never the real file. That is what makes pointing it
at code you do not trust safe. It is not a sandbox for whole programs and it is
not a debugger.

Analyse software you own or are authorised to analyse. Patching a binary you do
not own may violate its licence and, in some jurisdictions, copyright law.
