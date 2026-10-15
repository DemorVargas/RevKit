# PE notes

Field offsets that matter, and the traps.

## Layout

```
0x00  MZ
0x3C  e_lfanew (4 bytes, points at PE\0\0)
      PE\0\0
+4    COFF header (20 bytes)
+24   optional header (size at COFF+16)
      section table (40 bytes per section)
```

`optional_size` from the COFF header tells you where the section table starts.
Do not hardcode it.

## Optional header offsets

Relative to the start of the optional header:

| Offset | PE32+ | PE32 |
| --- | --- | --- |
| 0x10 | AddressOfEntryPoint | AddressOfEntryPoint |
| 0x18 | ImageBase (8 bytes) | BaseOfData, then ImageBase (4 bytes) |
| 0x20 | SectionAlignment | SectionAlignment |
| 0x38 | SizeOfImage | SizeOfImage |
| 0x44 | Subsystem | Subsystem |
| 0x58 | | LoaderFlags |
| 0x5C | | NumberOfRvaAndSizes |
| 0x60 | | DataDirectory |
| 0x68 | LoaderFlags | |
| 0x6C | NumberOfRvaAndSizes | |
| 0x70 | DataDirectory | |

The 8-byte ImageBase in PE32+ and the absent BaseOfData shift everything after
0x18. Getting this wrong produces headers that parse as garbage while still
looking plausible, which is the worst kind of bug.

## Section table

40 bytes each: name (8), VirtualSize, VirtualAddress, SizeOfRawData,
PointerToRawData, two pointers, two 16-bit counts, Characteristics.

`VirtualSize` can exceed `SizeOfRawData`. The tail of such a section has no file
bytes, so `rva_to_offset` returns None for it rather than a bogus offset.

## Characteristics worth reading

- `0x0020` LARGE_ADDRESS_AWARE
- `0x0002` EXECUTABLE_IMAGE
- `0x0100` 32BIT_MACHINE
- `0x0200` DEBUG_STRIPPED
- `0x2000` DLL

## Imports

The import directory is a null-terminated array of 20-byte descriptors:
OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk.

Thunks are 4 bytes in PE32 and 8 in PE32+. A high-bit-set thunk is an ordinal
import; otherwise it points at a hint word followed by the name.

Walking `OriginalFirstThunk` gives you the names. `FirstThunk` is the IAT, which
a loaded binary has already had patched with addresses, so it is only useful on
disk.

## Rich header

Sits between the DOS stub and PE\0\0, ends with `Rich` followed by a key. Each
8-byte entry before it is XORed with that key and decodes to a component id and a
count. Five different compilers in one binary is worth knowing about.

## TLS callbacks

Run before the entry point. Malware uses them so that a debugger breaking on
`main` misses the payload entirely. Any non-empty TLS callback array in an
unknown sample deserves attention.

## Overlay

Anything after the end of the last section with real data. Second-stage payloads
and appended config blocks both live here. `overlay_start` is rounded up to the
file alignment.
