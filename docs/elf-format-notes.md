# ELF notes

## Layout

```
0x00  \x7fELF
0x04  EI_CLASS   (1 = 32-bit, 2 = 64-bit)
0x05  EI_DATA    (1 = little, 2 = big)
0x10  e_type, e_machine
0x18  e_entry
0x20  e_phoff
0x28  e_shoff
```

Both 32-bit and 64-bit headers are parsed; the width comes from `EI_CLASS` and
the endianness from `EI_DATA`. Neither is assumed.

## Section vs program headers

Program headers describe how to load the file, section headers describe how to
link it. A stripped binary keeps program headers and loses section headers, so a
stripped PIE still has a usable dynamic segment.

`_vaddr_to_offset` translates virtual addresses through the LOAD segments. It is
used for `DT_SYMTAB` and `DT_STRTAB` when there is no section table to fall back
on.

## Symbol tables

`.symtab` is the full table and is usually stripped. `.dynsym` is the dynamic
symbol table and survives. `imports()` returns the undefined entries of
`.dynsym`, which is what a dynamically linked binary actually pulls in.

Entry size: 24 bytes for 64-bit, 16 for 32-bit. The `st_shndx` field is 0 for
undefined symbols, which is the import test.

## Dynamic table tags used

| Tag | Meaning |
| --- | --- |
| 1 | DT_NEEDED |
| 5 | DT_STRTAB |
| 6 | DT_SYMTAB |
| 14 | DT_SONAME |
| 15 | DT_RPATH |
| 29 | DT_RUNPATH |

## Notes

`NT_GNU_BUILD_ID` (type 3, name "GNU") is the build id. A missing build id on a
shipped binary is itself a finding, because it means you cannot correlate the
file against a known artifact.

## Segments worth reading

| Type | Meaning |
| --- | --- |
| 1 LOAD | Loadable segment |
| 2 DYNAMIC | Dynamic linking information |
| 3 INTERP | Program interpreter path |
| 7 TLS | Thread-local storage |
| 0x6474E551 GNU_STACK | Stack executability |
| 0x6474E552 GNU_RELRO | Read-only after relocation |

A `LOAD` segment with write and execute both set is worth a look.
