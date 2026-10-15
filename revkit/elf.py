"""ELF parser: headers, program and section headers, symbols, PLT/GOT, notes.

No pyelftools dependency. Everything is walked by hand so a stripped or
deliberately mangled ELF still yields what it has.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .io import Reader, FormatError, align_up

EI_CLASS = {1: "32-bit", 2: "64-bit"}
EI_DATA = {1: "little-endian", 2: "big-endian"}

ELF_TYPE = {1: "REL (relocatable)", 2: "EXEC (executable)", 3: "DYN (shared object)", 4: "CORE"}

EM = {
    3: "x86",
    8: "mips",
    20: "ppc",
    21: "ppc64",
    40: "arm",
    50: "ia64",
    62: "x86-64",
    183: "aarch64",
    243: "riscv",
}

PT = {
    0: "NULL",
    1: "LOAD",
    2: "DYNAMIC",
    3: "INTERP",
    4: "NOTE",
    5: "SHLIB",
    6: "PHDR",
    7: "TLS",
    0x6474E550: "GNU_EH_FRAME",
    0x6474E551: "GNU_STACK",
    0x6474E552: "GNU_RELRO",
    0x6474E553: "GNU_PROPERTY",
}

SHT = {
    0: "NULL",
    1: "PROGBITS",
    2: "SYMTAB",
    3: "STRTAB",
    4: "RELA",
    5: "HASH",
    6: "DYNAMIC",
    7: "NOTE",
    8: "NOBITS",
    9: "REL",
    11: "DYNSYM",
    14: "INIT_ARRAY",
    15: "FINI_ARRAY",
    16: "PREINIT_ARRAY",
    17: "GROUP",
    18: "SYMTAB_SHNDX",
    19: "RELR",
    0x6FFFFFF5: "GNU_ATTRIBUTES",
    0x6FFFFFF6: "GNU_HASH",
    0x6FFFFFFD: "GNU_VERDEF",
    0x6FFFFFFE: "GNU_VERNEED",
    0x6FFFFFFF: "GNU_VERSYM",
}

# Section flags worth reporting.
SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

STT = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE", 6: "TLS", 10: "GNU_IFUNC"}
STB = {0: "LOCAL", 1: "GLOBAL", 2: "WEAK"}
STV = {0: "DEFAULT", 1: "INTERNAL", 2: "HIDDEN", 3: "PROTECTED"}


@dataclass
class Segment:
    type: int
    offset: int
    virtual_address: int
    physical_address: int
    file_size: int
    memory_size: int
    flags: int
    alignment: int

    @property
    def type_name(self) -> str:
        return PT.get(self.type, f"0x{self.type:x}")

    @property
    def readable(self) -> bool:
        return bool(self.flags & 4)

    @property
    def writable(self) -> bool:
        return bool(self.flags & 2)

    @property
    def executable(self) -> bool:
        return bool(self.flags & 1)

    @property
    def rwx(self) -> str:
        return f"{'r' if self.readable else '-'}{'w' if self.writable else '-'}{'x' if self.executable else '-'}"

    def to_dict(self) -> dict:
        return {
            "type": self.type_name,
            "offset": self.offset,
            "virtual_address": self.virtual_address,
            "file_size": self.file_size,
            "memory_size": self.memory_size,
            "flags": self.flags,
            "rwx": self.rwx,
        }


@dataclass
class Symbol:
    name: str
    value: int
    size: int
    info: int
    other: int
    section_index: int
    section_name: str = ""

    @property
    def bind(self) -> str:
        return STB.get(self.info >> 4, "?")

    @property
    def type(self) -> str:
        return STT.get(self.info & 0xF, "?")

    @property
    def visibility(self) -> str:
        return STV.get(self.other & 0x3, "?")

    @property
    def is_func(self) -> bool:
        return self.type == "FUNC"

    @property
    def is_import(self) -> bool:
        return self.section_index == 0

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "value": self.value,
            "size": self.size,
            "bind": self.bind,
            "type": self.type,
            "visibility": self.visibility,
            "section": self.section_name or ("UND" if self.section_index == 0 else str(self.section_index)),
            "is_import": self.is_import,
        }


@dataclass
class Section:
    name: str
    type: int
    flags: int
    address: int
    offset: int
    size: int
    link: int
    info: int
    alignment: int
    entry_size: int

    @property
    def type_name(self) -> str:
        return SHT.get(self.type, f"0x{self.type:x}")

    @property
    def writable(self) -> bool:
        return bool(self.flags & SHF_WRITE)

    @property
    def executable(self) -> bool:
        return bool(self.flags & SHF_EXECINSTR)

    @property
    def alloc(self) -> bool:
        return bool(self.flags & SHF_ALLOC)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "type": self.type_name,
            "flags": self.flags,
            "address": self.address,
            "offset": self.offset,
            "size": self.size,
            "link": self.link,
            "alignment": self.alignment,
            "writable": self.writable,
            "executable": self.executable,
        }


@dataclass
class ELFFile:
    path: str
    data: bytes
    bits: int
    endian: str
    osabi: str
    elf_type: int
    machine: int
    entry_point: int
    sections: list[Section] = field(default_factory=list)
    segments: list[Segment] = field(default_factory=list)
    symbols: list[Symbol] = field(default_factory=list)
    dynsym: list[Symbol] = field(default_factory=list)
    dynamic: list[dict] = field(default_factory=list)
    notes: list[dict] = field(default_factory=list)
    interpreter: str = ""
    soname: str = ""
    build_id: str = ""
    rpath: list[str] = field(default_factory=list)
    runpath: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def is_64bit(self) -> bool:
        return self.bits == 64

    @property
    def is_little(self) -> bool:
        return self.endian == "little-endian"

    @property
    def machine_name(self) -> str:
        return EM.get(self.machine, f"0x{self.machine:x}")

    @property
    def type_name(self) -> str:
        return ELF_TYPE.get(self.elf_type, f"0x{self.elf_type:x}")

    def imports(self) -> list[Symbol]:
        """Undefined symbols in .dynsym are the imports."""
        return [s for s in self.dynsym if s.is_import and s.name]

    def exports(self) -> list[Symbol]:
        """Defined .dynsym entries other objects can link against. Section and
        file symbols are LOCAL, so the binding filter drops them."""
        return [s for s in self.dynsym
                if not s.is_import and s.name
                and s.bind in ("GLOBAL", "WEAK")
                and s.visibility in ("DEFAULT", "PROTECTED")]

    def summary(self) -> dict:
        return {
            "path": self.path,
            "format": "elf",
            "bits": self.bits,
            "endian": self.endian,
            "osabi": self.osabi,
            "machine": self.machine_name,
            "type": self.type_name,
            "entry_point": self.entry_point,
            "interpreter": self.interpreter,
            "soname": self.soname,
            "build_id": self.build_id,
            "section_count": len(self.sections),
            "segment_count": len(self.segments),
            "symbol_count": len(self.symbols),
            "import_count": len(self.imports()),
            "warnings": self.warnings,
        }


OSABI = {
    0: "SYSV",
    1: "HPUX",
    2: "NETBSD",
    3: "LINUX",
    4: "GNU_HURD",
    6: "SOLARIS",
    7: "AIX",
    8: "IRIX",
    9: "FREEBSD",
    10: "TRU64",
    11: "MODESTO",
    12: "OPENBSD",
    64: "ARM_AEABI",
    97: "ARM",
    255: "STANDALONE",
}


def parse_elf(data: bytes, path: str = "<memory>") -> ELFFile:
    if len(data) < 16 or data[:4] != b"\x7fELF":
        raise FormatError("not an ELF: missing \\x7fELF signature")

    ei_class = data[4]
    ei_data = data[5]
    if ei_class not in EI_CLASS:
        raise FormatError(f"bad EI_CLASS {ei_class}")
    if ei_data not in EI_DATA:
        raise FormatError(f"bad EI_DATA {ei_data}")

    is_64 = ei_class == 2
    is_le = ei_data == 1
    fmt = "<" if is_le else ">"
    osabi = OSABI.get(data[7], f"0x{data[7]:02x}")

    r = Reader(data)
    r.seek(16)
    elf_type = _u16(data, 16, is_le)
    machine = _u16(data, 18, is_le)
    if is_64:
        entry = _u64(data, 24, is_le)
        phoff = _u64(data, 32, is_le)
        shoff = _u64(data, 40, is_le)
        flags = _u32(data, 48, is_le)
        ehsize = _u16(data, 52, is_le)
        phentsize = _u16(data, 54, is_le)
        phnum = _u16(data, 56, is_le)
        shentsize = _u16(data, 58, is_le)
        shnum = _u16(data, 60, is_le)
        shstrndx = _u16(data, 62, is_le)
    else:
        entry = _u32(data, 24, is_le)
        phoff = _u32(data, 28, is_le)
        shoff = _u32(data, 32, is_le)
        flags = _u32(data, 36, is_le)
        ehsize = _u16(data, 40, is_le)
        phentsize = _u16(data, 42, is_le)
        phnum = _u16(data, 44, is_le)
        shentsize = _u16(data, 46, is_le)
        shnum = _u16(data, 48, is_le)
        shstrndx = _u16(data, 50, is_le)

    elf = ELFFile(
        path=path,
        data=data,
        bits=64 if is_64 else 32,
        endian="little-endian" if is_le else "big-endian",
        osabi=osabi,
        elf_type=elf_type,
        machine=machine,
        entry_point=entry,
    )

    if phoff and phnum:
        elf.segments = _parse_segments(data, phoff, phnum, phentsize, is_64, is_le)
    if shoff and shnum:
        elf.sections = _parse_sections(data, shoff, shnum, shentsize, shstrndx, is_64, is_le)
        elf.symbols = _parse_symbols(data, elf, ".symtab")
        elf.dynsym = _parse_symbols(data, elf, ".dynsym")
        elf.dynamic = _parse_dynamic(data, elf)
        elf.notes = _parse_notes(data, elf)
        _resolve_strings(elf)
    else:
        elf.warnings.append("no section header table (stripped or malformed)")
        # Still try the dynamic segment, which is what a stripped PIE has.
        for seg in elf.segments:
            if seg.type == 2:
                elf.dynamic = _parse_dynamic_at(data, seg.offset, seg.file_size, elf)
                elf.dynsym = _parse_dynsym_at(data, seg, elf)
                break

    return elf


def _u16(data: bytes, off: int, le: bool) -> int:
    return int.from_bytes(data[off : off + 2], "little" if le else "big")


def _u32(data: bytes, off: int, le: bool) -> int:
    return int.from_bytes(data[off : off + 4], "little" if le else "big")


def _u64(data: bytes, off: int, le: bool) -> int:
    return int.from_bytes(data[off : off + 8], "little" if le else "big")


def _parse_segments(data: bytes, phoff: int, phnum: int, entsize: int, is_64: bool, le: bool) -> list[Segment]:
    out = []
    for i in range(phnum):
        off = phoff + i * (entsize or (56 if is_64 else 32))
        if off + (56 if is_64 else 32) > len(data):
            break
        if is_64:
            ptype = _u32(data, off, le)
            flags = _u32(data, off + 4, le)
            poff = _u64(data, off + 8, le)
            vaddr = _u64(data, off + 16, le)
            paddr = _u64(data, off + 24, le)
            filesz = _u64(data, off + 32, le)
            memsz = _u64(data, off + 40, le)
            align = _u64(data, off + 48, le)
        else:
            ptype = _u32(data, off, le)
            poff = _u32(data, off + 4, le)
            vaddr = _u32(data, off + 8, le)
            paddr = _u32(data, off + 12, le)
            filesz = _u32(data, off + 16, le)
            memsz = _u32(data, off + 20, le)
            flags = _u32(data, off + 24, le)
            align = _u32(data, off + 28, le)
        out.append(
            Segment(
                type=ptype,
                offset=poff,
                virtual_address=vaddr,
                physical_address=paddr,
                file_size=filesz,
                memory_size=memsz,
                flags=flags,
                alignment=align,
            )
        )
    return out


def _parse_sections(
    data: bytes, shoff: int, shnum: int, entsize: int, shstrndx: int, is_64: bool, le: bool
) -> list[Section]:
    raw: list[dict] = []
    width = entsize or (64 if is_64 else 40)
    for i in range(shnum):
        off = shoff + i * width
        if off + width > len(data):
            break
        if is_64:
            name_off = _u32(data, off, le)
            stype = _u32(data, off + 4, le)
            flags = _u64(data, off + 8, le)
            addr = _u64(data, off + 16, le)
            soff = _u64(data, off + 24, le)
            size = _u64(data, off + 32, le)
            link = _u32(data, off + 40, le)
            info = _u32(data, off + 44, le)
            align = _u64(data, off + 48, le)
            entsize_s = _u64(data, off + 56, le)
        else:
            name_off = _u32(data, off, le)
            stype = _u32(data, off + 4, le)
            flags = _u32(data, off + 8, le)
            addr = _u32(data, off + 12, le)
            soff = _u32(data, off + 16, le)
            size = _u32(data, off + 20, le)
            link = _u32(data, off + 24, le)
            info = _u32(data, off + 28, le)
            align = _u32(data, off + 32, le)
            entsize_s = _u32(data, off + 36, le)
        raw.append(
            {
                "name_off": name_off,
                "type": stype,
                "flags": flags,
                "address": addr,
                "offset": soff,
                "size": size,
                "link": link,
                "info": info,
                "alignment": align,
                "entry_size": entsize_s,
            }
        )

    # Section names live in the shstrtab section, which is itself one of the sections.
    names_blob = b""
    if 0 <= shstrndx < len(raw):
        s = raw[shstrndx]
        if s["offset"] + s["size"] <= len(data):
            names_blob = data[s["offset"] : s["offset"] + s["size"]]

    out = []
    for s in raw:
        name = _name_from_blob(names_blob, s["name_off"])
        out.append(
            Section(
                name=name,
                type=s["type"],
                flags=s["flags"],
                address=s["address"],
                offset=s["offset"],
                size=s["size"],
                link=s["link"],
                info=s["info"],
                alignment=s["alignment"],
                entry_size=s["entry_size"],
            )
        )
    return out


def _name_from_blob(blob: bytes, off: int) -> str:
    if off >= len(blob):
        return ""
    end = blob.find(b"\x00", off)
    if end == -1:
        end = len(blob)
    return blob[off:end].decode("latin-1")


def _parse_symbols(data: bytes, elf: ELFFile, section_name: str) -> list[Symbol]:
    """Parse .symtab (or .dynsym) into symbols."""
    sec = next((s for s in elf.sections if s.name == section_name), None)
    if sec is None or sec.link == 0:
        return []
    strtab = elf.sections[sec.link] if sec.link < len(elf.sections) else None
    names = data[strtab.offset : strtab.offset + strtab.size] if strtab else b""
    if not names:
        return []

    entsize = sec.entry_size or (24 if elf.is_64bit else 16)
    out: list[Symbol] = []
    for off in range(sec.offset, sec.offset + sec.size, entsize):
        if off + entsize > len(data):
            break
        if elf.is_64bit:
            name_off = _u32(data, off, elf.is_little)
            info = data[off + 4]
            other = data[off + 5]
            shndx = _u16(data, off + 6, elf.is_little)
            value = _u64(data, off + 8, elf.is_little)
            size = _u64(data, off + 16, elf.is_little)
        else:
            name_off = _u32(data, off, elf.is_little)
            value = _u32(data, off + 4, elf.is_little)
            size = _u32(data, off + 8, elf.is_little)
            info = data[off + 12]
            other = data[off + 13]
            shndx = _u16(data, off + 14, elf.is_little)
        out.append(
            Symbol(
                name=_name_from_blob(names, name_off),
                value=value,
                size=size,
                info=info,
                other=other,
                section_index=shndx,
            )
        )
    return out


def _parse_dynamic(data: bytes, elf: ELFFile) -> list[dict]:
    sec = next((s for s in elf.sections if s.type == 6), None)  # SHT_DYNAMIC
    if sec is None:
        return []
    return _parse_dynamic_at(data, sec.offset, sec.size, elf)


def _parse_dynamic_at(data: bytes, off: int, size: int, elf: ELFFile) -> list[dict]:
    entsize = 16 if elf.is_64bit else 8
    out = []
    for pos in range(off, off + size, entsize):
        if pos + entsize > len(data):
            break
        if elf.is_64bit:
            tag = _u64(data, pos, elf.is_little)
            val = _u64(data, pos + 8, elf.is_little)
        else:
            tag = _u32(data, pos, elf.is_little)
            val = _u32(data, pos + 4, elf.is_little)
        if tag == 0:
            break
        out.append({"tag": tag, "value": val})
    return out


def _parse_dynsym_at(data: bytes, seg: Segment, elf: ELFFile) -> list[Symbol]:
    """When there is no section table, pull .dynsym out of the DYNAMIC segment
    using DT_SYMTAB and DT_STRTAB. The addresses there are virtual, so they have
    to be translated through the LOAD segments."""
    dyn = _parse_dynamic_at(data, seg.offset, seg.file_size, elf)
    strtab_va = next((d["value"] for d in dyn if d["tag"] == 5), None)
    symtab_va = next((d["value"] for d in dyn if d["tag"] == 6), None)
    if strtab_va is None or symtab_va is None:
        return []

    strtab_off = _vaddr_to_offset(elf, strtab_va)
    symtab_off = _vaddr_to_offset(elf, symtab_va)
    if strtab_off is None or symtab_off is None:
        return []
    names = data[strtab_off : strtab_off + 0x10000]
    if not names:
        return []

    entsize = 24 if elf.is_64bit else 16
    out = []
    # Walk until we hit the string table, which is the usual layout.
    for pos in range(symtab_off, symtab_off + 0x20000, entsize):
        if pos + entsize > len(data):
            break
        if _u64(data, pos, elf.is_little) == 0 and pos > symtab_off:
            break
        if elf.is_64bit:
            name_off = _u32(data, pos, elf.is_little)
            info = data[pos + 4]
            other = data[pos + 5]
            shndx = _u16(data, pos + 6, elf.is_little)
            value = _u64(data, pos + 8, elf.is_little)
            size = _u64(data, pos + 16, elf.is_little)
        else:
            name_off = _u32(data, pos, elf.is_little)
            value = _u32(data, pos + 4, elf.is_little)
            size = _u32(data, pos + 8, elf.is_little)
            info = data[pos + 12]
            other = data[pos + 13]
            shndx = _u16(data, pos + 14, elf.is_little)
        out.append(
            Symbol(
                name=_name_from_blob(names, name_off),
                value=value,
                size=size,
                info=info,
                other=other,
                section_index=shndx,
            )
        )
    return out


def _vaddr_to_offset(elf: ELFFile, vaddr: int) -> int | None:
    """Translate a virtual address to a file offset using the LOAD segments."""
    for seg in elf.segments:
        if seg.type == 1 and seg.virtual_address <= vaddr < seg.virtual_address + seg.file_size:
            return seg.offset + (vaddr - seg.virtual_address)
    return None


def _parse_notes(data: bytes, elf: ELFFile) -> list[dict]:
    """GNU build-id and other notes. A missing build-id on a shipped binary is
    itself a finding."""
    out = []
    for sec in elf.sections:
        if sec.type != 7:  # SHT_NOTE
            continue
        pos = sec.offset
        end = min(sec.offset + sec.size, len(data))
        while pos + 12 <= end:
            namesz = _u32(data, pos, elf.is_little)
            descsz = _u32(data, pos + 4, elf.is_little)
            ntype = _u32(data, pos + 8, elf.is_little)
            name = data[pos + 12 : pos + 12 + namesz].rstrip(b"\x00").decode("latin-1", "replace")
            desc_off = pos + 12 + align_up(namesz, 4)
            desc = data[desc_off : desc_off + descsz]
            if name == "GNU" and ntype == 3 and descsz >= 4:
                out.append({"type": "GNU_BUILD_ID", "value": desc.hex()})
            elif name == "GNU" and ntype == 1:
                out.append({"type": "GNU_ABI_TAG", "value": desc.hex()})
            else:
                out.append({"type": f"{name}:{ntype}", "value": desc[:64].hex()})
            pos = desc_off + align_up(descsz, 4)
    return out


def _resolve_strings(elf: ELFFile) -> None:
    """Fill in soname, interpreter, rpath and runpath from the dynamic table."""
    needed = []
    for d in elf.dynamic:
        if d["tag"] == 1:
            needed.append(d["value"])
    if not needed:
        return

    # DT_STRTAB points at the string table these offsets live in.
    strtab_va = next((d["value"] for d in elf.dynamic if d["tag"] == 5), None)
    strtab_off = _vaddr_to_offset(elf, strtab_va) if strtab_va else None
    if strtab_off is None:
        return

    def read_str(off: int) -> str:
        end = elf.data.find(b"\x00", strtab_off + off)
        if end == -1:
            return ""
        return elf.data[strtab_off + off : end].decode("latin-1", "replace")

    for d in elf.dynamic:
        if d["tag"] == 15:
            elf.rpath.append(read_str(d["value"]))
        elif d["tag"] == 29:
            elf.runpath.append(read_str(d["value"]))
        elif d["tag"] == 14:
            elf.soname = read_str(d["value"])

    # PT_INTERP is the interpreter, and it is a plain string in the file.
    for seg in elf.segments:
        if seg.type == 3:
            if seg.offset + seg.file_size <= len(elf.data):
                elf.interpreter = elf.data[seg.offset : seg.offset + seg.file_size].split(b"\x00")[0].decode(
                    "latin-1", "replace"
                )
            break

    for note in elf.notes:
        if note["type"] == "GNU_BUILD_ID":
            elf.build_id = note["value"]


def parse_elf_file(path: str) -> ELFFile:
    from .io import read_file

    return parse_elf(read_file(path), path)
