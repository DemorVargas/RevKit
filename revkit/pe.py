"""PE parser: headers, sections, imports, exports, resources, overlay.

Only the parts you actually read when you are triaging something. No dependency
on pefile, everything is walked by hand so a truncated or mangled sample still
gives you whatever it has instead of refusing to load.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .io import Reader, FormatError, align_up, cstr_at, rva_to_offset

# Machine types worth naming. The rest are rare enough to print as hex.
MACHINE = {
    0x14C: "i386",
    0x8664: "amd64",
    0x1C0: "arm",
    0xAA64: "arm64",
    0x1C4: "armnt",
    0x166: "mips",
    0x5032: "riscv32",
    0x5064: "riscv64",
}

# The characteristic bits that matter for triage.
CHARACTERISTICS = {
    0x0002: "LARGE_ADDRESS_AWARE",
    0x0020: "EXECUTABLE_IMAGE",
    0x0100: "32BIT_MACHINE",
    0x0200: "DEBUG_STRIPPED",
    0x2000: "DLL",
    0x4000: "UP_SYSTEM_ONLY",
}

SUBSYSTEM = {
    1: "NATIVE",
    2: "WINDOWS_GUI",
    3: "WINDOWS_CUI",
    5: "OS2_CUI",
    7: "POSIX_CUI",
    9: "WINDOWS_CE_GUI",
    10: "EFI_APPLICATION",
    14: "XBOX",
}

# Data directories in file order, index 0 first.
DIRECTORIES = [
    "export",
    "import",
    "resource",
    "exception",
    "certificate",
    "reloc",
    "debug",
    "architecture",
    "global_ptr",
    "tls",
    "load_config",
    "bound_import",
    "iat",
    "delay_import",
    "clr_runtime",
    "reserved",
]


@dataclass
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    pointer_to_raw_data: int
    size_of_raw_data: int
    characteristics: int
    entropy: float = 0.0

    @property
    def end(self) -> int:
        return self.pointer_to_raw_data + self.size_of_raw_data

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "virtual_address": self.virtual_address,
            "virtual_size": self.virtual_size,
            "pointer_to_raw_data": self.pointer_to_raw_data,
            "size_of_raw_data": self.size_of_raw_data,
            "characteristics": self.characteristics,
            "entropy": round(self.entropy, 4),
            "executable": bool(self.characteristics & 0x20000000),
            "writable": bool(self.characteristics & 0x80000000),
        }


@dataclass
class Import:
    dll: str
    name: str | None = None
    ordinal: int | None = None
    rva: int = 0

    def to_dict(self) -> dict:
        return {
            "dll": self.dll,
            "name": self.name,
            "ordinal": self.ordinal,
            "rva": self.rva,
        }


@dataclass
class Export:
    name: str | None
    ordinal: int
    rva: int
    forwarder: str | None = None

    def to_dict(self) -> dict:
        return {"name": self.name, "ordinal": self.ordinal, "rva": self.rva, "forwarder": self.forwarder}


@dataclass
class PEFile:
    path: str
    data: bytes
    machine: int
    timestamp: int
    entry_point: int
    image_base: int
    subsystem: int
    characteristics: int
    sections: list[Section] = field(default_factory=list)
    imports: list[Import] = field(default_factory=list)
    exports: list[Export] = field(default_factory=list)
    directories: dict[str, int] = field(default_factory=dict)
    overlay_start: int = 0
    warnings: list[str] = field(default_factory=list)
    rich: list[dict] = field(default_factory=list)
    tls_callbacks: list[int] = field(default_factory=list)
    load_config: dict = field(default_factory=dict)

    @property
    def is_dll(self) -> bool:
        return bool(self.characteristics & 0x2000)

    @property
    def is_64bit(self) -> bool:
        return self.machine == 0x8664

    @property
    def machine_name(self) -> str:
        return MACHINE.get(self.machine, f"0x{self.machine:04x}")

    def section_for_rva(self, rva: int) -> Section | None:
        for sec in self.sections:
            if sec.virtual_address <= rva < sec.virtual_address + max(sec.virtual_size, sec.size_of_raw_data):
                return sec
        return None

    def offset_for_rva(self, rva: int) -> int | None:
        return rva_to_offset(rva, [s.to_dict() for s in self.sections])

    def characteristic_names(self) -> list[str]:
        return [name for bit, name in CHARACTERISTICS.items() if self.characteristics & bit]

    def subsystem_name(self) -> str:
        return SUBSYSTEM.get(self.subsystem, f"unknown({self.subsystem})")

    def summary(self) -> dict:
        return {
            "path": self.path,
            "format": "pe",
            "machine": self.machine_name,
            "is_64bit": self.is_64bit,
            "is_dll": self.is_dll,
            "entry_point": self.entry_point,
            "image_base": self.image_base,
            "subsystem": self.subsystem_name(),
            "characteristics": self.characteristic_names(),
            "timestamp": self.timestamp,
            "timestamp_utc": _unix_to_utc(self.timestamp),
            "section_count": len(self.sections),
            "import_count": len(self.imports),
            "export_count": len(self.exports),
            "overlay_start": self.overlay_start,
            "overlay_size": len(self.data) - self.overlay_start if self.overlay_start else 0,
            "warnings": self.warnings,
        }


def _unix_to_utc(ts: int) -> str | None:
    """PE timestamps are seconds since 1970, but plenty of malware sets them to
    0 or to something absurd, so this never throws."""
    import datetime

    if ts <= 0 or ts > 4102444800:
        return None
    try:
        return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def parse_pe(data: bytes, path: str = "<memory>") -> PEFile:
    """Parse a PE. Raises FormatError if the headers are not there at all, but
    collects everything questionable in `warnings` instead of bailing."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise FormatError("not a PE: missing MZ signature")

    r = Reader(data)
    r.seek(0x3C)  # e_lfanew lives here
    pe_off = r.u32()
    if pe_off + 4 > len(data) or data[pe_off : pe_off + 4] != b"PE\x00\x00":
        raise FormatError("not a PE: PE\\0\\0 signature not found at e_lfanew")

    r.seek(pe_off + 4)
    machine = r.u16()
    num_sections = r.u16()
    timestamp = r.u32()
    r.u32()  # pointer to symbol table, dead since forever
    r.u32()  # number of symbols
    optional_size = r.u16()
    characteristics = r.u16()

    opt_off = r.tell()
    magic = r.u16()
    is_64 = magic == 0x20B
    r.seek(opt_off)

    # 0x00 magic, 0x02 linker version, 0x04-0x0C three size fields.
    r.read(16)
    entry_point = r.u32()
    r.u32()  # BaseOfCode
    if is_64:
        image_base = r.u64()
    else:
        r.u32()  # BaseOfData, PE32 only
        image_base = r.u32()
    r.u32()  # SectionAlignment
    r.u32()  # FileAlignment
    r.read(16)  # OS version, image version, subsystem version, win32 version
    r.u32()  # SizeOfImage
    r.u32()  # SizeOfHeaders
    r.u32()  # CheckSum
    subsystem = r.u16()
    r.u16()  # DllCharacteristics
    if is_64:
        r.read(32)  # stack/heap reserve and commit, x4
    else:
        r.read(16)  # stack/heap reserve and commit, x4 (32-bit)
    r.u32()  # LoaderFlags
    num_dirs = min(r.u32(), 16)

    directories: dict[str, int] = {}
    for i, name in enumerate(DIRECTORIES):
        if i >= num_dirs:
            break
        rva = r.u32()
        size = r.u32()
        directories[name] = rva
        directories[f"{name}_size"] = size

    if opt_off + optional_size > len(data):
        raise FormatError("optional header runs past the end of the file")

    # Section table sits right after the optional header.
    r.seek(opt_off + optional_size)
    sections = _parse_sections(r, num_sections, data, is_64)

    pe = PEFile(
        path=path,
        data=data,
        machine=machine,
        timestamp=timestamp,
        entry_point=entry_point,
        image_base=image_base,
        subsystem=subsystem,
        characteristics=characteristics,
        sections=sections,
        directories=directories,
    )

    pe.imports = _parse_imports(data, pe)
    pe.exports = _parse_exports(data, pe)
    pe.rich = _parse_rich(data, pe_off)
    pe.tls_callbacks = _parse_tls(data, pe)
    pe.load_config = _parse_load_config(data, pe)
    pe.overlay_start = _overlay_start(pe)
    return pe


def _parse_sections(r: Reader, count: int, data: bytes, is_64: bool) -> list[Section]:
    from .entropy import shannon

    out = []
    for _ in range(count):
        if r.remaining() < 40:
            break
        name = r.read(8).rstrip(b"\x00").decode("latin-1")
        virtual_size = r.u32()
        virtual_address = r.u32()
        size_raw = r.u32()
        ptr_raw = r.u32()
        r.read(8)  # pointer to relocations, pointer to line numbers
        r.u16()  # number of relocations
        r.u16()  # number of line numbers
        characteristics = r.u32()

        chunk = b""
        if 0 < ptr_raw and ptr_raw + size_raw <= len(data):
            chunk = data[ptr_raw : ptr_raw + size_raw]
        elif ptr_raw + size_raw > len(data) and ptr_raw < len(data):
            # Truncated section: read what is there rather than reporting nothing.
            chunk = data[ptr_raw:]
        out.append(
            Section(
                name=name,
                virtual_address=virtual_address,
                virtual_size=virtual_size,
                pointer_to_raw_data=ptr_raw,
                size_of_raw_data=size_raw,
                characteristics=characteristics,
                entropy=shannon(chunk) if chunk else 0.0,
            )
        )
    return out


def _parse_imports(data: bytes, pe: PEFile) -> list[Import]:
    """Walk the import descriptor table. Import-by-ordinal is common in packed
    binaries and gets reported as an ordinal rather than silently dropped."""
    rva = pe.directories.get("import")
    if not rva:
        return []
    off = pe.offset_for_rva(rva)
    if off is None:
        pe.warnings.append(f"import directory RVA 0x{rva:x} does not map to a file offset")
        return []

    out: list[Import] = []
    while off + 20 <= len(data):
        (orig_first_thunk, _ts, _fwd, name_rva, first_thunk) = (
            int.from_bytes(data[off : off + 4], "little"),
            int.from_bytes(data[off + 4 : off + 8], "little"),
            int.from_bytes(data[off + 8 : off + 12], "little"),
            int.from_bytes(data[off + 12 : off + 16], "little"),
            int.from_bytes(data[off + 16 : off + 20], "little"),
        )
        if orig_first_thunk == 0 and name_rva == 0 and first_thunk == 0:
            break
        name_off = pe.offset_for_rva(name_rva)
        dll = cstr_at(data, name_off) if name_off is not None else ""
        if not dll:
            pe.warnings.append(f"import descriptor at 0x{off:x} has no DLL name")
            off += 20
            continue

        thunk_rva = orig_first_thunk or first_thunk
        thunk_off = pe.offset_for_rva(thunk_rva)
        if thunk_off is not None:
            step = 8 if pe.is_64bit else 4
            while thunk_off + step <= len(data):
                raw = int.from_bytes(data[thunk_off : thunk_off + step], "little")
                if raw == 0:
                    break
                high_bit = 1 << (step * 8 - 1)
                if raw & high_bit:
                    out.append(Import(dll=dll, ordinal=raw & 0xFFFF, rva=thunk_rva))
                else:
                    name_ptr = pe.offset_for_rva(raw)
                    # Hint word, then the name.
                    out.append(Import(dll=dll, name=cstr_at(data, name_ptr + 2) if name_ptr else "", rva=thunk_rva))
                thunk_off += step
                thunk_rva += step
        off += 20
    return out


def _parse_exports(data: bytes, pe: PEFile) -> list[Export]:
    rva = pe.directories.get("export")
    if not rva:
        return []
    off = pe.offset_for_rva(rva)
    if off is None:
        return []

    name_off = pe.offset_for_rva(int.from_bytes(data[off + 12 : off + 16], "little"))
    dll_name = cstr_at(data, name_off) if name_off is not None else ""
    base = int.from_bytes(data[off + 16 : off + 20], "little")
    num_funcs = int.from_bytes(data[off + 20 : off + 24], "little")
    num_names = int.from_bytes(data[off + 24 : off + 28], "little")
    funcs_off = pe.offset_for_rva(int.from_bytes(data[off + 28 : off + 32], "little"))
    names_off = pe.offset_for_rva(int.from_bytes(data[off + 32 : off + 36], "little"))
    ords_off = pe.offset_for_rva(int.from_bytes(data[off + 36 : off + 40], "little"))
    if None in (funcs_off, names_off, ords_off) or num_funcs > 100000:
        return []

    names: dict[int, str] = {}
    for i in range(min(num_names, 100000)):
        no = names_off + i * 4
        if no + 4 > len(data):
            break
        ptr = pe.offset_for_rva(int.from_bytes(data[no : no + 4], "little"))
        names[i] = cstr_at(data, ptr) if ptr is not None else ""

    out = []
    for i in range(min(num_funcs, 100000)):
        fo = funcs_off + i * 4
        if fo + 4 > len(data):
            break
        func_rva = int.from_bytes(data[fo : fo + 4], "little")
        oo = ords_off + i * 2
        ordinal = int.from_bytes(data[oo : oo + 2], "little") + base if oo + 2 <= len(data) else base + i
        name = names.get(i)
        # A forwarder RVA lands inside the export directory itself.
        if name is None and func_rva and rva <= func_rva < rva + pe.directories.get("export_size", 0):
            fwd_off = pe.offset_for_rva(func_rva)
            name = cstr_at(data, fwd_off) if fwd_off is not None else None
            out.append(Export(name=None, ordinal=ordinal, rva=func_rva, forwarder=name))
            continue
        out.append(Export(name=name, ordinal=ordinal, rva=func_rva))
    if dll_name:
        pe.warnings.append(f"exported by {dll_name}")
    return out


def _parse_rich(data: bytes, pe_off: int) -> list[dict]:
    """The Rich header sits between the DOS stub and PE\\0\\0. It is a build
    stamp, and seeing five different compilers in one binary is worth knowing."""
    start = 0x80
    end = max(pe_off - 8, start)
    # The Rich header ends with "Rich" followed by a key.
    idx = data.find(b"Rich", start, end)
    if idx == -1:
        return []
    key = int.from_bytes(data[idx + 4 : idx + 8], "little")
    out = []
    # Walk backwards in 8-byte entries, each XORed with the key, until "DanS".
    pos = idx - 8
    while pos >= start:
        comp_id = int.from_bytes(data[pos : pos + 4], "little") ^ key
        count = int.from_bytes(data[pos + 4 : pos + 8], "little") ^ key
        if comp_id == 0 and count == 0:
            break
        if (comp_id >> 16) == 0x536E:  # "DanS" marker, start of the header
            break
        out.append({"id": comp_id & 0xFFFF, "build": comp_id >> 16, "count": count})
        pos -= 8
    return out


def _parse_tls(data: bytes, pe: PEFile) -> list[int]:
    """TLS callbacks run before the entry point. Malware uses them to kick off
    before a debugger can break on the main function."""
    rva = pe.directories.get("tls")
    if not rva:
        return []
    off = pe.offset_for_rva(rva)
    if off is None or off + (24 if pe.is_64bit else 24) > len(data):
        return []
    if pe.is_64bit:
        callbacks_rva = int.from_bytes(data[off + 24 : off + 32], "little")
    else:
        callbacks_rva = int.from_bytes(data[off + 12 : off + 16], "little")
    if not callbacks_rva:
        return []
    coff = pe.offset_for_rva(callbacks_rva)
    if coff is None:
        return []
    step = 8 if pe.is_64bit else 4
    out = []
    while coff + step <= len(data):
        ptr = int.from_bytes(data[coff : coff + step], "little")
        if ptr == 0:
            break
        out.append(ptr)
        coff += step
        if len(out) > 64:
            break
    return out


def _parse_load_config(data: bytes, pe: PEFile) -> dict:
    """SafeSEH list and CFG flags. An empty SafeSEH with CFG on is normal for
    modern binaries; SafeSEH off with a GUI subsystem is not."""
    rva = pe.directories.get("load_config")
    if not rva:
        return {}
    off = pe.offset_for_rva(rva)
    if off is None or off + 4 > len(data):
        return {}
    size = int.from_bytes(data[off : off + 4], "little")
    if size > len(data) - off or size > 256:
        size = min(size, 256)
    flags = int.from_bytes(data[off + 60 : off + 64], "little") if size >= 64 else 0
    return {
        "size": size,
        "guard_cf_flags": flags,
        "control_flow_guard": bool(flags & 0x4000) if flags else False,
        "security_cookie": int.from_bytes(data[off + 56 : off + 60], "little") if size >= 60 else 0,
    }


def _overlay_start(pe: PEFile) -> int:
    """End of the last section with real data. Anything past this is overlay."""
    end = 0
    for sec in pe.sections:
        if sec.size_of_raw_data and sec.pointer_to_raw_data:
            end = max(end, sec.pointer_to_raw_data + sec.size_of_raw_data)
    # SizeOfHeaders is also a floor: data before it is headers, not overlay.
    if not end:
        end = 0x400
    return align_up(end, 0x200)


def parse_pe_file(path: str) -> PEFile:
    from .io import read_file

    return parse_pe(read_file(path), path)
