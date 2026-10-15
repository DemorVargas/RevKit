"""Test helpers: build minimal but structurally valid PE and ELF images.

The tests need real headers, not hand-written hex blobs, so these builders
produce files the same way a linker would. Keeping them here means the tests
stay short.
"""

from __future__ import annotations

import socket
import struct

# Machine / subsystem values used by the builders.
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_I386 = 0x14C
IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
IMAGE_SUBSYSTEM_WINDOWS_CUI = 3
IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
IMAGE_FILE_DLL = 0x2000
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_TLS = 9
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10


def build_pe(
    *,
    machine: int = IMAGE_FILE_MACHINE_AMD64,
    subsystem: int = IMAGE_SUBSYSTEM_WINDOWS_GUI,
    is_dll: bool = False,
    sections: list[dict] | None = None,
    imports: dict[str, list[str]] | None = None,
    exports: list[str] | None = None,
    timestamp: int = 0x5A5A5A5A,
) -> bytes:
    """Assemble a PE32+ image with the requested sections and imports.

    RVAs are assigned before any section content is built, so the import table's
    internal RVAs are genuinely correct rather than approximate.
    """
    is64 = machine == IMAGE_FILE_MACHINE_AMD64
    image_base = 0x140000000 if is64 else 0x400000
    file_align = 0x200
    sect_align = 0x1000

    if sections is None:
        sections = [
            {"name": ".text", "data": b"\x90" * 0x100, "chars": IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ},
            {"name": ".rdata", "data": b"https://example.invalid/payload\x00", "chars": IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ},
        ]
    sections = [dict(s) for s in sections]

    optional_size = 0xF0 if is64 else 0xE0
    # Section table follows the PE signature, the COFF header and the optional header.
    section_table_off = 0x40 + 0x18 + optional_size

    # Pass 1: lay out the user sections, then work out where .idata would go.
    def layout_of(sec_list: list[dict], first_raw: int) -> list[tuple[dict, int, int]]:
        out = []
        rva = 0x1000
        raw = first_raw
        for sec in sec_list:
            raw_size = (len(sec["data"]) + file_align - 1) // file_align * file_align
            out.append((sec, rva, raw))
            rva += (len(sec["data"]) + sect_align - 1) // sect_align * sect_align
            raw += raw_size
        return out

    first_raw = (section_table_off + (len(sections) + (1 if imports else 0)) * 40 + file_align - 1) // file_align * file_align
    layout = layout_of(sections, first_raw)
    idata_rva = 0
    idata_raw = 0
    if imports:
        idata_rva = layout[-1][1] + (len(sections[-1]["data"]) + sect_align - 1) // sect_align * sect_align
        idata_raw = layout[-1][2] + (len(sections[-1]["data"]) + file_align - 1) // file_align * file_align

    # Pass 2: build .idata content now that its RVA is known.
    if imports:
        descriptors = list(imports.items())
        num_desc = len(descriptors) + 1
        desc_size = num_desc * 20
        cursor = desc_size
        thunk_arrays = []
        for dll, funcs in descriptors:
            thunk_arrays.append((cursor, funcs))
            cursor += (len(funcs) + 1) * (8 if is64 else 4)
        name_rvas = []
        fn_offsets = []
        for dll, funcs in descriptors:
            name_rvas.append(cursor)
            cursor += len(dll) + 1
            offs = []
            for fn in funcs:
                offs.append(cursor)
                cursor += 2 + len(fn) + 1
            fn_offsets.append(offs)

        buf = bytearray(cursor)
        desc_off = 0
        for (dll, funcs), (thunk_off, _), name_off, fn_offs in zip(descriptors, thunk_arrays, name_rvas, fn_offsets):
            struct.pack_into(
                "<IIIII", buf, desc_off,
                thunk_off + idata_rva, 0, 0, name_off + idata_rva, thunk_off + idata_rva,
            )
            desc_off += 20
            step = 8 if is64 else 4
            for i, fn in enumerate(funcs):
                struct.pack_into("<Q" if is64 else "<I", buf, thunk_off + i * step, fn_offs[i] + idata_rva)
            end = thunk_off + len(funcs) * step
            buf[end : end + step] = b"\x00" * step
            buf[name_off : name_off + len(dll)] = dll.encode()
            for fn, foff in zip(funcs, fn_offs):
                buf[foff + 2 : foff + 2 + len(fn)] = fn.encode()
        sections.append({"name": ".idata", "data": bytes(buf),
                         "chars": IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ})
        layout = layout_of(sections, first_raw)

    num_sections = len(sections)
    # One zero-filled buffer sized for the whole image, then everything is
    # written at its real offset. Appending would land section data at the end.
    total_size = layout[-1][2] + (len(sections[-1]["data"]) + file_align - 1) // file_align * file_align

    headers = bytearray(first_raw)
    headers[0:2] = b"MZ"
    struct.pack_into("<I", headers, 0x3C, 0x40)
    headers[0x40:0x44] = b"PE\x00\x00"

    chars = IMAGE_FILE_EXECUTABLE_IMAGE | (IMAGE_FILE_DLL if is_dll else 0)
    if is64:
        chars |= 0x0020  # LARGE_ADDRESS_AWARE
    struct.pack_into(
        "<HHIIIHH",
        headers,
        0x44,
        machine,
        num_sections,
        timestamp,
        0,
        0,
        optional_size,
        chars,
    )

    opt = 0x40 + 0x18
    # From here on, offsets differ between PE32 and PE32+ because PE32+ has an
    # 8-byte ImageBase and no BaseOfData, which shifts the tail of the header.
    dir_base = 0x70 if is64 else 0x60
    loader_flags_at = 0x68 if is64 else 0x58
    headers[opt : opt + 2] = b"\x0b\x02" if is64 else b"\x0b\x01"
    struct.pack_into("<I", headers, opt + 16, 0x1000)  # AddressOfEntryPoint
    struct.pack_into("<I", headers, opt + 20, 0x1000)  # BaseOfCode
    if is64:
        struct.pack_into("<Q", headers, opt + 24, image_base)
    else:
        struct.pack_into("<I", headers, opt + 28, image_base)
    struct.pack_into("<II", headers, opt + 32, sect_align, file_align)
    struct.pack_into("<H", headers, opt + 68, subsystem)
    struct.pack_into("<I", headers, opt + 56, 0x100000)  # SizeOfImage
    struct.pack_into("<I", headers, opt + 60, first_raw)  # SizeOfHeaders
    struct.pack_into("<I", headers, opt + loader_flags_at + 4, 16)  # NumberOfRvaAndSizes

    out = bytearray(total_size)
    out[0 : len(headers)] = headers
    for index, (sec, rva, raw) in enumerate(layout):
        struct.pack_into(
            "<8sIIIIIIHHI",
            out,
            section_table_off + index * 40,
            sec["name"][:8].encode(),
            len(sec["data"]),
            rva,
            (len(sec["data"]) + file_align - 1) // file_align * file_align,
            raw,
            0,
            0,
            0,
            0,
            sec["chars"],
        )
        out[raw : raw + len(sec["data"])] = sec["data"]

    # Import directory entry.
    if imports:
        for i, sec in enumerate(sections):
            if sec["name"] == ".idata":
                struct.pack_into("<II", out, opt + dir_base + IMAGE_DIRECTORY_ENTRY_IMPORT * 8,
                                 layout[i][1], len(sec["data"]))
                break

    return bytes(out)


def build_elf(
    *,
    bits: int = 64,
    machine: int = 62,
    little: bool = True,
    sections: list[dict] | None = None,
    dynamic: dict | None = None,
) -> bytes:
    """Assemble a minimal ELF with a section table and, optionally, a dynamic table."""
    is64 = bits == 64
    end = "<" if little else ">"
    if sections is None:
        sections = [
            {"name": ".text", "data": b"\x90" * 64, "type": 1, "flags": 6, "addr": 0x1000},
            {"name": ".rodata", "data": b"hello from elf\x00", "type": 1, "flags": 2, "addr": 0x2000},
        ]

    ehsize = 64 if is64 else 52
    shentsize = 64 if is64 else 40
    # Null section, the real sections, and the section-name string table.
    num = len(sections) + 2

    shstrtab = b"\x00" + b"".join(s["name"].encode() + b"\x00" for s in sections) + b".shstrtab\x00"
    shstr_index = {}
    off = 1
    for s in sections:
        shstr_index[s["name"]] = off
        off += len(s["name"]) + 1
    shstr_index[".shstrtab"] = off

    data_off = ehsize
    blobs = []
    for s in sections:
        blobs.append((s, data_off))
        data_off += len(s["data"])
    shstr_off = data_off
    data_off += len(shstrtab)
    shoff = (data_off + 7) & ~7

    out = bytearray(shoff + num * shentsize)
    out[0:4] = b"\x7fELF"
    out[4] = 2 if is64 else 1
    out[5] = 1 if little else 2
    out[6] = 1
    struct.pack_into(end + "HHIQQQIHHHHHH", out, 16, 2, machine, 1, 0x1000, 0, shoff, 0,
                     ehsize, 0, 0, shentsize, num, num - 1)

    for s, off_ in blobs:
        out[off_ : off_ + len(s["data"])] = s["data"]
    out[shstr_off : shstr_off + len(shstrtab)] = shstrtab

    # Section headers. Index 0 is the mandatory null section.
    def put_sh(idx: int, name_off: int, stype: int, flags: int, addr: int, offset: int, size: int,
               link: int = 0, info: int = 0, align: int = 1, entsize: int = 0) -> None:
        at = shoff + idx * shentsize
        if is64:
            struct.pack_into(end + "IIQQQQIIQQ", out, at, name_off, stype, flags, addr, offset, size, link, info, align, entsize)
        else:
            struct.pack_into(end + "IIIIIIIIII", out, at, name_off, stype, flags, addr, offset, size, link, info, align, entsize)

    put_sh(0, 0, 0, 0, 0, 0, 0)
    for i, (s, off_) in enumerate(blobs, start=1):
        put_sh(i, shstr_index[s["name"]], s.get("type", 1), s.get("flags", 2), s.get("addr", 0),
               off_, len(s["data"]), entsize=s.get("entsize", 0))
    put_sh(num - 1, shstr_index[".shstrtab"], 3, 0, 0, shstr_off, len(shstrtab), align=1)

    return bytes(out)


def build_shellcode() -> bytes:
    """A tiny x86-64 stub: write a message, then exit."""
    return bytes.fromhex(
        "48c7c001000000"      # mov rax, 1 (write)
        "48c7c701000000"      # mov rdi, 1 (stdout)
        "488d3511000000"      # lea rsi, [rip+0x11]
        "48c7c20d000000"      # mov rdx, 13
        "0f05"                # syscall
        "48c7c03c000000"      # mov rax, 60 (exit)
        "4831ff"              # xor rdi, rdi
        "0f05"                # syscall
        "68656c6c6f0a00"      # "hello\n"
    )


def build_xor_blob(plaintext: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in plaintext)


def build_packed_blob(payload: bytes) -> bytes:
    """A zlib-compressed blob, the usual shape of a hidden config."""
    import zlib

    return zlib.compress(payload)


def build_zip_with_file(name: str, content: bytes, compressed: bool = True) -> bytes:
    """A real ZIP containing one file, for the carving tests."""
    import io
    import zipfile

    buf = io.BytesIO()
    mode = zipfile.ZIP_DEFLATED if compressed else zipfile.ZIP_STORED
    with zipfile.ZipFile(buf, "w", mode) as zf:
        zf.writestr(name, content)
    return buf.getvalue()


def build_beacon(ip: str, port: int, payload: bytes) -> bytes:
    """A stub that opens a socket, connects and writes a payload to it.

    The displacements are computed rather than written out by hand. One that is
    off by a hex digit still assembles and still runs; it just points at the
    wrong address, which then reads as an emulator bug.
    """
    program = [
        ("hex", "48c7c029000000"),  # mov rax, 41 (socket)
        ("hex", "48c7c702000000"),  # mov rdi, 2 (AF_INET)
        ("hex", "48c7c601000000"),  # mov rsi, 1 (SOCK_STREAM)
        ("hex", "4831d2"),          # xor rdx, rdx
        ("hex", "0f05"),
        ("hex", "4989c4"),          # mov r12, rax, keep the fd
        ("hex", "4c89e7"),          # mov rdi, r12
        ("lea", "sockaddr"),        # lea rsi, [rip+...]
        ("hex", "48c7c210000000"),  # mov rdx, 16
        ("hex", "48c7c02a000000"),  # mov rax, 42 (connect)
        ("hex", "0f05"),
        ("hex", "4c89e7"),          # mov rdi, r12
        ("lea", "payload"),         # lea rsi, [rip+...]
        ("len", ""),                # mov rdx, len(payload)
        ("hex", "48c7c001000000"),  # mov rax, 1 (write)
        ("hex", "0f05"),
        ("hex", "48c7c03c000000"),  # mov rax, 60 (exit)
        ("hex", "4831ff"),          # xor rdi, rdi
        ("hex", "0f05"),
    ]

    at = 0x1000
    placed = []
    for kind, arg in program:
        size = 7 if kind in ("lea", "len") else len(bytes.fromhex(arg))
        placed.append((kind, arg, at))
        at += size

    sockaddr_at, payload_at = at, at + 16
    sockaddr = struct.pack("<H", 2) + struct.pack("!H", port) + socket.inet_aton(ip) + b"\x00" * 8

    out = bytearray()
    for kind, arg, here in placed:
        if kind == "hex":
            out += bytes.fromhex(arg)
        elif kind == "lea":
            target = sockaddr_at if arg == "sockaddr" else payload_at
            out += bytes.fromhex("488d35" + struct.pack("<i", target - (here + 7)).hex())
        else:
            out += bytes.fromhex("48c7c2" + struct.pack("<I", len(payload)).hex())
    return bytes(out) + sockaddr + payload
