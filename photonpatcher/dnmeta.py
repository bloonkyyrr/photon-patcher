"""ECMA-335 (CLI) metadata reader and rewriter.

This is the piece that makes the patcher work on Mono games beyond a dumb
byte-for-byte replacement:

* the ``#US`` (user string) heap is parsed entry by entry, so a literal can be
  replaced by a *shorter or longer* value,
* the ``#~`` table stream is parsed far enough to find every ``MethodDef`` RVA,
* a small IL walker finds every ``ldstr`` token, which lets us retarget a
  literal to a freshly appended string,
* the whole metadata blob can be rebuilt and relocated into the PE image when
  the ``#US`` heap has to grow.

Anything unexpected raises :class:`MetadataError`; the caller then degrades to a
length-preserving patch instead of risking a corrupt assembly.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .pe import PEImage, PEError, align


class MetadataError(Exception):
    """Raised when the metadata is not laid out the way we expect."""


# --------------------------------------------------------------------------- #
# compressed integers (ECMA-335 II.23.2)
# --------------------------------------------------------------------------- #
def read_compressed_uint(data, offset: int) -> tuple[int, int]:
    first = data[offset]
    if first & 0x80 == 0:
        return first, 1
    if first & 0xC0 == 0x80:
        return ((first & 0x3F) << 8) | data[offset + 1], 2
    if first & 0xE0 == 0xC0:
        value = (
            ((first & 0x1F) << 24)
            | (data[offset + 1] << 16)
            | (data[offset + 2] << 8)
            | data[offset + 3]
        )
        return value, 4
    raise MetadataError(f"invalid compressed integer 0x{first:02X}")


def write_compressed_uint(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    if value < 0x4000:
        return bytes([0x80 | (value >> 8), value & 0xFF])
    if value < 0x20000000:
        return bytes(
            [0xC0 | ((value >> 24) & 0x1F), (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF]
        )
    raise MetadataError("value too large for a compressed integer")


# --------------------------------------------------------------------------- #
# table stream
# --------------------------------------------------------------------------- #
TABLE_IDS = {
    "Module": 0x00,
    "TypeRef": 0x01,
    "TypeDef": 0x02,
    "FieldPtr": 0x03,
    "Field": 0x04,
    "MethodPtr": 0x05,
    "MethodDef": 0x06,
    "ParamPtr": 0x07,
    "Param": 0x08,
    "InterfaceImpl": 0x09,
    "MemberRef": 0x0A,
    "Constant": 0x0B,
    "CustomAttribute": 0x0C,
    "FieldMarshal": 0x0D,
    "DeclSecurity": 0x0E,
    "ClassLayout": 0x0F,
    "FieldLayout": 0x10,
    "StandAloneSig": 0x11,
    "EventMap": 0x12,
    "EventPtr": 0x13,
    "Event": 0x14,
    "PropertyMap": 0x15,
    "PropertyPtr": 0x16,
    "Property": 0x17,
    "MethodSemantics": 0x18,
    "MethodImpl": 0x19,
    "ModuleRef": 0x1A,
    "TypeSpec": 0x1B,
    "ImplMap": 0x1C,
    "FieldRVA": 0x1D,
    "EncLog": 0x1E,
    "EncMap": 0x1F,
    "Assembly": 0x20,
    "AssemblyProcessor": 0x21,
    "AssemblyOS": 0x22,
    "AssemblyRef": 0x23,
    "AssemblyRefProcessor": 0x24,
    "AssemblyRefOS": 0x25,
    "File": 0x26,
    "ExportedType": 0x27,
    "ManifestResource": 0x28,
    "NestedClass": 0x29,
    "GenericParam": 0x2A,
    "MethodSpec": 0x2B,
    "GenericParamConstraint": 0x2C,
}

# tables we need before MethodDef (0x06) to compute its row offset
TABLES = {
    0x00: [("Generation", "u2"), ("Name", "str"), ("Mvid", "guid"), ("EncId", "guid"), ("EncBaseId", "guid")],
    0x01: [("ResolutionScope", "ResolutionScope"), ("Name", "str"), ("Namespace", "str")],
    0x02: [
        ("Flags", "u4"),
        ("Name", "str"),
        ("Namespace", "str"),
        ("Extends", "TypeDefOrRef"),
        ("FieldList", "Field"),
        ("MethodList", "MethodDef"),
    ],
    0x03: [("Field", "Field")],
    0x04: [("Flags", "u2"), ("Name", "str"), ("Signature", "blob")],
    0x05: [("Method", "MethodDef")],
    0x06: [
        ("RVA", "u4"),
        ("ImplFlags", "u2"),
        ("Flags", "u2"),
        ("Name", "str"),
        ("Signature", "blob"),
        ("ParamList", "Param"),
    ],
}

CODED = {
    "TypeDefOrRef": (2, ["TypeDef", "TypeRef", "TypeSpec"]),
    "ResolutionScope": (2, ["Module", "ModuleRef", "AssemblyRef", "TypeRef"]),
}


class TablesStream:
    """The ``#~`` stream: row counts plus the MethodDef table."""

    def __init__(self, data: bytes, base: int, size: int):
        self.data = data
        self.base = base
        self.size = size
        if base + 24 > len(data):
            raise MetadataError("truncated table stream header")
        heap_sizes = data[base + 6]
        valid = struct.unpack_from("<Q", data, base + 8)[0]
        if struct.unpack_from("<I", data, base)[0] != 0:
            raise MetadataError("unexpected table stream reserved word")

        self.row_counts: dict[int, int] = {}
        cursor = base + 24
        for table_id in range(64):
            if (valid >> table_id) & 1:
                if cursor + 4 > len(data):
                    raise MetadataError("truncated row count array")
                self.row_counts[table_id] = struct.unpack_from("<I", data, cursor)[0]
                cursor += 4
        self.rows_start = cursor
        self.str_size = 4 if heap_sizes & 0x01 else 2
        self.guid_size = 4 if heap_sizes & 0x02 else 2
        self.blob_size = 4 if heap_sizes & 0x04 else 2

        if 0x06 not in self.row_counts:
            raise MetadataError("assembly has no MethodDef table")

        self._row_sizes: dict[int, int] = {}
        offset = self.rows_start
        for table_id in sorted(self.row_counts):
            if table_id >= 0x06:
                break
            if table_id not in TABLES:
                raise MetadataError(f"no schema for metadata table 0x{table_id:02X}")
            offset += self.row_size(table_id) * self.row_counts[table_id]
        self.methoddef_offset = offset
        self.methoddef_size = self.row_size(0x06)
        total = offset + self.methoddef_size * self.row_counts[0x06]
        if total > len(data):
            raise MetadataError("MethodDef table runs past the end of the file")

    # ------------------------------------------------------------------ sizes
    def _column_size(self, spec: str) -> int:
        if spec == "u1":
            return 1
        if spec == "u2":
            return 2
        if spec == "u4":
            return 4
        if spec == "str":
            return self.str_size
        if spec == "guid":
            return self.guid_size
        if spec == "blob":
            return self.blob_size
        if spec in CODED:
            bits, targets = CODED[spec]
            biggest = 0
            for name in targets:
                biggest = max(biggest, self.row_counts.get(TABLE_IDS[name], 0))
            return 2 if biggest < (1 << (16 - bits)) else 4
        if spec in TABLE_IDS:
            return 2 if self.row_counts.get(TABLE_IDS[spec], 0) <= 0xFFFF else 4
        raise MetadataError(f"unknown column type {spec!r}")

    def row_size(self, table_id: int) -> int:
        if table_id not in self._row_sizes:
            if table_id not in TABLES:
                raise MetadataError(f"no schema for metadata table 0x{table_id:02X}")
            self._row_sizes[table_id] = sum(self._column_size(spec) for _, spec in TABLES[table_id])
        return self._row_sizes[table_id]

    # -------------------------------------------------------------- row access
    def method_rvas(self) -> list[int]:
        count = self.row_counts[0x06]
        size = self.methoddef_size
        return [
            struct.unpack_from("<I", self.data, self.methoddef_offset + i * size)[0]
            for i in range(count)
        ]


# --------------------------------------------------------------------------- #
# IL walking
# --------------------------------------------------------------------------- #
_SWITCH = 0xFF
_UNKNOWN = 0xFE

_OP_SIZE = bytearray(256)
_INVALID = set()


def _init_opcodes() -> None:
    # one byte operand (int8 / short branch)
    for op in range(0x0E, 0x14):
        _OP_SIZE[op] = 1
    _OP_SIZE[0x1F] = 1
    for op in range(0x2B, 0x38):
        _OP_SIZE[op] = 1
    _OP_SIZE[0xDE] = 1
    # four byte operand (int32 / token / branch)
    for op in (0x20, 0x22, 0x27, 0x28, 0x29, 0x6F, 0x79, 0x8C, 0x8D, 0x8F,
               0xA3, 0xA4, 0xA5, 0xC2, 0xC6, 0xD0, 0xDD):
        _OP_SIZE[op] = 4
    for op in range(0x38, 0x45):
        _OP_SIZE[op] = 4
    for op in range(0x70, 0x76):
        _OP_SIZE[op] = 4
    for op in range(0x7B, 0x82):
        _OP_SIZE[op] = 4
    # eight byte operand
    _OP_SIZE[0x21] = 8
    _OP_SIZE[0x23] = 8
    # switch
    _OP_SIZE[0x45] = _SWITCH
    # unused single byte opcodes: stop walking that method
    for op in (0x24, 0x77, 0x78):
        _INVALID.add(op)
    for op in list(range(0xA6, 0xB3)) + list(range(0xBB, 0xC2)) + [0xC4, 0xC5]:
        _INVALID.add(op)
    for op in list(range(0xC7, 0xD0)) + list(range(0xE1, 0x100)):
        _INVALID.add(op)


_init_opcodes()

_FE_OP_SIZE = {
    0x00: 0, 0x01: 0, 0x02: 0, 0x03: 0, 0x04: 0, 0x05: 0,
    0x06: 4, 0x07: 4, 0x09: 2, 0x0A: 2, 0x0B: 2, 0x0C: 2,
    0x0D: 2, 0x0E: 2, 0x0F: 0, 0x11: 0, 0x12: 1, 0x13: 0,
    0x14: 0, 0x15: 4, 0x16: 4, 0x17: 0, 0x18: 0, 0x19: 1,
    0x1A: 0, 0x1C: 4, 0x1D: 0, 0x1E: 0,
}


@dataclass
class LdstrSite:
    heap_offset: int
    token_offset: int  # absolute file offset of the 4-byte token operand


def _walk_il(data: bytes, code: int, code_size: int, out: list[LdstrSite]) -> bool:
    """Scan one method body.  Returns False if the body was not understood."""
    cursor = 0
    while cursor < code_size:
        op = data[code + cursor]
        if op == 0xFE:
            if cursor + 1 >= code_size:
                return True
            sub = data[code + cursor + 1]
            size = _FE_OP_SIZE.get(sub)
            if size is None:
                return False
            cursor += 2 + size
            continue
        if op in _INVALID:
            return False
        size = _OP_SIZE[op]
        operand = code + cursor + 1
        if op == 0x72:  # ldstr
            if operand + 4 > code_size + code:
                return False
            token = struct.unpack_from("<I", data, operand)[0]
            if token >> 24 == 0x70:
                out.append(LdstrSite(heap_offset=token & 0x00FFFFFF, token_offset=operand))
            size = 4
        elif size == _SWITCH:
            if operand + 4 > code + code_size:
                return False
            count = struct.unpack_from("<I", data, operand)[0]
            if count > (code_size - cursor) // 4:
                return False
            size = 4 + 4 * count
        elif size == _UNKNOWN:
            return False
        cursor += 1 + size
    return True


def find_ldstr_sites(data: bytes, pe: PEImage, tables: TablesStream) -> tuple[dict[int, list[LdstrSite]], int]:
    """Map ``#US`` heap offset -> every ``ldstr`` instruction using it."""
    sites: dict[int, list[LdstrSite]] = {}
    failed = 0
    for rva in tables.method_rvas():
        if rva == 0:
            continue
        try:
            body = pe.rva_to_offset(rva)
        except PEError:
            failed += 1
            continue
        if body >= len(data):
            failed += 1
            continue
        header = data[body]
        if header & 0x03 == 0x02:  # tiny
            code_size = header >> 2
            code = body + 1
        elif header & 0x03 == 0x03:  # fat
            if body + 12 > len(data):
                failed += 1
                continue
            flags_size = struct.unpack_from("<H", data, body)[0]
            header_size = (flags_size >> 12) * 4
            if header_size < 12:
                failed += 1
                continue
            code_size = struct.unpack_from("<I", data, body + 4)[0]
            code = body + header_size
        else:
            failed += 1
            continue
        if code + code_size > len(data):
            failed += 1
            continue
        found: list[LdstrSite] = []
        if not _walk_il(data, code, code_size, found):
            failed += 1
            continue
        for site in found:
            sites.setdefault(site.heap_offset, []).append(site)
    return sites, failed


# --------------------------------------------------------------------------- #
# user strings
# --------------------------------------------------------------------------- #
@dataclass
class UserString:
    heap_offset: int  # offset inside #US, points at the length prefix
    data_offset: int  # absolute file offset of the UTF-16 payload
    prefix_len: int
    byte_len: int  # payload bytes (without the terminal flag byte)
    capacity: int  # prefix + payload + terminal byte
    value: str = ""
    index: int = 0
    extra: dict = field(default_factory=dict)

    @property
    def entry_bytes(self) -> bytes:
        return write_compressed_uint(self.byte_len + 1) + self.value.encode("utf-16-le") + b"\0"

    @property
    def reserved(self) -> int:
        """Bytes reserved for this entry inside the heap (prefix + payload + 1)."""
        return self.byte_len + 1


class Metadata:
    """A parsed metadata blob living inside a PE image."""

    def __init__(self, data: bytes):
        self.data = data
        self.root_offset, self.root_size = self._locate()
        self._parse_root()

    # ------------------------------------------------------------------ setup
    def _locate(self) -> tuple[int, int]:
        pe = PEImage(self.data)
        info = pe.cli_header
        offset, size = info["metadata_offset"], info["metadata_size"]
        if offset + size > len(self.data):
            raise MetadataError("metadata directory runs past the end of the file")
        return offset, size

    def _parse_root(self) -> None:
        data = self.data
        base = self.root_offset
        if data[base : base + 4] != b"BSJB":
            raise MetadataError("bad metadata signature")
        self.major, self.minor = struct.unpack_from("<HH", data, base + 4)
        version_len = struct.unpack_from("<I", data, base + 12)[0]
        if version_len < 4 or version_len > 512:
            raise MetadataError("implausible metadata version length")
        self.version_len = version_len
        self.version_bytes = data[base + 16 : base + 16 + version_len]
        self.flags, self.stream_count = struct.unpack_from("<HH", data, base + 16 + version_len)
        cursor = base + 20 + version_len
        self.streams: dict[str, tuple[int, int]] = {}
        for _ in range(self.stream_count):
            if cursor + 8 > len(data):
                raise MetadataError("truncated stream header")
            offset, size = struct.unpack_from("<II", data, cursor)
            cursor += 8
            end = data.find(b"\0", cursor, cursor + 64)
            if end < 0:
                raise MetadataError("unterminated stream name")
            name = data[cursor:end].decode("latin-1")
            cursor = base + align(end + 1 - base, 4)
            self.streams[name] = (base + offset, size)
        for name, (offset, size) in self.streams.items():
            if offset + size > len(data):
                raise MetadataError(f"stream {name} runs past the end of the file")

    # ------------------------------------------------------------------ access
    def stream(self, name: str) -> bytes | None:
        entry = self.streams.get(name)
        if entry is None:
            return None
        offset, size = entry
        return self.data[offset : offset + size]

    @property
    def us_info(self) -> tuple[int, int]:
        entry = self.streams.get("#US")
        if entry is None:
            raise MetadataError("assembly has no #US heap")
        return entry

    def user_strings(self) -> list[UserString]:
        base, size = self.us_info
        data = self.data
        entries: list[UserString] = []
        cursor = 0
        while cursor < size:
            first = data[base + cursor]
            if first == 0:  # padding / empty string marker
                cursor += 1
                continue
            try:
                byte_len, prefix = read_compressed_uint(data, base + cursor)
            except MetadataError:
                break
            if byte_len < 1 or cursor + prefix + byte_len > size:
                break
            payload = base + cursor + prefix
            raw = data[payload : payload + byte_len - 1]
            if len(raw) % 2:
                raw = raw[:-1]
            entries.append(
                UserString(
                    heap_offset=cursor,
                    data_offset=payload,
                    prefix_len=prefix,
                    byte_len=len(raw),
                    capacity=prefix + byte_len,
                    value=raw.decode("utf-16-le", errors="replace"),
                    index=len(entries),
                )
            )
            cursor += prefix + byte_len
        return entries

    def strings_heap_peek(self, limit: int = 40000) -> str:
        """Decoded #Strings heap, used only for Photon evidence detection."""
        blob = self.stream("#Strings") or b""
        return blob[:limit].decode("latin-1")

    def tables(self) -> TablesStream:
        for name in ("#~", "#-"):
            entry = self.streams.get(name)
            if entry is not None:
                return TablesStream(self.data, entry[0], entry[1])
        raise MetadataError("assembly has no #~ table stream")

    # ----------------------------------------------------------------- rebuild
    def rebuild(self, replacements: dict[str, bytes]) -> bytes:
        """Return a complete metadata blob with some streams replaced.

        Stream order and every byte of untouched streams are preserved, so all
        existing heap offsets and table row indexes stay valid.
        """
        names = list(self.streams)
        header = bytearray()
        header += b"BSJB"
        header += struct.pack("<HHII", self.major, self.minor, 0, self.version_len)
        header += self.version_bytes
        header += struct.pack("<HH", self.flags, len(names))

        table_size = sum(8 + align(len(name.encode("latin-1")) + 1, 4) for name in names)
        position = len(header) + table_size
        bodies = bytearray()
        placements: list[tuple[str, int, int]] = []
        for name in names:
            payload = replacements.get(name)
            if payload is None:
                offset, size = self.streams[name]
                payload = self.data[offset : offset + size]
            placements.append((name, position, len(payload)))
            bodies += payload
            padding = align(len(payload), 4) - len(payload)
            bodies += b"\0" * padding
            position += len(payload) + padding

        for name, offset, size in placements:
            header += struct.pack("<II", offset, size)
            encoded = name.encode("latin-1") + b"\0"
            header += encoded
            header += b"\0" * (align(len(encoded), 4) - len(encoded))
        return bytes(header + bodies)


# --------------------------------------------------------------------------- #
# convenience: apply a new value to one user string in memory
# --------------------------------------------------------------------------- #
def encode_user_string(value: str) -> bytes:
    payload = value.encode("utf-16-le")
    return write_compressed_uint(len(payload) + 1) + payload + b"\0"


def patch_user_string_in_place(data: bytearray, entry: UserString, new_value: str) -> int:
    """Overwrite a ``#US`` entry without moving anything.

    Shorter values leave unreferenced padding behind (harmless: the heap is
    indexed, never scanned sequentially by the runtime).  Returns the new
    absolute payload offset.
    """
    encoded = encode_user_string(new_value)
    if len(encoded) > entry.capacity:
        raise MetadataError(
            f"new value needs {len(encoded)} bytes but only {entry.capacity} are reserved"
        )
    entry_offset = entry.data_offset - entry.prefix_len
    data[entry_offset : entry_offset + entry.capacity] = encoded + b"\0" * (entry.capacity - len(encoded))
    return entry_offset + len(encoded) - 1 - len(new_value.encode("utf-16-le"))
