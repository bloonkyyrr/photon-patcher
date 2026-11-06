"""IL2CPP ``global-metadata.dat`` string literal engine.

IL2CPP keeps every managed string literal in one blob with an index table of
``(length, dataIndex)`` pairs, so literals can be replaced at *any* length:

* if the rebuilt blob fits inside the original allocation it is written in
  place and the leftover tail is zeroed,
* otherwise the new blob is appended to the file and the header is repointed
  (nothing else in the file moves, so all other offsets stay valid).

The header layout used here (sanity, version, stringLiteral*, stringLiteralData*)
has been stable from metadata version 24 through 31.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

IL2CPP_SANITY = 0xFAB11BAF

VERSION_NAMES = {
    24: "Unity 2018.3 - 2019.2 (v24)",
    24.1: "Unity 2019.3 (v24.1)",
    24.2: "Unity 2019.4 (v24.2)",
    24.3: "Unity 2020.1 (v24.3)",
    24.4: "Unity 2020.2 (v24.4)",
    24.5: "Unity 2021.1 (v24.5)",
    27: "Unity 2021.2 - 2022 (v27)",
    27.1: "Unity 2022.1 (v27.1)",
    27.2: "Unity 2022.3 (v27.2)",
    29: "Unity 2023.1 (v29)",
    29.1: "Unity 2023.2 (v29.1)",
    31: "Unity 6000 / 2023.3 (v31)",
}


class Il2CppError(Exception):
    """Raised when global-metadata.dat cannot be understood safely."""


@dataclass
class Literal:
    index: int
    length: int
    data_index: int
    offset: int  # absolute file offset of the UTF-8 bytes
    value: str


def version_label(raw: int) -> str:
    """Decode the packed 64-bit-ish version stored as two 32-bit halves."""
    major = (raw >> 32) & 0xFFFF if raw > 0xFFFF else raw
    minor = raw & 0xFF if raw > 0xFFFF else 0
    label = VERSION_NAMES.get(major)
    if label:
        return label
    return f"metadata v{major}" + (f".{minor}" if minor else "")


class GlobalMetadata:
    def __init__(self, data: bytes):
        self.data = data
        if len(data) < 32:
            raise Il2CppError("file is too small to be global-metadata.dat")
        sanity = struct.unpack_from("<I", data, 0)[0]
        if sanity != IL2CPP_SANITY:
            raise Il2CppError("bad magic (not an IL2CPP global-metadata.dat)")
        self.raw_version = struct.unpack_from("<I", data, 4)[0]
        (
            self.literal_table_offset,
            self.literal_table_size,
            self.literal_data_offset,
            self.literal_data_size,
        ) = struct.unpack_from("<IIII", data, 8)

        if self.literal_table_offset + self.literal_table_size > len(data):
            raise Il2CppError("literal table runs past the end of the file")
        if self.literal_data_offset > len(data):
            raise Il2CppError("literal data starts past the end of the file")

        self.literal_count = self.literal_table_size // 8
        self.literals: list[Literal] = []
        data_end = min(len(data), self.literal_data_offset + self.literal_data_size)
        for index in range(self.literal_count):
            length, data_index = struct.unpack_from(
                "<iI", data, self.literal_table_offset + index * 8
            )
            if length < 0:
                continue
            offset = self.literal_data_offset + data_index
            if offset + length > data_end:
                continue
            raw = data[offset : offset + length]
            try:
                value = raw.decode("utf-8")
            except UnicodeDecodeError:
                value = raw.decode("latin-1")
            self.literals.append(Literal(index, length, data_index, offset, value))

    # ------------------------------------------------------------------ helpers
    @property
    def version(self) -> str:
        return version_label(self.raw_version)

    def literal_at(self, index: int) -> Literal | None:
        for literal in self.literals:
            if literal.index == index:
                return literal
        return None

    # ------------------------------------------------------------------ rebuild
    def build(self, replacements: dict[int, str]) -> tuple[bytes, dict[int, int]]:
        """Build a fresh literal blob.  Returns ``(blob, {index: data_index})``."""
        blob = bytearray()
        placements: dict[int, int] = {}
        by_index = {literal.index: literal for literal in self.literals}
        for index in range(self.literal_count):
            literal = by_index.get(index)
            if literal is None:
                placements[index] = 0
                continue
            new_value = replacements.get(index)
            if new_value is None:
                payload = self.data[literal.offset : literal.offset + literal.length]
            else:
                payload = new_value.encode("utf-8")
            placements[index] = len(blob)
            blob += payload
        return bytes(blob), placements

    def apply(self, replacements: dict[int, str]) -> bytes:
        """Return the patched file bytes (does not write to disk)."""
        if not replacements:
            return self.data
        blob, placements = self.build(replacements)
        data = bytearray(self.data)

        for index, data_index in placements.items():
            literal = self.literal_at(index)
            if literal is None:
                continue
            if index in replacements:
                length = len(replacements[index].encode("utf-8"))
            else:
                length = literal.length
            struct.pack_into("<iI", data, self.literal_table_offset + index * 8, length, data_index)

        if len(blob) <= self.literal_data_size:
            start = self.literal_data_offset
            data[start : start + len(blob)] = blob
            tail = start + len(blob)
            end = min(len(data), start + self.literal_data_size)
            data[tail:end] = b"\0" * (end - tail)
            struct.pack_into("<I", data, 20, len(blob))
            return bytes(data)

        # Not enough room: append the rebuilt blob and repoint the header.
        pad = (-len(data)) % 8
        data += b"\0" * pad
        start = len(data)
        data += blob
        struct.pack_into("<I", data, 16, start)
        struct.pack_into("<I", data, 20, len(blob))
        return bytes(data)
