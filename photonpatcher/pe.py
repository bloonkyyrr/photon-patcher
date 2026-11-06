"""Small PE/COFF reader and writer.

Only what the patcher needs: header parsing, RVA -> file offset mapping, the
CLI (managed) header and the ability to append a blob at the end of the image
while growing the section that covers it.  Everything is bounds checked and
raises :class:`PEError` instead of producing a corrupt file.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

DIR_CLI_HEADER = 14
CLI_SIGNATURE = 0x48


def align(value: int, alignment: int) -> int:
    if alignment <= 1:
        return value
    return ((value + alignment - 1) // alignment) * alignment


class PEError(Exception):
    """Raised for any file that is not a PE image we understand."""


@dataclass
class Section:
    index: int
    name: str
    header_offset: int
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_pointer: int
    characteristics: int

    @property
    def raw_end(self) -> int:
        return self.raw_pointer + self.raw_size

    @property
    def span(self) -> int:
        return max(self.virtual_size, self.raw_size)


class PEImage:
    """Read-only view over a PE image held in memory."""

    def __init__(self, data: bytes):
        self.data = data
        self._parse()

    # ---------------------------------------------------------------- helpers
    def u16(self, offset: int) -> int:
        return struct.unpack_from("<H", self.data, offset)[0]

    def u32(self, offset: int) -> int:
        return struct.unpack_from("<I", self.data, offset)[0]

    # ----------------------------------------------------------------- parsing
    def _parse(self) -> None:
        if len(self.data) < 0x40 or self.data[:2] != b"MZ":
            raise PEError("not a PE file (missing MZ header)")
        e_lfanew = self.u32(0x3C)
        if e_lfanew <= 0 or e_lfanew + 0x18 > len(self.data):
            raise PEError("not a PE file (bad e_lfanew)")
        if self.data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
            raise PEError("not a PE file (missing PE signature)")

        self.e_lfanew = e_lfanew
        coff = e_lfanew + 4
        self.coff_offset = coff
        self.machine = self.u16(coff)
        self.section_count = self.u16(coff + 2)
        self.timestamp = self.u32(coff + 4)
        self.size_of_optional_header = self.u16(coff + 16)
        self.characteristics = self.u16(coff + 18)
        self.optional_offset = coff + 20

        magic = self.u16(self.optional_offset)
        if magic == 0x10B:
            self.is_pe32_plus = False
        elif magic == 0x20B:
            self.is_pe32_plus = True
        else:
            raise PEError(f"unsupported optional header magic 0x{magic:04X}")

        self.size_of_image_offset = self.optional_offset + 56
        self.section_alignment = self.u32(self.optional_offset + 32) or 0x1000
        self.file_alignment = self.u32(self.optional_offset + 36) or 0x200
        self.size_of_headers = self.u32(self.optional_offset + 60)
        self.data_directory_offset = self.optional_offset + (112 if self.is_pe32_plus else 96)

        self.sections: list[Section] = []
        table = self.optional_offset + self.size_of_optional_header
        for index in range(self.section_count):
            header = table + index * 40
            if header + 40 > len(self.data):
                raise PEError("truncated section table")
            name = self.data[header : header + 8].split(b"\0", 1)[0].decode("latin-1")
            virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from(
                "<IIII", self.data, header + 8
            )
            self.sections.append(
                Section(
                    index=index,
                    name=name,
                    header_offset=header,
                    virtual_size=virtual_size,
                    virtual_address=virtual_address,
                    raw_size=raw_size,
                    raw_pointer=raw_pointer,
                    characteristics=self.u32(header + 36),
                )
            )

    # ------------------------------------------------------------------- query
    def data_directory(self, index: int) -> tuple[int, int]:
        offset = self.data_directory_offset + index * 8
        if offset + 8 > len(self.data):
            return (0, 0)
        return (self.u32(offset), self.u32(offset + 4))

    def section_for_rva(self, rva: int) -> Section | None:
        for section in self.sections:
            if section.virtual_address <= rva < section.virtual_address + max(section.span, 1):
                return section
        return None

    def rva_to_offset(self, rva: int) -> int:
        section = self.section_for_rva(rva)
        if section is None:
            if rva < self.size_of_headers:
                return rva
            raise PEError(f"RVA 0x{rva:X} is not mapped by any section")
        delta = rva - section.virtual_address
        if delta >= section.raw_size:
            raise PEError(f"RVA 0x{rva:X} points into virtual-only padding")
        offset = section.raw_pointer + delta
        if offset >= len(self.data):
            raise PEError(f"RVA 0x{rva:X} maps past the end of the file")
        return offset

    @property
    def cli_header(self) -> dict:
        rva, size = self.data_directory(DIR_CLI_HEADER)
        if not rva or not size:
            raise PEError("file has no CLI header (not a .NET assembly)")
        offset = self.rva_to_offset(rva)
        if offset + 16 > len(self.data):
            raise PEError("truncated CLI header")
        metadata_rva, metadata_size = struct.unpack_from("<II", self.data, offset + 8)
        if not metadata_rva or not metadata_size:
            raise PEError("CLI header has no metadata directory")
        return {
            "offset": offset,
            "rva": rva,
            "size": size,
            "metadata_rva": metadata_rva,
            "metadata_size": metadata_size,
            "metadata_offset": self.rva_to_offset(metadata_rva),
        }

    # ------------------------------------------------------------------ writer
    def add_section(self, blob: bytes, name: str = ".phop") -> tuple[bytes, int]:
        """Append ``blob`` in a brand new read-only data section.

        A dedicated section matters: the CLR refuses to take an assembly
        manifest from a discardable section such as ``.reloc``, so growing the
        trailing section in place is not safe for relocated metadata.

        Returns ``(new_file_bytes, rva_of_blob)``.
        """
        data = bytearray(self.data)
        table_start = self.optional_offset + self.size_of_optional_header
        table_end = table_start + self.section_count * 40
        first_raw = min(
            (section.raw_pointer for section in self.sections if section.raw_size),
            default=self.size_of_headers or 0x200,
        )
        limit = min(self.size_of_headers or 0x200, first_raw)
        if table_end + 40 > limit:
            raise PEError("the PE header has no room for another section header")

        raw_pointer = align(len(data), self.file_alignment or 0x200)
        data.extend(b"\0" * (raw_pointer - len(data)))
        data.extend(blob)
        raw_size = align(len(blob), self.file_alignment or 0x200)
        data.extend(b"\0" * (raw_size - len(blob)))

        virtual_address = align(
            max(
                (
                    section.virtual_address
                    + align(max(section.virtual_size, section.raw_size), self.section_alignment)
                    for section in self.sections
                ),
                default=self.section_alignment,
            ),
            self.section_alignment,
        )

        header = bytearray(40)
        encoded = name.encode("ascii", "replace")[:8]
        header[: len(encoded)] = encoded
        struct.pack_into("<IIII", header, 8, len(blob), virtual_address, raw_size, raw_pointer)
        struct.pack_into("<I", header, 36, 0x40000040)  # INITIALIZED_DATA | READ
        data[table_end : table_end + 40] = header
        struct.pack_into("<H", data, self.coff_offset + 2, self.section_count + 1)

        size_of_image = align(
            virtual_address + align(len(blob), self.section_alignment), self.section_alignment
        )
        struct.pack_into(
            "<I",
            data,
            self.size_of_image_offset,
            max(size_of_image, struct.unpack_from("<I", data, self.size_of_image_offset)[0]),
        )
        return bytes(data), virtual_address

    def extend_last_section(self, blob: bytes, strip_signature: bool = True) -> tuple[bytes, int]:
        """Grow the trailing section over ``blob`` appended at end of file.

        Used when the PE header has no room for another section header.  The
        strong-name certificate (which lives after the last section) has to be
        dropped first, otherwise the section would overlap it and the image
        becomes invalid.  Returns ``(new_file_bytes, rva_of_blob)``.
        """
        data = bytearray(self.data)
        if strip_signature:
            offset, size = self.data_directory(4)
            if size:
                if offset + size < len(data) - 7:
                    raise PEError("certificate table is not at the end of the image")
                struct.pack_into("<II", data, self.data_directory_offset + 32, 0, 0)
                del data[offset:]

        pad = align(len(data), 4) - len(data)
        data.extend(b"\0" * pad)
        start = len(data)
        data.extend(blob)

        section = max(self.sections, key=lambda s: s.raw_end)
        if start < section.raw_pointer:
            raise PEError("image has no trailing section to grow")
        raw_size = align(len(data) - section.raw_pointer, self.file_alignment or 0x200)
        data.extend(b"\0" * (section.raw_pointer + raw_size - len(data)))

        struct.pack_into("<I", data, section.header_offset + 16, raw_size)
        virtual = max(section.virtual_size, start + len(blob) - section.raw_pointer)
        struct.pack_into("<I", data, section.header_offset + 8, virtual)
        struct.pack_into(
            "<I",
            data,
            self.size_of_image_offset,
            align(section.virtual_address + virtual, self.section_alignment),
        )
        return bytes(data), section.virtual_address + (start - section.raw_pointer)
