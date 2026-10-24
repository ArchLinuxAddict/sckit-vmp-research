#!/usr/bin/env python3
"""Evidence-based parser for the SckitVMP container used by VMPPBridge.

Only structures established from the native parser and cross-checked against all
records in the shipped asset are interpreted.  The XOR mask and method-header
layout are documented with native evidence in reports/phase11/.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional, Sequence
import hashlib
import struct

MAGIC = b"SckitVMP"
SECTION_COUNT = 6
HEADER_AFTER_PAIRS = 64
STRING_XOR_MASK = 0xA3


class VmpFormatError(ValueError):
    """Raised when a SckitVMP container is structurally invalid."""


def _need(data: bytes, off: int, size: int, what: str) -> None:
    if off < 0 or size < 0 or off + size > len(data):
        raise VmpFormatError(
            f"{what}: need {size} bytes at 0x{off:x}, file has 0x{len(data):x}"
        )


def read_u32(data: bytes, off: int, what: str = "u32") -> int:
    _need(data, off, 4, what)
    return struct.unpack_from("<I", data, off)[0]


def read_uleb128(data: bytes, off: int, what: str = "uleb128") -> tuple[int, int]:
    value = 0
    shift = 0
    start = off
    while True:
        if off >= len(data):
            raise VmpFormatError(f"{what}: truncated at 0x{off:x}")
        byte = data[off]
        off += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, off
        shift += 7
        if shift > 35:
            raise VmpFormatError(f"{what}: overlong value at 0x{start:x}")


def decode_modified_utf8(data: bytes) -> str:
    """Decode Java modified UTF-8 (CESU-8 surrogates, C0 80 for NUL).

    Standard 4-byte UTF-8 is accepted as a compatibility extension, but the
    native table is expected to use modified UTF-8.  Invalid sequences raise
    VmpFormatError rather than being silently replaced.
    """
    out: list[str] = []
    i = 0
    n = len(data)
    while i < n:
        b0 = data[i]
        if b0 <= 0x7F:
            out.append(chr(b0))
            i += 1
            continue
        if 0xC0 <= b0 <= 0xDF:
            if i + 1 >= n:
                raise VmpFormatError(f"mutf8 truncated 2-byte sequence at 0x{i:x}")
            b1 = data[i + 1]
            if b1 & 0xC0 != 0x80:
                raise VmpFormatError(f"mutf8 bad continuation at 0x{i + 1:x}")
            cp = ((b0 & 0x1F) << 6) | (b1 & 0x3F)
            if cp == 0:
                if (b0, b1) != (0xC0, 0x80):
                    raise VmpFormatError(f"mutf8 illegal zero at 0x{i:x}")
            elif cp < 0x80:
                raise VmpFormatError(f"mutf8 overlong 2-byte at 0x{i:x}")
            out.append(chr(cp))
            i += 2
            continue
        if 0xE0 <= b0 <= 0xEF:
            if i + 2 >= n:
                raise VmpFormatError(f"mutf8 truncated 3-byte sequence at 0x{i:x}")
            b1, b2 = data[i + 1], data[i + 2]
            if b1 & 0xC0 != 0x80 or b2 & 0xC0 != 0x80:
                raise VmpFormatError(f"mutf8 bad continuation at 0x{i:x}")
            cp = ((b0 & 0x0F) << 12) | ((b1 & 0x3F) << 6) | (b2 & 0x3F)
            if cp < 0x800:
                raise VmpFormatError(f"mutf8 overlong 3-byte at 0x{i:x}")
            # CESU-8 surrogate pair: combine two consecutive 3-byte units.
            if 0xD800 <= cp <= 0xDBFF and i + 5 < n and data[i + 3] == 0xED:
                c1 = data[i + 4]
                c2 = data[i + 5]
                if c1 & 0xC0 == 0x80 and c2 & 0xC0 == 0x80:
                    low = ((data[i + 3] & 0x0F) << 12) | ((c1 & 0x3F) << 6) | (c2 & 0x3F)
                    if 0xDC00 <= low <= 0xDFFF:
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00)
                        out.append(chr(cp))
                        i += 6
                        continue
            out.append(chr(cp))
            i += 3
            continue
        if 0xF0 <= b0 <= 0xF7:
            if i + 3 >= n:
                raise VmpFormatError(f"mutf8 truncated 4-byte sequence at 0x{i:x}")
            b1, b2, b3 = data[i + 1], data[i + 2], data[i + 3]
            if b1 & 0xC0 != 0x80 or b2 & 0xC0 != 0x80 or b3 & 0xC0 != 0x80:
                raise VmpFormatError(f"mutf8 bad 4-byte continuation at 0x{i:x}")
            cp = (
                ((b0 & 0x07) << 18)
                | ((b1 & 0x3F) << 12)
                | ((b2 & 0x3F) << 6)
                | (b3 & 0x3F)
            )
            if cp < 0x10000:
                raise VmpFormatError(f"mutf8 overlong 4-byte at 0x{i:x}")
            out.append(chr(cp))
            i += 4
            continue
        raise VmpFormatError(f"mutf8 invalid start byte 0x{b0:02x} at 0x{i:x}")
    return "".join(out)


def utf16_unit_count(text: str) -> int:
    units = 0
    for ch in text:
        cp = ord(ch)
        units += 2 if cp > 0xFFFF else 1
    return units


def decode_string_bytes(raw: bytes) -> bytes:
    return bytes(byte ^ (index & STRING_XOR_MASK) for index, byte in enumerate(raw))


@dataclass(frozen=True)
class StringRecord:
    index: int
    raw_offset: int
    decoded_length_hint: int
    encoded_length: int
    raw: bytes
    xor_bytes: bytes
    text: Optional[str]
    decode_status: str
    length_matches: bool


@dataclass(frozen=True)
class CodeHeader:
    method_id: int
    word1: int
    word2: int
    word3: int
    flag: int
    word1_value: int
    registers: int
    ins: int
    insn_count: int
    next_code_offset: Optional[int]
    span_to_next: Optional[int]


@dataclass(frozen=True)
class MethodRecord:
    method_id: int
    class_index: int
    name_index: int
    exception_index: int  # 0xffffffff == none
    aux: int
    code_offset: int
    class_name: Optional[str]
    method_name: Optional[str]
    code_header: Optional[CodeHeader]
    exception_type_count: Optional[int]


@dataclass(frozen=True)
class Section:
    index: int
    offset: int
    count: int
    end: int
    kind: str


@dataclass
class VmpFile:
    path: Path
    data: bytes
    sha256: str
    sections: list[Section]
    reserved: tuple[int, int]
    strings: list[StringRecord]
    string_ids: list[int]
    exception_vectors: list[tuple[int, ...]]
    reference_records: list[tuple[int, int, int]]
    methods: list[MethodRecord]
    byte_blob: bytes
    code_start: int = HEADER_AFTER_PAIRS
    code_end: int = 0

    @property
    def method_count(self) -> int:
        return len(self.methods)

    @property
    def string_count(self) -> int:
        return len(self.strings)

    def method(self, invoke_id: int) -> MethodRecord:
        if not 0 <= invoke_id < len(self.methods):
            raise VmpFormatError(f"Method index out of bounds: {invoke_id}")
        return self.methods[invoke_id]

    def decrypt_string(self, string_id: int) -> str:
        if not 0 <= string_id < len(self.strings):
            raise VmpFormatError(f"String index out of bounds: {string_id}")
        rec = self.strings[string_id]
        if rec.text is None:
            raise VmpFormatError(f"String {string_id} is not valid modified UTF-8")
        return rec.text


def _parse_strings(data: bytes, section: Section, next_offset: int) -> list[StringRecord]:
    records: list[StringRecord] = []
    pos = section.offset
    for index in range(section.count):
        start = pos
        hint, pos = read_uleb128(data, pos, f"string[{index}] decoded length")
        enc_len, pos = read_uleb128(data, pos, f"string[{index}] encoded length")
        _need(data, pos, enc_len, f"string[{index}] bytes")
        raw = data[pos : pos + enc_len]
        pos += enc_len
        xored = decode_string_bytes(raw)
        text: Optional[str] = None
        status = "decoded"
        try:
            text = decode_modified_utf8(xored)
        except VmpFormatError as exc:
            status = f"invalid_mutf8: {exc}"
        units = utf16_unit_count(text) if text is not None else None
        records.append(
            StringRecord(
                index=index,
                raw_offset=start,
                decoded_length_hint=hint,
                encoded_length=enc_len,
                raw=raw,
                xor_bytes=xored,
                text=text,
                decode_status=status,
                length_matches=(units == hint) if units is not None else False,
            )
        )
    if pos != next_offset:
        raise VmpFormatError(
            f"string section ends at 0x{pos:x}, next section starts at 0x{next_offset:x}"
        )
    return records


def _parse_u32_array(data: bytes, section: Section, next_offset: int) -> list[int]:
    end = section.offset + section.count * 4
    if end != next_offset:
        raise VmpFormatError(
            f"section {section.index} size {section.count}*4 ends at 0x{end:x}, "
            f"next section starts at 0x{next_offset:x}"
        )
    _need(data, section.offset, section.count * 4, f"section {section.index}")
    return list(struct.unpack_from(f"<{section.count}I", data, section.offset))


def _parse_vectors(data: bytes, section: Section, next_offset: int) -> list[tuple[int, ...]]:
    vectors: list[tuple[int, ...]] = []
    pos = section.offset
    for index in range(section.count):
        count = read_u32(data, pos, f"section2 vector[{index}] count")
        pos += 4
        byte_count = count * 4
        _need(data, pos, byte_count, f"section2 vector[{index}]")
        vectors.append(struct.unpack_from(f"<{count}I", data, pos) if count else ())
        pos += byte_count
    if pos != next_offset:
        raise VmpFormatError(
            f"section2 ends at 0x{pos:x}, next section starts at 0x{next_offset:x}"
        )
    return vectors


def _parse_reference_records(data: bytes, section: Section, next_offset: int) -> list[tuple[int, int, int]]:
    expected_end = section.offset + section.count * 12
    if expected_end != next_offset:
        raise VmpFormatError(
            f"section3 size {section.count}*12 ends at 0x{expected_end:x}, "
            f"next section starts at 0x{next_offset:x}"
        )
    _need(data, section.offset, section.count * 12, "section3")
    return [
        struct.unpack_from("<3I", data, section.offset + i * 12)
        for i in range(section.count)
    ]


def _parse_method_records(
    data: bytes,
    section: Section,
    next_offset: int,
    strings: Sequence[StringRecord],
    class_ids: Sequence[int],
    exception_vectors: Sequence[tuple[int, ...]],
) -> list[MethodRecord]:
    expected_end = section.offset + section.count * 20
    if expected_end != next_offset:
        raise VmpFormatError(
            f"section4 size {section.count}*20 ends at 0x{expected_end:x}, "
            f"next section starts at 0x{next_offset:x}"
        )
    _need(data, section.offset, section.count * 20, "section4")
    raw_records = [
        struct.unpack_from("<5I", data, section.offset + i * 20)
        for i in range(section.count)
    ]
    code_offsets = sorted({rec[4] for rec in raw_records if rec[4]})
    next_code = {
        off: (code_offsets[i + 1] if i + 1 < len(code_offsets) else None)
        for i, off in enumerate(code_offsets)
    }
    methods: list[MethodRecord] = []
    for method_id, (class_index, name_index, exc_index, aux, code_offset) in enumerate(raw_records):
        if class_index >= len(class_ids):
            raise VmpFormatError(f"method {method_id}: class index {class_index} out of range")
        class_string_id = class_ids[class_index]
        if class_string_id >= len(strings):
            raise VmpFormatError(
                f"method {method_id}: class string index {class_string_id} out of range"
            )
        if name_index >= len(strings):
            raise VmpFormatError(f"method {method_id}: name index {name_index} out of range")
        class_name = strings[class_string_id].text
        method_name = strings[name_index].text
        exc_count: Optional[int] = None
        if exc_index != 0xFFFFFFFF:
            if exc_index >= len(exception_vectors):
                raise VmpFormatError(
                    f"method {method_id}: exception index {exc_index} out of range"
                )
            exc_count = len(exception_vectors[exc_index])
        header: Optional[CodeHeader] = None
        if code_offset:
            if code_offset < HEADER_AFTER_PAIRS or code_offset + 16 > section.offset:
                raise VmpFormatError(
                    f"method {method_id}: code offset 0x{code_offset:x} out of range "
                    f"or header overlaps section0"
                )
            method_id_on_disk = read_u32(data, code_offset, f"method {method_id} code id")
            if method_id_on_disk != method_id:
                raise VmpFormatError(
                    f"method {method_id}: code record id {method_id_on_disk} does not match"
                )
            w1, w2, w3 = struct.unpack_from("<3I", data, code_offset + 4)
            w2_value = w2 >> 8
            header = CodeHeader(
                method_id=method_id_on_disk,
                word1=w1,
                word2=w2,
                word3=w3,
                flag=w1 & 0xFF,
                word1_value=w1 >> 8,
                registers=w2_value >> 16,
                ins=w2_value & 0xFFFF,
                insn_count=w3 >> 8,
                next_code_offset=next_code.get(code_offset),
                span_to_next=(
                    next_code[code_offset] - code_offset
                    if next_code.get(code_offset) is not None
                    else None
                ),
            )
        methods.append(
            MethodRecord(
                method_id=method_id,
                class_index=class_index,
                name_index=name_index,
                exception_index=exc_index,
                aux=aux,
                code_offset=code_offset,
                class_name=class_name,
                method_name=method_name,
                code_header=header,
                exception_type_count=exc_count,
            )
        )
    return methods


def parse_bytes(data: bytes, path: Path | str = "<bytes>") -> VmpFile:
    if len(data) < HEADER_AFTER_PAIRS:
        raise VmpFormatError(f"file too small: {len(data)}")
    if data[:8] != MAGIC:
        raise VmpFormatError(f"bad magic: {data[:8]!r}")
    pairs = [struct.unpack_from("<II", data, 8 + i * 8) for i in range(SECTION_COUNT)]
    reserved = struct.unpack_from("<II", data, 56)
    offsets = [p[0] for p in pairs]
    counts = [p[1] for p in pairs]
    if any(o < HEADER_AFTER_PAIRS for o in offsets):
        raise VmpFormatError(f"section offset before code start: {offsets}")
    if any(b <= a for a, b in zip(offsets, offsets[1:])):
        raise VmpFormatError(f"section offsets not strictly increasing: {offsets}")
    end_of_last = offsets[-1] + counts[-1]
    if end_of_last > len(data):
        raise VmpFormatError(
            f"last section ends at 0x{end_of_last:x}, file has 0x{len(data):x}"
        )
    # The final section is a byte blob: its count is its byte length.
    if end_of_last != len(data):
        raise VmpFormatError(
            f"last section ends at 0x{end_of_last:x}, trailing bytes to 0x{len(data):x}"
        )
    kinds = ["strings", "u32-array", "exception-vectors", "reference-records", "method-records", "byte-blob"]
    sections = [
        Section(i, offsets[i], counts[i], offsets[i + 1] if i + 1 < SECTION_COUNT else len(data), kinds[i])
        for i in range(SECTION_COUNT)
    ]
    strings = _parse_strings(data, sections[0], sections[1].offset)
    class_ids = _parse_u32_array(data, sections[1], sections[2].offset)
    exception_vectors = _parse_vectors(data, sections[2], sections[3].offset)
    references = _parse_reference_records(data, sections[3], sections[4].offset)
    methods = _parse_method_records(
        data, sections[4], sections[5].offset, strings, class_ids, exception_vectors
    )
    _need(data, sections[5].offset, sections[5].count, "section5")
    blob = data[sections[5].offset : sections[5].offset + sections[5].count]
    if sections[5].count != sections[5].end - sections[5].offset:
        raise VmpFormatError("section5 count is not its byte length")
    return VmpFile(
        path=Path(path),
        data=data,
        sha256=hashlib.sha256(data).hexdigest(),
        sections=sections,
        reserved=reserved,
        strings=strings,
        string_ids=class_ids,
        exception_vectors=exception_vectors,
        reference_records=references,
        methods=methods,
        byte_blob=blob,
        code_start=HEADER_AFTER_PAIRS,
        code_end=sections[0].offset,
    )


def load(path: Path | str) -> VmpFile:
    p = Path(path)
    return parse_bytes(p.read_bytes(), p)


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Parse a SckitVMP container")
    ap.add_argument("vmp")
    ap.add_argument("--method", type=int, help="show one invoke method id")
    ap.add_argument("--string", type=int, help="show one decryptString id")
    args = ap.parse_args()
    v = load(args.vmp)
    print(f"size={len(v.data)} sha256={v.sha256}")
    for s in v.sections:
        print(f"section{s.index} {s.kind} offset=0x{s.offset:x} count={s.count} end=0x{s.end:x}")
    print(f"methods={v.method_count} strings={v.string_count} code=0x{v.code_start:x}..0x{v.code_end:x}")
    if args.method is not None:
        m = v.method(args.method)
        print(m)
    if args.string is not None:
        print(repr(v.decrypt_string(args.string)))
