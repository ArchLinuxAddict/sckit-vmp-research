#!/usr/bin/env python3
"""Extract the SckitVMP opcode dispatch table from libsnehakimakichut.so.

The ELF is non-PIE loaded at base 0x100000 by the Phase VI Ghidra project.
File offsets and ELF VAs are used here; Ghidra VA = ELF VA + 0x100000.
"""
from __future__ import annotations

import argparse
import csv
import struct
from collections import Counter, defaultdict
from pathlib import Path

GHIDRA_BASE = 0x100000
JUMP_TABLE_FILE_OFF = 0x8FF0
JUMP_BASE_ELF = 0x286B8
TAG_TABLE_FILE_OFF = 0xB660
OPCODE_COUNT = 159
TEXT_START = 0x202F4
TEXT_END = 0x202F4 + 0x48910


def u64s(data: bytes, off: int, count: int) -> list[int]:
    return list(struct.unpack_from(f"<{count}Q", data, off))


def i32s(data: bytes, off: int, count: int) -> list[int]:
    return list(struct.unpack_from(f"<{count}i", data, off))


def extract(lib: Path, out_csv: Path) -> dict:
    data = lib.read_bytes()
    tags = u64s(data, TAG_TABLE_FILE_OFF, 16)
    if any(v > 0x20 for v in tags):
        raise SystemExit(f"unexpected tag offsets: {tags}")
    rels = i32s(data, JUMP_TABLE_FILE_OFF, OPCODE_COUNT)
    targets = [JUMP_BASE_ELF + rel for rel in rels]
    if any(not (TEXT_START <= t < TEXT_END) for t in targets):
        bad = [hex(t) for t in targets if not (TEXT_START <= t < TEXT_END)]
        raise SystemExit(f"jump target outside .text: {bad[:5]}")
    groups: dict[int, int] = {}
    rows = []
    for opcode, target in enumerate(targets, 1):
        if target not in groups:
            groups[target] = len(groups)
        rows.append(
            {
                "opcode": opcode,
                "hex": f"0x{opcode:02x}",
                "handler_elf_va": f"0x{target:x}",
                "handler_ghidra_va": f"0x{target + GHIDRA_BASE:x}",
                "handler_group": groups[target],
                "group_size": 0,
                "jump_table_entry_file_offset": f"0x{JUMP_TABLE_FILE_OFF + (opcode - 1) * 4:x}",
                "evidence": "opcode-1 indexes the signed relative table; target is in .text",
                "confidence": "CONFIRMED_ADDRESS",
                "semantic_status": (
                    "UNRESOLVED; shared JNI object-array handler family (opcodes 50-63)"
                    if 50 <= opcode <= 63 else "UNRESOLVED"
                ),
            }
        )
    counts = Counter(targets)
    for row in rows:
        row["group_size"] = counts[int(row["handler_elf_va"], 16)]
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return {
        "tags": tags,
        "targets": targets,
        "groups": counts,
        "unique_handlers": len(counts),
        "rows": rows,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("library", type=Path)
    ap.add_argument("--csv", type=Path, default=Path("reports/phase11/opcode_dispatch.csv"))
    args = ap.parse_args()
    info = extract(args.library, args.csv)
    print(f"opcodes={len(info['targets'])} unique_handlers={info['unique_handlers']}")
    print("tag->opcode-field-offset:", ", ".join(f"{i}:0x{v:x}" for i, v in enumerate(info["tags"])))
    print("largest handler groups:")
    for target, count in info["groups"].most_common(12):
        opcodes = [i + 1 for i, t in enumerate(info["targets"]) if t == target]
        print(f"  0x{target:x} ({0x100000 + target:#x} Ghidra): {count} opcodes {opcodes[:12]}")
    print(f"wrote {args.csv}")


if __name__ == "__main__":
    main()
