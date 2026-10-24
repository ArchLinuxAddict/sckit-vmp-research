# Opcode mapping (address-level, evidence-based)

## What is mapped

The native interpreter consumes 0x20-byte IR records. The opcode is selected by
a tag-dependent u16 offset, then used as a one-based index into a 159-entry jump
table. The mapping below is **opcode number → native handler address**. It is
not a Java opcode-name mapping.

Evidence:
- dispatch code at Ghidra `0x128698`–`0x1286c4`;
- tag table at Ghidra `0x10b660`;
- 159 signed relative entries at Ghidra `0x108ff0`;
- dispatch base `0x1286b8`;
- full extracted table in `data/opcode_dispatch.csv`.

## IR and opcode extraction

| Step | Observed operation |
|---|---|
| 1 | `record = code_base + ip*0x20` |
| 2 | `tag = qword0 ^ 0x8000000000000000`; if `tag >= 16`, tag = 14 |
| 3 | `opcode_offset = tag_table[tag]` (16 qwords) |
| 4 | `opcode = u16(record + opcode_offset)` |
| 5 | `handler = dispatch_base + s32(jump_table[opcode-1])` |
| 6 | invalid/zero/out-of-range opcode follows the parser's `Invalid opcode` error path |

Tag table values:

| Tag | Opcode-field offset |
|---:|---:|
| 0 | `0x0c` |
| 1 | `0x08` |
| 2 | `0x0c` |
| 3 | `0x08` |
| 4 | `0x0e` |
| 5 | `0x08` |
| 6 | `0x08` |
| 7 | `0x0e` |
| 8 | `0x12` |
| 9 | `0x0e` |
| 10 | `0x08` |
| 11 | `0x10` |
| 12 | `0x10` |
| 13 | `0x08` |
| 14 | `0x1c` |
| 15 | `0x0c` |

## Opcode coverage

- 159 opcode values (`1..159`).
- 116 unique handler addresses.
- 7-wide shared families: 50–56, 57–63, 64–70, 71–77, 78–84, 85–91.
- Shared partial family: 92, 93, 94, 96.
- Remaining opcodes have individual or smaller shared targets; see the CSV.

The seven-wide families are consistent with generated opcode/branch families
(`crates/vmp_shell/src/generated_branches.rs` is present in the binary), but no
individual Java-equivalent opcode names were assigned.

## Handler-observation example

Handler `0x1286c8` (opcodes 50–56):
- reads u16 fields at record offsets `+8`, `+10`, `+12`, `+14`;
- calls `FUN_001275cc`, `FUN_0012f2a8`, `FUN_00127248`;
- calls JNI table entries `+0x558` (`GetArrayLength`) and `+0x568`
  (`GetObjectArrayElement`);
- calls `FUN_0012746c`.

This supports an **object-array/JNI handler family** classification
(PROBABLE), not a claim that all seven opcodes are Java `invoke-*` operations.
All handler addresses and shared groups remain **CONFIRMED**; all exact opcode
semantics remain **UNRESOLVED**.

## Why no invoke-ID crosswalk to opcodes yet

`invoke(id)` selects method record `id` and then executes that method's decoded
code. The method-code payload decoder has not been isolated. Consequently, an
invoke ID cannot honestly be assigned an opcode sequence yet. The crosswalk in
`data/managed-native-crosswalk-excerpt.csv` stops at the confirmed method record and marks
`opcode_status=UNRESOLVED`.

## Reproduction check

```bash
python3 scripts/phase11/analyze_native_opcodes.py \
  artifacts/phase5/SAMPLE-01/native/lib__arm64-v8a__libsnehakimakichut.so \
  --csv data/opcode_dispatch.csv
```

The script checks all 159 targets lie in `.text`; a bad target aborts rather than
inventing an opcode mapping.

---

*Public sanitized edition. Private raw artifacts, full inventories, and device/network identifiers are withheld; see `docs/publication-audit.md`.*
