# SckitVMP format reconstruction

## Artifact and tooling

- Target: `<private-artifact>`
- Size: 562,963 bytes
- SHA-256: `4108ca26ce6ebcb9252e644c4d1d00a08693ad232990649ef06a72cbe636d232`
- Native consumer: `lib__arm64-v8a__libsnehakimakichut.so` (AArch64 ELF),
  SHA-256 `091b06ee3cdf2ea3521a45542aebd25f60219484b93ae62ad204f5cc868da230`
- Tools used: Ghidra 12.2 PUBLIC (Java 27), `llvm-objdump` 23.1.3, Python 3.14.8.
- Read-only analysis: the original APK, asset, and library were never patched.
  Parser tests operate on copies or in-memory mutations.

Earlier phases described the six header pairs as `(offset,length)`. That was a
**structural approximation**. The native parser treats the second value as a
**record count**; section 0, for example, has 6,004 variable-size records in a
181,197-byte span, not a 6,004-byte span.

## Top-level layout (observed, exact)

| Offset | Size | Meaning | Evidence |
|---:|---:|---|---|
| `0x00` | 8 | `SckitVMP` magic | `JNI_OnLoad` compares the first 8 bytes with little-endian `0x504d5674696b6353` |
| `0x08` | 48 | six `(u32 offset, u32 count)` pairs | native parser reads 14 u32 values; the first 12 are these pairs |
| `0x38` | 8 | two reserved u32, both `0` | native parser reads and discards the last two u32 values |
| `0x40` | `0x4a4cc` | method-code region; first method starts here | first code record is at `0x40`; last method code is at `0x4a4d6` |
| `0x4a50c` | 181,197 | string section (6,004 records) | parsed exactly to next offset |
| `0x768d9` | 2,708 | 677-entry u32 class table | `677*4` exactly |
| `0x7736d` | 4,400 | 353 exception vectors | variable vectors; ends exactly at next section |
| `0x7849d` | 11,244 | 937 records × 3 u32 | `937*12` exactly |
| `0x7b089` | 36,900 | 1,845 method records × 5 u32 | `1845*20` exactly |
| `0x840ad` | 22,118 | 22,118-byte byte blob | count equals byte length |

The six pairs are:

| Index | Offset | Count | Span to next section/EOF |
|---:|---:|---:|---:|
| 0 | `0x4a50c` (304,396) | 6,004 | 181,197 |
| 1 | `0x768d9` (485,593) | 677 | 2,708 |
| 2 | `0x7736d` (488,301) | 353 | 4,400 |
| 3 | `0x7849d` (492,701) | 937 | 11,244 |
| 4 | `0x7b089` (503,945) | 1,845 | 36,900 |
| 5 | `0x840ad` (540,845) | 22,118 | 22,118 |

**Confidence: CONFIRMED.** The parser consumes each section to the exact next
offset, and the native loader rejects a bad magic/missing section before
registration.

## Section 0 — string table

Each record is:

```
uleb128 decoded_utf16_unit_count
uleb128 encoded_byte_count
uint8[encoded_byte_count] encoded_bytes
```

Decoding (confirmed for all 6,004 records):

```
for i, byte in enumerate(encoded_bytes):
    byte ^= (i & 0xA3)
text = modified_utf8_decode(bytes)
```

Native evidence:
- `FUN_001313f4` at Ghidra `0x1313f4` copies an input slice and XORs byte `i`
  with `i & mask` (`and w12, w9, w20` in the loop).
- The VMP string call is at ELF `0x38fc4` / Ghidra `0x138fc4` with `w3=0xA3`.
- The post-transform decoder is the `mutf8` implementation
  (`Unexpected EOF`, overlong-sequence and surrogate diagnostics in
  `crates/common_android/src/mutf8.rs`).
- A separate call at ELF `0x38c80` / Ghidra `0x138c80` uses `w3=0x6F` for the
  asset name, confirming the same generic routine with a different mask.

Validation results:
- 6,004/6,004 records decode without error.
- 6,004/6,004 decoded UTF-16 unit counts equal the first length field.
- Example: record 0 decodes to `Ljava/lang/AllException;`.
- Example: record 35 decodes to `Lcom/aebas/aebas_client/aebas;`.
- Example: record 5148 decodes to
  `https://<redacted-firebase-rtdb>/`, matching the Phase X
  `LoginDialog` `decryptString(5148)` bytecode constant.
- Phase X output check: record 1893 = `<redacted-sample-string>`, 2884 = `new`, 2885 = `sabea`.

The table includes descriptors, method names, UI strings, SQL fragments, and
runtime support strings. Root/status examples are record 5395
(`This Device is rooted!`), 5909 (`Cannot Reboot. Rooted device is required.`),
5605 (`Error Code`), 5619 (`500`), and 5926–5928 (`STATUS: `,
`ONLINE`, `OFFLINE`). These are UI/text evidence, not proof of which method
emits them. `decryptString(id)` is a **string-table index** (`0 <= id < 6004`),
distinct from `invoke(id)`.

## Section 1 — class table

677 u32 entries. Method-record field 0 is an index into this table (values
observed `10..659`). `section1[index]` is a string-table ID; the referenced
string decodes to a JNI class descriptor.

Examples:
- `section1[40] = 44` → `Lc1/e0;` (owner of method 5, `onCreate`)
- `section1[213] = 478` → `Lcom/aebas/aebas_client/MainActivityLaunch;`
- `section1[625] = 1710` → `Lop/jat/dilog/LoginDialog$NetTask;`
- `section1[632] = 1750` → `Lop/jat/dilog/LoginDialog$100000002;`

**Confidence: CONFIRMED** for the indirection: all 1,845 method class indices
are in range, and the resulting strings are valid JNI descriptors.

## Section 2 — exception vectors

353 vectors. Each vector is `u32 count` followed by `count` u32 type indexes.
The section contains 747 type entries in total and ends exactly at `0x7849d`.

Method-record field 2 is an exception-vector index or `0xffffffff` for none.
1,289 methods have a vector; 556 have `0xffffffff`. All non-sentinel indexes
are in `0..352` (353 values).

The exact meaning of each type entry is not yet proven; it is an exception type
index space, not a method opcode.

## Section 3 — three-word reference records

937 records of `(u32, u32, u32)` at `0x7849d`. The fields have ranges:
- field 0: `10..656`
- field 1: `2..648`
- field 2: `1..1890`

They are consistent with field/type/reference metadata, but their role has not
been established by tracing a consumer. They are recorded in the parser and
inventory but are not used for the method crosswalk.

## Section 4 — method records

1,845 records of five u32 values:

| Field | Meaning | Confidence | Evidence |
|---:|---|---|---|
| 0 | class-table index | CONFIRMED | all in `0..676`; resolves to JNI descriptors |
| 1 | method-name string index | CONFIRMED | direct `0..6003` index; names match Java call sites |
| 2 | exception-vector index or `0xffffffff` | CONFIRMED | all values in `0..352` or sentinel |
| 3 | auxiliary value | OBSERVED, semantics unresolved | values `1..653`; does **not** equal Java argument count |
| 4 | method-code offset, 0 = no code | CONFIRMED | 724 non-zero offsets; every target begins with the matching method ID |

Method record index = `invoke(id)`. The native stub directly indexes the method
metadata with this ID after bounds-checking against 1,845. There is no evidence
that a Java invocation ID is an opcode or a record byte offset.

Examples (from `data/method-record-excerpt.csv`):

| ID | Class | Method | Exception | Aux | Code offset |
|---:|---|---|---:|---:|---:|
| 0 | `Lcom/aebas/aebas_client/aebas;` | `onCreate` | none | 1 | `0x40` |
| 5 | `Lc1/e0;` | `onCreate` | 1 | 1 | `0x9d` |
| 15 | `...ActivityAuthorization;` | `SaveDomainDetails` | 4 | 2 | `0x195` |
| 304 | `...MainActivityLaunch;` | `a` | none | 2 | `0xac11` |
| 1641 | `Lop/jat/dilog/LoginDialog;` | `hasNet` | none | 2 | `0x44bb0` |
| 1744 | `...LoginDialog$NetTask;` | `fetch` | none | 599 | `0x47920` |
| 1839 | `...LoginDialog$100000002;` | `run` | none | 1 | `0x4a259` |
| 1843 | `...LoginDialog$100000000;` | `onDismiss` | 352 | 1 | `0x4a4d6` |

## Method-code region and 16-byte record headers

The method-code region starts at file offset `0x40` and ends at section 0
(`0x4a50c`). 724 methods have non-zero offsets; 1,121 have 0 and therefore no
code record.

Every non-zero offset in the shipped file points to a record whose first u32 is
the same method ID: **724/724 matches**, with **724 unique offsets**. This is
strong evidence that field 4 is a code-record selector, not a string/hash/line
field.

The first 16 bytes of a code record are:

| Relative offset | Observed field |
|---:|---|
| `+0x00` | `u32 method_id` (must equal the table ID) |
| `+0x04` | packed word 1: low byte flag `0`/`1`; upper 24 bits 0..22,116 |
| `+0x08` | packed word 2: low byte `0`; upper bits contain register and `ins`-like counts |
| `+0x0c` | packed word 3: low byte `0`; upper 24 bits 2..2,043 |

Across 724 records:
- flag 0: 636; flag 1: 88.
- word 2 low byte is 0 in all 724 records; decoding `word2 >> 8` as
  `(registers << 16) | ins` gives plausible values, e.g. method 1839 =
  registers 2, ins 6.
- word 3 low byte is 0 in all 724 records; `word3 >> 8` gives 2..2,043 and
  behaves like an instruction count (method 1839 = 52, method 1843 = 5).
- word 1 upper 24 bits are unique across the 724 records (0..22,116), but its
  semantic label (debug index/auxiliary table offset) is unresolved.

The native parser rejects unsupported code flags (`Invalid method code flag:`,
string at `0x109eab`, error path around Ghidra `0x13e478`). This supports treating
the low byte of word 1 as a real format flag, not a padding byte.

**Do not infer opcodes from this header.** The payload after `+0x10` has not been
decoded into the 0x20-byte IR records used by the interpreter. The header is a
confirmed record boundary and metadata block; payload semantics are unresolved.

## Section 5 — byte blob

22,118 bytes at `0x840ad`. Its count is exactly its byte length. Method code
offsets do **not** point into this section; they all point into
`0x40..0x4a4d6`. The section is therefore not the primary method-code store.
Candidate roles (unresolved) include auxiliary tables, debug/line data, or a
constant pool. No code path has been demonstrated to consume it as opcodes.

## Parser and validation

`scripts/phase11/vmp_format.py` implements only the confirmed structures:
- magic and six `(offset,count)` pairs;
- code-region bounds;
- exact section-boundary checks;
- ULEB128 string records, XOR mask `0xA3`, modified UTF-8 decoding;
- class table, exception vectors, reference records, method records;
- method-code record ID/flags/header validation;
- separate `method(invoke_id)` and `decrypt_string(string_id)` APIs.

Malformed-input behavior is tested in `tests/phase11/test_vmp_format.py`:
bad magic, truncated header, non-monotonic offsets, count/span mismatches,
string-length overflow, method-code offset out of range, and code-record ID
mismatch all raise `VmpFormatError`. No original artifact is written.

---

*Public sanitized edition. Private raw artifacts, full inventories, and device/network identifiers are withheld; see `docs/publication-audit.md`.*
