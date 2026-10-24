# VMP parser design

## Purpose and scope

`scripts/phase11/vmp_format.py` parses only the SckitVMP structures that have
been demonstrated by native code and validated against all records in the
shipped artifact. It deliberately does **not** pretend to decode method payloads
or opcode sequences.

Implemented structures:

1. Header: 8-byte magic, six `(u32 offset, u32 count)` pairs, two reserved u32.
2. Code region: `0x40 .. sections[0].offset`.
3. Section 0: 6,004 encoded strings.
4. Section 1: 677-entry class table.
5. Section 2: 353 exception-type vectors.
6. Section 3: 937 three-u32 reference records.
7. Section 4: 1,845 five-u32 method records.
8. Section 5: 22,118-byte opaque blob.
9. Method-code record header: u32 ID + three packed words, validated for ID
   match and bounds.

Not implemented because evidence is insufficient:
- decoding method-code payload bytes into 0x20-byte IR;
- assigning Java-equivalent meanings to opcodes;
- interpreting section 3 fields or section 5 semantics;
- cryptographic/TLS/activation parsing.

## Header and bounds rules

```text
magic        = b"SckitVMP" at 0x00
pairs[i]     = (u32 offset, u32 count) at 0x08 + i*8, i=0..5
reserved     = two u32 at 0x38 and 0x3c, expected zero in this sample
code_start   = 0x40
code_end     = sections[0].offset
```

Validation performed:
- file length ≥ 64;
- exact magic;
- every section offset ≥ 0x40;
- offsets strictly increasing;
- last section end ≤ file length;
- last section end == file length (no trailing bytes);
- section 0 consumes exactly to section 1;
- section 1 consumes `count*4` exactly to section 2;
- section 2's variable vectors consume exactly to section 3;
- section 3 consumes `count*12` exactly to section 4;
- section 4 consumes `count*20` exactly to section 5;
- section 5 count is its byte length and ends at EOF;
- every ULEB128 has a length bound and a 35-bit upper bound;
- every string byte range is within the file;
- every method's class index is in section 1; every class string id is in
  section 0; every method-name index is in section 0; every non-sentinel
  exception index is in section 2;
- non-zero code offsets are within `0x40 .. section0.offset-16` and the u32 at
  the offset equals the method ID;
- code offsets are unique across methods (observed 724/724).

Errors raise `VmpFormatError` with the failing offset/section. A malformed file
does not cause an uncaught `struct.error` or an unbounded allocation loop in the
implemented paths.

## String decoding

Record format:

```text
decoded_utf16_units : uleb128
encoded_length      : uleb128
encoded_bytes       : encoded_length bytes
```

Decode:

```python
xored = bytes(byte ^ (i & 0xA3) for i, byte in enumerate(encoded_bytes))
text = decode_modified_utf8(xored)
```

The first varint is **UTF-16 code units**, not UTF-8 bytes. It matches every
decoded record (6,004/6,004). The XOR mask is taken from native
`FUN_001313f4`; the parser passes `0xA3`. The modified-UTF-8 decoder supports
NUL as `C0 80` and CESU-8 surrogate pairs.

`decrypt_string(id)` is a separate index space (`0..6003`) from `method(id)`
(`0..1844`).

## Method records

For method ID `i`, read five little-endian u32s at
`section4.offset + i*20`:

| Field | Parser name | Interpretation | Status |
|---:|---|---|---|
| 0 | `class_index` | index into section 1 | confirmed |
| 1 | `name_index` | index into section 0 | confirmed |
| 2 | `exception_index` | section 2 index, `0xffffffff` = none | confirmed |
| 3 | `aux` | unknown auxiliary value | observed only |
| 4 | `code_offset` | offset of method-code record, 0 = none | confirmed |

Class resolution:

```text
class_string_id = section1[class_index]
class_descriptor = strings[class_string_id].text
method_name = strings[name_index].text
```

## Method-code header

For non-zero `code_offset`:

```text
+0x00  u32 method_id       must equal the table index
+0x04  u32 word1           low byte flag (0/1), upper 24-bit aux value
+0x08  u32 word2           low byte 0; upper 24 bits split into registers/ins
+0x0c  u32 word3           low byte 0; upper 24-bit instruction-count candidate
+0x10  payload             not parsed
```

The parser records:
- `flag = word1 & 0xff`;
- `word1_value = word1 >> 8`;
- `registers = (word2 >> 8) >> 16`;
- `ins = (word2 >> 8) & 0xffff`;
- `insn_count = word3 >> 8`.

Only `method_id` and bounds are treated as strict format requirements. The
register/instruction interpretation is exposed as a probable interpretation, not
used to validate files.

## CLI

```bash
python3 scripts/phase11/vmp_format.py \
  <lawful-input>/sckit-vmp+.vmp \
  --method 1839 --string 5148
```

## Tests

`tests/phase11/test_vmp_format.py` has 20 tests:
- exact header/section counts and boundaries;
- all strings decode and length hints match;
- known `decryptString` values;
- method-name/owner crosswalk;
- 724 code-record IDs and flags;
- invoke/decryptString index spaces and bounds;
- malformed header, offsets, counts, string length, code offset, code ID;
- modified-UTF-8 rejection.

`tests/phase11/test_opcode_table.py` has 4 tests for the 159-entry native
dispatch table. The combined suite is 117 tests (115 pass, 2 pre-existing skips).

---

*Public sanitized edition. Private raw artifacts, full inventories, and device/network identifiers are withheld; see `docs/publication-audit.md`.*
