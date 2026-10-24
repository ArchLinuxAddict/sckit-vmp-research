# Synthetic minimal VMP boundary example

`minimal.dat` is a 108-byte synthetic container constructed for parser tests. It
is not extracted from the third-party application and contains no third-party
code.

It contains the six section descriptors and the minimum one record per section:

- section 0: one string record `X`;
- section 1: one class-table entry;
- section 2: one empty exception vector;
- section 3: one zero triple;
- section 4: one method record (class 0, name 0, no exception, no code);
- section 5: one byte.

It exists to test header bounds, section ordering, string decoding, and malformed
input handling without requiring the proprietary asset.

```bash
python3 scripts/phase11/vmp_format.py examples/minimal-vmp/minimal.dat
```

Expected: one string, one method, no code, sections at `0x40`, `0x43`, `0x47`,
`0x4b`, `0x57`, and `0x6b`.
