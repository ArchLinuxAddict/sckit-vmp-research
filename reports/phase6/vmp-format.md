# Phase VI VMP format note

Phase VI established a structural baseline for the preserved `SckitVMP` asset:
`SckitVMP` magic, six header pairs, a method/code region, and several numeric
tables. It initially described the pairs as `(offset,length)` and did not decode
the string transform.

**Phase XI supersedes that structural interpretation.** The pairs are
`(offset,count)`; section 0 is 6,004 variable-length strings; the string encoding
is XOR `(byte_index & 0xA3)` plus modified UTF-8. See the
[Phase XI reconstruction](../phase11/vmp_format_reconstruction.md) for the final
model and exact boundaries.

The private Phase VI parser/tests remain historical evidence. The public parser is
the Phase XI implementation and can be exercised against the synthetic fixture or
a lawfully obtained matching asset.

## Boundary

No VMP asset or native library is redistributed. The private original report was
not overwritten; this note records the later correction.
