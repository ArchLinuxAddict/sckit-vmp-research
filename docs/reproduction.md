# Reproduction

## Public, self-contained checks

Requirements: Python 3.10+ (tested 3.14), Git, POSIX shell. No Android device,
Ghidra, JADX, Frida, APK, VMP asset, or native library is required.

```bash
python3 -m unittest discover -s tests -v
python3 scripts/check_public_release.py
```

Expected public tests validate:

- the synthetic 108-byte container parser, string primitives, malformed input;
- opcode CSV shape (159/116) and selected method/crosswalk rows;
- documentation links and required files;
- exclusion of forbidden binaries and known sensitive patterns.

Parser example:

```bash
python3 scripts/phase11/vmp_format.py examples/minimal-vmp/minimal.dat \
  --method 0 --string 0
```

Expected: one method `X.X`, one string `X`, sections at
`0x40,0x43,0x47,0x4b,0x57,0x6b`, no method code.

## Optional: matching private/ lawful input

The full public parser can be pointed at a matching VMP asset if you lawfully
obtain one:

```bash
python3 scripts/phase11/vmp_format.py /path/to/sckit-vmp+.vmp --method 1839 --string 5148
```

Verify the SHA-256 in `data/private-source-hashes.json` first. The repository does
not provide or link to an unauthorized copy. Expected structural counts are in
`data/public-evidence-summary.json`; a differing input may legitimately produce
different counts.

The native opcode extractor:

```bash
python3 scripts/phase11/analyze_native_opcodes.py /path/to/libsnehakimakichut.so \
  --csv /tmp/opcode_dispatch.csv
```

It expects the matching library hash and the ELF layout used by the analysis.
It does not accept APK/DEX inputs and does not patch anything.

## Private tests

The private source project's full suite is not redistributed. Its final reports
were:

- Phase XI: 24/24 passed.
- Combined: 117 run, 115 passed, 2 skipped, 0 failed.

Those tests depend on private artifacts/captures and are not claimed to be
runnable from this public tree. The public tests are reported separately in
`docs/publication-audit.md`.

## Troubleshooting

- A parser error with a matching-hash input indicates a version/format
  difference; do not patch production files to force a parse.
- If the synthetic example fails, confirm the working directory is the repository
  root and Python version is ≥3.10.
- A documentation-link failure usually means a renamed report; update the link
  rather than deleting the target.
