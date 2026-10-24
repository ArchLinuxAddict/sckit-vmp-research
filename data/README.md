# Public data

This directory contains only safe, derived data.

| File | Purpose |
|---|---|
| `opcode_dispatch.csv` | 159 opcode numbers → native handler addresses from the preserved library; address-level only. |
| `method-record-excerpt.csv` | Selected VMP method records used in the public findings; not the full 1,845-row inventory. |
| `managed-native-crosswalk-excerpt.csv` | Selected managed invocation → method-record joins; not the full 607/117-site inventory. |
| `private-source-hashes.json` | Hashes/sizes of the preserved source inputs; the inputs themselves are not redistributed. |
| `public-evidence-summary.json` | Public aggregate counts, confidence notes, and test provenance. |
| `public-files.json` | SHA-256 allowlist of the public tree (the manifest excludes itself). |

## Not included

APK/DEX/native/VMP files, PCAPs, screenshots, device logs, full decrypted string
inventory, full method/call-site inventories, raw Ghidra output, activation
material, credentials, and personal/device identifiers are excluded. See
[the publication audit](../docs/publication-audit.md).
