# Phase XI executive summary — SckitVMP reconstruction

## Scope and artifacts

Phase XI reused the Phase V–X evidence without modifying the APK, VMP asset, or
native libraries. The primary artifacts are:

| Artifact | Size | SHA-256 |
|---|---:|---|
| `<private-artifact>` | 5,983,863 | `96330aaf76d1c2ea99591189d10f06ecd454504721e96af8ad777e8e512d7292` |
| `resources/assets/sckit-vmp+.vmp` | 562,963 | `4108ca26ce6ebcb9252e644c4d1d00a08693ad232990649ef06a72cbe636d232` |
| `native/lib__arm64-v8a__libsnehakimakichut.so` | 443,280 | `091b06ee3cdf2ea3521a45542aebd25f60219484b93ae62ad204f5cc868da230` |

The Ghidra project uses image base `0x100000`; addresses in these reports are
Ghidra addresses. Subtract `0x100000` for ELF-relative VAs (the form emitted by
`llvm-objdump`). File offsets are absolute in `sckit-vmp+.vmp`.

## Principal results

1. **The VMP container is fully structurally parsed.** It has an 8-byte
   `SckitVMP` magic, six `(offset,count)` pairs, two zero words, and a method-code
   region from `0x40` to `0x4a50c`. The six sections have been parsed to exact
   boundaries:
   - 6,004 strings (`0x4a50c`–`0x768d9`)
   - 677-entry class table (`0x768d9`–`0x7736d`)
   - 353 exception-type vectors (`0x7736d`–`0x7849d`)
   - 937 three-word reference records (`0x7849d`–`0x7b089`)
   - 1,845 five-word method records (`0x7b089`–`0x840ad`)
   - a 22,118-byte blob (`0x840ad`–EOF); its semantic role remains unresolved.

2. **The string encoding is recovered and verified on all 6,004 records.** Each
   record is `uleb128 decoded_utf16_units`, `uleb128 encoded_bytes`, then bytes.
   The bytes are XORed with `(byte_index & 0xA3)` and then decoded as modified
   UTF-8. Native evidence: `FUN_001313f4` XORs each byte with `index & mask`,
   called with mask `0xA3`; the parser then uses the modified-UTF-8 decoder in
   `crates/common_android/src/mutf8.rs`. All 6,004 records decode, and every
   decoded UTF-16 unit count matches the first length field. Known Phase X
   `decryptString` outputs (`<redacted-sample-string>`, `new`, `sabea`, the Firebase URL) match the
   same table exactly.

3. **`invoke(id)` is a method selector, not an opcode.**
   `VMPPBridge.invoke` enters the native stub at Ghidra `0x13eb98`. The stub
   bounds-checks `id` against `DAT_00177be0+0x50` (1,845 entries), performs a
   hash lookup, and takes the method metadata pointer at
   `DAT_00177be0+0x48 + id*0x40`. Method IDs observed in Phase X range from 0 to
   1,843, exactly fitting this table. No Java invocation ID is treated as an
   opcode.

4. **Method names and owners are now recovered.** Method record fields 0, 1, 2,
   3, and 4 are class-table index, method-name string index, exception-vector
   index (`0xffffffff` = none), auxiliary value, and code-record offset.
   Examples:
   - `invoke(1839)` → `Lop/jat/dilog/LoginDialog$100000002;.run`
   - `invoke(1744)` → `Lop/jat/dilog/LoginDialog$NetTask;.fetch`
   - `invoke(1641)` → `Lop/jat/dilog/LoginDialog;.hasNet`
   - `invoke(1685)` → `Lop/jat/dilog/LoginDialog;.offlineOk`
   - `invoke(304)` → `Lcom/aebas/aebas_client/MainActivityLaunch;.a`

   This confirms the Phase X finding that 1839 is an animation callback. The
   Frida-time exception at 1839 is a runtime/security-state effect, not evidence
   that 1839 itself is a detector.

5. **The native execution pipeline is mapped.** The native `invoke` stub calls
   `vmp_runtime::inner_invoke` at Ghidra `0x12824c`. That routine builds the
   exception table and frame, then dispatches 0x20-byte decoded IR records at
   `0x1286b8`. The opcode field is selected by a tag-dependent offset table at
   Ghidra `0x10b660`; the opcode then indexes a 159-entry jump table at Ghidra
   `0x108ff0`. There are 116 unique handlers. Opcodes 50–56, 57–63, 64–70,
   71–77, 78–84, and 85–91 are seven-wide handler families.

6. **Method-code records were validated but not fully decoded.** 724 of 1,845
   methods have non-zero code offsets (all within `0x40..0x4a50c`). Every one of
   the 724 code records begins with a u32 equal to its method ID; 636 have code
   flag 0 and 88 have flag 1. A 16-byte header is followed by an encoded payload.
   The exact payload-to-opcode decoding remains unresolved, so no method ID is
   assigned an opcode sequence.

7. **Detection paths are correlated, not causally solved.** The decoded VMP
   string table contains root/status UI text (`This Device is rooted!`,
   `Cannot Reboot. Rooted device is required.`, `Error Code`, `500`, `STATUS:`,
   `ONLINE`/`OFFLINE`), but no exact `Root Detected`, `Frida Detected`,
   `VPN Detected`, `Please don't try to crack me!!!`, or `RcIsRooted` literal.
   Error codes 500/900/300 remain observed outcomes. The security-controlled
   branch in `inner_invoke` (runtime byte `+0x24` and global `DAT_00177bb8`) is a
   candidate anti-tamper gate, but it has not been tied to a specific detector.
   `isPmsHooked` at `libScKitShieldV1` `0x165e48` remains a separate static
   finding. `RcIsRooted` remains unresolved.

8. **Activation calls are identified by owner and record.** The activation IDs
   now resolve to `LoginDialog$NetTask` (`fetch`, `verify`, `pushDeviceId`,
   `pushExpiryDate`, `chkExp`) and `LoginDialog` (`hasNet`, `offlineOk`). This
   establishes call ownership and method records only; it does not establish
   the Firebase request schema, key semantics, `STATUS: ONLINE`, or successful
   activation.

## Deliverables and tests

All Phase XI reports are under `reports/phase11/`; scripts are under
`scripts/phase11/`, and tests are under `tests/phase11/`.

- Existing suite: **93 tests run — 91 passed, 2 skipped, 0 failed**.
- Opcode address mapping: `reports/phase11/opcode_mapping.md` and
  `data/opcode_dispatch.csv`.
- Phase XI suite: **24 tests run — 24 passed, 0 failed** (private source project).
- Combined discovery (`python3 -m unittest discover -s tests`): **117 run — 115 passed, 2 skipped, 0 failed** (private source project).

## Highest-value next step

Decode the 16-byte method-code header's payload into the 0x20-byte IR consumed by
`inner_invoke` and validate the mapping for a small, non-security method first
(for example, a UI callback). This would convert the now-confirmed
method-ID-to-record mapping into a method-ID-to-opcode-sequence mapping without
touching production security checks.

---

*Public sanitized edition. Private raw artifacts, full inventories, and device/network identifiers are withheld; see `docs/publication-audit.md`.*
