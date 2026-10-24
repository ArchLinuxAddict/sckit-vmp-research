# Limitations

## Technical

- **Method payload decoder missing.** The 16-byte method-code header and
  method-ID matches are confirmed; the variable payload after the header has not
  been decoded into the 0x20-byte IR. No method has a complete opcode sequence.
- **Opcode semantics.** 159 opcode values and 116 handler addresses are mapped,
  but Java-equivalent meanings are not assigned.
- **Section 5/reference records.** The 22,118-byte blob and 937 triples are
  structurally recorded but have no demonstrated consumer.
- **Method header fields.** Register/`ins`-like and instruction-count-like fields
  are candidate interpretations; the auxiliary word's semantics are unresolved.
- **Detections.** 500/900/300 are observed outcomes. The exact predicates,
  signals, and VMP/native attribution are unresolved. The anti-crack exception's
  throw site is unresolved.
- **`RcIsRooted`.** No confirmed producer/consumer; it remains a Bundle clue.
- **Activation.** Request/response schema, key semantics, `STATUS: ONLINE`, and
  post-activation behavior are not established. No authorized key/account was
  available.
- **TLS.** Application payloads and complete certificate details were not
  available; no decryption/pinning bypass was attempted.

## Environmental

- Runtime observations come from specific preserved devices/builds and do not
  automatically generalize.
- Some protected-app paths require location, network, an activation key, or a
  vendor-authorized environment and were not exercised.
- The private source project used tooling not included here (Ghidra, JADX,
  Rizin, Frida, Android tools). Public tests use Python only.

## Evidence inconsistencies

- The Phase X manifest has stale hashes/sizes for two inventories and the Phase X
  executive summary. The private files were preserved; the audit records the
  mismatch rather than retroactively editing it.
- Earlier reports described VMP pairs as `(offset,length)`. Phase XI corrected
  them to `(offset,count)` and documented the correction.
- Phase VI/VIII reports call the VMP string table “obfuscated printable strings”;
  Phase XI recovered the actual XOR/mutf8 transform. The earlier reports are
  preserved as historical stages.

## Publication

- No GitHub remote was configured in the release environment; no public URL or
  push is claimed unless independently verified.
- Full raw inventories, captures, screenshots, logs, binaries, and extracted
  app strings are withheld. This limits independent reproduction of runtime and
  full-table claims to holders of lawful matching inputs.
