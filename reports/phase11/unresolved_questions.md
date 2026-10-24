# Phase XI unresolved questions

## VMP format

1. **Method-code payload encoding.** The 16-byte header and 724 code-record IDs
   are confirmed, but the payload after `+0x10` has not been decoded into the
   0x20-byte IR records consumed by `inner_invoke`. The exact instruction
   encoding, operand layout, and variable-length rules remain unknown.
2. **Opcode semantics.** All 159 opcode numbers and 116 handler addresses are
   confirmed. Only opcode families (not individual Java-equivalent meanings) are
   partially classified. No opcode is assigned a name such as `const-string`,
   `invoke-virtual`, etc.
3. **Method header fields.** `word1_value` (0..22,116), `word2` register/`ins`
   split, and `word3` instruction-count candidate need validation against a
   controlled method trace. The low-byte flag's 0/1 values are observed, but the
   meaning of the flag states is unknown.
4. **Section 5 role.** The 22,118-byte blob has no demonstrated consumer. It is
   not the primary method-code store; candidate roles remain unproven.
5. **Section 3 role.** The 937 triples are recorded structurally but no consumer
   was traced.
6. **Aux field.** Method field 3 (values 1..653) is not the Java argument count
   and is not yet semantically identified.
7. **Native registration names.** Four registered native function pointers are
   mapped by behavior, but the generated registration-name strings were not
   independently decoded. The split between `initApp` and `initApp2` is
   inferred from their shared body.
8. **`decrypt(byte[])`.** It is declared in Java but absent from the four-entry
   registration table; whether any code path invokes it is unresolved.

## Detection correlation

1. Which VMP method or native routine emits the observed 500 root outcome?
2. Which routine emits 900 Frida outcome and what signal does it test?
3. Which routine emits 300 VPN outcome and what transport/property does it test?
4. Is the `inner_invoke` security branch (`runtime+0x24`, `DAT_00177bb8`) the
   anti-crack path, and what sets the dirty state?
5. Does `invoke(1744)` (`LoginDialog$NetTask.fetch`) participate in the anti-crack
   exception, or does it merely run while the global state is dirty?
6. Where does `Please don't try to crack me!!!` come from? It is not a VMP
   plaintext and was not found in the analyzed native library.
7. What is the producer/consumer of `RcIsRooted`? It remains a Bundle clue only.
8. Is the decoded VMP string `This Device is rooted!` used by the 500 gate or by
   a different feature?

## Activation/network

1. Exact Firebase path under `AADHAR/` and request/response JSON schema.
2. Whether `fetch`, `verify`, `chkExp`, `pushDeviceId`, and `pushExpiryDate`
   perform HTTP, cache, or UI work at their native call sites.
3. `STATUS: ONLINE` semantics; it is a decoded VMP UI string, not proven
   network/activation state.
4. Post-activation path and success/failure conditions.
5. TLS application payload contents; no pinning bypass or key forgery was
   performed.

## Highest-value next step

Decode the variable method payload into the 0x20-byte IR for a small,
non-security UI method (for example, one LoginDialog animation callback) and
then validate the same decoder on a second method with a different header flag.
This is the shortest evidence-based route from the now-confirmed
method-ID-to-record mapping to a genuine opcode-sequence mapping.

---

*Public sanitized edition. Private raw artifacts, full inventories, and device/network identifiers are withheld; see `docs/publication-audit.md`.*
