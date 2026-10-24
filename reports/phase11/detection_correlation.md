# Detection-path correlation

## Observed outcomes (do not promote to causal proof)

| Outcome | Evidence | Status |
|---|---|---|
| Rooted rooted test device: `Error Code: 500 / Root Detected` | Phase X `private evidence (withheld)`, `root_error_2s.png` | CONFIRMED observed |
| Frida spawn on rooted device: `Error Code: 900 / Details: Frida Detected` | Phase X `private evidence (withheld)` | CONFIRMED observed |
| PCAPdroid VPN on unrooted unrooted test device: `Error Code: 300 / Details: VPN Detected` | Phase X `private evidence (withheld)` | CONFIRMED observed |
| `RuntimeException: Please don't try to crack me!!!` at `invoke(1839)` / `invoke(1744)` under Frida | `private evidence (withheld)`, `private evidence (withheld)` | CONFIRMED observed under instrumentation |
| `PMS Hook Detected` static check | `libScKitShieldV1.so` `isPmsHooked` Ghidra `0x165e48` | CONFIRMED static implementation; not observed triggered |
| `RcIsRooted` Bundle field | Phase IX/X logcat type-mismatch clue only | UNRESOLVED |

The three error codes are **observed UI outcomes**, not proof that a VMP
invocation or native predicate named root/Frida/VPN has been identified.

## What the VMP reconstruction adds

### IDs are not detectors

The native `invoke` stub at Ghidra `0x13eb98` uses the Java integer as a method
table index (`DAT_00177be0+0x50` count; metadata at
`DAT_00177be0+0x48 + id*0x40`). There is no code path that maps `invoke(500)`,
`invoke(900)`, or `invoke(300)` directly to the corresponding UI error. The
observed error numbers are not in the invoke-ID range semantics at all.

### 1839 and 1744 are real methods, but not proven detectors

The recovered method records identify:

| ID | Class | Method | Class ownership |
|---:|---|---|---|
| 1839 | `Lop/jat/dilog/LoginDialog$100000002;` | `run` | LoginDialog anonymous Runnable |
| 1744 | `Lop/jat/dilog/LoginDialog$NetTask;` | `fetch` | LoginDialog network task |
| 1641 | `Lop/jat/dilog/LoginDialog;` | `hasNet` | LoginDialog |
| 1685 | `Lop/jat/dilog/LoginDialog;` | `offlineOk` | LoginDialog |
| 1665 | `Lop/jat/dilog/LoginDialog$NetTask;` | `chkExp` | LoginDialog |

The 1839 mapping **preserves** the Phase X statically confirmed animation
callback. The fact that the anti-crack exception surfaced at 1839 during Frida
means the runtime/security state was dirty when this callback ran; it does not
mean `run()` detects Frida.

Likewise, 1744 is `fetch`, so the observed exception at 1744 under attach is
compatible with a global runtime gate, not proof that `fetch` performs the
detection. The Phase VI execution order shows 1744 before 1839
(`frida_root_trace2_console.txt:160–256`), so the exception may be triggered by
the state present at those calls rather than by their names.

### Candidate gate in `inner_invoke`

`FUN_0012824c` (`0x12824c`) contains a branch controlled by:

- runtime byte `*(char *)(runtime_state + 0x24)`, and
- global `DAT_00177bb8`.

In that branch it calls `FUN_001303d4` (`0x1303d4`) and `FUN_001258f4`, builds
data through `FUN_0014b57c`, and has `crates/vmp_shell/src/inner_invoke.rs`
error framing. This is a **candidate anti-tamper/security gate**, not a
confirmed root/Frida/VPN detector:

- no comparison against a root path, Frida agent, VPN transport, or error
  number was demonstrated in this branch;
- the branch is reachable on `invoke`, so a global dirty state could explain the
  observed exception at unrelated methods.

**Confidence: PROBABLE** that this branch participates in the anti-crack
exception. **UNRESOLVED** for the concrete predicate and for the 500/900/300
causality.

### Decoded VMP strings and detection text

The string table was decoded completely (6,004/6,004). Relevant strings include:

| String ID | Decoded text |
|---:|---|
| 5395 | `This Device is rooted!` |
| 5909 | `Cannot Reboot. Rooted device is required.` |
| 5605 | `Error Code` |
| 5619 | `500` |
| 5926 | `STATUS: ` |
| 5927 | `ONLINE` |
| 5928 | `OFFLINE` |

These establish that root/status/error UI text exists inside the VMP string
table. They do **not** establish which method emits `This Device is rooted!` or
whether it participates in the 500 gate; the `Error Code`/`500` strings sit in a
mixed network/error/UI string region and are not proof of the root error code.

A direct search of the decoded table found no exact:
- `Root Detected`
- `Frida Detected`
- `VPN Detected`
- `Please don't try to crack me`
- `RcIsRooted`
- `frida` (case-insensitive; `Friday` is unrelated)

Therefore the three **exact UI outcome strings** are not backed by matching VMP
string literals, and the anti-crack message is not a VMP plaintext literal. It
must be built/decrypted elsewhere or supplied by another DEX/native component.

## `Please don't try to crack me!!!` control-flow assessment

Established:
- The string was observed as a Java `RuntimeException` at `invoke(1839)` and
  `invoke(1744)` under Frida.
- Those IDs are valid method records; 1839 is the animation `run()`.
- `inner_invoke` has a security-controlled branch with a Rust error path.
- No literal string or direct cross-reference exists in the VMP asset or the
  analyzed native library.

Not established:
- The exception throw site in native code.
- Whether the predicate is Frida-specific, root-specific, or a combined
  anti-instrumentation state.
- Whether `invoke(1839)` itself checks anything before the exception.

**Conclusion:** the exception is an instrumentation-time **effect** correlated
with LoginDialog/VMP calls. It is not proven to be a detector implementation.

## `RcIsRooted`

`RcIsRooted` remains **UNRESOLVED**:
- It appears only in an unrooted Bundle type-mismatch log.
- No DEX/native plaintext producer or consumer was found.
- The decoded VMP string table contains no `RcIsRooted`.
- No Bundle-key writer/reader xref is established.

Do not treat it as the root predicate without a producer/consumer trace.

## VPN and network calls

- `hasNet` (1641) and `offlineOk` (1685) now resolve to `LoginDialog` methods,
  but their names and call sites do not establish VPN detection.
- `STATUS: ONLINE` is a decoded VMP UI string (5926/5927); it is not proven to be
  a VPN status, Firebase health, or activation success.
- Phase X VPN capture triggered error 300 while Firebase/DNS/TCP traffic
  continued; this is an observed gate, not proof that `hasNet`/`offlineOk`
  implement it.

## `isPmsHooked` (preserved static finding)

`libScKitShieldV1.so::isPmsHooked` at Ghidra `0x165e48` remains a separately
confirmed static implementation that logs `PMS Hook Detected`. It is not in the
`libsnehakimakichut.so` VMP call graph and was not observed triggered. It must
not be conflated with the VMP anti-crack branch.

## Correlation summary

| Question | Status |
|---|---|
| Is `invoke(1839)` the root/Frida detector? | **No** — it maps to an animation `run()`; the exception is runtime-state correlated |
| Does `invoke(1744)` itself detect Frida? | **UNRESOLVED** — it maps to `fetch`; exception observed there too |
| Is there a VMP-level security gate? | **PROBABLE** — `inner_invoke` branch on runtime `+0x24`/`DAT_00177bb8`; predicate unresolved |
| Are 500/900/300 mapped to VMP IDs? | **No** — observed outcomes only |
| Is `RcIsRooted` mapped? | **No** — unresolved Bundle clue |
| Is `isPmsHooked` part of this gate? | **No** — separate library/check |

---

*Public sanitized edition. Private raw artifacts, full inventories, and device/network identifiers are withheld; see `docs/publication-audit.md`.*
