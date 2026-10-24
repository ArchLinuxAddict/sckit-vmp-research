# Findings

Status definitions: **CONFIRMED** = direct structural/observed evidence;
**PROBABLE** = converging but incomplete; **CORRELATED** = shared context/timeline;
**UNRESOLVED** = insufficient evidence.

| # | Finding | Status | Evidence summary | Limitation |
|---:|---|---|---|---|
| F1 | `SckitVMP` magic and six `(offset,count)` sections | CONFIRMED | Native parser + exact boundary consumption | Only preserved sample |
| F2 | Section sizes: 6,004 strings; 677 classes; 353 exception vectors; 937 references; 1,845 methods; 22,118-byte blob | CONFIRMED | Parser consumes each section to exact next offset | Section 5/reference roles unresolved |
| F3 | String transform is XOR `(byte_index & 0xA3)` + modified UTF-8 | CONFIRMED | Native XOR routine/call mask; all 6,004 records decode with matching length hints | Full strings not published |
| F4 | `invoke(id)` is a 1,845-entry method-table selector | CONFIRMED | Native bounds check/index; 0..1843 observed | Not an opcode/address |
| F5 | `invoke(1839)` = `LoginDialog$100000002.run` animation callback | CONFIRMED | VMP class/name + Java call site | Not a detector |
| F6 | 724/724 non-zero code offsets point to matching method IDs | CONFIRMED | Whole-table validation | Payload after header undecoded |
| F7 | Native bridge addresses: invoke `0x13eb98`, inner `0x12824c`, dispatch `0x1286b8` | CONFIRMED | Disassembly/decompilation | Ghidra base caveat |
| F8 | 159 opcode entries / 116 unique handler targets | CONFIRMED | Extracted relative table; all targets in `.text` | Semantics unassigned |
| F9 | Rooted run produces 500/root | CONFIRMED behavior | Private UI/log observation | Exact predicate unresolved |
| F10 | Frida run produces 900/Frida | CONFIRMED behavior | Private UI/log observation | Exact signal unresolved |
| F11 | VPN run produces 300/VPN | CONFIRMED behavior | Private UI/log observation | VPN method changes environment |
| F12 | Anti-crack exception at 1839/1744 under instrumentation | CONFIRMED exception; cause unresolved | Private Frida logs | Not proof of method-local detector |
| F13 | `RcIsRooted` exists as a Bundle clue | UNRESOLVED | Private logcat only | No producer/consumer |
| F14 | `isPmsHooked` at `0x165e48` logs a PMS-hook check | CONFIRMED static; not triggered | Native decompilation | Separate library; runtime outcome unknown |
| F15 | Activation methods belong to LoginDialog/NetTask | CONFIRMED ownership | Method records + selected Java call sites | Backend semantics unresolved |
| F16 | Android ID and a Firebase RTDB base are used by activation UI | CONFIRMED static/UI context | Selected call sites + UI | Exact endpoint/schema withheld; `STATUS: ONLINE` unresolved |
| F17 | App traffic to attendance/Firebase endpoints precedes root UI | CORRELATED | Private pcap/socket attribution | No causation/TLS payload |
| F18 | Exact root/Frida/VPN detector map is complete | **NO** | No mapping established | Do not claim |

## What the findings do not mean

- A method ID is not an opcode.
- A class/method name is not proof of a predicate.
- A network request near an error is not proof of causation.
- A string in the VMP table is not proof of which method emits it.
- A confirmed exception is not a confirmed detector implementation.
- The preserved build's behavior is not universal across versions/devices.

See [limitations](limitations.md) and
[Phase XI unresolved questions](../reports/phase11/unresolved_questions.md).
