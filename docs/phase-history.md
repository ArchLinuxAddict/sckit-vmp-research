# Phase history

The private investigation contains more raw detail than the public set. This
table preserves phase identity and records the actual progression; it does not
claim that every private report was independently revalidated for this release.

| Phase | Objective | Methods | Principal discoveries | Public report |
|---|---|---|---|---|
| I–V | Establish target/provenance, APK/DEX/engine inventory, runtime harness | Static inventory, local engine analysis, device lab preparation | Preserved sample identity; engine/resource and DEX inventory; root/Frida baseline path | Summarized only where needed in VI–XI |
| VI | Native/VMP baseline | Ghidra, JADX, Frida string bridge, runtime A/B | Shield loader paths; `isPmsHooked`; VMP Rust modules; bridge string calls | [Phase VI](../reports/phase6/README.md) |
| VII | Detection inventory | Static app scan, runtime observations, owned fixture | 15-entry layer inventory; root/Frida/PMS/PairIP/activation separated; 1839 correction began | [Phase VII](../reports/phase7/detection-inventory.md) |
| VIII | Unrooted differential | Unrooted test device, permission flow, fixture validation | Root gate absent on unrooted run; VIP dialog reached; 1839 confirmed as animation callback; 25-entry private inventory | [Phase VIII](../reports/phase8/README.md) |
| IX | Network/VPN/activation | Device capture, socket attribution, PCAPdroid, static activation calls | Traffic before root error; VPN 300; Firebase/API context; activation UI | [Phase IX](../reports/phase9/README.md) |
| X | Managed call-site inventory | DEX call-site inventory and categorization | 607 app sites / 62 classes; 117 log sites; distinct method IDs; detection candidates heuristic | [Phase X](../reports/phase10/README.md) |
| XI | Binary reconstruction | Ghidra, Python parser, table extraction, full-record validation | Exact container model; 6,004 strings; 1,845 methods; 724 code-ID matches; 159 opcodes/116 handlers | [Phase XI](../reports/phase11/README.md) |

## Count evolution (private tests)

| Phase | Private test result |
|---|---|
| VI | 71 run, 69 passed, 2 skipped |
| VIII | 81 run, 79 passed, 2 skipped |
| IX | 88 run, 86 passed, 2 skipped |
| X | 93 run, 91 passed, 2 skipped |
| XI | 117 run, 115 passed, 2 skipped (Phase XI alone: 24/24) |

The counts are from the reports at those phases; they are not combined into a
claim that every test exercises public functionality. The public test suite is
separate and input-independent.

## Corrections

- **1839:** An early detector hypothesis was corrected to
  `LoginDialog$100000002.run`, an animation callback.
- **Header pairs:** Phase IX/X described `(offset,length)`; Phase XI established
  `(offset,count)`.
- **String lengths:** Phase XI established UTF-16-unit decoded length plus
  encoded byte length, and recovered the XOR/mutf8 transform.
- **Phase X manifest:** two inventories and the Phase X executive summary have
  stale hashes/sizes in the private manifest; the originals were preserved and
  the discrepancy is documented in the Phase X audit.

## Unresolved at release

Method payload decoder, exact 500/900/300 predicates, anti-crack throw site,
`RcIsRooted`, activation schema, `STATUS: ONLINE`, TLS payloads.
