# Phase VII — detection inventory

Phase VII separated observations by layer. It contains **15 entries** in the
private inventory; this is a sanitized summary, not a universal detector map.

| ID | Layer/component | Finding | Status |
|---|---|---|---|
| ROOT-500 | VMP/app + log activity | Rooted run displays 500/root behavior | CONFIRMED behavior |
| FRIDA-900 | VMP/app + log activity | Frida spawn displays 900/Frida behavior | CONFIRMED behavior |
| VMP-ANTICRACK | VMP/LoginDialog | Anti-crack exception observed under instrumentation | CONFIRMED exception; cause unresolved |
| PMS-HOOK | APK Shield native | `isPmsHooked` logs a PMS-hook message | CONFIRMED static; not triggered |
| PAIRIP-LICENSE | App/PairIP | License/RSA/paywall path | STATIC; not exercised |
| PAIRIP-PM-PROXY | App/PairIP helpers | Package-manager/installer proxy path | STATIC; runtime effect not isolated |
| INSTALLER-ID | PairIP/helpers | Installer/package identity checks | STATIC |
| SIGNATURE-STRINGS | DEX/VMP strings | Signature-related strings | STRING ONLY |
| RE-SIGN | App/PairIP/SCKit | Re-signed copy still hit root 500 | CONFIRMED behavior, root-masked |
| APP-LOGIN | LoginDialog/VMP | Activation/device-binding surface | STATIC; no key |
| DEBUGGER | App scan | No direct Java debugger API found | NOT OBSERVED |
| HOOK-STRINGS | App/native scan | No direct Java hook strings beyond separate native/UI evidence | NOT OBSERVED |
| EMULATOR | App scan | No direct emulator predicate found | NOT OBSERVED |
| ROOT-PATHS | App scan | No direct Java root-path check found | NOT OBSERVED |
| ATTACH | Instrumentation lifecycle | Attach vs spawn behavior | INCONCLUSIVE |

The private inventory used a 15-row JSON schema with evidence paths. Those raw
paths and device identifiers are withheld. The later Phase XI work adds native
address and VMP structure evidence but does not turn any detector hypothesis into
a confirmed predicate.

## Boundary

No root-hiding, Frida concealment, VPN bypass, license modification, or
production entitlement was used. The anti-crack message is not proof that 1839 is
the detector; Phase VIII and Phase XI retain the animation-callback correction.
