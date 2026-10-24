# Phase VIII error-path analysis (sanitized)

| Path | Observation | Status |
|---|---|---|
| E1 | Rooted, uninstrumented: Error Code 500 / Root Detected; flow stops before main app | CONFIRMED behavior |
| E2 | Frida spawn: Error Code 900 / Frida Detected | CONFIRMED behavior |
| E3 | `RuntimeException: Please don't try to crack me!!!` at VMP calls under instrumentation | CONFIRMED exception; cause unresolved |
| E4 | `PMS Hook Detected` native log path | CONFIRMED static; not triggered |
| E5 | PairIP license/paywall path | STATIC; not exercised |
| E6 | Activation invalid/expired/inactive UI states | STATIC/UI context; no key |
| E7 | Location permission denial returns to launcher | CONFIRMED runtime observation |
| E8 | Background-location/App Info path | CONFIRMED runtime observation |
| E9 | Unrooted activation/VIP dialog with `STATUS: ONLINE` | CONFIRMED UI; semantics unresolved |

The error renderer reads `errorCode`/`message` Intent extras; it does not establish
the detector implementation. `PMS Hook` is separate from root/Frida. PairIP is a
separate app/licensing layer and was not proven to be SCKit. No causal relation
between network responses and the root outcome is established.

Private raw logs/screenshots are withheld. The public Phase XI detection report
adds decoded VMP root/status UI strings but still does not identify the predicate.
