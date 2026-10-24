# Phase VIII — unrooted differential and VMP attribution

## Objective

Test whether the observed root gate was unconditional, separate the root/Frida
behavior from other app layers, and correct attribution of the VMP call ID that
surfaced during instrumentation.

## Key results

- On the unrooted test device, the root gate was absent. The app reached privacy
  terms, requested location, and subsequently displayed the activation/VIP
  dialog (no key entered). This is environment-dependent behavior, not a claim
  that root detection is disabled universally.
- Denying location returned to the launcher; location permission remained a
  mandatory path in the tested build.
- The rooted, uninstrumented run reproduced the 500/root behavior.
- The Frida-instrumented run produced 900/Frida behavior.
- A re-signed copy still hit the root gate; any later signature-specific check was
  masked.
- `VMPPBridge.invoke(1839)` is `LoginDialog$100000002.run`, an animation
  callback. The anti-crack exception observed at 1839 is not evidence that 1839
  detects Frida.
- The private Phase VIII detection inventory grew to 25 entries; the Phase VII
  inventory had 15. This expansion reflects additional static/behavioral entries,
  not 25 independent production detectors.

## Reports

- [VMP attribution correction](vmp-analysis.md)
- [Error paths](error-paths.md)

## Boundaries / unresolved

No production license environment, activation key, TLS decryption, or modified
APK was used. The exact root/Frida predicates, signature-check behavior, and
post-activation path remain unresolved. Private device models, identifiers, and
logs are withheld.

The private Phase VIII suite reported **81 tests: 79 passed, 2 skipped, 0
failed**. Public tests are separate.
