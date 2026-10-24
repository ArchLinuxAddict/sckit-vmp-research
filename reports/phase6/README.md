# Phase VI — native/VMP baseline

## Objective

Establish the native layers behind the preserved Android build: the APK Shield
loader, the VMP bridge/runtime, string decryption behavior, and the initial
root/Frida runtime comparison.

## Methods

- Ghidra 12.2 headless analysis of `libScKitShieldV1.so` and
  `libsnehakimakichut.so`.
- JADX inspection of the preserved DEX/application layer.
- Classloader-aware Frida calls to `VMPPBridge.decryptString`.
- Rooted-device runtime A/B and temporary Magisk DenyList observation.
- Hash verification of recovered runtime DEX files and embedded engine resources.

## Confirmed findings

- `libScKitShieldV1.so` exports JNI entry points for `SubApp.attach`,
  `SubApp.create`, and `JNI_OnLoad`.
- `loadDex` reflects into `BaseDexClassLoader`/`DexPathList`; the loader path
  creates/uses app-private `files/dalvik/*.dex`.
- `replaceApplication` uses `ActivityThread`/`LoadedApk`/`makeApplication`
  internals to replace the application object.
- `isPmsHooked` logs the shield-side PMS-hook message; it is a separate check from
  the observed root/Frida/VPN gates.
- `libsnehakimakichut.so` is a Rust VMP runtime with `JNI_OnLoad`, `vmp_parser`,
  `vmp_runtime`, `opcode`, `method_executor`, `inner_invoke`, and
  `generated_branches`-associated code.
- The classloader-aware bridge successfully called `decryptString` and proved the
  Java-to-native string path.

## Important correction

`VMPPBridge.invoke(1839)` is a LoginDialog animation Runnable, not a root
detector. The `Please don't try to crack me!!!` exception observed under Frida is
an instrumentation-time effect; its exact security-state trigger was not
recovered in Phase VI.

## Reports

- [Native analysis](native-analysis.md)
- [VMP format at Phase VI](vmp-format.md)

## Boundaries

No modified third-party APK was installed. The temporary DenyList test was
reverted. No root/Frida/VPN/licensing bypass was implemented. The private Phase VI
suite reported **71 tests: 69 passed, 2 skipped, 0 failed**; public tests are
separate and do not require proprietary inputs.

## Unresolved

- Exact root/Frida detector method and signal.
- VMP opcode/method semantics.
- Authentic protected-output generation (the preserved engine lacks an authorized
  remote entitlement).
