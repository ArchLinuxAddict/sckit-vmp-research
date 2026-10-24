# Phase VI native analysis (sanitized release edition)

## APK Shield loader

The Java `SubApp` path loads `ScKitShieldV1` and calls native `attach`/`create`.
The recovered native path includes:

```text
App::getAssetManager
loadDex
App::replaceApplication
```

`loadDex` uses `BaseDexClassLoader`/`DexPathList` reflection and app-private
`files/dalvik/classes.dex`/`classes2.dex` paths. Runtime-recovered DEX images were
hash-checked against static inner DEX images in the private project. The exact
native asset-to-file extraction step is supported by the extracted DEX and
runtime paths but was not decompiled line-by-line.

`replaceApplication` operates through `ActivityThread`/`LoadedApk` fields and
`makeApplication`. `isPmsHooked` at Ghidra `0x165e48` logs a PMS-hook message; it
was not observed triggered in the private runs. It must not be conflated with the
root/Frida/VPN gates.

## VMP runtime

`libsnehakimakichut.so` `JNI_OnLoad` is at Ghidra `0x138a58`. Embedded Rust source
paths identify parser/runtime/opcode/method-executor/inner-invoke and security
modules. Function roles inferred from size/string context are hypotheses, not
symbol-backed labels. The Java bridge itself is confirmed by the native
declarations, class loading, and successful string calls.

## Confidence

| Claim | Status |
|---|---|
| Shield JNI/loader paths exist | CONFIRMED static + runtime paths |
| `isPmsHooked` is a native PMS check | CONFIRMED static; runtime not triggered |
| VMP bridge used by the app | CONFIRMED |
| 1839 is a root detector | NOT SUPPORTED |
| Root/Frida logic is in the VMP/app layer | PROBABLE, not pinpointed |
| VMP opcode semantics complete | UNRESOLVED |

## Boundary

This report is a sanitized edition. Raw decompiled output, protected DEX/native
files, and runtime captures remain private.
