# Phase VIII VMP attribution (sanitized)

JADX places `VMPPBridge.invoke(1839, ...)` in
`LoginDialog$AnonymousClass100000002.run()`, an animation Runnable. It is not a
root/Frida detector. The observed exception under Frida occurs at that callback,
but the security state that throws it is not identified by the ID alone.

At this phase the VMP container was structurally mapped, with the older
`(offset,length)` presentation. Phase XI later corrected it to `(offset,count)`,
decoded all 6,004 strings, and recovered class/method names. The earlier private
report's structural observations were retained, not rewritten.

Confirmed at this phase:

- the VMP bridge is used by the app;
- `invoke(1839)` is an animation callback (corrected from an earlier
  detector hypothesis);
- string-table calls succeed;
- the root/Frida gates are behaviorally real.

Unresolved at this phase:

- exact detector predicate and VMP method;
- method-level VMP record mapping;
- opcode semantics;
- relation between the anti-crack exception and the 500/900 gates.

The public Phase XI [native pipeline](../phase11/native_execution_pipeline.md)
adds the bridge/dispatch addresses without claiming a detector mapping.
