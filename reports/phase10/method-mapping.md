# Phase X method mapping (sanitized)

## Distinction

The Java integer passed to `VMPPBridge.invoke(id, args)` is a **method-table
selector**. It is not a native function address, a code offset, or an opcode.
Phase XI confirmed the method table has 1,845 records and the native stub
bounds-checks the ID against that count.

## Selected IDs

| Call context | ID | Recovered owner/method (Phase XI) |
|---|---:|---|
| MainActivityLaunch startup callback | 304 | `MainActivityLaunch.a` |
| MainActivityLaunch `onCreate` | 320 | `MainActivityLaunch.onCreate` |
| ActivityAuthorization `onCreate` | 124 | `ActivityAuthorization.onCreate` |
| LOGIN control | 1727 | `LoginDialog.onClick` |
| Network state | 1641 | `LoginDialog.hasNet` |
| Offline state | 1685 | `LoginDialog.offlineOk` |
| Expiry check | 1665 | `LoginDialog$NetTask.chkExp` |
| Fetch | 1744 | `LoginDialog$NetTask.fetch` |
| Push device ID | 1756 | `LoginDialog$NetTask.pushDeviceId` |
| Push expiry | 1764 | `LoginDialog$NetTask.pushExpiryDate` |
| Verify | 1765 | `LoginDialog$NetTask.verify` |
| Animation callback | 1839 | `LoginDialog$100000002.run` |

## Important limits

- The invocation inventory did **not** recover an ID-to-native-record/opcode map
  at Phase X. Phase XI later recovered method records and code offsets, but not
  the code payload/opcode sequence.
- Category labels are heuristics.
- Detection-candidate names do not prove detection behavior.
- `invoke(1839)` is an animation callback; the anti-crack exception observed there
  is a runtime-state correlation.

The full app/log inventories and raw source contexts are private. Selected
machine-readable rows are in
[method-record-excerpt.csv](../../data/method-record-excerpt.csv) and
[crosswalk excerpt](../../data/managed-native-crosswalk-excerpt.csv).
