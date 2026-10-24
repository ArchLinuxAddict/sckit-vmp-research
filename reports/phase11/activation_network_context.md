# Activation and network context

This report records only what the recovered method table and Phase IX/X call
sites establish. It does not guess activation keys, forge tokens, alter server
responses, or bypass TLS/pinning.

## Recovered ownership for activation IDs

Method IDs from `private Phase X inventory (not published)` and
private Phase X inventory (withheld) now resolve through section 4 and section 1 to
the following owners:

| Java call site | ID | Record owner | Record method | Java args | Code offset |
|---|---:|---|---|---:|---:|
| `hasNet()` | 1641 | `Lop/jat/dilog/LoginDialog;` | `hasNet` | 1 | `0x44bb0` |
| `offlineOk()` | 1685 | `Lop/jat/dilog/LoginDialog;` | `offlineOk` | 1 | `0x454c8` |
| `chkExp` | 1665 | `Lop/jat/dilog/LoginDialog$NetTask;` | `chkExp` | 1 | `0x47706` |
| `fetch()` | 1744 | `Lop/jat/dilog/LoginDialog$NetTask;` | `fetch` | 1 | `0x47920` |
| `pushDeviceId(String,int,String)` | 1756 | `Lop/jat/dilog/LoginDialog$NetTask;` | `pushDeviceId` | 3 | `0x47d3e` |
| `pushExpiryDate(String,int,String)` | 1764 | `Lop/jat/dilog/LoginDialog$NetTask;` | `pushExpiryDate` | 3 | `0x480d3` |
| `verify()` | 1765 | `Lop/jat/dilog/LoginDialog$NetTask;` | `verify` | 1 | `0x48468` |
| `findExpiryInfoForKey` | 1661 | `Lop/jat/dilog/LoginDialog;` | `findExpiryInfoForKey` | 2 | `0x4454c` |
| `daysLeftForExpiry` | 1657 | `Lop/jat/dilog/LoginDialog;` | `daysLeftForExpiry` | 2 | `0x44274` |
| `msLeftForExpiry` | 1666 | `Lop/jat/dilog/LoginDialog;` | `msLeftForExpiry` | 2 | `0x452da` |
| `refreshExpiryDisplay` | 1642 | `Lop/jat/dilog/LoginDialog;` | `refreshExpiryDisplay` | 2 | `0x45bbe` |
| LOGIN `onClick` | 1727 | `Lop/jat/dilog/LoginDialog;` | `onClick` | 2 | `0x46c31` |
| animation callback | 1839 | `Lop/jat/dilog/LoginDialog$100000002;` | `run` | 1 | `0x4a259` |

The names and owners are recovered from the VMP class table/string table. They
are not inferred from the `decryptString` values alone. The table is in
`data/method-record-excerpt.csv`; the call-site join is in
`data/managed-native-crosswalk-excerpt.csv`.

## What the call sites establish

From Phase X JADX and the method map:

- `LoginDialog` obtains `android_id` via `Settings.Secure.getString(...,
  "android_id")` and uses `getString(5148)` =
  `https://<redacted-firebase-rtdb>/`.
- `PROJECT_PATH = "AADHAR/"`; preference/string IDs `5120=LP`, `5134=ts`,
  `5136=th`, `5138=sk` decode exactly in the VMP string table.
- `fetch`, `verify`, `pushDeviceId`, `pushExpiryDate`, and `chkExp` are methods
  on `LoginDialog$NetTask`, not arbitrary free functions. This is a real
  ownership correction from the Phase X name-only inventory.
- `hasNet` and `offlineOk` are on `LoginDialog`.
- `invoke(1839)` remains `LoginDialog$100000002.run`, an animation callback.

These facts support a remote activation/key-expiry workflow, but do **not**
establish:
- the exact Firebase path under `AADHAR/`;
- the JSON request/response fields;
- the semantics of `verify` vs `chkExp` vs `fetch`;
- whether `pushDeviceId`/`pushExpiryDate` write, read, or cache;
- the meaning of `STATUS: ONLINE` (decoded VMP strings 5926/5927);
- the post-activation path.

## Network context

Phase X observed Firebase and `<public-sector-attendance-api>` DNS/TCP flows in both
rooted and unrooted runs, including the VPN run. TLS payloads were not
recovered; no HTTP request/response schema is claimed. The VPN run reached error
300 before the VIP flow, and the unrooted non-VPN run reached the VIP screen
(Phase X evidence, not new traffic).

## Detection-adjacent IDs

The recovered activation IDs are not the observed 500/900/300 error selectors.
No native or VMP evidence maps any of these method IDs to an error code. The
decoded VMP string table contains the root UI text and `Error Code`/`500`, but
the table does not prove which method emits the rooted page.

## Blockers retained

- No vendor-authorized activation key/account; no attempt was made to guess or
  forge one.
- No TLS decryption/pinning bypass; no production server manipulation.
- The post-activation execution path, exact request schema, and `STATUS:
  ONLINE` meaning remain unresolved.

---

*Public sanitized edition. Private raw artifacts, full inventories, and device/network identifiers are withheld; see `docs/publication-audit.md`.*
