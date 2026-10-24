# Phase X — managed call-site inventory

## Objective

Inventory `VMPPBridge.invoke` call sites in the app and log/bridge DEX to separate
managed call sites from native records and to prioritize startup, authorization,
and activation paths.

## Results

- **607** app-DEX invocation sites across **62 source files / 62 top-level
  classes**.
- **117** additional LoginDialog/log-DEX sites.
- Categories by name/context heuristic: lifecycle/UI 126, activation 35,
  network/HTTP/TLS 48, feature/location 101, detection-candidate 21, unknown 276
  (607 app sites total).
- Six `HttpStatus.SC_*` constants were resolved; one literal ID 0 remains in an
  app `onCreate`.
- The ID range observed is `0..1843`, consistent with the Phase XI 1,845-method
  table.
- `invoke(1839)` remains `LoginDialog$100000002.run`, not a detector.

## Reports

- [Method mapping](method-mapping.md)

## Boundary

The full 607/117 rows contain third-party source context and are not published.
The public excerpt contains selected startup, authorization, and activation IDs.
Categorization is heuristic, not proof of semantics.

The private Phase X suite reported **93 tests: 91 passed, 2 skipped, 0 failed**.
A pre-existing Phase X manifest mismatch for two inventories and its executive
summary is documented in [the Phase XI audit](../phase11/phase10_audit.md).
