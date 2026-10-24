# Reports

This directory contains the **public, sanitized edition** of selected Phase VI–XI
reports. The private research record contains additional raw logs, screenshots,
captures, full inventories, decompiled output, and proprietary source artifacts;
those are not redistributed.

Phase identity is preserved by directory. Each public report is a release-edition
summary or a sanitized copy of a longer private report. Where a historical
private report used `(offset,length)` for the VMP sections, the Phase XI report
corrects the model to `(offset,count)`; the private original was not rewritten.

## Phase indexes

- [Phase VI](phase6/README.md) — native/VMP baseline, shield loader, string bridge.
- [Phase VII](phase7/detection-inventory.md) — detection inventory and layers.
- [Phase VIII](phase8/README.md) — unrooted differential and VMP attribution.
- [Phase IX](phase9/README.md) — network, VPN, activation context.
- [Phase X](phase10/README.md) — managed call-site inventory.
- [Phase XI](phase11/README.md) — VMP format and native pipeline.

## Evidence handling

Raw evidence paths mentioned by the private reports are intentionally omitted or
replaced by `private evidence (withheld)`. Hashes and counts in the public reports
refer to the preserved private sample and can be checked only by a lawful holder
of the same input. The public data excerpts are in [`../data`](../data/README.md).

The Phase X manifest mismatch is documented in
[the Phase X audit](phase11/phase10_audit.md): two inventory files and the Phase X
executive summary had stale hash/size entries in the private manifest. The
originals were preserved; this release does not silently repair historical
evidence.
