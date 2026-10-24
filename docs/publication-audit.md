# Publication audit

**Audit date:** 2026-10-24
**Release tree:** `public-release/` (sanitized subset of the private project)
**Status:** local release candidate; **no GitHub remote/push verified**.

## 1. Scope and release decision

The private project contains the original APK, DEX/native libraries, the VMP
asset, raw captures/logs/screenshots, generated tool stacks, and full inventories.
Those are not safe to publish merely because they are locally available.
The release contains only documentation, selected derived data, original analysis
code, and self-contained tests.

**Decision:** publish the sanitized analysis only. Do not publish third-party
binaries, raw evidence, full extracted strings, full method/call-site inventories,
or material whose redistribution rights were not established.

## 2. Allowlist (included)

| Category | Included files |
|---|---|
| Top-level policy | `README.md`, `DISCLAIMER.md`, `CONTRIBUTING.md`, `SECURITY.md`, `.gitignore` |
| Documentation | `docs/overview.md`, `methodology.md`, `architecture.md`, `phase-history.md`, `findings.md`, `limitations.md`, `reproduction.md`, `ethics-and-scope.md`, `publication-audit.md` |
| Sanitized reports | selected Phase VI–XI summaries under `reports/` |
| Derived data | `opcode_dispatch.csv`, method-record excerpt, crosswalk excerpt, source hashes, public summary |
| Code | `scripts/phase11/vmp_format.py`, `scripts/phase11/analyze_native_opcodes.py`, `scripts/check_public_release.py` |
| Tests/examples | self-contained `tests/`, synthetic 108-byte `examples/minimal-vmp/minimal.dat` |

No `LICENSE` file is included because a repository-wide license could not be
established for all material.

## 3. Exclusions (not included)

| Category | Reason | Handling |
|---|---|---|
| Original/resigned APK, DEX, native `.so`, VMP asset, engine binaries | Third-party/proprietary; redistribution rights not established | private originals; hashes only |
| PCAP/PCAPNG, DNS/socket maps, raw traffic | privacy; unrelated device traffic; sensitive metadata | private; sanitized endpoint-level summary only |
| Screenshots, logcat, Frida/ADB output, device JSON | device IDs, serials, paths, personal/environmental data | private; no public copies |
| Full 6,004-string inventory | third-party application text/data | private; selected structural/UI examples only |
| Full 1,845-method and 607/117 call-site inventories | third-party source/context; rights and scope review | private; selected IDs only |
| Raw Ghidra/decompiled output and function indexes | derived proprietary code; size | private; addresses/selected pseudocode summary only |
| Tooling/1.7 GB local environment, caches, Git-ignored files | not research artifacts; unnecessary | excluded |
| Activation material, credentials, keys, tokens | sensitive/unauthorized | none observed/used/included |

## 4. Automated and manual checks

- `python3 -m unittest discover -s tests -v` — public result recorded below.
- `python3 scripts/check_public_release.py` — checks required docs, relative
  links/anchors, forbidden suffixes, oversized files, known sensitive patterns,
  JSON/CSV shape, and opcode counts.
- Manual review of every staged filename, README/disclaimer, reports, data
  excerpts, and synthetic fixture.
- Private full-suite result retained from the source project:
  **117 run, 115 passed, 2 skipped, 0 failed**; Phase XI **24/24**.
- No scanner pass is treated as a substitute for content review.

**Public test result:** 14 tests run, 14 passed, 0 skipped, 0 failed (localhost, final release run; rerun the command above to verify).

## 5. Sensitive-data findings

- Exact Firebase project identifier, public-sector API host, IPs, device models,
  Android IDs, PIDs/UIDs, serials, screenshots, and raw logs are excluded.
- Public reports use categories/placeholders; no live credential or activation
  key is included.
- The synthetic fixture contains only `X` and zero metadata, not app data.
- No Git history existed in the private project; the release repository was
  initialized fresh, so no previously committed secret history is inherited.

## 6. Phase X inconsistency

The private `reports/phase10/evidence_manifest.json` records older hashes/sizes
for `vmp_invoke_inventory.csv`, `vmp_log_invoke_inventory.csv`, and the Phase X
executive summary. The files were preserved, not retroactively “fixed”. The
public Phase XI audit documents the mismatch. This does not affect the recovered
counts (607 app sites, 117 log sites) or the selected Phase XI records, which were
re-read directly.

## 7. Licensing and attribution

No blanket license is granted. Third-party names/trademarks remain with their
owners. Quoted technical facts and selected identifiers are used for analysis;
raw third-party expression is withheld. If a rights holder identifies an included
item that exceeds permissible use, it can be reviewed/removed.

## 8. GitHub / remote status

Publication was performed with GitHub CLI 2.103.2 after authenticated login to
**ArchLinuxAddict**. Verified repository:

- URL: https://github.com/ArchLinuxAddict/sckit-vmp-research
- visibility: **PUBLIC**
- default branch: `main`
- initial verified release commit:
  `e63475171d3155a42d0b76883a7c82952ca700d3`
- remote tree: 51 blobs; no excluded binary/capture paths found
- license metadata: absent (`null`), matching the intentional no-license
  decision

Local history before publication:

- `f2f01bb` — `Document sanitized SckitVMP Phase VI-XI research`
- `e634751` — `Record local release audit and public allowlist`

This documentation update is the final post-push commit; the repository HEAD at
verification is reported in the release summary. The remote `origin` points only
to the repository above.

## 9. Residual release risks

- Derived method/class names and addresses are still third-party-adjacent; legal
  review may be needed before publication.
- The public tests cannot reproduce private runtime/detection claims; those
  remain observation/correlation evidence.
- The exact detector/activation questions remain unresolved and are not presented
  as solved.
- A future remote push must re-run the audit against the actual staged tree;
  this file is not a substitute for that final gate.
