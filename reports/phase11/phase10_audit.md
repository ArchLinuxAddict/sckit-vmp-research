# Phase X artifact audit

## Inputs re-verified in Phase XI

| Artifact | Size | SHA-256 |
|---|---:|---|
| `<private-artifact>` | 5,983,863 | `96330aaf76d1c2ea99591189d10f06ecd454504721e96af8ad777e8e512d7292` |
| `resources/assets/sckit-vmp+.vmp` | 562,963 | `4108ca26ce6ebcb9252e644c4d1d00a08693ad232990649ef06a72cbe636d232` |
| `native/lib__arm64-v8a__libsnehakimakichut.so` | 443,280 | `091b06ee3cdf2ea3521a45542aebd25f60219484b93ae62ad204f5cc868da230` |

The APK/asset/library hashes were unchanged during Phase XI. All parser tests ran
against copies or in-memory mutations.

## Phase X report hashes

| File | Bytes | SHA-256 |
|---|---:|---|
| `activation_flow.md` | 1,920 | `c1b0af2bf306c9f3db872fd329a2e74bd5141e46d4e726e570b379a8825fb73a` |
| `correlated_timeline.md` | 1,654 | `623e26f16ad23067ba538d311e4aa86a0bd53fe9cfda3072f8a1ce04f3ee355d` |
| `evidence_gaps.md` | 1,252 | `5be132189f954c41d837004de8b67f50b201f76e2385c8c2ce0fc87594f76311` |
| `evidence_manifest.json` | 4,669 | `6e697efddbbf49b83a5b3111e13005cbfd797ed974aa70511ab3749aab366c24` |
| `executive_summary.md` | 3,363 | `ebb37053e742549f7523145259c88b6b7b5c92b049486f4d24bc8c8aa01c7dcc` |
| `frida_detection_trace.md` | 1,295 | `3a12946ab26edd7859d3985950b7b0261dea5946d5966a011436c4ef92dd89d6` |
| `reproduction_steps.md` | 1,094 | `66c4982e6515bbe876946d462772759c5447d77059f60c1031faa20eb39980d6` |
| `root_detection_trace.md` | 2,079 | `2b7fc68fdbed80674c9adbfe6c9c58e644ca93e3a5ca9293bb7a01cdfff37925` |
| `vmp_invoke_inventory.csv` | 205,399 | `05fc9cd6a8dd7b4aa0cc164253bed591a3be81530cd442b5388225fcd9c87d14` |
| `vmp_log_invoke_inventory.csv` | 40,452 | `d5925a28b7d1a85ada99cb3c583b571fb2ccec7ce6fbf21a9134c51b7088d45d` |
| `vmp_method_mapping.md` | 3,804 | `3912f90ab92b59c4119fb42b5f5634853bf9f7b1b69deb48fdc44ba748e792ff` |
| `vpn_detection_trace.md` | 1,342 | `38ae562801270d0af1d4e7b19741cabc817cd762690280d0543fbc983c183e06` |

## Manifest discrepancy (recorded, not repaired)

`reports/phase10/evidence_manifest.json` records older hashes/sizes for two
inventories and for `executive_summary.md`:

| File | Phase X manifest | Current |
|---|---|---|
| `vmp_invoke_inventory.csv` | 191,479 / `937a071d…` | 205,399 / `05fc9cd6…` |
| `vmp_log_invoke_inventory.csv` | 38,931 / `0998dcab…` | 40,452 / `d5925a28…` |
| `executive_summary.md` | 3,363 / `64de6fb2…` | 3,363 / `ebb37053…` |

The other Phase X reports match their manifest entries. Phase XI did **not**
overwrite these files. The discrepancy is preserved as an audit finding; the
current inventories are the copies used for the Phase XI crosswalk, and their
site counts/contents were checked directly (607 app sites, 117 log sites). No
attempt was made to rewrite the Phase X manifest retrospectively.

## Conclusions retained from Phase X

- Rooted baseline observed 500/root; unrooted baseline passed the root gate.
- Frida spawn observed 900/Frida; anti-crack exception observed at
  `invoke(1839)`/`1744`.
- VPN observed 300/VPN.
- `invoke(1839)` is an animation callback; retained.
- `isPmsHooked` at `libScKitShieldV1` `0x165e48` is a separate PMS-hook check.
- `RcIsRooted` remains an unexplained Bundle field.
- Activation reached the VIP screen only without root/VPN, and no key was
  supplied.

Phase XI adds the VMP format/native/ID mapping; it does not overwrite these
behavioral observations.

---

*Public sanitized edition. Private raw artifacts, full inventories, and device/network identifiers are withheld; see `docs/publication-audit.md`.*
