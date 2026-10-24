# Phase XI — SckitVMP binary reconstruction

Phase XI is the final technical phase. It reconstructed the container, decoded
the string table, mapped 1,845 method records, validated 724 code-record IDs,
mapped the native bridge/inner-invoke pipeline, and extracted the 159-entry
opcode handler table.

## Public reports

- [Executive summary](executive_summary.md)
- [VMP format reconstruction](vmp_format_reconstruction.md)
- [Native execution pipeline](native_execution_pipeline.md)
- [Native call graph](native_callgraph.md)
- [Opcode mapping (address-level)](opcode_mapping.md)
- [Detection correlation](detection_correlation.md)
- [Activation and network context](activation_network_context.md)
- [Parser design](parser_design.md)
- [Unresolved questions](unresolved_questions.md)
- [Phase X manifest audit](phase10_audit.md)

## Public data

- [Opcode dispatch table](../../data/opcode_dispatch.csv)
- [Selected method records](../../data/method-record-excerpt.csv)
- [Selected managed/native crosswalk](../../data/managed-native-crosswalk-excerpt.csv)
- [Public evidence summary](../../data/public-evidence-summary.json)

## Withheld evidence

The full 6,004-string inventory, full 1,845-method inventory, full 607/117
call-site inventories, raw Ghidra decompilation, the VMP asset, native library,
APK/DEX files, runtime logs, screenshots, and network captures are withheld. See
[the publication audit](../../docs/publication-audit.md).

## Tests

The private source project reported **24/24 Phase XI tests passing** and a
combined private suite of **117 run, 115 passed, 2 skipped, 0 failed**. The public
repository includes self-contained tests that do not require the proprietary
inputs; their actual result is recorded in the publication audit.
