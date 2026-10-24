# Overview

This repository is a sanitized, reproducible record of one reverse-engineering
investigation: the static reconstruction of the `SckitVMP` container used by a
preserved Android application and the native `libsnehakimakichut.so` runtime.

The research is deliberately split into two claims that are often conflated:

1. **The container and parts of the execution pipeline were reconstructed.** The
   header, sections, string transform, method records, native bridge, inner
   invoke, and address-level opcode table have direct structural evidence.
2. **The production detection predicates were not fully identified.** Runtime
   observations establish that root/Frida/VPN outcomes occur, but the specific
   VMP method or native predicate that causes each outcome remains unresolved.

The public tree contains the second kind of claim only where the evidence
supports it. It does not present a detector map, a bypass, or a complete
activation implementation.

## Audience

- reverse-engineering researchers evaluating the format/pipeline model;
- software engineers interested in managed/native VM bridges and evidence-driven
  analysis;
- readers assessing the reliability, scope, and legitimacy of the research.

## Release composition

Included:

- comprehensive documentation and sanitized phase reports;
- original Phase XI parser/opcode extractor code;
- selected derived data: opcode addresses, method-record excerpt, crosswalk
  excerpt, hashes, and aggregate counts;
- self-contained tests and a synthetic minimal container.

Excluded:

- APK/DEX/native/VMP binaries;
- pcap/pcapng, screenshots, logcat, Frida/ADB output;
- full string/method/call-site inventories;
- device IDs, IPs, PIDs/UIDs, credentials, activation material;
- tool binaries and private raw evidence.

See [publication audit](publication-audit.md) and
[ethics and scope](ethics-and-scope.md).
