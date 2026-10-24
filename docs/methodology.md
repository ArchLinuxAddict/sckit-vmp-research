# Methodology

## Evidence classes

| Class | Definition | Example |
|---|---|---|
| Static observation | Bytes/structures/control flow that can be re-read from an input | `SckitVMP` header, section boundaries, XOR loop |
| Runtime observation | Behavior recorded on a specific device/build | 500/900/300 UI outcomes |
| Correlation | Two observations placed in a shared timeline/context | DNS/TCP before root error |
| Interpretation | Mechanism that fits evidence but lacks a demonstrated predicate | security-gated branch in `inner_invoke` |
| Hypothesis | Explicit unanswered possibility | section-5 blob role |

The reports label these rather than using “confirmed” for an interpretation.

## Workflow

1. Preserve the input and record hashes.
2. Extract static structures with a script; validate the entire collection, not
   one record.
3. Map managed call sites to native registration/bridge functions.
4. During runtime work, separate device behavior from static structure and keep
   raw evidence private.
5. When a result is surprising, look for alternative explanations: method ID vs
   opcode, animation callback vs detector, network correlation vs causation.
6. Reproduce the public subset with tests; mark input-gated/private tests as such.
7. Before release, audit artifacts for third-party binaries, secrets, personal
   data, and unsupported claims.

## Confidence discipline

- A byte-offset match for all 724 code records supports a **format** claim.
- A method-name lookup that matches known Java call sites supports an **ID
  mapping** claim.
- A Frida-time exception at an animation callback does **not** establish that
  the callback is a detector.
- A pcap showing traffic before an error does **not** establish that the traffic
  caused the error.
- A heuristic class-name category does **not** establish semantics.

## Sanitization

The private originals remain separate. Public reports replace local paths,
device models, network addresses, process IDs, project-specific endpoints, and
full extracted strings with categories or redacted placeholders. The audit in
`publication-audit.md` records the exclusions. Historical inconsistencies are
retained and documented rather than silently rewritten.
