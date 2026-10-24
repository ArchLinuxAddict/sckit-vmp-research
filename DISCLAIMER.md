# Disclaimer

**Read this before using or redistributing anything in this repository.**

## A. Independent research and non-endorsement

This repository documents independent technical research. It is **not** an
official project, release, certification, audit, or endorsement of SCKit, the
application developer, any government department or agency, Google, Firebase,
Samsung, or any other third party. No affiliation, partnership, sponsorship,
vendor authorization, or approval is claimed.

The research used a preserved local sample and private test environments. A
technical ability to inspect or run a copy of software does not imply that the
vendor or any other party approved this analysis.

## B. Authorization and scope

Access to a device or an APK does not by itself establish authorization to
modify, redistribute, circumvent, or interfere with that software or any service
it uses. The private investigation was structured around static analysis and
observation. It did not patch, repack, or reinstall a modified third-party APK
and did not claim that production security, integrity, licensing, or activation
checks were bypassed.

This public repository contains analysis, selected derived metadata, and
self-contained tests. It does **not** contain a production APK, DEX file, native
library, VMP asset, captured traffic, screenshots, device logs, activation key,
credential, or bypass patch. No vendor authorization is asserted; if you need
authorization, obtain it from the relevant rights holder.

## C. Educational and research purpose

The materials are published to support understanding of:

- binary container formats and managed/native execution;
- reverse-engineering methodology and evidence preservation;
- the difference between observations, correlations, interpretations, and
  demonstrated causation;
- reproducible analysis and responsible handling of sensitive artifacts.

“Educational” or “research” is a description of purpose, not a legal safe harbor
and not a substitute for authorization, licensing, or compliance.

## D. No legal advice

This repository is not legal advice. Copyright, contract, privacy,
anti-circumvention, computer-misuse, trade-secret, export, and other rules vary
by jurisdiction and by the agreements that apply to a particular copy of
software. Readers are responsible for determining whether their access, use,
analysis, or redistribution is lawful and authorized. Nothing here asserts that
reverse engineering is universally legal or illegal.

## E. Intellectual property and third-party materials

Third-party names, package identifiers, class/method names, product names,
logos, and trademarks remain the property of their respective rights holders.
They are used nominatively to identify the subject of analysis. Publication of an
analysis does not transfer ownership of third-party software and does not grant
permission to redistribute it.

No third-party binary or raw application asset is intentionally included in this
repository. Selected facts, offsets, counts, method names, and derived tables
are included for technical verification. If any rights holder believes an
included item exceeds permissible quotation or fair use, please follow the
reporting route in `SECURITY.md` so it can be reviewed and removed if
appropriate.

## F. No guarantee of completeness or correctness

Findings are tied to the specific preserved sample, versions, device
configurations, toolchain, and observations documented here. Different builds,
devices, server behavior, or environments may behave differently.

The repository distinguishes:

- **CONFIRMED** structures/behaviors;
- **PROBABLE** interpretations;
- **CORRELATED** observations;
- **UNRESOLVED** questions.

The analysis is not guaranteed exhaustive. In particular, the method-code
payload decoder, exact 500/900/300 predicates, `RcIsRooted` semantics,
activation protocol, and TLS application payloads remain unresolved. Do not
generalize the recovered method mapping into a universal detector map.

## G. No warranty

The materials are provided “as is” to the extent permitted by applicable law,
without a promise that they are error-free, complete, merchantable, fit for a
particular purpose, or safe for every environment. Nothing in this disclaimer
purports to exclude liability that cannot legally be excluded.

## H. Use at the reader's responsibility

You are responsible for obtaining appropriate authorization, protecting your
devices and data, validating scripts before execution, and complying with
applicable laws, licenses, and agreements. Do not use this repository to gain
unauthorized access, steal credentials, tamper with production entitlements, or
evade protections on systems you do not own or have permission to test.

## I. No production-bypass distribution

This release is intended to document analysis, not to distribute production
bypass patches, forged activation credentials, modified third-party binaries, or
instructions for defeating security controls. The public tree intentionally
excludes such material. If you believe otherwise, report the specific file and
claim so it can be reviewed.

## J. Privacy and sensitive data

The public release was reviewed for credentials, device identifiers, personal
data, private configuration, and sensitive packet payloads. Raw logs, captures,
screenshots, full string inventories, and device-bound values are excluded.
Exact IP addresses, PIDs/UIDs, serial numbers, Android IDs, and the
project-specific Firebase identifier are withheld.

If you discover accidental sensitive data, use the repository's private security
reporting channel when one is available. Do not republish the suspected data.

## K. Security reporting

If this repository is hosted on GitHub, use the repository's **Security →
Report a vulnerability** / private security-advisory flow. No private email
address is invented here, and no response-time guarantee is made. Reports about
accidental secrets or personal data should identify the file and category
without repeating the sensitive value.

## L. Governing legal obligations

This disclaimer does not waive rights or obligations established by applicable
law or valid agreements. It does not authorize activity that the reader
otherwise lacks permission to perform. Where this repository's statements
conflict with a valid license, contract, or law, those obligations control.

## M. Explicit unresolved findings

Do not treat the following as solved:

- the exact encoding/decoding of the variable method-code payload into IR;
- the exact root, Frida, or VPN predicate and its VMP method/native address;
- the throw site and causal role of `Please don't try to crack me!!!`;
- the producer/consumer/semantics of `RcIsRooted`;
- the activation request/response schema and `STATUS: ONLINE` meaning;
- TLS application payloads or complete certificate observations;
- the purpose and consumers of the 22,118-byte VMP blob and reference records.

See `docs/limitations.md` and `reports/phase11/unresolved_questions.md` for the
full list. The repository is a bounded research record, not a claim of complete
reverse engineering or a production security assessment.
