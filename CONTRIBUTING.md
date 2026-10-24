# Contributing

Contributions are welcome when they improve evidence quality, reproducibility,
or clarity without expanding the repository's sensitive-data or bypass surface.

## Ground rules

- Do not submit APKs, DEX files, native libraries, VMP assets, packet captures,
  screenshots, device logs, raw application strings, credentials, device IDs,
  personal data, or proprietary configuration.
- Do not submit root/Frida/VPN/integrity/licensing/anti-tamper bypass tooling or
  operational instructions for defeating production controls.
- Do not guess activation keys, forge tokens, or manipulate production servers.
- Keep third-party names nominative and do not imply vendor affiliation.
- State whether a claim is CONFIRMED, PROBABLE, CORRELATED, or UNRESOLVED and
  identify the evidence class.

## Reproducing a claim

1. Describe the matching input version/hash and how it can be lawfully obtained.
2. Provide a minimal script or command that works from repository-relative paths.
3. Include a test for structural claims where practical.
4. Explain expected output and negative/malformed cases.
5. Use synthetic or sanitized fixtures; never attach private evidence.

## Pull-request checklist

- [ ] No forbidden binary or sensitive artifact added.
- [ ] Documentation links resolve.
- [ ] `python3 -m unittest discover -s tests -v` passes.
- [ ] `python3 scripts/check_public_release.py` passes.
- [ ] New claims include status and evidence references.
- [ ] Third-party attribution/licensing statements remain accurate.
- [ ] No vendor authorization or affiliation is implied without evidence.

## Corrections

If a historical report contains a material error, preserve the original and add
a dated/versioned correction note. Do not silently rewrite evidence. The Phase X
manifest discrepancy and Phase XI count-semantics corrections are examples of the
required transparent approach.

## License

No contributor license or repository-wide license is currently asserted because
rights for all material have not been established. By contributing, you confirm
that you have the right to submit your contribution and agree that it may be
removed if a rights or privacy concern is validated.
