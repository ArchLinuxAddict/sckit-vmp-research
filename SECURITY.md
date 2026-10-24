# Security and privacy reporting

## What to report

Please report, privately:

- accidentally published credentials, tokens, private keys, cookies, or
  authentication headers;
- device identifiers, Android IDs, serial numbers, personal data, or private
  configuration;
- unredacted packet payloads, unrelated traffic, or sensitive logs;
- proprietary binaries/assets that should not be redistributed;
- a concrete technical error that could cause a reader to misunderstand a
  security conclusion.

## How to report

If this repository is hosted on GitHub, use **Security → Report a vulnerability**
to open a private security advisory. Do not open a public issue containing the
sensitive value. No private email address or guaranteed response time is
invented by this repository.

A useful report includes the file path, a short description of the category, and
the minimum information needed to locate the item. Do not attach a full capture
or repeat a live secret.

## Scope boundary

This is a research-documentation repository, not a vendor security-response team
and not a product support channel. Reports about the third-party application's
production systems should go to the appropriate vendor/owner through their own
channel. This project will not assist with unauthorized access, bypass, or
credential use.

## Handling

Validated accidental disclosures will be removed or redacted, and the public
history will be reviewed. If a secret was exposed in a remote history, credential
revocation and appropriate history remediation may be required; deleting only
the current file is not sufficient.
