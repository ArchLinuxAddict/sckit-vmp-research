# Phase IX — network, VPN, and activation context

## Objective

Correlate runtime network activity with the observed root gate, attempt an
unrooted capture without modifying production protections, and document the
activation UI context.

## Results

- On the rooted device, the app resolved and connected to a public-sector
  attendance API and a Firebase RTDB endpoint before the root-error activity.
  Socket attribution tied the flows to the target process at capture time.
- The sequence is **temporal correlation**, not proof that a response caused the
  root decision.
- A PCAPdroid VPN attempt on the unrooted device produced observed error 300/VPN.
  The capture method itself changed the environment and prevented the VIP flow.
- The unrooted, non-VPN run reached the activation/VIP dialog with a
  device-bound identifier and `STATUS: ONLINE`; no key was entered.
- TLS application payloads and certificate details were not recovered.

## Reports

- [Network forensics](network-forensics.md)

## Boundaries

Raw pcap/pcapng, screenshots, exact IPs, PIDs/UIDs, device identifiers, packet
payloads, and project-specific Firebase identifiers are withheld. No TLS
decryption, pinning bypass, CA installation, proxy, key guessing, or server
manipulation was performed.

The private Phase IX suite reported **88 tests: 86 passed, 2 skipped, 0 failed**;
the experiment matrix had 8 passed / 5 blocked. Public tests are separate.
