# Phase IX network forensics (sanitized)

## Collection

Private captures used device-side packet capture and socket attribution on a
rooted test device, plus a per-app PCAPdroid VPN attempt on an unrooted device.
Raw captures, exact addresses, capture timestamps, device models, PIDs/UIDs, and
unrelated device traffic are withheld.

## Confirmed observations

- The target process resolved and connected to a public-sector attendance API
  host and a Firebase RTDB endpoint during startup.
- Socket attribution at capture time associated both 443 flows with the target
  process.
- The connections occurred before the root-error activity in the observed
  timeline.
- A PCAPdroid VPN run produced the observed 300/VPN outcome while target DNS/TCP
  attempts were still visible. The VPN method itself changed the environment.
- SNI/host metadata was visible; TLS application payloads were not decrypted.

## Interpretation

The order is compatible with network initialization before the root gate, but
does not establish that a server response causes the root decision. The exact
Firebase project identifier, resolved IPs, timestamps, and packet contents are
withheld. `STATUS: ONLINE` is a UI string, not proven activation/network state.

## Limitations

- No unrooted no-VPN capture was available.
- No TLS decryption or certificate inspection was completed.
- No pinning bypass, CA installation, or proxy was used.
- Raw traffic may include unrelated device DNS; only sanitized endpoint-level
  observations are published.
