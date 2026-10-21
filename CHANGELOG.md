# Changelog

All notable changes to iotaudit are documented here. This project follows
[Semantic Versioning](https://semver.org/).

## [0.1.4] - 2026-10-21

### Added
- **`iotaudit credcheck`**: opt-in default-credential check for one device you own. Gated behind
  a typed per-IP confirmation, it tries only a short list of documented vendor default logins
  (telnet/http/ftp), never a wordlist; it is rate-limited, stops at the first accepted login, and
  reports only "default login accepted" (high) or "not accepted" (info). LAN addresses only. Also
  exposed as the MCP tool `default_credential_check`.

## [0.1.3] - 2026-10-20

### Added
- **`iotaudit upnp`**: read-only UPnP IGD audit listing the port forwards your router opened and
  the device each one points to. Runs after `capture` by default (`--no-upnp` to skip; opt-in
  with `--upnp` for `analyze`) and adds a finding for forwards to the audited device. Only
  `GetExternalIPAddress` / `GetGenericPortMappingEntry` are sent, only to private/loopback router
  URLs. Also available as the MCP tool `upnp_port_mappings`.

### Fixed
- The HTML report is now always escaped. Autoescaping did not apply to `report.html.j2`, so
  names taken from the network (SNI, DNS, hostnames) were inserted unescaped; a crafted name
  could inject markup into a report opened from disk. Reports served by `iotaudit web` were
  already protected by a no-script CSP.

## [0.1.2] - 2026-10-19

### Added
- **`iotaudit web`**: a local web UI to view reports, upload a pcap (PCAPdroid supported) and
  run a one-click LAN scan + capture. Binds to `127.0.0.1` by default; `--lan` opts in to phone
  access on the same Wi-Fi. Always token-protected, with Host/Origin checks, private-range
  clients only in LAN mode, and an explicit consent box before capturing.
- `docs/phones.md`: what works on Android (PCAPdroid) and the honest limits on iPhone.

## [0.1.1] - 2026-10-18

### Added
- **Evidence-based device-type identification** (camera, plug/bulb, TV, speaker, robot vacuum,
  printer, NAS, hub, phone, computer). Each signal names its source (open ports, mDNS, SSDP,
  OUI, hostname, and the cloud domains/SNI the device talked to); confidence is "high" only
  when independent sources agree or one is near-conclusive, otherwise "medium"/"low". Shown in
  the report and summary, and attached to each device as `device_type`.
- **PCAPdroid import** for an Android path: `from_pcap` auto-detects PCAPdroid captures, strips
  the bogus Ethernet header + per-packet trailer (so no fake MAC is learned), and records the
  originating app names in `collector.apps`.
- `publish.yml` now also lists the server on the official MCP registry (OIDC) after PyPI.

### Changed
- Shortened `server.json` description to satisfy the MCP registry (<=100 chars).

## [0.1.0] - 2026-10-17

First tagged release. iotaudit audits **your own** smart-home devices: it watches what each one
does on the network and gives it an A–F grade with a one-page HTML report.

### Added
- **Capture modes**: hotspot (Linux/NetworkManager), ARP mode (macOS + Linux, spoofs one owned
  device and restores ARP tables + IP-forwarding on exit), and offline pcap analysis.
- **`--watch-lan`**: also watch device ↔ LAN-peer unicast so phone P2P video is visible.
- **IPv6 / NDP**: capture filter now covers the device's IPv6 and ICMPv6 neighbor discovery;
  IPv6 flows, link-local bytes and NDP messages are counted and shown in the report.
  Experimental `--ipv6-ndp` additionally NDP-spoofs IPv6 link-local pairs.
- **Honest "media not observed" note**: when a device sets up a P2P session (STUN/TURN) but no
  sustained media stream is captured on the LAN, over IPv6 or to the cloud, the report says so
  plainly: the video most likely went straight to your phone over Wi-Fi and was not observed.
- **Special-use / bogon peers**: addresses like `192.0.0.0/24` are no longer mistaken for real
  Wi-Fi devices; they are flagged as placeholder / DS-Lite / P2P-signalling artifacts.
- **Analysis**: per-destination org/country (bundled DB-IP + ip2asn-lite, offline), plaintext
  vs TLS vs custom-encryption (entropy) vs STUN, trackers, device profiles (YAML), time-series
  with burst detection, idle-upload check, `nmap` open-port scan with risk notes.
- **MCP server** (`iotaudit-mcp`) and a consent gate (own-network only).
- `iotaudit.review.review_report()` to re-check a saved JSON report for the not-observed verdict.

### Notes
- Two Wi-Fi clients can exchange media without it passing through your computer (client
  isolation), so "not observed" never means "did not happen". Capture at the router for ground
  truth. iotaudit reports indicators from observed traffic, not proof of vendor wrongdoing.
