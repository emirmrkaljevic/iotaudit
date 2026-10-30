# Changelog

All notable changes to iotaudit are documented here. This project follows
[Semantic Versioning](https://semver.org/).

## [0.1.12] - 2026-10-30

### Added
- **Home Assistant summary.** `iotaudit auto --ha-json PATH` and
  `iotaudit export AUDIT.json [--compare PREV.json] [--out PATH]` write a
  compact JSON file: per device name, IP, grade, finding count, and whether it
  changed since the previous audit, plus totals and the worst grade. A
  `command_line` sensor can read it. Example YAML in the docs:
  https://emirmrkaljevic.github.io/iotaudit/home-assistant.html

## [0.1.11] - 2026-10-27

### Added
- **`iotaudit auto`.** One command for a network you own. It asks for the
  ownership phrase (or accepts the existing `--i-own-this-network` flag),
  picks the interface that has the default route, discovers devices, identifies
  them, scans ports with nmap, lists UPnP forwards (read-only), and captures
  passively for 60 seconds with a progress line. It writes HTML and JSON in
  `~/iotaudit/YYYY-MM-DD/`, plus a PDF when `iotaudit[pdf]` is installed.
  If that folder already has a JSON audit, the new run is compared with the
  latest one and the exit code matches `iotaudit diff`. Each device is printed
  on one line, then the report path.
- Missing `nmap` or `tcpdump` stops the command with the install line for this
  computer: `brew install ...` on macOS, `sudo apt install ...` on Debian and
  Ubuntu, and `dnf`, `pacman`, or `zypper` when that is the package manager.

### Notes
- `--yes` stays only on `iotaudit credcheck`. `auto` does not add another way
  to skip a confirmation, and it does not try default passwords.
- Passive capture does not ARP-spoof and does not start a hotspot. On a normal
  Wi-Fi network, traffic between two other devices may never reach this
  computer. Use `iotaudit capture --mode arp` when you need that.
- The first run in a dated folder has nothing to compare. A later run the same
  day compares with the latest JSON already in that folder, not with yesterday.
- The gateway is included in discovery and in the port scan. This computer is not.

## [0.1.10] - 2026-10-26

### Added
- **Offline known-issue hints.** A small curated catalog shipped in the package
  maps banners iotaudit already observed (nmap product and version, HTTP
  `Server`, UPnP and SSDP headers, and an RTSP response that did not ask for
  authentication) to a public NVD CVE page. Each hint says it is possible,
  based on the version string, and that the firmware still has to be checked.
  There is no network lookup and no update command. The list is whatever
  shipped with this release.
- Hints are on each device as `known_issue_hints` in the JSON report, in the
  HTML report (and therefore the PDF), and in the MCP `analyze_pcap` result.

### Grade rule
- A hint does not change the A-F grade unless both are true: the observed
  version string equals a version the entry lists exactly, and the entry
  severity is critical. That case subtracts 25 points, the same as one high
  finding, after the limited-data cap. A version range, an open service with
  no matching version, or any severity other than critical leaves the score
  unchanged.

## [0.1.9] - 2026-10-25

### Added
- **`iotaudit diff OLD.json NEW.json`.** Compares two saved JSON audits. Devices
  match by MAC, then by IP. The report lists new and gone destination domains
  and IPs, new countries, new open ports, grade changes, verdict changes,
  newly seen unencrypted traffic, and new UPnP forwards when the JSON includes
  them. Plain text by default. `--json` prints the same result for scripts.
  Exit code 1 when something security-relevant appeared, and 0 otherwise, so
  cron can alert. Missing or unreadable input exits 2.
- **`--compare PREV.json`** on `capture` and `analyze`. After the HTML and JSON
  report, print that diff against an earlier audit and use the same exit code.
- MCP tool `diff_results` with the same comparison.

### Notes
- A change is security-relevant when a device, destination domain, destination
  IP, country, open port, worse grade, unencrypted flow, or UPnP forward
  appeared. Something that only went away, or a grade that improved, is
  reported and does not by itself exit 1. A verdict change is reported and
  does not by itself exit 1.

## [0.1.8] - 2026-10-24

### Added
- **PDF export.** `iotaudit analyze` and `iotaudit capture` take `--pdf` and write a PDF
  next to the HTML report. `iotaudit report --pdf <json-or-html>` converts a saved JSON
  or HTML report. Install the optional extra with `pip install "iotaudit[pdf]"` (xhtml2pdf,
  pure Python, no Cairo or Pango). If that extra is missing, the command prints one install
  line instead of crashing. Analyze and capture still write the HTML.
- Print styles so each device starts with its grade and verdict, table rows stay on one
  page, and the destination table header repeats. The on-screen traffic chart is omitted
  from print and PDF.
- MCP `analyze_pcap` accepts `pdf=true`. With `report_path` set, it writes the PDF beside
  the HTML.

## [0.1.7] - 2026-10-23

### Changed
- Use synthetic MAC, CGNAT, and LAN addresses across all sample reports and test
  fixtures.

## [0.1.6] - 2026-10-23

### Added
- **Per-device safety verdict.** Each device now has a `verdict` string in the JSON
  report and a one-line verdict beside the grade in the HTML report. The longer
  `summary` paragraph is unchanged. Observed facts (risky open ports, hardcoded
  public DNS, TLS versus plaintext, destination countries from the local GeoIP
  lookup) are stated plainly. Traffic patterns stay indicators: a match carries
  a confidence and is not a claim about what was sent, and the line does not
  accuse a vendor.

## [0.1.5] - 2026-10-22

### Added
- **Per-device destination countries** in the HTML report and in the device JSON
  (`destination_countries`). Each country is an observed fact: a local lookup of an IP
  the device contacted, with destination and byte counts. Confidence is certain.
- **Traffic-pattern confidence** for video, audio, telemetry, and unknown. The report,
  the plain-English findings, and `traffic_patterns` in the device JSON word each match
  as an indicator with low, medium, or high confidence. A pattern match is not proof of
  what was sent.

### Changed
- User-facing sentences (findings, report text, and related detail) no longer use em dashes.
  They use commas, periods, or parentheses.

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
does on the network and gives it an A-F grade with a one-page HTML report.

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
