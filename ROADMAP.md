# iotaudit roadmap

iotaudit aims to be an all-rounder audit for **any** smart device you own: cameras, pet feeders,
plugs, bulbs, TVs, speakers, doorbells, robot vacuums, baby monitors, hubs. The goal is a clear,
plain-English verdict per device, built only from what can be observed on your own network.

**Principles**

- Local-only. No telemetry, no cloud account, no uploads.
- Own networks and own devices only; every active step is behind an explicit consent prompt.
- Facts vs inferences: observed facts are marked `certain`; anything inferred from traffic
  patterns carries a confidence level (`low` / `medium` / `high`) and is worded as an
  *indicator* ("looks like video upload"), never as a certainty or an accusation.

## Data model (in place since 0.0.x)

Every result is a `Finding` with `category`, `severity`, `title`, `detail`, `confidence` and an
`evidence` dict (byte counts, packet-size histograms, timestamps, matched rules). Each destination
can carry a `TrafficClass` (`video`, `audio`, `audio+video`, `telemetry`, `firmware-download`,
`unknown`) with confidence and a `while_app_idle` flag. New analysers only add findings; grading
and reports pick them up automatically. Grading weights inferred findings by confidence (v0.2).

## v0.1.0 – MVP (target: within a few days)

Done in the first commit:
- [x] Hotspot mode (laptop becomes the access point via NetworkManager) and pcap import
- [x] DNS / TLS SNI / HTTP Host extraction, per-device destinations
- [x] Country (local GeoLite2 / DB-IP Lite `.mmdb`), organisation, tracker tagging
- [x] Plaintext vs TLS detection, outdated TLS 1.0/1.1, QUIC
- [x] nmap open-port scan with risk notes
- [x] Device profile library (YAML), A–F grade, HTML report, JSON output
- [x] MCP server (`analyze_pcap`, `capture`, `scan_device`), consent gate, CI

Remaining for v0.1.0:
- [ ] Real-device validation (Tuya-based pet feeder first) and profile tuning
- [ ] Hotspot capture hardening (auto-detect Wi-Fi interface, client list, IPv6)
- [ ] Bundled download helper for the free country database
- [x] Report polish: per-device plain-English summary paragraph, destination country summary
  (0.1.5 also shows video / audio / telemetry / unknown as indicators with confidence)
- [ ] PyPI release, MCP registry listing

## v0.2 – "What is it sending?" (traffic classification)

Plain-English per-device findings such as:
> *Your camera sends data to `xyz.example.com` (Germany, Amazon AWS). Pattern looks like
> **video** (sustained ~1.2 Mbit/s upload, large packets, steady timing) – confidence: medium.
> This also happened while the app was closed.*

- Per-destination time series: bitrate up/down, packet-size distribution, inter-arrival timing
- Heuristics: video (sustained high upload, large near-MTU packets, keyframe bursts),
  audio (steady low bitrate ~20–130 kbit/s, small regular packets), telemetry (small periodic
  heartbeats), firmware download (large one-off downstream burst)
- Protocol hints: RTSP/RTP, WebRTC (STUN/TURN, DTLS-SRTP), P2P relay services, MQTT
- "Upload while app idle": user marks idle periods (CLI prompt / web UI button) or uses the
  phone-traffic timeline (below) to know when the app was open
- Confidence scoring, labelled test captures, documented false-positive cases
- Grading weighted by confidence

## v0.3 – Phone & web UI

- **Web UI** served by the laptop or a Raspberry Pi: start/stop captures, mark "app open/closed",
  view reports from a phone browser on the same network
- **Android**: capture the companion app's own traffic with a local VPN-based capture
  (PCAPdroid-style: `VpnService`, no root). Export pcap or stream to iotaudit; first step is
  documenting how to use PCAPdroid itself, then an optional companion app
- **iOS (honest limits)**: no packet capture on a stock iPhone. Options:
  - capture on the laptop/Pi hotspot (the iPhone joins it) – sees destinations, not app identity
  - `rvictl` remote virtual interface from a Mac over USB (macOS + Xcode tools)
  - a local VPN app (`NEPacketTunnelProvider`) would need a paid Apple developer account and
    App Store review – out of scope for now
  - TLS contents of pinned apps stay hidden; we report metadata only
- Correlate phone-app traffic with device traffic (app open → device starts streaming)

## v0.4 – Security checks

- CVEs per vendor/model/firmware: banner + profile → OSV / NVD / CISA KEV (cached locally)
- [x] Default credentials: short vendor-default list, only on a user-confirmed own device,
  rate-limited, never brute force (0.1.4, `iotaudit credcheck`)
- [x] UPnP IGD: list port forwards on your router and attribute them to devices (0.1.3, read-only)
- DNS bypass: hardcoded resolvers (8.8.8.8 etc.), DNS-over-HTTPS / DoT endpoints
- Device scanning your LAN (ARP sweeps, port probes from the IoT device)
- Firmware update checks: is the device phoning a firmware endpoint, version vs latest known
- Insecure local services: telnet, ADB, unauthenticated RTSP/ONVIF, open MQTT

## v0.5 – Continuous mode

- Raspberry Pi image / OpenWrt package, scheduled reports
- Alerts: new/unexpected device on the network, new destination country, idle upload,
  new open port
- ARP mode (own network only, extra consent) for devices that cannot be moved to a hotspot
- PDF export

## Verdict

Done in 0.1.6. Each device gets a one-line safety verdict on top of the A-F grade, for example
*"D: Telnet open on the LAN; uses public DNS directly; encrypted cloud traffic (US); P2P video setup (stream not observed here)."*
The verdict separates observed facts (open ports, hardcoded public DNS, TLS versus plaintext,
destination countries) from inferred indicators (traffic patterns, worded with a confidence
and never as proof).

## Device coverage

Community YAML profiles per brand/model: expected domains, ports, protocols, known CVEs, notes.
Priority categories: cameras & doorbells, pet feeders, plugs & bulbs (Tuya, Xiaomi, Shelly),
smart TVs, speakers, robot vacuums, baby monitors.

## Distribution

PyPI, MCP registries (official registry, Glama, Smithery, mcp.so), awesome lists
(awesome-mcp-servers, awesome-iot, awesome-privacy, awesome-selfhosted), DEV.to write-ups,
r/homelab, r/privacy, r/selfhosted.
