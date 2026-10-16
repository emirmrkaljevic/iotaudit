# iotaudit

[![CI](https://github.com/emirmrkaljevic/iotaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/emirmrkaljevic/iotaudit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Is your smart pet feeder, camera or plug safe?** `iotaudit` watches what your own IoT devices
do on the network and gives each one an **A–F grade** with a one-page HTML report:

- **Who it talks to** – domains (from DNS + TLS SNI + HTTP Host), IPs, country, organisation
- **Encrypted or not** – flags plaintext HTTP / unencrypted TCP, outdated TLS 1.0/1.1
- **Trackers** – analytics/telemetry endpoints
- **Expected vs unexpected** – compares traffic against community **device profiles** (YAML)
- **Open ports** – optional `nmap` scan with risk notes (telnet, RTSP, UPnP, ADB, ...)
- **MCP server** – let your assistant run "audit my pet feeder" locally

Everything runs locally. No account, no telemetry, no cloud.

> Status: early (0.0.x). Hotspot capture, pcap analysis, grading, report and MCP server work;
> CVE lookup, UPnP checks, ARP mode and idle-upload detection are on the roadmap.

## Install

```bash
pip install git+https://github.com/emirmrkaljevic/iotaudit   # PyPI release coming soon
pip install "iotaudit[mcp,geo] @ git+https://github.com/emirmrkaljevic/iotaudit"
sudo apt install nmap            # optional, for --scan
```

Linux with NetworkManager is needed for hotspot mode. Capturing requires root (or `CAP_NET_RAW`).

## Quick start

**1. Hotspot mode (recommended).** Your laptop becomes a Wi-Fi access point; re-pair the device to it.
No traffic interception on anyone else's network.

```bash
sudo iotaudit capture --mode hotspot --iface wlan0 --ssid iotaudit --password 'choose-a-pass' \
     --duration 900 --device 10.42.0.50 --scan --out feeder.html
```

Use the companion app normally (feed, stream, update) during the capture, then leave the device idle.

**2. Existing pcap** (from Wireshark, your router, OpenWrt `tcpdump`, ...):

```bash
iotaudit analyze capture.pcap --device 192.168.1.50 --json results.json
```

**3. Port scan only:** `iotaudit scan 192.168.1.50`

Countries: download a free country database (GeoLite2-Country or DB-IP Lite `.mmdb`) and pass
`--geoip path.mmdb` or set `IOTAUDIT_GEOIP`. MAC vendors: set `IOTAUDIT_OUI` to an IEEE `oui.txt`.

## Grading

Score starts at 100; each finding subtracts points (high 25, medium 10, low 4).
A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 45, E ≥ 30, F below.

## Device profiles

Profiles live in [`src/iotaudit/profiles/`](src/iotaudit/profiles). Add your own with `--profiles DIR`.

```yaml
id: tuya-generic
name: Tuya-based smart device
match:
  mac_vendors: ["Tuya", "Espressif"]
  domains: ["tuyaeu.com", "tuyaus.com"]
expected_domains: ["tuyaeu.com", "tuya.com", "ntp.org"]
expected_ports: [443, 8883, 123]
notes: "MQTT over TLS to the Tuya region cloud."
```

PRs with profiles for your devices are very welcome.

## MCP server

```json
{ "mcpServers": { "iotaudit": { "command": "iotaudit-mcp" } } }
```

Tools: `analyze_pcap`, `capture`, `scan_device`. Capture and scan require explicit
`i_own_this_network=true` confirmation.

## Legal & consent

- **Only use iotaudit on networks you own or administer and on devices you own** (or have written
  permission to test). Intercepting or scanning other people's networks or devices is a criminal
  offence in most jurisdictions (e.g. EU Directive 2013/40/EU, US CFAA).
- Every capture/scan asks you to type a consent phrase (or pass `--i-own-this-network`).
- Hotspot mode is the default because it does not interfere with anyone else's traffic.
- The scanner refuses public IP addresses.
- Captured data stays on your machine. Reports may contain personal data – share them carefully.
- Results are **indicators based on observed traffic**, not proof of wrongdoing by any vendor.

## Roadmap

- CVE lookup (OSV / NVD / CISA KEV) from service banners
- UPnP IGD port-forward check on your router
- "Uploading while idle" heuristic for cameras
- ARP mode (own network only, extra consent)
- Larger tracker list and device profile library
- PDF export, continuous mode

## License

MIT
