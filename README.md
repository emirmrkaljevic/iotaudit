# iotaudit

<!-- mcp-name: io.github.emirmrkaljevic/iotaudit -->

[![CI](https://github.com/emirmrkaljevic/iotaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/emirmrkaljevic/iotaudit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![PyPI](https://img.shields.io/pypi/v/iotaudit.svg)](https://pypi.org/project/iotaudit/)

<p align="center"><a href="https://skintoscan.com/#packages"><img src=".github/assets/skintoscan-support.svg" width="684" alt="Support my open-source work: get a SkinToScan pack"></a><br><sub>If you find this useful, you can support me by getting a SkinToScan pack, my other project. It's a one-time purchase that directly funds my open-source work.</sub></p>
<p align="center"><a href="https://skintoscan.com/checkout/?add-to-cart=138"><img src=".github/assets/skintoscan-pack-1.svg" width="220" alt="Buy Single Picture Check, €4.49"></a> <a href="https://skintoscan.com/checkout/?add-to-cart=139"><img src=".github/assets/skintoscan-pack-5.svg" width="220" alt="Buy 5 Picture Pack, €19.99 (popular)"></a> <a href="https://skintoscan.com/checkout/?add-to-cart=140"><img src=".github/assets/skintoscan-pack-15.svg" width="220" alt="Buy 15 Picture Pack, €54.99"></a></p>

iotaudit is for anyone who wants a straight answer about their own smart-home devices: cameras, plugs, feeders, bulbs, doorbells, and the rest. It watches what a device does on your network and gives each one an A-F grade, a one-line safety verdict, and a one-page HTML report. Everything runs locally: no account, no telemetry, no cloud.

I wrote it for the cheap gadgets that end up on a home Wi-Fi. The questions are usually the same: who does it talk to, is that traffic encrypted, are any surprising ports open, and did anything change since last time.

## Install

```bash
pipx install iotaudit
```

Capturing traffic needs root (`sudo`). An optional port scan needs `nmap`. PDF export and the MCP server are extras: `pip install "iotaudit[pdf]"` and `pip install "iotaudit[mcp]"`. More install notes, including how to get `iotaudit` onto macOS sudo's PATH, are in the [usage guide](docs/usage.md).

## Quick start

One command asks you to confirm this is your network, finds devices, runs the safe checks, captures passively, and writes the report:

```bash
sudo iotaudit auto
```

Files land in `~/iotaudit/YYYY-MM-DD/` as HTML and JSON (and a PDF if that extra is installed). If you already have a capture from Wireshark, your router, OpenWrt `tcpdump`, or PCAPdroid, analyse it without root:

```bash
iotaudit analyze capture.pcap
```

Skip the typed confirmation with `--i-own-this-network` once you already know this is your network. To pull one device's traffic through this computer, use ARP or hotspot mode. See [capture modes](docs/modes.md).

## What it does

- A one-line verdict next to the grade. Open ports, public DNS (including DNS-over-TLS and DNS-over-HTTPS), TLS or plaintext, and destination countries are observed facts. Video, audio, and other traffic patterns stay indicators with a confidence.
- Who the device talks to: domains (DNS, TLS SNI, HTTP Host), IPs, country, organisation.
- Encryption: plaintext HTTP, unencrypted TCP, old TLS, or high-entropy "custom" protocols.
- Optional nmap port scan with risk notes, a read-only UPnP port-forward list, an idle-upload check, and a traffic timeline.
- Offline known-issue hints when a banner matches a curated CVE. A hint changes the grade only in a narrow case; details are in [device profiles](docs/device-profiles.md).
- Turn a saved audit into a shareable profile draft with `iotaudit profile export` (see [device profiles](docs/device-profiles.md)).
- `iotaudit diff` (and `--compare`) to see what changed since the last audit.
- HTML and PDF reports, CSV or Markdown export, and `--redact` when you want to share a report without local addresses.
- Grades can go into Home Assistant over MQTT (`--ha-mqtt`, with discovery so sensors appear without YAML) or as a JSON file (`--ha-json`). See the [Home Assistant guide](https://emirmrkaljevic.github.io/iotaudit/home-assistant.html).

Current release is **0.1.23**. A [sample report](docs/sample-report.html) and a short demo are on the [report page](docs/report.md). A full vulnerability feed is still on the [roadmap](ROADMAP.md).

![iotaudit auto demo (sample data)](docs/auto-demo.svg)

## MCP server

```bash
pip install "iotaudit[mcp]"
iotaudit-mcp
```

This starts a local MCP server (stdio) so a client on your machine can run the same audit tools. `diff_results` compares two saved JSON audits the same way `iotaudit diff` does. The server is listed on [mcpservers.org](https://mcpservers.org/servers/emirmrkaljevic/iotaudit) and the official MCP Registry. Tool list and options: [MCP server](docs/mcp.md).

## Consent and scope

iotaudit only audits your own network and your own devices. It refuses non-private targets and requires `--i-own-this-network` or an interactive `I OWN THIS NETWORK` confirmation. ARP or NDP spoofing on a network you do not own may be illegal. All data stays local. There is no telemetry.

Findings are indicators based on observed traffic, not proof of wrongdoing by any vendor. IP geolocation by [DB-IP](https://db-ip.com). MIT licensed.

## Docs

- [Usage](docs/usage.md): install, `auto`, PDF, `diff`, cron, export, credcheck, UPnP, and the web UI
- [Capture modes](docs/modes.md): ARP, hotspot, IPv6, and P2P video
- [Reports](docs/report.md): sample report, PDF, sharing and redaction
- [DNS that bypasses your resolver](docs/dns-bypass.md)
- [Device profiles and known-issue hints](docs/device-profiles.md)
- [Home Assistant](https://emirmrkaljevic.github.io/iotaudit/home-assistant.html)
- [Web UI and phones](docs/phones.md)
- [Share results](https://emirmrkaljevic.github.io/iotaudit/share-results.html)
- [What common devices send](https://emirmrkaljevic.github.io/iotaudit/)
- [Changelog](CHANGELOG.md) and [roadmap](ROADMAP.md)
