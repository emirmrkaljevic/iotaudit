# iotaudit

[![CI](https://github.com/emirmrkaljevic/iotaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/emirmrkaljevic/iotaudit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

<p align="center"><a href="https://skintoscan.com/#packages"><img src="https://img.shields.io/badge/%E2%98%95_Support_me-Get_a_SkinToScan_pack-ff5f5f?style=for-the-badge" alt="Support me: get a SkinToScan pack"></a><br><sub>If you find this useful, you can support me by getting a SkinToScan pack, my other project. It's a one-time purchase that directly funds my open-source work.</sub></p>
<p align="center"><a href="https://skintoscan.com/checkout/?add-to-cart=138"><img src="https://img.shields.io/badge/1_Check-%E2%82%AC4.49-ff5f5f?style=for-the-badge" alt="Buy 1 Picture Check, €4.49"></a> <a href="https://skintoscan.com/checkout/?add-to-cart=139"><img src="https://img.shields.io/badge/5_Pack-%E2%82%AC19.99-ff5f5f?style=for-the-badge" alt="Buy 5 Picture Pack, €19.99"></a> <a href="https://skintoscan.com/checkout/?add-to-cart=140"><img src="https://img.shields.io/badge/15_Pack-%E2%82%AC54.99-ff5f5f?style=for-the-badge" alt="Buy 15 Picture Pack, €54.99"></a></p>

**Is your smart pet feeder, camera or plug safe?** `iotaudit` watches what your own IoT devices
do on the network and gives each one an **A–F grade** with a one-page HTML report. Everything
runs locally: no account, no telemetry, no cloud.

It answers the questions you actually have about a cheap smart device:

- **Who does it talk to?** Domains (DNS + TLS SNI + HTTP Host), IPs, country, organisation.
- **Is it encrypted?** Plaintext HTTP, unencrypted TCP, old TLS, or "custom" high-entropy protocols.
- **What ports are open?** Optional `nmap` scan with risk notes (telnet, RTSP, UPnP, ADB, …).
- **Does it phone home while idle?** Idle-upload check and a traffic timeline with bursts.
- **Where did the video go?** LAN peer (phone P2P) vs cloud vs STUN/TURN — and an honest note
  when a stream was set up but never actually passed through your computer.

> Status: **0.1.0**. Hotspot + ARP capture, pcap analysis, IPv6/NDP, grading, HTML report and the
> MCP server work. CVE lookup and UPnP checks are on the [roadmap](ROADMAP.md).

## Sample report

A report for a Tuya-associated pet feeder (anonymized). It talks to US clouds over TLS/MQTT, keeps
**telnet open**, uses **hardcoded 8.8.8.8**, sets up a **P2P video session that was not observed**
on this run, and shows an odd **special-use "LAN peer"** that is not a real device:

![Sample iotaudit report](docs/sample-report.png)

Open [`docs/sample-report.html`](docs/sample-report.html) in a browser for the full version.

## Install

```bash
# from source (PyPI release prepared via Trusted Publishing, not yet live)
pipx install "git+https://github.com/emirmrkaljevic/iotaudit"
# or, with the MCP server + geo extras:
pip install "iotaudit[mcp] @ git+https://github.com/emirmrkaljevic/iotaudit"
```

Capturing needs root (`sudo`). The optional port scan needs `nmap`.

## Quickstart

### macOS

```bash
brew install nmap
pipx install "git+https://github.com/emirmrkaljevic/iotaudit"

# Just run it: pick your device from the list, then leave it alone (or use its app).
sudo "$(which iotaudit)" capture --mode arp --i-own-this-network
```

iotaudit scans your LAN, lists devices (IP, MAC, vendor; Tuya/Espressif flagged as likely IoT),
and lets you pick one. It then ARP-spoofs **only that device** so its traffic flows through your
Mac, captures for up to an hour (Ctrl+C stops early and still writes the report), and restores the
ARP tables and IP-forwarding on exit. With a device picked, `--watch-lan` (phone P2P) and the
IPv6/NDP filter are on by default.

### Linux

```bash
sudo apt install nmap
pipx install "git+https://github.com/emirmrkaljevic/iotaudit"

# Same ARP flow as macOS:
sudo "$(which iotaudit)" capture --mode arp --i-own-this-network

# Or hotspot mode: your laptop becomes an AP; re-pair the device to it (needs NetworkManager).
sudo iotaudit capture --mode hotspot --iface wlan0 --ssid iotaudit --password 'choose-a-pass' \
     --device 10.42.0.50 --scan --out feeder.html
```

### Analyse an existing capture

```bash
# from Wireshark, your router, or OpenWrt `tcpdump -w`
iotaudit analyze capture.pcap --device 192.168.1.50 --json results.json --out report.html
```

The report lands at `./iotaudit-report.html` with a matching `.json` next to it.

## IPv6, P2P video, and "not observed"

Live video from a camera or feeder often does **not** go to the cloud — it goes **directly to your
phone** over the local Wi-Fi (P2P), after a short STUN/TURN handshake. iotaudit tries hard to see
that stream (`--watch-lan` spoofs device↔phone, and the capture filter now includes IPv6 and NDP),
but two Wi-Fi clients can talk **without their traffic ever passing through your computer** —
because of Access-Point client isolation, a phone ignoring the spoof, or the stream riding IPv6
link-local (`fe80::`). When that happens the report says so honestly:

> *Live video set up but not observed here* — the session was negotiated (STUN) but no sustained
> stream was captured; it most likely went straight to your phone. **Not observed ≠ not happening.**

For ground truth, capture at the router instead. `--ipv6-ndp` (experimental) also NDP-spoofs IPv6
link-local pairs.

## MCP server

```bash
iotaudit-mcp        # exposes audit tools to a local assistant ("audit my pet feeder")
```

## Consent & scope

iotaudit only audits **your own** network. It refuses non-private targets and requires
`--i-own-this-network` (or an interactive `I OWN THIS NETWORK` confirmation). ARP/NDP spoofing on a
network you do not own may be illegal.

Findings are **indicators based on observed traffic, not proof** of wrongdoing by any vendor.
IP geolocation by [DB-IP](https://db-ip.com). MIT licensed.
