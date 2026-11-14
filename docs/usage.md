---
title: Using iotaudit
---
# Using iotaudit

Install, the one-command audit, reports, diffs, and the smaller commands. For ARP and hotspot capture, see [capture modes](modes.md). For Home Assistant, see the [Home Assistant guide](home-assistant.md).

## Install

```bash
pipx install iotaudit
# or with the MCP server extra, and PDF export:
pip install "iotaudit[mcp]"
pip install "iotaudit[pdf]"
# latest from source:
pipx install "git+https://github.com/emirmrkaljevic/iotaudit"
```

Capturing needs root (`sudo`). The optional port scan needs `nmap`.

## The one-command audit

One command does the audit. It asks you to confirm this is your network, picks the active interface, finds devices, identifies them, scans ports, lists UPnP forwards (read-only), captures passively for 60 seconds, and writes the report.

```bash
sudo iotaudit auto
```

Each device is printed on one line, then the report path. Files land in `~/iotaudit/YYYY-MM-DD/` as HTML and JSON. A PDF is written next to them when `iotaudit[pdf]` is installed (`pip install "iotaudit[pdf]"`). If that folder already has a run from today, the new run is compared with the latest one.

Skip the typed confirmation with the existing ownership flag:

```bash
sudo iotaudit auto --i-own-this-network
```

A longer capture, or an explicit folder:

```bash
sudo iotaudit auto --i-own-this-network --duration 120 --out-dir ~/iotaudit
```

`nmap` and `tcpdump` are required. If either is missing, the command prints one install line and stops:

```bash
# macOS
brew install nmap tcpdump
# Debian or Ubuntu
sudo apt install nmap tcpdump
```

On macOS, Homebrew and a pipx install often sit outside sudo's PATH:

```bash
sudo env PATH="$PATH" "$(which iotaudit)" auto --i-own-this-network
```

Default passwords are not tested. That check stays opt-in, one device at a time (`iotaudit credcheck`, which is the only command with `--yes`).

`auto` does not ARP-spoof and does not start a hotspot. It records traffic that already passes this computer. To pull one device's traffic through this machine, use `capture --mode arp` in [capture modes](modes.md).

## Analyse an existing capture

```bash
# from Wireshark, your router, or OpenWrt `tcpdump -w`
iotaudit analyze capture.pcap --device 192.168.1.50 --json results.json --out report.html
```

The report lands at `./iotaudit-report.html` with a matching `.json` next to it, unless you pass `--out` and `--json`.

## PDF export

```bash
pip install "iotaudit[pdf]"

# Writes report.pdf next to report.html:
iotaudit analyze capture.pcap --device 192.168.1.50 --out report.html --pdf
sudo "$(which iotaudit)" capture --mode arp --i-own-this-network --pdf

# Convert a report you already saved (HTML, or the JSON list of devices):
iotaudit report --pdf report.html
iotaudit report --pdf results.json --out results.pdf
```

`--pdf` on `analyze` and `capture` writes a PDF next to the HTML. Print styles put the grade and verdict at the top of each device (the first device shares page 1 with the title; every later device starts on a new page), keep table rows in one piece, and repeat the table header. The on-screen traffic chart is left out of the PDF.

The renderer is xhtml2pdf, a pure-Python extra (`xhtml2pdf`, pulled in by `iotaudit[pdf]`). No Cairo or Pango install is required. If the extra is not installed, `analyze` and `capture` still write the HTML and print one install line. `iotaudit report --pdf` prints that same line and exits, because the PDF is its only output. The MCP tool `analyze_pcap` takes `pdf=true` together with `report_path` and writes the PDF beside the HTML.

## Compare two audits

```bash
iotaudit diff "$HOME/iotaudit/yesterday.json" "$HOME/iotaudit/today.json"
iotaudit diff "$HOME/iotaudit/yesterday.json" "$HOME/iotaudit/today.json" --json

# Same diff, printed after the HTML and JSON report:
iotaudit analyze capture.pcap --device 192.168.1.50 \
    --json "$HOME/iotaudit/today.json" --out "$HOME/iotaudit/today.html" \
    --compare "$HOME/iotaudit/yesterday.json"
```

Devices match by MAC. If either side has no MAC, they match by IP. A different MAC at the same IP is one device gone and one device new. For each device the report lists new and gone destination domains and IPs, new countries, new open ports, grade changes, verdict changes, newly seen unencrypted traffic, and new UPnP forwards when the JSON has them.

Exit code **1** when something security-relevant appeared: a device, a destination domain or IP, a country, an open port, a worse grade, unencrypted traffic, or a UPnP forward. Exit code **0** otherwise, including when the only changes are departures or a better grade. A verdict change is printed either way and does not by itself exit 1. Missing or unreadable input exits 2. With `--compare`, `capture` and `analyze` use that same code after they write the report.

`capture` and `analyze` already write JSON (next to the HTML, or at `--json`). Keep the previous file and pass it as `--compare`, or run `diff` on the two files later. `--json` on `diff` prints the machine-readable result. On `capture` and `analyze`, `--json` is still the path of the results file.

Cron stays quiet when nothing new showed up. This script prints the diff, and exits 1, only when something security-relevant appeared:

```sh
#!/bin/sh
# 15 6 * * 1-5 "$HOME/iotaudit/check.sh"
report=$(iotaudit diff "$HOME/iotaudit/yesterday.json" "$HOME/iotaudit/today.json") || {
    printf '%s\n' "$report"
    exit 1
}
exit 0
```

LAN peers are not compared. Open ports are the scanned `open_ports`, not the remote port a destination was contacted on. UPnP is read from findings with category `upnp`, or from a top-level `upnp.mappings` list joined on `internal_client`. An audit saved without a UPnP check has no forwards, so the next audit's forwards show up as new. Other findings are not listed one by one; a grade or verdict change still shows when those findings moved the grade or the verdict.

## Default-password check (opt-in)

```bash
iotaudit credcheck 192.168.0.50                 # telnet by default
iotaudit credcheck 192.168.0.50 --service telnet --service http
```

The one active login iotaudit makes, and only when you ask for it. It tries a short list of documented vendor default credentials (for example the `root`/`xc3511` that the Mirai-era cameras shipped with), never a password wordlist. You confirm the exact IP by typing a phrase, it only targets a LAN address, it waits between attempts, stops at the first login that works, and reports just "default login accepted" or "not accepted"; it never keeps or uses the session. Use it on your own devices only.

## Router port forwards (UPnP)

```bash
iotaudit upnp          # or --json
```

Many devices quietly ask the router to open a public port to themselves. `iotaudit upnp` lists every UPnP port forward and the LAN device it points to. It only sends the two read-only UPnP queries, and only to a router on a private address. It also runs after each `capture` (skip with `--no-upnp`) and adds a finding when a forward points at the audited device. If nothing answers, UPnP is off on your router, which is the safest setting.

## Web UI

```bash
iotaudit web                          # http://127.0.0.1:8765, token printed on start
sudo "$(which iotaudit)" web --lan    # also from a phone on the same Wi-Fi (token required)
```

View reports, upload a pcap (including PCAPdroid captures from Android) and run a one-click scan and capture from the browser. Localhost by default; `--lan` is opt-in, token-protected and only answers private-range clients. iPhones can use the web UI but cannot capture on their own; see [phones](phones.md) for what works on Android and iOS and what does not.

## Export, Home Assistant, and sharing

For a spreadsheet, the same per-device summary as CSV:

```bash
iotaudit export audit.json --compare earlier.json --format csv --out devices.csv
```

Or as a Markdown table to paste into an issue or forum post: `iotaudit export audit.json --format md`. Add `--redact` to leave out IP addresses before you post it. To share a full report in one step: `iotaudit report audit.json --redact` writes `audit.redacted.html` with local IPs, MACs and hostnames replaced by labels like `lan-1`. Add `--pdf` for a PDF (needs `pip install "iotaudit[pdf]"`). Or keep the JSON copy with `iotaudit redact audit.json`. More detail is on the [share results](share-results.md) and [report](report.md) pages.

To show grades in Home Assistant, publish the summary over MQTT or write a JSON file. From 0.1.20, `--ha-mqtt` also writes MQTT discovery configs so the sensors appear without YAML:

```bash
export IOTAUDIT_MQTT_PASSWORD='your-broker-password'
iotaudit export ~/iotaudit/2026-01-01/120000.json --compare earlier.json --ha-mqtt 192.168.1.2
sudo iotaudit auto --ha-json /path/to/homeassistant/config/iotaudit.json
iotaudit export ~/iotaudit/2026-01-01/120000.json --compare earlier.json --out iotaudit.json
```

Each device gets `name`, `ip`, `grade`, `findings`, and `changed` (null on the first run). Ready-to-paste sensor YAML and MQTT details are in the [Home Assistant guide](home-assistant.md).

## Device profiles

`iotaudit profile export AUDIT.json DEVICE` writes a draft profile YAML from a saved audit, after the same redaction as `iotaudit redact`. Details and how to submit one are in [device profiles](device-profiles.md).

