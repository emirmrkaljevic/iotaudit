---
title: Grade devices from an OpenWrt tcpdump capture
---
# Grade devices from an OpenWrt tcpdump capture

For a short start, see the [README](https://github.com/emirmrkaljevic/iotaudit#readme).

An OpenWrt router already sits in the path of your LAN traffic, so a `tcpdump` capture taken there is often the most complete view of what a device sends. You then grade that file on a laptop with `iotaudit analyze`. No root is needed for a saved pcap, and nothing is uploaded.

The addresses below are documentation placeholders (`192.0.2.1` is the router, `192.0.2.50` is the device). Substitute your own. Only capture a network and devices you own.

## Install tcpdump on the router

SSH in and install the full `tcpdump` package (not a reduced extra), then leave the session:

```bash
ssh root@192.0.2.1
opkg update && opkg install tcpdump
```

The LAN bridge is usually `br-lan`. If a capture starts and then says the interface is missing, check the name with `ip link` on the router.

## Capture to the laptop over SSH

This streams a pcap to your laptop, so the file never sits in the router's `/tmp` (on many OpenWrt devices `/tmp` is RAM). `-U` writes each packet as it arrives. `not port 22` keeps the SSH session itself out of the file.

```bash
ssh root@192.0.2.1 'tcpdump -i br-lan -U -w - not port 22' > capture.pcap
```

To follow one device only:

```bash
ssh root@192.0.2.1 'tcpdump -i br-lan -U -w - host 192.0.2.50 and not port 22' > capture.pcap
```

Let it run while you use the device and, if you can, while its app is closed, so idle traffic shows up too. Stop with Ctrl+C. The file `capture.pcap` is then on the laptop.

## Or write a file on the router

If you prefer to store the capture on the router and copy it afterwards:

```bash
ssh root@192.0.2.1 'tcpdump -i br-lan -w /tmp/capture.pcap host 192.0.2.50'
scp root@192.0.2.1:/tmp/capture.pcap .
```

Stop tcpdump with Ctrl+C before you copy the file. Keep `/tmp` in mind on small routers: a long capture can fill RAM. The SSH stream above avoids that.

## Grade the capture

```bash
pipx install iotaudit
iotaudit analyze capture.pcap --device 192.0.2.50 --no-scan --out report.html
```

That writes `report.html` and `report.json` in the current directory. `--device` focuses the report on that address. `--no-scan` skips nmap, which otherwise would run from the laptop against each `--device`. Use a scan only when this computer can still reach the device on your LAN, and you want the open-port check.

If you omit `--device`, iotaudit grades every private LAN address it sees in the pcap (typical home ranges such as `192.168.0.0/16`). Documentation addresses like `192.0.2.50` are not in those ranges, so the examples above keep `--device`.

The report lists destinations (domains from DNS, TLS SNI and HTTP Host, countries, organisation), plaintext versus TLS, DNS that bypasses your resolver, idle uploads, and an A to F grade with a one-line verdict. You can also add `--pdf` if you have installed `iotaudit[pdf]`.

## Privacy

A capture on `br-lan` can include every device on that LAN, not just the gadget you care about, plus local IPs, MAC addresses, and any plaintext payloads. Keep the pcap on your own machine. If you want to show a report, use `iotaudit report report.json --redact` or `iotaudit export report.json --format md --redact` so local addresses are replaced. Redaction is not a guarantee of complete anonymity. iotaudit itself stays local: no account, no telemetry.

See also the [usage guide](../usage.md), [capture modes](../modes.md), and [share results](../share-results.md).
