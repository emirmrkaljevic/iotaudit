---
title: Capture modes
---
# Capture modes

`iotaudit auto` records traffic that already passes this computer. It does not ARP-spoof and does not start a hotspot. To pull one device's traffic through this machine, use `iotaudit capture`.

## macOS (ARP)

```bash
brew install nmap
pipx install iotaudit

# Just run it: pick your device from the list, then leave it alone (or use its app).
sudo "$(which iotaudit)" capture --mode arp --i-own-this-network
```

iotaudit scans your LAN, lists devices (IP, MAC, vendor; Tuya/Espressif flagged as likely IoT), and lets you pick one. It then ARP-spoofs only that device so its traffic flows through your Mac, captures for up to an hour (Ctrl+C stops early and still writes the report), and restores the ARP tables and IP-forwarding on exit. With a device picked, `--watch-lan` (phone P2P) and the IPv6/NDP filter are on by default.

On macOS, Homebrew and a pipx install often sit outside sudo's PATH. The `sudo "$(which iotaudit)"` form above is the usual fix. See also the [usage guide](usage.md).

## Linux (ARP or hotspot)

```bash
sudo apt install nmap
pipx install iotaudit

# Same ARP flow as macOS:
sudo "$(which iotaudit)" capture --mode arp --i-own-this-network

# Or hotspot mode: your laptop becomes an AP; re-pair the device to it (needs NetworkManager).
sudo iotaudit capture --mode hotspot --iface wlan0 --ssid iotaudit --password 'choose-a-pass' \
     --device 10.42.0.50 --scan --out feeder.html
```

Hotspot mode is useful when you cannot (or would rather not) ARP-spoof on the main LAN, or when client isolation would hide the device from this computer.

## IPv6, P2P video, and "not observed"

Live video from a camera or feeder often does **not** go to the cloud: it goes **directly to your phone** over the local Wi-Fi (P2P), after a short STUN/TURN handshake. iotaudit tries hard to see that stream (`--watch-lan` spoofs device and phone, and the capture filter includes IPv6 and NDP), but two Wi-Fi clients can talk without their traffic ever passing through your computer, because of Access-Point client isolation, a phone ignoring the spoof, or the stream riding IPv6 link-local (`fe80::`). When that happens the report says so honestly:

> *Live video set up but not observed here*: the session was negotiated (STUN) but no sustained stream was captured; it most likely went straight to your phone. **Not observed ≠ not happening.**

For ground truth, capture at the router instead. `--ipv6-ndp` (experimental) also NDP-spoofs IPv6 link-local pairs.

The report also distinguishes LAN peer (phone P2P) vs cloud vs STUN/TURN, and notes when a stream was set up but never actually passed through your computer.

You can also analyse a capture you already have (`iotaudit analyze capture.pcap`). Details are in the [usage guide](usage.md). What phones can and cannot do is in [phones](phones.md).
