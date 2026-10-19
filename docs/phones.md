# Phones: Android, iPhone and the web UI

iotaudit audits a smart-home **device**. A phone is usually the *controller* (the vendor app), not
the thing you are grading. This page explains what each phone can and cannot do, without
overselling.

## The web UI (`iotaudit web`)

Run it on the computer that does the capturing:

```bash
iotaudit web                                  # http://127.0.0.1:8765 only
sudo "$(which iotaudit)" web --lan            # also reachable from your phone on the same Wi-Fi
```

It prints a URL with a random token, e.g. `http://192.168.0.20:8765/?token=…`. Open that exact
URL on your phone; the token is moved into a cookie and stripped from the address bar.

What it does:

- lists and serves the HTML reports in `./iotaudit-reports`;
- **uploads a pcap** (from Wireshark, a router, or PCAPdroid) and analyzes it;
- **scan & capture**: scans the LAN, you pick one device, tick "I own this network and this
  device", and it runs the ARP capture on the computer. Captures need the server to run as root.

Safety defaults: it binds to `127.0.0.1` unless you pass `--lan`; a token is always required;
`--lan` only answers clients from private/loopback ranges; the `Host` header is checked
(blocks DNS rebinding) and POSTs from other origins are rejected. There is no TLS, so the token
travels in clear text on your Wi-Fi. Only use `--lan` on a network you trust, stop the server
when you are done, and pass your own `--token` if you want a stable one.

## Android: PCAPdroid (works today)

[PCAPdroid](https://github.com/emanuele-f/PCAPdroid) is a free, open-source, no-root capture app.
It sees the **phone's own** traffic through a local VPN, so on Android you can audit the vendor
app (and anything else on the phone), but not the IoT device itself.

1. In PCAPdroid, choose *PCAP file* as the dump mode. Optionally enable the *PCAPdroid trailer*
   so each packet carries the app name.
2. Optionally filter to the vendor app. Start, use the app for a few minutes, stop.
3. Upload the `.pcap` in the web UI, or copy it over and run `iotaudit analyze capture.pcap`.

iotaudit detects PCAPdroid files, strips the fake Ethernet header and trailer, and records which
apps were seen. To audit the device itself, capture on a computer (ARP or hotspot mode).

## iPhone: honest limits

- **iotaudit cannot run on iOS.** There is no shell, no raw sockets, and no way to ARP-capture
  another device from an iPhone.
- **No PCAPdroid equivalent that we have tested.** iOS only allows capture through a VPN
  (Network Extension) app, and we do not know of a free, open-source one that exports full pcaps.
  We have not tested any App Store capture apps with iotaudit.
- **Mac + cable (iPhone's own traffic):** with Xcode installed, `rvictl -s <UDID>` creates an
  `rvi0` interface that mirrors the iPhone's traffic; `sudo tcpdump -i rvi0 -w iphone.pcap`
  records it. This is the iPhone's traffic, not the IoT device's, and iotaudit has **not been
  tested** on `rvi0` captures yet; if one fails to parse, please open an issue.
- **What does work:** Safari on the iPhone can open the `--lan` web UI to view reports and start
  a capture that runs on your Mac or Linux box. With a device picked, `--watch-lan` shows
  device-to-phone P2P video, so the phone still shows up in the report as a LAN peer.
- **Private Wi-Fi Address:** iOS (and Android) may use a different random MAC per network, so the
  phone's MAC in a report will not match the one on its label. That is expected.

## Wi-Fi that blocks this

Guest networks and some mesh/ISP routers enable *client isolation*: devices cannot reach each
other. Then the phone cannot open the web UI and ARP mode cannot see the device. Use the main
network, or hotspot mode on Linux.
