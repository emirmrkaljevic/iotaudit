---
title: Device profiles and known-issue hints
---
# Device profiles and known-issue hints

iotaudit tries to recognise what a device is from traffic, hostname, and MAC vendor, then compares destinations with a bundled profile when one matches.

## Bundled profiles

The package ships YAML profiles for common consumer devices, including Tuya-based gadgets, Xiaomi / Mi Home, generic RTSP/ONVIF cameras, iotbing.com cloud cameras and feeders, Ring doorbells and cameras, Philips Hue bridges, Shelly devices, and Sonoff / eWeLink switches.

A profile can match on a cloud domain, a distinctive vendor, or a hostname (for example a Shelly whose default name still starts with `shelly`, even when cloud is disabled). Generic Amazon traffic alone does not attach the Ring profile, and a Signify vendor alone does not attach the Hue profile.

Once a profile matches, destinations outside its usual cloud are flagged as unexpected. Saved audits and the HTML report include the hostname when it is known; `--redact` still replaces it.

iotaudit also has a broader device-type guess (camera, plug, hub, and so on) from ports, mDNS, and destination names, with a confidence. That guess is an indicator, not a model claim.

Short public-documentation pages for typical destinations:

- [IP cameras](devices/ip-camera.md)
- [iotbing.com cameras and feeders](devices/pet-camera-iotbing.md)
- [Tuya smart plugs](devices/tuya-smart-plug.md)
- [Philips Hue bridges](devices/philips-hue-bridge.md)
- [Chromecast and Google Cast](devices/chromecast.md)
- [Shelly and Sonoff switches](devices/shelly-sonoff.md)
- [Ring doorbells and cameras](devices/ring-doorbell.md)
- [Wi-Fi pet feeders](devices/wifi-pet-feeder.md)
- [Xiaomi Mi Home](devices/xiaomi-mi-home.md)

The published versions of those pages live at [the docs site](https://emirmrkaljevic.github.io/iotaudit/).

Current release is 0.1.23. 0.1.22 added the Ring, Hue, Shelly and Sonoff/eWeLink profiles and hostname matching.


## Submit a profile

You can turn a device from a saved audit into a draft profile, with local addresses already removed:

```bash
iotaudit profile export ~/iotaudit/2026-01-01/120000.json 1
# or: iotaudit profile export audit.json "Example Vendor" --out draft.yaml
```

The command redacts the audit the same way `iotaudit redact` does, then writes YAML in the bundled format. The draft contains only the vendor, an optional model, public domains (collapsed to the registrable name, so `a2.tuyaeu.com` becomes `tuyaeu.com`), destination ports, and destination countries. Device hostnames are not included, even as placeholders such as `host-1`.

Review the file before you share it. Drop any domain that is not this product's usual cloud, and add a model or a public source if you have one. Then open a GitHub issue with the Device profile template, or a pull request. The steps are also in [CONTRIBUTING.md](https://github.com/emirmrkaljevic/iotaudit/blob/main/CONTRIBUTING.md).

## Known-issue hints

iotaudit compares banners it already has with a small catalog shipped in the package (`src/iotaudit/data/known_issues.yaml`). The facts it can use are:

- an open service from the port scan, plus the nmap product and version
- an HTTP `Server` header from a response the device sent
- a UPnP or SSDP header (including an InternetGatewayDevice advertisement)
- an RTSP response that did not ask for authentication, when that was already in the capture or in the scan record

There is no lookup at runtime and no `hints --update-from` command. The file changes only when you install a newer iotaudit.

Each hint is a possibility, not proof the firmware is vulnerable. The text always includes: possible, based on version string; verify firmware. The reference is the NVD page for that CVE.

Hints show in the HTML report, in the PDF (the PDF is the same HTML), in the device JSON as `known_issue_hints`, and in the MCP `analyze_pcap` result.

**Grade rule.** A hint does not change the A-F grade unless both are true: the observed version string equals a version the entry lists exactly, and the entry severity is critical. That case subtracts 25 points, the same as one high finding, and the subtraction is applied after the limited-data cap so it still moves a thin capture. A version range, a product name without that exact version, an open port on its own, or any severity other than critical leaves the score unchanged. Telnet being open, an exposed UPnP IGD, or RTSP with no authentication is not by itself a CVE. The catalog cites one only when the banner or the service fact matches that entry.

Limits:

- The file is a short curated list (on the order of 10 to 20 issues), not the NVD and not a firmware database.
- A patched device can still show an old version string. An unpatched device can hide the version. Either way the hint says to verify the firmware.
- Banners are read from IPv4 packets and from the nmap record. IPv6 service banners are not parsed.
- RTSP with no authentication is recorded when a captured RTSP `200` has no `WWW-Authenticate` header, or when the scan extra info already says so. The shipped list does not treat that fact alone as a CVE. It is mentioned on a hint when a versioned RTSP entry also matches.
- No network access is used to refresh the list.
