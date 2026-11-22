---
title: iotaudit guide and device pages
---
# What do smart devices on your network send?

Short pages on typical network behaviour of common consumer IoT devices, based on public documentation and iotaudit's device profiles. Observed and public facts only. For a short start, see the [README](https://github.com/emirmrkaljevic/iotaudit#readme). The same list lives under [device pages](devices/README.md).

- [What does an IP camera (Hikvision, Dahua, Amcrest) send?](devices/ip-camera.md)
- [What is iotbing.com and why is my camera or feeder talking to it?](devices/pet-camera-iotbing.md)
- [What does a Tuya smart plug send?](devices/tuya-smart-plug.md)
- [What does a Philips Hue bridge send?](devices/philips-hue-bridge.md)
- [What does a Chromecast or Google Cast device send?](devices/chromecast.md)
- [What does a Shelly or Sonoff smart switch send?](devices/shelly-sonoff.md)
- [What does a Ring doorbell or camera send?](devices/ring-doorbell.md)
- [What does a Wi-Fi pet feeder send?](devices/wifi-pet-feeder.md)
- [What does a Xiaomi Mi Home device send?](devices/xiaomi-mi-home.md)

## Using iotaudit

- [Usage](usage.md): install, `auto`, PDF, diff, cron, export, credcheck, UPnP, and the web UI
- [Capture modes](modes.md): ARP, hotspot, IPv6, and P2P video
- [OpenWrt router captures](integrations/openwrt.md): tcpdump over SSH, then `iotaudit analyze`
- [Reports](report.md): sample report, PDF, sharing and redaction
- [DNS that bypasses your resolver](dns-bypass.md)
- [Device profiles and known-issue hints](device-profiles.md)
- [MCP server](mcp.md)
- [Web UI and phones](integrations/phones.md)

## Home Assistant

- [Show iotaudit results in Home Assistant](integrations/home-assistant.md)
- [Share your results without leaking your network](share-results.md)

## Get iotaudit

`pipx install iotaudit` (or `pip install iotaudit`), then `sudo iotaudit auto`. See the [README](https://github.com/emirmrkaljevic/iotaudit#readme) and [PyPI](https://pypi.org/project/iotaudit/).

