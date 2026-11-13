---
title: iotaudit device profiles
---
# What do smart devices on your network send?

Short pages on typical network behaviour of common consumer IoT devices, based on public documentation and iotaudit's device profiles. Observed and public facts only.

- [What does an IP camera (Hikvision, Dahua, Amcrest) send?](devices/ip-camera.html)
- [What is iotbing.com and why is my camera or feeder talking to it?](devices/pet-camera-iotbing.html)
- [What does a Tuya smart plug send?](devices/tuya-smart-plug.html)
- [What does a Philips Hue bridge send?](devices/philips-hue-bridge.html)
- [What does a Chromecast or Google Cast device send?](devices/chromecast.html)
- [What does a Shelly or Sonoff smart switch send?](devices/shelly-sonoff.html)
- [What does a Ring doorbell or camera send?](devices/ring-doorbell.html)
- [What does a Wi-Fi pet feeder send?](devices/wifi-pet-feeder.html)
- [What does a Xiaomi Mi Home device send?](devices/xiaomi-mi-home.html)

## Using iotaudit

- [Usage](usage.html): install, `auto`, PDF, diff, cron, export, credcheck, UPnP, and the web UI
- [Capture modes](modes.html): ARP, hotspot, IPv6, and P2P video
- [Reports](report.html): sample report, PDF, sharing and redaction
- [DNS that bypasses your resolver](dns-bypass.html)
- [Device profiles and known-issue hints](device-profiles.html)
- [MCP server](mcp.html)
- [Web UI and phones](phones.html)

## Home Assistant

- [Show iotaudit results in Home Assistant](home-assistant.html)
- [Share your results without leaking your network](share-results.html)

## Get iotaudit

`pipx install iotaudit` (or `pip install iotaudit`), then `sudo iotaudit auto`. See the [README](https://github.com/emirmrkaljevic/iotaudit#readme) and [PyPI](https://pypi.org/project/iotaudit/).

