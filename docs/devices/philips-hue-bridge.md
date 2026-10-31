---
title: "What does a Philips Hue bridge send?"
---
# What does a Philips Hue bridge send?

Typical network behaviour of a Hue bridge, based on public documentation:

- HTTPS (443) to Signify cloud endpoints under meethue.com for remote control, app sync and firmware updates.
- NTP (123) for time sync.
- On the LAN it announces itself over mDNS (_hue._tcp) and SSDP, and serves the local API on HTTP (80) and HTTPS (443).
- The lights themselves talk Zigbee to the bridge, not Wi-Fi, so they do not show up as separate IP devices.

A bridge talking to domains outside meethue.com, or opening new ports, is worth a closer look. iotaudit tags it as a hub/bridge from mDNS and DNS names and flags unexpected destinations.


## Check your own devices

Install and run a passive audit on your own network:

```
pip install iotaudit
sudo iotaudit auto
```

Full install instructions: [README](https://github.com/emirmrkaljevic/iotaudit#readme). Only audit networks and devices you own. All data stays local, no telemetry.

[All device pages](../)
