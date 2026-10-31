---
title: "What does a Shelly or Sonoff smart switch send?"
---
# What does a Shelly or Sonoff smart switch send?

Typical network behaviour of popular Wi-Fi relays and plugs, based on public documentation:

- Shelly: optional Shelly Cloud connection over HTTPS/WebSocket to shelly.cloud endpoints, which can be disabled. Local HTTP API on port 80, optional MQTT to your own broker, mDNS announcement (_shelly._tcp or _http._tcp).
- Sonoff (eWeLink firmware): HTTPS and WebSocket to ewelink.cc / coolkit.cc cloud servers. Some models offer a LAN mode announced over mDNS (_ewelink._tcp).
- Both use NTP (123) for time sync.

With cloud disabled, a Shelly should talk only to your LAN, NTP and your MQTT broker. Anything else is worth a closer look. iotaudit tags these as plug/bulb devices and flags unexpected destinations.


## Check your own devices

Install and run a passive audit on your own network:

```
pip install iotaudit
sudo iotaudit auto
```

Full install instructions: [README](https://github.com/emirmrkaljevic/iotaudit#readme). Only audit networks and devices you own. All data stays local, no telemetry.

[All device pages](../)
