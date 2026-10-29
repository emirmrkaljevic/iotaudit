---
title: "What does a Xiaomi Mi Home device send?"
---
# What does a Xiaomi Mi Home device send?

Xiaomi miIO devices (plugs, purifiers, vacuums):

- Encrypted UDP to ot.io.mi.com on port 8053.
- HTTPS to xiaomi.com, mi.com, xiaomi.net.
- NTP (123).
- Local UDP port 54321 for the miIO LAN protocol.

iotaudit has a profile for this and highlights anything beyond it. Local only, no telemetry.


## Check your own devices

Install and run a passive audit on your own network:

```
pip install iotaudit
sudo iotaudit auto
```

Full install instructions: [README](https://github.com/emirmrkaljevic/iotaudit#readme). Only audit networks and devices you own. All data stays local, no telemetry.

[All device pages](../)
