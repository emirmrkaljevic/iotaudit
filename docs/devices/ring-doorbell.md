---
title: "What does a Ring doorbell or camera send?"
---
# What does a Ring doorbell or camera send?

Typical network behaviour of Ring doorbells and cameras, based on public documentation:

- HTTPS (443) and media streams to Amazon / Ring cloud hosts under ring.com, amazonaws.com and amazon.com.
- NTP (123) for time sync, and DNS to the resolver your LAN gives out (or sometimes Amazon DNS).
- On the LAN the device is quiet when idle. Motion and live view open short-lived media sessions to the cloud; two-way talk adds another stream.
- Ring does not expose RTSP or ONVIF on the LAN the way many third-party cameras do.

A Ring device talking to domains outside Amazon and Ring, or opening unexpected LAN ports, is worth a closer look. iotaudit flags unexpected destinations from a passive capture on your own network and writes a one-page report per device.


## Check your own devices

Install and run a passive audit on your own network:

```
pip install iotaudit
sudo iotaudit auto
```

Full install instructions: [README](https://github.com/emirmrkaljevic/iotaudit#readme). Only audit networks and devices you own. All data stays local, no telemetry.

[All device pages](../)