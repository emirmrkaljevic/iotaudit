---
title: "What does a Chromecast or Google Cast device send?"
---
# What does a Chromecast or Google Cast device send?

Typical network behaviour of Chromecast and other Google Cast devices, based on public documentation:

- HTTPS (443) and QUIC (UDP 443) to Google services: google.com, googleapis.com, gstatic.com, googlevideo.com and similar.
- NTP (123), often to time.google.com, and DNS to the configured resolver (some devices try 8.8.8.8 directly).
- On the LAN it announces itself over mDNS (_googlecast._tcp) and listens on ports 8008 and 8009 for casting.
- Streaming apps add their own CDNs while you cast (for example Netflix or YouTube video hosts).

Hard-coded DNS to 8.8.8.8 is a common surprise when you run a local DNS filter. iotaudit identifies Cast devices from mDNS and ports 8008/8009 and lists every destination per device.


## Check your own devices

Install and run a passive audit on your own network:

```
pip install iotaudit
sudo iotaudit auto
```

Full install instructions: [README](https://github.com/emirmrkaljevic/iotaudit#readme). Only audit networks and devices you own. All data stays local, no telemetry.

[All device pages](../)
