---
title: "What does an IP camera (Hikvision, Dahua, Amcrest) send?"
---
# What does an IP camera (Hikvision, Dahua, Amcrest) send?

Typical traffic for consumer IP cameras:

- Cloud and P2P relay for remote viewing: hik-connect.com, easy4ip.com, amcrestcloud.com.
- HTTPS (443) and NTP (123).
- On the LAN, cameras often expose RTSP (554), ONVIF (80 or 8899) and sometimes telnet.

An open telnet port or a connection to an unknown P2P relay is the first thing I would check. iotaudit flags both from a passive capture on your own network and writes a one-page report per device.


## Check your own devices

Install and run a passive audit on your own network:

```
pip install iotaudit
sudo iotaudit auto
```

Full install instructions: [README](https://github.com/emirmrkaljevic/iotaudit#readme). Only audit networks and devices you own. All data stays local, no telemetry.

[All device pages](../)
