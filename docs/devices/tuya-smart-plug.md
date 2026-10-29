---
title: "What does a Tuya smart plug send?"
---
# What does a Tuya smart plug send?

Most white-label Wi-Fi plugs, bulbs and feeders run Tuya firmware. What you can usually expect on the network:

- HTTPS (443) and MQTT over TLS (8883) to the Tuya region cloud: tuyaeu.com, tuyaus.com or tuyacn.com depending on the account region.
- NTP (123) for time sync.
- Sometimes aliyuncs.com endpoints.
- Port 6668 open on the LAN: the Tuya local control protocol.

Anything outside that list is worth a closer look. I built iotaudit to check this on my own network: `sudo iotaudit auto` captures passively, matches the device to its profile and flags unexpected destinations. All data stays local.


## Check your own devices

Install and run a passive audit on your own network:

```
pip install iotaudit
sudo iotaudit auto
```

Full install instructions: [README](https://github.com/emirmrkaljevic/iotaudit#readme). Only audit networks and devices you own. All data stays local, no telemetry.

[All device pages](../)
