---
title: "What does a Wi-Fi pet feeder send?"
---
# What does a Wi-Fi pet feeder send?

Many Wi-Fi feeders (for example IMIPAW models using the PETTECH app) are built on Tuya Wi-Fi/BT modules. Expect:

- HTTPS (443) and MQTT over TLS (8883) to the Tuya region cloud (tuyaeu.com, tuyaus.com, tuyacn.com) and smart321.com.
- NTP (123), sometimes aliyuncs.com.
- Tuya LAN control on 6668. 2.4 GHz only.

Some camera feeders instead talk to *.iotbing.com (HTTPS, MQTT over TLS, STUN 3478 for video). Domains vary by region and account, so confirm on your own capture. iotaudit does that and writes a report.


## Check your own devices

Install and run a passive audit on your own network:

```
pip install iotaudit
sudo iotaudit auto
```

Full install instructions: [README](https://github.com/emirmrkaljevic/iotaudit#readme). Only audit networks and devices you own. All data stays local, no telemetry.

[All device pages](../)
