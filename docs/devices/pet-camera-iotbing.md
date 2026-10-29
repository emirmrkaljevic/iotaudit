---
title: "What is iotbing.com and why is my camera or feeder talking to it?"
---
# What is iotbing.com and why is my camera or feeder talking to it?

Some pet feeders and cameras query a1-us, a1-eu or a1-sg.iotbing.com. Public hostname classification associates *.iotbing.com with the Tuya Smart IoT platform, and TLS certificates cover *.iotbing.com. Typical traffic: HTTPS and MQTT over TLS hosted on AWS, STUN/TURN (3478) for P2P video, sometimes a custom TCP port such as 1443.

That is an association, not a claim about any brand. To see what your own device does, iotaudit runs a passive capture on your own network and lists every destination.


## Check your own devices

Install and run a passive audit on your own network:

```
pip install iotaudit
sudo iotaudit auto
```

Full install instructions: [README](https://github.com/emirmrkaljevic/iotaudit#readme). Only audit networks and devices you own. All data stays local, no telemetry.

[All device pages](../)
