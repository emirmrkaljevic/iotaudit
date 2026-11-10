---
title: iotaudit in Home Assistant
---
# Show iotaudit results in Home Assistant

iotaudit can feed a compact grade summary into Home Assistant in two ways:
publish it over MQTT (best when iotaudit runs on a different machine than
Home Assistant), or write a small JSON file that a `command_line` sensor
reads. Either way you get a dashboard card and can trigger an automation
when a device changes or the worst grade drops.

## MQTT (recommended when Home Assistant is on another host)

If you already run an MQTT broker for Home Assistant (Mosquitto is the usual
choice), iotaudit can publish the summary there. From 0.1.20 it also writes
Home Assistant MQTT discovery configs, so the sensors appear without extra
YAML. Enable the MQTT integration in Home Assistant first.

```bash
# password stays in the environment, not on the command line
export IOTAUDIT_MQTT_PASSWORD='your-broker-password'
iotaudit export ~/iotaudit/2026-01-01/120000.json --compare earlier.json \
  --ha-mqtt 192.168.1.2
```

`--ha-mqtt` accepts a hostname, `host:port`, or an `mqtt://` / `mqtts://` URL.
The default port is 1883 (8883 when you use `mqtts://`). Set a username with
`--ha-mqtt-user`, or with `IOTAUDIT_MQTT_USER`. You can also run it from the
one-command audit:

```bash
sudo iotaudit auto --i-own-this-network --ha-mqtt 192.168.1.2 --ha-mqtt-user home
```

By default the messages are retained under the `iotaudit` topic prefix:

- `iotaudit/summary` is the full JSON (same shape as the file export)
- `iotaudit/worst_grade`, `iotaudit/changed` (how many devices changed),
  `iotaudit/security_relevant`, and `iotaudit/generated` are compact values
  for simple sensors
- `iotaudit/device/<id>/grade` and `iotaudit/device/<id>/state` cover each device

Discovery configs go to `homeassistant/sensor/.../config` (and a binary sensor
for `security_relevant`). To publish only the `iotaudit/...` topics, add
`--no-ha-mqtt-discovery`. To use a different prefix: `--ha-mqtt-topic mysensors`.

This talks to a broker you already run. iotaudit does not start one, and it
does not need a Python MQTT package.

## 1. Write the summary (file)

Run the audit on a machine that can see your network, and point `--ha-json` at a folder Home Assistant can read:

```bash
sudo iotaudit auto --ha-json /config/iotaudit.json
```

Or convert an audit you already saved:

```bash
iotaudit export audit.json --compare previous.json --out /config/iotaudit.json
```

## 2. What the file looks like

Example with documentation addresses:

```json
{
  "generated": "2026-01-01T12:00:00",
  "devices": 2,
  "worst_grade": "D",
  "findings": 3,
  "changed": 1,
  "gone": 0,
  "security_relevant": true,
  "device_list": [
    {"name": "Example camera (port 554)", "ip": "192.168.1.50", "grade": "D",
     "findings": 3, "changed": true, "status": "changed"},
    {"name": "Example plug", "ip": "192.168.1.51", "grade": "A",
     "findings": 0, "changed": false, "status": "unchanged"}
  ]
}
```

`changed` is `null` on the first run, when there is nothing to compare with.

{% raw %}
## 3. Sensor YAML

Add this to `configuration.yaml` and restart Home Assistant:

```yaml
command_line:
  - sensor:
      name: iotaudit worst grade
      unique_id: iotaudit_worst_grade
      command: "cat /config/iotaudit.json"
      scan_interval: 600
      value_template: "{{ value_json.worst_grade }}"
      json_attributes:
        - generated
        - devices
        - findings
        - changed
        - security_relevant
        - device_list
  - binary_sensor:
      name: iotaudit something changed
      unique_id: iotaudit_changed
      command: "cat /config/iotaudit.json"
      scan_interval: 600
      device_class: problem
      payload_on: "on"
      payload_off: "off"
      value_template: "{{ 'on' if value_json.security_relevant else 'off' }}"
```

One device as its own sensor (template sensor):

```yaml
template:
  - sensor:
      - name: Camera iotaudit grade
        state: >
          {{ (state_attr('sensor.iotaudit_worst_grade', 'device_list') or [])
             | selectattr('ip', 'eq', '192.168.1.50')
             | map(attribute='grade') | first | default('unknown') }}
```

## 4. Example automation

```yaml
automation:
  - alias: Notify when iotaudit sees new risk
    trigger:
      - platform: state
        entity_id: binary_sensor.iotaudit_something_changed
        to: "on"
    action:
      - service: notify.notify
        data:
          message: >
            iotaudit: {{ state_attr('sensor.iotaudit_worst_grade', 'changed') }}
            device(s) changed, worst grade {{ states('sensor.iotaudit_worst_grade') }}.
```

{% endraw %}

To run audits on a schedule, use cron on the audit machine, for example once a night.

[Back to the device pages](index.html) | [iotaudit on GitHub](https://github.com/emirmrkaljevic/iotaudit)
