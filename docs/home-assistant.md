---
title: iotaudit in Home Assistant
---
# Show iotaudit results in Home Assistant

iotaudit can write a small JSON file after each audit. Home Assistant reads it with a `command_line` sensor, so you get a dashboard card and can trigger an automation when a device changes or the worst grade drops. Everything stays on your machine.

## 1. Write the summary

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
