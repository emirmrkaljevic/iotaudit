"""Compact JSON summary for Home Assistant sensors.

Home Assistant can read this file with a ``command_line`` sensor
(``cat summary.json``) and pull per-device values out with templates.
The same summary can also be published to an MQTT broker you already run.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from pathlib import Path

from .enrich import normalize_mac

_GRADES = "ABCDEF"


def _name(device: dict) -> str:
    return str(device.get("looks_like") or device.get("vendor") or device.get("ip") or "unknown")


def _key(device: dict) -> tuple:
    return (normalize_mac(device.get("mac")) or None, device.get("ip"))


def _diff_index(diff: dict | None) -> dict:
    index: dict = {}
    for record in (diff or {}).get("devices") or []:
        mac = normalize_mac(record.get("mac")) or None
        if mac:
            index[("mac", mac)] = record
        if record.get("ip"):
            index.setdefault(("ip", record["ip"]), record)
    return index


def ha_summary(devices: list[dict], diff: dict | None = None, now: datetime | None = None) -> dict:
    """Build the summary. ``changed`` is None for every device when there is no earlier run."""
    index = _diff_index(diff)
    rows = []
    for device in devices:
        mac, ip = _key(device)
        record = index.get(("mac", mac)) if mac else None
        record = record or index.get(("ip", ip))
        if diff is None:
            changed, status = None, "first_run"
        elif record is None:
            changed, status = True, "new"
        else:
            status = record.get("status") or "changed"
            changed = status != "unchanged"
        rows.append({
            "name": _name(device),
            "ip": ip,
            "grade": device.get("grade"),
            "findings": len(device.get("findings") or []),
            "changed": changed,
            "status": status,
        })
    gone = [r for r in (diff or {}).get("devices") or [] if r.get("status") == "gone"]
    grades = [r["grade"] for r in rows if r["grade"] in _GRADES]
    return {
        "generated": (now or datetime.now()).isoformat(timespec="seconds"),
        "devices": len(rows),
        "worst_grade": max(grades, key=_GRADES.index) if grades else None,
        "findings": sum(r["findings"] for r in rows),
        "changed": sum(1 for r in rows if r["changed"]) + len(gone),
        "gone": len(gone),
        "security_relevant": bool(diff and diff.get("security_relevant")),
        "device_list": rows,
    }


def write_ha_summary(path: str | Path, summary: dict) -> Path:
    dest = Path(path).expanduser()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return dest


CSV_FIELDS = ["name", "ip", "grade", "findings", "changed", "status"]


def summary_csv(summary: dict) -> str:
    """One row per device, for spreadsheets. ``changed`` is empty on a first run."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    for row in summary.get("device_list") or []:
        out = {k: row.get(k) for k in CSV_FIELDS}
        if out["changed"] is not None:
            out["changed"] = "yes" if out["changed"] else "no"
        writer.writerow(out)
    return buf.getvalue()


def summary_markdown(summary: dict) -> str:
    """Markdown table, handy to paste into an issue or forum post."""
    def cell(value) -> str:
        if value is None:
            return ""
        if value is True or value is False:
            return "yes" if value else "no"
        return str(value).replace("|", "\\|").replace("\n", " ")

    lines = [
        f"iotaudit summary: {summary.get('devices', 0)} devices, "
        f"worst grade {summary.get('worst_grade') or 'n/a'}, "
        f"{summary.get('findings', 0)} finding{'' if summary.get('findings') == 1 else 's'}",
        "",
        "| " + " | ".join(CSV_FIELDS) + " |",
        "|" + "---|" * len(CSV_FIELDS),
    ]
    for row in summary.get("device_list") or []:
        lines.append("| " + " | ".join(cell(row.get(k)) for k in CSV_FIELDS) + " |")
    return "\n".join(lines) + "\n"


def redact_summary(summary: dict) -> dict:
    """Copy of the summary without IP addresses, safe to post publicly."""
    out = dict(summary)
    out["device_list"] = []
    for n, row in enumerate(summary.get("device_list") or [], 1):
        row = dict(row)
        if row.get("name") == row.get("ip"):
            row["name"] = f"device {n}"
        row["ip"] = None
        out["device_list"].append(row)
    out["redacted"] = True
    return out


def topic_slug(value: str) -> str:
    """Turn a name or IP into a short MQTT topic / unique_id fragment."""
    out = []
    prev_us = False
    for ch in (value or "").lower():
        if ch.isalnum():
            out.append(ch)
            prev_us = False
        elif not prev_us:
            out.append("_")
            prev_us = True
    return "".join(out).strip("_") or "device"


def device_unique_id(device: dict, index: int) -> str:
    ip = topic_slug(str(device.get("ip") or ""))
    name = topic_slug(str(device.get("name") or ""))
    if ip and name and name != ip:
        return f"iotaudit_{name}_{ip}"
    if ip:
        return f"iotaudit_{ip}"
    if name:
        return f"iotaudit_{name}"
    return f"iotaudit_device_{index}"


def ha_mqtt_messages(
    summary: dict,
    *,
    base_topic: str = "iotaudit",
    discovery: bool = True,
    discovery_prefix: str = "homeassistant",
    version: str | None = None,
) -> list[tuple[str, str, bool]]:
    """Build retained MQTT messages for a Home Assistant summary.

    Publishes the full JSON under ``base_topic/summary``, plus compact
    topics for the worst grade, the changed flag, and each device grade.
    When *discovery* is true, also publishes Home Assistant MQTT discovery
    configs so sensors appear without YAML.
    """
    from . import __version__

    sw = version or __version__
    base = base_topic.strip().strip("/") or "iotaudit"
    prefix = discovery_prefix.strip().strip("/") or "homeassistant"
    payload = json.dumps(summary, separators=(",", ":"))
    messages: list[tuple[str, str, bool]] = [
        (f"{base}/summary", payload, True),
        (f"{base}/worst_grade", str(summary.get("worst_grade") or ""), True),
        (f"{base}/changed", str(int(summary.get("changed") or 0)), True),
        (f"{base}/security_relevant", "true" if summary.get("security_relevant") else "false", True),
        (f"{base}/generated", str(summary.get("generated") or ""), True),
    ]
    devices = list(summary.get("device_list") or [])
    for i, device in enumerate(devices):
        uid = device_unique_id(device, i)
        messages.append((f"{base}/device/{uid}/grade", str(device.get("grade") or ""), True))
        messages.append((
            f"{base}/device/{uid}/state",
            json.dumps(device, separators=(",", ":")),
            True,
        ))

    if not discovery:
        return messages

    ha_device = {
        "identifiers": ["iotaudit"],
        "name": "iotaudit",
        "manufacturer": "iotaudit",
        "model": "network audit",
        "sw_version": sw,
    }

    def config(component: str, object_id: str, body: dict) -> tuple[str, str, bool]:
        body = dict(body)
        body["device"] = ha_device
        body.setdefault("availability_topic", f"{base}/availability")
        return (f"{prefix}/{component}/{object_id}/config", json.dumps(body, separators=(",", ":")), True)

    messages.append((f"{base}/availability", "online", True))
    messages.append(config("sensor", "iotaudit_worst_grade", {
        "name": "iotaudit worst grade",
        "unique_id": "iotaudit_worst_grade",
        "state_topic": f"{base}/worst_grade",
        "icon": "mdi:shield-alert",
    }))
    messages.append(config("binary_sensor", "iotaudit_changed", {
        "name": "iotaudit something changed",
        "unique_id": "iotaudit_changed",
        "state_topic": f"{base}/security_relevant",
        "payload_on": "true",
        "payload_off": "false",
        "device_class": "problem",
    }))
    messages.append(config("sensor", "iotaudit_changed_count", {
        "name": "iotaudit changed devices",
        "unique_id": "iotaudit_changed_count",
        "state_topic": f"{base}/changed",
        "icon": "mdi:swap-horizontal",
    }))
    messages.append(config("sensor", "iotaudit_generated", {
        "name": "iotaudit last audit",
        "unique_id": "iotaudit_generated",
        "state_topic": f"{base}/generated",
        "icon": "mdi:clock-outline",
    }))
    messages.append(config("sensor", "iotaudit_summary", {
        "name": "iotaudit summary",
        "unique_id": "iotaudit_summary",
        "state_topic": f"{base}/summary",
        "value_template": "{{ value_json.worst_grade }}",
        "json_attributes_topic": f"{base}/summary",
        "icon": "mdi:lan",
    }))
    for i, device in enumerate(devices):
        uid = device_unique_id(device, i)
        label = device.get("name") or device.get("ip") or f"device {i + 1}"
        messages.append(config("sensor", uid, {
            "name": f"iotaudit {label}",
            "unique_id": uid,
            "state_topic": f"{base}/device/{uid}/grade",
            "json_attributes_topic": f"{base}/device/{uid}/state",
            "icon": "mdi:router-wireless",
        }))
    return messages


def publish_ha_summary(
    summary: dict,
    target_spec: str,
    *,
    base_topic: str = "iotaudit",
    discovery: bool = True,
    username: str | None = None,
    password: str | None = None,
) -> int:
    """Publish *summary* to a broker. Raises ValueError or mqttpub.MqttError."""
    from .mqttpub import parse_mqtt_target, publish_many

    target = parse_mqtt_target(target_spec, username=username, password=password)
    messages = ha_mqtt_messages(summary, base_topic=base_topic, discovery=discovery)
    return publish_many(target, messages)


def publish_ha_mqtt(summary: dict, args) -> int:
    """Publish from argparse flags. Returns 0 on success, 1 on failure. Prints one line."""
    import sys

    from .mqttpub import MqttError, parse_mqtt_target

    target = getattr(args, "ha_mqtt", None)
    if not target:
        return 0
    try:
        count = publish_ha_summary(
            summary,
            target,
            base_topic=getattr(args, "ha_mqtt_topic", None) or "iotaudit",
            discovery=getattr(args, "ha_mqtt_discovery", True),
            username=getattr(args, "ha_mqtt_user", None),
        )
        info = parse_mqtt_target(target, username=getattr(args, "ha_mqtt_user", None))
        scheme = "mqtts" if info["tls"] else "mqtt"
        print(f"Published {count} MQTT messages to {scheme}://{info['host']}:{info['port']}")
        return 0
    except (ValueError, OSError, TimeoutError, MqttError) as exc:
        print(f"error: MQTT publish failed: {exc}", file=sys.stderr)
        return 1
