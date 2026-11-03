"""Compact JSON summary for Home Assistant sensors.

Home Assistant can read this file with a ``command_line`` sensor
(``cat summary.json``) and pull per-device values out with templates.
Everything stays on disk; nothing is sent anywhere.
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
