"""Compare two saved iotaudit JSON audits.

Devices match by MAC when both sides have one and they agree. Otherwise a
device matches by IP, unless both sides have MACs and those MACs differ.
A MAC change at the same IP is one device gone and another one new.

Compared per device: destination domains (from destinations and DNS queries)
and destination IPs, countries, open ports, grade, verdict, unencrypted
destinations, and UPnP forwards. LAN peers are not compared. Remote
destination ports are not compared on their own.

UPnP forwards are read from findings with category "upnp", and from a
top-level ``upnp.mappings`` list when the JSON has one (matched by
``internal_client``). An audit saved without that data has no forwards.

``security_relevant`` is true when something security-relevant appeared:
a device, destination domain, destination IP, country, open port, worse
grade, unencrypted destination, or UPnP forward. Items that only went away,
and a grade that improved, are reported and do not by themselves set it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .enrich import normalize_mac

_GRADE_RANK = {letter: index for index, letter in enumerate("ABCDEF")}
_REASON_ORDER = (
    "new_device",
    "new_domain",
    "new_ip",
    "new_country",
    "new_port",
    "grade_worse",
    "new_unencrypted",
    "new_upnp",
)
_UPNP_TITLE = re.compile(r"Port\s+(\d+)\s*/\s*([A-Za-z0-9]+)\s+forwarded", re.IGNORECASE)
_UPNP_INTERNAL = re.compile(r"to\s+\S+:(\d+)")


@dataclass
class Audit:
    """Devices from one saved audit, plus UPnP mappings keyed by client IP."""

    devices: list[dict]
    upnp_by_ip: dict[str, list[dict]] = field(default_factory=dict)


def load_audit(path: str | Path) -> Audit:
    """Load an audit JSON file. Raises ValueError with a short message."""
    file = Path(path)
    if not file.is_file():
        raise ValueError(f"not a file: {file}")
    try:
        text = file.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"cannot read {file.name}: {exc.strerror or exc}") from exc
    except UnicodeError as exc:
        raise ValueError(f"cannot read {file.name} as UTF-8") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"not JSON: {file.name}: line {exc.lineno} column {exc.colno}") from exc
    try:
        return audit_from_json(data)
    except ValueError as exc:
        raise ValueError(f"{file.name}: {exc}") from exc


def audit_from_json(data: object) -> Audit:
    """Accept a device list, one device object, or ``{"devices": [...], "upnp": ...}``."""
    upnp_by_ip: dict[str, list[dict]] = {}
    if isinstance(data, list):
        devices = data
    elif isinstance(data, dict) and isinstance(data.get("devices"), list):
        devices = data["devices"]
        upnp_by_ip = _index_upnp(data.get("upnp"))
    elif isinstance(data, dict) and data.get("ip"):
        devices = [data]
    else:
        raise ValueError(
            "audit JSON must be a list of devices, or an object with a devices list"
        )
    for index, device in enumerate(devices, start=1):
        if not isinstance(device, dict):
            raise ValueError(f"device {index} is not an object")
    return Audit(devices=list(devices), upnp_by_ip=upnp_by_ip)


def audit_from_devices(
    devices: list[dict], upnp_by_ip: dict[str, list[dict]] | None = None,
) -> Audit:
    """Wrap device dicts that are already in memory (the JSON just written)."""
    copied = []
    for index, device in enumerate(devices, start=1):
        if not isinstance(device, dict):
            raise ValueError(f"device {index} is not an object")
        copied.append(device)
    return Audit(devices=copied, upnp_by_ip=dict(upnp_by_ip or {}))


def diff_results(old_path: str, new_path: str) -> dict:
    """Compare two audit JSON files. Same result as ``iotaudit diff --json``."""
    return diff_audits(
        load_audit(old_path), load_audit(new_path), old_label=old_path, new_label=new_path,
    )


def diff_audits(
    old: Audit,
    new: Audit,
    old_label: str | None = None,
    new_label: str | None = None,
) -> dict:
    """Return the machine-readable diff. ``exit_code`` is 1 when risk appeared, else 0."""
    pairs, gone, appeared = _pair_devices(old.devices, new.devices)
    devices: list[dict] = []
    for old_dev, new_dev, how in pairs:
        devices.append(_compare_pair(
            old_dev, new_dev, how, _upnp_for(old, old_dev), _upnp_for(new, new_dev),
        ))
    for device in appeared:
        devices.append(_new_record(device, _upnp_for(new, device)))
    for device in gone:
        devices.append(_gone_record(device, _upnp_for(old, device)))

    seen: list[str] = []
    for device in devices:
        for reason in device["reasons"]:
            if reason not in seen:
                seen.append(reason)
    rank = {name: index for index, name in enumerate(_REASON_ORDER)}
    reasons = sorted(seen, key=lambda name: rank.get(name, len(rank)))
    security = any(device["security_relevant"] for device in devices)
    summary = {
        "devices_old": len(old.devices),
        "devices_new": len(new.devices),
        "matched": len(pairs),
        "unchanged": sum(1 for device in devices if device["status"] == "unchanged"),
        "changed": sum(1 for device in devices if device["status"] == "changed"),
        "new_devices": sum(1 for device in devices if device["status"] == "new"),
        "gone_devices": sum(1 for device in devices if device["status"] == "gone"),
    }
    return {
        "old": old_label,
        "new": new_label,
        "security_relevant": security,
        "exit_code": 1 if security else 0,
        "reasons": reasons,
        "summary": summary,
        "devices": devices,
    }


def format_diff(result: dict) -> str:
    """Plain-English report. Ends with a newline."""
    old = result.get("old") or "the earlier audit"
    new = result.get("new") or "the later audit"
    summary = result["summary"]
    lines = [
        f"Compared {old} with {new}.",
        (
            f"Matched {_count(summary['matched'], 'device')}. "
            f"{summary['unchanged']} unchanged, {summary['changed']} changed, "
            f"{summary['new_devices']} new, {summary['gone_devices']} gone."
        ),
        "",
    ]
    for device in result["devices"]:
        if device["status"] == "unchanged":
            continue
        lines.extend(_device_lines(device))
        lines.append("")
    lines.append(_closing_line(result))
    return "\n".join(lines) + "\n"


def _closing_line(result: dict) -> str:
    if not result["security_relevant"]:
        return "No security-relevant changes appeared."
    count = sum(1 for device in result["devices"] if device["security_relevant"])
    if count == 1:
        return "Security-relevant changes appeared on 1 device."
    return f"Security-relevant changes appeared on {count} devices."


def _device_lines(device: dict) -> list[str]:
    lines = [_header(device)]
    status = device["status"]
    if status == "gone":
        return lines
    if status == "new":
        grade = device["grade"]["new"]
        if grade:
            lines.append(f"  Grade {grade}.")
        verdict = device["verdict"]["new"]
        if verdict:
            lines.append(f"  Verdict: {verdict}")
    else:
        old_ip, new_ip = device.get("old_ip"), device.get("new_ip")
        if old_ip and new_ip and old_ip != new_ip:
            lines.append(f"  Address changed from {old_ip} to {new_ip}.")
        grade = device["grade"]
        if grade["changed"]:
            lines.append(_grade_line(grade))
        verdict = device["verdict"]
        if verdict["changed"]:
            lines.append("  Verdict changed.")
            if verdict["old"]:
                lines.append(f"    Earlier: {verdict['old']}")
            if verdict["new"]:
                lines.append(f"    Now: {verdict['new']}")
    lines.extend(_change_lines(device))
    return lines


def _header(device: dict) -> str:
    label = _label(device)
    status = device["status"]
    if status == "new":
        return f"{label} is new."
    if status == "gone":
        last = device["grade"]["old"]
        if last:
            return f"{label} is gone. Last grade {last}."
        return f"{label} is gone."
    how = "MAC" if device.get("matched_by") == "mac" else "IP"
    return f"{label}, matched by {how}."


def _label(device: dict) -> str:
    ip = device.get("ip") or "unknown device"
    extra = []
    if device.get("mac"):
        extra.append(device["mac"])
    if device.get("vendor"):
        extra.append(device["vendor"])
    if extra:
        return f"{ip} ({', '.join(extra)})"
    return ip


def _grade_line(grade: dict) -> str:
    old, new = grade["old"] or "none", grade["new"] or "none"
    if grade["worsened"]:
        return f"  Grade changed from {old} to {new} (worse)."
    if grade["improved"]:
        return f"  Grade changed from {old} to {new} (better)."
    return f"  Grade changed from {old} to {new}."


def _change_lines(device: dict) -> list[str]:
    lines: list[str] = []
    _add(lines, "New destination domain", "New destination domains", device["new_domains"])
    _add(lines, "Destination domain gone", "Destination domains gone", device["gone_domains"])
    _add(lines, "New destination IP", "New destination IPs", device["new_ips"])
    _add(lines, "Destination IP gone", "Destination IPs gone", device["gone_ips"])
    _add(lines, "New country", "New countries", device["new_countries"])
    _add(lines, "Country no longer seen", "Countries no longer seen", device["gone_countries"])
    _add(lines, "New open port", "New open ports", [_port_text(port) for port in device["new_ports"]])
    _add(lines, "Open port closed", "Open ports closed", [_port_text(port) for port in device["closed_ports"]])
    _add(
        lines, "Newly unencrypted traffic", "Newly unencrypted traffic",
        [_unencrypted_text(row) for row in device["new_unencrypted"]],
    )
    _add(lines, "New UPnP forward", "New UPnP forwards", [_upnp_text(row) for row in device["new_upnp"]])
    _add(
        lines, "UPnP forward closed", "UPnP forwards closed",
        [_upnp_text(row) for row in device["closed_upnp"]],
    )
    return lines


def _add(lines: list[str], one: str, many: str, items: list[str]) -> None:
    if not items:
        return
    label = one if len(items) == 1 else many
    lines.append(f"  {label}: {', '.join(items)}.")


def _port_text(port: dict) -> str:
    label = f"{port['port']}/{port['proto']}"
    notes = [str(note) for note in (port.get("service"), port.get("risk")) if note]
    if notes:
        return f"{label} ({', '.join(notes)})"
    return label


def _unencrypted_text(row: dict) -> str:
    notes = []
    domains = row.get("domains") or []
    ports = row.get("ports") or []
    if domains:
        notes.append(", ".join(domains))
    if len(ports) == 1:
        notes.append(f"port {ports[0]}")
    elif ports:
        notes.append("ports " + ", ".join(str(port) for port in ports))
    if notes:
        return f"{row['ip']} ({'; '.join(notes)})"
    return str(row["ip"])


def _upnp_text(row: dict) -> str:
    internal = row.get("internal_port")
    target = f"device port {internal}" if internal is not None else "this device"
    text = f"{row['protocol']} public port {row['external_port']} to {target}"
    if row.get("remote_host"):
        text += f", from {row['remote_host']} only"
    if row.get("description"):
        text += f", description {row['description']}"
    return text


def _count(count: int, singular: str) -> str:
    word = singular if count == 1 else singular + "s"
    return f"{count} {word}"


def _pair_devices(old: list[dict], new: list[dict]):
    pairs: list[tuple[dict, dict, str]] = []
    used_old: set[int] = set()
    used_new: set[int] = set()

    new_by_mac: dict[str, int] = {}
    for index, device in enumerate(new):
        mac = _mac(device)
        if mac and mac not in new_by_mac:
            new_by_mac[mac] = index
    for index, device in enumerate(old):
        mac = _mac(device)
        if not mac:
            continue
        other = new_by_mac.get(mac)
        if other is None or other in used_new:
            continue
        pairs.append((device, new[other], "mac"))
        used_old.add(index)
        used_new.add(other)

    new_by_ip: dict[str, int] = {}
    for index, device in enumerate(new):
        if index in used_new:
            continue
        ip = _ip(device)
        if ip and ip not in new_by_ip:
            new_by_ip[ip] = index
    for index, device in enumerate(old):
        if index in used_old:
            continue
        ip = _ip(device)
        if not ip:
            continue
        other = new_by_ip.get(ip)
        if other is None or other in used_new:
            continue
        old_mac, new_mac = _mac(device), _mac(new[other])
        if old_mac and new_mac and old_mac != new_mac:
            continue
        pairs.append((device, new[other], "ip"))
        used_old.add(index)
        used_new.add(other)

    gone = [old[index] for index in range(len(old)) if index not in used_old]
    appeared = [new[index] for index in range(len(new)) if index not in used_new]
    return pairs, gone, appeared


def _compare_pair(
    old: dict,
    new: dict,
    matched_by: str | None,
    old_upnp: list[dict],
    new_upnp: list[dict],
) -> dict:
    old_domains, new_domains = _domains(old), _domains(new)
    old_ips, new_ips = _dest_ips(old), _dest_ips(new)
    old_countries, new_countries = _countries(old), _countries(new)
    old_port_map, new_port_map = _port_map(old), _port_map(new)
    old_plain, new_plain = _unencrypted(old), _unencrypted(new)
    old_forwards, new_forwards = _forwards(old, old_upnp), _forwards(new, new_upnp)
    grade = _grade_change(old, new)
    verdict = _verdict_change(old, new)
    old_ip, new_ip = _ip(old) or None, _ip(new) or None

    added_domains = sorted(new_domains - old_domains)
    removed_domains = sorted(old_domains - new_domains)
    added_ips = sorted(new_ips - old_ips)
    removed_ips = sorted(old_ips - new_ips)
    added_countries = sorted(new_countries - old_countries)
    removed_countries = sorted(old_countries - new_countries)
    added_ports = [new_port_map[key] for key in sorted(set(new_port_map) - set(old_port_map))]
    removed_ports = [old_port_map[key] for key in sorted(set(old_port_map) - set(new_port_map))]
    added_plain = [new_plain[ip] for ip in sorted(set(new_plain) - set(old_plain))]
    added_upnp = [new_forwards[key] for key in sorted(set(new_forwards) - set(old_forwards))]
    removed_upnp = [old_forwards[key] for key in sorted(set(old_forwards) - set(new_forwards))]

    reasons = _reasons(
        new_domains=added_domains,
        new_ips=added_ips,
        new_countries=added_countries,
        new_ports=added_ports,
        grade_worse=grade["worsened"],
        new_unencrypted=added_plain,
        new_upnp=added_upnp,
    )
    changed = bool(
        reasons or removed_domains or removed_ips or removed_countries or removed_ports
        or removed_upnp or grade["changed"] or verdict["changed"] or (old_ip != new_ip)
    )
    return _record(
        status="changed" if changed else "unchanged",
        matched_by=matched_by,
        old=old,
        new=new,
        old_ip=old_ip,
        new_ip=new_ip,
        grade=grade,
        verdict=verdict,
        added_domains=added_domains,
        removed_domains=removed_domains,
        added_ips=added_ips,
        removed_ips=removed_ips,
        added_countries=added_countries,
        removed_countries=removed_countries,
        added_ports=added_ports,
        removed_ports=removed_ports,
        added_plain=added_plain,
        added_upnp=added_upnp,
        removed_upnp=removed_upnp,
        reasons=reasons,
    )


def _new_record(device: dict, upnp: list[dict]) -> dict:
    record = _compare_pair(_blank(), device, None, [], upnp)
    record["status"] = "new"
    record["grade"]["changed"] = False
    record["verdict"]["changed"] = False
    reasons = ["new_device"]
    for reason in record["reasons"]:
        if reason not in reasons:
            reasons.append(reason)
    record["reasons"] = reasons
    record["security_relevant"] = True
    return record


def _gone_record(device: dict, upnp: list[dict]) -> dict:
    record = _compare_pair(device, _blank(), None, upnp, [])
    record["status"] = "gone"
    record["grade"]["changed"] = False
    record["grade"]["worsened"] = False
    record["grade"]["improved"] = False
    record["verdict"]["changed"] = False
    record["reasons"] = []
    record["security_relevant"] = False
    return record


def _record(
    *,
    status: str,
    matched_by: str | None,
    old: dict,
    new: dict,
    old_ip: str | None,
    new_ip: str | None,
    grade: dict,
    verdict: dict,
    added_domains: list[str],
    removed_domains: list[str],
    added_ips: list[str],
    removed_ips: list[str],
    added_countries: list[str],
    removed_countries: list[str],
    added_ports: list[dict],
    removed_ports: list[dict],
    added_plain: list[dict],
    added_upnp: list[dict],
    removed_upnp: list[dict],
    reasons: list[str],
) -> dict:
    mac = _mac(new) or _mac(old)
    vendor = _vendor(new) or _vendor(old)
    return {
        "status": status,
        "matched_by": matched_by,
        "ip": new_ip or old_ip,
        "mac": mac,
        "vendor": vendor,
        "old_ip": old_ip,
        "new_ip": new_ip,
        "grade": grade,
        "verdict": verdict,
        "new_domains": added_domains,
        "gone_domains": removed_domains,
        "new_ips": added_ips,
        "gone_ips": removed_ips,
        "new_countries": added_countries,
        "gone_countries": removed_countries,
        "new_ports": added_ports,
        "closed_ports": removed_ports,
        "new_unencrypted": added_plain,
        "new_upnp": added_upnp,
        "closed_upnp": removed_upnp,
        "security_relevant": bool(reasons),
        "reasons": reasons,
    }


def _reasons(
    *,
    new_domains: list[str],
    new_ips: list[str],
    new_countries: list[str],
    new_ports: list[dict],
    grade_worse: bool,
    new_unencrypted: list[dict],
    new_upnp: list[dict],
) -> list[str]:
    present = {
        "new_domain": bool(new_domains),
        "new_ip": bool(new_ips),
        "new_country": bool(new_countries),
        "new_port": bool(new_ports),
        "grade_worse": grade_worse,
        "new_unencrypted": bool(new_unencrypted),
        "new_upnp": bool(new_upnp),
    }
    return [reason for reason in _REASON_ORDER if present.get(reason)]


def _blank() -> dict:
    return {
        "ip": None,
        "mac": None,
        "destinations": [],
        "dns_queries": [],
        "open_ports": [],
        "findings": [],
        "destination_countries": [],
    }


def _upnp_for(audit: Audit, device: dict) -> list[dict]:
    ip = _ip(device)
    if not ip:
        return []
    return list(audit.upnp_by_ip.get(ip) or [])


def _index_upnp(raw: object) -> dict[str, list[dict]]:
    if isinstance(raw, dict):
        mappings = raw.get("mappings") or []
    elif isinstance(raw, list):
        mappings = raw
    else:
        return {}
    if not isinstance(mappings, list):
        return {}
    by_ip: dict[str, list[dict]] = {}
    for item in mappings:
        if not isinstance(item, dict):
            continue
        ip = str(item.get("internal_client") or "").strip()
        if not ip:
            continue
        by_ip.setdefault(ip, []).append(item)
    return by_ip


def _mac(device: dict) -> str | None:
    return normalize_mac(device.get("mac"))


def _ip(device: dict) -> str:
    raw = device.get("ip")
    if raw is None:
        return ""
    return str(raw).strip()


def _vendor(device: dict) -> str | None:
    raw = device.get("vendor")
    if not raw:
        return None
    text = str(raw).strip()
    return text or None


def _norm_domain(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip().lower().rstrip(".")
    return text or None


def _norm_ip(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if ":" in text:
        return text.lower()
    return text


def _domains(device: dict) -> set[str]:
    found: set[str] = set()
    for dest in device.get("destinations") or []:
        if not isinstance(dest, dict):
            continue
        for name in dest.get("domains") or []:
            domain = _norm_domain(name)
            if domain:
                found.add(domain)
    for name in device.get("dns_queries") or []:
        domain = _norm_domain(name)
        if domain:
            found.add(domain)
    return found


def _dest_ips(device: dict) -> set[str]:
    found: set[str] = set()
    for dest in device.get("destinations") or []:
        if not isinstance(dest, dict):
            continue
        ip = _norm_ip(dest.get("ip"))
        if ip:
            found.add(ip)
    return found


def _countries(device: dict) -> set[str]:
    found: set[str] = set()
    for row in device.get("destination_countries") or []:
        if isinstance(row, str):
            name = row
        elif isinstance(row, dict):
            name = row.get("country") or ""
        else:
            continue
        text = str(name).strip().upper()
        if text:
            found.add(text)
    for dest in device.get("destinations") or []:
        if isinstance(dest, dict) and dest.get("country"):
            text = str(dest["country"]).strip().upper()
            if text:
                found.add(text)
    return found


def _port_map(device: dict) -> dict[tuple[int, str], dict]:
    found: dict[tuple[int, str], dict] = {}
    for item in device.get("open_ports") or []:
        row = _port_row(item)
        if row:
            found[(row["port"], row["proto"])] = row
    return found


def _port_row(item: object) -> dict | None:
    if isinstance(item, int):
        return {"port": item, "proto": "tcp", "service": None, "risk": None}
    if not isinstance(item, dict) or item.get("port") is None:
        return None
    try:
        port = int(item["port"])
    except (TypeError, ValueError):
        return None
    proto = str(item.get("proto") or "tcp").strip().lower() or "tcp"
    return {
        "port": port,
        "proto": proto,
        "service": item.get("service") or None,
        "risk": item.get("risk") or None,
    }


def _unencrypted(device: dict) -> dict[str, dict]:
    found: dict[str, dict] = {}
    for dest in device.get("destinations") or []:
        if not isinstance(dest, dict) or not _is_unencrypted(dest):
            continue
        ip = _norm_ip(dest.get("ip"))
        if not ip:
            continue
        domains = sorted({
            domain for domain in (_norm_domain(name) for name in dest.get("domains") or []) if domain
        })
        ports = sorted(_int_list(dest.get("ports")))
        kind = dest.get("encryption_kind") or "plaintext"
        found[ip] = {"ip": ip, "domains": domains, "ports": ports, "encryption_kind": kind}
    return found


def _is_unencrypted(dest: dict) -> bool:
    kind = str(dest.get("encryption_kind") or "").strip().lower()
    if kind == "plaintext":
        return True
    if kind:
        return False
    return dest.get("encrypted") is False


def _int_list(values: object) -> list[int]:
    if not isinstance(values, list):
        return []
    out = []
    for value in values:
        try:
            out.append(int(value))
        except (TypeError, ValueError):
            continue
    return out


def _forwards(device: dict, extra: list[dict]) -> dict[tuple, dict]:
    found: dict[tuple, dict] = {}
    for finding in device.get("findings") or []:
        row = _forward_from_finding(finding)
        if row:
            found[_upnp_key(row)] = row
    for mapping in extra:
        row = _forward_from_mapping(mapping)
        if row and _upnp_key(row) not in found:
            found[_upnp_key(row)] = row
    return found


def _upnp_key(row: dict) -> tuple:
    return (
        row["protocol"],
        row["external_port"],
        row.get("internal_port"),
        row.get("remote_host") or "",
    )


def _forward_from_finding(finding: object) -> dict | None:
    if not isinstance(finding, dict):
        return None
    if str(finding.get("category") or "").lower() != "upnp":
        return None
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    external = evidence.get("external_port")
    protocol = evidence.get("protocol")
    internal = evidence.get("internal_port")
    if external is None or not protocol:
        match = _UPNP_TITLE.search(str(finding.get("title") or ""))
        if not match:
            return None
        external = match.group(1)
        protocol = match.group(2)
        if internal is None:
            detail = _UPNP_INTERNAL.search(str(finding.get("detail") or ""))
            internal = detail.group(1) if detail else None
    try:
        external_port = int(external)
    except (TypeError, ValueError):
        return None
    proto = str(protocol).strip().upper()
    if not proto:
        return None
    try:
        internal_port = int(internal) if internal is not None and internal != "" else None
    except (TypeError, ValueError):
        internal_port = None
    remote = str(evidence.get("remote_host") or "").strip() or None
    description = evidence.get("description")
    description = str(description).strip() if description else None
    return {
        "protocol": proto,
        "external_port": external_port,
        "internal_port": internal_port,
        "remote_host": remote,
        "description": description or None,
    }


def _forward_from_mapping(mapping: dict) -> dict | None:
    if not isinstance(mapping, dict) or not mapping.get("enabled", True):
        return None
    try:
        external_port = int(mapping["external_port"])
    except (KeyError, TypeError, ValueError):
        return None
    proto = str(mapping.get("protocol") or "").strip().upper()
    if not proto:
        return None
    internal = mapping.get("internal_port")
    try:
        internal_port = int(internal) if internal is not None and internal != "" else None
    except (TypeError, ValueError):
        internal_port = None
    remote = str(mapping.get("remote_host") or "").strip() or None
    description = mapping.get("description")
    description = str(description).strip() if description else None
    return {
        "protocol": proto,
        "external_port": external_port,
        "internal_port": internal_port,
        "remote_host": remote,
        "description": description or None,
    }


def _grade_letter(device: dict) -> str | None:
    raw = device.get("grade")
    if raw is None:
        return None
    text = str(raw).strip().upper()
    if not text:
        return None
    letter = text[0]
    if letter not in _GRADE_RANK:
        return None
    return letter


def _grade_change(old: dict, new: dict) -> dict:
    old_letter, new_letter = _grade_letter(old), _grade_letter(new)
    worsened = bool(
        old_letter and new_letter and _GRADE_RANK[new_letter] > _GRADE_RANK[old_letter]
    )
    improved = bool(
        old_letter and new_letter and _GRADE_RANK[new_letter] < _GRADE_RANK[old_letter]
    )
    return {
        "old": old_letter,
        "new": new_letter,
        "changed": old_letter != new_letter,
        "worsened": worsened,
        "improved": improved,
    }


def _verdict_text(device: dict) -> str:
    raw = device.get("verdict")
    if raw is None:
        return ""
    return str(raw).strip()


def _verdict_change(old: dict, new: dict) -> dict:
    old_text, new_text = _verdict_text(old), _verdict_text(new)
    return {"old": old_text, "new": new_text, "changed": old_text != new_text}
