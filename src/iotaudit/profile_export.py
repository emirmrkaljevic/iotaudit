"""Build a shareable device-profile YAML from a saved audit.

The draft contains only vendor, an optional model, public domains,
destination ports, and destination countries. Local IPs, MACs, hostnames,
SSIDs, serials and paths are removed with the same redaction used by
`iotaudit redact`, then dropped from the profile even as placeholders.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

import yaml

from .redact import redact_audit

# Multi-part public suffixes so account-like hosts collapse to the registrable
# domain (eu-west-1.amazonaws.com -> amazonaws.com, not west-1.amazonaws.com).
_MULTI_TLD = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk",
    "com.au", "net.au", "org.au",
    "co.nz", "co.jp", "co.kr", "co.in", "co.za",
    "com.br", "com.cn", "com.tw", "com.hk", "com.sg", "com.mx",
})
_LOCAL_SUFFIXES = frozenset({
    "local", "lan", "home", "internal", "intranet", "localdomain", "dhcp",
    "corp", "private",
})
_PLACEHOLDER = re.compile(r"^(lan|host)-\d+$", re.I)
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_MAC = re.compile(r"^[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}$")
_SLUG = re.compile(r"[^a-z0-9]+")
_SAFE_TOKEN = re.compile(r"^[A-Za-z][A-Za-z0-9 +/().-]{0,80}$")


def _devices(data: Any) -> list[dict]:
    if isinstance(data, list):
        devices = data
    elif isinstance(data, dict) and isinstance(data.get("devices"), list):
        devices = data["devices"]
    elif isinstance(data, dict) and data.get("ip"):
        devices = [data]
    else:
        raise ValueError(
            "audit JSON must be a list of devices, or an object with a devices list"
        )
    for index, device in enumerate(devices, start=1):
        if not isinstance(device, dict):
            raise ValueError(f"device {index} is not an object")
    return devices


def _norm_mac(text: str) -> str:
    return text.lower().replace("-", ":")


def find_device(devices: list[dict], selector: str) -> tuple[int, dict]:
    """Return (0-based index, device) for an index, IP, MAC, vendor, or hostname."""
    raw = (selector or "").strip()
    if not raw:
        raise ValueError("pass a 1-based index, vendor, or device IP")
    if raw.isdigit():
        index = int(raw)
        if 1 <= index <= len(devices):
            return index - 1, devices[index - 1]
        raise ValueError(
            f"no device at index {index} ({len(devices)} in the audit)"
        )

    hits: list[tuple[int, dict]] = []
    lowered = raw.lower()
    mac_sel = _norm_mac(raw) if _MAC.match(raw) else None
    for i, dev in enumerate(devices):
        ip = str(dev.get("ip") or "")
        mac = _norm_mac(str(dev.get("mac") or ""))
        vendor = str(dev.get("vendor") or "")
        hostname = str(dev.get("hostname") or "")
        profile = str(dev.get("profile") or "")
        if ip == raw or (mac_sel and mac == mac_sel):
            hits.append((i, dev))
            continue
        if vendor.lower() == lowered or hostname.lower() == lowered or profile.lower() == lowered:
            hits.append((i, dev))
            continue
        if vendor and lowered in vendor.lower():
            hits.append((i, dev))
    # unique hits only
    uniq = []
    seen = set()
    for item in hits:
        if item[0] not in seen:
            seen.add(item[0])
            uniq.append(item)
    if len(uniq) == 1:
        return uniq[0]
    if len(uniq) > 1:
        raise ValueError(
            f"{len(uniq)} devices matched that selector. Pass a 1-based index."
        )
    raise ValueError(
        f"no device matched that selector ({len(devices)} in the audit). "
        "Try a 1-based index, the vendor name, or an IP."
    )


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _is_local_ip(text: str) -> bool:
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return False
    return addr.is_private or addr.is_link_local or addr.is_loopback or addr.is_reserved


def _registrable(name: str) -> str | None:
    host = name.strip().lower().rstrip(".")
    if not host or _is_ip(host) or _PLACEHOLDER.match(host):
        return None
    if any(ch in host for ch in "/\\ "):
        return None
    parts = host.split(".")
    if len(parts) < 2 or not all(_DNS_LABEL.match(p) for p in parts):
        return None
    if parts[-1] in _LOCAL_SUFFIXES:
        return None
    last2 = ".".join(parts[-2:])
    if last2 in _MULTI_TLD:
        if len(parts) < 3:
            return None
        return ".".join(parts[-3:])
    return last2


def _safe_label(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or _PLACEHOLDER.match(text) or _is_ip(text) or _MAC.match(text):
        return None
    if any(ch in text for ch in "/\\:@") or "lan-" in text.lower() or "host-" in text.lower():
        return None
    if not _SAFE_TOKEN.match(text):
        return None
    return text


def _model_from(device: dict) -> str | None:
    direct = _safe_label(device.get("model"))
    if direct:
        return direct
    return None


def _type_label(device: dict) -> str | None:
    info = device.get("device_type")
    if not isinstance(info, dict):
        return None
    for key in ("label", "type"):
        label = _safe_label(info.get(key))
        if label and " " not in label:
            return label.lower()
    return None


def _public_domains(device: dict) -> list[str]:
    names: list[str] = []
    for item in device.get("dns_queries") or []:
        if isinstance(item, str):
            names.append(item)
    for dest in device.get("destinations") or []:
        if not isinstance(dest, dict):
            continue
        if dest.get("lan") or dest.get("special_use"):
            continue
        ip = dest.get("ip")
        if isinstance(ip, str) and (ip.startswith("lan-") or _is_local_ip(ip)):
            continue
        for item in dest.get("domains") or []:
            if isinstance(item, str):
                names.append(item)
    found: list[str] = []
    seen: set[str] = set()
    for name in names:
        domain = _registrable(name)
        if domain and domain not in seen:
            seen.add(domain)
            found.append(domain)
    return sorted(found)


def _destination_ports(device: dict) -> list[int]:
    ports: set[int] = set()
    for dest in device.get("destinations") or []:
        if not isinstance(dest, dict):
            continue
        if dest.get("lan") or dest.get("special_use"):
            continue
        ip = dest.get("ip")
        if isinstance(ip, str) and (ip.startswith("lan-") or _is_local_ip(ip)):
            continue
        for port in dest.get("ports") or []:
            try:
                number = int(port)
            except (TypeError, ValueError):
                continue
            if 1 <= number <= 65535:
                ports.add(number)
    return sorted(ports)


def _countries(device: dict) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()

    def add(value: Any) -> None:
        label = _safe_label(value)
        if not label:
            return
        key = label.lower()
        if key in seen:
            return
        seen.add(key)
        found.append(label)

    rows = device.get("destination_countries") or []
    if isinstance(rows, list):
        for row in rows:
            if isinstance(row, dict):
                add(row.get("country"))
            elif isinstance(row, str):
                add(row)
    for dest in device.get("destinations") or []:
        if isinstance(dest, dict) and not dest.get("lan"):
            add(dest.get("country"))
    return found


def _slug(*parts: str | None) -> str:
    raw = "-".join(p for p in parts if p)
    text = _SLUG.sub("-", raw.lower()).strip("-")
    return text or "observed-device"


def profile_from_device(device: dict) -> dict:
    """Build a bundled-format profile dict from an already-redacted device."""
    vendor = _safe_label(device.get("vendor"))
    model = _model_from(device)
    typ = _type_label(device)
    domains = _public_domains(device)
    if not domains:
        raise ValueError(
            "no public destinations to put in a profile (only local or unresolvable traffic)"
        )
    existing = _safe_label(device.get("profile"))
    if existing:
        name = existing
    elif vendor and typ:
        name = f"{vendor} {typ}"
    elif vendor:
        name = f"{vendor} device"
    else:
        name = "Observed device"
    profile: dict[str, Any] = {
        "id": _slug(vendor, typ or model),
        "name": name,
        "match": {"domains": list(domains)},
    }
    if vendor:
        profile["match"]["mac_vendors"] = [vendor]
        # keep domains first in the file: rebuild match in a stable order
        profile["match"] = {
            "mac_vendors": [vendor],
            "domains": list(domains),
        }
    if model:
        profile["model"] = model
    profile["expected_domains"] = list(domains)
    ports = _destination_ports(device)
    if ports:
        profile["expected_ports"] = ports
    countries = _countries(device)
    if countries:
        profile["destination_countries"] = countries
    notes = (
        "Draft exported from a local audit. Review the vendor, model and "
        "domains before sharing. Drop any domain that is not this product's "
        "usual cloud, and add a public source if you have one."
    )
    if countries:
        notes += " Destination countries observed: " + ", ".join(countries) + "."
    profile["notes"] = notes
    return profile


def render_profile(profile: dict) -> str:
    body = yaml.safe_dump(
        profile,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
    )
    header = (
        "# Draft iotaudit device profile. Review before you share it.\n"
        "# Contains only vendor, model, public domains, ports and destination countries.\n"
        "# Local IPs, MACs, hostnames, SSIDs and paths were removed with iotaudit redact.\n"
    )
    return header + body


def export_profile(data: Any, selector: str) -> str:
    """Redact a saved audit and return a draft profile YAML for one device."""
    devices = _devices(data)
    index, _original = find_device(devices, selector)
    redacted = redact_audit(data)
    redacted_devices = _devices(redacted)
    if index >= len(redacted_devices):
        raise ValueError("redaction dropped the selected device")
    profile = profile_from_device(redacted_devices[index])
    return render_profile(profile)
