"""Remove local network details from a saved audit before sharing it.

Private and link-local IP addresses, MAC addresses, local hostnames, and
capture source details (interface names, file paths) are replaced with stable
placeholders, so the same device keeps the same label everywhere in the file.
Public cloud destinations stay as they are: they are the point of the report.
"""

from __future__ import annotations

import ipaddress
import re

_MAC = re.compile(r"\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(r"(?<![0-9A-Za-z:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Za-z:])")
_LOCAL_NAME_KEYS = {"hostname", "mdns_name", "dhcp_name"}
_META_DROP = {"source", "iface", "interface", "ssid", "path", "pcap"}


def _is_local(text: str) -> bool:
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return False
    return addr.is_private or addr.is_link_local or addr.is_loopback


class Redactor:
    def __init__(self) -> None:
        self.ips: dict[str, str] = {}
        self.macs: dict[str, str] = {}
        self.names: dict[str, str] = {}

    def ip(self, text: str) -> str:
        if text not in self.ips:
            self.ips[text] = f"lan-{len(self.ips) + 1}"
        return self.ips[text]

    def mac(self, text: str) -> str:
        key = text.lower().replace("-", ":")
        if key not in self.macs:
            hi, lo = divmod(len(self.macs) + 1, 256)
            self.macs[key] = f"02:00:00:00:{hi:02x}:{lo:02x}"
        return self.macs[key]

    def name(self, text: str) -> str:
        if text not in self.names:
            self.names[text] = f"host-{len(self.names) + 1}"
        return self.names[text]

    def text(self, value: str) -> str:
        value = _MAC.sub(lambda m: self.mac(m.group(0)), value)
        value = _IPV4.sub(lambda m: self.ip(m.group(0)) if _is_local(m.group(0)) else m.group(0), value)
        value = _IPV6.sub(lambda m: self.ip(m.group(0)) if _is_local(m.group(0)) else m.group(0), value)
        for real, label in self.names.items():
            value = value.replace(real, label)
        return value

    def walk(self, obj, key: str | None = None):
        if isinstance(obj, dict):
            return {self.text(k) if isinstance(k, str) else k: self.walk(v, k) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.walk(v, key) for v in obj]
        if isinstance(obj, str):
            if key in _LOCAL_NAME_KEYS and obj:
                return self.name(obj)
            return self.text(obj)
        return obj


def _collect_names(obj, red: Redactor) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in _LOCAL_NAME_KEYS and isinstance(v, str) and v:
                red.name(v)
            else:
                _collect_names(v, red)
    elif isinstance(obj, list):
        for v in obj:
            _collect_names(v, red)


def redact_audit(data):
    """Return a redacted copy of a saved audit (list of devices or {devices, meta})."""
    red = Redactor()
    _collect_names(data, red)
    if isinstance(data, dict):
        meta = {k: v for k, v in (data.get("meta") or {}).items() if k not in _META_DROP}
        out = red.walk({k: v for k, v in data.items() if k != "meta"})
        out["meta"] = {**red.walk(meta), "redacted": True}
        return out
    return red.walk(data)
