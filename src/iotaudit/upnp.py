"""Read-only UPnP IGD audit: which port forwards has your router opened, and for whom?

Many cheap devices ask the router (via UPnP IGD) to forward a public port to themselves. That
makes them reachable from the internet. This module only *lists* those mappings; it never adds,
changes or deletes one. Only allow-listed read actions are sent, and only to routers on a
private/loopback address (a bogus SSDP reply cannot point it at the internet).
"""

from __future__ import annotations

import ipaddress
import re
import socket
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlsplit
from xml.etree import ElementTree as ET

SSDP_ADDR = ("239.255.255.250", 1900)
SEARCH_TARGETS = (
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
)
WAN_SERVICES = (
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
)
READ_ONLY_ACTIONS = frozenset({"GetGenericPortMappingEntry", "GetExternalIPAddress"})
MAX_ENTRIES = 256
MAX_BODY = 512 * 1024

# Ports where an internet-facing forward is especially worrying.
RISKY_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP admin/web", 443: "HTTPS admin/web",
    554: "RTSP video", 1883: "MQTT (plaintext)", 2323: "Telnet (alt)", 3389: "RDP",
    5000: "UPnP/web admin", 5555: "Android ADB", 8000: "web/video", 8080: "HTTP admin/web",
    8554: "RTSP video", 34567: "DVR/camera (XMEye)", 37777: "DVR (Dahua)",
}


def _local_url(url: str) -> bool:
    try:
        host = urlsplit(url).hostname or ""
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if urlsplit(url).scheme not in ("http",):
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def discover(timeout: float = 3.0) -> list[str]:
    """SSDP M-SEARCH for IGDs; returns unique LOCATION URLs on private addresses."""
    found: list[str] = []
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    s.settimeout(timeout)
    try:
        for st in SEARCH_TARGETS:
            msg = (f"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
                   f'MAN: "ssdp:discover"\r\nMX: 2\r\nST: {st}\r\n\r\n')
            s.sendto(msg.encode(), SSDP_ADDR)
        while True:
            try:
                data, _ = s.recvfrom(4096)
            except TimeoutError:
                break
            m = re.search(rb"(?im)^location:\s*(\S+)", data)
            if m:
                loc = m.group(1).decode("ascii", "replace")
                if _local_url(loc) and loc not in found:
                    found.append(loc)
    finally:
        s.close()
    return found


def _fetch(url: str, data: bytes | None = None, headers: dict | None = None,
           timeout: float = 5.0) -> tuple[int, bytes]:
    if not _local_url(url):
        raise ValueError(f"refusing non-local UPnP URL: {url}")
    req = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (local http only)
            return r.status, r.read(MAX_BODY)
    except urllib.error.HTTPError as e:  # SOAP faults come back as HTTP 500
        return e.code, e.read(MAX_BODY)


def _strip_ns(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_description(xml: bytes, location: str) -> dict:
    """Find the WAN connection service control URL and the router's friendly name."""
    root = ET.fromstring(xml)
    base = location
    name = model = None
    igd = False
    for el in root.iter():
        t = _strip_ns(el.tag)
        if t == "URLBase" and (el.text or "").strip():
            base = el.text.strip()
        elif t == "friendlyName" and name is None:
            name = (el.text or "").strip()
        elif t == "modelName" and model is None:
            model = (el.text or "").strip()
        elif t == "deviceType" and "InternetGatewayDevice" in (el.text or ""):
            igd = True
    services = {}
    for svc in root.iter():
        if _strip_ns(svc.tag) != "service":
            continue
        fields = {_strip_ns(c.tag): (c.text or "").strip() for c in svc}
        if fields.get("serviceType") in WAN_SERVICES and fields.get("controlURL"):
            services[fields["serviceType"]] = urljoin(base, fields["controlURL"])
    for st in WAN_SERVICES:
        if st in services:
            return {"service": st, "control_url": services[st], "name": name, "model": model,
                    "igd": igd}
    return {"service": None, "control_url": None, "name": name, "model": model, "igd": igd}


def soap(control_url: str, service: str, action: str, args: dict | None = None) -> dict:
    """Send one allow-listed read-only SOAP action. Returns response fields or {'fault': code}."""
    if action not in READ_ONLY_ACTIONS:
        raise ValueError(f"{action} is not a read-only action")
    inner = "".join(f"<{k}>{v}</{k}>" for k, v in (args or {}).items())
    body = (
        '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
        f'<u:{action} xmlns:u="{service}">{inner}</u:{action}></s:Body></s:Envelope>'
    ).encode()
    status, data = _fetch(control_url, body, {
        "Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": f'"{service}#{action}"'})
    return parse_soap_response(data, status)


def parse_soap_response(data: bytes, status: int = 200) -> dict:
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return {"fault": f"http {status}"}
    out = {}
    fault = None
    for el in root.iter():
        t = _strip_ns(el.tag)
        if t == "errorCode":
            fault = (el.text or "").strip()
        elif len(el) == 0 and t not in ("Envelope", "Body", "faultcode", "faultstring",
                                         "errorDescription"):
            out[t] = (el.text or "").strip()
    if fault or status >= 400:
        return {"fault": fault or f"http {status}"}
    return out


def list_mappings(control_url: str, service: str) -> list[dict]:
    rows = []
    for i in range(MAX_ENTRIES):
        r = soap(control_url, service, "GetGenericPortMappingEntry", {"NewPortMappingIndex": i})
        if "fault" in r:
            break
        try:
            ext = int(r.get("NewExternalPort") or 0)
            internal = int(r.get("NewInternalPort") or 0)
        except ValueError:
            continue
        rows.append({
            "external_port": ext,
            "protocol": (r.get("NewProtocol") or "").upper(),
            "internal_client": r.get("NewInternalClient") or "",
            "internal_port": internal,
            "description": r.get("NewPortMappingDescription") or "",
            "enabled": (r.get("NewEnabled") or "1") in ("1", "true", "yes"),
            "remote_host": r.get("NewRemoteHost") or "",
            "lease_seconds": int(r["NewLeaseDuration"]) if (r.get("NewLeaseDuration") or "").isdigit()
            else None,
        })
    return rows


def audit(timeout: float = 3.0, locations: list[str] | None = None) -> dict:
    """Discover the router(s) and list current port mappings. Never modifies anything."""
    result = {"routers": [], "mappings": [], "errors": []}
    for loc in locations if locations is not None else discover(timeout):
        try:
            _st, xml = _fetch(loc)
            desc = parse_description(xml, loc)
            router = {"location": loc, **desc, "external_ip": None}
            if desc["control_url"]:
                ext = soap(desc["control_url"], desc["service"], "GetExternalIPAddress")
                router["external_ip"] = ext.get("NewExternalIPAddress")
                for m in list_mappings(desc["control_url"], desc["service"]):
                    result["mappings"].append({**m, "router": desc.get("name") or loc})
            result["routers"].append(router)
        except Exception as e:  # noqa: BLE001
            result["errors"].append(f"{loc}: {type(e).__name__}: {e}")
    return result


def findings_for_device(ip: str, upnp: dict | None) -> list[dict]:
    """Findings for one device from an audit() result (empty if nothing applies)."""
    if not upnp:
        return []
    out = []
    for m in upnp.get("mappings", []):
        if m.get("internal_client") != ip or not m.get("enabled", True):
            continue
        port = m["external_port"]
        why = RISKY_PORTS.get(m["internal_port"]) or RISKY_PORTS.get(port)
        open_to = f"from {m['remote_host']} only" if m.get("remote_host") else "from anywhere"
        out.append({
            "category": "upnp",
            "severity": "high" if why else "medium",
            "title": f"Port {port}/{m['protocol']} forwarded to this device via UPnP"
                     + (f" ({why})" if why else ""),
            "detail": (f"The router forwards public port {port} to {ip}:{m['internal_port']} "
                       f"({open_to}); description \"{m.get('description') or '-'}\". The device "
                       "is reachable from the internet on that port. If you don't need remote "
                       "access without the vendor cloud, disable UPnP on the router."),
            "confidence": "certain",
            "evidence": {k: m.get(k) for k in ("external_port", "protocol", "internal_port",
                                               "description", "remote_host", "lease_seconds")},
        })
    return out
