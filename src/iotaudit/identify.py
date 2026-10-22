"""Fast LAN device identification (~10-20s): mDNS, SSDP/UPnP, NetBIOS, Tuya LAN UDP,
telltale TCP ports, and HTTP banners, combined with OUI into a 'Looks like' label and confidence.
All local, no cloud calls.

OUI alone never asserts a brand or model. It only adds the vendor and a generic hint at low confidence.
Brand/type labels require real evidence (mDNS/SSDP/Tuya broadcast/ports/HTTP), and the
list shows that evidence source.
"""

from __future__ import annotations

import re
import socket
import struct
import threading
import time
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed

from .enrich import is_likely_iot, mac_vendor

# Port open -> (label template with evidence, confidence)
PORT_HINTS = {
    6668: ("Tuya device (port 6668 open)", "high"),
    6667: ("Tuya device (port 6667 open)", "medium"),
    6666: ("Tuya device (port 6666 open)", "medium"),
    8008: ("Chromecast / Google Cast (port 8008)", "high"),
    8009: ("Chromecast / Google Cast (port 8009)", "high"),
    62078: ("iPhone / iPad (lockdownd port 62078)", "high"),
    7000: ("Apple AirPlay device (port 7000)", "high"),
    554: ("IP camera (RTSP port 554)", "high"),
    8554: ("IP camera (RTSP port 8554)", "medium"),
    9197: ("Samsung TV (port 9197)", "high"),
    8001: ("Samsung TV (port 8001)", "high"),
    9100: ("Network printer (port 9100)", "high"),
    631: ("Network printer (IPP port 631)", "medium"),
    54321: ("Xiaomi miIO device (port 54321)", "high"),
    8899: ("ONVIF camera (port 8899)", "medium"),
    23: ("Telnet device (port 23)", "medium"),
}

MDNS_TYPES = [
    "_hap._tcp.local.", "_homekit._tcp.local.", "_googlecast._tcp.local.",
    "_airplay._tcp.local.", "_raop._tcp.local.", "_spotify-connect._tcp.local.",
    "_printer._tcp.local.", "_ipp._tcp.local.", "_http._tcp.local.",
    "_androidtvremote2._tcp.local.", "_sftp-ssh._tcp.local.",
]

MDNS_LABEL = {
    "_hap": ("Apple HomeKit device (mDNS _hap)", "high"),
    "_homekit": ("Apple HomeKit device (mDNS)", "high"),
    "_googlecast": ("Chromecast / Google Cast (mDNS)", "high"),
    "_airplay": ("Apple AirPlay device (mDNS)", "high"),
    "_raop": ("Apple AirPlay speaker (mDNS)", "high"),
    "_spotify-connect": ("Spotify Connect speaker (mDNS)", "high"),
    "_printer": ("Network printer (mDNS)", "high"),
    "_ipp": ("Network printer (mDNS _ipp)", "high"),
    "_androidtvremote2": ("Android TV (mDNS)", "high"),
}

# Vendors that typically make Wi-Fi SoCs / modules for white-label IoT.
IOT_MODULE_VENDORS = (
    "espressif", "tuya", "beken", "bilian", "da xia long que", "realtek",
    "hangzhou", "mxchip", "ai-thinker", "high-flying", "newracom",
)


def _tcp_open(ip: str, port: int, timeout: float = 0.4) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def probe_ports(ip: str, ports: list[int] | None = None) -> list[int]:
    ports = ports or list(PORT_HINTS)
    open_ports = []
    with ThreadPoolExecutor(max_workers=20) as pool:
        futs = {pool.submit(_tcp_open, ip, p): p for p in ports}
        for fut in as_completed(futs):
            if fut.result():
                open_ports.append(futs[fut])
    return sorted(open_ports)


def http_title(ip: str, port: int = 80, timeout: float = 0.8) -> str | None:
    try:
        req = urllib.request.Request(
            f"http://{ip}:{port}/",
            headers={"User-Agent": "iotaudit/0.0.1"},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(8192).decode("utf-8", "replace")
        m = re.search(r"<title[^>]*>([^<]+)</title>", body, re.I)
        return m.group(1).strip() if m else None
    except Exception:  # noqa: BLE001
        return None


def ssdp_search(timeout: float = 2.0) -> dict[str, dict]:
    msg = (
        b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
        b'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n'
    )
    found: dict[str, dict] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout)
    try:
        sock.sendto(msg, ("239.255.255.250", 1900))
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, addr = sock.recvfrom(65535)
            except TimeoutError:
                break
            text = data.decode("utf-8", "replace")
            ip = addr[0]
            info = found.setdefault(ip, {})
            for line in text.split("\r\n"):
                if ":" in line:
                    k, _, v = line.partition(":")
                    info[k.strip().lower()] = v.strip()
            loc = info.get("location")
            if loc and "friendly_name" not in info:
                try:
                    with urllib.request.urlopen(loc, timeout=0.8) as resp:
                        xml = resp.read(65536)
                    root = ET.fromstring(xml)

                    def find(tag, node=root):
                        for el in node.iter():
                            if el.tag.endswith(tag) and el.text:
                                return el.text.strip()
                        return None

                    info["friendly_name"] = find("friendlyName")
                    info["manufacturer"] = find("manufacturer")
                    info["model_name"] = find("modelName")
                except Exception:  # noqa: BLE001
                    pass
    finally:
        sock.close()
    return found


def mdns_browse(timeout: float = 2.5) -> dict[str, list[str]]:
    def encode_name(name: str) -> bytes:
        out = b""
        for label in name.rstrip(".").split("."):
            out += bytes([len(label)]) + label.encode()
        return out + b"\x00"

    results: dict[str, list[str]] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout)
    try:
        for i, svc in enumerate(MDNS_TYPES):
            txn = struct.pack("!HHHHHH", 0x1200 + i, 0, 1, 0, 0, 0)
            query = txn + encode_name(svc) + struct.pack("!HH", 12, 1)
            try:
                sock.sendto(query, ("224.0.0.251", 5353))
            except OSError:
                continue
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, addr = sock.recvfrom(65535)
            except TimeoutError:
                break
            ip = addr[0]
            text = data.decode("latin-1", "replace").lower()
            hits = results.setdefault(ip, [])
            for svc in MDNS_TYPES:
                key = svc.split(".")[0]
                if key.lstrip("_") in text or key in text:
                    if key not in hits:
                        hits.append(key)
    finally:
        sock.close()
    return results


def netbios_name(ip: str, timeout: float = 0.6) -> str | None:
    payload = (
        b"\x00\x00\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00"
        + b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (ip, 137))
        data, _ = sock.recvfrom(1024)
        if len(data) < 57:
            return None
        n = data[56]
        if n < 1 or len(data) < 57 + 18:
            return None
        return data[57:57 + 15].decode("ascii", "replace").strip("\x00 ")
    except OSError:
        return None
    finally:
        sock.close()


def tuya_lan_listen(timeout: float = 2.0) -> dict[str, dict]:
    found: dict[str, dict] = {}
    socks = []
    for port in (6666, 6667):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("", port))
        except OSError:
            s.close()
            continue
        s.settimeout(0.3)
        socks.append(s)
    end = time.time() + timeout
    while time.time() < end and socks:
        for s in socks:
            try:
                data, addr = s.recvfrom(65535)
            except (TimeoutError, OSError):
                continue
            ip = addr[0]
            info = found.setdefault(ip, {"tuya": True})
            text = data.decode("utf-8", "replace")
            for key in ("gwId", "productKey", "uuid", "devId"):
                m = re.search(rf'"{key}"\s*:\s*"([^"]+)"', text)
                if m:
                    info[key] = m.group(1)
            if b"Tuya" in data or b"tuya" in data or info.get("gwId"):
                info["tuya"] = True
    for s in socks:
        s.close()
    return found


def _oui_guess(vendor: str | None) -> str | None:
    """Vendor-only hint from OUI. Always low confidence; never names a product."""
    if not vendor:
        return None
    if vendor.startswith("random"):
        return "Phone/laptop (randomized MAC)"
    vl = vendor.lower()
    if any(k in vl for k in IOT_MODULE_VENDORS) or is_likely_iot(vendor):
        return f"{vendor} (IoT module maker, OUI only)"
    return f"{vendor} device (OUI only)"


def identify_device(ip: str, mac: str | None = None, hostname: str | None = None,
                    role: str | None = None, ssdp: dict | None = None,
                    mdns: dict | None = None, tuya: dict | None = None) -> dict:
    """Return {looks_like, confidence, evidence}. Brand/type needs real evidence."""
    evidence: list[str] = []
    # (label, confidence, source). Source "oui" is never preferred over active evidence.
    candidates: list[tuple[str, str, str]] = []

    if role == "router":
        return {"looks_like": "Router / gateway", "confidence": "certain",
                "evidence": ["default gateway"], "open_ports": []}
    if role == "this-host":
        return {"looks_like": "This Mac / PC", "confidence": "certain",
                "evidence": ["local address"], "open_ports": []}

    vendor = mac_vendor(mac)
    if vendor:
        evidence.append(f"OUI: {vendor}")
        label = _oui_guess(vendor)
        if label:
            candidates.append((label, "low", "oui"))

    if hostname:
        evidence.append(f"hostname: {hostname}")
        hl = hostname.lower()
        if "iphone" in hl or "ipad" in hl:
            candidates.append((f"iPhone/iPad (hostname {hostname})", "high", "hostname"))
        elif "android" in hl:
            candidates.append((f"Android phone (hostname {hostname})", "high", "hostname"))
        elif "macbook" in hl or "imac" in hl:
            candidates.append((f"Mac (hostname {hostname})", "high", "hostname"))
        elif "printer" in hl:
            candidates.append((f"Printer (hostname {hostname})", "high", "hostname"))

    try:
        nb = netbios_name(ip)
    except Exception:  # noqa: BLE001
        nb = None
    if nb:
        evidence.append(f"NetBIOS: {nb}")
        candidates.append((f"Windows PC (NetBIOS {nb})", "medium", "netbios"))

    if ssdp and ip in ssdp:
        info = ssdp[ip]
        name = info.get("friendly_name") or info.get("model_name")
        mfr = info.get("manufacturer")
        if name:
            evidence.append(f"SSDP: {name}")
            label = f"{name} (SSDP)"
            if mfr:
                label = f"{name} ({mfr}, SSDP)"
            candidates.append((label, "high", "ssdp"))
        elif mfr:
            candidates.append((f"{mfr} device (SSDP)", "medium", "ssdp"))

    if mdns and ip in mdns:
        for svc in mdns[ip]:
            evidence.append(f"mDNS: {svc}")
            if svc in MDNS_LABEL:
                label, conf = MDNS_LABEL[svc]
                candidates.append((label, conf, "mdns"))

    if tuya and ip in tuya:
        evidence.append("Tuya LAN broadcast")
        pk = tuya[ip].get("productKey") or tuya[ip].get("gwId")
        detail = f"gwId={pk[:12]}" if pk else "UDP 6666/6667"
        candidates.append((f"Tuya device (LAN broadcast, {detail})", "high", "tuya"))

    open_ports: list[int] = []
    try:
        open_ports = probe_ports(ip)
    except Exception:  # noqa: BLE001
        pass
    for port in open_ports:
        if port in PORT_HINTS:
            label, conf = PORT_HINTS[port]
            evidence.append(f"open {port}/tcp")
            candidates.append((label, conf, "port"))
    if 80 in open_ports or 8080 in open_ports:
        title = http_title(ip, 80 if 80 in open_ports else 8080)
        if title:
            evidence.append(f"HTTP title: {title}")
            candidates.append((f"{title} (HTTP title)", "high", "http"))

    rank = {"certain": 4, "high": 3, "medium": 2, "low": 1}
    active = [c for c in candidates if c[2] != "oui"]
    oui_only = [c for c in candidates if c[2] == "oui"]
    if active:
        active.sort(key=lambda x: rank.get(x[1], 0), reverse=True)
        best_label, best_conf = active[0][0], active[0][1]
    elif oui_only:
        best_label, best_conf = oui_only[0][0], "low"
    else:
        return {"looks_like": "Unknown device", "confidence": "low", "evidence": evidence,
                "open_ports": open_ports}
    from .devicetype import identify_device_type

    mdns_svcs = list(mdns.get(ip, [])) if mdns else []
    ssdp_blob = None
    if ssdp and ip in ssdp:
        info = ssdp[ip]
        ssdp_blob = " ".join(str(v) for v in (info.get("friendly_name"),
                             info.get("model_name"), info.get("manufacturer")) if v)
    dtype = identify_device_type(
        open_ports=open_ports,
        domains=[ssdp_blob] if ssdp_blob else [],
        mdns=mdns_svcs,
        vendor=vendor,
        hostname=hostname,
    )
    return {"looks_like": best_label, "confidence": best_conf, "evidence": evidence,
            "open_ports": open_ports, "device_type": dtype.get("type"),
            "device_type_label": dtype.get("label"),
            "device_type_confidence": dtype.get("confidence")}


def identify_network(devices: list[dict], budget_s: float = 15.0) -> list[dict]:
    """Enrich devices with looks_like. Shared LAN listens once, then per-host probes."""
    t0 = time.time()
    ssdp: dict = {}
    mdns: dict = {}
    tuya: dict = {}

    def run_ssdp():
        nonlocal ssdp
        try:
            ssdp = ssdp_search(timeout=min(2.5, budget_s / 3))
        except Exception:  # noqa: BLE001
            pass

    def run_mdns():
        nonlocal mdns
        try:
            mdns = mdns_browse(timeout=min(2.5, budget_s / 3))
        except Exception:  # noqa: BLE001
            pass

    def run_tuya():
        nonlocal tuya
        try:
            tuya = tuya_lan_listen(timeout=min(2.0, budget_s / 4))
        except Exception:  # noqa: BLE001
            pass

    threads = [threading.Thread(target=f) for f in (run_ssdp, run_mdns, run_tuya)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=budget_s / 2)

    out = []
    for d in devices:
        info = identify_device(d["ip"], d.get("mac"), d.get("hostname"), d.get("role"),
                               ssdp, mdns, tuya)
        d = dict(d)
        d["looks_like"] = info["looks_like"]
        d["id_confidence"] = info["confidence"]
        d["id_evidence"] = info.get("evidence") or []
        d["open_ports"] = info.get("open_ports") or []
        d["device_type"] = info.get("device_type")
        d["device_type_label"] = info.get("device_type_label")
        d["device_type_confidence"] = info.get("device_type_confidence")
        if is_likely_iot(d.get("vendor")) or "Tuya" in (d["looks_like"] or ""):
            d["likely_iot"] = True
        out.append(d)
        if time.time() - t0 > budget_s:
            # Still identify remaining via OUI/role only (skip further port probes by
            # short-circuiting (probe_ports still runs; budget is soft).
            pass
    return out
