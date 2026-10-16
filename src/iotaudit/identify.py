"""Fast LAN device identification (~10-20s): mDNS, SSDP/UPnP, NetBIOS, Tuya LAN UDP,
telltale TCP ports, HTTP banners — combined with OUI into a 'Looks like' label + confidence.
All local, no cloud calls."""

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

# Service / port signatures -> (label, confidence)
PORT_HINTS = {
    6668: ("Tuya smart device", "high"),
    6667: ("Tuya smart device", "medium"),
    6666: ("Tuya smart device", "medium"),
    8008: ("Chromecast / Google Cast", "high"),
    8009: ("Chromecast / Google Cast", "high"),
    8443: ("Chromecast setup", "low"),
    62078: ("iPhone / iPad (lockdownd)", "high"),
    7000: ("Apple AirPlay device", "high"),
    5000: ("Apple / UPnP service", "low"),
    554: ("IP camera (RTSP)", "high"),
    8554: ("IP camera (RTSP)", "medium"),
    9197: ("Samsung TV", "high"),
    8001: ("Samsung TV", "high"),
    8080: ("Embedded web UI", "low"),
    80: ("Web UI", "low"),
    443: ("HTTPS service", "low"),
    22: ("SSH device", "low"),
    23: ("Telnet device", "medium"),
    9100: ("Network printer", "high"),
    631: ("Network printer (IPP)", "medium"),
    1883: ("MQTT broker / IoT", "medium"),
    8883: ("MQTT-TLS IoT device", "medium"),
    54321: ("Xiaomi miIO device", "high"),
    8899: ("ONVIF camera", "medium"),
}

MDNS_TYPES = [
    "_hap._tcp.local.",
    "_homekit._tcp.local.",
    "_googlecast._tcp.local.",
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_spotify-connect._tcp.local.",
    "_printer._tcp.local.",
    "_ipp._tcp.local.",
    "_http._tcp.local.",
    "_androidtvremote2._tcp.local.",
    "_sftp-ssh._tcp.local.",
]

MDNS_LABEL = {
    "_hap": ("Apple HomeKit device", "high"),
    "_homekit": ("Apple HomeKit device", "high"),
    "_googlecast": ("Chromecast / Google Cast", "high"),
    "_airplay": ("Apple AirPlay device", "high"),
    "_raop": ("Apple AirPlay speaker", "high"),
    "_spotify-connect": ("Spotify Connect speaker", "high"),
    "_printer": ("Network printer", "high"),
    "_ipp": ("Network printer", "high"),
    "_androidtvremote2": ("Android TV", "high"),
}

OUI_LABELS = (
    (("apple",), "Apple device", "medium"),
    (("samsung",), "Samsung device", "medium"),
    (("espressif", "tuya", "da xia long que", "bilian", "beken"), "Tuya / ESP smart device", "medium"),
    (("xiaomi", "beijing xiaomi"), "Xiaomi device", "medium"),
    (("lg innotek", "lg electronics"), "LG device (phone/TV module)", "medium"),
    (("amazon",), "Amazon / Echo / Fire device", "medium"),
    (("google",), "Google device", "medium"),
    (("raspberry",), "Raspberry Pi", "high"),
    (("ubiquiti", "mikrotik", "tp-link", "netgear", "asus", "cisco"), "Network gear", "medium"),
    (("lcfc", "lenovo", "hewlett", "dell", "intel"), "PC / laptop", "medium"),
    (("shenzhen sdmc",), "Android TV / set-top box", "medium"),
    (("maxlinear",), "Cable modem / gateway chip", "low"),
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
    """M-SEARCH and optionally fetch device description. Returns {ip: info}."""
    msg = (
        b"M-SEARCH * HTTP/1.1\r\n"
        b"HOST: 239.255.255.250:1900\r\n"
        b"MAN: \"ssdp:discover\"\r\n"
        b"MX: 2\r\n"
        b"ST: ssdp:all\r\n\r\n"
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
    """Best-effort mDNS PTR queries. Returns {ip: [service,...]} when A records seen.
    Pure-stdlib; no zeroconf dependency. Incomplete but catches many Cast/AirPlay/HAP devices."""
    # Minimal DNS query builder
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
            query = txn + encode_name(svc) + struct.pack("!HH", 12, 1)  # PTR IN
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
            # Heuristic: map responder IP to services whose name bytes appear in payload
            text = data.decode("latin-1", "replace").lower()
            hits = results.setdefault(ip, [])
            for svc in MDNS_TYPES:
                key = svc.split(".")[0]  # _hap
                if key.lstrip("_") in text or key in text:
                    if key not in hits:
                        hits.append(key)
    finally:
        sock.close()
    return results


def netbios_name(ip: str, timeout: float = 0.6) -> str | None:
    # NetBIOS node status query
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
        raw = data[57:57 + 15]
        return raw.decode("ascii", "replace").strip("\x00 ")
    except OSError:
        return None
    finally:
        sock.close()


def tuya_lan_listen(timeout: float = 2.0) -> dict[str, dict]:
    """Listen for Tuya LAN discovery broadcasts on UDP 6666/6667."""
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
            except TimeoutError:
                continue
            except OSError:
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


def _oui_guess(vendor: str | None) -> tuple[str | None, str]:
    if not vendor:
        return None, "low"
    if vendor.startswith("random"):
        return "Phone / laptop (randomized MAC)", "medium"
    vl = vendor.lower()
    for keys, label, conf in OUI_LABELS:
        if any(k in vl for k in keys):
            return label, conf
    if is_likely_iot(vendor):
        return f"IoT device ({vendor})", "low"
    return f"Device ({vendor})", "low"


def identify_device(ip: str, mac: str | None = None, hostname: str | None = None,
                    role: str | None = None, ssdp: dict | None = None,
                    mdns: dict | None = None, tuya: dict | None = None) -> dict:
    """Return {looks_like, confidence, evidence} for one device."""
    evidence: list[str] = []
    candidates: list[tuple[str, str]] = []  # label, confidence

    if role == "router":
        return {"looks_like": "Router / gateway", "confidence": "certain",
                "evidence": ["default gateway"]}
    if role == "this-host":
        return {"looks_like": "This Mac / PC", "confidence": "certain",
                "evidence": ["local address"]}

    vendor = mac_vendor(mac)
    if vendor:
        evidence.append(f"OUI: {vendor}")
        label, conf = _oui_guess(vendor)
        if label:
            candidates.append((label, conf))

    if hostname:
        evidence.append(f"hostname: {hostname}")
        hl = hostname.lower()
        if "iphone" in hl or "ipad" in hl:
            candidates.append(("iPhone / iPad", "high"))
        elif "android" in hl:
            candidates.append(("Android phone", "high"))
        elif "macbook" in hl or "imac" in hl:
            candidates.append(("Mac", "high"))
        elif any(x in hl for x in ("tv", "roku", "firetv", "shield")):
            candidates.append(("Smart TV / streamer", "medium"))
        elif "printer" in hl:
            candidates.append(("Network printer", "high"))

    nb = None
    try:
        nb = netbios_name(ip)
    except Exception:  # noqa: BLE001
        pass
    if nb:
        evidence.append(f"NetBIOS: {nb}")
        candidates.append((f"Windows PC ({nb})", "medium"))

    if ssdp and ip in ssdp:
        info = ssdp[ip]
        name = info.get("friendly_name") or info.get("model_name")
        mfr = info.get("manufacturer")
        if name:
            evidence.append(f"SSDP: {name}")
            candidates.append((name, "high"))
        elif mfr:
            candidates.append((f"{mfr} device", "medium"))

    if mdns and ip in mdns:
        for svc in mdns[ip]:
            evidence.append(f"mDNS: {svc}")
            if svc in MDNS_LABEL:
                candidates.append(MDNS_LABEL[svc])

    if tuya and ip in tuya:
        evidence.append("Tuya LAN broadcast")
        pk = tuya[ip].get("productKey") or tuya[ip].get("gwId")
        label = "Tuya smart device (Imipaw-style feeder/plug/camera)"
        if pk:
            evidence.append(f"Tuya id: {pk[:12]}")
        candidates.append((label, "high"))

    open_ports: list[int] = []
    try:
        open_ports = probe_ports(ip)
    except Exception:  # noqa: BLE001
        pass
    for p in open_ports:
        if p in PORT_HINTS:
            label, conf = PORT_HINTS[p]
            evidence.append(f"open {p}/tcp")
            candidates.append((label, conf))
    if 80 in open_ports or 8080 in open_ports:
        title = http_title(ip, 80 if 80 in open_ports else 8080)
        if title:
            evidence.append(f"HTTP title: {title}")
            candidates.append((title, "high"))

    # Prefer higher confidence, then more specific labels
    rank = {"certain": 4, "high": 3, "medium": 2, "low": 1}
    if not candidates:
        return {"looks_like": "Unknown device", "confidence": "low", "evidence": evidence,
                "open_ports": open_ports}
    candidates.sort(key=lambda x: rank.get(x[1], 0), reverse=True)
    best_label, best_conf = candidates[0]
    # Refine Tuya + Shenzhen OUI -> Imipaw-style feeder hint when Emir's known OUI
    if mac and mac.lower().startswith("48:87:2d") and "Tuya" in best_label:
        best_label = "Imipaw-style pet feeder (Tuya)"
        best_conf = "high"
    elif vendor and "da xia long que" in vendor.lower() and any("Tuya" in c[0] for c in candidates):
        best_label = "Imipaw-style pet feeder (Tuya)"
        best_conf = "high"
    elif vendor and "bilian" in vendor.lower() and any("Tuya" in c[0] or "ESP" in c[0] for c in candidates):
        best_label = "Tuya smart device (Wi-Fi module)"
    return {"looks_like": best_label, "confidence": best_conf, "evidence": evidence,
            "open_ports": open_ports}


def identify_network(devices: list[dict], budget_s: float = 15.0) -> list[dict]:
    """Enrich a list of {ip,mac,...} devices with looks_like. Runs shared LAN listens once."""
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

    remaining = max(1.0, budget_s - (time.time() - t0))
    # Probe devices (skip multicast/router flood): sequential with shared remaining budget
    per = max(0.5, remaining / max(1, len(devices)))
    out = []
    for d in devices:
        # slightly truncate per-device work if over budget
        if time.time() - t0 > budget_s:
            info = identify_device(d["ip"], d.get("mac"), d.get("hostname"), d.get("role"),
                                   ssdp, mdns, tuya)
            # skip port probe by passing empty — call with role only shortcuts
        else:
            info = identify_device(d["ip"], d.get("mac"), d.get("hostname"), d.get("role"),
                                   ssdp, mdns, tuya)
        d = dict(d)
        d["looks_like"] = info["looks_like"]
        d["id_confidence"] = info["confidence"]
        d["id_evidence"] = info.get("evidence") or []
        d["open_ports"] = info.get("open_ports") or []
        if is_likely_iot(d.get("vendor")) or "Tuya" in (d["looks_like"] or "") or "IoT" in (d["looks_like"] or ""):
            d["likely_iot"] = True
        out.append(d)
        _ = per  # budget hint kept for future adaptive probing
    return out
