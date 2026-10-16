"""Open-port scan via nmap (must be installed). Only scans a single, user-confirmed device IP."""

from __future__ import annotations

import ipaddress
import shutil
import subprocess
import xml.etree.ElementTree as ET

RISKY_PORTS = {
    23: ("telnet", "high", "Telnet exposes an unencrypted login shell."),
    21: ("ftp", "medium", "FTP sends credentials in plaintext."),
    554: ("rtsp", "medium", "RTSP video stream reachable on the LAN; check it needs a password."),
    1900: ("upnp", "medium", "UPnP can open router ports without asking."),
    5000: ("upnp/http", "low", "Often a UPnP or debug web interface."),
    80: ("http", "low", "Unencrypted web interface."),
    8080: ("http-alt", "low", "Unencrypted web interface."),
    8899: ("onvif", "medium", "ONVIF camera control endpoint."),
    6668: ("tuya-local", "low", "Tuya local control protocol (encrypted with device key)."),
    5555: ("adb", "high", "Android Debug Bridge open - full device control."),
    22: ("ssh", "medium", "SSH open; make sure default passwords are changed."),
}


def nmap_scan(ip: str, top_ports: int = 200, udp: bool = False, timeout: int = 300) -> list[dict]:
    if not ipaddress.ip_address(ip).is_private:
        raise ValueError("iotaudit only scans devices on your private LAN.")
    if not shutil.which("nmap"):
        raise RuntimeError("nmap not found. Install it (e.g. `sudo apt install nmap`).")
    args = ["nmap", "-Pn", "-sV", "--version-light", "--top-ports", str(top_ports), "-oX", "-", ip]
    if udp:
        args.insert(1, "-sU")
    r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    return parse_nmap_xml(r.stdout)


def parse_nmap_xml(xml: str) -> list[dict]:
    if not xml.strip():
        return []
    out = []
    root = ET.fromstring(xml)
    for port in root.iter("port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        svc = port.find("service")
        num = int(port.get("portid"))
        info = {
            "port": num,
            "proto": port.get("protocol"),
            "service": svc.get("name") if svc is not None else None,
            "product": " ".join(
                x for x in [svc.get("product"), svc.get("version")] if x
            ) if svc is not None else "",
        }
        if num in RISKY_PORTS:
            info["risk"], info["why"] = RISKY_PORTS[num][1], RISKY_PORTS[num][2]
        out.append(info)
    return out
