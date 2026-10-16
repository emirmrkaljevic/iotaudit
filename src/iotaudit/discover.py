"""LAN device discovery: ARP-sweep the local subnet and resolve vendor/hostname.
Used by `iotaudit capture` when no --device is given, to offer a numbered picker.
Own network only - this just enumerates what is already on your LAN."""

from __future__ import annotations

import ipaddress
import platform
import socket
import subprocess

from .enrich import mac_vendor


def local_cidr(iface: str | None = None) -> str | None:
    """Best-effort local IPv4 /24 (or smaller) for the primary interface."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 9))  # no packets actually sent
        ip = s.getsockname()[0]
        s.close()
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except OSError:
        return None


def _reverse_dns(ip: str) -> str | None:
    try:
        name = socket.gethostbyaddr(ip)[0]
        return name if name and name != ip else None
    except (OSError, socket.herror):
        return None


def _arp_table() -> dict[str, str]:
    """Parse the OS ARP cache as a fallback (ip -> mac)."""
    out: dict[str, str] = {}
    cmd = ["arp", "-a"] if platform.system() == "Darwin" else ["ip", "neigh"]
    r = subprocess.run(cmd, capture_output=True, text=True, check=False)
    for line in r.stdout.splitlines():
        toks = line.replace("(", " ").replace(")", " ").split()
        ip = next((t for t in toks if t.count(".") == 3 and t.replace(".", "").isdigit()), None)
        mac = next((t for t in toks if t.count(":") == 5), None)
        if ip and mac and mac.lower() != "ff:ff:ff:ff:ff:ff":
            out[ip] = mac.lower()
    return out


def arp_sweep(cidr: str | None = None, iface: str | None = None, timeout: int = 3) -> list[dict]:
    """Return a list of {ip, mac, vendor, hostname} for hosts on the subnet.
    Uses a scapy ARP broadcast when possible (needs root), else the OS ARP cache."""
    cidr = cidr or local_cidr(iface)
    found: dict[str, str] = {}
    if cidr:
        try:
            from scapy.layers.l2 import ARP, Ether
            from scapy.sendrecv import srp

            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr),
                         timeout=timeout, iface=iface, verbose=False)
            for _snd, rcv in ans:
                found[rcv.psrc] = rcv.hwsrc.lower()
        except (PermissionError, OSError, RuntimeError):
            pass
    for ip, mac in _arp_table().items():
        found.setdefault(ip, mac)
    devices = []
    for ip in sorted(found, key=lambda x: tuple(int(p) for p in x.split("."))):
        devices.append({
            "ip": ip, "mac": found[ip], "vendor": mac_vendor(found[ip]),
            "hostname": _reverse_dns(ip),
        })
    return devices


def format_table(devices: list[dict]) -> str:
    lines = [f"{'#':>2}  {'IP':<16}{'MAC':<19}{'Vendor':<22}Hostname"]
    for i, d in enumerate(devices, 1):
        hint = d["vendor"] or ""
        if hint and any(k in hint for k in ("Tuya", "Espressif")):
            hint += "  <- likely IoT"
        lines.append(f"{i:>2}  {d['ip']:<16}{d['mac']:<19}{hint:<22}{d['hostname'] or ''}")
    return "\n".join(lines)


def pick(devices: list[dict], stream_in=None, stream_out=None) -> dict | None:
    import sys

    out = stream_out or sys.stderr
    if not devices:
        print("No devices found. Are you on the device's Wi-Fi (2.4GHz, no client isolation)?",
              file=out)
        return None
    print(format_table(devices), file=out)
    print("\nEnter the number of the device to audit (or q to quit): ", end="", file=out, flush=True)
    raw = (stream_in or sys.stdin).readline().strip()
    if not raw or raw.lower().startswith("q"):
        return None
    try:
        idx = int(raw)
    except ValueError:
        return None
    return devices[idx - 1] if 1 <= idx <= len(devices) else None
