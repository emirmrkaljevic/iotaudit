"""LAN device discovery: ARP-sweep the local subnet and resolve vendor/hostname.
Used by `iotaudit capture` when no --device is given, to offer a numbered picker.
Own network only - this just enumerates what is already on your LAN."""

from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess

from .enrich import is_likely_iot, mac_vendor, normalize_mac
from .identify import identify_network


def _is_multicast(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_multicast
    except ValueError:
        return False


def _self_ips() -> set[str]:
    ips = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 9))
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    return {i for i in ips if not i.startswith("127.")}


def _gateway_ip() -> str | None:
    try:
        from .arp import default_gateway
        return default_gateway()
    except Exception:  # noqa: BLE001
        return None



def _parse_netmask_hex(token: str) -> int | None:
    """macOS ifconfig prints netmask as hex (0xffffff00). Linux rarely uses this path."""
    t = token.strip().lower()
    if t.startswith("0x"):
        try:
            bits = bin(int(t, 16)).count("1")
            return bits if 0 < bits <= 32 else None
        except ValueError:
            return None
    if t.count(".") == 3:
        try:
            return ipaddress.IPv4Network(f"0.0.0.0/{t}").prefixlen
        except ValueError:
            return None
    return None


def local_cidr(iface: str | None = None) -> str | None:
    """Best-effort local IPv4 CIDR. Prefers ifconfig/ip for real netmask; falls back to /24."""
    system = platform.system()
    try:
        if system == "Darwin":
            r = subprocess.run(["ifconfig"] + ([iface] if iface else []),
                               capture_output=True, text=True, check=False)
            # inet 192.168.1.10 netmask 0xffffff00 broadcast ...
            for m in re.finditer(
                r"inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(\S+)", r.stdout
            ):
                ip, mask = m.group(1), m.group(2)
                if ip.startswith("127."):
                    continue
                bits = _parse_netmask_hex(mask) or 24
                return str(ipaddress.ip_network(f"{ip}/{bits}", strict=False))
        else:
            cmd = ["ip", "-4", "-o", "addr", "show"]
            if iface:
                cmd.append(iface)
            r = subprocess.run(cmd, capture_output=True, text=True, check=False)
            for line in r.stdout.splitlines():
                m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", line)
                if m and not m.group(1).startswith("127."):
                    return str(ipaddress.ip_network(m.group(1), strict=False))
    except (OSError, ValueError):
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 9))
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


def parse_arp_a(text: str) -> dict[str, str]:
    """Parse macOS/BSD `arp -a` output into {ip: normalized_mac}.
    Skips '(incomplete)' and malformed lines.

    Sample:
        ? (192.168.1.1) at 0:1a:2b:3:4:5 on en0 ifscope [ethernet]
        router.home (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
        ? (192.168.1.50) at (incomplete) on en0 ifscope [ethernet]
    """
    out: dict[str, str] = {}
    for line in text.splitlines():
        if "incomplete" in line.lower():
            continue
        m = re.search(
            r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:.\-]+)\s",
            line,
        )
        if not m:
            # Linux `ip neigh`: 192.168.1.1 lladdr aa:bb:cc:dd:ee:ff REACHABLE
            m2 = re.search(
                r"^(\d+\.\d+\.\d+\.\d+)\s+.*\blladdr\s+([0-9a-fA-F:.\-]+)",
                line,
            )
            if not m2:
                continue
            ip, raw_mac = m2.group(1), m2.group(2)
        else:
            ip, raw_mac = m.group(1), m.group(2)
        mac = normalize_mac(raw_mac)
        if mac and mac != "ff:ff:ff:ff:ff:ff":
            out[ip] = mac
    return out


def _arp_table() -> dict[str, str]:
    cmd = ["arp", "-a"] if platform.system() == "Darwin" else ["ip", "neigh"]
    r = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return parse_arp_a(r.stdout)


def _ping_sweep(cidr: str, timeout: float = 0.3) -> None:
    """Best-effort ping of hosts to populate the ARP cache (used when scapy ARP fails)."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return
    if net.num_addresses > 512:
        return
    procs = []
    for host in net.hosts():
        flag = "-c" if platform.system() != "Windows" else "-n"
        # Fire-and-forget; don't wait for each individually.
        procs.append(subprocess.Popen(
            ["ping", flag, "1", "-W", "1" if platform.system() == "Darwin" else str(int(timeout * 1000)),
             str(host)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ))
        if len(procs) >= 64:
            for p in procs:
                try:
                    p.wait(timeout=timeout + 0.5)
                except subprocess.TimeoutExpired:
                    p.kill()
            procs = []
    for p in procs:
        try:
            p.wait(timeout=timeout + 0.5)
        except subprocess.TimeoutExpired:
            p.kill()


def arp_sweep(cidr: str | None = None, iface: str | None = None, timeout: int = 3) -> list[dict]:
    """Return a list of {ip, mac, vendor, hostname} for hosts on the subnet.
    Tries scapy ARP first; on failure, ping-sweeps then reads the OS ARP cache."""
    cidr = cidr or local_cidr(iface)
    found: dict[str, str] = {}
    scapy_ok = False
    if cidr:
        try:
            from scapy.layers.l2 import ARP, Ether
            from scapy.sendrecv import srp

            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr),
                timeout=timeout, iface=iface, verbose=False,
            )
            for _snd, rcv in ans:
                mac = normalize_mac(rcv.hwsrc)
                if mac:
                    found[rcv.psrc] = mac
            scapy_ok = True
        except Exception:  # noqa: BLE001 — any scapy/pcap failure falls back
            scapy_ok = False
        if not scapy_ok or not found:
            _ping_sweep(cidr)
    for ip, mac in _arp_table().items():
        found.setdefault(ip, mac)
    self_ips = _self_ips()
    gateway = _gateway_ip()
    devices = []
    for ip in sorted(found, key=lambda x: tuple(int(p) for p in x.split("."))):
        if _is_multicast(ip):
            continue
        mac = normalize_mac(found[ip]) or found[ip]
        try:
            vendor = mac_vendor(mac)
        except Exception:  # noqa: BLE001
            vendor = None
        role = None
        if ip == gateway:
            role = "router"
        elif ip in self_ips:
            role = "this-host"
        devices.append({
            "ip": ip, "mac": mac, "vendor": vendor, "hostname": _reverse_dns(ip),
            "role": role, "likely_iot": is_likely_iot(vendor),
        })
    try:
        return identify_network(devices)
    except Exception:
        return devices


def format_table(devices: list[dict]) -> str:
    lines = [f"{'#':>2}  {'IP':<15} {'Looks like':<42} {'Conf':<7} MAC"]
    for i, d in enumerate(devices, 1):
        looks = d.get("looks_like") or d.get("vendor") or "Unknown device"
        conf = d.get("id_confidence") or ""
        if d.get("role") == "router":
            looks = "Router / gateway"
            conf = "certain"
        elif d.get("role") == "this-host":
            looks = "This Mac / PC"
            conf = "certain"
        lines.append(f"{i:>2}  {d['ip']:<15} {looks:<42} {conf:<7} {d.get('mac') or ''}")
    return "\n".join(lines)


def pick(devices: list[dict], stream_in=None, stream_out=None) -> dict | None:
    import sys

    out = stream_out or sys.stderr
    if not devices:
        print(
            "No devices found. Are you on the device's Wi-Fi (2.4GHz, no client isolation)?",
            file=out,
        )
        return None
    print(format_table(devices), file=out)
    print("\nEnter the number of the device to audit (or q to quit): ", end="",
          file=out, flush=True)
    raw = (stream_in or sys.stdin).readline().strip()
    if not raw or raw.lower().startswith("q"):
        return None
    try:
        idx = int(raw)
    except ValueError:
        return None
    return devices[idx - 1] if 1 <= idx <= len(devices) else None
