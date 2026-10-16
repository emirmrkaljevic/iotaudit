"""ARP mode (own network only, like IoT Inspector): ARP-spoof a single target device so its
traffic flows through this computer, capture it, forward it, and restore ARP tables on exit.

Only works on a network you own/administer and only against a device you own. Requires root
and an explicit consent step in the CLI/MCP layer. On macOS it also toggles IP forwarding
(net.inet.ip.forwarding) so the target keeps working, and restores it afterwards.
"""

from __future__ import annotations

import ipaddress
import platform
import subprocess
import sys
import threading
import time


class IPForwarding:
    """Enable OS IP forwarding so the spoofed device keeps internet access; restore the prior
    value on exit. Supports macOS (sysctl net.inet.ip.forwarding) and Linux (ip_forward)."""

    KEYS = {"Darwin": "net.inet.ip.forwarding", "Linux": "net.ipv4.ip_forward"}

    def __init__(self):
        self.key = self.KEYS.get(platform.system())
        self.prev: str | None = None

    def _get(self) -> str | None:
        r = subprocess.run(["sysctl", "-n", self.key], capture_output=True, text=True, check=False)
        return r.stdout.strip() if r.returncode == 0 else None

    def __enter__(self):
        if not self.key:
            raise RuntimeError("IP forwarding toggle is only supported on macOS and Linux.")
        self.prev = self._get()
        subprocess.run(["sysctl", "-w", f"{self.key}=1"], capture_output=True, text=True, check=False)
        return self

    def __exit__(self, *exc):
        if self.prev is not None:
            subprocess.run(["sysctl", "-w", f"{self.key}={self.prev}"],
                           capture_output=True, text=True, check=False)
        return False


def _require_private(*ips: str) -> None:
    for ip in ips:
        if not ipaddress.ip_address(ip).is_private:
            raise ValueError(f"ARP mode only works on your private LAN; {ip} is not private.")


def default_gateway() -> str | None:
    """Best-effort default gateway lookup (macOS `route`, Linux `ip route`)."""
    if platform.system() == "Darwin":
        r = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True, check=False)
        for line in r.stdout.splitlines():
            if "gateway:" in line:
                return line.split(":", 1)[1].strip()
    else:
        r = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, check=False)
        parts = r.stdout.split()
        if "via" in parts:
            return parts[parts.index("via") + 1]
    return None


def _resolve_mac(ip: str, iface: str | None) -> str:
    from scapy.layers.l2 import getmacbyip

    for _ in range(3):
        mac = getmacbyip(ip)
        if mac:
            return mac
        time.sleep(0.5)
    raise RuntimeError(f"Could not resolve MAC for {ip}. Is the device on this LAN? "
                       "(2.4GHz, no AP/client isolation?)")


class ArpSpoofer:
    """Two-way ARP spoof between target and gateway. Restores both on stop()."""

    def __init__(self, target_ip: str, gateway_ip: str, iface: str | None = None, interval: float = 2.0):
        _require_private(target_ip, gateway_ip)
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.iface = iface
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.target_mac: str | None = None
        self.gateway_mac: str | None = None

    def _send(self, pdst, hwdst, psrc):
        from scapy.layers.l2 import ARP, Ether
        from scapy.sendrecv import send

        pkt = Ether(dst=hwdst) / ARP(op=2, pdst=pdst, hwdst=hwdst, psrc=psrc)
        send(pkt, iface=self.iface, verbose=False)

    def _loop(self):
        while not self._stop.is_set():
            # tell target that we are the gateway, and the gateway that we are the target
            self._send(self.target_ip, self.target_mac, self.gateway_ip)
            self._send(self.gateway_ip, self.gateway_mac, self.target_ip)
            self._stop.wait(self.interval)

    def start(self):
        self.target_mac = _resolve_mac(self.target_ip, self.iface)
        self.gateway_mac = _resolve_mac(self.gateway_ip, self.iface)
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return self

    def restore(self):
        """Send correct ARP replies a few times to heal both caches."""
        from scapy.layers.l2 import ARP
        from scapy.sendrecv import send

        if not (self.target_mac and self.gateway_mac):
            return
        from scapy.layers.l2 import Ether
        for _ in range(5):
            send(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=2, pdst=self.gateway_ip, hwdst="ff:ff:ff:ff:ff:ff",
                psrc=self.target_ip, hwsrc=self.target_mac), iface=self.iface, verbose=False)
            send(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=2, pdst=self.target_ip, hwdst="ff:ff:ff:ff:ff:ff",
                psrc=self.gateway_ip, hwsrc=self.gateway_mac), iface=self.iface, verbose=False)

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        self.restore()


def start(target_ip: str, gateway_ip: str | None = None, iface: str | None = None):
    """Convenience: resolve gateway if needed and start spoofing. Caller must stop() and should
    wrap capture in IPForwarding(). Raises if not run as root."""
    if hasattr(__import__("os"), "geteuid") and __import__("os").geteuid() != 0:
        raise PermissionError("ARP mode needs root. Re-run with sudo.")
    gw = gateway_ip or default_gateway()
    if not gw:
        raise RuntimeError("Could not determine the default gateway; pass --gateway.")
    print(f"ARP mode: spoofing {target_ip} <-> gateway {gw} on {iface or 'default iface'}.",
          file=sys.stderr)
    return ArpSpoofer(target_ip, gw, iface).start()
