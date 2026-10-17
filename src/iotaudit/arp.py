"""ARP mode (own network only): ARP-spoof one owned device so its traffic flows through this
computer, capture it, forward it, and restore ARP tables on exit.

Uses sendp() with an explicit Ether(dst=<known MAC>) so scapy never ARP-resolves L2 itself
(which on macOS produced 'MAC address to reach destination not found. Using broadcast.' and
empty captures). MACs should come from the LAN scan; getmacbyip is only a last resort.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import platform
import subprocess
import sys
import threading
import time
import warnings

from .enrich import normalize_mac


class IPForwarding:
    """Enable OS IP forwarding; restore the prior value on exit."""

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
        now = self._get()
        if now != "1":
            raise RuntimeError(
                f"Could not enable IP forwarding ({self.key}={now!r}). "
                "ARP mode needs it so the device keeps internet access. Re-run with sudo."
            )
        print(f"IP forwarding enabled ({self.key}=1; was {self.prev}).", file=sys.stderr)
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


def resolve_iface(iface: str | None = None) -> str:
    """Turn 'auto'/None into the real interface that has the default route (e.g. en0)."""
    if iface and iface not in ("auto", "any", "default"):
        return iface
    if platform.system() == "Darwin":
        r = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True, check=False)
        for line in r.stdout.splitlines():
            if line.strip().startswith("interface:"):
                return line.split(":", 1)[1].strip()
    try:
        from scapy.all import conf

        # conf.route.route("0.0.0.0") -> (iface, gw, ip)
        route = conf.route.route("0.0.0.0")
        if route and route[0]:
            return route[0]
    except Exception:  # noqa: BLE001
        pass
    if platform.system() != "Darwin":
        r = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, check=False)
        parts = r.stdout.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    raise RuntimeError("Could not resolve capture interface; pass --iface en0 (or your Wi-Fi iface).")


def our_mac(iface: str) -> str:
    """MAC address of our own interface."""
    try:
        from scapy.all import get_if_hwaddr

        mac = normalize_mac(get_if_hwaddr(iface))
        if mac:
            return mac
    except Exception:  # noqa: BLE001
        pass
    if platform.system() == "Darwin":
        r = subprocess.run(["ifconfig", iface], capture_output=True, text=True, check=False)
        for line in r.stdout.splitlines():
            if "ether" in line:
                mac = normalize_mac(line.split()[1])
                if mac:
                    return mac
    raise RuntimeError(f"Could not read MAC of interface {iface}.")


def _resolve_mac(ip: str, iface: str | None, known: str | None = None) -> str:
    if known:
        mac = normalize_mac(known)
        if mac:
            return mac
    from scapy.layers.l2 import getmacbyip

    for _ in range(3):
        mac = normalize_mac(getmacbyip(ip) or "")
        if mac:
            return mac
        time.sleep(0.4)
    raise RuntimeError(
        f"Could not resolve MAC for {ip}. Re-run without --device so the LAN scan "
        "caches it, or check 2.4GHz / client isolation."
    )


def _quiet_scapy():
    logging.getLogger("scapy").setLevel(logging.ERROR)
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    warnings.filterwarnings("ignore", module="scapy")


class ArpSpoofer:
    """Two-way ARP spoof between target and gateway via sendp() + known MACs."""

    def __init__(self, target_ip: str, gateway_ip: str, iface: str,
                 target_mac: str | None = None, gateway_mac: str | None = None,
                 our_mac_addr: str | None = None, interval: float = 2.0,
                 extra_peers: list[tuple[str, str]] | None = None):
        """extra_peers: [(ip, mac), ...] other LAN hosts to poison both ways with target."""
        _require_private(target_ip, gateway_ip)
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.iface = iface
        self.interval = interval
        self._known_target_mac = target_mac
        self._known_gateway_mac = gateway_mac
        self.our_mac = our_mac_addr
        self.extra_peers = list(extra_peers or [])
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.target_mac: str | None = None
        self.gateway_mac: str | None = None

    def _sendp(self, dst_mac: str, pdst: str, hwdst: str, psrc: str, hwsrc: str | None = None):
        from scapy.layers.l2 import ARP, Ether
        from scapy.sendrecv import sendp

        pkt = Ether(dst=dst_mac, src=self.our_mac) / ARP(
            op=2, pdst=pdst, hwdst=hwdst, psrc=psrc, hwsrc=hwsrc or self.our_mac,
        )
        sendp(pkt, iface=self.iface, verbose=False, count=1)

    def _loop(self):
        while not self._stop.is_set():
            # Tell target: "I (our MAC) am the gateway"
            self._sendp(self.target_mac, self.target_ip, self.target_mac, self.gateway_ip)
            # Tell gateway: "I (our MAC) am the target"
            self._sendp(self.gateway_mac, self.gateway_ip, self.gateway_mac, self.target_ip)
            # Optional: poison target <-> each LAN peer (see phone P2P video)
            for peer_ip, peer_mac in self.extra_peers:
                self._sendp(self.target_mac, self.target_ip, self.target_mac, peer_ip)
                self._sendp(peer_mac, peer_ip, peer_mac, self.target_ip)
            self._stop.wait(self.interval)

    def start(self):
        _quiet_scapy()
        if not self.our_mac:
            self.our_mac = our_mac(self.iface)
        self.target_mac = _resolve_mac(self.target_ip, self.iface, self._known_target_mac)
        self.gateway_mac = _resolve_mac(self.gateway_ip, self.iface, self._known_gateway_mac)
        self._thread = threading.Thread(target=self._loop, name="arp-spoof", daemon=True)
        self._thread.start()
        return self

    def restore(self):
        if not (self.target_mac and self.gateway_mac and self.our_mac):
            return
        _quiet_scapy()
        for _ in range(5):
            self._sendp("ff:ff:ff:ff:ff:ff", self.target_ip, "ff:ff:ff:ff:ff:ff",
                        self.gateway_ip, hwsrc=self.gateway_mac)
            self._sendp("ff:ff:ff:ff:ff:ff", self.gateway_ip, "ff:ff:ff:ff:ff:ff",
                        self.target_ip, hwsrc=self.target_mac)
            for peer_ip, peer_mac in self.extra_peers:
                self._sendp("ff:ff:ff:ff:ff:ff", self.target_ip, "ff:ff:ff:ff:ff:ff",
                            peer_ip, hwsrc=peer_mac)
                self._sendp("ff:ff:ff:ff:ff:ff", peer_ip, "ff:ff:ff:ff:ff:ff",
                            self.target_ip, hwsrc=self.target_mac)

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        self.restore()


def _ll_from_mac(mac: str) -> str | None:
    """Derive the EUI-64 IPv6 link-local address (fe80::/64) from a MAC."""
    try:
        from scapy.utils6 import in6_mactoifaceid

        iface_id = in6_mactoifaceid(mac).lower()
        return "fe80::" + iface_id
    except Exception:  # noqa: BLE001
        return None


class NDPSpoofer:
    """Experimental IPv6 neighbor-discovery spoof so device<->peer link-local unicast passes
    through us, the IPv6 analogue of ARP spoofing. Sends unsolicited Neighbor Advertisements
    (override set) claiming our MAC for each side's link-local address. Best-effort: on a Wi-Fi
    network with client isolation the stream may still never reach us, which the report notes."""

    def __init__(self, iface: str, our_mac_addr: str,
                 pairs: list[tuple[str, str]] | None = None, interval: float = 2.0):
        """pairs: [(ipv6_or_mac_a, ipv6_or_mac_b), ...] — each side given as a link-local
        address or a MAC (we derive the link-local via EUI-64)."""
        self.iface = iface
        self.our_mac = our_mac_addr
        self.interval = interval
        self.interfaces: list[tuple[str, str]] = []  # resolved (ll_a, ll_b)
        for a, b in (pairs or []):
            la = a if a.lower().startswith("fe80") else _ll_from_mac(a)
            lb = b if b.lower().startswith("fe80") else _ll_from_mac(b)
            if la and lb:
                self.interfaces.append((la, lb))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _advert(self, victim_ll: str, claimed_ll: str):
        from scapy.layers.inet6 import ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, IPv6
        from scapy.layers.l2 import Ether
        from scapy.sendrecv import sendp

        pkt = (Ether(src=self.our_mac)
               / IPv6(src=claimed_ll, dst=victim_ll)
               / ICMPv6ND_NA(tgt=claimed_ll, R=0, S=0, O=1)
               / ICMPv6NDOptDstLLAddr(lladdr=self.our_mac))
        sendp(pkt, iface=self.iface, verbose=False, count=1)

    def _loop(self):
        while not self._stop.is_set():
            for la, lb in self.interfaces:
                self._advert(la, lb)  # tell A: our MAC is B
                self._advert(lb, la)  # tell B: our MAC is A
            self._stop.wait(self.interval)

    def start(self):
        _quiet_scapy()
        if not self.interfaces:
            return self
        self._thread = threading.Thread(target=self._loop, name="ndp-spoof", daemon=True)
        self._thread.start()
        print(f"NDP mode (experimental): spoofing {len(self.interfaces)} IPv6 link-local "
              f"pair(s) on {self.iface}.", file=sys.stderr)
        return self

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)


def start(target_ip: str, gateway_ip: str | None = None, iface: str | None = None,
          target_mac: str | None = None, gateway_mac: str | None = None,
          extra_peers: list[tuple[str, str]] | None = None):
    """Start spoofing. Returns ArpSpoofer (caller must stop()). Needs root."""
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise PermissionError("ARP mode needs root. Re-run with sudo.")
    gw = gateway_ip or default_gateway()
    if not gw:
        raise RuntimeError("Could not determine the default gateway; pass --gateway.")
    real_iface = resolve_iface(iface)
    us = our_mac(real_iface)
    peers = list(extra_peers or [])
    print(
        f"ARP mode: spoofing {target_ip} ({target_mac or '?'}) <-> "
        f"gateway {gw} ({gateway_mac or '?'})"
        + (f" + {len(peers)} LAN peer(s)" if peers else "")
        + f" on {real_iface} (us {us}).",
        file=sys.stderr,
    )
    return ArpSpoofer(
        target_ip, gw, real_iface,
        target_mac=target_mac, gateway_mac=gateway_mac, our_mac_addr=us,
        extra_peers=peers,
    ).start()
