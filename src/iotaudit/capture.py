"""Packet capture and flow extraction (DNS, TLS ClientHello/SNI, plaintext HTTP)."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

from .models import Flow

TLS_VERSIONS = {0x0301: "TLS1.0", 0x0302: "TLS1.1", 0x0303: "TLS1.2", 0x0304: "TLS1.3"}
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"PATCH ", b"OPTIONS ")


def is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private or a.is_multicast or a.is_link_local or a.is_loopback


def parse_client_hello(payload: bytes) -> tuple[str | None, str | None]:
    """Return (tls_version, sni) if payload begins with a TLS ClientHello, else (None, None)."""
    try:
        if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
            return None, None
        version = TLS_VERSIONS.get(int.from_bytes(payload[9:11], "big"))
        i = 43
        i += 1 + payload[i]  # session id
        cs_len = int.from_bytes(payload[i:i + 2], "big")
        i += 2 + cs_len
        i += 1 + payload[i]  # compression
        ext_end = i + 2 + int.from_bytes(payload[i:i + 2], "big")
        i += 2
        sni = None
        while i + 4 <= min(ext_end, len(payload)):
            etype = int.from_bytes(payload[i:i + 2], "big")
            elen = int.from_bytes(payload[i + 2:i + 4], "big")
            body = payload[i + 4:i + 4 + elen]
            if etype == 0 and len(body) > 5:
                nlen = int.from_bytes(body[3:5], "big")
                sni = body[5:5 + nlen].decode("ascii", "replace")
            elif etype == 43 and len(body) > 1:  # supported_versions
                vers = [int.from_bytes(body[1 + k:3 + k], "big") for k in range(0, body[0], 2)]
                if 0x0304 in vers:
                    version = "TLS1.3"
            i += 4 + elen
        return version, sni
    except (IndexError, ValueError):
        return None, None


def parse_http_host(payload: bytes) -> str | None:
    if not payload.startswith(HTTP_METHODS):
        return None
    for line in payload.split(b"\r\n")[1:20]:
        if line.lower().startswith(b"host:"):
            return line[5:].strip().decode("ascii", "replace")
    return ""


class Collector:
    """Aggregates packets into flows and DNS answers."""

    def __init__(self, device_ips: Iterable[str] | None = None):
        self.device_ips = set(device_ips or [])
        self.flows: dict[tuple, Flow] = {}
        self.dns: dict[str, set[str]] = {}  # ip -> names (from answers)
        self.queries: dict[str, set[str]] = {}  # client ip -> queried names
        self.macs: dict[str, str] = {}

    def _wanted(self, ip: str) -> bool:
        return (ip in self.device_ips) if self.device_ips else is_private(ip)

    def add(self, pkt) -> None:  # scapy packet
        from scapy.layers.dns import DNS
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.l2 import Ether

        if IP not in pkt:
            return
        ip = pkt[IP]
        if Ether in pkt and is_private(ip.src):
            self.macs.setdefault(ip.src, pkt[Ether].src.lower())
        if DNS in pkt:
            self._dns(pkt[DNS], ip)
        if not self._wanted(ip.src) or is_private(ip.dst):
            return
        l4 = pkt[TCP] if TCP in pkt else pkt[UDP] if UDP in pkt else None
        if l4 is None:
            return
        proto = "tcp" if TCP in pkt else "udp"
        key = (ip.src, ip.dst, l4.dport, proto)
        f = self.flows.get(key) or Flow(ip.src, ip.dst, l4.dport, proto)
        self.flows[key] = f
        f.packets += 1
        f.bytes += len(ip)
        payload = bytes(l4.payload)
        if payload:
            ver, sni = parse_client_hello(payload)
            if ver or sni:
                f.tls, f.tls_version, f.sni = True, ver or f.tls_version, sni or f.sni
            host = parse_http_host(payload)
            if host is not None:
                f.plaintext_http, f.http_host = True, host or f.http_host
            if proto == "udp" and l4.dport == 443:
                f.tls = True  # QUIC
                f.tls_version = f.tls_version or "QUIC"

    def _dns(self, dns, ip) -> None:
        if dns.qr == 0 and dns.qd:
            name = dns.qd[0].qname.decode(errors="replace").rstrip(".")
            self.queries.setdefault(ip.src, set()).add(name.lower())
        elif dns.qr == 1 and dns.an:
            for i in range(dns.ancount):
                try:
                    rr = dns.an[i]
                except IndexError:
                    break
                if rr.type in (1, 28):
                    name = rr.rrname.decode(errors="replace").rstrip(".").lower()
                    self.dns.setdefault(str(rr.rdata), set()).add(name)


def live(iface: str, seconds: int, collector: Collector) -> Collector:
    from scapy.all import sniff

    sniff(iface=iface, prn=collector.add, store=False, timeout=seconds)
    return collector


def from_pcap(path: str, collector: Collector) -> Collector:
    from scapy.utils import PcapReader

    with PcapReader(path) as rd:
        for pkt in rd:
            collector.add(pkt)
    return collector
