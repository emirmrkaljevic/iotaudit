"""Packet capture and flow extraction (DNS, TLS ClientHello/SNI, plaintext HTTP)."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

from .models import Flow

TLS_VERSIONS = {0x0301: "TLS1.0", 0x0302: "TLS1.1", 0x0303: "TLS1.2", 0x0304: "TLS1.3"}
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"PATCH ", b"OPTIONS ")


def is_broadcast_or_multicast(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_multicast or a.is_reserved or str(a).endswith(".255") or ip in (
        "255.255.255.255", "0.0.0.0",
    )


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


def build_bpf(target_ip: str | None, device_mac: str | None = None, ipv6: bool = True) -> str | None:
    """BPF that captures the focused device's IPv4 *and* its IPv6 + NDP.

    `ether host <mac>` grabs both address families for the device once ARP/NDP spoofing routes
    them through us; `icmp6` additionally grabs multicast neighbor-discovery so we can tell when
    a phone<->device stream is negotiated over IPv6 link-local even if its media never reaches us.
    """
    parts: list[str] = []
    if target_ip:
        parts.append(f"host {target_ip}")
    from .enrich import normalize_mac

    mac = normalize_mac(device_mac)
    if mac:
        parts.append(f"ether host {mac}")
    if ipv6:
        parts.append("icmp6")
    if not parts:
        return None
    return " or ".join(f"({p})" for p in parts)


class Collector:
    """Aggregates packets into flows and DNS answers."""

    def __init__(self, device_ips: Iterable[str] | None = None):
        self.device_ips = set(device_ips or [])
        self.flows: dict[tuple, Flow] = {}
        self.lan_flows: dict[tuple, Flow] = {}  # device <-> LAN peers
        self.dns: dict[str, set[str]] = {}  # ip -> names (from answers)
        self.queries: dict[str, set[str]] = {}  # client ip -> queried names
        self.macs: dict[str, str] = {}
        # IPv6: counted separately so we can answer "did media go over IPv6?".
        self.ipv6_flows: dict[tuple, Flow] = {}  # (src6, dst6, dport, proto) -> Flow
        self.v6_macs: dict[str, str] = {}        # ipv6 -> MAC (for device attribution)
        self.ndp = {"ns": 0, "na": 0, "rs": 0, "ra": 0, "redirect": 0}
        self.ndp_neighbors: dict[str, str] = {}  # ipv6 -> MAC learned from NS/NA

    def _wanted(self, ip: str) -> bool:
        return (ip in self.device_ips) if self.device_ips else is_private(ip)

    def add(self, pkt) -> None:  # scapy packet
        import time as _time

        from scapy.layers.dns import DNS
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.inet6 import IPv6
        from scapy.layers.l2 import Ether

        from .traffic import bucket_key

        if IPv6 in pkt:
            self._add_v6(pkt)
            return
        if IP not in pkt:
            return
        ip = pkt[IP]
        if Ether in pkt and is_private(ip.src):
            # Only learn MAC from the packet source, never from Ethernet dst
            # (dst is often the gateway/our NIC and would mis-label the device).
            self.macs.setdefault(ip.src, pkt[Ether].src.lower())
        if DNS in pkt:
            self._dns(pkt[DNS], ip)
        l4 = pkt[TCP] if TCP in pkt else pkt[UDP] if UDP in pkt else None
        if l4 is None:
            return
        proto = "tcp" if TCP in pkt else "udp"
        ts = float(getattr(pkt, "time", None) or _time.time())
        b = bucket_key(ts)
        payload = bytes(l4.payload) if l4.payload else b""

        # Outbound from focused device
        if self._wanted(ip.src):
            self._account(ip.src, ip.dst, l4.dport, proto, len(ip), b, payload, outbound=True,
                          tls_probe=True)
        # Inbound to focused device (bytes_in)
        elif self._wanted(ip.dst):
            self._account(ip.dst, ip.src, l4.sport if hasattr(l4, "sport") else l4.dport,
                          proto, len(ip), b, payload, outbound=False, tls_probe=False)

    def _add_v6(self, pkt) -> None:
        """Account IPv6 unicast flows and ICMPv6 NDP (neighbor discovery) separately.

        IPv6 media between two Wi-Fi clients usually rides link-local (fe80::) addresses that
        never appear in an IPv4/ARP capture, which is a prime reason a phone<->device video
        stream can be invisible. We count these so the report can say so honestly."""
        import time as _time

        from scapy.layers.inet import TCP, UDP
        from scapy.layers.inet6 import (
            ICMPv6ND_NA,
            ICMPv6ND_NS,
            ICMPv6ND_RA,
            ICMPv6ND_Redirect,
            ICMPv6ND_RS,
            IPv6,
        )
        from scapy.layers.l2 import Ether

        from .traffic import bucket_key

        ip6 = pkt[IPv6]
        src, dst = ip6.src, ip6.dst
        if Ether in pkt:
            self.v6_macs.setdefault(src, pkt[Ether].src.lower())
        # NDP neighbour discovery (link-local control plane)
        if ICMPv6ND_NS in pkt:
            self.ndp["ns"] += 1
            tgt = getattr(pkt[ICMPv6ND_NS], "tgt", None)
            if tgt and Ether in pkt:
                self.ndp_neighbors.setdefault(tgt, pkt[Ether].src.lower())
        if ICMPv6ND_NA in pkt:
            self.ndp["na"] += 1
            tgt = getattr(pkt[ICMPv6ND_NA], "tgt", None)
            if tgt and Ether in pkt:
                self.ndp_neighbors.setdefault(tgt, pkt[Ether].src.lower())
        if ICMPv6ND_RS in pkt:
            self.ndp["rs"] += 1
        if ICMPv6ND_RA in pkt:
            self.ndp["ra"] += 1
        if ICMPv6ND_Redirect in pkt:
            self.ndp["redirect"] += 1
        l4 = pkt[TCP] if TCP in pkt else pkt[UDP] if UDP in pkt else None
        if l4 is None:
            return
        proto = "tcp" if TCP in pkt else "udp"
        ts = float(getattr(pkt, "time", None) or _time.time())
        b = bucket_key(ts)
        nbytes = len(ip6)
        payload = bytes(l4.payload) if l4.payload else b""
        dport = int(getattr(l4, "dport", 0) or 0)
        key = (src, dst, dport, proto)
        f = self.ipv6_flows.get(key) or Flow(src, dst, dport, proto, lan=True)
        self.ipv6_flows[key] = f
        f.packets += 1
        f.bytes += nbytes
        f.series[b] = f.series.get(b, 0) + nbytes
        if payload and len(f.payload_samples) < 4:
            f.payload_samples.append(payload[:512])

    def ipv6_summary(self, device_mac: str | None) -> dict:
        """Aggregate IPv6 flows, attributing to the focused device by MAC when known."""
        from .enrich import normalize_mac

        dmac = normalize_mac(device_mac)
        flows = list(self.ipv6_flows.values())
        if dmac:
            mine = [f for f in flows
                    if normalize_mac(self.v6_macs.get(f.src)) == dmac
                    or normalize_mac(self.v6_macs.get(f.dst)) == dmac]
            attributed = bool(mine)
        else:
            mine, attributed = flows, False
        total_bytes = sum(f.bytes for f in mine)
        link_local = sum(
            f.bytes for f in mine
            if f.src.lower().startswith("fe80") or f.dst.lower().startswith("fe80")
        )
        peers = sorted({f.dst for f in mine} | {f.src for f in mine})
        return {
            "flows": len(mine),
            "bytes": total_bytes,
            "link_local_bytes": link_local,
            "ndp": dict(self.ndp),
            "neighbors": len(self.ndp_neighbors),
            "peers": peers[:12],
            "attributed_by_mac": attributed,
            "any_ipv6_seen": bool(flows) or any(self.ndp.values()),
        }

    def _account(self, device_ip, peer_ip, port, proto, nbytes, bucket, payload, *,
                 outbound: bool, tls_probe: bool) -> None:
        from .models import Flow

        broadcast = is_broadcast_or_multicast(peer_ip)
        lan = is_private(peer_ip) or broadcast
        if lan:
            store = self.lan_flows
        else:
            store = self.flows
        # For inbound, key by peer as "dst" from device POV still
        key = (device_ip, peer_ip, port, proto)
        f = store.get(key) or Flow(device_ip, peer_ip, port, proto, lan=lan)
        store[key] = f
        if outbound:
            f.packets += 1
            f.bytes += nbytes
            f.series[bucket] = f.series.get(bucket, 0) + nbytes
        else:
            f.packets_in += 1
            f.bytes_in += nbytes
            f.__dict__.setdefault("series_in", {})
            f.__dict__["series_in"][bucket] = f.__dict__["series_in"].get(bucket, 0) + nbytes
        if payload and len(f.payload_samples) < 8 and outbound:
            f.payload_samples.append(payload[:512])
        if payload and tls_probe and outbound and not lan:
            ver, sni = parse_client_hello(payload)
            if ver or sni:
                f.tls, f.tls_version, f.sni = True, ver or f.tls_version, sni or f.sni
            host = parse_http_host(payload)
            if host is not None:
                f.plaintext_http, f.http_host = True, host or f.http_host
            if proto == "udp" and port == 443:
                f.tls = True
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


def live(iface: str | None, seconds: int, collector: Collector,
         bpf_filter: str | None = None, progress_every: int = 10) -> Collector:
    """Sniff on iface for `seconds`. Prints a live counter every `progress_every` seconds.
    If 0 packets from the focused device after 60s, prints a clear hint."""
    import sys
    import time

    from scapy.all import sniff

    from .arp import _quiet_scapy

    _quiet_scapy()
    started = time.time()
    last_report = started
    warned_empty = False
    focused = set(collector.device_ips)

    def _count_from_device() -> tuple[int, int]:
        pkts = bytes_ = 0
        for f in collector.flows.values():
            if not focused or f.src in focused:
                pkts += f.packets
                bytes_ += f.bytes
        return pkts, bytes_

    def on_packet(pkt):
        nonlocal last_report, warned_empty
        collector.add(pkt)
        now = time.time()
        if now - last_report >= progress_every:
            pkts, nbytes = _count_from_device()
            who = (", ".join(sorted(focused)) if focused else "LAN")
            print(f"  … packets seen from {who}: {pkts}, bytes: {nbytes}", file=sys.stderr, flush=True)
            last_report = now
            if not warned_empty and now - started >= 60 and pkts == 0:
                warned_empty = True
                print(
                    "WARNING: 0 packets from the device after 60s. Check: same 2.4GHz Wi-Fi, "
                    "no client isolation, IP forwarding on, and that ARP spoof is targeting "
                    "the right MAC. Ctrl+C to abort.",
                    file=sys.stderr, flush=True,
                )

    kwargs = dict(prn=on_packet, store=False, timeout=seconds)
    if iface:
        kwargs["iface"] = iface
    if bpf_filter:
        kwargs["filter"] = bpf_filter
    print(f"Sniffing on {iface or 'default'} filter={bpf_filter!r} for {seconds}s "
          f"(Ctrl+C to stop)…", file=sys.stderr, flush=True)
    sniff(**kwargs)
    pkts, nbytes = _count_from_device()
    print(f"Capture done: {pkts} packets / {nbytes} bytes from device.", file=sys.stderr)
    return collector


PCAPDROID_TRAILER_MAGIC = b"\x01\x07\x20\x21"  # 0x01072021, big-endian


def _strip_pcapdroid(pkt):
    """If a packet carries a PCAPdroid trailer (bogus Ethernet header + 32-byte trailer appended
    after the L3 data), return (clean_ip_packet, appname); otherwise (pkt, None).

    PCAPdroid frames look like [ETH(bogus) | IP | payload | trailer]. The fake Ethernet MACs are
    meaningless, so we drop down to the IP layer (no MAC is learned) and trim the trailer bytes."""
    raw = bytes(pkt)
    idx = raw.rfind(PCAPDROID_TRAILER_MAGIC, max(0, len(raw) - 40))
    if idx < 0:
        return pkt, None
    appname = None
    try:
        # trailer: magic(4) uid(4) appname(20) fcs(4)
        appname = raw[idx + 8:idx + 28].split(b"\x00", 1)[0].decode("ascii", "replace") or None
    except Exception:  # noqa: BLE001
        appname = None
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6

    inner = None
    if IP in pkt:
        inner = pkt[IP]
    elif IPv6 in pkt:
        inner = pkt[IPv6]
    if inner is None:
        return pkt, appname
    # Re-parse only the real L3 bytes, dropping the appended trailer/padding.
    try:
        cls = inner.__class__
        clean = cls(bytes(inner))
        return clean, appname
    except Exception:  # noqa: BLE001
        return inner, appname


def from_pcap(path: str, collector: Collector, pcapdroid: bool | None = None) -> Collector:
    """Read a pcap/pcapng. PCAPdroid captures (Android) are detected automatically: the bogus
    Ethernet header + per-packet trailer are stripped, and app names are recorded in
    collector.apps. Pass pcapdroid=True/False to force detection on/off."""
    from scapy.utils import PcapReader

    if not hasattr(collector, "apps"):
        collector.apps = {}
    with PcapReader(path) as rd:
        for pkt in rd:
            if pcapdroid is not False:
                clean, app = _strip_pcapdroid(pkt)
                if app is not None:
                    pkt = clean
                    collector.apps[app] = collector.apps.get(app, 0) + 1
                elif pcapdroid is True:
                    pkt = clean
            collector.add(pkt)
    return collector
