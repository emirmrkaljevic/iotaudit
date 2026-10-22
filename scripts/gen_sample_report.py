"""Generate an anonymized sample HTML report from feeder-like data (based on Emir's real
fourth-run capture) that also exercises IPv6/NDP, the special-use bogon peer, and the honest
'media not observed' note. Used for docs/sample-report.html. No real personal data."""

from __future__ import annotations

from pathlib import Path

from scapy.layers.inet import UDP
from scapy.layers.inet6 import ICMPv6ND_NA, ICMPv6ND_NS, IPv6
from scapy.layers.l2 import Ether

from iotaudit.analyze import build_devices, to_dict
from iotaudit.capture import Collector
from iotaudit.models import Flow
from iotaudit.report import render_html

DEV = "192.168.0.50"            # anonymized LAN IP
DMAC = "14:5d:34:00:00:01"      # Bilian OUI kept, device bytes zeroed (anonymized)
PMAC = "a4:30:7a:00:00:02"      # Samsung OUI (phone), anonymized


def _series(nbytes: int, start: int = 1_700_000_000, buckets: int = 90) -> dict[int, int]:
    """Spread bytes over a 15 minute window so bitrate heuristics have a real duration."""
    per = max(1, nbytes // buckets)
    return {start + i * 10: per for i in range(buckets)}


def collector() -> Collector:
    col = Collector([DEV])
    col.macs[DEV] = DMAC
    col.queries[DEV] = {"a1-us.iotbing.com"}
    col.dns["35.155.252.83"] = {"a1-us.iotbing.com"}  # real cloud IP (not personal)
    # Internet destinations mirroring the real run (iotbing TLS, AWS MQTT, OVH custom:1443, STUN).
    specs = [
        ("35.155.252.83", 443, 17000, True, "tcp", None),   # iotbing / AWS (cloud, not personal)
        ("52.32.71.30", 8883, 23000, True, "tcp", None),    # AWS MQTT
        ("15.204.79.232", 1443, 72000, False, "tcp", b"\x9f\xd2" + bytes(range(256)) * 2),  # OVH :1443
        ("15.204.72.48", 3478, 4000, False, "udp", None),   # OVH STUN/TURN
    ]
    for dst, port, nbytes, tls, proto, sample in specs:
        f = Flow(DEV, dst, port, proto, bytes=nbytes, bytes_in=nbytes,
                 packets=max(1, nbytes // 100), packets_in=max(1, nbytes // 100), tls=tls)
        if sample:
            f.payload_samples = [sample]
        f.series = _series(nbytes)
        col.flows[(f.src, f.dst, f.dport, f.proto)] = f
    # Public DNS bypassing the router.
    dns = Flow(DEV, "8.8.8.8", 53, "udp", bytes=200, packets=4)
    dns.series = _series(200)
    col.flows[(dns.src, dns.dst, dns.dport, dns.proto)] = dns
    # Tuya discovery broadcast (separate from peers).
    bc = Flow(DEV, "255.255.255.255", 6667, "udp", bytes=48000, packets=220, lan=True)
    col.lan_flows[(bc.src, bc.dst, bc.dport, bc.proto)] = bc
    # The odd special-use "LAN peer" (192.0.0.0/24) from the real run.
    bogon = Flow(DEV, "192.0.0.6", 63720, "udp", bytes=3360, packets=24, lan=True)
    col.lan_flows[(bogon.src, bogon.dst, bogon.dport, bogon.proto)] = bogon
    # IPv6: NDP seen between feeder and phone, but no IPv6 media captured.
    col.add(Ether(src=DMAC) / IPv6(src="fe80::165d:34ff:fe00:1", dst="ff02::1:ff00:2")
            / ICMPv6ND_NS(tgt="fe80::a630:7aff:fe00:2"))
    col.add(Ether(src=PMAC) / IPv6(src="fe80::a630:7aff:fe00:2", dst="fe80::165d:34ff:fe00:1")
            / ICMPv6ND_NA(tgt="fe80::a630:7aff:fe00:2"))
    col.add(Ether(src=DMAC, dst=PMAC) / IPv6(src="fe80::165d:34ff:fe00:1",
            dst="fe80::a630:7aff:fe00:2") / UDP(sport=7000, dport=7001) / (b"\x00" * 120))
    return col


def main() -> None:
    scans = {DEV: [{"port": 23, "proto": "tcp", "service": "telnet",
                    "product": "BusyBox telnetd", "risk": "high",
                    "why": "Telnet exposes an unencrypted login shell."}]}
    devs = [to_dict(d) for d in build_devices(collector(), scans=scans)]
    html = render_html(devs, {"source": "arp:en0 (anonymized sample)", "duration": 900})
    out = Path(__file__).resolve().parents[1] / "docs" / "sample-report.html"
    out.write_text(html, encoding="utf-8")
    print("wrote", out)
    print("findings:", [f["title"] for f in devs[0]["findings"]])


if __name__ == "__main__":
    main()
